// SPDX-License-Identifier: MIT OR Apache-2.0
//! `RusshTransport` against an SSH server on the loopback interface.
//!
//! The rest of the suite reaches the transport's decisions through functions that
//! need no SSH. What happens between the transport and a device — what russh hands
//! back, and when — can only be seen with a device on the other end. The device
//! here is russh's own server, started by each test on a free port and made to
//! behave the one way that test is about.

#![cfg(feature = "russh-transport")]

use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use netconf::russh_transport::RusshTransport;
use netconf::{
    Auth, ConnectOptions, NetconfError, NetconfTransport, SshPolicy, Timeouts, TransportError,
};
use russh::server::{Auth as ServerAuth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};

/// How the device on the other end behaves.
#[derive(Clone, Copy)]
enum Device {
    /// Accepts the password and answers the subsystem request with a failure,
    /// leaving the channel open — what sshd does when NETCONF over SSH is not
    /// enabled.
    NoNetconf,
    /// Opens the subsystem, then stops reading at the first data it is sent: its
    /// session stalls there, so the window it offered is never opened again.
    NeverReads,
    /// Rejects the password, and names the methods it would accept instead.
    RejectsPassword,
    /// Takes the handshake, and never answers the login.
    NeverAnswersLogin,
    /// Shows a login banner, opens the subsystem, and at the first data it is sent
    /// ends it: EOF, then the subsystem's exit status and signal, then a close.
    EndsTheSubsystem,
    /// Shows a login banner, opens the subsystem, and at the first data it is sent
    /// disconnects, saying why.
    Disconnects,
    /// Opens the subsystem, and at the first data it is sent sends EOF, then data
    /// all the same, then its exit status and a close.
    DataAfterEof,
    /// A small NETCONF device: shows a login banner, sends its hello when the
    /// subsystem opens, answers `<close-session/>` with `<ok/>`, and at the
    /// client's EOF sends the subsystem's exit status and closes the channel.
    ClosesCleanly,
    /// Writes on stderr why, then answers the subsystem request with a failure.
    ExplainsTheRefusal,
    /// Opens the subsystem, and at the first data it is sent writes on stderr why,
    /// then closes the channel.
    ExplainsAndCloses,
    /// Opens the subsystem, and at the first data it is sent writes on stderr why,
    /// then never answers.
    ExplainsAndStalls,
    /// Writes on stderr why, and never answers the subsystem request.
    ExplainsAndNeverOpens,
    /// Opens the subsystem, and from the first data it is sent writes on stderr
    /// four times a second, and never answers.
    DripsOnStderr,
    /// A small NETCONF device like `ClosesCleanly` that writes on stderr as well:
    /// with its hello, and again at the client's EOF.
    Chatty,
    /// Sends its hello when the subsystem opens, and answers nothing after it.
    HelloThenSilent,
}

/// What the devices that explain themselves write on stderr: a line to read, and
/// one with a secret in it.
const EXPLANATION: &str = "netconf: database locked by another session\n\
                           authentication-key \"$9$stderr-leak\";\n";

/// The banner the devices that say goodbye show before the login.
const BANNER: &str = "Authorized use only\nmaintenance window 22:00-23:00";

impl Device {
    /// The username each device is connected to as, so the events of one test can
    /// be told from another's.
    fn username(self) -> &'static str {
        match self {
            Device::NoNetconf => "no-netconf",
            Device::NeverReads => "never-reads",
            Device::RejectsPassword => "rejected",
            Device::NeverAnswersLogin => "never-answers-login",
            Device::EndsTheSubsystem => "ends-the-subsystem",
            Device::Disconnects => "disconnects",
            Device::DataAfterEof => "data-after-eof",
            Device::ClosesCleanly => "closes-cleanly",
            Device::ExplainsTheRefusal => "explains-the-refusal",
            Device::ExplainsAndCloses => "explains-and-closes",
            Device::ExplainsAndStalls => "explains-and-stalls",
            Device::ExplainsAndNeverOpens => "explains-and-never-opens",
            Device::DripsOnStderr => "drips-on-stderr",
            Device::Chatty => "chatty",
            Device::HelloThenSilent => "hello-then-silent",
        }
    }
}

struct Handler {
    device: Device,
    /// Held so the channels stay open: sshd does not close a channel whose
    /// subsystem it refused.
    channels: Vec<Channel<Msg>>,
    /// The device has begun writing on stderr.
    dripping: bool,
}

impl russh::server::Handler for Handler {
    type Error = russh::Error;

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(match self.device {
            Device::EndsTheSubsystem
            | Device::Disconnects
            | Device::ClosesCleanly
            | Device::Chatty => Some(BANNER.into()),
            _ => None,
        })
    }

    async fn auth_password(&mut self, user: &str, _: &str) -> Result<ServerAuth, Self::Error> {
        LOGINS.lock().unwrap().push(user.to_string());
        Ok(match self.device {
            Device::RejectsPassword => ServerAuth::Reject {
                proceed_with_methods: Some(MethodSet::from(
                    &[MethodKind::PublicKey, MethodKind::KeyboardInteractive][..],
                )),
                partial_success: false,
            },
            Device::NeverAnswersLogin => std::future::pending().await,
            _ => ServerAuth::Accept,
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.push(channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.device {
            Device::NoNetconf => session.channel_failure(channel),
            Device::ExplainsTheRefusal => {
                session.extended_data(channel, 1, EXPLANATION.as_bytes())?;
                session.channel_failure(channel)
            }
            Device::ExplainsAndNeverOpens => {
                session.extended_data(channel, 1, EXPLANATION.as_bytes())
            }
            Device::ExplainsAndCloses | Device::ExplainsAndStalls | Device::DripsOnStderr => {
                session.channel_success(channel)
            }
            Device::NeverReads
            | Device::RejectsPassword
            | Device::NeverAnswersLogin
            | Device::EndsTheSubsystem
            | Device::Disconnects
            | Device::DataAfterEof => session.channel_success(channel),
            Device::ClosesCleanly | Device::Chatty | Device::HelloThenSilent => {
                session.channel_success(channel)?;
                if let Device::Chatty = self.device {
                    session.extended_data(channel, 1, &b"warning: chatty-hello\n"[..])?;
                }
                let hello = "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\
                             <capabilities><capability>urn:ietf:params:xml:ns:netconf:base:1.0\
                             </capability></capabilities><session-id>9</session-id></hello>]]>]]>";
                session.data(channel, hello.as_bytes())
            }
        }
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Device::ClosesCleanly | Device::Chatty = self.device {
            if let Device::Chatty = self.device {
                session.extended_data(channel, 1, &b"chatty-goodbye"[..])?;
            }
            session.exit_status_request(channel, 0)?;
            session.close(channel)?;
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.device {
            Device::NeverReads => std::future::pending::<()>().await,
            // EOF first: what comes after it has to be read too.
            Device::EndsTheSubsystem => {
                session.eof(channel)?;
                session.exit_status_request(channel, 1)?;
                session.exit_signal_request(
                    channel,
                    russh::Sig::TERM,
                    false,
                    "netconf subsystem stopped",
                    "en",
                )?;
                session.close(channel)?;
            }
            Device::Disconnects => session.disconnect(
                russh::Disconnect::ByApplication,
                "going down for maintenance",
                "en",
            )?,
            Device::ExplainsAndCloses => {
                session.extended_data(channel, 1, EXPLANATION.as_bytes())?;
                session.close(channel)?;
            }
            Device::ExplainsAndStalls => {
                session.extended_data(channel, 1, EXPLANATION.as_bytes())?;
            }
            Device::DripsOnStderr if !self.dripping => {
                self.dripping = true;
                let handle = session.handle();
                tokio::spawn(async move {
                    while handle
                        .extended_data(channel, 1, &b"still working\n"[..])
                        .await
                        .is_ok()
                    {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                });
            }
            Device::ClosesCleanly | Device::Chatty
                if data.windows(13).any(|w| w == b"close-session") =>
            {
                let ok = "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" \
                          message-id=\"1\"><ok/></rpc-reply>]]>]]>";
                session.data(channel, ok.as_bytes())?;
            }
            Device::DataAfterEof => {
                session.eof(channel)?;
                session.data(channel, &b"late words"[..])?;
                session.exit_status_request(channel, 0)?;
                session.close(channel)?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// The window the device offers: what a client may send before the device has to
/// read. Small, so a device that never reads is reached with a small send.
const WINDOW: u32 = 32 * 1024;

/// Start a device on a free loopback port, and return what connects to it: its
/// host key pinned, and `timeouts` as given.
async fn start(device: Device, timeouts: Timeouts) -> ConnectOptions {
    capture_events();
    let key = russh::keys::PrivateKey::from(
        russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]),
    );
    let pin = key
        .public_key()
        .fingerprint(russh::keys::HashAlg::Sha256)
        .to_string();
    let config = Arc::new(russh::server::Config {
        keys: vec![key],
        window_size: WINDOW,
        auth_rejection_time: Duration::ZERO,
        ..Default::default()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let handler = Handler {
            device,
            channels: Vec::new(),
            dripping: false,
        };
        if let Ok(session) = russh::server::run_stream(config, socket, handler).await {
            let _ = session.await;
        }
    });
    ConnectOptions {
        host: "127.0.0.1".into(),
        port,
        username: device.username().into(),
        auth: Auth::Password(krypto::SecretString::from_string("test-password".into()).unwrap()),
        ssh_policy: SshPolicy::Modern,
        timeouts,
        platform_hint: None,
        host_key: Some(pin),
    }
}

/// Every tracing event with an `event` and a `username` field, in order, from every
/// test in this file.
static EVENTS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

/// The level of every `ssh_connect` event, with its `username`, in order.
static SSH_CONNECT_LEVELS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

/// Every `ssh_session_failed` event, with all its fields as text.
static SESSION_FAILED_EVENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Every `netconf_subsystem_stderr` event, with all its fields as text, from every
/// test in this file: the event has no `username`.
static STDERR_EVENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Every username a device was asked to let in with a password, in order, from
/// every test in this file.
static LOGINS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// How many times a device was asked to let `username` in with a password.
fn logins_for(username: &str) -> usize {
    LOGINS
        .lock()
        .unwrap()
        .iter()
        .filter(|user| *user == username)
        .count()
}

/// The events emitted for `username`.
fn events_for(username: &str) -> Vec<String> {
    EVENTS
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, user)| user == username)
        .map(|(event, _)| event.clone())
        .collect()
}

/// Install the capture as the global subscriber, once, before any test connects.
///
/// Global rather than per test: tracing caches, per callsite, whether anyone is
/// listening, and a subscriber set for one thread races that cache when another
/// test emits the same event first — the capture then comes back empty.
fn capture_events() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        tracing::subscriber::set_global_default(Capture).expect("no other subscriber");
    });
}

struct Capture;

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        #[derive(Default)]
        struct Fields {
            event: Option<String>,
            username: Option<String>,
            /// Every field, `name=value`.
            all: String,
        }
        impl tracing::field::Visit for Fields {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "event" {
                    self.event = Some(value.to_string());
                }
                self.all.push_str(&format!("{}={value} ", field.name()));
            }
            // `username = %…` arrives here, rendered through its `Display`, and so
            // does every field that is not a string.
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "username" {
                    self.username = Some(format!("{value:?}"));
                }
                self.all.push_str(&format!("{}={value:?} ", field.name()));
            }
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        if fields.event.as_deref() == Some("ssh_session_failed") {
            SESSION_FAILED_EVENTS
                .lock()
                .unwrap()
                .push(fields.all.clone());
        }
        if fields.event.as_deref() == Some("netconf_subsystem_stderr") {
            STDERR_EVENTS.lock().unwrap().push(fields.all.clone());
        }
        if let (Some("ssh_connect"), Some(username)) = (fields.event.as_deref(), &fields.username) {
            SSH_CONNECT_LEVELS
                .lock()
                .unwrap()
                .push((username.clone(), event.metadata().level().to_string()));
        }
        if let (Some(event), Some(username)) = (fields.event, fields.username) {
            EVENTS.lock().unwrap().push((event, username));
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// **A device without NETCONF over SSH is told apart, and at once.** sshd answers
/// the subsystem request with a failure and leaves the channel open. russh returns
/// from `request_subsystem` as soon as the request is queued, so the refusal used to
/// go unread: the session was logged as established, and the hello then waited out
/// `per_rpc` for a reply that was never coming.
#[tokio::test]
async fn a_refused_subsystem_is_its_own_error_and_is_not_logged_as_established() {
    let opts = start(Device::NoNetconf, Timeouts::default()).await;

    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(20), RusshTransport::connect(&opts))
        .await
        .expect("connect did not return");
    let elapsed = started.elapsed();

    let text = match result {
        Err(e @ NetconfError::Transport(TransportError::SubsystemUnavailable { .. })) => {
            e.to_string()
        }
        Err(e) => panic!("expected SubsystemUnavailable, got {e}"),
        Ok(_) => panic!("a refused subsystem was taken for an open one"),
    };
    assert!(text.contains("set system services netconf ssh"), "{text}");
    assert!(
        elapsed < Duration::from_secs(5),
        "the refusal waited {elapsed:?}"
    );
    let events = events_for(Device::NoNetconf.username());
    assert!(
        events.iter().any(|e| e == "ssh_connect"),
        "nothing was captured: {events:?}"
    );
    assert!(
        !events.iter().any(|e| e == "ssh_session_established"),
        "{events:?}"
    );
}

/// **A send waits no longer than its budget.** A device that stops reading lets the
/// SSH window fill, and russh's `data` then waits for window space that never
/// comes. The send has to give up after `per_rpc`, as a read does, instead of
/// holding the session until its deadline.
#[tokio::test]
async fn a_send_to_a_device_that_never_reads_times_out_within_its_budget() {
    let per_rpc = Duration::from_secs(2);
    let opts = start(
        Device::NeverReads,
        Timeouts {
            per_rpc,
            ..Timeouts::default()
        },
    )
    .await;
    let mut transport = RusshTransport::connect(&opts)
        .await
        .map_err(|e| e.to_string())
        .expect("the device opens the subsystem");

    let more_than_the_window = vec![b' '; 8 * WINDOW as usize];
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        transport.send(&more_than_the_window),
    )
    .await
    .expect("the send outlived its budget");
    let elapsed = started.elapsed();

    match result {
        Err(NetconfError::Timeout {
            op: "rpc-send",
            limit,
            during,
            ..
        }) => {
            assert_eq!(limit, per_rpc);
            assert_eq!(during, "while the request was being sent");
        }
        other => panic!(
            "expected an rpc-send timeout, got {:?}",
            other.map_err(|e| e.to_string())
        ),
    }
    assert!(
        elapsed >= per_rpc && elapsed < per_rpc + Duration::from_secs(3),
        "the send gave up after {elapsed:?}, with a budget of {per_rpc:?}"
    );
}

/// **A send after the session's deadline says that nothing was sent** (0.7.0): the
/// lifetime ran out before the request went out, and the timeout says so, with the
/// lifetime as the limit that ran out.
#[tokio::test]
async fn a_send_after_the_deadline_says_nothing_was_sent() {
    let total = Duration::from_secs(1);
    let opts = start(
        Device::NeverReads,
        Timeouts {
            total,
            ..Timeouts::default()
        },
    )
    .await;
    let mut transport = RusshTransport::connect(&opts)
        .await
        .map_err(|e| e.to_string())
        .expect("the device opens the subsystem");
    tokio::time::sleep(total).await;
    match transport.send(b"<hello/>").await {
        Err(NetconfError::Timeout {
            op: "session-ttl",
            limit,
            during,
            ..
        }) => {
            assert_eq!(limit, total);
            assert_eq!(during, "before the request was sent — nothing was sent");
        }
        other => panic!(
            "expected a session-ttl timeout, got {:?}",
            other.map_err(|e| e.to_string())
        ),
    }
}

/// **Wrong credentials are their own error**, carrying what the device said. They
/// used to be `Io` with the same text, and a consumer could tell them from a broken
/// connection only by parsing it.
#[tokio::test]
async fn a_rejected_password_is_its_own_error_and_names_what_the_device_accepts() {
    let opts = start(Device::RejectsPassword, Timeouts::default()).await;
    let e = match RusshTransport::connect(&opts).await {
        Ok(_) => panic!("the device rejected the password, and connect went on"),
        Err(e) => e,
    };
    let text = e.to_string();
    match e {
        NetconfError::Transport(TransportError::AuthRejected {
            username,
            remaining_methods,
            partial_success,
        }) => {
            assert_eq!(username, Device::RejectsPassword.username());
            assert_eq!(remaining_methods, ["publickey", "keyboard-interactive"]);
            assert!(!partial_success);
        }
        other => panic!("expected AuthRejected, got {other}"),
    }
    assert!(
        text.contains("rejected")
            && text.contains("publickey")
            && text.contains("keyboard-interactive"),
        "{text}"
    );
}

/// **A device that presents another key than the pinned one is refused as
/// `HostKey`, before the login**, through the transport and through the session:
/// the error carries the key the device presented, and the password is never sent.
/// The links of this chain have tests of their own with hand-made input; this one
/// runs the chain against a device, so a russh that answered a refused key with
/// another error would be seen here.
#[tokio::test]
async fn a_host_key_that_is_not_the_pinned_one_is_refused_before_the_login() {
    let another_key = format!("SHA256:{}", "A".repeat(43));
    let user = "pinned-another-key";

    let mut opts = start(Device::ClosesCleanly, Timeouts::default()).await;
    let presented = opts
        .host_key
        .replace(another_key.clone())
        .expect("start pins the device's key");
    opts.username = user.into();
    match RusshTransport::connect(&opts).await {
        Err(NetconfError::Transport(TransportError::HostKey { observed, .. })) => {
            assert_eq!(observed.as_deref(), Some(presented.as_str()));
        }
        Err(e) => panic!("expected HostKey, got {e}"),
        Ok(_) => panic!("a key that is not the pinned one was accepted"),
    }
    assert_eq!(
        logins_for(user),
        0,
        "the password was sent after the key was refused"
    );

    let mut opts = start(Device::ClosesCleanly, Timeouts::default()).await;
    opts.host_key = Some(another_key);
    opts.username = user.into();
    match netconf::NetconfSession::<RusshTransport>::connect(&opts).await {
        Err(NetconfError::Transport(TransportError::HostKey { observed, .. })) => {
            assert_eq!(observed.as_deref(), Some(presented.as_str()));
        }
        Err(e) => panic!("expected HostKey, got {e}"),
        Ok(_) => panic!("a key that is not the pinned one was accepted"),
    }
    assert_eq!(
        logins_for(user),
        0,
        "the password was sent after the key was refused"
    );

    // The record sees a login: with the device's own key pinned, the user is let in.
    let mut opts = start(Device::ClosesCleanly, Timeouts::default()).await;
    opts.username = user.into();
    RusshTransport::connect(&opts)
        .await
        .map_err(|e| e.to_string())
        .expect("the device's own key is pinned");
    assert_eq!(logins_for(user), 1);
}

/// A device that sends its banner and never goes further: the key exchange stalls.
/// It reads what it is sent and throws it away, and `closed` reports when the client
/// ended the connection — when a read came back empty or failed.
async fn stalling_device() -> (u16, tokio::sync::oneshot::Receiver<Instant>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tell, closed) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"SSH-2.0-stalls\r\n").await.unwrap();
        let mut buf = [0u8; 4096];
        while let Ok(1..) = socket.read(&mut buf).await {}
        let _ = tell.send(Instant::now());
    });
    (port, closed)
}

/// **The host-key probe runs under the session's `Timeouts`, as `connect` does.** It
/// used to take `connect` alone, unvalidated, so `total` did not bound it and a
/// `connect` of any size was waited out in full. Timeouts `connect` would refuse are
/// refused before anything goes on the wire; a stalled probe gives up within
/// `connect`, as `Timeout("ssh-connect")`, and a `connect` longer than `total` ends
/// at `total`, as `Timeout("session-ttl")`.
#[tokio::test]
async fn the_host_key_probe_runs_under_the_same_limits_as_connect() {
    use netconf::russh_transport::observe_host_key;

    let over_the_ceiling = Timeouts {
        total: Duration::from_secs(3600),
        ..Timeouts::default()
    };
    let m = match observe_host_key("127.0.0.1", 1, &SshPolicy::Modern, &over_the_ceiling).await {
        Ok(fp) => panic!("Timeouts outside their frames were let through, got {fp}"),
        Err(e) => e.to_string(),
    };
    assert!(m.contains("Timeouts::total"), "{m}");

    for (timeouts, tag, limit) in [
        (
            Timeouts {
                connect: Duration::from_secs(2),
                ..Timeouts::default()
            },
            "ssh-connect",
            Duration::from_secs(2),
        ),
        (
            Timeouts {
                connect: Duration::from_secs(3600),
                total: Duration::from_secs(1),
                ..Timeouts::default()
            },
            "session-ttl",
            Duration::from_secs(1),
        ),
    ] {
        let (port, _closed) = stalling_device().await;
        let bound = timeouts.connect.min(timeouts.total);
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            observe_host_key("127.0.0.1", port, &SshPolicy::Modern, &timeouts),
        )
        .await
        .expect("the probe outlived its budget");
        let elapsed = started.elapsed();
        match result {
            Err(NetconfError::Timeout {
                op,
                limit: ran_out,
                during,
                ..
            }) if op == tag => {
                assert_eq!(ran_out, limit, "{tag}");
                assert_eq!(during, "while connecting", "{tag}");
            }
            other => panic!(
                "expected Timeout({tag:?}), got {:?}",
                other.map_err(|e| e.to_string())
            ),
        }
        assert!(
            elapsed >= bound && elapsed < bound + Duration::from_secs(1),
            "the probe gave up after {elapsed:?}, with a bound of {bound:?}"
        );
    }
}

/// **When connecting gives up, the device sees the connection end — at once.** russh
/// runs the session in a task of its own, which owns the socket, and giving up on a
/// wait did not stop it: a device stalling the key exchange kept its connection
/// until russh's inactivity timer, set to `total`, ran out — and a device that keeps
/// sending restarts that timer. `connect` and the host-key probe both give up within
/// `connect` here, and the device must see the connection close then, not at
/// `total`.
#[tokio::test]
async fn when_connecting_gives_up_the_device_sees_the_connection_end() {
    use netconf::russh_transport::observe_host_key;

    let timeouts = Timeouts {
        connect: Duration::from_secs(2),
        total: Duration::from_secs(20),
        ..Timeouts::default()
    };
    for probe in [false, true] {
        let (port, closed) = stalling_device().await;
        let started = Instant::now();
        let result = if probe {
            observe_host_key("127.0.0.1", port, &SshPolicy::Modern, &timeouts)
                .await
                .map(|_| ())
        } else {
            let opts = ConnectOptions {
                host: "127.0.0.1".into(),
                port,
                username: "stalled".into(),
                auth: Auth::Password(
                    krypto::SecretString::from_string("test-password".into()).unwrap(),
                ),
                ssh_policy: SshPolicy::Modern,
                timeouts,
                platform_hint: None,
                // Never compared: the key exchange never gets that far.
                host_key: Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
            };
            RusshTransport::connect(&opts).await.map(|_| ())
        };
        assert!(
            matches!(result, Err(NetconfError::Timeout { .. })),
            "probe: {probe}: {:?}",
            result.map_err(|e| e.to_string())
        );
        let seen = tokio::time::timeout(Duration::from_secs(5), closed)
            .await
            .unwrap_or_else(|_| panic!("probe: {probe}: the device still had the connection"))
            .expect("the device reports when the connection ends");
        let after = seen - started;
        assert!(
            after < timeouts.connect + Duration::from_secs(1),
            "probe: {probe}: the device saw the connection end after {after:?}, with a \
             connect budget of {:?}",
            timeouts.connect
        );
    }
}

/// **Every wait while connecting ends within `connect`.** russh bounds none of them
/// itself, beyond an inactivity timer set to the whole TTL. A device that took the
/// handshake and never answered the login held `connect` until that timer ran out,
/// and it came back as a rejected login with no methods — a false «wrong password».
#[tokio::test]
async fn a_device_that_never_answers_the_login_times_out_within_the_connect_budget() {
    let connect = Duration::from_secs(2);
    let opts = start(
        Device::NeverAnswersLogin,
        Timeouts {
            connect,
            ..Timeouts::default()
        },
    )
    .await;

    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(20), RusshTransport::connect(&opts))
        .await
        .expect("connect outlived its budget");
    let elapsed = started.elapsed();

    match result {
        Err(NetconfError::Timeout {
            op: "ssh-connect",
            limit,
            during,
            ..
        }) => {
            assert_eq!(limit, connect);
            assert_eq!(during, "while connecting");
        }
        other => panic!(
            "expected an ssh-connect timeout, got {:?}",
            other.map(|_| ()).map_err(|e| e.to_string())
        ),
    }
    assert!(
        elapsed >= connect && elapsed < connect + Duration::from_secs(3),
        "connect gave up after {elapsed:?}, with a budget of {connect:?}"
    );
}

/// **What the device says over SSH as the subsystem ends goes with the error**
/// (0.5.13): its exit status and signal — sent here after its EOF, which `recv` used
/// to return at — and the banner it showed at login. They were dropped, and the
/// caller was left with a channel that had closed.
#[tokio::test]
async fn the_subsystems_exit_and_the_banner_go_with_the_close() {
    let opts = start(Device::EndsTheSubsystem, Timeouts::default()).await;
    let mut transport = RusshTransport::connect(&opts)
        .await
        .map_err(|e| e.to_string())
        .expect("the device opens the subsystem");
    transport.send(b"<hello/>").await.expect("the send");
    let e = tokio::time::timeout(Duration::from_secs(20), transport.recv())
        .await
        .expect("the read outlived its budget")
        .expect_err("the device ended the subsystem");
    let text = e.to_string();
    match e {
        NetconfError::Transport(TransportError::Closed { ssh, .. }) => {
            assert_eq!(ssh.exit_status, Some(1));
            let signal = ssh.exit_signal.expect("the exit signal");
            assert_eq!(signal.name, "TERM");
            assert_eq!(signal.message, "netconf subsystem stopped");
            assert_eq!(signal.language, "en");
            assert_eq!(ssh.banner.as_deref(), Some(BANNER));
        }
        other => panic!("expected Closed, got {other}"),
    }
    assert!(
        text.contains("exit status: 1")
            && text.contains("exit signal: TERM")
            && text.contains("Authorized use only\\nmaintenance"),
        "{text}"
    );
}

/// **The device's disconnect message goes with the error** (0.5.13): its reason
/// code and what it said. russh's default handler dropped it, and the caller got
/// «peer closed» or russh's own text.
#[tokio::test]
async fn the_devices_disconnect_message_goes_with_the_error() {
    let opts = start(Device::Disconnects, Timeouts::default()).await;
    let mut transport = RusshTransport::connect(&opts)
        .await
        .map_err(|e| e.to_string())
        .expect("the device opens the subsystem");
    transport.send(b"<hello/>").await.expect("the send");
    let e = tokio::time::timeout(Duration::from_secs(20), transport.recv())
        .await
        .expect("the read outlived its budget")
        .expect_err("the device disconnected");
    match e {
        NetconfError::Transport(TransportError::Closed { ssh, .. }) => {
            let d = ssh.disconnect.expect("the disconnect message");
            assert_eq!(d.code, 11, "by application");
            assert_eq!(d.description, "going down for maintenance");
            assert_eq!(ssh.banner.as_deref(), Some(BANNER));
        }
        other => panic!("expected Closed, got {other}"),
    }
}

/// **Data the device sends after its EOF is handed on** (0.5.13), and what follows
/// it — the exit status, the close — is still read. `recv` used to return at the
/// EOF, and a read after it dropped data.
#[tokio::test]
async fn data_after_the_devices_eof_is_handed_on() {
    let opts = start(Device::DataAfterEof, Timeouts::default()).await;
    let mut transport = RusshTransport::connect(&opts)
        .await
        .map_err(|e| e.to_string())
        .expect("the device opens the subsystem");
    transport.send(b"<hello/>").await.expect("the send");
    let data = tokio::time::timeout(Duration::from_secs(20), transport.recv())
        .await
        .expect("the read outlived its budget")
        .expect("the data after the EOF");
    assert_eq!(&data[..], b"late words");
    let then = tokio::time::timeout(Duration::from_secs(20), transport.recv())
        .await
        .expect("the read outlived its budget");
    match then {
        Err(NetconfError::Transport(TransportError::Closed { ssh, .. })) => {
            assert_eq!(ssh.exit_status, Some(0));
        }
        other => panic!("expected Closed with the exit status, got {other:?}"),
    }
}

/// **A clean close hands over what the device said over SSH** (0.5.13): the
/// transport sends its EOF, reads the subsystem's exit status and the close that
/// follow, and the session's `close()` returns them with the login banner. The
/// transport used to send EOF and disconnect without reading, ignoring whether
/// either went through, and `close()` returned nothing.
#[tokio::test]
async fn a_clean_close_hands_over_what_the_device_said_over_ssh() {
    let opts = start(Device::ClosesCleanly, Timeouts::default()).await;
    let transport = RusshTransport::connect(&opts)
        .await
        .map_err(|e| e.to_string())
        .expect("the device opens the subsystem");
    let s = netconf::NetconfSession::establish(transport, false)
        .await
        .map_err(|e| e.to_string())
        .expect("the hello exchange");
    assert_eq!(s.session_id(), Some(9));
    let end = tokio::time::timeout(Duration::from_secs(20), s.close())
        .await
        .expect("close outlived its budget")
        .map_err(|e| e.to_string())
        .expect("a clean close");
    assert!(end.warnings.is_empty());
    assert_eq!(end.ssh.exit_status, Some(0));
    // No policy is bound, so the banner comes redacted as a reply would; it holds
    // no secret, and reads as it was sent.
    assert_eq!(end.ssh.banner.as_deref(), Some(BANNER));
}

/// **`check_device` takes a connection step by step and reports on each** (0.7.0).
/// Against a device that answers, every step is there with its time, and the
/// report holds what the device showed on the way.
#[tokio::test]
async fn a_device_check_reports_every_step_of_a_device_that_answers() {
    use netconf::russh_transport::{CheckStep, Verdict, check_device};
    let opts = start(Device::ClosesCleanly, Timeouts::default()).await;
    let check = tokio::time::timeout(Duration::from_secs(20), check_device(&opts))
        .await
        .expect("the check outlived its limit")
        .map_err(|e| e.to_string())
        .expect("the check was started");

    assert_eq!(check.verdict(), Verdict::Ok, "{check}");
    assert!(check.stopped().is_none(), "{check}");
    let steps: Vec<CheckStep> = check.steps().iter().map(|(step, _)| *step).collect();
    assert_eq!(
        steps,
        [
            CheckStep::Tcp,
            CheckStep::Ssh,
            CheckStep::Login,
            CheckStep::Netconf,
            CheckStep::Hello,
            CheckStep::Request,
        ]
    );
    assert_eq!(check.limit(), opts.timeouts.connect);
    assert!(check.elapsed() < check.limit());
    assert_eq!(check.fingerprint(), opts.host_key.as_deref());
    assert_eq!(check.session_id(), Some(9));
    assert!(!check.capabilities().is_empty());
    assert_eq!(check.banner(), Some(BANNER));
    // One word, one line, and everything.
    assert!(check.summary().starts_with("ok — every step answered"));
    let full = check.to_string();
    assert!(full.contains("the login: "), "{full}");
    assert!(full.contains("session id: 9"), "{full}");
}

/// **A check that stops says where, and why** (0.7.0). The steps before it are
/// there, and the error is the one `connect` would have returned.
#[tokio::test]
async fn a_device_check_says_where_it_stopped_and_why() {
    use netconf::russh_transport::{CheckStep, Verdict, check_device};

    let opts = start(Device::RejectsPassword, Timeouts::default()).await;
    let check = check_device(&opts)
        .await
        .map_err(|e| e.to_string())
        .unwrap();
    assert_eq!(check.verdict(), Verdict::Dead, "{check}");
    match check.stopped() {
        Some((CheckStep::Login, NetconfError::Transport(TransportError::AuthRejected { .. }))) => {}
        other => panic!("expected the login to stop it, got {other:?}"),
    }
    let steps: Vec<CheckStep> = check.steps().iter().map(|(step, _)| *step).collect();
    assert_eq!(steps, [CheckStep::Tcp, CheckStep::Ssh]);
    assert!(check.fingerprint().is_some());
    assert!(
        check.summary().starts_with("dead — stopped at the login"),
        "{}",
        check.summary()
    );

    let opts = start(Device::NoNetconf, Timeouts::default()).await;
    let check = check_device(&opts)
        .await
        .map_err(|e| e.to_string())
        .unwrap();
    match check.stopped() {
        Some((
            CheckStep::Netconf,
            NetconfError::Transport(TransportError::SubsystemUnavailable { .. }),
        )) => {}
        other => panic!("expected the subsystem to stop it, got {other:?}"),
    }
}

/// **A check against a device that presents another key than the pinned one stops at
/// the SSH step**, with the `HostKey` error `connect` returns, and the report's
/// fingerprint is the key the device presented.
#[tokio::test]
async fn a_device_check_stops_at_a_host_key_that_is_not_the_pinned_one() {
    use netconf::russh_transport::{CheckStep, Verdict, check_device};
    let mut opts = start(Device::ClosesCleanly, Timeouts::default()).await;
    let presented = opts
        .host_key
        .replace(format!("SHA256:{}", "A".repeat(43)))
        .expect("start pins the device's key");
    let check = tokio::time::timeout(Duration::from_secs(20), check_device(&opts))
        .await
        .expect("the check outlived its limit")
        .map_err(|e| e.to_string())
        .expect("the check was started");

    assert_eq!(check.verdict(), Verdict::Dead, "{check}");
    match check.stopped() {
        Some((
            CheckStep::Ssh,
            NetconfError::Transport(TransportError::HostKey { observed, .. }),
        )) => assert_eq!(observed.as_deref(), Some(presented.as_str())),
        other => panic!("expected the host key to stop it, got {other:?}"),
    }
    let steps: Vec<CheckStep> = check.steps().iter().map(|(step, _)| *step).collect();
    assert_eq!(steps, [CheckStep::Tcp]);
    assert_eq!(check.fingerprint(), Some(presented.as_str()));
    assert!(
        check
            .summary()
            .starts_with("dead — stopped at the SSH handshake and host key"),
        "{}",
        check.summary()
    );
}

/// **A login that never answers stops the check at the login, within its limit**
/// (0.7.0). `connect` says `Timeout { op: "ssh-connect" }` for it, as it does for a
/// device that is not there at all; the check says which step it was.
#[tokio::test]
async fn a_device_check_names_the_step_that_ran_out_of_time() {
    use netconf::russh_transport::{CheckStep, Verdict, check_device};
    let limit = Duration::from_secs(2);
    let opts = start(
        Device::NeverAnswersLogin,
        Timeouts {
            connect: limit,
            ..Timeouts::default()
        },
    )
    .await;
    let started = Instant::now();
    let check = tokio::time::timeout(Duration::from_secs(20), check_device(&opts))
        .await
        .expect("the check outlived its limit")
        .map_err(|e| e.to_string())
        .unwrap();
    assert!(started.elapsed() < limit + Duration::from_secs(3));
    assert_eq!(check.verdict(), Verdict::Dead, "{check}");
    match check.stopped() {
        Some((
            CheckStep::Login,
            NetconfError::Timeout {
                op: "ssh-connect",
                limit: ran_out,
                during,
                ..
            },
        )) => {
            assert_eq!(*ran_out, limit);
            assert_eq!(during, "while connecting");
        }
        other => panic!("expected the login to run out of time, got {other:?}"),
    }
}

/// **A check that runs out of time after the connection says what it was waiting
/// for** (0.7.0): the device's hello, or the answer to closing the session — under
/// `connect`, the one clock of the check.
#[tokio::test]
async fn a_device_check_says_what_it_was_waiting_for_when_time_ran_out() {
    use netconf::russh_transport::{CheckStep, check_device};
    let limit = Duration::from_secs(2);
    let timeouts = Timeouts {
        connect: limit,
        ..Timeouts::default()
    };
    for (device, step, waiting) in [
        (
            Device::NeverReads,
            CheckStep::Hello,
            "while waiting for the device's hello",
        ),
        (
            Device::HelloThenSilent,
            CheckStep::Request,
            "while closing the session",
        ),
    ] {
        let opts = start(device, timeouts).await;
        let check = tokio::time::timeout(Duration::from_secs(20), check_device(&opts))
            .await
            .expect("the check outlived its limit")
            .map_err(|e| e.to_string())
            .unwrap();
        match check.stopped() {
            Some((
                stopped,
                NetconfError::Timeout {
                    op: "rpc-recv",
                    limit: ran_out,
                    during,
                    ..
                },
            )) if stopped == step => {
                assert_eq!(*ran_out, limit, "{check}");
                assert_eq!(during, waiting, "{check}");
            }
            other => panic!("expected {step} to run out of time, got {other:?}"),
        }
    }
}

/// **No TCP connection is `NoContact`, and what `connect` refuses outright is no
/// report** (0.7.0): with nothing listening the check stops at its first step, and
/// without a pinned host key nothing is checked at all.
#[tokio::test]
async fn a_device_check_tells_no_contact_from_a_check_that_never_started() {
    use netconf::russh_transport::{CheckStep, Verdict, check_device};
    // A port nothing listens on: bound, then let go.
    let port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let mut opts = start(Device::ClosesCleanly, Timeouts::default()).await;
    opts.port = port;
    let check = check_device(&opts)
        .await
        .map_err(|e| e.to_string())
        .unwrap();
    assert_eq!(check.verdict(), Verdict::NoContact, "{check}");
    assert!(matches!(check.stopped(), Some((CheckStep::Tcp, _))));
    assert!(check.steps().is_empty());
    assert!(
        check
            .summary()
            .starts_with("no contact — stopped at the TCP connection")
    );

    opts.host_key = None;
    assert!(check_device(&opts).await.is_err());
}

/// What the devices that explain themselves wrote, as it is handed over: redacted,
/// and printable.
fn assert_explained(text: &str) {
    assert!(
        text.starts_with("netconf: database locked by another session\\nauthentication-key "),
        "{text}"
    );
    assert!(!text.contains("stderr-leak"), "a secret leaked: {text}");
}

/// **What a device writes on stderr before it refuses the subsystem goes with the
/// refusal** — redacted (0.7.0; it was made printable only).
#[tokio::test]
async fn a_refusal_carries_what_the_device_wrote_on_stderr() {
    let opts = start(Device::ExplainsTheRefusal, Timeouts::default()).await;
    let e = RusshTransport::connect(&opts)
        .await
        .err()
        .expect("the device refuses the subsystem");
    let text = e.to_string();
    let NetconfError::Transport(TransportError::SubsystemUnavailable { stderr, ssh }) = e else {
        panic!("expected SubsystemUnavailable, got {text}");
    };
    assert_explained(&stderr);
    assert_eq!(ssh.stderr, None);
    assert!(!text.contains("stderr-leak"), "{text}");
}

/// **A device that says why and closes the channel is `Closed`, with what it wrote
/// on stderr in `ssh.stderr`** (0.7.0; part of `detail` before, and not redacted).
#[tokio::test]
async fn a_close_carries_what_the_device_wrote_on_stderr() {
    let opts = start(Device::ExplainsAndCloses, Timeouts::default()).await;
    let mut transport = RusshTransport::connect(&opts)
        .await
        .map_err(|e| e.to_string())
        .expect("the device opens the subsystem");
    transport.send(b"<hello/>").await.expect("the send");
    let e = tokio::time::timeout(Duration::from_secs(20), transport.recv())
        .await
        .expect("the read outlived its budget")
        .expect_err("the device closed the channel");
    let text = e.to_string();
    let NetconfError::Transport(TransportError::Closed { detail, ssh, .. }) = e else {
        panic!("expected Closed, got {text}");
    };
    assert_eq!(detail, "the device closed the netconf subsystem");
    assert_explained(ssh.stderr.as_deref().expect("what the device wrote"));
    assert!(text.contains("; the device wrote on stderr: netconf: database locked"));
    assert!(!text.contains("stderr-leak"), "{text}");
}

/// **A device that says why and then goes silent gives a timeout that carries what
/// it wrote** (0.7.0). The error used to be the bare timeout, and the device's
/// explanation was only in the log. It is handed over once: the next read's
/// timeout has none of it.
#[tokio::test]
async fn a_timeout_carries_what_the_device_wrote_on_stderr() {
    let opts = start(
        Device::ExplainsAndStalls,
        Timeouts {
            per_rpc: Duration::from_secs(1),
            ..Timeouts::default()
        },
    )
    .await;
    let mut transport = RusshTransport::connect(&opts)
        .await
        .map_err(|e| e.to_string())
        .expect("the device opens the subsystem");
    transport.send(b"<hello/>").await.expect("the send");
    let e = tokio::time::timeout(Duration::from_secs(20), transport.recv())
        .await
        .expect("the read outlived its budget")
        .expect_err("the device never answers");
    let text = e.to_string();
    let NetconfError::Timeout {
        op,
        limit,
        during,
        stderr,
        ..
    } = e
    else {
        panic!("expected Timeout, got {text}");
    };
    assert_eq!(op, "rpc-recv");
    assert_eq!(limit, Duration::from_secs(1));
    assert_eq!(during, "while waiting for an answer");
    assert_explained(&stderr);
    assert!(
        text.starts_with(
            "timeout: rpc-recv after 1s, while waiting for an answer; the device wrote on \
             stderr: netconf: "
        ),
        "{text}"
    );

    match transport.recv().await {
        Err(NetconfError::Timeout { op, stderr, .. }) => {
            assert_eq!(op, "rpc-recv");
            assert_eq!(stderr, "");
        }
        other => panic!("expected Timeout, got {other:?}"),
    }
    assert_eq!(transport.take_stderr(), None);
}

/// **What a device writes on stderr while all goes well is there for the taking,
/// once, and what it writes as the session ends comes with the close** (0.7.0). It
/// was only in the log.
#[tokio::test]
async fn what_the_device_wrote_on_stderr_is_handed_over_when_nothing_failed() {
    let opts = start(Device::Chatty, Timeouts::default()).await;
    let transport = RusshTransport::connect(&opts)
        .await
        .map_err(|e| e.to_string())
        .expect("the device opens the subsystem");
    let mut s = netconf::NetconfSession::establish(transport, false)
        .await
        .map_err(|e| e.to_string())
        .expect("the hello exchange");
    assert_eq!(s.take_stderr().as_deref(), Some("warning: chatty-hello"));
    assert_eq!(s.take_stderr(), None);

    let end = tokio::time::timeout(Duration::from_secs(20), s.close())
        .await
        .expect("close outlived its budget")
        .map_err(|e| e.to_string())
        .expect("a clean close");
    // The device did not end this line; the session is over, so it goes as it is.
    assert_eq!(end.ssh.stderr.as_deref(), Some("chatty-goodbye"));
    assert_eq!(end.ssh.exit_status, Some(0));
}

/// **The log says that a device wrote on stderr, and how much — not what** (0.7.0).
/// The text is free text from the device: the redaction takes what it knows the
/// shape of, and the log is no place for the rest.
#[tokio::test]
async fn the_log_does_not_carry_what_the_device_wrote_on_stderr() {
    let opts = start(Device::ExplainsTheRefusal, Timeouts::default()).await;
    let _ = RusshTransport::connect(&opts).await;
    let events = STDERR_EVENTS.lock().unwrap().clone();
    let bytes = format!("bytes={} ", EXPLANATION.len());
    assert!(
        events
            .iter()
            .any(|e| e.contains(&bytes) && e.contains("cut=false")),
        "{events:?}"
    );
    for text in ["database locked", "stderr-leak", "chatty"] {
        assert!(
            !events.iter().any(|e| e.contains(text)),
            "{text}: {events:?}"
        );
    }
}

/// **A device that says why and never answers the subsystem request gives a timeout
/// that carries what it wrote** (0.7.0). The connection attempt ends there, so all
/// of it goes with the timeout.
#[tokio::test]
async fn a_timeout_opening_the_subsystem_carries_what_the_device_wrote_on_stderr() {
    let opts = start(
        Device::ExplainsAndNeverOpens,
        Timeouts {
            connect: Duration::from_secs(2),
            ..Timeouts::default()
        },
    )
    .await;
    let e = tokio::time::timeout(Duration::from_secs(20), RusshTransport::connect(&opts))
        .await
        .expect("connect outlived its budget")
        .err()
        .expect("the device never opens the subsystem");
    let text = e.to_string();
    let NetconfError::Timeout {
        op,
        limit,
        during,
        stderr,
        ..
    } = e
    else {
        panic!("expected Timeout, got {text}");
    };
    assert_eq!(op, "ssh-subsystem");
    assert_eq!(limit, Duration::from_secs(2));
    assert_eq!(during, "while waiting for the netconf subsystem");
    assert_explained(&stderr);
}

/// **A device check that runs to its end reports what the device wrote on stderr**
/// (0.7.0): a device that answers every step can still be saying that something is
/// wrong. A check that stops has the text in its error.
#[tokio::test]
async fn a_device_check_reports_what_the_device_wrote_on_stderr() {
    use netconf::russh_transport::{CheckStep, check_device};

    let opts = start(Device::Chatty, Timeouts::default()).await;
    let check = check_device(&opts).await.expect("a report");
    assert!(check.stopped().is_none(), "{check}");
    assert_eq!(
        check.stderr(),
        Some("warning: chatty-hello\\nchatty-goodbye")
    );
    let full = check.to_string();
    assert!(
        full.contains("\n  stderr: warning: chatty-hello\\nchatty-goodbye"),
        "{full}"
    );

    let opts = start(Device::ExplainsTheRefusal, Timeouts::default()).await;
    let check = check_device(&opts).await.expect("a report");
    let (step, error) = check.stopped().expect("the check stopped");
    assert_eq!(step, CheckStep::Netconf);
    let text = error.to_string();
    assert!(
        text.contains("the device said: netconf: database locked"),
        "{text}"
    );
    assert!(!check.to_string().contains("stderr-leak"), "{check}");
    assert_eq!(check.stderr(), None);
}

/// **A read has one clock** (0.7.0). The limit used to start again for every
/// message on the channel, and the ones that carry no data do not end the read: a
/// device that kept writing on stderr held one read until the session's deadline.
/// The wait `close` does is bounded the same way.
#[tokio::test]
async fn a_device_that_keeps_writing_on_stderr_does_not_hold_a_read() {
    let timeouts = Timeouts {
        per_rpc: Duration::from_secs(1),
        ..Timeouts::default()
    };
    let opts = start(Device::DripsOnStderr, timeouts).await;
    let mut transport = RusshTransport::connect(&opts)
        .await
        .map_err(|e| e.to_string())
        .expect("the device opens the subsystem");
    transport.send(b"<hello/>").await.expect("the send");

    let started = Instant::now();
    let e = tokio::time::timeout(Duration::from_secs(20), transport.recv())
        .await
        .expect("the read ran past its limit")
        .expect_err("the device never answers");
    match &e {
        NetconfError::Timeout {
            op: "rpc-recv",
            limit,
            during,
            ..
        } => {
            assert_eq!(*limit, timeouts.per_rpc, "{e}");
            assert_eq!(during, "while waiting for an answer", "{e}");
        }
        other => panic!("expected an rpc-recv timeout, got {other}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );

    let started = Instant::now();
    let _ = tokio::time::timeout(Duration::from_secs(20), transport.close())
        .await
        .expect("the close ran past its limit");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
}

/// **A connect refused for its `Timeouts` does not spend the legacy warning**
/// (0.7.0). A device gets the full warning once. The `Timeouts` were checked after
/// it was logged, so a refused connect took it, and the first real connection to
/// the device went out without it.
#[tokio::test]
async fn a_connect_refused_for_its_timeouts_does_not_spend_the_legacy_warning() {
    capture_events();
    let levels = || -> Vec<String> {
        SSH_CONNECT_LEVELS
            .lock()
            .unwrap()
            .iter()
            .filter(|(user, _)| user == "legacy-warning")
            .map(|(_, level)| level.clone())
            .collect()
    };
    // No test connects here under a legacy policy, and nothing listens on the port.
    let mut opts = ConnectOptions {
        host: "127.0.0.2".into(),
        port: 1,
        username: "legacy-warning".into(),
        auth: Auth::Password(krypto::SecretString::from_string("test-password".into()).unwrap()),
        ssh_policy: SshPolicy::LegacyJunos,
        timeouts: Timeouts {
            total: Duration::from_secs(3600),
            ..Timeouts::default()
        },
        platform_hint: None,
        host_key: Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
    };
    assert!(RusshTransport::connect(&opts).await.is_err());
    assert!(levels().is_empty(), "{:?}", levels());

    opts.timeouts = Timeouts {
        connect: Duration::from_secs(2),
        ..Timeouts::default()
    };
    assert!(RusshTransport::connect(&opts).await.is_err());
    assert_eq!(levels(), ["WARN"]);
    assert!(RusshTransport::connect(&opts).await.is_err());
    assert_eq!(levels(), ["WARN", "INFO"]);
}

/// Put a wire between the client and the device, which the test can cut: a TCP
/// relay on a port of its own. Sending on the returned channel resets the
/// client's connection, as a line that breaks does.
async fn behind_a_wire(
    mut opts: ConnectOptions,
) -> (ConnectOptions, tokio::sync::oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let device_port = opts.port;
    opts.port = listener.local_addr().unwrap().port();
    let (cut, mut cut_now) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut device = tokio::net::TcpStream::connect(("127.0.0.1", device_port))
            .await
            .unwrap();
        tokio::select! {
            _ = tokio::io::copy_bidirectional(&mut client, &mut device) => {}
            _ = &mut cut_now => {}
        }
        // A reset rather than a close: the client is told nothing first.
        let _ = client.set_zero_linger();
    });
    (opts, cut)
}

/// **A connection that breaks says why** (0.7.0). russh knows what ended the
/// connection, and netconf passed the error on without keeping it: the channel
/// just ended, and the caller was told that the peer had closed. The reason is in
/// the error now, and in the log.
#[tokio::test]
async fn a_connection_that_breaks_says_why() {
    let opts = start(Device::NeverReads, Timeouts::default()).await;
    let (opts, cut) = behind_a_wire(opts).await;
    let mut transport = RusshTransport::connect(&opts)
        .await
        .map_err(|e| e.to_string())
        .expect("the device opens the subsystem");

    cut.send(()).expect("the wire is there to cut");
    let started = Instant::now();
    let e = tokio::time::timeout(Duration::from_secs(20), transport.recv())
        .await
        .expect("the read outlived the connection")
        .expect_err("the connection is gone");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    let text = e.to_string();
    let NetconfError::Transport(TransportError::Closed { detail, .. }) = e else {
        panic!("expected Closed, got {text}");
    };
    assert!(
        detail.starts_with("the SSH connection failed: ") && detail.len() > 30,
        "{detail}"
    );
    let events = SESSION_FAILED_EVENTS.lock().unwrap().clone();
    assert!(
        events.iter().any(|e| e.contains("error=")),
        "the failure was not logged: {events:?}"
    );
}
