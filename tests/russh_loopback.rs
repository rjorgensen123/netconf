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
}

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
        }
    }
}

struct Handler {
    device: Device,
    /// Held so the channels stay open: sshd does not close a channel whose
    /// subsystem it refused.
    channels: Vec<Channel<Msg>>,
}

impl russh::server::Handler for Handler {
    type Error = russh::Error;

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(match self.device {
            Device::EndsTheSubsystem | Device::Disconnects | Device::ClosesCleanly => {
                Some(BANNER.into())
            }
            _ => None,
        })
    }

    async fn auth_password(&mut self, _: &str, _: &str) -> Result<ServerAuth, Self::Error> {
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
            Device::NeverReads
            | Device::RejectsPassword
            | Device::NeverAnswersLogin
            | Device::EndsTheSubsystem
            | Device::Disconnects
            | Device::DataAfterEof => session.channel_success(channel),
            Device::ClosesCleanly => {
                session.channel_success(channel)?;
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
        if let Device::ClosesCleanly = self.device {
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
            Device::ClosesCleanly if data.windows(13).any(|w| w == b"close-session") => {
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
        }
        impl tracing::field::Visit for Fields {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "event" {
                    self.event = Some(value.to_string());
                }
            }
            // `username = %…` arrives here, rendered through its `Display`.
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "username" {
                    self.username = Some(format!("{value:?}"));
                }
            }
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
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

    assert!(
        matches!(result, Err(NetconfError::Timeout { op: "rpc-send", .. })),
        "{:?}",
        result.map_err(|e| e.to_string())
    );
    assert!(
        elapsed >= per_rpc && elapsed < per_rpc + Duration::from_secs(3),
        "the send gave up after {elapsed:?}, with a budget of {per_rpc:?}"
    );
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

    for (timeouts, tag) in [
        (
            Timeouts {
                connect: Duration::from_secs(2),
                ..Timeouts::default()
            },
            "ssh-connect",
        ),
        (
            Timeouts {
                connect: Duration::from_secs(3600),
                total: Duration::from_secs(1),
                ..Timeouts::default()
            },
            "session-ttl",
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
        assert!(
            matches!(result, Err(NetconfError::Timeout { op, .. }) if op == tag),
            "expected Timeout({tag:?}), got {:?}",
            result.map_err(|e| e.to_string())
        );
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
                host_key: Some("SHA256:never-presented".into()),
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

    assert!(
        matches!(
            result,
            Err(NetconfError::Timeout {
                op: "ssh-connect",
                ..
            })
        ),
        "{:?}",
        result.map(|_| ()).map_err(|e| e.to_string())
    );
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
