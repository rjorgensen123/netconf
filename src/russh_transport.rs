// SPDX-License-Identifier: MIT OR Apache-2.0
//! The real SSH transport for NETCONF over russh (feature `russh-transport`).
//!
//! It opens an SSH connection, authenticates with a **password** — never a key —
//! and asks for the subsystem `netconf` on that session. **SSH is the transport**:
//! netconf is a subsystem on the session (RFC 6242), not a separate port we connect
//! to. The raw byte stream is exposed as [`NetconfTransport`]; framing, whether
//! `]]>]]>` or chunked, is handled by the layer above.
//!
//! **The fingerprint format is `ssh-key`'s, not ours.** russh 0.65 builds on
//! `ssh-key`, whose `Fingerprint` renders as `SHA256:<base64 without padding>` —
//! the same string an operator sees in the `ssh` client. The source is the
//! `ssh-key` documentation. Note that russh 0.45 produced bare base64, so values
//! pinned against that version do not match.

use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::time::timeout;

use crate::error::{ExitSignal, NetconfError, SshDisconnect, SshMessages, TransportError};
use crate::framing::DEFAULT_MAX_MESSAGE;
use crate::transport::{Auth, ConnectOptions, NetconfTransport, ReplyBudget, SshPolicy, Timeouts};
use crate::wire::printable;

/// russh's text for an error, through the filter: the transport has no policy to
/// let anything through, and while connecting none is bound, so it is redacted, as
/// the hello is (0.5.13). It carries nothing of the device's in practice; the rule
/// is that every text leaving netconf has passed the filter.
fn russh_text(e: impl std::fmt::Display) -> String {
    crate::redact::redact_secrets(&e.to_string())
}

fn io_err(e: impl std::fmt::Display) -> NetconfError {
    NetconfError::Transport(TransportError::Io(russh_text(e)))
}

/// What the device has said over SSH so far, shared between the handler, which
/// russh runs in its own task, and the transport.
type Said = Arc<StdMutex<SshMessages>>;

/// A copy of what the device has said over SSH.
fn said_now(said: &StdMutex<SshMessages>) -> SshMessages {
    said.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

/// Add to what the device has said over SSH.
fn note(said: &StdMutex<SshMessages>, add: impl FnOnce(&mut SshMessages)) {
    add(&mut said.lock().unwrap_or_else(|p| p.into_inner()));
}

/// A failure where the connection or the channel may be gone: `Closed`, carrying
/// what the device said over SSH, when it said anything (0.5.13); otherwise `Io`
/// with the text, as before.
fn ended(detail: impl std::fmt::Display, ssh: SshMessages) -> NetconfError {
    if ssh.is_empty() {
        return io_err(detail);
    }
    NetconfError::Transport(TransportError::Closed {
        detail: russh_text(detail),
        partial: String::new(),
        ssh: Box::new(ssh),
    })
}

/// Keep `msg` when it is the subsystem's exit status or exit signal (0.5.13). The
/// device sends them as the subsystem ends, and they used to be skipped like the
/// channel's housekeeping.
fn note_exit(said: &StdMutex<SshMessages>, msg: &russh::ChannelMsg) {
    match msg {
        russh::ChannelMsg::ExitStatus { exit_status } => {
            let code = *exit_status;
            note(said, |s| s.exit_status = Some(code));
        }
        russh::ChannelMsg::ExitSignal {
            signal_name,
            core_dumped,
            error_message,
            lang_tag,
        } => {
            // A known signal's `Debug` is its name; a custom one is the device's.
            let name = match signal_name {
                russh::Sig::Custom(name) => name.clone(),
                known => format!("{known:?}"),
            };
            let signal = ExitSignal {
                name,
                core_dumped: *core_dumped,
                message: error_message.clone(),
                language: lang_tag.clone(),
            };
            note(said, |s| s.exit_signal = Some(signal));
        }
        _ => {}
    }
}

/// The russh client handler. It verifies the host key against a pinned fingerprint,
/// when one is set, and captures the observed one for enrollment. It keeps what the
/// device says over SSH outside the channel: its login banner and its disconnect
/// message (0.5.13).
struct ClientHandler {
    /// The pinned fingerprint, from the consumer. `None` means enrollment mode.
    pinned: Option<String>,
    /// The observed fingerprint, filled in while connecting.
    observed: Arc<StdMutex<Option<String>>>,
    /// What the device has said over SSH.
    said: Said,
}

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    /// The device's login banner (RFC 4252 §5.4), kept for the error a connection
    /// that ends brings (0.5.13). russh's default drops it.
    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        note(&self.said, |s| {
            s.banner = Some(match s.banner.take() {
                Some(before) => format!("{before}\n{banner}"),
                None => banner.to_string(),
            });
        });
        Ok(())
    }

    /// The device's disconnect message (RFC 4253 §11.1), kept for the error the
    /// ended connection brings (0.5.13). russh's default drops it; an error is
    /// passed on as russh's default passes it.
    async fn disconnected(
        &mut self,
        reason: russh::client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        match reason {
            russh::client::DisconnectReason::ReceivedDisconnect(info) => {
                let disconnect = SshDisconnect {
                    code: info.reason_code as u32,
                    description: info.message,
                    language: info.lang_tag,
                };
                note(&self.said, |s| s.disconnect = Some(disconnect));
                Ok(())
            }
            russh::client::DisconnectReason::Error(e) => Err(e),
        }
    }

    async fn check_server_key(
        &mut self,
        server_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // `SHA256:<base64 without padding>` — `ssh-key`'s `Fingerprint` `Display`,
        // which is the form the `ssh` client shows. Source: the `ssh-key` docs. For
        // a certificate it is the fingerprint of the key the certificate carries
        // (0.6.1).
        let fp = server_key
            .public_key()
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();
        // Recorded even if the lock was poisoned: the key is what the device
        // presented, and the error that follows needs it (0.5.13).
        *self.observed.lock().unwrap_or_else(|p| p.into_inner()) = Some(fp.clone());
        // A host certificate is refused, pinned or not (0.6.1). The pin is a key,
        // and nothing here knows which authorities to trust, so a certificate
        // proves nothing the pin can check. `preferred_for` advertises no
        // certificate algorithm, so a device has no way to present one; this is
        // the floor beneath that.
        if server_key.certificate().is_some() {
            tracing::warn!(
                event = "ssh_host_key_mismatch",
                observed = %fp,
                "the device presented a host certificate, which is not accepted — connection rejected"
            );
            return Ok(false);
        }
        match &self.pinned {
            // Pinned: accept ONLY on an exact match — never a silent accept, never
            // trust-on-first-use.
            //
            // Both sides use `ssh-key`'s format (see the module header), which is
            // settled from documentation. The comparison is therefore strict byte
            // equality with no normalisation: if a device presents anything other
            // than what was pinned, that IS a discrepancy.
            //
            // Constant-time, through krypto's `ct_eq`. A host key fingerprint is not
            // a secret, so this avoids no real oracle — but it is the right habit,
            // and the portfolio's one implementation of it.
            Some(expected) => {
                let ok = krypto::ct_eq(expected.as_bytes(), fp.as_bytes());
                if ok {
                    tracing::debug!(
                        event = "ssh_host_key_verified",
                        fingerprint = %fp,
                        "host key matches the pinned fingerprint"
                    );
                } else {
                    // A security event: this may be the wrong device, or a
                    // machine-in-the-middle.
                    tracing::warn!(
                        event = "ssh_host_key_mismatch",
                        observed = %fp,
                        "host key does NOT match the pinned fingerprint — connection rejected"
                    );
                }
                Ok(ok)
            }
            // Enrollment: accept, and let the consumer pin `observed_host_key`.
            None => {
                tracing::info!(
                    event = "ssh_host_key_enrollment",
                    fingerprint = %fp,
                    "no pinned host key — enrollment, fingerprint observed"
                );
                Ok(true)
            }
        }
    }
}

/// Refuse a host or username that cannot be right, before either is logged or
/// sent anywhere.
///
/// Both go into log events verbatim, so a control character in either — a
/// newline above all — could forge a log line of its own. Neither can legitimately
/// hold one, a host cannot hold whitespace, and an empty value is a configuration
/// fault that would otherwise surface as a baffling connection or authentication
/// error. The value itself is not echoed: it is the thing that cannot be trusted
/// in a log line.
///
/// `username` is `None` for the host-key probe, which authenticates as no one.
fn check_target(host: &str, username: Option<&str>) -> Result<(), NetconfError> {
    let problem = if host.is_empty() {
        Some("host is empty")
    } else if host.chars().any(|c| c.is_control() || c.is_whitespace()) {
        Some("host contains whitespace or a control character")
    } else {
        match username {
            Some("") => Some("username is empty"),
            Some(u) if u.chars().any(char::is_control) => {
                Some("username contains a control character")
            }
            _ => None,
        }
    };
    match problem {
        Some(p) => Err(NetconfError::Transport(TransportError::Io(format!(
            "{p} — refused before anything is logged or sent"
        )))),
        None => Ok(()),
    }
}

/// Why `SshPolicy::Custom` is refused — by `connect()` and `observe_host_key()`
/// alike, in the same words.
const CUSTOM_REFUSED: &str = "SshPolicy::Custom is not implemented yet — use Modern or \
                              LegacyJunos. We refuse rather than negotiate with a \
                              different algorithm list than the one you asked for.";

/// A cap on how much of the subsystem's stderr we keep in a session. Enough to
/// carry an explanation, too little for a device that floods it to fill our memory.
const MAX_STDERR: usize = 4096;

/// What a text handed over says when the device wrote more than is kept.
const STDERR_CUT: &str = "[cut: the device wrote more than 4096 bytes on stderr in this session, \
                          and the rest was not kept]";

/// Append `text` to the kept stderr, never letting it grow past `cap` bytes.
/// Whether all of it was kept.
///
/// The cut lands on a character boundary. `String::truncate` panics when the
/// length it is given falls inside a character, and `from_utf8_lossy` turns every
/// invalid byte into U+FFFD, three bytes long — so a device writing more than
/// `cap` bytes of non-ASCII text or binary noise to stderr hit that boundary and
/// took the reading thread down. Nothing a device sends may be able to do that.
///
/// A separate function so the cut can be unit-tested without SSH, like
/// `close_outcome`.
fn append_capped(buf: &mut String, text: &str, cap: usize) -> bool {
    let mut end = cap.saturating_sub(buf.len()).min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    buf.push_str(&text[..end]);
    end == text.len()
}

/// What the subsystem has written on stderr in this session, and how much of it
/// has been handed over (0.7.0).
///
/// Junos puts its explanation there when something is wrong with the subsystem
/// itself, and that explanation is often the only thing that says WHY. We do not
/// INTERPRET it: it is kept, and handed to whoever it concerns — in the error of
/// the request that failed, to the session when it asks, and what is left when
/// the transport closes. Each piece is handed over once.
///
/// It is free text from the device, and it is treated as sensitive:
///
/// - **Capped.** At most `MAX_STDERR` bytes are kept in a session. What comes after
///   is dropped, unread; the text handed over says so, once, and so does the log.
/// - **Redacted, whatever the policy.** The transport has no policy to ask, so the
///   redaction is the one a reply passes where none is bound. The text is kept as
///   the device wrote it and redacted whole each time some of it is handed over:
///   it comes in pieces, and a piece alone can not be redacted — the name of a
///   secret statement may be in the piece before it, and so may the `-----BEGIN`
///   line of a private key. That is also why nothing is removed when it is handed
///   over; `given` says how far that has come.
/// - **In ended lines.** What makes a word a secret may come after it on its line,
///   so a line is handed over when the device has ended it. One it has not ended
///   waits for the end of the session, where nothing more can come.
/// - **Printable**, after the redaction: a control character the device wrote stays
///   visible instead of acting on a terminal or a log.
/// - **Not logged.** The redaction takes what it knows the shape of, and a secret
///   in a form it does not know would pass. The event says that the device wrote,
///   and how much.
/// - **Wiped** when the transport is dropped. The copies the redaction works on
///   are not.
struct Stderr {
    kept: zeroize::Zeroizing<String>,
    /// How far into `kept` has been handed over: always where a line begins, or
    /// the end.
    given: usize,
    /// The device wrote more than is kept.
    cut: bool,
    /// A text handed over has said so.
    cut_told: bool,
}

impl Stderr {
    fn new() -> Self {
        Stderr {
            // All it will hold, so it is never moved, and never left behind unwiped.
            kept: zeroize::Zeroizing::new(String::with_capacity(MAX_STDERR)),
            given: 0,
            cut: false,
            cut_told: false,
        }
    }

    /// Keep what the subsystem wrote, up to the cap, and log that it wrote.
    /// `ext == 1` is stderr (RFC 4254 §5.2); other codes do not occur in practice,
    /// but we take them the same way rather than filtering them out.
    ///
    /// Past the cap nothing is done with what comes: no copy, no redaction, no
    /// event. A device that floods stderr costs us the cap and one last event.
    fn keep(&mut self, data: &[u8], ext: u32) {
        if self.cut {
            return;
        }
        self.cut = !append_capped(&mut self.kept, &String::from_utf8_lossy(data), MAX_STDERR);
        tracing::warn!(
            event = "netconf_subsystem_stderr",
            ext,
            bytes = data.len(),
            cut = self.cut,
            "the netconf subsystem wrote to stderr"
        );
    }

    /// Hand over what has not been handed over yet: the lines the device has
    /// ended, and at the `end` of the session the line it has not ended as well.
    /// `None` when there is nothing, or nothing but whitespace.
    fn take(&mut self, end: bool) -> Option<String> {
        let upto = if end {
            self.kept.len()
        } else {
            self.kept.rfind('\n').map_or(0, |n| n + 1)
        };
        let mut text = String::new();
        if upto > self.given {
            // The lines `given..upto` is made of, out of the whole text redacted:
            // the redaction keeps every line a line.
            let first = self.kept[..self.given].matches('\n').count();
            let new = &self.kept[self.given..upto];
            let count = new.matches('\n').count() + usize::from(!new.ends_with('\n'));
            let redacted = crate::redact::redact_secrets(&self.kept);
            let lines: Vec<&str> = redacted.split('\n').skip(first).take(count).collect();
            text = printable(lines.join("\n").trim());
            self.given = upto;
        }
        if self.cut && !self.cut_told {
            self.cut_told = true;
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(STDERR_CUT);
        }
        (!text.is_empty()).then_some(text)
    }
}

/// Wait for the device's answer to the subsystem request. `Ok` means the subsystem
/// is open, with any data that came before the answer.
///
/// **russh 0.65's `request_subsystem` does not wait for the answer.** With
/// `want_reply` set it queues the request and returns `Ok` at once; the device's
/// `SSH_MSG_CHANNEL_SUCCESS` or `SSH_MSG_CHANNEL_FAILURE` (RFC 4254 §5.4) arrives
/// later, on the channel, as `ChannelMsg::Success` or `ChannelMsg::Failure`. The
/// transport used to take the `Ok` for the answer. A device without NETCONF over
/// SSH refuses the subsystem and leaves the channel open, so the session was logged
/// as established, and the hello then waited out `per_rpc` for a reply that was
/// never coming — and ended as a timeout that named neither the cause nor the fix.
///
/// A failure, or a channel that ends before the answer, is `SubsystemUnavailable`
/// with what the device wrote on stderr. Data before the answer can only come from
/// a subsystem that runs, so it counts as open and is kept for the first `recv`.
/// The wait is bounded by the caller, as one step of the connection phase — see
/// `in_connect_phase`.
///
/// The refusal carries what the device said over SSH (0.5.13): an exit status or
/// signal that came before it, its banner, its disconnect message.
async fn await_subsystem(
    channel: &mut russh::Channel<russh::client::Msg>,
    stderr: &mut Stderr,
    said: &StdMutex<SshMessages>,
) -> Result<Option<Bytes>, NetconfError> {
    loop {
        match channel.wait().await {
            Some(russh::ChannelMsg::Success) => return Ok(None),
            Some(russh::ChannelMsg::Data { data }) => {
                return Ok(Some(Bytes::copy_from_slice(&data)));
            }
            Some(russh::ChannelMsg::ExtendedData { data, ext }) => {
                stderr.keep(&data, ext);
            }
            Some(russh::ChannelMsg::Failure)
            | Some(russh::ChannelMsg::Eof)
            | Some(russh::ChannelMsg::Close)
            | None => {
                return Err(NetconfError::Transport(
                    TransportError::SubsystemUnavailable {
                        // The connection ends here, so all of it goes.
                        stderr: stderr.take(true).unwrap_or_default(),
                        ssh: Box::new(said_now(said)),
                    },
                ));
            }
            Some(other) => note_exit(said, &other),
        }
    }
}

/// What a closed channel means. **If the device said something — on stderr, or over
/// SSH — THAT is the answer**: `Closed`, carrying it in `ssh` (0.5.13; `Io` with the
/// stderr before, and what it said over SSH was dropped. The stderr was part of
/// `detail` until 0.7.0). Otherwise an empty read is the signal the layer above
/// uses for «the peer hung up».
///
/// A separate function so the decision can be unit-tested without SSH, like
/// `recv_budget`.
fn close_outcome(ssh: SshMessages) -> Result<Bytes, NetconfError> {
    if ssh.is_empty() {
        return Ok(Bytes::new());
    }
    Err(NetconfError::Transport(TransportError::Closed {
        detail: "the device closed the netconf subsystem".into(),
        partial: String::new(),
        ssh: Box::new(ssh),
    }))
}

/// Keep `data`, sent after the session was closed, up to `cap` bytes in all
/// (0.7.0). How many bytes of it were not kept. What the device sends after the
/// close used to be kept without limit.
fn keep_late(after: &mut Vec<u8>, data: &[u8], cap: usize) -> usize {
    let room = cap.saturating_sub(after.len()).min(data.len());
    after.extend_from_slice(&data[..room]);
    data.len() - room
}

/// What the `Closed` for data sent after the session was closed says: that it
/// came, and when more came than is kept, how much came and how much is kept.
fn late_detail(kept: usize, dropped: usize) -> String {
    let came = "the device sent data after the session was closed";
    if dropped == 0 {
        return came.into();
    }
    format!(
        "{came}: {} B, more than is kept — the first {kept} B are here, and the rest was \
         dropped",
        kept.saturating_add(dropped)
    )
}

/// `e` with what the device wrote on stderr put in it, when `e` is a timeout
/// (0.7.0).
fn with_stderr(e: NetconfError, said: Option<String>) -> NetconfError {
    match e {
        NetconfError::Timeout { op, partial, .. } => NetconfError::Timeout {
            op,
            partial,
            stderr: said.unwrap_or_default(),
        },
        other => other,
    }
}

/// The SSH+NETCONF transport: one device, one channel.
pub struct RusshTransport {
    handle: russh::client::Handle<ClientHandler>,
    channel: russh::Channel<russh::client::Msg>,
    observed_host_key: Option<String>,
    /// What the subsystem wrote on stderr, and how much of it has been handed
    /// over. It used to be discarded silently.
    stderr: Stderr,
    /// Data that arrived before the device answered the subsystem request, handed
    /// out by the first `recv`. See `await_subsystem`.
    pending: Option<Bytes>,
    /// What the device has said over SSH: its banner and disconnect message, from
    /// the handler, and the subsystem's exit status or signal, from the channel. It
    /// goes with the error a closed channel or connection brings (0.5.13).
    said: Said,
    /// Whether the device has sent EOF on the channel: from then on a wait that
    /// runs out ends in the close outcome rather than a timeout.
    eof: bool,
    /// Whether the channel has closed, so `close` has nothing more to read.
    closed: bool,
    /// The session's limits. `per_rpc` — or `per_commit` while a commit is in
    /// flight — bounds how long a single `recv()` or `send()` may block, more tightly
    /// than russh's own `inactivity_timeout`.
    timeouts: Timeouts,
    /// Which of the two the request in flight runs under, as the session last said
    /// through `reply_budget`.
    budget: ReplyBudget,
    /// The session's hard deadline (`Timeouts::total`, with the clock started when
    /// connecting). Once reached, every further operation is
    /// `Timeout { op: "session-ttl" }` — regardless of activity.
    deadline: std::time::Instant,
}

/// The remaining waiting budget for one read: the smaller of the per-read limit —
/// `per_rpc`, or `per_commit` during a commit — and the time left until the session
/// deadline. `None` means the deadline has passed, so there is no waiting and the
/// failure is immediate. A separate function so the logic can be unit-tested
/// without SSH.
fn recv_budget(
    per_read: std::time::Duration,
    deadline: std::time::Instant,
    now: std::time::Instant,
) -> Option<std::time::Duration> {
    if now >= deadline {
        return None;
    }
    Some(per_read.min(deadline - now))
}

/// Run `step`, one wait while the connection is being established, under what is
/// left of the connection phase: it ends at `connect_by` — `Timeouts::connect` after
/// the phase began — and never past the session's `deadline`. Running out is
/// `Timeout { op: tag }`, or `Timeout { op: "session-ttl" }` when the deadline is what ran out.
///
/// Every wait in `connect` and in `observe_host_key` goes through here. russh bounds
/// none of them itself, beyond an inactivity timer that restarts on activity and is
/// set to the whole TTL. Authentication and opening the channel used to wait on that timer alone: a device
/// that took the handshake and never answered the login held `connect` for the
/// whole TTL, and russh then reported the ended session as a login the device had
/// turned down, with no methods — a false «wrong password».
///
/// A phase that is already over fails before the step starts, so nothing — the
/// password included — is sent after it.
async fn in_connect_phase<T>(
    step: impl std::future::Future<Output = T>,
    connect_by: std::time::Instant,
    deadline: std::time::Instant,
    tag: &'static str,
) -> Result<T, NetconfError> {
    let now = std::time::Instant::now();
    let budget = match recv_budget(connect_by.saturating_duration_since(now), deadline, now) {
        None => return Err(NetconfError::timeout("session-ttl")),
        Some(left) if left.is_zero() => return Err(NetconfError::timeout(tag)),
        Some(left) => left,
    };
    timeout(budget, step).await.map_err(|_| {
        if std::time::Instant::now() >= deadline {
            NetconfError::timeout("session-ttl")
        } else {
            NetconfError::timeout(tag)
        }
    })
}

/// A second handle on the TCP connection beneath an SSH session that is being set
/// up, which ends the connection when it is dropped.
///
/// russh runs the session in a task of its own, and that task owns the socket.
/// Giving up on a wait — dropping the future — does not end the task, and russh
/// 0.65 offers no call that does: there is no `Handle` until the key exchange is
/// done, `Handle::disconnect` only queues a message that the task reads when no key
/// exchange is running and no data is waiting to go out, and russh keeps the task's
/// join handle to itself, which detaches the task when dropped. So the task kept the
/// connection until its inactivity timer ran out — set to the session's TTL, and
/// restarted whenever the device sends anything. A device we had given up on kept
/// its connection for the whole TTL, or longer.
///
/// netconf therefore opens the TCP connection itself, hands russh the stream, and
/// keeps a clone of the socket here. Dropping this shuts the socket down in both
/// directions: the device sees the connection end at once, and russh's task, whose
/// reads now end, finishes and closes it. [`keep`](Self::keep) hands the connection
/// over to an established session, which ends it the ordinary way.
struct Tether(Option<std::net::TcpStream>);

impl Tether {
    /// Hold `tcp`: the stream to hand russh, and the tether that can cut it.
    fn hold(tcp: tokio::net::TcpStream) -> std::io::Result<(tokio::net::TcpStream, Tether)> {
        let tcp = tcp.into_std()?;
        let clone = tcp.try_clone()?;
        Ok((tokio::net::TcpStream::from_std(tcp)?, Tether(Some(clone))))
    }

    /// Let the connection live on: close our handle on it, not the connection.
    fn keep(mut self) {
        self.0.take();
    }
}

impl Drop for Tether {
    fn drop(&mut self) {
        if let Some(tcp) = self.0.take() {
            let _ = tcp.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// The TCP connection, the SSH handshake and the host key check, each a step of the
/// connection phase (see `in_connect_phase`), with the connection tethered so that
/// giving up ends it (see [`Tether`]).
///
/// The outer error is the phase running out. The inner one is russh's, for the
/// caller to classify and log; the connection is already cut by then.
async fn open_ssh(
    host: &str,
    port: u16,
    config: Arc<russh::client::Config>,
    handler: ClientHandler,
    connect_by: std::time::Instant,
    deadline: std::time::Instant,
    progress: &mut Progress,
) -> Result<Result<(russh::client::Handle<ClientHandler>, Tether), russh::Error>, NetconfError> {
    progress.begin();
    let tcp = in_connect_phase(
        tokio::net::TcpStream::connect((host, port)),
        connect_by,
        deadline,
        "ssh-connect",
    )
    .await?;
    let (tcp, tether) = match tcp.and_then(Tether::hold) {
        Ok(held) => held,
        Err(e) => return Ok(Err(e.into())),
    };
    progress.done(CheckStep::Tcp);
    let handle = in_connect_phase(
        russh::client::connect_stream(config, tcp, handler),
        connect_by,
        deadline,
        "ssh-connect",
    )
    .await?;
    Ok(handle.map(|handle| (handle, tether)))
}

/// Classify a russh connect error into the right transport branch: a host key
/// discrepancy becomes `HostKey`, an algorithm or key-exchange failure becomes
/// `Negotiation`, and everything else is `Io`.
///
/// **We match on russh's TYPES, not on the text of its messages.** There used to be a
/// string matcher here, and it was wrong in three cases: `Kex` and `KexInit` render
/// as «Key exchange ...» with a space, so a search for «kex» never found them, and
/// `WrongServerSig` contains none of the keywords at all. All three landed in `Io`.
///
/// That was not cosmetic. A consumer is expected to raise its own alarm on the
/// `HostKey` branch — it is either the wrong device or a machine-in-the-middle — and
/// a negotiation failure asks the operator for something quite different from a
/// plumbing error. The wrong branch means the wrong action.
///
/// Matching on types also makes us immune to russh rewording a message in a patch
/// release; a string matcher would have broken silently.
///
/// **No message is dropped.** Every branch carries russh's own text onwards in
/// `detail` or `Io`, including the one that ends in the generic branch — through
/// the filter (0.5.13), and so in the `ssh_connect_failed` event built from it.
fn classify_connect_err(e: russh::Error, observed: Option<String>) -> NetconfError {
    let detail = russh_text(&e);
    match e {
        // The device is not the one we pinned, or it cannot prove it is itself.
        // `WrongServerSig` is as much a question of identity as a rejected key: the
        // signature over the key exchange did not hold.
        russh::Error::UnknownKey
        | russh::Error::WrongServerSig
        | russh::Error::KeyChanged { .. } => {
            // The fingerprint the device presented travels WITH the error.
            // `check_server_key` saw the key before this point, so it is known here,
            // and a consumer should not have to connect again to learn who answered.
            NetconfError::Transport(TransportError::HostKey { observed, detail })
        }

        // russh gives the lists TYPED. To a client, `theirs` is exactly what the
        // device announced — the one piece of information an operator needs in front
        // of an old device that will not talk to us. It used to be `Vec::new()`.
        russh::Error::NoCommonAlgo { theirs, .. } => {
            NetconfError::Transport(TransportError::Negotiation {
                // The names as the device wrote them, made printable: russh checks
                // only that they are ASCII, and ASCII has control characters.
                offered: theirs.iter().map(|a| printable(a)).collect(),
                detail,
            })
        }

        // Key exchange never completed. We do not know which algorithm brought it
        // down — russh does not say here — but it is a negotiation failure, not a
        // broken connection.
        russh::Error::Kex | russh::Error::KexInit | russh::Error::UnknownAlgo => {
            NetconfError::Transport(TransportError::Negotiation {
                offered: Vec::new(),
                detail,
            })
        }

        // The rest is plumbing: the connection broke, time ran out, the packet was
        // malformed. The text travels on unchanged — we do not interpret it, we pass
        // it along.
        other => io_err(other),
    }
}

impl RusshTransport {
    /// The host key a consumer can pin, for enrollment. `None` until the handler has
    /// seen it.
    pub fn observed_host_key(&self) -> Option<String> {
        self.observed_host_key.clone()
    }

    /// [`connect`](NetconfTransport::connect), recording each step it completes and
    /// the time it took (0.7.0). `connect` discards the record; [`check_device`]
    /// reads it.
    async fn connect_steps(
        opts: &ConnectOptions,
        progress: &mut Progress,
    ) -> Result<Self, NetconfError> {
        // First, before the host and username go into the log events below.
        check_target(&opts.host, Some(opts.username.as_str()))?;

        // A legacy SSH policy is ALWAYS per device, never global, and every use should
        // be traceable. So we log which policy this connection actually runs with —
        // `LegacyJunos` and `Custom` at `warn`, because they are a deliberate weakening
        // that someone should be able to see afterwards. Never the password.
        let policy_name = match &opts.ssh_policy {
            SshPolicy::Modern => "modern",
            SshPolicy::LegacyJunos => "legacy-junos",
            SshPolicy::Custom { .. } => "custom",
        };
        let legacy_allowed = !matches!(opts.ssh_policy, SshPolicy::Modern);

        // BLIND TRUST-ON-FIRST-USE IS CLOSED.
        //
        // `connect()` authenticates — it **sends the network password**. Without a
        // pinned host key we do not know who answers at that address, and then the
        // password must not move. `check_server_key` used to accept any key when
        // `host_key` was `None`, and the password went out regardless.
        //
        // *Observing* a device is a different operation, and has its own path:
        // `observe_host_key()` runs key exchange and disconnects without
        // authenticating. It takes no credential parameter at all, so a password
        // cannot leak from it.
        if opts.host_key.is_none() {
            return Err(NetconfError::Transport(TransportError::Io(
                "no pinned host key — refusing to authenticate against an unverified \
                 device. Use observe_host_key() to fetch the fingerprint for approval first."
                    .into(),
            )));
        }

        // `Custom` promises «full manual control» in the API, but the names have to be
        // resolved against russh's typed constants, and that mapping is not built. We
        // cannot deliver what the API promises — and then we must **refuse**, not
        // quietly do something else. The previous choice, falling back to legacy, did
        // the opposite of what a consumer tightening things would expect.
        if matches!(opts.ssh_policy, SshPolicy::Custom { .. }) {
            return Err(NetconfError::Transport(TransportError::Io(
                CUSTOM_REFUSED.into(),
            )));
        }

        // The session TTL, fail-closed: the range is validated BEFORE anything
        // connects — and before the logging below (0.7.0; it came after it, and a
        // connect refused for its `Timeouts` spent the legacy warning).
        opts.timeouts
            .validate()
            .map_err(|m| NetconfError::Transport(TransportError::Io(m)))?;

        // Logged after the refusals above, so a connect that is refused does not
        // spend the device's one legacy warning on nothing. A connect that gets
        // here has a pinned host key: without one it was refused above.
        if !legacy_allowed {
            tracing::info!(
                event = "ssh_connect",
                host = %opts.host,
                port = opts.port,
                username = %opts.username,
                ssh_policy = policy_name,
                host_key = "pinned",
                "connecting to a device over SSH"
            );
        } else if warn_legacy_once(&opts.host) {
            // The first time for this device: the full warning.
            tracing::warn!(
                event = "ssh_connect",
                legacy = true,
                host = %opts.host,
                port = opts.port,
                username = %opts.username,
                ssh_policy = policy_name,
                host_key = "pinned",
                "LEGACY: connecting with an ssh policy that permits algorithms outside \
                 today's recommendations — a per-device opt-in, and not recommended"
            );
        } else {
            // Afterwards: still tagged `legacy`, and the word is still in the message,
            // but without the noise.
            tracing::info!(
                event = "ssh_connect",
                legacy = true,
                host = %opts.host,
                port = opts.port,
                username = %opts.username,
                ssh_policy = policy_name,
                host_key = "pinned",
                "LEGACY: connecting to a device with an ssh policy outside the current recommendation (see first warning)"
            );
        }

        // The clock of the session TTL starts HERE — when connecting, not at the
        // first RPC.
        let started = std::time::Instant::now();
        let deadline = started + opts.timeouts.total;
        // The connection phase starts on the same clock. Every wait until `connect`
        // returns ends by `connect_by`, and never past `deadline`: see
        // `in_connect_phase`. `connect` is not capped by `validate`, so one too large
        // to add simply leaves the deadline as the bound.
        let connect_by = started
            .checked_add(opts.timeouts.connect)
            .unwrap_or(deadline);

        let mut config = russh::client::Config {
            // Not what bounds any wait: `in_connect_phase` bounds each one while
            // connecting, and `send` and `recv` bound theirs after that. russh's
            // inactivity clock RESETS on activity and is set once for the session's
            // whole life, so it is not the lifetime limit either — that is
            // `deadline` above. It stays at the TTL: set to `connect`, it would end
            // an established session that sat idle for that long.
            inactivity_timeout: Some(opts.timeouts.total),
            ..Default::default()
        };
        config.preferred = preferred_for(&opts.ssh_policy);
        let config = Arc::new(config);

        let observed = Arc::new(StdMutex::new(None));
        let said: Said = Arc::default();
        let handler = ClientHandler {
            pinned: opts.host_key.clone(),
            observed: observed.clone(),
            said: said.clone(),
        };

        // The TCP connection, the handshake and the host key check. From here until
        // `connect` returns `Ok`, every way out — a phase running out, a refusal, an
        // error — drops `tether`, and the device sees the connection end.
        let (mut handle, tether) = open_ssh(
            &opts.host, opts.port, config, handler, connect_by, deadline, progress,
        )
        .await?
        // Classify: a host key pin mismatch becomes HostKey, a key exchange or
        // algorithm failure becomes Negotiation.
        .map_err(|e| {
            // `check_server_key` has already put the fingerprint here if it got
            // as far as seeing the key. We read it BEFORE building the error, so
            // it travels out with it.
            let seen = observed.lock().unwrap_or_else(|p| p.into_inner()).clone();
            let err = classify_connect_err(e, seen);
            tracing::warn!(
                event = "ssh_connect_failed",
                host = %opts.host,
                port = opts.port,
                ssh_policy = policy_name,
                error = %err,
                "SSH connection failed"
            );
            err
        })?;
        progress.done(CheckStep::Ssh);
        progress.fingerprint = observed.lock().unwrap_or_else(|p| p.into_inner()).clone();

        // Password authentication. The cleartext is taken transiently from the
        // SecretString right before use. Our copy is wrapped in `Zeroizing` so it is
        // cleared on drop; russh makes its own owned `String` internally, which is
        // outside our control.
        let Auth::Password(secret) = &opts.auth;
        let password = zeroize::Zeroizing::new(secret.expose_str(|s| s.to_string()));
        // A failure here and below may be the device ending the connection; what it
        // said over SSH goes with it (0.5.13).
        let authed = in_connect_phase(
            handle.authenticate_password(opts.username.as_str(), password.as_str()),
            connect_by,
            deadline,
            "ssh-connect",
        )
        .await?
        .map_err(|e| ended(e, said_now(&said)))?;
        if let russh::client::AuthResult::Failure {
            remaining_methods,
            partial_success,
        } = &authed
        {
            // The device's own words, not ours. See `TransportError::AuthRejected`.
            let methods: Vec<String> = remaining_methods.iter().map(String::from).collect();
            let named = methods.join(", ");
            let rejected = TransportError::AuthRejected {
                username: opts.username.clone(),
                remaining_methods: methods,
                partial_success: *partial_success,
            };
            tracing::warn!(
                event = "ssh_auth_failed",
                host = %opts.host,
                username = %opts.username,
                partial_success = *partial_success,
                remaining_methods = %named,
                "{rejected}"
            );
            return Err(NetconfError::Transport(rejected));
        }
        progress.done(CheckStep::Login);

        let mut channel = in_connect_phase(
            handle.channel_open_session(),
            connect_by,
            deadline,
            "ssh-connect",
        )
        .await?
        .map_err(|e| ended(e, said_now(&said)))?;
        // The `netconf` subsystem on the SSH session (RFC 6242). The port is SSH's own
        // and lives in `opts.port`; it does not belong here. The request is queued,
        // not answered: the device's answer is read here, and the session is
        // established only once it is a yes.
        let mut stderr = Stderr::new();
        let answer = in_connect_phase(
            async {
                channel
                    .request_subsystem(true, "netconf")
                    .await
                    .map_err(|e| ended(e, said_now(&said)))?;
                await_subsystem(&mut channel, &mut stderr, &said).await
            },
            connect_by,
            deadline,
            "ssh-subsystem",
        )
        .await;
        // A device that wrote why and then never answered: the attempt ends here,
        // so all it wrote goes with the timeout (0.7.0).
        let pending = match answer {
            Ok(answer) => answer?,
            Err(e) => return Err(with_stderr(e, stderr.take(true))),
        };
        progress.done(CheckStep::Netconf);

        let observed_host_key = observed.lock().unwrap_or_else(|p| p.into_inner()).clone();
        tracing::info!(
            event = "ssh_session_established",
            host = %opts.host,
            username = %opts.username,
            ssh_policy = policy_name,
            "SSH session up, NETCONF subsystem opened"
        );
        // Established: from here the session ends the connection, through `close`.
        tether.keep();
        Ok(RusshTransport {
            handle,
            channel,
            observed_host_key,
            stderr,
            pending,
            said,
            eof: false,
            closed: false,
            timeouts: opts.timeouts,
            budget: ReplyBudget::PerRpc,
            deadline,
        })
    }
}

/// How far a connection has come, and how long each step took (0.7.0) — see
/// [`check_device`].
#[derive(Default)]
struct Progress {
    /// When the step in progress began. `None` until the connection is started:
    /// what `connect` refuses before that has checked nothing.
    mark: Option<std::time::Instant>,
    /// The steps completed, in order, each with the time it took.
    steps: Vec<(CheckStep, std::time::Duration)>,
    /// The fingerprint of the host key the device presented, once the handshake
    /// has gone through.
    fingerprint: Option<String>,
}

impl Progress {
    /// The connection is started: the first step is in progress from now.
    fn begin(&mut self) {
        self.mark = Some(std::time::Instant::now());
    }

    /// `step` is completed; the next one is in progress from now.
    fn done(&mut self, step: CheckStep) {
        let now = std::time::Instant::now();
        let took = self.mark.map_or_else(Default::default, |mark| now - mark);
        self.steps.push((step, took));
        self.mark = Some(now);
    }
}

/// Devices we have already warned about legacy use for.
static WARNED_LEGACY: StdMutex<Option<std::collections::BTreeSet<String>>> = StdMutex::new(None);

/// `true` the first time this device is connected to under a legacy policy, and
/// `false` afterwards. One warning is enough: every later event still carries the
/// `legacy` tag, so the use stays visible. If the lock fails we warn once too often
/// rather than stay silent.
fn warn_legacy_once(host: &str) -> bool {
    match WARNED_LEGACY.lock() {
        Ok(mut guard) => guard
            .get_or_insert_with(std::collections::BTreeSet::new)
            .insert(host.to_string()),
        Err(_) => true,
    }
}

/// The preferred algorithms for each policy.
///
/// russh's `Preferred::DEFAULT` is deliberately modern-only — no SHA-1 key exchange,
/// no `ssh-rsa`, no CBC or 3DES — and **fails against older releases**, so the lists
/// are set explicitly here.
///
/// `LegacyJunos` is a **superset**: the modern algorithms come first and the legacy
/// ones form the tail. The peer chooses, so a modern device uses modern algorithms
/// regardless. That is why the policy is *permitting* rather than *preferring*.
///
/// A known limit of the library beneath us: russh 0.65 has no `hmac-md5`. A device
/// offering ONLY that cannot be reached through this transport at all, and would need
/// a different SSH implementation behind the same trait.
fn preferred_for(policy: &SshPolicy) -> russh::Preferred {
    use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
    use russh::{cipher, kex, mac};

    // Today's recommendation. It extends the russh default with ecdh-nistp, which
    // Junos offers.
    const MODERN_KEX: &[kex::Name] = &[
        kex::CURVE25519,
        kex::CURVE25519_PRE_RFC_8731,
        kex::DH_G16_SHA512,
        kex::DH_G14_SHA256,
        kex::ECDH_SHA2_NISTP256,
        kex::ECDH_SHA2_NISTP384,
        kex::ECDH_SHA2_NISTP521,
    ];
    const MODERN_KEY: &[Algorithm] = &[
        Algorithm::Ed25519,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        },
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        },
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        },
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        },
    ];
    const MODERN_CIPHER: &[cipher::Name] = &[
        cipher::CHACHA20_POLY1305,
        cipher::AES_256_GCM,
        cipher::AES_256_CTR,
        cipher::AES_192_CTR,
        cipher::AES_128_CTR,
    ];
    const MODERN_MAC: &[mac::Name] = &[
        mac::HMAC_SHA512_ETM,
        mac::HMAC_SHA256_ETM,
        mac::HMAC_SHA512,
        mac::HMAC_SHA256,
    ];

    // The superset: modern first, then what russh has besides — group exchange and
    // group 18 at full strength, then the SHA-1 tail for older releases. The span is
    // R14 to Evo, and nothing russh can do is held back from it.
    const LEGACY_KEX: &[kex::Name] = &[
        kex::CURVE25519,
        kex::CURVE25519_PRE_RFC_8731,
        kex::DH_G16_SHA512,
        kex::DH_G14_SHA256,
        kex::ECDH_SHA2_NISTP256,
        kex::ECDH_SHA2_NISTP384,
        kex::ECDH_SHA2_NISTP521,
        kex::DH_G18_SHA512,
        kex::DH_GEX_SHA256,
        kex::DH_G14_SHA1,
        kex::DH_GEX_SHA1,
        kex::DH_G1_SHA1,
    ];
    const LEGACY_KEY: &[Algorithm] = &[
        Algorithm::Ed25519,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        },
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        },
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        },
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        },
        // `ssh-rsa` (SHA-1) and `ssh-dss` — the legacy tail, for old Junos.
        Algorithm::Rsa { hash: None },
        Algorithm::Dsa,
    ];
    // 3des-cbc is DELIBERATELY absent. A survey of four real devices showed that the
    // modern list alone covered all of them: the 3DES tail protected nothing and was
    // pure attack surface. Should a device turn up that can do nothing else, that is
    // a deliberate decision to take then, not a default.
    const LEGACY_CIPHER: &[cipher::Name] = &[
        cipher::CHACHA20_POLY1305,
        cipher::AES_256_GCM,
        cipher::AES_256_CTR,
        cipher::AES_192_CTR,
        cipher::AES_128_CTR,
        cipher::AES_256_CBC,
        cipher::AES_192_CBC,
        cipher::AES_128_CBC,
    ];
    const LEGACY_MAC: &[mac::Name] = &[
        mac::HMAC_SHA512_ETM,
        mac::HMAC_SHA256_ETM,
        mac::HMAC_SHA512,
        mac::HMAC_SHA256,
        mac::HMAC_SHA1_ETM,
        mac::HMAC_SHA1,
    ];

    // No host certificate algorithm is advertised under any policy, whatever
    // russh's default (0.6.1): the pin is a key, and `check_server_key` refuses
    // a certificate.
    let base = russh::Preferred {
        host_key_certificates: std::borrow::Cow::Borrowed(&[]),
        ..russh::Preferred::default()
    };
    match policy {
        SshPolicy::Modern => russh::Preferred {
            kex: MODERN_KEX.into(),
            key: MODERN_KEY.into(),
            cipher: MODERN_CIPHER.into(),
            mac: MODERN_MAC.into(),
            ..base
        },
        SshPolicy::LegacyJunos => russh::Preferred {
            kex: LEGACY_KEX.into(),
            key: LEGACY_KEY.into(),
            cipher: LEGACY_CIPHER.into(),
            mac: LEGACY_MAC.into(),
            ..base
        },
        // Custom is NOT implemented, and therefore falls back to the STRICTEST list,
        // not the loosest.
        //
        // This arm used to return the legacy lists, which meant a consumer choosing
        // `Custom` in order to *tighten* things got `3des-cbc`, `ssh-rsa` and
        // `diffie-hellman-group1-sha1` switched on instead — fail-open, in a crate
        // whose floor is fail-closed.
        //
        // `connect()` and `observe_host_key()` refuse `Custom` with a clear error, so
        // this branch should not be reached in practice. It reads `Modern` because a
        // defence in depth must never point at the weakest option.
        SshPolicy::Custom { .. } => base,
    }
}

impl RusshTransport {
    /// What the device has said over SSH, with what it wrote on stderr and has not
    /// been handed over yet (0.7.0): the lines it has ended, and at the `end` of
    /// the session the rest.
    fn said(&mut self, end: bool) -> SshMessages {
        let mut ssh = said_now(&self.said);
        ssh.stderr = self.stderr.take(end);
        ssh
    }

    /// A `Timeout` for `op`, with what the device wrote on stderr (0.7.0). The
    /// session goes on, so it is the lines the device has ended.
    fn timed_out(&mut self, op: &'static str) -> NetconfError {
        with_stderr(NetconfError::timeout(op), self.stderr.take(false))
    }
}

#[async_trait]
impl NetconfTransport for RusshTransport {
    async fn connect(opts: &ConnectOptions) -> Result<Self, NetconfError> {
        Self::connect_steps(opts, &mut Progress::default()).await
    }

    fn reply_budget(&mut self, budget: ReplyBudget) {
        self.budget = budget;
    }

    async fn send(&mut self, bytes: &[u8]) -> Result<(), NetconfError> {
        // The same budget as a read: the smaller of the per-read limit and what is
        // left of the session. A device that stops reading fills the SSH window, and
        // `channel.data` then waits for space that never comes. Before, only
        // russh's inactivity timer bounded that wait — and it is set to the whole
        // TTL, so a stuck send held the session for its entire lifetime.
        let Some(budget) = recv_budget(
            self.timeouts.per_read(self.budget),
            self.deadline,
            std::time::Instant::now(),
        ) else {
            return Err(self.timed_out("session-ttl"));
        };
        // &[u8] implements AsyncRead, so russh sends it as channel data. A send that
        // fails has found the channel or the connection gone; what the device said
        // over SSH goes with it (0.5.13), and what it wrote on stderr (0.7.0).
        match timeout(budget, self.channel.data(bytes)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(ended(e, self.said(true))),
            Err(_) if std::time::Instant::now() >= self.deadline => {
                Err(self.timed_out("session-ttl"))
            }
            Err(_) => Err(self.timed_out("rpc-send")),
        }
    }

    fn take_stderr(&mut self) -> Option<String> {
        self.stderr.take(false)
    }

    async fn recv(&mut self) -> Result<Bytes, NetconfError> {
        // One clock for the whole read (0.7.0). The limit used to start again for
        // every message on the channel, and the ones that carry no data — stderr,
        // an exit status — do not end the read: a device that kept sending those
        // held one read until the session's deadline.
        let read_by = std::time::Instant::now() + self.timeouts.per_read(self.budget);
        loop {
            // Both the per-read deadline AND the session deadline: never wait longer
            // than the smaller of what is left of the per-read limit — `per_rpc`, or
            // `per_commit` during a commit — and the remaining TTL. A device that
            // stops answering part-way through an RPC does not hang us, and a
            // session lives never past its total lifetime, regardless of activity.
            let now = std::time::Instant::now();
            let left = recv_budget(read_by.saturating_duration_since(now), self.deadline, now);
            let budget = match left {
                Some(left) if !left.is_zero() => left,
                // After the device's EOF, the wait for what follows it ends in the
                // close outcome, however it ends.
                _ if self.eof => return close_outcome(self.said(true)),
                Some(_) => return Err(self.timed_out("rpc-recv")),
                None => return Err(self.timed_out("session-ttl")),
            };
            if let Some(data) = self.pending.take() {
                return Ok(data);
            }
            let msg = match timeout(budget, self.channel.wait()).await {
                Ok(msg) => msg,
                Err(_) if self.eof => {
                    return close_outcome(self.said(true));
                }
                Err(_) if std::time::Instant::now() >= self.deadline => {
                    return Err(self.timed_out("session-ttl"));
                }
                Err(_) => return Err(self.timed_out("rpc-recv")),
            };
            match msg {
                Some(russh::ChannelMsg::Data { data }) => {
                    return Ok(Bytes::copy_from_slice(&data));
                }
                // **stderr from the subsystem — never discarded.** This is where Junos
                // puts its explanation when something is wrong with the subsystem
                // itself, and it is often the only text that says WHY. It used to be
                // ignored, so a device that explained itself and then hung up left the
                // operator with «peer closed before a complete message» and nothing
                // else. See `Stderr`.
                Some(russh::ChannelMsg::ExtendedData { data, ext }) => {
                    self.stderr.keep(&data, ext);
                    continue;
                }
                // The device's EOF: it sends no more data, but what follows it is
                // still read (0.5.13) — the subsystem's exit status and signal, which
                // an SSH server may send after its EOF, and the close. Data that
                // comes all the same is handed on like any other; it used to be
                // dropped, and `recv` returned at the EOF before any of it came.
                Some(russh::ChannelMsg::Eof) => {
                    self.eof = true;
                    continue;
                }
                Some(russh::ChannelMsg::Close) | None => {
                    self.closed = true;
                    return close_outcome(self.said(true));
                }
                Some(other) => {
                    note_exit(&self.said, &other);
                    continue;
                }
            }
        }
    }

    /// Send EOF on the channel, read what the device sends until it closes the
    /// channel, then disconnect — and return what the device said over SSH
    /// (0.5.13).
    ///
    /// The EOF ends the subsystem's input, and the device ends the subsystem: its
    /// exit status or signal, and its close, are read here, so they are not lost.
    /// The wait is a read like any other, bounded by `per_rpc` and the session's
    /// deadline; a device that keeps the channel open past it is disconnected all
    /// the same. Data the device sends after the session is over is no answer to
    /// anything, and is returned as `Closed`, in `partial`, rather than dropped.
    ///
    /// russh fails the EOF and the disconnect with `SendError` only when the SSH
    /// connection has already ended — the device ended it first, which after
    /// `<close-session/>` it may. There is nothing to send them on then, and
    /// nothing from the device in the failure: what it said is in what is
    /// returned. Any other failure is returned, with what the device said. Both used
    /// to be ignored.
    async fn close(mut self) -> Result<SshMessages, NetconfError> {
        // Data from the device after the session was over.
        let mut late = None;
        if !self.closed {
            match self.channel.eof().await {
                Ok(()) | Err(russh::Error::SendError) => {}
                Err(e) => return Err(ended(e, self.said(true))),
            }
            // What comes after the close is kept up to the size of one message.
            let (mut after, mut dropped) = (Vec::new(), 0_usize);
            // One clock for the whole wait (0.7.0), as for a read.
            let closed_by = std::time::Instant::now() + self.timeouts.per_read(ReplyBudget::PerRpc);
            loop {
                let now = std::time::Instant::now();
                let left =
                    recv_budget(closed_by.saturating_duration_since(now), self.deadline, now);
                let Some(budget) = left.filter(|left| !left.is_zero()) else {
                    break;
                };
                match timeout(budget, self.channel.wait()).await {
                    Err(_) | Ok(None) | Ok(Some(russh::ChannelMsg::Close)) => break,
                    Ok(Some(russh::ChannelMsg::Data { data })) => {
                        let lost = keep_late(&mut after, &data, DEFAULT_MAX_MESSAGE);
                        dropped = dropped.saturating_add(lost);
                    }
                    Ok(Some(russh::ChannelMsg::ExtendedData { data, ext })) => {
                        self.stderr.keep(&data, ext);
                    }
                    Ok(Some(other)) => note_exit(&self.said, &other),
                }
            }
            if !after.is_empty() {
                late = Some(NetconfError::Transport(TransportError::Closed {
                    detail: late_detail(after.len(), dropped),
                    partial: crate::wire::bytes_as_text(&after),
                    ssh: Box::new(self.said(true)),
                }));
            }
        }
        let disconnected = match self
            .handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
        {
            Ok(()) | Err(russh::Error::SendError) => None,
            Err(e) => Some(ended(e, self.said(true))),
        };
        tracing::info!(event = "ssh_session_closed", "SSH session closed");
        match (late, disconnected) {
            (None, None) => Ok(self.said(true)),
            (Some(e), None) | (None, Some(e)) => Err(e),
            (Some(e), Some(d)) => Err(NetconfError::CleanupFailed {
                error: Box::new(e),
                cleanup: vec![("disconnect", d)],
            }),
        }
    }
}

/// Observe a device's host key **without authenticating** — the enrollment step.
///
/// Enrollment has an ordering trap: we must not send a password to a device we have
/// not verified, but we cannot verify the device without having seen its host key.
/// Taken seriously, that trap means enrollment can never complete — and in practice
/// it becomes trust-on-first-use anyway.
///
/// The way out is in SSH itself: **the host key is presented during key exchange,
/// before authentication.** This function therefore runs key exchange, reads the
/// fingerprint and disconnects. It takes **no credential parameter at all**, so a
/// password being unable to leak from here is a property of the signature rather than
/// a rule someone has to remember.
///
/// It runs under `timeouts` as [`RusshTransport::connect`] does (0.5.9): they are
/// validated the same way, and the TCP connection and key exchange end within
/// `connect`, counted from the start, and never past `total`. Running out is
/// `Timeout { op: "ssh-connect" }`, or `Timeout { op: "session-ttl" }` when `total` is what ran
/// out.
///
/// It pins nothing. It *returns* a fingerprint; the step from observed to approved
/// belongs to the consumer, and requires a person.
pub async fn observe_host_key(
    host: &str,
    port: u16,
    ssh_policy: &SshPolicy,
    timeouts: &crate::transport::Timeouts,
) -> Result<String, NetconfError> {
    // First, before the host goes into the log events below.
    check_target(host, None)?;

    let policy_name = match ssh_policy {
        SshPolicy::Modern => "modern",
        SshPolicy::LegacyJunos => "legacy-junos",
        SshPolicy::Custom { .. } => "custom",
    };
    tracing::info!(
        event = "ssh_host_key_probe",
        host = %host,
        port,
        ssh_policy = policy_name,
        "observing host key without authentication (enrollment)"
    );

    // The refusals `connect()` makes, for what the probe uses, before anything goes
    // on the wire. `Custom` used to fall back to russh's default list here without
    // saying so.
    if matches!(ssh_policy, SshPolicy::Custom { .. }) {
        return Err(NetconfError::Transport(TransportError::Io(
            CUSTOM_REFUSED.into(),
        )));
    }

    // The same limits as `connect()`, on the same clock: the frame is validated
    // before anything connects, and the probe is a connection phase like the one in
    // `connect()` — it ends `connect` after it began, and never past `total`. It used
    // to take `connect` alone, unvalidated: `total` did not bound it, and a `connect`
    // of any size was waited out in full.
    timeouts
        .validate()
        .map_err(|m| NetconfError::Transport(TransportError::Io(m)))?;
    let started = std::time::Instant::now();
    let deadline = started + timeouts.total;
    let connect_by = started.checked_add(timeouts.connect).unwrap_or(deadline);

    let mut config = russh::client::Config {
        // Not what bounds the probe: `in_connect_phase` does. It is set no longer
        // than the phase can last, so nothing of the probe outlives it.
        inactivity_timeout: Some(timeouts.connect.min(timeouts.total)),
        ..Default::default()
    };
    config.preferred = preferred_for(ssh_policy);

    let observed = Arc::new(StdMutex::new(None));
    let handler = ClientHandler {
        // No pin: we are here precisely because there is none. With one, a probe would
        // be pointless — a differing key already stops the connection.
        pinned: None,
        observed: observed.clone(),
        // The probe ends before the login, so there is nothing for the device to say.
        said: Arc::default(),
    };

    // Every way out of the probe drops `tether`, and the device sees the connection
    // end at once — when it gives up, and when it has what it came for.
    let (handle, tether) = open_ssh(
        host,
        port,
        Arc::new(config),
        handler,
        connect_by,
        deadline,
        &mut Progress::default(),
    )
    .await?
    .map_err(|e| {
        let seen = observed.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let err = classify_connect_err(e, seen);
        tracing::warn!(
            event = "ssh_host_key_probe_failed",
            host = %host,
            port,
            ssh_policy = policy_name,
            error = %err,
            "could not observe host key"
        );
        err
    })?;

    let fp = observed.lock().unwrap_or_else(|p| p.into_inner()).clone();
    // Disconnect at once. We have what we came for, and an open unauthenticated
    // connection has no reason to stay up.
    drop(handle);
    drop(tether);

    let fp = fp.ok_or_else(|| {
        NetconfError::Transport(TransportError::Io(
            "the SSH connection yielded no host key to observe".into(),
        ))
    })?;
    tracing::info!(
        event = "ssh_host_key_observed",
        host = %host,
        port,
        fingerprint = %fp,
        "host key observed — the consumer must have a human approve it"
    );
    Ok(fp)
}

/// A step of [`check_device`], in the order they are taken (0.7.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckStep {
    /// The TCP connection: the device is reachable.
    Tcp,
    /// The SSH handshake and the host key check: it is the device that was pinned.
    Ssh,
    /// The login: the device lets the user in.
    Login,
    /// The channel and the `netconf` subsystem: NETCONF over SSH is there.
    Netconf,
    /// The hello exchange: the NETCONF service answers.
    Hello,
    /// One request and its reply — `<close-session/>`, answered with `<ok/>`: the
    /// device handles a request.
    Request,
}

impl std::fmt::Display for CheckStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CheckStep::Tcp => "the TCP connection",
            CheckStep::Ssh => "the SSH handshake and host key",
            CheckStep::Login => "the login",
            CheckStep::Netconf => "the NETCONF subsystem",
            CheckStep::Hello => "the hello",
            CheckStep::Request => "the request",
        })
    }
}

/// What a [`DeviceCheck`] comes to, in one word (0.7.0) — see
/// [`DeviceCheck::verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// Every step answered, in less than a tenth of the time the check was given.
    Ok,
    /// Every step answered, in less than half of the time.
    Slow,
    /// Every step answered, and it took half of the time or more.
    VerySlow,
    /// The device was reached, and a step after that did not answer or was refused.
    Dead,
    /// No TCP connection: the device, or the network to it, is not there.
    NoContact,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Verdict::Ok => "ok",
            Verdict::Slow => "a bit slow",
            Verdict::VerySlow => "very slow",
            Verdict::Dead => "dead",
            Verdict::NoContact => "no contact",
        })
    }
}

/// What [`check_device`] found (0.7.0): every step it took with the time it took,
/// where it stopped and why, and what the device showed on the way.
///
/// The report is always whole. How much of it to read is the consumer's choice:
///
/// - **One word:** [`verdict`](Self::verdict).
/// - **One line:** [`summary`](Self::summary) — the verdict, the time, and where
///   and why it stopped.
/// - **Everything:** `Display` writes the summary and a line for each step and
///   each thing the device showed; the same is there as data in
///   [`steps`](Self::steps), [`stopped`](Self::stopped) and the rest.
#[derive(Debug)]
pub struct DeviceCheck {
    limit: std::time::Duration,
    steps: Vec<(CheckStep, std::time::Duration)>,
    stopped: Option<(CheckStep, std::time::Duration, NetconfError)>,
    fingerprint: Option<String>,
    capabilities: Vec<String>,
    session_id: Option<u64>,
    banner: Option<String>,
    stderr: Option<String>,
}

impl DeviceCheck {
    /// The check in one word. Every step answered: `Ok` in less than a tenth of
    /// [`limit`](Self::limit), `Slow` in less than half of it, `VerySlow` otherwise.
    /// A step stopped: `NoContact` when it was the TCP connection, `Dead` when it
    /// was any step after it.
    ///
    /// The bounds follow the time limit the check was given, not fixed seconds: a
    /// consumer that wants «slow» to mean something else gives another limit.
    pub fn verdict(&self) -> Verdict {
        match &self.stopped {
            Some((CheckStep::Tcp, ..)) => Verdict::NoContact,
            Some(_) => Verdict::Dead,
            None => {
                let elapsed = self.elapsed();
                if elapsed * 10 < self.limit {
                    Verdict::Ok
                } else if elapsed * 2 < self.limit {
                    Verdict::Slow
                } else {
                    Verdict::VerySlow
                }
            }
        }
    }

    /// The check in one line: the verdict and the time it took, and when a step
    /// stopped, which one and the error it stopped with.
    pub fn summary(&self) -> String {
        let seconds = |d: std::time::Duration| format!("{:.3}s", d.as_secs_f64());
        let verdict = self.verdict();
        let limit = seconds(self.limit);
        match &self.stopped {
            None => format!(
                "{verdict} — every step answered, in {} of {limit}",
                seconds(self.elapsed())
            ),
            Some((step, _, error)) => format!(
                "{verdict} — stopped at {step} after {} of {limit}: {error}",
                seconds(self.elapsed())
            ),
        }
    }

    /// The time the whole check took, a step that stopped included.
    pub fn elapsed(&self) -> std::time::Duration {
        let stopped = self.stopped.as_ref().map_or_else(Default::default, |s| s.1);
        self.steps
            .iter()
            .map(|(_, took)| *took)
            .sum::<std::time::Duration>()
            + stopped
    }

    /// The time the check was given: `Timeouts::connect` of the options it ran
    /// with.
    pub fn limit(&self) -> std::time::Duration {
        self.limit
    }

    /// The steps that answered, in the order they were taken, each with the time it
    /// took.
    pub fn steps(&self) -> &[(CheckStep, std::time::Duration)] {
        &self.steps
    }

    /// The step that did not answer or was refused, with the error it stopped with
    /// — the error `connect` or the session would have returned, the device's own
    /// words in it, redacted. `None` when every step answered.
    pub fn stopped(&self) -> Option<(CheckStep, &NetconfError)> {
        self.stopped.as_ref().map(|(step, _, error)| (*step, error))
    }

    /// The fingerprint of the host key the device presented, when the handshake
    /// got far enough to see it.
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }

    /// The capabilities of the device's hello. Empty when the check stopped before
    /// it.
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// The session id of the device's hello, when it sent one.
    pub fn session_id(&self) -> Option<u64> {
        self.session_id
    }

    /// The banner the device showed before the login, when the check ran to its
    /// end and the device showed one. Redacted, as everything the device says is
    /// before a policy is bound.
    pub fn banner(&self) -> Option<&str> {
        self.banner.as_deref()
    }

    /// What the device wrote on the subsystem's stderr during the check, when the
    /// check ran to its end and the device wrote something. A device that answers
    /// every step can still be saying that something is wrong. When the check
    /// stopped, the text is in the error of [`stopped`](Self::stopped). Redacted and
    /// printable — see [`SshMessages::stderr`].
    pub fn stderr(&self) -> Option<&str> {
        self.stderr.as_deref()
    }
}

impl std::fmt::Display for DeviceCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())?;
        for (step, took) in &self.steps {
            write!(f, "\n  {step}: {:.3}s", took.as_secs_f64())?;
        }
        if let Some((step, took, _)) = &self.stopped {
            write!(f, "\n  {step}: stopped after {:.3}s", took.as_secs_f64())?;
        }
        if let Some(fingerprint) = &self.fingerprint {
            write!(f, "\n  host key: {}", printable(fingerprint))?;
        }
        if let Some(id) = self.session_id {
            write!(f, "\n  session id: {id}")?;
        }
        if !self.capabilities.is_empty() {
            write!(f, "\n  capabilities: {}", self.capabilities.join(" "))?;
        }
        if let Some(banner) = &self.banner {
            write!(f, "\n  banner: {}", printable(banner))?;
        }
        if let Some(stderr) = &self.stderr {
            write!(f, "\n  stderr: {stderr}")?;
        }
        Ok(())
    }
}

/// Check that a device is there and answers NETCONF (0.7.0), and say how far a
/// connection gets and how long each step takes.
///
/// **It is the tool for after a timeout.** A request that timed out says the device
/// has a problem, and not which: gone from the network, a login that hangs, a
/// NETCONF service that does not answer. A `Timeout` from `connect` does not say it
/// either — the TCP connection, the handshake, the login and the channel share one
/// time limit and one name. This function takes the steps one by one and reports on
/// each. The crate never runs it by itself, and decides nothing from it: the
/// consumer does.
///
/// It takes what a connection takes, and does what one does: the TCP connection,
/// the SSH handshake with the host key check, the login, the `netconf` subsystem,
/// the hello exchange, and one request — `<close-session/>`, which the device
/// answers with `<ok/>`. That is one connection, one login and one NETCONF session,
/// opened and closed: no configuration is read and no command is run, and no policy
/// is needed. Lighter still is [`observe_host_key`], which stops before the login.
///
/// **One clock.** The whole check runs within `Timeouts::connect`, counted from
/// when it starts, and never past `total`; a short limit makes a quick check. A
/// step that runs out of it is the step the check stopped at.
///
/// **Always a report.** Once the connection is started, what comes back is a
/// [`DeviceCheck`], whether every step answered or one stopped — the step, and the
/// error `connect` would have returned, are in it. `Err` is only what `connect`
/// refuses before anything is connected — no pinned host key, `SshPolicy::Custom`,
/// time limits out of range, a host or username that cannot be right: then nothing
/// was checked.
///
/// **Nothing is left behind.** The connection is ended when the check is over,
/// however it ended.
pub async fn check_device(opts: &ConnectOptions) -> Result<DeviceCheck, NetconfError> {
    use crate::session::{NetconfSession, redact_content};

    let limit = opts.timeouts.connect;
    let mut progress = Progress::default();
    let mut check = DeviceCheck {
        limit,
        steps: Vec::new(),
        stopped: None,
        fingerprint: None,
        capabilities: Vec::new(),
        session_id: None,
        banner: None,
        stderr: None,
    };
    // What is left of the one clock, for the steps after `connect`.
    let started = std::time::Instant::now();
    let left = || limit.saturating_sub(started.elapsed());
    // The step in progress stopped with `error`: the report as it stands.
    let stop = |mut check: DeviceCheck, mut progress: Progress, step, error: NetconfError| {
        let took = progress
            .mark
            .map_or_else(Default::default, |mark| mark.elapsed());
        check.steps = std::mem::take(&mut progress.steps);
        // The key the device presented: from a handshake that went through, or from
        // the error of one that was refused for it.
        if check.fingerprint.is_none() {
            check.fingerprint = match &error {
                NetconfError::Transport(TransportError::HostKey { observed, .. }) => {
                    observed.clone()
                }
                _ => progress.fingerprint.take(),
            };
        }
        check.stopped = Some((step, took, error));
        check
    };

    let transport = match RusshTransport::connect_steps(opts, &mut progress).await {
        Ok(transport) => transport,
        // Refused before anything was connected: nothing was checked.
        Err(e) if progress.mark.is_none() => return Err(e),
        Err(e) => {
            // The step after the last one that answered.
            let step = match progress.steps.last() {
                None => CheckStep::Tcp,
                Some((CheckStep::Tcp, _)) => CheckStep::Ssh,
                Some((CheckStep::Ssh, _)) => CheckStep::Login,
                Some(_) => CheckStep::Netconf,
            };
            // No policy is bound, so what the device said is redacted.
            return Ok(stop(check, progress, step, redact_content(e)));
        }
    };
    check.fingerprint = transport.observed_host_key();

    let session = match timeout(left(), NetconfSession::establish(transport, true)).await {
        Ok(Ok(session)) => session,
        Ok(Err(e)) => return Ok(stop(check, progress, CheckStep::Hello, e)),
        Err(_) => {
            let e = NetconfError::timeout("rpc-recv");
            return Ok(stop(check, progress, CheckStep::Hello, e));
        }
    };
    progress.done(CheckStep::Hello);
    check.capabilities = session.capabilities().to_vec();
    check.session_id = session.session_id();

    match timeout(left(), session.close()).await {
        Ok(Ok(end)) => {
            progress.done(CheckStep::Request);
            check.banner = end.ssh.banner;
            check.stderr = end.ssh.stderr;
            check.steps = progress.steps;
            Ok(check)
        }
        Ok(Err(e)) => Ok(stop(check, progress, CheckStep::Request, e)),
        Err(_) => {
            let e = NetconfError::timeout("rpc-recv");
            Ok(stop(check, progress, CheckStep::Request, e))
        }
    }
}

#[cfg(test)]
mod ttl_tests {
    use super::recv_budget;
    use std::time::{Duration, Instant};

    #[test]
    fn budget_is_min_of_per_rpc_and_remaining_ttl() {
        let now = Instant::now();
        let per_rpc = Duration::from_secs(60);
        // Plenty of TTL left, so per_rpc is the limit.
        assert_eq!(
            recv_budget(per_rpc, now + Duration::from_secs(500), now),
            Some(per_rpc)
        );
        // Less TTL left than per_rpc, so the remainder is the limit.
        assert_eq!(
            recv_budget(per_rpc, now + Duration::from_secs(10), now),
            Some(Duration::from_secs(10))
        );
        // Deadline passed: no waiting, fail at once.
        assert_eq!(recv_budget(per_rpc, now, now), None);
        assert_eq!(
            recv_budget(per_rpc, now, now + Duration::from_secs(1)),
            None
        );
    }

    /// A commit's longer limit is bounded by the session like any other: it never
    /// waits past the deadline.
    #[test]
    fn a_commit_budget_is_still_bounded_by_the_remaining_ttl() {
        use crate::transport::{ReplyBudget, Timeouts};
        let now = Instant::now();
        let t = Timeouts {
            per_rpc: Duration::from_secs(5),
            per_commit: Some(Duration::from_secs(240)),
            ..Timeouts::default()
        };
        let per_commit = t.per_read(ReplyBudget::PerCommit);
        assert_eq!(
            recv_budget(per_commit, now + Duration::from_secs(500), now),
            Some(Duration::from_secs(240))
        );
        assert_eq!(
            recv_budget(per_commit, now + Duration::from_secs(10), now),
            Some(Duration::from_secs(10))
        );
        assert_eq!(recv_budget(per_commit, now, now), None);
    }
}

#[cfg(test)]
mod classification_tests {
    use super::classify_connect_err;
    use crate::error::{NetconfError, TransportError};

    fn branch(e: russh::Error) -> &'static str {
        match classify_connect_err(e, None) {
            NetconfError::Transport(TransportError::HostKey { .. }) => "host-key",
            NetconfError::Transport(TransportError::Negotiation { .. }) => "negotiation",
            NetconfError::Transport(TransportError::Io(_)) => "io",
            _ => "other",
        }
    }

    /// The device is not the one we pinned, or it cannot prove it is itself. Both
    /// are **host-key** questions, and a consumer is expected to raise its own
    /// alarm on that branch — land them in `io` and a security event becomes a
    /// plumbing error.
    #[test]
    fn the_host_key_branch_catches_all_three() {
        assert_eq!(branch(russh::Error::UnknownKey), "host-key");
        assert_eq!(branch(russh::Error::WrongServerSig), "host-key");
        assert_eq!(branch(russh::Error::KeyChanged { line: 1 }), "host-key");
    }

    /// A device we cannot agree on algorithms with is a NEGOTIATION failure.
    /// `Kex` and `KexInit` render as «Key exchange …» with a space, so a string
    /// matcher looking for «kex» never finds them.
    #[test]
    fn failed_key_exchange_is_negotiation_not_io() {
        assert_eq!(branch(russh::Error::Kex), "negotiation");
        assert_eq!(branch(russh::Error::KexInit), "negotiation");
        assert_eq!(branch(russh::Error::UnknownAlgo), "negotiation");
    }

    /// What russh knows and we used to throw away: `theirs` is, to a client,
    /// EXACTLY what the device offered. Without it the operator is left with «we
    /// could not agree» and no idea what the device can actually do.
    #[test]
    fn what_the_device_offered_travels_with_the_negotiation_error() {
        let e = russh::Error::NoCommonAlgo {
            kind: russh::AlgorithmKind::Kex,
            ours: vec!["curve25519-sha256".into()],
            theirs: vec!["diffie-hellman-group1-sha1".into()],
        };
        match classify_connect_err(e, None) {
            NetconfError::Transport(TransportError::Negotiation { offered, .. }) => {
                assert_eq!(
                    offered,
                    vec!["diffie-hellman-group1-sha1".to_string()],
                    "the device's own list must travel with the error"
                );
            }
            other => panic!("expected a negotiation error, got {other:?}"),
        }
    }

    /// **The fingerprint travels with the error.** `check_server_key` sees the key
    /// before anything else happens, so it is known at the moment the error is
    /// built. Without this a consumer would have to connect ONE MORE TIME to say
    /// what the device presented — and the evidence would then be «what answered
    /// when we asked again», not «what was presented in the handshake that broke».
    #[test]
    fn the_host_key_error_carries_the_fingerprint_the_device_presented() {
        let seen = Some("SHA256:a-completely-different-device".to_string());
        match classify_connect_err(russh::Error::UnknownKey, seen) {
            NetconfError::Transport(TransportError::HostKey { observed, .. }) => {
                assert_eq!(
                    observed.as_deref(),
                    Some("SHA256:a-completely-different-device"),
                    "the fingerprint must travel out with the error"
                );
            }
            other => panic!("expected a host-key error, got {other:?}"),
        }
    }

    /// If KEX never got far enough for a key to be seen, there is nothing to carry,
    /// and the field must be empty rather than filled with something that merely
    /// looks like a value.
    #[test]
    fn with_no_observation_the_field_is_empty() {
        match classify_connect_err(russh::Error::UnknownKey, None) {
            NetconfError::Transport(TransportError::HostKey { observed, .. }) => {
                assert!(observed.is_none(), "no observation means an empty field");
            }
            other => panic!("expected a host-key error, got {other:?}"),
        }
    }

    /// **russh's text goes through the filter before it leaves netconf** (0.5.13),
    /// in the error and in the `ssh_connect_failed` event built from it: while
    /// connecting no policy is bound, so it is redacted, as the hello is.
    #[test]
    fn russh_text_is_redacted_before_it_leaves_netconf() {
        let said = || std::io::Error::other("refused: authentication-key hunter2");
        match classify_connect_err(russh::Error::IO(said()), None) {
            NetconfError::Transport(TransportError::Io(s)) => {
                assert!(!s.contains("hunter2"), "{s}");
                assert!(s.contains("authentication-key"), "{s}");
            }
            other => panic!("expected Io, got {other:?}"),
        }
        let NetconfError::Transport(TransportError::Io(s)) =
            super::ended(russh::Error::IO(said()), Default::default())
        else {
            panic!("expected Io");
        };
        assert!(!s.contains("hunter2"), "{s}");
    }

    /// Everything else is still plumbing, and is not to be dressed up as more.
    #[test]
    fn everything_else_is_io() {
        assert_eq!(branch(russh::Error::HUP), "io");
        assert_eq!(branch(russh::Error::ConnectionTimeout), "io");
    }
}

#[cfg(test)]
mod host_key_tests {
    use super::ClientHandler;
    use russh::client::Handler;
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    use russh::keys::ssh_key::private::{Ed25519Keypair, PrivateKey};
    use russh::keys::ssh_key::public::Ed25519PublicKey;
    use russh::keys::{HashAlg, PublicKey, PublicKeyOrCertificate};
    use std::sync::{Arc, Mutex};

    /// A host key made from fixed bytes: no device and no randomness, and two
    /// different bytes give two different keys of the same kind — whose
    /// fingerprints are therefore the same length.
    fn key(byte: u8) -> PublicKeyOrCertificate {
        PublicKey::from(Ed25519PublicKey([byte; 32])).into()
    }

    fn fingerprint(k: &PublicKeyOrCertificate) -> String {
        k.public_key().fingerprint(HashAlg::Sha256).to_string()
    }

    /// The handler `connect()` builds, with `pinned` as the pin, and the slot it
    /// records the presented key in.
    fn handler(pinned: &str) -> (ClientHandler, Arc<Mutex<Option<String>>>) {
        let observed = Arc::new(Mutex::new(None));
        let h = ClientHandler {
            pinned: Some(pinned.to_string()),
            observed: observed.clone(),
            said: Arc::default(),
        };
        (h, observed)
    }

    /// **Only the pinned key is accepted.** The pin is the whole of what stands
    /// between the network password and a device that merely answers at the right
    /// address. The pinned key passes; a different key is refused, as is a pin that
    /// differs from the presented fingerprint in one character or is a prefix of it.
    /// What the device presented is recorded every time.
    #[tokio::test]
    async fn only_the_pinned_host_key_is_accepted() {
        let device = key(1);
        let pin = fingerprint(&device);

        let (mut h, seen) = handler(&pin);
        assert!(h.check_server_key(&device).await.unwrap(), "the pinned key");
        assert_eq!(seen.lock().unwrap().as_deref(), Some(pin.as_str()));

        let other = key(2);
        assert_eq!(
            fingerprint(&other).len(),
            pin.len(),
            "same length, other key"
        );
        let (mut h, seen) = handler(&pin);
        assert!(
            !h.check_server_key(&other).await.unwrap(),
            "a key other than the pinned one was accepted"
        );
        assert_eq!(
            seen.lock().unwrap().as_deref(),
            Some(fingerprint(&other).as_str()),
            "what the device presented must be recorded"
        );

        let mut one_off = pin.clone();
        let last = one_off.pop().unwrap();
        one_off.push(if last == 'A' { 'B' } else { 'A' });
        for wrong in [one_off.as_str(), &pin[..pin.len() - 1], ""] {
            let (mut h, _) = handler(wrong);
            assert!(
                !h.check_server_key(&device).await.unwrap(),
                "the pin {wrong:?} accepted {pin}"
            );
        }
    }

    /// **A host certificate is refused** (0.6.1), pinned or not, even when the
    /// key it carries is the pinned one: the pin is a key, and nothing here knows
    /// which authorities to trust. The key it carries is recorded all the same.
    #[tokio::test]
    async fn a_host_certificate_is_refused() {
        let device = key(4);
        let authority = PrivateKey::from(Ed25519Keypair::from_seed(&[5; 32]));
        let mut builder =
            Builder::new([0; 16], device.public_key().key_data().clone(), 0, u64::MAX).unwrap();
        builder
            .cert_type(CertType::Host)
            .unwrap()
            .all_principals_valid()
            .unwrap();
        let certificate = PublicKeyOrCertificate::from(builder.sign(&authority).unwrap());
        let pin = fingerprint(&device);
        assert_eq!(fingerprint(&certificate), pin, "it carries the pinned key");

        let (mut h, seen) = handler(&pin);
        assert!(
            !h.check_server_key(&certificate).await.unwrap(),
            "a certificate for the pinned key was accepted"
        );
        assert_eq!(seen.lock().unwrap().as_deref(), Some(pin.as_str()));

        let observed = Arc::new(Mutex::new(None));
        let mut enrolling = ClientHandler {
            pinned: None,
            observed: observed.clone(),
            said: Arc::default(),
        };
        assert!(
            !enrolling.check_server_key(&certificate).await.unwrap(),
            "a certificate was accepted for enrollment"
        );
        assert_eq!(observed.lock().unwrap().as_deref(), Some(pin.as_str()));
    }

    /// The key the device presented is recorded even when the lock around the
    /// record was poisoned (0.5.13); the record used to be skipped then, and the
    /// error that followed had no key to name.
    #[tokio::test]
    async fn the_presented_key_is_recorded_through_a_poisoned_lock() {
        let device = key(3);
        let (mut h, seen) = handler("SHA256:something-else");
        let poison = seen.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poison.lock().unwrap();
            panic!("poison the lock");
        })
        .join();
        assert!(seen.is_poisoned());
        assert!(!h.check_server_key(&device).await.unwrap());
        assert_eq!(
            seen.lock().unwrap_or_else(|p| p.into_inner()).as_deref(),
            Some(fingerprint(&device).as_str())
        );
    }
}

#[cfg(test)]
mod target_tests {
    use super::check_target;

    /// A host or username that cannot be right is refused before it reaches a log
    /// line, where a newline in either could otherwise start a line of its own.
    #[test]
    fn a_bad_host_or_username_is_refused() {
        for (host, user) in [
            ("", Some("ops")),
            ("pe1\nx", Some("ops")),
            ("pe 1", Some("ops")),
            ("pe1", Some("")),
            ("pe1", Some("ops\r\nx")),
            ("pe1\n", None),
        ] {
            assert!(check_target(host, user).is_err(), "{host:?} / {user:?}");
        }
    }

    /// Ordinary values pass, an IPv6 literal included, with or without a username.
    #[test]
    fn ordinary_targets_pass() {
        for host in ["pe1.example.net", "10.0.0.1", "2001:db8::1"] {
            check_target(host, Some("ops-user")).unwrap();
            check_target(host, None).unwrap();
        }
    }
}

#[cfg(test)]
mod stderr_tests {
    use super::{
        MAX_STDERR, STDERR_CUT, Stderr, append_capped, close_outcome, ended, keep_late,
        late_detail, with_stderr,
    };
    use crate::error::{NetconfError, SshMessages, TransportError};
    use crate::redact::REDACTED;

    /// What the device wrote, as it came in `pieces`.
    fn wrote(pieces: &[&str]) -> Stderr {
        let mut stderr = Stderr::new();
        for piece in pieces {
            stderr.keep(piece.as_bytes(), 1);
        }
        stderr
    }

    /// What the device has said over SSH when all it did was write `text` on
    /// stderr, at the end of the session.
    fn said(text: &str) -> SshMessages {
        SshMessages {
            stderr: wrote(&[text]).take(true),
            ..SshMessages::default()
        }
    }

    /// If the device said nothing, an empty read is the signal the layer above is
    /// waiting for: «the peer hung up». `read_message` is what turns that into an
    /// error with its own wording, and that has to keep working.
    #[test]
    fn a_silent_disconnect_is_still_an_empty_read() {
        assert_eq!(close_outcome(said("")).unwrap().len(), 0);
        assert_eq!(close_outcome(said("   \n ")).unwrap().len(), 0);
    }

    /// What the device said over SSH is an answer too (0.5.13): an exit status alone
    /// makes the close `Closed`, carrying it.
    #[test]
    fn what_the_device_said_over_ssh_is_the_answer_too() {
        let ssh = SshMessages {
            exit_status: Some(1),
            ..SshMessages::default()
        };
        match close_outcome(ssh) {
            Err(NetconfError::Transport(TransportError::Closed { detail, ssh, .. })) => {
                assert!(detail.contains("closed the netconf subsystem"), "{detail}");
                assert_eq!(ssh.exit_status, Some(1));
            }
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    /// If the device said something, THAT is the answer. Closing a channel is
    /// rarely an explanation by itself — the explanation arrived on stderr just
    /// before, and it should reach the person instead of being discarded. It is in
    /// `ssh.stderr` (0.7.0; part of `detail` before), and in the error's text.
    #[test]
    fn if_the_device_said_something_that_is_the_answer() {
        let e = close_outcome(said("\nnetconf: permission denied\n")).unwrap_err();
        let text = e.to_string();
        let NetconfError::Transport(TransportError::Closed { detail, ssh, .. }) = e else {
            panic!("expected a transport error");
        };
        assert_eq!(ssh.stderr.as_deref(), Some("netconf: permission denied"));
        assert_eq!(detail, "the device closed the netconf subsystem");
        assert!(
            text.ends_with("; the device wrote on stderr: netconf: permission denied"),
            "{text}"
        );
    }

    /// A control character the device wrote on stderr is written out as an escape,
    /// so the device's text stays on its line and shows what it holds.
    #[test]
    fn what_the_device_said_is_made_printable() {
        let text = wrote(&["bell\u{7} and\r\nmore\u{2028}x"]).take(true);
        assert_eq!(
            text.as_deref(),
            Some("bell\\u{0007} and\\r\\nmore\\u{2028}x")
        );
    }

    /// A secret the device wrote on stderr is redacted, whatever the policy: the
    /// transport has none (0.7.0).
    #[test]
    fn what_the_device_said_has_its_secrets_redacted() {
        let text = wrote(&["error: could not load\nencrypted-password \"$9$leak\";\n"])
            .take(false)
            .unwrap();
        assert!(!text.contains("$9$leak"), "{text}");
        assert!(
            text.starts_with("error: could not load\\nencrypted-password "),
            "{text}"
        );
        assert!(text.contains(REDACTED), "{text}");
    }

    /// Each piece is handed over once, and redacted with what the device wrote
    /// before it (0.7.0). A private key written a line at a time has its
    /// `-----BEGIN` line in an earlier piece, already handed over, and a line of it
    /// read alone is no key.
    #[test]
    fn each_piece_is_handed_over_once_redacted_with_what_came_before() {
        let mut stderr = Stderr::new();
        let mut given = Vec::new();
        for piece in [
            "error: bad key\n-----BEGIN PRIVATE KEY-----\n",
            "MIIEkeyBodyLineOne\n",
            "MIIEkeyBodyLineTwo\n-----END PRIVATE KEY-----\n",
            "done\n",
        ] {
            stderr.keep(piece.as_bytes(), 1);
            given.push(stderr.take(false).unwrap_or_default());
        }
        let all = given.join("|");
        assert!(!all.contains("keyBody"), "{all}");
        assert_eq!(given[0], "error: bad key\\n-----BEGIN PRIVATE KEY-----");
        assert_eq!(given[1], REDACTED);
        assert_eq!(given[3], "done");
        // Nothing is handed over twice.
        assert_eq!(stderr.take(false), None);
        assert_eq!(stderr.take(true), None);
    }

    /// A line is handed over when the device has ended it (0.7.0): what makes a
    /// word on it a secret may still come. The password in a URL is one only once
    /// the `@` after it is there. At the end of the session nothing more can come,
    /// and the line goes as it is.
    #[test]
    fn a_line_is_handed_over_when_the_device_ends_it() {
        let mut stderr = wrote(&["fetching scp://user:hunter2"]);
        assert_eq!(stderr.take(false), None);
        stderr.keep(b"@host/file failed\nand then", 1);
        let line = stderr.take(false).unwrap();
        assert!(!line.contains("hunter2"), "{line}");
        assert!(line.starts_with("fetching scp://user:"), "{line}");
        assert!(line.ends_with("@host/file failed"), "{line}");
        assert_eq!(stderr.take(false), None);
        assert_eq!(stderr.take(true).as_deref(), Some("and then"));
    }

    /// At most `MAX_STDERR` bytes are kept in a session, and the text handed over
    /// says so, once, when more came (0.7.0). Past the cap nothing is done with
    /// what the device writes.
    #[test]
    fn what_comes_past_the_cap_is_dropped_and_the_text_says_so() {
        let mut stderr = wrote(&[&"x".repeat(MAX_STDERR - 1), "\nsecret \"hunter2\";\n"]);
        let text = stderr.take(false).unwrap();
        assert_eq!(text, format!("{} {STDERR_CUT}", "x".repeat(MAX_STDERR - 1)));
        stderr.keep(b"more\n", 1);
        assert_eq!(stderr.kept.len(), MAX_STDERR);
        assert_eq!(stderr.take(false), None);
        assert_eq!(stderr.take(true), None);

        // The device wrote more, and all that was kept is handed over already: the
        // note comes alone.
        let mut stderr = wrote(&["kept\n"]);
        assert_eq!(stderr.take(false).as_deref(), Some("kept"));
        stderr.keep("y".repeat(MAX_STDERR).as_bytes(), 1);
        assert_eq!(stderr.take(false).as_deref(), Some(STDERR_CUT));
    }

    /// A timeout carries what the device wrote (0.7.0), and nothing else does
    /// through `with_stderr`.
    #[test]
    fn a_timeout_carries_what_the_device_wrote() {
        let e = with_stderr(
            NetconfError::timeout("rpc-recv"),
            wrote(&["commit: database locked\n"]).take(false),
        );
        assert_eq!(
            e.to_string(),
            "timeout: rpc-recv; the device wrote on stderr: commit: database locked"
        );
        let NetconfError::Timeout { stderr, .. } = e else {
            panic!("expected Timeout");
        };
        assert_eq!(stderr, "commit: database locked");
        let other = with_stderr(NetconfError::Policy("no".into()), Some("text".into()));
        assert!(matches!(other, NetconfError::Policy(_)), "{other:?}");
    }

    /// A send or a close that finds the connection gone is `Closed` when the
    /// device wrote on stderr (0.7.0), as when it said something over SSH: the
    /// text goes with it. With nothing said it is `Io`, as before.
    #[test]
    fn a_failure_on_a_connection_that_is_gone_carries_what_the_device_wrote() {
        match ended("channel closed", said("netconf: shutting down\n")) {
            NetconfError::Transport(TransportError::Closed { ssh, .. }) => {
                assert_eq!(ssh.stderr.as_deref(), Some("netconf: shutting down"));
            }
            other => panic!("expected Closed, got {other:?}"),
        }
        assert!(matches!(
            ended("channel closed", SshMessages::default()),
            NetconfError::Transport(TransportError::Io(_))
        ));
    }

    /// What the device sends after the session is closed is kept up to a cap, and
    /// the error says when more came (0.7.0). It was kept without limit.
    #[test]
    fn what_comes_after_the_close_is_capped_and_the_error_says_so() {
        let mut after = Vec::new();
        assert_eq!(keep_late(&mut after, b"abcd", 6), 0);
        assert_eq!(keep_late(&mut after, b"efgh", 6), 2);
        assert_eq!(keep_late(&mut after, b"ijkl", 6), 4);
        assert_eq!(after, b"abcdef");

        assert_eq!(
            late_detail(6, 0),
            "the device sent data after the session was closed"
        );
        assert_eq!(
            late_detail(6, 6),
            "the device sent data after the session was closed: 12 B, more than is kept — \
             the first 6 B are here, and the rest was dropped"
        );
    }

    /// The cap never cuts inside a character. It used to cut with `truncate` at a
    /// byte offset, which panics there — and `from_utf8_lossy` makes every invalid
    /// byte a three-byte U+FFFD, so binary noise on stderr was enough.
    #[test]
    fn the_cap_lands_on_a_character_boundary() {
        // «ø» is two bytes and U+FFFD three, so a cap of 5 falls inside a
        // character in both.
        for text in ["øøøø", "\u{FFFD}\u{FFFD}"] {
            let mut kept = String::new();
            assert!(!append_capped(&mut kept, text, 5));
            assert!(kept.len() <= 5, "over the cap: {kept:?}");
            assert!(text.starts_with(&kept), "not a prefix: {kept:?}");
        }
    }

    /// What is kept grows up to the cap across several pieces, and not past it.
    #[test]
    fn the_cap_holds_across_pieces() {
        let mut kept = String::new();
        assert!(append_capped(&mut kept, "abc", 4));
        assert!(!append_capped(&mut kept, "def", 4));
        assert_eq!(kept, "abcd");
        assert!(!append_capped(&mut kept, "ghi", 4));
        assert_eq!(kept, "abcd");
    }
}
