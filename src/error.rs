// SPDX-License-Identifier: MIT OR Apache-2.0
//! The error model — three branches a consumer can tell apart **programmatically**,
//! without parsing text:
//!
//! - [`NetconfError::Transport`] — «the network failed» (SSH, IO, negotiation,
//!   host key).
//! - [`NetconfError::Protocol`] — «we spoke wrongly» (framing, parsing, hello).
//! - [`NetconfError::Device`] — «the device said no» (a structured `<rpc-error>`).
//!
//! This is the contract towards the consumer: three branches, three different
//! courses of action. Malformed input always produces an error, **never a panic**.

use std::fmt;

use crate::wire::printable;

/// An error from the NETCONF layer. `#[non_exhaustive]`: new branches can arrive.
#[derive(Debug)]
#[non_exhaustive]
pub enum NetconfError {
    /// SSH or the network — «the network failed».
    Transport(TransportError),
    /// Framing, parsing or hello — «we spoke wrongly».
    ///
    /// A struct variant since 0.5.13: what the device sent travels beside the
    /// explanation, as a field of its own, so a consumer can take it out as data.
    Protocol {
        /// What is wrong, in words.
        detail: String,
        /// What the device sent that the error is about (0.5.13): the reply, the
        /// hello, the bytes in the de-framer — as the device sent them, with every
        /// byte that is not part of valid UTF-8 written as `\xNN`. Through a
        /// session it comes with the device's secrets redacted unless the policy lets
        /// them through, as a reply does. `None` when the error names nothing the
        /// device sent.
        received: Option<String>,
    },
    /// A structured `<rpc-error>` from the device — «the device said no». The first
    /// error of the reply; every other `<rpc-error>` in it is in
    /// [`DeviceError::also`].
    ///
    /// Boxed: this is the largest variant by a wide margin, and an unboxed one
    /// would make every `Result` in the crate carry its size on the success path
    /// too. The error is the cold path; the indirection costs nothing that matters
    /// and keeps the common case small.
    Device(Box<DeviceError>),
    /// An operation exceeded its time limit.
    ///
    /// A struct variant since 0.5.13, so the incomplete message travels with it.
    Timeout {
        /// The operation that ran out: `"ssh-connect"`, `"ssh-subsystem"`,
        /// `"rpc-recv"`, `"rpc-send"` or `"session-ttl"`.
        op: &'static str,
        /// The part of a message the session had received when time ran out, as the
        /// device sent it — in chunked framing with its chunk headers — redacted as a
        /// reply is (0.5.13). Empty when nothing was waiting to be completed.
        partial: String,
    },
    /// The configuration filter (`ConfigPolicy`) refused the change.
    Policy(String),
    /// A fresh `show | compare` deviates from the approved diff — the candidate
    /// drifted between review and commit, and compare-then-commit aborted.
    Drift {
        /// The fresh diff, the one that deviates, as the session's policy lets it
        /// through — redacted as [`PreparedChange::diff`](crate::PreparedChange::diff)
        /// is (0.5.13). The approved one is the consumer's own.
        fresh: String,
    },
    /// The device changed between a confirmed commit and the commit that was to
    /// confirm it (0.5.12): its last commit is no longer the confirmed one, or its
    /// candidate holds changes that are not the confirmed commit's. The confirming
    /// commit was withheld, and the device rolls the confirmed commit back by itself
    /// when its timeout runs out.
    ///
    /// What changed, and the diff, travel as data (0.5.13; a text until then).
    ChangedSinceConfirmed(Box<DeviceChanged>),
    /// The commit **succeeded** — the device answered it without an error, so the
    /// change is live — and a step after it failed.
    ///
    /// A struct variant since 0.5.13, so the device's answer to the commit goes with
    /// it: a later step failing used to leave only its own error.
    CommittedThenFailed {
        /// The device's `<rpc-reply>` to the commit, as the commit returns it — with
        /// the device's secrets redacted unless the policy lets them through.
        reply: String,
        /// The error of the step after the commit, as it came back.
        error: Box<NetconfError>,
    },
    /// A commit was sent, and no answer that could be read came back. The inner
    /// error is what happened instead: a timeout, a broken connection, a reply that
    /// did not parse or did not belong to the request. The device has not said
    /// whether the commit took effect.
    CommitUnanswered(Box<NetconfError>),
    /// An operation failed, and the cleanup after it failed too. Both are reported:
    /// the first failure as it came back, and every cleanup step that failed after
    /// it, in order, with what came back from each.
    CleanupFailed {
        /// The failure the cleanup followed.
        error: Box<NetconfError>,
        /// Each cleanup step that failed — `"discard-changes"`, `"unlock"`,
        /// `"close"`, `"disconnect"` — with its error.
        cleanup: Vec<(&'static str, NetconfError)>,
    },
    /// An operation of several requests failed, after some of them had gone through
    /// (0.5.13): the device's answers to those are here, so they are not lost with
    /// the failure. `prepare_change`, `confirm_commit` and `abort_change` return it
    /// — a lock and a load that went through before a compare failed, the discard
    /// and unlock of the cleanup after it. When none went through, the error comes
    /// as it is.
    WithReplies {
        /// Each request that went through, by its RPC name — `"lock"`,
        /// `"load-configuration"`, `"discard-changes"`, `"unlock"` — with the
        /// device's `<rpc-reply>`, in the order they were sent, redacted as a reply
        /// is.
        replies: Vec<(&'static str, String)>,
        /// What failed, as it came back.
        error: Box<NetconfError>,
    },
    /// [`NetconfSession::close`](crate::NetconfSession::close) failed (0.5.13). The
    /// session is over all the same, and what it held goes with the error: a failed
    /// close used to drop the warnings the session held.
    CloseFailed {
        /// What failed, as it came back.
        error: Box<NetconfError>,
        /// What the session handed over as it ended: its warnings, and what the
        /// device said over SSH when closing the transport went through.
        end: Box<crate::session::SessionEnd>,
    },
}

/// The detail behind the transport branch. Algorithm negotiation has its own
/// variant carrying what the peer offered, so the error explains itself when the
/// device is an old one.
#[derive(Debug)]
#[non_exhaustive]
pub enum TransportError {
    /// A generic transport or IO failure.
    Io(String),
    /// Algorithm negotiation failed; `offered` is what the peer announced.
    Negotiation {
        /// The algorithms the peer announced.
        offered: Vec<String>,
        /// A human-readable explanation.
        detail: String,
    },
    /// An unknown or changed host key. Never silently accepted.
    HostKey {
        /// The fingerprint the device ACTUALLY presented in the handshake that
        /// broke.
        ///
        /// `check_server_key` sees the key before anything else happens, so it is
        /// known at the moment the error is built. It used to be left in an `Arc`
        /// the error path never read, which meant a consumer had to connect ONE
        /// MORE TIME to tell the operator what the device had presented. The
        /// evidence then became «what answered when we asked again» rather than
        /// «what was presented in the handshake that broke» — in practice the same
        /// device, but not the same statement.
        ///
        /// `None` means key exchange never got far enough for a key to be seen, so
        /// there is no observation to carry.
        observed: Option<String>,
        /// A human-readable explanation.
        detail: String,
    },
    /// The device did not open the `netconf` subsystem (0.5.8): it answered the
    /// request with a failure, or closed the channel before it answered.
    ///
    /// The login itself went through, so the address, the host key and the
    /// credentials are all fine. What is missing is NETCONF over SSH on the device —
    /// on Junos, `set system services netconf ssh`. The transport used to take the
    /// refusal for an open subsystem, and the session then failed later as a timeout
    /// that named neither the cause nor the fix.
    SubsystemUnavailable {
        /// What the device wrote on stderr before it refused, trimmed, with every
        /// control character written out as an escape (0.5.11). Empty when it wrote
        /// nothing, which is the usual case.
        stderr: String,
        /// What the device said over SSH before it refused: its login banner, the
        /// exit status or signal of the subsystem, its disconnect message
        /// (0.5.13).
        ssh: Box<SshMessages>,
    },
    /// The device did not let the login through with the password (0.5.8). It used
    /// to be `Io` with this text, so telling wrong credentials from a broken
    /// connection took parsing it.
    ///
    /// What the device said travels with it. If it wants `publickey` or
    /// `keyboard-interactive`, «the password was rejected» sends the operator down
    /// the wrong path: the password was never the problem.
    AuthRejected {
        /// The username the login was attempted as.
        username: String,
        /// The methods the device says it accepts, in its order, by their SSH names
        /// (`password`, `publickey`, `keyboard-interactive`, …). russh keeps only the
        /// names it knows.
        remaining_methods: Vec<String>,
        /// The device ACCEPTED the password and requires further authentication.
        /// Saying «rejected» then is not merely unhelpful, it is wrong, and the text
        /// says which of the two it was.
        partial_success: bool,
    },
    /// The device ended the channel or the connection (0.5.13), before a message
    /// was complete or with something said on the way out.
    ///
    /// It used to be `Io`, `peer closed before a complete message` or russh's
    /// text, with the incomplete message and whatever the device said over SSH
    /// left behind.
    Closed {
        /// What ended, in words — and what the subsystem wrote on stderr, when it
        /// wrote something, as `Io` carried it before.
        detail: String,
        /// The part of a message the session had received when it ended, as the
        /// device sent it — in chunked framing with its chunk headers — redacted as a
        /// reply is. Empty when nothing was waiting to be completed. From closing
        /// the transport, what the device sent after the session was over.
        partial: String,
        /// What the device said over SSH: its login banner, the exit status or
        /// signal of the subsystem, its disconnect message.
        ssh: Box<SshMessages>,
    },
}

/// What a device said over SSH, beside the NETCONF stream (0.5.13). Each part is
/// `None` when the device did not send it. The text is held as the device sent it;
/// `Display` on the error makes it printable, and through a session it comes with
/// the device's secrets redacted unless the policy lets them through.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshMessages {
    /// The banner the device showed before the login (RFC 4252 §5.4). Several
    /// banners are joined by a line break.
    pub banner: Option<String>,
    /// The exit status the device sent for the `netconf` subsystem (RFC 4254
    /// §6.10).
    pub exit_status: Option<u32>,
    /// The signal the device said ended the subsystem (RFC 4254 §6.10).
    pub exit_signal: Option<ExitSignal>,
    /// The disconnect message the device sent (RFC 4253 §11.1).
    pub disconnect: Option<SshDisconnect>,
}

impl SshMessages {
    /// Whether the device said none of it.
    #[cfg_attr(not(feature = "russh-transport"), allow(dead_code))]
    pub(crate) fn is_empty(&self) -> bool {
        self == &SshMessages::default()
    }
}

/// An SSH `exit-signal` (RFC 4254 §6.10), as the device sent it (0.5.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitSignal {
    /// The signal's name without the `SIG` prefix: `TERM`, `KILL`, …
    pub name: String,
    /// Whether the device says the process dumped core.
    pub core_dumped: bool,
    /// The device's message.
    pub message: String,
    /// The language tag of the message (RFC 3066).
    pub language: String,
}

/// An SSH disconnect message (RFC 4253 §11.1), as the device sent it (0.5.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshDisconnect {
    /// The reason code: `11` is «by application», `2` a protocol error, and so on
    /// — the table is RFC 4253 §11.1.
    pub code: u32,
    /// The device's description.
    pub description: String,
    /// The language tag of the description (RFC 3066).
    pub language: String,
}

/// What changed on the device between a confirmed commit and the commit that was
/// to confirm it — [`NetconfError::ChangedSinceConfirmed`] (0.5.13).
///
/// Every text in it comes from the device, as the session's policy lets it
/// through: the device's secrets redacted unless the policy has `allow_secrets` or
/// is `all_free`.
#[derive(Debug)]
pub struct DeviceChanged {
    /// Which of the two checks failed.
    pub check: ConfirmedCheck,
    /// The device's last commit right after the confirmed commit, as the session
    /// recorded it: the first `<commit-history>` entry's fields, `name=value`,
    /// joined with ` · `, filtered as the device wrote them and then made
    /// printable.
    pub confirmed: String,
    /// The device's last commit now, written the same way.
    pub now: String,
    /// The rollback the diff is taken against: `0` for the candidate check, where
    /// the diff is `show | compare`; for the last-commit check, the place the
    /// confirmed commit has in the device's commit history now. `None` when the
    /// confirmed commit no longer stands in that history — then there is nothing
    /// to compare with, and no diff.
    pub rollback: Option<u32>,
    /// The candidate against that rollback, as the device wrote it: for the
    /// last-commit check, what was committed after the confirmed commit, and
    /// anything loaded in the candidate besides; for the candidate check, the
    /// changes in the candidate. `None` when `rollback` is, and when fetching it
    /// failed — then `diff_error` says why.
    pub diff: Option<String>,
    /// Why the diff against `rollback` could not be fetched: the error the request
    /// for it came back with (0.5.13). The device changed all the same, and the
    /// confirming commit is withheld; the error used to be returned in place of
    /// this one, and the caller did not learn that the device had changed. `None`
    /// when the diff came, or when there was none to fetch.
    pub diff_error: Option<Box<NetconfError>>,
}

/// Which check withheld a confirming commit — see [`DeviceChanged`] (0.5.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmedCheck {
    /// The device's last commit is no longer the confirmed one: someone committed
    /// after it.
    LastCommit,
    /// The candidate holds changes that are not the confirmed commit's.
    Candidate,
}

/// A structured `<rpc-error>` (RFC 6241 §4.3). Every field is optional, because
/// the classic non-RFC replies from Junos leave some of them out.
#[derive(Debug, Clone, Default)]
pub struct DeviceError {
    /// `error-type` (transport | rpc | protocol | application).
    pub error_type: Option<String>,
    /// `error-tag` (for example `operation-failed`).
    pub tag: Option<String>,
    /// `error-severity` (error | warning).
    pub severity: Option<String>,
    /// `error-path` (an XPath to the element that failed).
    pub path: Option<String>,
    /// `error-message` (human-readable text from the device).
    pub message: Option<String>,
    /// `error-app-tag`: the application's own tag, where the device sets one.
    pub app_tag: Option<String>,
    /// `error-info`, as text that keeps the names of the elements in it.
    ///
    /// Junos often puts the specific cause here — `<error-info><bad-element>` names
    /// the statement it actually objected to — and it used to be parsed past. The
    /// element is free-form in RFC 6241, so the content is kept as text rather than
    /// modelled; it is for a person to read, not for a program to branch on. Each
    /// element in it is `name: text`, nested names joined by `/`, and the parts are
    /// joined with ` · ` (0.5.13): `bad-element: vlan-id`, `session-id: 7`. The
    /// names used to be dropped, which left `7` with nothing to say what it was.
    pub info: Option<String>,
    /// Every part of the `<rpc-error>` that is none of the fields above, in the
    /// device's order (0.5.13): a child element as its local name and its text, and
    /// text outside every element as `#text` and the text, a comment as `#comment`
    /// and a processing instruction as `#pi`. Junos puts `<source-daemon>` here,
    /// among others; they used to be dropped. A field the
    /// device sent more than once is here too, from its second time on, by its
    /// name; the field above holds the first, and each later one used to overwrite
    /// it. Made
    /// printable, like the fields above; through a session the text comes with the
    /// device's secrets redacted unless the policy lets them through — redacted as
    /// the device wrote it, and made printable after.
    pub other: Vec<(String, String)>,
    /// Every other `<rpc-error>` in the same reply, in the order the device sent
    /// them — further errors and warnings alike, each with its own severity (0.5.7).
    /// Only the first error used to be reported, and the rest of the reply was
    /// dropped. Empty on the entries inside it.
    pub also: Vec<DeviceError>,
    /// What the reply held besides its `<rpc-error>`s, when that is more than
    /// `<ok/>` (0.5.13): the reply with every `<rpc-error>` cut out, as the device
    /// sent it — a commit's `<commit-results>` names the routing engine, a load's
    /// result counts its errors. Through a session it comes with the device's
    /// secrets redacted unless the policy lets them through. On the first error
    /// only; `None` on the entries in `also`, and when the reply held nothing more.
    /// It used to be dropped.
    pub rest: Option<String>,
}

impl DeviceError {
    /// What the `error-tag` means, for the tags this crate translates (0.5.7).
    ///
    /// The tags are standard — RFC 6241, Appendix A, which is the reference for the
    /// full list and their meaning. A translation is a reading aid next to the
    /// device's own message, never in place of it. `None` for a tag that is not
    /// translated, or for no tag.
    pub fn explanation(&self) -> Option<&'static str> {
        Some(match self.tag.as_deref()? {
            "lock-denied" => "the configuration is locked by another session",
            "in-use" => "the resource is in use by someone else",
            "access-denied" => "the user is not allowed to do this on the device",
            "invalid-value" => "a value in the request is not valid",
            "data-exists" => "what was to be created already exists",
            "data-missing" => "what was to be changed or deleted does not exist",
            "unknown-element" | "bad-element" => {
                "the request holds an element the device does not accept"
            }
            "operation-not-supported" => "the device does not support the operation",
            _ => return None,
        })
    }
}

impl NetconfError {
    /// A `Protocol` error that names nothing the device sent.
    pub(crate) fn protocol(detail: impl Into<String>) -> Self {
        NetconfError::Protocol {
            detail: detail.into(),
            received: None,
        }
    }

    /// A `Protocol` error carrying what the device sent.
    pub(crate) fn protocol_with(detail: impl Into<String>, received: impl Into<String>) -> Self {
        NetconfError::Protocol {
            detail: detail.into(),
            received: Some(received.into()),
        }
    }

    /// `self` with `received` set to `text` when it is a `Protocol` error that does not
    /// carry what the device sent yet: for an error built where the document is
    /// not to hand — an entity — and passed on where it is.
    pub(crate) fn about(self, text: &str) -> Self {
        match self {
            NetconfError::Protocol {
                detail,
                received: None,
            } => NetconfError::Protocol {
                detail,
                received: Some(text.to_string()),
            },
            other => other,
        }
    }

    /// A `Timeout` for `op`, with nothing received yet; the session adds what it had.
    #[cfg_attr(not(feature = "russh-transport"), allow(dead_code))]
    pub(crate) fn timeout(op: &'static str) -> Self {
        NetconfError::Timeout {
            op,
            partial: String::new(),
        }
    }
}

/// `; <what>: <the device's text, printable>`, or `; <what>: (empty)`.
fn write_content(f: &mut fmt::Formatter<'_>, what: &str, text: &str) -> fmt::Result {
    if text.is_empty() {
        write!(f, "; {what}: (empty)")
    } else {
        write!(f, "; {what}: {}", printable(text))
    }
}

/// The incomplete message, when there is one.
fn write_partial(f: &mut fmt::Formatter<'_>, partial: &str) -> fmt::Result {
    if partial.is_empty() {
        Ok(())
    } else {
        write_content(f, "the incomplete message so far", partial)
    }
}

/// Every part of `ssh` the device sent, each after a `; `.
fn write_ssh(f: &mut fmt::Formatter<'_>, ssh: &SshMessages) -> fmt::Result {
    if let Some(code) = ssh.exit_status {
        write!(f, "; the subsystem's exit status: {code}")?;
    }
    if let Some(s) = &ssh.exit_signal {
        let core = if s.core_dumped { ", core dumped" } else { "" };
        write!(
            f,
            "; the subsystem's exit signal: {}{core}",
            printable(&s.name)
        )?;
        if !s.message.is_empty() {
            write!(f, ", the device said: {}", printable(&s.message))?;
        }
    }
    if let Some(d) = &ssh.disconnect {
        write!(f, "; the device disconnected, reason code {}", d.code)?;
        if !d.description.is_empty() {
            write!(f, ", and said: {}", printable(&d.description))?;
        }
    }
    if let Some(b) = &ssh.banner {
        write_content(f, "the device's login banner", b)?;
    }
    Ok(())
}

impl fmt::Display for NetconfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetconfError::Transport(e) => write!(f, "transport: {e}"),
            NetconfError::Protocol { detail, received } => {
                write!(f, "protocol: {detail}")?;
                match received {
                    Some(r) => write_content(f, "the device sent", r),
                    None => Ok(()),
                }
            }
            NetconfError::Device(d) => write!(f, "device: {d}"),
            NetconfError::Timeout { op, partial } => {
                write!(f, "timeout: {op}")?;
                write_partial(f, partial)
            }
            NetconfError::Policy(s) => write!(f, "policy: {s}"),
            NetconfError::Drift { fresh } => {
                write!(
                    f,
                    "drift: a fresh show|compare deviates from the approved one"
                )?;
                write_content(f, "the fresh diff", fresh)
            }
            NetconfError::ChangedSinceConfirmed(c) => {
                write!(f, "changed since the confirmed commit: {c}")
            }
            NetconfError::CommittedThenFailed { reply, error } => {
                write!(
                    f,
                    "committed: the commit succeeded, then this failed: {error}"
                )?;
                write_content(f, "the device's answer to the commit", reply)
            }
            NetconfError::CommitUnanswered(e) => {
                write!(
                    f,
                    "commit unanswered: a commit was sent and no readable answer came back: {e}"
                )
            }
            NetconfError::WithReplies { replies, error } => {
                write!(f, "{error}")?;
                for (step, reply) in replies {
                    write_content(f, &format!("the device's answer to {step}"), reply)?;
                }
                Ok(())
            }
            NetconfError::CloseFailed { error, end } => {
                write!(f, "close: {error}")?;
                for w in &end.warnings {
                    let severity = w.severity.as_deref().unwrap_or("warning");
                    write!(f, "; the session held this {severity}: {w}")?;
                }
                write_ssh(f, &end.ssh)
            }
            NetconfError::CleanupFailed { error, cleanup } => {
                write!(f, "{error}; the cleanup after it failed too:")?;
                for (i, (step, e)) in cleanup.iter().enumerate() {
                    let sep = if i == 0 { " " } else { "; " };
                    write!(f, "{sep}{step}: {e}")?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Io(s) => write!(f, "io: {s}"),
            TransportError::Negotiation { offered, detail } => {
                write!(
                    f,
                    "negotiation ({detail}); peer offered: {}",
                    offered.join(", ")
                )
            }
            TransportError::HostKey { observed, detail } => match observed {
                Some(fp) => write!(f, "host key: {detail}; device presented: {fp}"),
                None => write!(f, "host key: {detail}"),
            },
            TransportError::SubsystemUnavailable { stderr, ssh } => {
                write!(
                    f,
                    "the device did not offer the NETCONF subsystem — NETCONF over SSH is not \
                     enabled on the device (Junos: `set system services netconf ssh`)"
                )?;
                if !stderr.is_empty() {
                    write!(f, "; the device said: {stderr}")?;
                }
                write_ssh(f, ssh)
            }
            TransportError::Closed {
                detail,
                partial,
                ssh,
            } => {
                write!(f, "closed: {detail}")?;
                write_partial(f, partial)?;
                write_ssh(f, ssh)
            }
            TransportError::AuthRejected {
                remaining_methods,
                partial_success,
                ..
            } => {
                if *partial_success {
                    write!(
                        f,
                        "the device ACCEPTED the password but requires further authentication — "
                    )?;
                } else {
                    write!(f, "SSH password authentication rejected by the device — ")?;
                }
                if remaining_methods.is_empty() {
                    write!(f, "the device named no other method")
                } else {
                    write!(
                        f,
                        "the device says it accepts: {}",
                        remaining_methods.join(", ")
                    )
                }
            }
        }
    }
}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = self.tag.as_deref().unwrap_or("unknown");
        let msg = self.message.as_deref().unwrap_or("(no message)");
        match self.explanation() {
            Some(what) => write!(f, "{tag} — {what} (RFC 6241, Appendix A): {msg}")?,
            None => write!(f, "{tag}: {msg}")?,
        }
        // Every field the device filled in is in the text (0.5.13): `info` is
        // where Junos names what it objected to, and it used to be left out.
        for (name, value) in [
            ("path", &self.path),
            ("info", &self.info),
            ("app-tag", &self.app_tag),
            ("type", &self.error_type),
        ] {
            if let Some(v) = value {
                write!(f, " [{name}: {v}]")?;
            }
        }
        for (name, value) in &self.other {
            write!(f, " [{name}: {value}]")?;
        }
        for other in &self.also {
            let severity = other.severity.as_deref().unwrap_or("error");
            write!(f, "; also {severity}: {other}")?;
        }
        if let Some(rest) = &self.rest {
            write_content(f, "the reply besides its errors", rest)?;
        }
        Ok(())
    }
}

impl fmt::Display for DeviceChanged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const WITHHELD: &str = "the confirming commit is withheld, and the device rolls the \
                                confirmed commit back by itself when its timeout runs out";
        match self.check {
            ConfirmedCheck::LastCommit => write!(
                f,
                "the device's last commit is no longer the confirmed one — it was «{}», it is \
                 «{}»; {WITHHELD}",
                printable(&self.confirmed),
                printable(&self.now)
            )?,
            ConfirmedCheck::Candidate => write!(
                f,
                "the candidate holds {} line(s) of changes that are not the confirmed \
                 commit's; {WITHHELD}, since the confirming commit would commit them too",
                self.diff.as_deref().map_or(0, |d| d.lines().count())
            )?,
        }
        match (self.rollback, &self.diff, &self.diff_error) {
            (Some(n), Some(diff), _) => {
                write_content(f, &format!("the diff against rollback {n}"), diff)
            }
            (Some(n), None, Some(e)) => {
                write!(
                    f,
                    "; the diff against rollback {n} could not be fetched: {e}"
                )
            }
            _ => write!(
                f,
                "; the confirmed commit is no longer in the device's commit history, so there \
                 is no rollback to compare with"
            ),
        }
    }
}

impl std::error::Error for NetconfError {}
impl std::error::Error for TransportError {}
impl std::error::Error for DeviceError {}
