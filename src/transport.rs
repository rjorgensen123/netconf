// SPDX-License-Identifier: MIT OR Apache-2.0
//! The transport abstraction. The NETCONF layer is written against
//! [`NetconfTransport`], never against russh directly, so a different SSH
//! implementation can slot in without touching anything above it.
//!
//! Implementations: [`mock::MockTransport`](crate::mock), always available and used
//! by the protocol tests, and `russh_transport::RusshTransport` for real SSH, behind
//! the `russh-transport` feature.

use async_trait::async_trait;
use bytes::Bytes;
use krypto::SecretString;
use std::time::Duration;

use crate::error::{NetconfError, SshMessages};

/// A byte transport beneath the NETCONF layer — typically the SSH subsystem
/// `netconf`.
///
/// [`recv`](Self::recv) returns *arbitrary* pieces; they do not necessarily make up
/// a whole NETCONF message. [`Decoder`](crate::framing::Decoder) puts them back
/// together.
#[async_trait]
pub trait NetconfTransport: Send + Sized {
    /// Connect according to `opts`.
    async fn connect(opts: &ConnectOptions) -> Result<Self, NetconfError>;
    /// Send raw bytes, already framed by the caller.
    async fn send(&mut self, bytes: &[u8]) -> Result<(), NetconfError>;
    /// Receive the next piece of bytes. An empty `Bytes` means the peer closed.
    async fn recv(&mut self) -> Result<Bytes, NetconfError>;
    /// Close the transport, and return what the device said over SSH, beside the
    /// NETCONF stream — empty for a transport that is not SSH (0.5.13; `()`
    /// before). It is what the session's [`close`](crate::NetconfSession::close)
    /// hands over in [`SessionEnd::ssh`](crate::session::SessionEnd::ssh).
    async fn close(self) -> Result<SshMessages, NetconfError>;

    /// **Crate-internal, and sealed.** The session saying which time budget the
    /// request it is about to send, and the reply to it, run under (0.5.7).
    ///
    /// The argument's type lives in a private module and cannot be named outside
    /// this crate, so outside it this method can be neither called nor overridden:
    /// it is not part of the surface. The default ignores it. `RusshTransport`
    /// overrides it to apply [`Timeouts::per_commit`] to the commit RPCs.
    #[doc(hidden)]
    fn reply_budget(&mut self, _budget: sealed::ReplyBudget) {}
}

/// The session's hook into the transport's timing, kept off the public surface.
///
/// [`ReplyBudget`](sealed::ReplyBudget) is `pub` so that the public trait may take
/// it, but it sits in a private module, so no code outside the crate can name it.
/// That is what seals [`NetconfTransport::reply_budget`].
mod sealed {
    /// Which of the session's time budgets a request and its reply run under. The
    /// session names it; the transport turns it into a duration with
    /// `Timeouts::per_read`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ReplyBudget {
        /// `Timeouts::per_rpc`: the hello, `close-session` and every RPC that is not
        /// a commit — `commit_check` included, since it commits nothing.
        PerRpc,
        /// `Timeouts::per_commit`, or `per_rpc` when that is `None`: `commit` and
        /// `commit_confirmed`, and so the commit inside `confirm_commit`.
        PerCommit,
    }
}

pub(crate) use sealed::ReplyBudget;

/// Authentication. **Password only**, per user, against RADIUS or TACACS+. SSH keys
/// are deliberately *not* used. The password is accepted solely as a
/// [`SecretString`] — never as a `String`, a `&str` or an owned `Vec<u8>`. The
/// username is in [`ConnectOptions::username`].
pub enum Auth {
    /// The network password: transient, used during SSH authentication and zeroized
    /// afterwards.
    Password(SecretString),
}

/// A platform hint: the key into the small table of quirks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Classic Junos, from the older releases through the newer FreeBSD-based ones.
    Junos,
    /// Junos Evo.
    JunosEvo,
}

/// SSH algorithms that are **outside today's recommendations**. They are not
/// forbidden — the span of releases we target needs them — but they must be
/// **visible**. The choice is always made per device, never globally, and use is
/// meant to be audited.
///
/// The transport marks a connection `legacy` by its **policy**, not by what was
/// negotiated: a device on `LegacyJunos` gets `legacy = true` on its `ssh_connect`
/// event even when the modern algorithms win, because the transport does not learn
/// which ones did.
///
/// A consumer can use [`is_legacy`] to mark its own audit events.
pub const LEGACY_ALGORITHMS: &[&str] = &[
    // SHA-1 based key exchange. group1 is additionally exposed to Logjam, being
    // 1024-bit MODP.
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    // RSA with a SHA-1 signature, and DSA.
    "ssh-rsa",
    "ssh-dss",
    // 64-bit block ciphers (Sweet32), and CBC in SSH (MAC-then-encrypt weaknesses).
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    // SHA-1-MAC.
    "hmac-sha1",
    "hmac-sha1-etm@openssh.com",
];

/// Is this algorithm name outside today's recommendations? For a consumer that marks
/// its own events `legacy` in logs and audit trails by algorithm name. The transport's
/// own `legacy` tag follows the policy instead — see [`LEGACY_ALGORITHMS`].
pub fn is_legacy(algorithm: &str) -> bool {
    LEGACY_ALGORITHMS.contains(&algorithm)
}

/// The SSH policy — **always per device, never global**. `LegacyJunos` is a superset
/// of `Modern`: the modern algorithms are still negotiated first, and legacy ones are
/// *permitted*, not *preferred*.
///
/// The variants genuinely affect the negotiation. `Modern` is today's recommendation;
/// `LegacyJunos` appends SHA-1 key exchange, `ssh-rsa`, CBC and `hmac-sha1` as a
/// tail, so that older releases remain reachable. No policy offers 3DES (removed in
/// 0.3.2). The exact lists are in `docs/API.md`.
pub enum SshPolicy {
    /// curve25519, ecdh-nistp and SHA-2 Diffie-Hellman; ed25519, ecdsa and rsa-sha2
    /// host keys; chacha20, aes-gcm and aes-ctr; hmac-sha2, encrypt-then-MAC first.
    /// Newer releases.
    Modern,
    /// Modern plus SHA-1 key exchange — group14-sha1 and the 1024-bit group1-sha1 —
    /// ssh-rsa with SHA-1 signatures, aes-cbc as a last resort, and hmac-sha1. For
    /// older releases.
    LegacyJunos,
    /// Full manual control.
    Custom {
        /// Key exchange algorithms.
        kex: Vec<String>,
        /// Host key algorithms.
        hostkey: Vec<String>,
        /// Ciphers.
        cipher: Vec<String>,
        /// MAC algorithms.
        mac: Vec<String>,
    },
}

/// Time limits for a session, at TWO levels:
///
/// 1. **`max_total` — the absolute ceiling.** A setting the consumer chooses ONCE,
///    when it adopts this crate (5 minutes by default; the permitted range is
///    [`Timeouts::MIN_CEILING`]..=[`Timeouts::MAX_CEILING`], 1 to 10 minutes). No
///    session can ever live longer than this. The ceiling is a FAILSAFE: if
///    something crashes on the consumer's side mid-task, the session still dies on
///    its own within it.
/// 2. **`total` — THIS session's TTL.** The consumer saying how long this particular
///    task may live. Many small tasks need very little; seconds are allowed. It must
///    fall within the ceiling.
///
/// Both are validated fail-closed at connection time. Nothing is silently clamped.
///
/// Within a session, every single read and send waits no longer than its budget:
/// `per_rpc`, or `per_commit` for a commit RPC when that is set — and never past the
/// session's deadline.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// The maximum time to establish the transport, counted from when the connection
    /// is started — the same moment the TTL clock starts — and never past the
    /// session's deadline. For `RusshTransport` it covers every wait before `connect`
    /// returns: the TCP connection, the SSH handshake and host key check,
    /// authentication, opening the channel and the device's answer to the subsystem
    /// request. The hello is not part of it: it is ordinary sends and reads, each
    /// under [`Timeouts::per_rpc`]. `russh_transport::observe_host_key` runs under
    /// the same bound: its TCP connection and key exchange end within it, and never
    /// past `total`.
    pub connect: Duration,
    /// The maximum time for each single read and each single send of an RPC. Commit
    /// RPCs use [`Timeouts::per_commit`] instead, when it is set.
    pub per_rpc: Duration,
    /// **The budget for commit RPCs** (0.5.7). It takes the place of
    /// [`Timeouts::per_rpc`] for `commit` and `commit_confirmed` — and so for the
    /// commit inside `confirm_commit`. `commit_check` commits nothing and stays on
    /// `per_rpc`. A commit on a device can take far longer than an ordinary RPC.
    ///
    /// `None` means the same as `per_rpc`. When it is set it must be at least one
    /// second and no more than [`Timeouts::max_total`]; it need not fit inside
    /// `total`, and like every wait it never runs past the session's deadline.
    pub per_commit: Option<Duration>,
    /// **This session's TTL.** The clock starts when the connection is opened, and
    /// once the deadline is reached the transport refuses further operations with
    /// [`crate::NetconfError::Timeout`] with `op` `"session-ttl"` — regardless of activity.
    /// Set per task: at least one second, and no more than
    /// [`Timeouts::max_total`].
    pub total: Duration,
    /// **The absolute ceiling** on any session TTL — the consumer's adoption choice,
    /// five minutes by default within a range of one to ten. `total` can never be set
    /// above it.
    pub max_total: Duration,
}

impl Timeouts {
    /// The lower bound on the ceiling [`Timeouts::max_total`] — one minute.
    pub const MIN_CEILING: Duration = Duration::from_secs(60);
    /// The upper bound on the ceiling [`Timeouts::max_total`] — ten minutes.
    pub const MAX_CEILING: Duration = Duration::from_secs(600);

    /// Validate both levels, fail-closed. The transport calls this when connecting,
    /// and `russh_transport::observe_host_key` before it probes:
    /// the ceiling must lie in `MIN_CEILING..=MAX_CEILING`, and the session TTL must
    /// be at least one second and no more than the ceiling. The message says what was
    /// given and what the range is; nothing is silently clamped.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_total < Self::MIN_CEILING || self.max_total > Self::MAX_CEILING {
            return Err(format!(
                "Timeouts::max_total is {}s — the absolute ceiling must be between {}s and {}s \
                 (the consumer sets it once, when adopting netconf; nothing is silently clamped)",
                self.max_total.as_secs(),
                Self::MIN_CEILING.as_secs(),
                Self::MAX_CEILING.as_secs()
            ));
        }
        if self.total < Duration::from_secs(1) || self.total > self.max_total {
            return Err(format!(
                "Timeouts::total is {}s — this session's TTL must be at least 1s and at most \
                 max_total ({}s); small tasks get small TTLs, nothing is silently clamped",
                self.total.as_secs(),
                self.max_total.as_secs()
            ));
        }
        // The two smaller limits were never checked, and a zero in either is not a
        // strict setting — it is a session that can never do anything. `per_rpc` of
        // zero makes every read time out before it starts; `connect` of zero makes
        // the connection itself impossible. Both fail in a way that looks like the
        // device is at fault.
        if self.connect.is_zero() {
            return Err(
                "Timeouts::connect is 0s — a connection cannot be established in no time"
                    .to_string(),
            );
        }
        if self.per_rpc.is_zero() {
            return Err(
                "Timeouts::per_rpc is 0s — every read would time out before it began".to_string(),
            );
        }
        // `None` runs commits under `per_rpc`, which is checked above. A commit budget
        // that is set is held to the ceiling: a commit allowed to wait longer than any
        // session can live is a mistake, not a setting.
        if let Some(per_commit) = self.per_commit {
            if per_commit < Duration::from_secs(1) || per_commit > self.max_total {
                return Err(format!(
                    "Timeouts::per_commit is {}s — a commit's budget must be at least 1s and \
                     at most max_total ({}s), or None to use per_rpc; nothing is silently clamped",
                    per_commit.as_secs(),
                    self.max_total.as_secs()
                ));
            }
        }
        // Deliberately NOT checked: that `per_rpc`, `per_commit` or `connect` fits
        // inside `total`. A short-lived task keeps the default per-read limit, and
        // `recv_budget` already waits for the smaller of the two. Refusing that
        // combination would reject the ordinary case — small tasks with small TTLs —
        // for no gain.
        Ok(())
    }

    /// The limit on each single read and send under `budget`: `per_commit` for a
    /// commit when it is set, and `per_rpc` otherwise. The transport bounds it by
    /// what is left of the session.
    // Only `RusshTransport` enforces time, so without its feature this is used by
    // the tests alone.
    #[cfg_attr(not(feature = "russh-transport"), allow(dead_code))]
    pub(crate) fn per_read(&self, budget: ReplyBudget) -> Duration {
        match budget {
            ReplyBudget::PerRpc => self.per_rpc,
            ReplyBudget::PerCommit => self.per_commit.unwrap_or(self.per_rpc),
        }
    }
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            connect: Duration::from_secs(30),
            per_rpc: Duration::from_secs(60),
            // Commits run under `per_rpc` unless the consumer gives them their own.
            per_commit: None,
            // The ceiling defaults to five minutes — the consumer's adoption choice,
            // within one to ten. The TTL equals the ceiling unless something says
            // otherwise; a consumer sets its own per task, and small tasks can be
            // very short.
            total: Duration::from_secs(300),
            max_total: Duration::from_secs(300),
        }
    }
}

/// Everything a transport needs in order to connect to one device.
pub struct ConnectOptions {
    /// Hostname or address.
    pub host: String,
    /// Port. 830 is the NETCONF default; 22 is supported and is where the subsystem
    /// usually answers.
    pub port: u16,
    /// Username.
    pub username: String,
    /// Authentication. Password only; SSH keys are not used.
    pub auth: Auth,
    /// The SSH policy for *this* device.
    pub ssh_policy: SshPolicy,
    /// Time limits.
    pub timeouts: Timeouts,
    /// **Reserved — not read today.** A placeholder for a future table of quirks:
    /// differences between Junos generations, and in time between vendors. Only
    /// `None`, the default, is in use; setting anything else has no effect yet. It is
    /// kept deliberately, so the field exists on the day a platform difference forces
    /// it.
    pub platform_hint: Option<Platform>,
    /// **The pinned host key fingerprint**, and it is required.
    ///
    /// The transport MUST verify that the device's host key matches, and REFUSE on
    /// any difference — never a silent accept, never trust-on-first-use.
    ///
    /// `None` is **refused** by `connect()`. It used to mean «accept whatever the
    /// device presents and report it», but `connect()` authenticates: it sends the
    /// network password. Handing a password to a device we have not verified is the
    /// thing pinning exists to prevent, so enrollment cannot happen on this path.
    ///
    /// Learning a device's key is a separate operation with its own function,
    /// `russh_transport::observe_host_key`, which runs the key exchange and
    /// disconnects without authenticating. It takes no credential parameter at all.
    pub host_key: Option<String>,
}
