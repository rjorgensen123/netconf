# netconf — API contract (v0.6.0)

**The version is a floor: v0.6.0 is the LOWEST netconf this contract describes.** Every netconf
from 0.6.0 onwards has what is written here. 0.6.0 is the first release on crates.io, so the
contract starts there and describes nothing older. The number is raised only when the public surface
itself changes — to the crate version at that moment — and stands still while it does not, however
many releases pass in between. A contract *newer* than the crate it describes would promise
something the code does not do, so it can never be ahead of `Cargo.toml`.

The whole public surface of `netconf` — precise enough to reimplement the crate from. How to *use*
the crate is in `docs/Usage.md`; the filter rules told in prose, in `docs/Filter.md`; what the crate
is, in `docs/Home.md`.

**The authoritative source is `src/lib.rs` + `CHANGELOG.md`; on divergence the code wins.** The
`VERSION` constant (mirrors `Cargo.toml`) is the anchor that says which filter/feature set is
active — the mapping version → capabilities lives in `CHANGELOG.md`.

Two normative rules bind whoever *changes* the surface:

- **Verify input and output.** All input is validated (type, length, range, character set —
  fail-closed; unknown values/verbs are rejected, never silently skipped). **No log event carries
  a secret the crate can recognize**, and no log event carries configuration or diff content.
  **Data the consumer asked for goes out with the device's secrets redacted** —
  `get_configuration`, `command`, `compare`, `PreparedChange::diff` and the raw `rpc` reply alike —
  unless the policy has `allow_secrets` or is `all_free`; `redact` (§7) is that filter, and the
  drift guard compares like with like, since a fresh diff under the same policy reads the same
  way. **What the device said goes with every answer, an error included**: an error
  carries the device's content — the diff, the reply, the bytes, what it said over SSH — in fields
  of its own beside the explanation, through the same filter as a reply. Error texts that echo
  configuration are redacted before they are built. Text the device wrote is made printable
  before it goes into an error's text or a log line. An uncovered case → update this
  document.
- **The feedback contract.** What the crate answers — success, errors and status — lives HERE:
  `Result` with the three error branches (§8), and the tracing facade (the logging section) for
  events. An answer not written here is a gap in the contract and should be reported — not
  interpreted.

---

## What the crate is

A narrow, asynchronous **NETCONF client (RFC 6241/6242) for Junos**. The governing
compatibility requirement is the whole span **Junos R14 → Junos Evo**. The RPC set is stable
across that span; the problems live in **SSH negotiation** and **reply parsing** — which is why
framing and the error model are the core, not RPC building.

**No YANG layer, no multivendor abstraction.** `#![forbid(unsafe_code)]` — zero `unsafe`.
Device passwords are taken **exclusively** as `krypto::SecretString` (krypto 0.7) —
secrets never cross the API boundary as plain text; that is type-enforced, not a convention.

## Root exports — 1:1 with `lib.rs`

```rust
pub const VERSION: &str;  // the crate version (mirrors Cargo.toml); the anchor for the active filter/feature set

pub mod change; pub mod error; pub mod framing; pub mod junos;
pub mod mock; pub mod policy; pub mod redact; pub mod rpc;
pub mod russh_transport; pub mod session; pub mod transport;

pub use change::PreparedChange;
pub use error::{DeviceError, NetconfError, TransportError};
pub use framing::{Decoder, Framing};
pub use junos::{Format, LoadAction};
pub use policy::{Access, Change, ConfigPolicy, Match, Op, ParseError, Scope, Violation};
pub use redact::{contains_secrets, redact_secrets, Redactor, REDACTED};
pub use session::NetconfSession;
pub use transport::{
 is_legacy, Auth, ConnectOptions, NetconfTransport, Platform, SshPolicy, Timeouts,
 LEGACY_ALGORITHMS,
};
```

**Public modules:** `change` · `error` · `framing` · `junos` · `mock` · `policy` · `redact` ·
`rpc` · `session` · `transport` · `russh_transport` *(behind the `russh-transport` feature)*.

> **Note:** `rpc` and `mock` are `pub mod` without root re-exports — reachable as
> `netconf::rpc::…` / `netconf::mock::…` and in active use by consumers (§10).

**Derived traits.** `Op`, `Match`, `Access`, `Scope`, `Framing`, `Format`, `LoadAction` and
`Platform` are `Copy + Eq`. `Change`, `Violation` and `ParseError` are `Clone + Eq`. `Timeouts`
is `Copy` and `Default`; `DeviceError`, `Redactor` and `SessionEnd` are `Clone` and `Default`; `ConfigPolicy`,
`Rule` and `PreparedChange` are `Clone`. Everything implements `Debug` except `Auth`, `SshPolicy`,
`ConnectOptions`, `NetconfSession`, `MockTransport` and `RusshTransport` — `Auth` holds the
password. `NetconfError`, `TransportError`, `DeviceError` and `ParseError` implement `Display`
and `std::error::Error`; `DeviceChanged` implements `Display`.

---

## 1. The transport abstraction

The NETCONF layer is written against a trait, **never against russh directly**. That is what
lets a different SSH implementation slot in unchanged without touching the layers above it.

```rust
#[async_trait]
pub trait NetconfTransport: Send + Sized {
 async fn connect(opts: &ConnectOptions) -> Result<Self, NetconfError>;
 async fn send(&mut self, bytes: &[u8]) -> Result<(), NetconfError>; // already framed
 async fn recv(&mut self) -> Result<Bytes, NetconfError>; // arbitrary pieces; empty = the peer closed
 async fn close(self) -> Result<SshMessages, NetconfError>; // what the device said over SSH; empty when not SSH
 #[doc(hidden)] fn reply_budget(&mut self, _budget: ReplyBudget) {} // sealed, see below
}
```

The trait is declared with `#[async_trait]` (the `async-trait` crate), so an implementation outside
the crate is written `#[async_trait::async_trait] impl NetconfTransport for …`. `recv` hands back
pieces of any size; `Decoder` (§3) puts them together.

**`reply_budget` is sealed**. It is how the session tells the transport which budget the
request it is about to send runs under — `ReplyBudget::PerCommit` for a commit RPC,
`ReplyBudget::PerRpc` for everything else (§1, `per_commit`). `ReplyBudget` sits in a private
module and cannot be named outside the crate, so outside it the method can be neither called nor
overridden, and it is not part of the surface: an implementation outside the crate needs nothing
for it. `RusshTransport` applies `per_commit` through it. A transport implemented outside the crate is
never told which RPC is a commit, so whatever it does with `Timeouts` applies to every RPC alike.

```rust
pub struct ConnectOptions {
 pub host: String,
 pub port: u16, // SSH's port: 830 is the NETCONF port, 22 is where the subsystem usually answers
 pub username: String,
 pub auth: Auth,
 pub ssh_policy: SshPolicy,
 pub timeouts: Timeouts,
 pub platform_hint: Option<Platform>, // RESERVED — not read (see below)
 pub host_key: Option<String>, // the pinned fingerprint; RusshTransport refuses None (§9)
}

pub struct Timeouts {
 pub connect: Duration, pub per_rpc: Duration,
 pub per_commit: Option<Duration>, // commit RPCs (≥ 1 s, ≤ max_total); None = per_rpc
 pub total: Duration,     // THIS session's TTL (≥ 1 s, ≤ max_total)
 pub max_total: Duration, // the absolute ceiling, the consumer's adoption choice
}
impl Timeouts {
 pub const MIN_CEILING: Duration; // 1 minute  (lower bound for the ceiling)
 pub const MAX_CEILING: Duration; // 10 minutes (upper bound for the ceiling)
 pub fn validate(&self) -> Result<(), String>; // fail-closed, called by the transport at connect, and by observe_host_key
}
impl Default for Timeouts { … } // connect 30 s · per_rpc 60 s · per_commit None · total 300 s · max_total 300 s

pub enum Auth { Password(SecretString) } // password ONLY — a design choice
pub enum Platform { Junos, JunosEvo } // reserved together with platform_hint
```

### The session lifetime (TTL) — read this before adopting the crate

The lifetime has **two levels**, and the clock starts when the connection is started.
A reached deadline → `Timeout { op: "session-ttl" }` on every further send and read, regardless of
activity. **The transport enforces time:** `RusshTransport` does, `MockTransport` does not, and
`NetconfSession` itself keeps no clock — `connect`, `validate` and the deadline below are the
transport's. `close()` reports a `Timeout` like any request, in `CloseFailed`.

- **`max_total` — the absolute ceiling.** Your adoption choice, set once when you take the
  crate into use (default **5 minutes**; frame **1–10 minutes**,
  `MIN_CEILING`..=`MAX_CEILING`). No session can ever live longer than this. **The ceiling is
  a failsafe:** even if something crashes in the consumer mid-task, the session dies by itself
  within the ceiling.
- **`total` — THIS session's TTL.** Your per-task message about how long this particular
  session gets to live: **≥ 1 s and ≤ the ceiling**. Small tasks do not need long lives; a
  sequence that must span a commit-confirmed window needs more.
- `connect` and `per_rpc` must not be zero — a zero in either is a session that can never
  do anything. Neither has to fit inside `total`: a single wait is `min(per_rpc, remaining TTL)`.
- `per_commit`, when it is set, must be **≥ 1 s and ≤ `max_total`**; `None` is always
  valid and means `per_rpc`. It need not fit inside `total` either: a single wait in a commit is
  `min(per_commit, remaining TTL)`.
- Values outside the frames are **rejected at connect** by the transport (`validate`,
  fail-closed, as `Transport(Io)` with a message that says what was given and what the range is)
  — nothing is silently clamped.
- `connect` (30 s default) bounds establishment as a whole, counted from when the connection is
  started — the same moment as the TTL clock — and never past the session deadline:
  the TCP connection, the SSH handshake and host key check, authentication, opening the channel
  and the device's answer to the subsystem request. Running out is `Timeout { op: "ssh-connect" }`, or
  `Timeout { op: "ssh-subsystem" }` while waiting for the subsystem answer, or `Timeout { op: "session-ttl" }`
  when the deadline is what ran out. The hello is not part of it: `per_rpc` (60 s default) bounds
  each single read, the hello's included, and each single send. `observe_host_key` runs
  under the same bound and the same validation, with the same tags (§9). When `connect`
  or `observe_host_key` gives up — the bound running out, or any other failure — the TCP
  connection is closed at once, and the device sees it end.
- **Commit RPCs have their own budget**: `per_commit` takes the place of `per_rpc` for
  `commit` and `commit_confirmed` — and so for the commit inside `confirm_commit` — because a
  commit on a device can take far longer than an ordinary RPC. `commit_check` commits nothing and
  stays on `per_rpc`, as does every other request. `None` (the default) runs commits under
  `per_rpc`. A commit that outlasts its budget is `CommitUnanswered(Timeout { op: "rpc-recv" })`
  (§4), whichever budget it ran under — from `confirm_commit` inside `WithReplies` when a
  request of the cleanup after it went through (§5).
- The consequence you MUST design for: a session has a deadline. Handle
  `Timeout { op: "session-ttl" }` deliberately (typically: a new connection for the next task). The
  values are parameters and will be calibrated with operational experience.

**Reserved field:** `platform_hint`/`Platform` is not read — only `None`/default is in
active use. A placeholder for a future quirks table (platform differences; eventually non-Juniper
too). Setting the field has no effect yet.

**`Auth` has a single variant, and that is a design choice.** No SSH keys: authentication is
per-user against RADIUS/TACACS+. The password crosses the boundary exclusively as
`krypto::SecretString`.

### SSH policy — always per device, never global

```rust
pub enum SshPolicy {
 Modern,
 LegacyJunos,
 Custom { kex: Vec<String>, hostkey: Vec<String>, cipher: Vec<String>, mac: Vec<String> },
}

pub const LEGACY_ALGORITHMS: &[&str]; // diffie-hellman-group1-sha1, -group14-sha1, -group-exchange-sha1, ssh-rsa, ssh-dss, 3des-cbc, aes{128,192,256}-cbc, hmac-sha1, hmac-sha1-etm@openssh.com
pub fn is_legacy(algorithm: &str) -> bool; // is this name in LEGACY_ALGORITHMS?
```

**The rule:** a legacy policy is set per device and never globally, and every `connect` under one
is logged (one warning per device — after that it stays visible through the tagging;
`observe_host_key` names the policy in its `ssh_host_key_probe` event instead). `LegacyJunos` is a
**superset** of `Modern` — modern algorithms are still negotiated first; the old ones are merely
allowed in addition. We do **not** forbid the old ones (the R14→Evo span requires them), but they
must be **visible**: `is_legacy()` exists so the consumer can mark them in logs and audit. The
transport's own `legacy` tag follows the **policy**, not the algorithm actually negotiated, which
it does not learn.

What each policy offers, in order of preference:

| | `Modern` | `LegacyJunos` appends |
|---|---|---|
| key exchange | `curve25519-sha256`, `curve25519-sha256@libssh.org`, `diffie-hellman-group16-sha512`, `diffie-hellman-group14-sha256`, `ecdh-sha2-nistp256`, `-nistp384`, `-nistp521` | `diffie-hellman-group18-sha512`, `diffie-hellman-group-exchange-sha256`, then `diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`, `diffie-hellman-group1-sha1` |
| host key | `ssh-ed25519`, `ecdsa-sha2-nistp256`, `-nistp384`, `-nistp521`, `rsa-sha2-512`, `rsa-sha2-256` | `ssh-rsa`, `ssh-dss` |
| cipher | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes256-ctr`, `aes192-ctr`, `aes128-ctr` | `aes256-cbc`, `aes192-cbc`, `aes128-cbc` |
| MAC | `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512`, `hmac-sha2-256` | `hmac-sha1-etm@openssh.com`, `hmac-sha1` |

`3des-cbc` is in `LEGACY_ALGORITHMS`, so it is marked when seen, but **no policy offers it**.
 `LegacyJunos` offers everything russh 0.62 has for the R14 to Evo span;
 the two full-strength additions are not legacy, the SHA-1 group exchange and
`ssh-dss` are. `Custom` is rejected at connect (not implemented — we refuse rather than
negotiate with a different list than the one you asked for).

---

## 2. The session

```rust
pub struct NetconfSession<T: NetconfTransport>;

impl<T: NetconfTransport> NetconfSession<T> {
 pub async fn connect(opts: &ConnectOptions) -> Result<Self, NetconfError>;
 pub async fn establish(transport: T, offer_1_1: bool) -> Result<Self, NetconfError>;
 pub async fn rpc(&mut self, inner: &str) -> Result<String, NetconfError>; // the <rpc-reply>, secrets redacted
 pub async fn close(self) -> Result<SessionEnd, NetconfError>; // the warnings it held and what the device said over SSH; a failure is CloseFailed
 pub fn hello(&self) -> String; // the device's <hello>, whole, secrets redacted
 pub fn capabilities(&self) -> &[String]; // made printable
 pub fn session_id(&self) -> Option<u64>;   // the device's <session-id> from hello; None when absent or not a number as RFC 6241 writes one
 pub fn take_warnings(&mut self) -> Vec<DeviceError>; // warnings from replies that succeeded
 pub fn framing(&self) -> Framing;
 pub fn transport(&self) -> &T;
 pub fn set_policy(&mut self, policy: ConfigPolicy);
 pub fn policy(&self) -> Option<&ConfigPolicy>;
 pub fn set_synchronize_commits(&mut self, on: bool); // off by default
}
```

**`set_policy`** binds the filter to the session — once, after connecting, by
convention: each call replaces the policy, nothing enforces a single call. Every typed
helper (§4, §5) passes it before anything goes on the wire: without a bound policy
nothing is permitted — no read, no `show`, no command, no change — exactly as under
`ConfigPolicy::all_deny()`, and a policy that can change nothing (`read_only`, `all_free(Ro)`,
rules without a change grant) refuses `load_configuration`, `commit`, `commit_confirmed` and a
`rollback` to a previous configuration, which loads one whole and so needs `all_free(Rwd)` like a
`Text` load; `rollback(0)` only discards. The refusals are `NetconfError::Policy`: `no policy
bound to the session — nothing is permitted, as under ConfigPolicy::all_deny() …`, `all-deny:
nothing is permitted …`, `the policy bound to this session permits no change …`. Raw `rpc()` goes
around the gates (low level, documented), not around the redaction.

**`set_synchronize_commits`** is for devices with two Routing Engines. When it is on,
`commit` and `commit_confirmed` — and so `confirm_commit` — carry `<synchronize/>`, the Junos
`commit synchronize`, which commits on both (§4). It is **off by default**, and the consumer
decides: a dual-RE device configured with `system commit synchronize` synchronizes every commit by
itself, which is the recommended setup. Off, no commit carries it; `commit_check` never carries it.

One session per connection, **no pooling**. `connect` announces base:1.1 and falls back to EOM if
the peer does not announce 1.1. `establish` exists for an already-connected transport — it is what
the mock tests use, and why all protocol logic is testable without hardware. Both hellos are EOM
framed; chunked is used only when **both** sides announced base:1.1. A hello with no capabilities
is `Protocol`, and so is one that is not UTF-8, that does not parse as XML, or that uses an entity
other than the five predefined ones and character references anywhere in it. Data the device
sends after its hello, before the first request, stops a switch to chunked framing as `Protocol`;
 whitespace there is tolerated. The hello with no capabilities, the hello that is not
UTF-8 and the data after it go with the error in `received`. A transport that returns
empty bytes before a whole message is in — the peer closed — is `Transport(Closed { detail:
"peer closed before a complete message", partial, .. })`,
for the hello and for every reply, and a `Timeout` while a message is coming in carries it the same
way: `partial` is what had arrived of the message, as it arrived — in chunked framing with its
chunk headers.

**What the device sent goes with the error**. The parsing, the de-framer and the
transport build their errors without a policy to hand; the session passes each one through the
policy's filter before it reaches the caller, exactly as it passes a reply: `received`, `partial`,
the diffs, what the device said over SSH and the text of an `Io` error come with the device's
secrets redacted unless the policy has `allow_secrets` or is `all_free`. During `connect` and
`establish` no policy is bound yet, so they are redacted. Bytes that are not part of valid UTF-8
are written as `\xNN`, so nothing the device sent is lost on the way.

**`rpc()`** wraps the body in `<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
message-id="N">` (N counts from 1 per session) and returns the raw reply. What it refuses, as
`Protocol` — each with the reply in `received`:

- a reply whose `message-id` is present and is not, byte for byte, the one the request was sent
  with: `reply message-id `<text>` does not match the request's (N) …`, the device's
  text filtered as the reply is and made printable.
  A reply **without** one is accepted — Junos omits it
  on some replies;
- a document that is not an `<rpc-reply>`: `reply is not an <rpc-reply> but a <root>`,
  naming the root that stood there — an empty `<rpc-reply/>` is an ordinary answer;
 a document that holds a fatal `<rpc-error>` is `Device` whatever its root, since the
  error is the more specific answer; a document with no element at all is `reply contains no
  elements at all`;
- XML that does not parse, or is incomplete at the end, or uses an entity other than the five
  predefined ones and character references — anywhere in the reply;
- a reply that is not UTF-8.

An `<rpc-error>` becomes `Device` (§8): the first error of the reply, carrying every other
`<rpc-error>` of it — further errors and warnings, in the device's order — in `DeviceError::also`.
 Warnings alone do not fail the call; they are kept for `take_warnings()`.

**The reply goes out with the device's secrets redacted**, each replaced by `REDACTED`
(§7), unless the session's policy has `allow_secrets` or is `all_free`. This is the one place
every reply passes, so it holds for the typed helpers and for raw `rpc()` alike; a session with no
policy bound has nothing that lets a secret out.

**`close()`** sends `<close-session/>` and **waits for the reply**, bounded by the
transport's read budget, then closes the transport, and returns a **`SessionEnd`**:

```rust
pub struct SessionEnd { // netconf::session::SessionEnd
 pub warnings: Vec<DeviceError>, // every warning the session held, in the device's order
 pub ssh: SshMessages, // what the device said over SSH, as the transport returned it closing
}
```

`warnings` are those of earlier replies that `take_warnings()` has not handed over, then those of
the reply to `<close-session/>` — the session ends here, and nothing could take them after. When
that reply holds an error — the device refusing to close — its warnings are with that error, in
the `also` of the `Device` error in `CloseFailed`, as for any reply. `ssh`
is what the transport's `close` returns, with the device's secrets redacted unless the policy lets
them through: the login banner, the subsystem's exit status or signal, a disconnect message;
empty for a transport that is not SSH. What goes wrong is reported as for any request: a send that fails, a reply that does not
come in time or is left incomplete (`Timeout`, or `Closed` with `partial`), a reply that cannot be
read or is not the answer to this request (`Protocol`), and an `<rpc-error>`, the device refusing
(`Device`). A device that ends the session without replying has ended it — unless it left a
message incomplete, or said something over SSH as it ended: an exit status or signal, or a
disconnect message, is then the answer, and it is reported as the `Closed` that carries it. The
login banner was said at the login and does not count. The transport is closed either way, and
**every failure is `CloseFailed { error, end }`**: the error, and the `SessionEnd`, so
the warnings reach the caller then too; when closing the transport fails, `end.ssh` is empty and
what the device said is in that error. When both the close-session and closing the transport
fail, `error` is `CleanupFailed` with the step `"close"`.

**`hello()`** returns the device's `<hello>` whole, as it sent it, with its secrets
redacted unless the policy lets them through. The session reads the capabilities — one in CDATA
too — and the session id out of it; the rest is here, such as the comments where Junos writes
the login's user and class. A session id that is not a number reads as `None`.

**`transport()`** gives read access to the transport, so the consumer can ask about
things the NETCONF layer does not know — first and foremost which host key SSH actually saw.

---

## 3. Framing (RFC 6242)

```rust
pub enum Framing { Eom, Chunked }
pub const EOM: &[u8] = b"]]>]]>";
pub const DEFAULT_MAX_MESSAGE: usize = 64 * 1024 * 1024;
pub fn encode(mode: Framing, msg: &[u8]) -> Vec<u8>;

pub struct Decoder;
impl Decoder {
 pub fn new(mode: Framing) -> Self;
 pub fn with_max_message_size(mode: Framing, max: usize) -> Self;
 pub fn set_mode(&mut self, mode: Framing); // only on a message boundary
 pub fn push(&mut self, data: &[u8]);
 pub fn next_message(&mut self) -> Result<Option<Vec<u8>>, NetconfError>; // Ok(None) = more bytes needed
}
```

**EOM is the baseline; chunked is used only when hello announces it** — framing is chosen by
announced capabilities, never by a version assumption.

`encode` in chunked mode writes the whole message as one chunk, `\n#<len>\n<data>\n##\n`; an empty
message is the end marker alone, never a chunk of size 0.

`Decoder` is **incremental** and tolerates a message — and the EOM sequence itself — being split
across arbitrary TCP boundaries. It never panics on invalid input; a violation is `Protocol`.
Every violation carries the buffer as it stood in `received`: a buffer past the cap,
a chunk-size that is empty, not one RFC 6242 allows, 0 or past the cap, and a chunk header that is
not one — `\n#` missing at a chunk's start, no LF after `##` or after the chunk-size — where the
text also names the bytes found where the frame broke and their offset: `chunked: expected \n# at
chunk start, found `XY` at byte 7`.
Whitespace between chunked messages is discarded, anything else there is a violation,
and a chunk size of 0 is refused. The chunk-size is read as RFC 6242 writes it: decimal
digits, no leading zero, at most 4294967295 — `007` is a violation. De-framing a message
costs time in proportion to its size, however many reads it arrives in: the EOM search
and the chunked walk both resume where they stopped, rather than start over on every
read.

**The size cap is part of the contract:** `DEFAULT_MAX_MESSAGE` = **64 MiB** — `Decoder::new` uses
it, `with_max_message_size` sets another — applied to the
de-framer's buffer and to a single chunk (fail-closed — the guard against a device that never ends
a message or states an absurd chunk length). In EOM mode the buffer is refused once it passes the
cap without a terminator; in chunked mode the buffered bytes, chunk headers included, and the
chunks' total are both held under it. NETCONF has **no streaming of a single reply** (chunked framing is wire
framing, not incremental delivery) — large configurations are therefore read in **segments**:
`get_configuration` with a filter, subtree by subtree. The consumer must be deliberate about
what it asks for.

`set_mode` must **only** be called when the residual buffer is empty — typically right after
hello (always EOM) when the session switches to chunked.

---

## 4. Junos helpers

> **`get_configuration` and `command` are gated:** sensitive trees require
> `allow_read` (None = the whole config → requires all); commands: only `show …` by default,
> `show configuration <tree>` is gated by the read grants (abbreviation-tolerant on the DENY
> side), the rest requires `allow_command` or `all_free(Rwd)`, and `read_only` refuses it whatever
> is granted. Without a bound policy nothing is permitted.
>
> **`load_configuration` enforces the session's policy** (the one write entrance with a
> payload): no policy → refused (`NetconfError::Policy`); `Format::Set` → parsed (fail-closed)
> and checked; `Text`/`Xml` → refused unless the policy is `all_free(Rwd)` (deliberate,
> format-agnostic full control).

Typed operations on top of the generic RPC layer, so the consumer never handcrafts XML.

```rust
pub enum LoadAction { Merge, Replace, Override }
pub enum Format { Text, Set, Xml }

impl<T: NetconfTransport> NetconfSession<T> {
 pub async fn lock(&mut self) -> Result<String, NetconfError>; // the <rpc-reply>, secrets redacted
 pub async fn unlock(&mut self) -> Result<String, NetconfError>; // the <rpc-reply>
 pub async fn load_configuration(&mut self, payload: &str, action: LoadAction, format: Format)
 -> Result<String, NetconfError>; // the <rpc-reply>; Set/Text escaped; Xml passed through verbatim
 pub async fn commit_check(&mut self) -> Result<String, NetconfError>; // the <rpc-reply>, secrets redacted
 pub async fn commit(&mut self, comment: Option<&str>) -> Result<String, NetconfError>; // the <rpc-reply>; no readable answer → CommitUnanswered; confirming a confirmed commit: checks the device first
 pub async fn commit_confirmed(&mut self, minutes: u32, comment: Option<&str>)
 -> Result<String, NetconfError>; // the <rpc-reply>; no readable answer → CommitUnanswered; records the device's last commit
 pub fn confirmed_commit(&self) -> Option<String>; // the record commit_confirmed keeps, secrets redacted; None when nothing is waiting
 pub async fn rollback(&mut self, n: u32) -> Result<String, NetconfError>; // the <rpc-reply>; 0 = last committed; n > 0 needs all_free(Rwd)
 pub async fn discard_changes(&mut self) -> Result<String, NetconfError>; // the <rpc-reply>
 pub async fn get_configuration(&mut self, filter: Option<&str>) -> Result<String, NetconfError>; // the <rpc-reply>, secrets redacted
 pub async fn compare(&mut self) -> Result<String, NetconfError>; // the diff text; "" = empty; absent = Protocol
 pub async fn command(&mut self, cmd: &str) -> Result<String, NetconfError>; // the <rpc-reply>, secrets redacted
}
```

**Every helper returns the device's answer**: the `<rpc-reply>`, with the device's
secrets redacted unless the policy lets them through, as `rpc()` does — all but `compare`, which
returns the diff text (below). Junos answers `<commit-configuration>` with `<commit-results>`: one
`<routing-engine>` for each routing engine, its name, `<commit-check-success/>` or
`<commit-success/>`, and its messages — for `commit_check` the reply is what the check found. It
answers `lock`, `unlock` and `discard_changes` with `<ok/>`, and `load_configuration` and
`rollback`, which is a `<load-configuration>`, with `<load-configuration-results>`; whatever it
answers comes back. Warnings in a reply that succeeds are in `take_warnings()`. The operations of
§5 give back their requests' answers the same way.

**Every helper passes the session's policy first** — see `set_policy` in §2: no
policy or `all_deny` refuses all of them before anything is sent; `load_configuration`, `prepare_change`,
`commit`, `commit_confirmed` and `rollback(n > 0)` also need a policy that permits a change, and
`rollback(n > 0)` needs `all_free(Rwd)`: `rollback <n> loads a previous configuration whole, which
the policy cannot check; like a Text or Xml load it requires the deliberate
ConfigPolicy::all_free(Rwd)`.

**A confirmed commit is confirmed only into the state it was made in**. After
`commit_confirmed` has been answered, the session reads `<get-commit-information/>` and keeps the
device's last commit — the confirmed one — as its record: the first `<commit-history>` entry's
fields, `name=value`, joined with ` · `, with the `junos:seconds` on `<date-time>` as the field
`seconds` after it — `date-time=2026-10-03 10:00:00 UTC · seconds=1759485600`, the commit's time as
a number, read strictly as one; what is not one goes as it stood. The
comparison of the recorded entry with the device's takes it in. A value in CDATA, a field that is there and empty
(`name=`) and text outside every field (`#text=…`) are in it, and an
empty first `<commit-history/>` is an entry with nothing in it, which is no record — it was
skipped, and the next entry taken for the last commit. The `commit` that is to confirm it reads the commit
information again and the candidate's diff before it commits: if the last commit is another one,
or the candidate holds changes, the commit is **withheld** as `ChangedSinceConfirmed`, and the
device rolls the confirmed commit back by itself when its timeout runs out — a confirming commit
would otherwise also commit whatever someone else loaded in between. Unchanged, it confirms and
the record is cleared. The record is the session's: a confirming commit on another session makes
no check. `confirmed_commit()` reads it, as the policy lets it through, and is `None`
when no confirmed commit made on the session is waiting. If the record cannot be read after
`commit_confirmed`, that is `CommittedThenFailed`, carrying the answer to the commit:
the confirmed commit is live. Both readings are made raw, for the crate's own comparison, and
leave the crate only through the policy's filter.

**What changed goes with the withheld commit**, as data in a `DeviceChanged` (§8): which
check failed, the recorded entry and the device's last entry now, and the diff — so the operator
can decide what to do about it. When the candidate holds changes, the diff is the one the check
read. When another commit came after the confirmed one, the diff is fetched: `<get-configuration
compare="rollback" rollback="N" format="text"/>`, `show | compare rollback N`, where N is the
place the confirmed commit has in the commit history just read — found by every field but
`sequence-number`, which every later commit moves on by one. That is the candidate against the
configuration the confirmed commit made: what was committed after it, and anything loaded in the
candidate besides. When the confirmed commit is no longer in the history, there is nothing to
compare with: `rollback` and `diff` are `None`, and the text says so. The entries and the diff
come as the policy lets them through. When fetching the diff fails, the answer is still
`ChangedSinceConfirmed`: `rollback` names the place, `diff` is `None`, and `diff_error` holds the
error the request came back with, filtered as every error is — the device changed whatever the
fetch did, and the caller sees it.

What each helper sends. *Escaped* means `&`, `<` and `>` become entities — nothing else is touched.

| Helper | RPC body |
|---|---|
| `lock` / `unlock` | `<lock><target><candidate/></target></lock>` / the same with `unlock` |
| `load_configuration`, `Set` | `<load-configuration action="set" format="text"><configuration-set>` payload, escaped — `format="text"`, and **the `LoadAction` is not used** |
| `load_configuration`, `Text` | `<load-configuration action="<action>" format="text"><configuration-text>` payload, escaped |
| `load_configuration`, `Xml` | `<load-configuration action="<action>"><configuration>` payload **verbatim** — the caller owns its well-formedness |
| `commit_check` | `<commit-configuration><check/></commit-configuration>` |
| `commit` | `<commit-configuration/>`, or with `<log>` comment, escaped; with `set_synchronize_commits(true)`, `<synchronize/>` first inside it. When a confirmed commit made on this session is waiting: first `<get-commit-information/>`, then the compare RPC, then the commit; when the last commit is another, no commit, and the compare RPC against rollback N when the confirmed commit is still in the history |
| `commit_confirmed` | `<commit-configuration><confirmed/><confirm-timeout>` minutes, then the optional `<log>`; with `set_synchronize_commits(true)`, `<synchronize/>` first inside it; then `<get-commit-information/>` |
| `rollback` | `<load-configuration rollback="n"/>` |
| `discard_changes` | `<discard-changes/>` |
| `get_configuration` | `<get-configuration/>`, or the filter inside `<get-configuration>`, serialized from what the read gate parsed |
| `compare` | `<get-configuration compare="rollback" rollback="0" format="text"/>` |
| `command` | `<command format="text">` command, escaped |

`commit` and `commit_confirmed` wait under `Timeouts::per_commit` when it is set, and under
`per_rpc` when it is not; `commit_check` always waits under `per_rpc` (§1).

`commit_confirmed(minutes, …)` gives Junos' auto-rollback: if no confirming `commit` arrives
within the deadline, the device rolls back by itself. It is the safety net under the whole
deploy flow. *(Note the interplay with the session TTL: a sequence that must span a confirmation
window needs `total` set accordingly — the consumer's responsibility.)*

`compare()` returns the **plain diff text** (the contents of `<configuration-output>`, CDATA
included, trimmed), not the envelope. An empty element — `<configuration-output/>`, or one
holding only whitespace — is `""`, no change. A reply with **no** `<configuration-output>` is
`Protocol`: absent is not empty, and a reply holding only `<ok/>` or only warnings does
not say what the diff is. What the
device sent instead is in `received`.

**The read gate.** The filter must be well-formed XML whose elements all close inside it
— no declaration, doctype or processing instruction, no `]]>]]>` — or the read is refused as
`Policy` before anything is sent; the same parse gives the gate its targets. Every
element name in a `get_configuration` filter is a target, nested
ones included, with any namespace prefix removed and compared in lowercase; the
`configuration` element itself is not. A filter with no element names counts as the whole
configuration. A target is refused when it **is** a `SENSITIVE_READ_ROOTS` entry that has no
`allow_read` grant. XML element names are never abbreviated, so they are matched exactly. The abbreviation-tolerant
prefix rule belongs to `show configuration <tree>`, where `sys` is refused as `system` — and it
judges the first word after `configuration` alone, since only it names a tree.
Under `logical-systems <name>` or `tenants <name>` it judges the word after the name, and the
tree, or one system whole, is a read of a whole configuration — on the CLI, a prefix such as
`log` included, and in XML a `<logical-systems>` or `<tenants>` with nothing in it but a `<name>`.

Refused, the text is `reading `<tree>` requires an explicit read grant (allow_read) — it carries
device secrets`, or for the whole configuration `reading the FULL configuration includes sensitive
trees without a read grant: [<trees>] — grant with allow_read(...) or read specific subtrees`; under
`all_deny`, `all-deny: nothing is permitted — no read (denied, fail-closed)`.

**The filter is read strictly, and what was read is what is sent**. The filter sent to
the device is serialized from what the gate read, so the two cannot differ. Refused, as `Policy` and with nothing sent: a declaration, doctype,
processing instruction, comment or CDATA; an element left open, or an end tag that closes nothing;
an element or attribute name that is not an ASCII XML name (`[A-Za-z_][A-Za-z0-9_.-]*`, with an
optional prefix); an attribute unquoted, given twice, or holding `<`; an entity other than the five
predefined ones and character references; a control character, written directly or as a character
reference such as `&#12;`; and `]]>]]>`. Whitespace between elements is not kept.

**The command gate.** Every part of the command is checked, pipes included. Strings are read by the set parser's quoting
rule (§6): a `|` inside a double-quoted string does not split the command, `\"` inside one is a
quote that does not close it, and a quote that does not close refuses the command —
`unbalanced quote: «command» (denied, fail-closed)`, the command redacted. A quote belongs in a
pipe's pattern and nowhere else: one in the command itself refuses it — `a quote in the
command itself …`. A command is one line of printable ASCII and a tab: a control
character refuses it — a carriage return reaches the device as a line break, as a newline
does — `a control character, U+000D, in the command …`, and so does any other character outside
printable ASCII, U+2028 and U+2029 among them — `a character outside printable ASCII, U+2028, in
the command …`. A pipe is only valid on `show`, and each must be one of `READ_ONLY_PIPES` —
`compare`, `count`, `display`, `except`, `find`, `last`, `match`, `no-more`, `resolve`, `trim`,
written in full and in lowercase; `save`, `append`, `tee`,
`request` and the rest are refused; a `|` with nothing after it is `an empty pipe — `|` with
nothing after it (denied, fail-closed)`. `| compare` may name a rollback and nothing else — `| compare`
or `| compare rollback <n>`; a file on the device is not read through it. The first word
must be `show` in full and in lowercase; `sh` is refused, and `SHOW` is
refused with `keywords are lowercase, as the device reads them: `SHOW` is not `show` …`. When the
second word is a prefix of `configuration` — `conf`, even `c` — the rest is a read and goes through
the read gate, and no tree means the whole configuration; the prefix in another case is refused the
same way. `show system rollback <n>` shows a previous configuration whole and is a read of the whole
configuration, the two keywords matched as prefixes on the refusal side like
`configuration` — `show sys rollback 1` too. `show ephemeral-configuration [instance
<name>] [merge] [<tree>]` is a configuration read and judged as `show configuration <tree>` is,
`ephemeral-configuration`, `instance` and `merge` matched as prefixes. Any other command needs an `allow_command` grant whose words are the
command's first words, compared as written, or `all_free(Rwd)`;
`read_only` refuses it whatever is granted; a blank grant grants nothing. An
empty command is refused.

The other refusals read: `operational command outside the rule set: only `show ...` is allowed by
default (got `<word>`) …`; `read-only: only `show ...` is permitted — `<word>` is refused whatever is
granted (denied, fail-closed)`; `a pipe (`|`) is only valid on `show` — `<word>` takes none (denied,
fail-closed)`; `the pipe `| <name>` is not a read-only filter …`; `keywords are lowercase, as the
device reads them: `<word>` is not `configuration` (denied, fail-closed)`; `empty operational
command`; and under `all_deny`, `all-deny: nothing is permitted — no command (denied, fail-closed)`.

An ordinary `show` runs under the device user's own login class on the
box, which this crate does not try to reproduce.

---

## 5. Compare-then-commit

Two phases with **operator approval in between** — the mechanism the deploy flow rests on.

```rust
pub struct PreparedChange {
 pub diff: String,
 pub replies: Vec<(&'static str, String)>, // the answers to the lock and the load, by RPC name
 /* raw: Option<String>, private — the diff as the device wrote it */
}

impl PreparedChange {
 pub fn from_diff(diff: String) -> Self; // from a diff carried across a restart; compares redacted with redacted
 pub fn redacted_diff(&self) -> String; // equals diff unless the policy lets secrets through
 pub fn has_secrets(&self) -> bool;
 pub fn fingerprint(&self) -> u64; // FNV-1a 64-bit, stable across processes — for log/audit, not security
}

impl<T: NetconfTransport> NetconfSession<T> {
 pub async fn prepare_change(&mut self, payload: &str, format: Format,
 action: LoadAction) // the session's policy
 -> Result<PreparedChange, NetconfError>;
 pub async fn confirm_commit(&mut self, approved: &PreparedChange, comment: &str)
 -> Result<Vec<(&'static str, String)>, NetconfError>; // the answers to the commit and the unlock
 pub async fn abort_change(&mut self) -> Result<Vec<(&'static str, String)>, NetconfError>; // discard + unlock, their answers; every failure reported
}
```

**Phase 1** runs the policy check against the **session's** policy (`set_policy`;
fail-fast, *before* anything is sent, before lock too), locks, loads the payload and fetches the
`show | compare` diff. `load_configuration` re-enforces the same policy as defence in depth. The
candidate stays loaded and locked until phase 2 or `abort_change`. The device's answers to the
lock and the load are in `PreparedChange::replies`, as `("lock", reply)` and
`("load-configuration", reply)`; empty for a change built with `from_diff`. If the load or the
compare fails, the candidate is discarded and unlocked before the error is returned; if that
cleanup fails too, the error is `CleanupFailed`, carrying the failure and each cleanup step that
failed.

**An answer that came does not get lost with a failure.** The operations here send several
requests, and when one fails after others went through, the device's answers to those — before
the failure, and from the cleanup after it — go with the error in `WithReplies { replies, error }`
(§8), by RPC name, in the order sent; `error` is the failure, or the `CleanupFailed`
that carries it. With no request through, the error comes as it is. So a drift caught in phase 2
is `WithReplies { replies: [discard-changes, unlock], error: Drift { .. } }`.

**Phase 2** commits — but only if the device still shows the same diff, compared **byte for byte**
**as the device wrote it**: a change built by `prepare_change` keeps the raw diff in a
private field for this comparison alone, so a change inside a value the policy redacts is drift
too. A change built with `from_diff`, from a diff the consumer stored at approval, has no
raw text and is compared with the fresh diff redacted under the session's policy. If anything
changed in between, the consumer gets `NetconfError::Drift { fresh }`, carrying the fresh diff as
the policy lets it through — redacted as `diff` is.
That is the drift guard. **Every** failure in phase 2 before the commit goes in — drift, a
timeout, a broken connection — discards the candidate and unlocks before the error is returned,
 so the device is never left locked with an unreviewed candidate.

Everything that comes back is reported. Phase 2 returns the device's answers to the
commit and the unlock, `[("commit-configuration", reply), ("unlock", reply)]`. A commit
the device answered without an error, followed by an unlock that failed, is `CommittedThenFailed`
— the change is live, nothing is discarded, and the unlock's error is inside, with the device's
answer to the commit in `reply`. A commit that got no readable answer is
`CommitUnanswered`, carrying what happened instead. A cleanup that fails after any failure makes
the error `CleanupFailed`, carrying both. Either comes inside `WithReplies` when a request of the
cleanup went through. `abort_change` attempts both discard and unlock and
reports every failure; it returns their answers, `[("discard-changes", reply), ("unlock", reply)]`,
and when one of them fails the other's answer goes with its error in `WithReplies`.


`fingerprint()` is **not** what the drift check uses. A consumer that wants to carry an approval
across a restart hashes `diff` with something it trusts.

> **`diff` is the diff as the policy let it through**: the device's secrets redacted,
> each replaced by `REDACTED` (§7), unless the policy has `allow_secrets` or is `all_free`. The
> drift comparison runs on the raw diff behind it. Only under a policy that lets
> secrets through is `redacted_diff()` a different string — then it is the one to **store and
> show**, and `has_secrets()` is true. `PreparedChange` has a
> private field, so it is built by `prepare_change` or `from_diff`, not as a struct literal;
> `Debug` shows `diff` alone.

---

## 6. `ConfigPolicy` — the write filter

The model is **WHAT × WHERE**: every rule says "in this place, these operations are allowed".
Everything else is refused — **default-deny**. Plus a **floor** that only `all_free` goes past.
Four kinds of policy: the ordinary one (`new`, `with_default_floor`), `read_only`,
`all_free` and `all_deny` — see below.

```rust
pub enum Op { Set, Delete }
pub enum Match { Node, Subtree }
pub enum Access { Ro, Rw, Rwd }
pub enum Scope { LogicalUnits, InterfaceDescriptions, Protocols } // #[non_exhaustive]

pub struct Change { pub op: Op, pub path: Vec<String> }
pub struct Violation { pub change: Change, pub reason: String }
pub struct Rule; // readable: see below
impl Rule {
 pub fn pattern(&self) -> String; // e.g. "interfaces * unit *"
 pub fn match_kind(&self) -> Match;
 pub fn ops(&self) -> &[Op];
}

impl Access { pub fn permits(self, op: Op) -> bool; } // Ro→none · Rw→Set · Rwd→Set+Delete

pub struct ConfigPolicy;
impl ConfigPolicy {
 pub fn new(protected_roots: &[&str]) -> Self;
 pub fn with_default_floor() -> Self; // the ordinary policy: sensitive trees need allow_read
 pub fn read_only() -> Self; // show and reads as the ordinary policy; no command and no change, whatever is granted
 pub fn all_free(access: Access) -> Self;
 pub const fn all_deny() -> Self; // nothing — what a session without a policy has
 pub fn grant(self, scope: Scope, access: Access) -> Self;
 pub fn allow(self, pattern: &str, m: Match, ops: &[Op]) -> Self;
 pub fn check(&self, changes: &[Change]) -> Result<(), Violation>; // first violation
 // Introspection: netconf ANSWERS what a filter permits —
 // a consumer can build a dynamic rule system and still show what applies.
 pub fn rules(&self) -> &[Rule];
 pub fn protected_roots(&self) -> &[String];
 pub fn all_free_access(&self) -> Option<Access>;
 pub fn is_all_free_rwd(&self) -> bool; // the session's Text/Xml gate
 pub fn is_all_deny(&self) -> bool;
 pub fn is_read_only(&self) -> bool;
 pub fn describe(&self) -> String; // human-readable summary
 // Reads + commands:
 pub fn allow_read(self, root: &str) -> Self; // grant: read a sensitive tree
 pub fn allow_command(self, prefix: &str) -> Self; // grant: op command beyond show; blank grants nothing
 pub fn allow_secrets(self) -> Self; // grant: the device's secrets come through unredacted
 pub fn secrets_allowed(&self) -> bool; // always true under all_free
 pub fn read_allows(&self) -> &[String];
 pub fn command_allows(&self) -> &[String];
 pub fn check_config_read(&self, targets: &[String]) -> Result<(), String>; // [] = the whole configuration
 pub fn check_command(&self, cmd: &str) -> Result<(), String>;
}

pub const SENSITIVE_READ_ROOTS: &[&str]; // system · security · access · groups · apply-groups · event-options
pub const READ_ONLY_PIPES: &[&str]; // the pipes a `show` may carry

pub const DEFAULT_PROTECTED_ROOTS: &[&str];
pub const KNOWN_TOP_LEVEL_HIERARCHIES: &[&str];
pub fn is_known_top_level(token: &str) -> bool;
pub fn verb_class(verb: &str) -> Option<Op>; // None = unknown → deny
pub fn parse_set_payload(payload: &str) -> Result<Vec<Change>, ParseError>;
pub enum ParseError { UnknownVerb(String), EmptyPath(String), UnbalancedQuote(String), Comment(String), SingleQuote(String), ControlCharacter { line: usize, character: char } } // #[non_exhaustive]
```

### Parsing a set payload

`parse_set_payload` reads one statement per line, `<verb> <path> [value]`, and rejects the
**whole** payload on an unknown verb (`edit` included), an empty path, an unbalanced quote, a
single quote or a `/*` comment outside a string, or a control character other than a tab. We never silently skip a statement we do not understand — it would otherwise reach the
device unchecked, and that is the bypass surface itself.

| Class | Verbs |
|---|---|
| `Op::Set` | `set` · `insert` · `copy` · `replace` · `annotate` · `activate` · `protect` |
| `Op::Delete` | `delete` · `deactivate` · `unprotect` · `wildcard delete` · `rename` |

- **Lines** end with `\n` or `\r\n`: where `str::lines` ends a line, and the two that XML turns
  into a newline before the device reads the payload. Any other control character — a carriage return that does not end a
  line, NUL, vertical tab, form feed, DEL, C1 — is `ControlCharacter`, and so are the
  Unicode line and paragraph separators U+2028 and U+2029, inside a string or
  out, checked on every line before any line is parsed: a lone `\r` is a line break to the device
  and none to the parser, so `#\rdelete protocols` was a skipped `#` line here and a
  `delete protocols` on the device. A tab is whitespace, and passes.
- **Tokens** are split on whitespace. A `"…"` sequence is one token, without the quotes. Inside
  it, `\` makes the next character literal and is itself dropped — `\"` is a quote that does not
  close the string, `\\` is one backslash — and a `\` that ends the string is an unbalanced
  quote. `""` is a token of its own — an empty value, not a missing one.
- **Only `"` quotes a value.** A `'` outside a string is `SingleQuote`; inside `"…"` it
  is an ordinary character.
- **Comments:** a line that begins with `#` is skipped whole. A `#` outside a quoted
  string makes the rest of its line a comment, and the line is judged without it: `delete
  protocols # x` is `delete protocols`, and the floor refuses it. Inside `"…"`, `#` is text. `load_configuration` sends a set payload without
  its `#` comments, so the device reads what the policy judged. A `/*` that begins a
  token outside a quoted string is `Comment`: a comment is not sent to a device, it goes
  in a quoted string. Inside `"…"`, or inside a token (`a/*b`), it is ordinary text.
- **`rename` and `copy`** have a filter of their own: `<path> to <tail>`, both sides there, or the line is `EmptyPath`. The words after
  `to` replace as many words at the end of the path, as Junos names the new identifier on the
  same level — `rename interfaces ge-0/0/0 unit 10 to unit 20` writes `interfaces ge-0/0/0 unit
  20`, and as many words as the path has, or more, are the whole target. `rename` is a `Delete`
  of the path and a `Set` of the target; `copy` a `Set` of the target, its source untouched. The
  floor and the rules judge both. `load_configuration` then reads the candidate configuration in
  set format, and when a target is there already, or a line before it writes it, the payload is
  refused as `Policy` and nothing is sent: a rename or a copy creates, it does not overwrite.
- **`edit` is not a verb**: it makes later lines relative to a new context, and the
  filter reads every line as a full path. It is `UnknownVerb`, with a message saying so.
- **Case:** verbs are lowercase only — `SET` is `UnknownVerb`.

A line-carrying `ParseError` (`EmptyPath`, `UnbalancedQuote`, `Comment`, `SingleQuote`) holds the line
**already redacted** with `redact_secrets`, because the text ends up in `NetconfError::Policy`
and from there in the consumer's log. `UnknownVerb` holds the unrecognised word, redacted the same
way: `$9$hunter2 x` is `unknown verb «$9$[SENSITIVE: …]» (denied, fail-closed)`. A word with nothing to redact —
`edit`, `SET`, `frobnicate` — comes through as written.
`ControlCharacter` holds no text at all: `line` is the line number, counted from 1 as
`str::lines` counts, and `character` the character.

`ParseError` is `#[non_exhaustive]`: a match on it needs a wildcard arm.

`Display`:

| Variant | Text |
|---|---|
| `UnknownVerb` | `unknown verb «v» (denied, fail-closed)` — and when the lowercase of the word is a verb, `unknown verb «SET» — verbs are lowercase, and «SET» is not «set» (denied, fail-closed)` |
| `EmptyPath` | `line without a path: «line»` |
| `UnbalancedQuote` | `unbalanced quote: «line»` |
| `UnknownVerb` for `edit`, `top`, `up`, `exit` | `«edit» moves the context later lines are read in, and the filter cannot follow it — write every line with its full path (denied, fail-closed)` |
| `Comment` | `a /* comment cannot be sent to a device — a comment goes in a quoted string (denied, fail-closed): «line»` |
| `SingleQuote` | `single quote outside a string — only " quotes a value (denied, fail-closed): «line»` |
| `ControlCharacter` | `a control character or line separator, U+<hex>, on line <n> — a line ends with a newline or CRLF, and only a tab may appear in it besides printable text (denied, fail-closed)` |

### Rules and matching

A pattern is space-separated tokens; `*` matches any one token, and every other token matches
**exactly, case included** — Junos names are case-sensitive, and `policy-statement EXPORT` is not
`export`. `Match::Node` matches a path of the same length; `Match::Subtree` a path **strictly
longer** than the pattern, with the same prefix.

`grant` adds these rules. The ops are `[Set]` for `Rw` and `[Set, Delete]` for `Rwd`; `Ro` adds
nothing.

| Scope | Rules |
|---|---|
| `LogicalUnits` | `interfaces * unit *` Subtree (ops) · `interfaces * unit *` Node `[Set]` — creating the unit · with `Rwd` also Node `[Delete]` — deleting the whole unit |
| `InterfaceDescriptions` | `interfaces * description` and `interfaces * unit * description`, each as Subtree and as Node (ops) |
| `Protocols` | `protocols *` Subtree (ops) — below a protocol, never the protocol node itself |

`Scope` is `#[non_exhaustive]`: a match on it needs a wildcard arm.

### The floor

`Op::Delete` of a whole protected top-level tree — `delete`, `deactivate`, `unprotect`, `rename` or
`wildcard delete` of the one-token path itself, and `wildcard delete <tree> *` with a literal `*` —
is refused under every policy except `all_free`, before any rule is consulted.
`logical-systems <name>` and `tenants <name>` hold a configuration of the same kind as the top
level: the system itself is not deleted, nor emptied with `*`, and what is under it is
judged as it would be at the top level, by the floor and by the rules — a rule matches the path
under the system, or the path as written. A bare `delete <tree>` rips out something that makes the device
unreachable or unmanageable. The floor compares **case-insensitively**: it is the one
rule meant to hold on its own, not because default-deny also happens to catch `System`.

The floor is the list given to `new`; `with_default_floor` and `read_only` use
`DEFAULT_PROTECTED_ROOTS` — verified
against the Juniper hierarchies for MX/PTX/ACX/SRX:
`system` · `interfaces` · `chassis` · `vmhost` · `protocols` · `routing-options` ·
`routing-instances` · `security` · `groups` · `apply-groups` · `class-of-service` ·
`policy-options` · `firewall` · `snmp` · `services` · `forwarding-options` · `vlans` ·
`bridge-domains` · `access` · and `logical-systems` · `tenants` · `virtual-chassis` ·
`multi-chassis` · `fabric` · `dynamic-profiles` · `accounting-options`.

`KNOWN_TOP_LEVEL_HIERARCHIES` is **not consulted by the policy**: default-deny refuses an unknown
top-level token because no rule allows it. The list lets a consumer tell «a tree I did not grant»
apart from «a tree that does not exist», and it is the list to show when someone asks which
hierarchies exist, and to build filters from. `is_known_top_level(token)` looks a token up in it,
exactly. It is the union across classic Junos and Evo, and the real set varies per device and
release:
`system` · `interfaces` · `chassis` · `routing-options` · `routing-instances` · `protocols` ·
`policy-options` · `firewall` · `firewall-options` · `class-of-service` · `forwarding-options` ·
`snmp` · `accounting-options` · `access` · `groups` · `apply-groups` · `apply-groups-except` ·
`apply-flags` · `apply-path` · `security` · `event-options` · `dynamic-profiles` · `applications` ·
`services` · `logical-systems` · `tenants` · `bridge-domains` · `vlans` · `switch-options` · `poe` ·
`virtual-chassis` · `fabric` · `multi-chassis` · `vmhost` · `diameter` · `jsrc` · `unified-edge` ·
`smtp` · `provider` · `schedulers` · `security-intelligence` · `health-monitor` ·
`protection-group` · `routing`.

### Refusals

`check` returns the first `Violation`; its `reason` is one of:

- `absolute floor: cannot delete the top-level tree «<tree>»` — for a nested system itself,
  `«logical-systems <name>»`
- `absolute floor: cannot delete the top-level tree «<tree>» of «logical-systems <name>»` (or
  `tenants`)
- `default-deny: no rule allows this (op, path)` — followed by `— paths are case-sensitive, and
  the same path in lowercase would be allowed` when that is true. The hint approves
  nothing.
- `all-free: <access> does not allow <op>`
- `all-deny: nothing is permitted`
- `read-only: no change is permitted, whatever is granted`

In the session these arrive as `NetconfError::Policy`, as do `could not parse payload: <ParseError>`
and the refusals for a missing policy, for a policy that permits no change, for
`rollback(n > 0)` without `all_free(Rwd)`, for `Text`/`Xml` without `all_free(Rwd)` — `policy
enforcement is only implemented for Format::Set (got <format>); raw Text/Xml loads require the
deliberate ConfigPolicy::all_free(Rwd)` — and for a `rename` or `copy` whose target is there
already: `the target «<path>» of a rename or copy is there already in the candidate configuration
— a rename or a copy creates, it does not overwrite (denied, fail-closed)`, or `…, written by a
line before it — …`.
The session's own gate comes first, so `read-only: no change is permitted …`,
`all-free: Ro does not allow …` and the policy's `all-deny: nothing is permitted` are reached
only through `check` and `check_command` directly; through a helper the session's texts are what
arrive: `no policy bound to the session …`, `all-deny: nothing is permitted — the policy bound to
this session denies every read, command and change`, `the policy bound to this session permits no
change …`.

### `all_free`

`all_free(access)` enforces **only the access level**, on any path — no scope rules and **no
floor**. For reading, every `all_free` level opens every tree, `Ro` included; for commands beyond
`show`, only `all_free(Rwd)` does, and then the command is not checked at all. Nothing is
redacted under it. **It turns the filter off:** netconf then runs without the feature
it exists for, and the floor, the read gate and the redaction hold for every policy but this one.
It exists for consumers that need "read/write/delete everything", and must be chosen deliberately.
Fail-closed parsing still applies.

### `read_only` and `all_deny`

`read_only()` is the ordinary policy's reading side and nothing else: `show` with its read-only
pipes, configuration reads with the sensitive trees behind `allow_read`, the device's secrets
redacted unless `allow_secrets` — and no command beyond `show` and no change, **whatever is
granted**: `allow_command`, `grant` and `allow` added to it have no effect.
`all_free_access()` is `None` for it.

`all_deny()` permits nothing — no read, no `show`, no command, no change — whatever is granted. It
is what a session without a bound policy has; bind it to say so out loud. It is a `const fn`, so a
`static` can hold it.

**The crate delivers the mechanism, not the policy.** Which modes exist is the consumer's
business — consumers compose theirs as `grant`/`allow` chains. *(The rules told in prose, with
examples: `docs/Filter.md`.)*

---

## 7. `redact` — the read filter

`ConfigPolicy` is the *write* side. This is the *read* side: what we fetch **from** the device
can carry the **device's** secrets. The session applies it to every reply, and to what
the device sent that it hands on otherwise — in an error, the hello, what the device said over
SSH — unless the policy has `allow_secrets` or is `all_free` — `all_deny` redacts even with `allow_secrets`, since
nothing it permits can carry a secret; the functions here are the same filter, for text the
consumer holds itself.

```rust
pub const REDACTED: &str = "[SENSITIVE: hidden by netconf — allow_secrets() on the policy shows it]";

pub struct Redactor;
impl Redactor {
 pub fn strict() -> Self; // SNMP community too
 pub fn snmp_community_visible(self) -> Self; // ← the default
 pub fn redact(&self, text: &str) -> String;
}
impl Default for Redactor { … } // = strict().snmp_community_visible()

pub fn redact_secrets(text: &str) -> String; // Redactor::default() — the SNMP v2c community stays visible
pub fn contains_secrets(text: &str) -> bool; // would redact_secrets change it? Warn WITHOUT logging the content
```

`redact` preserves the **line structure exactly** — line count, indentation, line breaks,
CRLF. A redacted diff therefore still reads as a diff. It is **idempotent**: a second
pass over its own output changes nothing. Each line is read until the rules find nothing more to
redact in it, and the secret elements a line leaves open are read on the line as it goes out.


**How a line is read**. Each line is read with its XML entities as the characters they
stand for — the five predefined ones and character references — so `&#x24;9&#x24;` is a `$9$`
and `authentication-&#107;ey` a statement name, in an XML reply as in a diff; what is not redacted
goes out as it came in, entities and all. Whitespace and the ASCII control characters separate
words. Every rule reads the line as it stands, and what any of them finds is redacted. Markup is
read only as XML writes it — a tag whose `<`, `>`, `=` and quotes are in the line as written; a
comment, a CDATA section, a processing instruction, a tag that is not well formed and text that
came from `&lt;…&gt;` are text like any other. The marker gets no treatment of its own: text that
looks like it is redacted like any other — a value beginning with it, and a `SECRET-DATA` line
holding it, too.

What is redacted:

- **By statement**. A statement from the list of those Junos keeps a secret in, by its exact name — the list, with
  where each is from, is in `docs/Filter.md`:
  `encrypted-password`, `plain-text-password-value`, `authentication-key`,
  `hello-authentication-key`, `authentication-password`, `privacy-key`, `privacy-password`,
  `simple-password`, `pre-shared-key`, `cak`, `secret`, `chap-secret`, `default-chap-secret`,
  `shared-secret`, `pap-password`, `local-password`, `default-pap-password`, `passphrase`,
  `challenge-password`, and the tokens `token`, `api-token`, `bearer-token`, `access-token`,
  `auth-token`, `authentication-token`, `refresh-token` and `oauth-token`;
  and in their context: `key` after `md5 N`, `authentication` or `encryption`; `ascii-text` and
  `hexadecimal` after `pre-shared-key` or `key`; `password` after `firewall-user`,
  `admin-search`, `authentication`, `proxy`, `client [<name>]`, `archive-sites <url>` or
  `url <url>`;
  `value` after `authentication-key N [type T]`. The context is the words before the name on the
  line, those of the text-format blocks it is in, or the `[edit …]` banner of a diff; in XML, the
  parent element. A word that merely holds one of these is none of them.
  The **first** such statement on a line wins, and everything after it becomes `REDACTED` — the
  trailing `;` `{` `}` `]` `)` and a `## …` or `/* … */` annotation are kept, and a list value
  keeps its own closing bracket: `secret [ "$9$a" "$9$b" ];` → `secret [SENSITIVE: …];`;
  the punctuation, the annotation and the whitespace between them are kept as they stood.
 An annotation is a word of its own, as Junos writes it; one glued to the value or
  inside a quoted value is part of the value, and past an annotation the line is read on.
 The whole line is scanned: `description`, `annotate`
  and `comment` do not end the scan, since they are also names in a path. A quoted
  free-text value is one token; it matches a statement only when the quoted word is itself one of
  these names. A name that says it alone is also read out of whatever is glued to it that cannot
  be part of a name — a control character, punctuation — and what follows the name is the value:
  `\u{7}secret x` and `x(secret y` are caught. No name is read out of the element's
  name in a tag as XML writes it; the element rule reads the tag. A name with a tag
  straight after it, `secret<x>`, is an element's text and has no value.
- **SNMP communities** (`community`, and `community-name` in SNMPv3) only under `strict()`, and
  not under `policy-options`, where a community is a BGP name. **SNMPv3 keys and passwords are always redacted.**
- **Hash and obfuscation literals** anywhere — `$<tag>$…` for any tag of one to four letters or
  digits: `$9$`, `$8$`, `$6$`, `$5$`, `$1$`, `$0$`, `$2a$`, `$sha1$` and the rest — become
  `$<tag>$` followed by `REDACTED`; the tag stays, so the operator can see which form it was.

- **The password in a URL** anywhere — `scp://user:password@host/path`, an archive site — becomes
  `REDACTED`; the user, the host and the path stay.
- **SSH key blobs** anywhere, by their base64 key-type prefix. The prefixes are those of public
  keys, so a public key under `system login user … authentication ssh-rsa` loses its blob; the
  statement name and the comment stay.
- **PEM blocks**, on one line or across lines; the `BEGIN`/`END` markers stay. Body text on a
  marker's own line goes too, any number of blocks may end and begin on one line, and a BEGIN
  marker without its closing hyphens fails closed: only a plain label is kept. What
  stands outside a block on such a line is read by the other rules.
- **XML leaves** `<name …>value</name>` whose local name is a secret statement — under its
  parent, where the list says one — attributes and all; and a value on the lines after such an element is opened, until the closing tag
  that names the **same** local name — including any value already on
  the opening tag's own line, and with attributes on the opening tag
  (`<authentication-key junos:changed="changed">`, the value on the next line, or the tag itself
  cut by the line end). Several elements can be open at once, each until its own closing tag; one whose
  opening tag went with a statement's value on the same line is carried all the same, and on the
  line that closes them, what follows the closing tag is read like any line. The tags stay as they were, but for the closing tag of an element whose opening
  tag went with a value.
- **The `SECRET-DATA` net.** A line Junos itself marks `SECRET-DATA` gets its value redacted
  anyway — after the statement name, also on a diff line whose `+`/`-`/`!` marker is a word of
  its own — unless a secret statement on it is written as a word of its own with a value
  after it. It fires on what the line holds, not on whether another rule changed it.


**The SNMP v2c community stays readable by default.**

---

## 8. Error model — three branches the consumer tells apart programmatically

```rust
pub enum NetconfError { // #[non_exhaustive]
 Transport(TransportError), // the network failed
 Protocol { detail: String, received: Option<String> }, // we spoke wrongly; received = what the device sent
 Device(Box<DeviceError>), // Junos said no — boxed
 Timeout { op: &'static str, partial: String }, // op: "ssh-connect" · "ssh-subsystem" · "rpc-recv" · "rpc-send" · "session-ttl"; partial = the incomplete message
 Policy(String), // our own policy stopped it — before anything was sent
 Drift { fresh: String }, // the diff changed between approval and commit; fresh = the fresh diff
 ChangedSinceConfirmed(Box<DeviceChanged>), // the device changed between a confirmed commit and its confirming commit, which was withheld
 CommittedThenFailed { reply: String, error: Box<NetconfError> }, // the commit succeeded, then a later step failed; reply = the answer to the commit
 CommitUnanswered(Box<NetconfError>), // a commit got no readable answer; inner = what happened
 CleanupFailed { error: Box<NetconfError>, cleanup: Vec<(&'static str, NetconfError)> }, // steps "discard-changes", "unlock"; "close", "disconnect"
 WithReplies { replies: Vec<(&'static str, String)>, error: Box<NetconfError> }, // the answers to the requests that went through around a failure
 CloseFailed { error: Box<NetconfError>, end: Box<SessionEnd> }, // close() failed; end = what the session held
}

pub enum TransportError { // #[non_exhaustive]
 Io(String),
 Negotiation { offered: Vec<String>, detail: String }, // what the peer actually offered
 HostKey { observed: Option<String>, detail: String }, // the key the device presented
 SubsystemUnavailable { stderr: String, ssh: Box<SshMessages> }, // the device did not open the netconf subsystem; ssh = what it said over SSH
 AuthRejected { username: String, remaining_methods: Vec<String>, partial_success: bool }, // the login was not let through
 Closed { detail: String, partial: String, ssh: Box<SshMessages> }, // the device ended the channel or the connection
}

// DeviceChanged, ConfirmedCheck, SshMessages, ExitSignal and SshDisconnect are in netconf::error,
// not re-exported at the root.
pub struct DeviceChanged { // what withheld a confirming commit
 pub check: ConfirmedCheck,
 pub confirmed: String, // the recorded entry: name=value, joined with " · "
 pub now: String, // the device's last entry now, written the same way
 pub rollback: Option<u32>, // what the diff is taken against; None = the confirmed commit is no longer in the history
 pub diff: Option<String>, // None when rollback is, and when fetching it failed
 pub diff_error: Option<Box<NetconfError>>, // why the diff could not be fetched
}
pub enum ConfirmedCheck { LastCommit, Candidate }

pub struct SshMessages { // what the device said over SSH; Default = nothing
 pub banner: Option<String>, // RFC 4252 §5.4; several joined by a line break
 pub exit_status: Option<u32>, // RFC 4254 §6.10
 pub exit_signal: Option<ExitSignal>, // RFC 4254 §6.10
 pub disconnect: Option<SshDisconnect>, // RFC 4253 §11.1
}
pub struct ExitSignal { pub name: String, pub core_dumped: bool, pub message: String, pub language: String }
pub struct SshDisconnect { pub code: u32, pub description: String, pub language: String }

pub struct DeviceError { // the fields are Option — Junos omits some — and the lists empty when there is nothing
 pub error_type: Option<String>, pub tag: Option<String>, pub severity: Option<String>,
 pub path: Option<String>, pub message: Option<String>,
 pub app_tag: Option<String>, pub info: Option<String>, // info keeps the element names
 pub other: Vec<(String, String)>, // every other child of the <rpc-error>, by name; loose text as "#text"; a comment or PI as "#comment" or "#pi"; a field sent again, by name
 pub also: Vec<DeviceError>, // every other <rpc-error> of the reply, errors and warnings
 pub rest: Option<String>, // the reply with every <rpc-error> cut out, when that is more than <ok/>
}
impl DeviceError { pub fn explanation(&self) -> Option<&'static str>; }
```

**`error-tag` is translated for some tags**. The tags are standard — RFC 6241,
Appendix A, the reference for all of them. `explanation()` gives the meaning for `lock-denied`,
`in-use`, `access-denied`, `invalid-value`, `data-exists`, `data-missing`, `unknown-element`,
`bad-element` and `operation-not-supported`, and the error text reads
`<tag> — <meaning> (RFC 6241, Appendix A): <the device's message>`. The device's own words are
always kept; any other tag reads `<tag>: <message>`.

The point of three branches is that the consumer can act correctly **without parsing text**.
`Negotiation` carries `offered` deliberately: against an old device "negotiation failed" is
useless, while "it offered these four algorithms" is immediately actionable.

`HostKey` carries `observed` for the same reason: the key the device actually presented is
known already in `check_server_key`, that is **before** the error is built. Without it the consumer
had to connect a second time to tell the operator what answered — and then the evidence was "what
answered when we asked again", not "what was presented in the handshake that broke". `None` means the
key exchange never got far enough for a key to be seen.

`SubsystemUnavailable` means the login went through — address, host key and credentials
are fine — and the device did not open the `netconf` subsystem: it answered the request with a
failure, or closed the channel before it answered. That is a device without NETCONF over SSH (on
Junos, `set system services netconf ssh`). `stderr` is what the device wrote there first, trimmed and made printable;
usually empty.

`AuthRejected` means the device did not let the login through with the password. It
carries what the device said: `remaining_methods`, the methods it accepts, in its order and by their
SSH names (russh keeps only the names it knows) — if it wants `publickey` or `keyboard-interactive`,
the password was never the problem; and `partial_success`, which means the device **accepted** the
password and requires further authentication. `username` is the one the login was attempted as.

`Timeout { op: "session-ttl", .. }` means the session's hard lifetime was reached —
routing, not a network failure: open a new session for the next task. Error texts are English.

**The device's content is data, beside the words**. `Protocol::received`,
`Timeout::partial`, `Closed::partial`, `Drift::fresh`, `CommittedThenFailed::reply`,
`WithReplies::replies`, `DeviceError::rest`, the diff of `DeviceChanged` and the texts of
`SshMessages` hold what the device sent, as it sent it — through a session, filtered as §2 says;
the entries of `DeviceChanged` and `DeviceError::other` are filtered as the device wrote them and
then made printable. The error's `Display` takes it along, made printable, so the text stands on its own:
`; the device sent: …`, `; the incomplete message so far: …`, `; the fresh diff: …`, `; the diff
against rollback N: …`, and `(empty)` for an empty one. `DeviceChanged::rollback` and `diff` are
`None` together when the confirmed commit is no longer in the device's commit history; `diff` is
`None` with `rollback` set when fetching it failed, and `diff_error` then holds the error.
`ConfirmedCheck` is `Copy + Eq`; `DeviceChanged` is not `Clone`, since it can hold an error;
`SshMessages`, `ExitSignal` and `SshDisconnect` are `Clone + Eq`, and `SshMessages` is `Default`.

`Closed` means the device ended the channel or the connection: before a message was
complete — `partial` is what had arrived of it — or with something said on the way out; from
`RusshTransport::close`, also that the device sent data after the session was over, which is then
in `partial` (§9). `ssh` is
what the device said over SSH; empty when it said nothing. `SubsystemUnavailable::ssh` is the same
for a subsystem the device would not open.

**`DeviceError`** is filled from the first `<rpc-error>` that is not `severity=warning` (a warning is
**not** fatal — R14 often emits commit warnings), and every other `<rpc-error>`
of the reply is in `also`. A self-closing `<rpc-error/>` is still an error. `info` is the text of `<error-info>` — Junos names the
statement it objected to in `<bad-element>` there — with the names of the elements in it
kept: each is `name: text`, nested names joined by `/`, an empty one `name:`, and the
parts joined with ` · `, so `<error-info><bad-element>unit</bad-element></error-info>` reads
`bad-element: unit` and a lock's `<session-id>7</session-id>` reads `session-id: 7`; a
`<bad-element>` straight under `<rpc-error>` reads the same. Markup inside any other field stays
part of its text, and a field name nested inside an open field does not start a new one:
 `bad <bad-element>unit</bad-element> here` reads as `bad unit here`.

**Nothing in an `<rpc-error>` is dropped**. A child that is none of the fields —
Junos's `<source-daemon>`, among others — is in `other` as its local name and its text, an empty
one with empty text, and text outside every element as `#text`, in the device's order; made
printable like the fields; a comment or processing instruction inside it is there as `#comment` or
`#pi`, and one outside the errors makes the rest of the reply worth carrying. **Nothing
is overwritten**: a field the device sends more than once
keeps the first in its place, and each later one goes into `other` by its name. An empty field — `<error-message/>` — is present and empty, `Some("")`,
where it read as absent; an empty `<bad-element/>` makes `info` `bad-element:`. **The rest of the reply goes with the first error** in `rest`:
the reply with every `<rpc-error>` cut out, as the device sent it, when what is left is more than
`<ok/>` — text, or an element with no child that is not `ok` or the root. A commit's
`<commit-results>` naming the routing engine is more; `<load-configuration-results><ok/>` around the
errors is not. `None` on the entries in `also`. Through a session, `other` and `rest` come with the
device's secrets redacted unless the policy lets them through, on the error and on every warning
`take_warnings` hands over. **Every field follows the policy too**: Junos echoes the
offending configuration line in `path`, `message` and `info`, and nothing makes it keep
`error-type`, `-tag`, `-severity` and `-app-tag` to fixed values; each comes with the device's
secrets redacted unless the policy lets them through — redacted as the device wrote it, then made
printable. `rpc::parse_rpc_reply`, with no policy bound, redacts every field,
`other` and `rest` with `redact_secrets`. Every field is made printable:
a control character, or U+2028/U+2029, is written out as an escape (`\n`, `\r`, `\t`,
`\u{XXXX}`), so the device's text stays on its line and shows what it holds.

`Display`:

| Type | Text |
|---|---|
| `NetconfError` | `transport: …` · `protocol: <detail>`, then `; the device sent: <received>` when it is `Some` · `device: <DeviceError>` · `timeout: <op>`, then `; the incomplete message so far: <partial>` when it is not empty · `policy: …` · `drift: a fresh show\|compare deviates from the approved one; the fresh diff: <fresh>` · `changed since the confirmed commit: <DeviceChanged>` · `committed: the commit succeeded, then this failed: <error>`, then `; the device's answer to the commit: <reply>` · `commit unanswered: a commit was sent and no readable answer came back: <error>` · `<error>; the cleanup after it failed too: <step>: <error>; …` (`CleanupFailed`, 0.5.7) · `<error>`, then `; the device's answer to <step>: <reply>` for each in `replies` (`WithReplies`, 0.5.13) · `close: <error>`, then `; the session held this <severity>: <DeviceError>` for each warning, then what the device said over SSH as for `Closed` (`CloseFailed`, 0.5.13) |
| `DeviceChanged` | `the device's last commit is no longer the confirmed one — it was «<confirmed>», it is «<now>»; the confirming commit is withheld, and the device rolls the confirmed commit back by itself when its timeout runs out`, or `the candidate holds <n> line(s) of changes that are not the confirmed commit's; …`; then `; the diff against rollback <N>: <diff>`, `; the diff against rollback <N> could not be fetched: <error>`, or `; the confirmed commit is no longer in the device's commit history, so there is no rollback to compare with` |
| `DeviceError` | `<tag>: <message> [path: <path>]` (`unknown` / `(no message)` when absent); for a translated tag `<tag> — <meaning> (RFC 6241, Appendix A): <message> …`; then ` [info: <info>]`, ` [app-tag: <app_tag>]` and ` [type: <error_type>]` for each that is present, and ` [<name>: <text>]` for each entry in `other`; then `; also <severity>: <DeviceError>` for each entry in `also`; then `; the reply besides its errors: <rest>` when `rest` is present |
| `TransportError` | `io: …` · `negotiation (<detail>); peer offered: <a, b>` · `host key: <detail>; device presented: <fingerprint>`, or without the second part when `observed` is `None` · ``the device did not offer the NETCONF subsystem — NETCONF over SSH is not enabled on the device (Junos: `set system services netconf ssh`)``, then `; the device said: <stderr>` when `stderr` is not empty · `SSH password authentication rejected by the device — <methods>`, or `the device ACCEPTED the password but requires further authentication — <methods>` under `partial_success`, where `<methods>` is `the device says it accepts: <a, b>` or `the device named no other method` · `closed: <detail>`, then the incomplete message as for `Timeout`. `SubsystemUnavailable` and `Closed` then add what the device said over SSH, each part present: `; the subsystem's exit status: <n>`, `; the subsystem's exit signal: <name>[, core dumped][, the device said: <message>]`, `; the device disconnected, reason code <n>[, and said: <description>]`, `; the device's login banner: <banner>` |

## Logging — the tracing facade

The crate emits structured events via `tracing` and never decides where they end up — the
consumer attaches a subscriber (without one, the facade is near-free). The events are part of
the contract:

| Event | Level | When |
|---|---|---|
| `ssh_connect` / `ssh_connect_failed` | info/warn | `ssh_connect`: the attempt (host, port, username, policy, `pinned`/`enrollment`), warn the first time per device under a legacy policy. `ssh_connect_failed` (host, port, `ssh_policy`, `error`): the TCP connection or the SSH handshake failed; a timeout, a rejected login or a refused subsystem are reported through their own errors, not this event |
| `ssh_auth_failed` | warn | authentication rejected (the methods the device named, `partial_success`) |
| `ssh_session_established` / `ssh_session_closed` | info | session lifecycle; established only once the device has opened the subsystem |
| `ssh_host_key_verified` / `ssh_host_key_mismatch` | debug/warn | pinned key matched / mismatch (rejected) |
| `ssh_host_key_enrollment` / `ssh_host_key_observed` | info | no pin — fingerprint observed |
| `ssh_host_key_probe` / `ssh_host_key_probe_failed` | info/warn | the `observe_host_key` run |
| `netconf_subsystem_stderr` | warn | the netconf subsystem wrote to stderr — the device's text |
| `secrets_in_diff` | warn | the compare diff `prepare_change` fetched carries device secrets (only a fingerprint is logged); `compare()` on its own emits nothing |

**The rules:** no event carries passwords, keys or unredacted config/diff content —
`secrets_in_diff` logs only a fingerprint, and fires only under a policy that lets secrets through.
 Text the device wrote — `netconf_subsystem_stderr` — is made printable before it is
logged. A legacy SSH policy is warned once per device; after
that its `ssh_connect` event still carries `legacy = true`, and `ssh_connect_failed` and
`ssh_session_established` name the policy in `ssh_policy`. The tag follows the policy, not the
negotiated algorithm. Error messages can be logged as they are: the device's text in them is
made printable where it is taken in — stderr, the fields of an `rpc-error`, a `message-id`, an
entity's name, the algorithm names a device announces (`Negotiation.offered`) and the
tag names quick-xml quotes in a parse error. A `message-id` and what the parser quotes
of the document — an end tag, an entity's name — are filtered as the reply is before they are
made printable: in a session under its policy, in the `rpc` parsing functions with
`redact_secrets`. The device's content an error carries is
made printable in its text as well; under a policy that lets secrets through it holds
them, as the reply would, and `redact_secrets` is the filter for such a log line. russh's text is
redacted where the transport takes it in, in the errors and in the events. The
`ssh_connect` event is logged
after the refusals for a missing pin and for `Custom`, so a refused connect does not spend the
device's one legacy warning.

---

## 9. `russh_transport` — real SSH *(feature `russh-transport`)*

```rust
pub struct RusshTransport;
impl RusshTransport { pub fn observed_host_key(&self) -> Option<String>; }

pub async fn observe_host_key(host: &str, port: u16, ssh_policy: &SshPolicy, timeouts: &Timeouts)
 -> Result<String, NetconfError>;
```

NETCONF runs as the **`netconf` subsystem** on the SSH session (RFC 6242); `port` is SSH's own.
`connect` returns only once the device has **answered** the subsystem request with a yes, or sent
data, which only a running subsystem does.
russh 0.62 returns from the request as soon as it is queued, so the transport reads the answer
itself, under `Timeouts::connect` and the session deadline (`Timeout { op: "ssh-subsystem" }`).

**The fingerprint format** is `SHA256:<base64 without padding>` — the form the `ssh` client shows.
A pinned key is compared by exact byte equality, with no normalisation.

The transport enforces the session TTL (§1): the frame is validated before anything connects, the
deadline is set at connection start, and `send`/`recv` refuse after the deadline. Each single
`send`/`recv` waits under `per_rpc`, or under `per_commit` while the session has a commit in flight.
 Before anything
connects, `connect` refuses — as `Transport(Io)` — a missing `host_key`, `SshPolicy::Custom`,
`Timeouts` outside their frames, and an empty host or username or one holding a control character
— a host may not hold whitespace either, and `observe_host_key` checks the host the
same way. Authentication therefore always has a pinned key; observation has
its own path. The password is taken out of the `SecretString` right before authentication, into a
copy that is zeroed on drop; russh makes its own copy internally, which is outside this crate's
control.

What a failure becomes (classified by russh's error types, not its message text):

| | Error |
|---|---|
| the key is not the pinned one, or the device's signature does not hold | `HostKey { observed }` |
| no common algorithm | `Negotiation { offered }` — what the device announced |
| key exchange failed otherwise | `Negotiation { offered: [] }` |
| the password was not accepted | `AuthRejected { username, remaining_methods, partial_success }` |
| the device refused the `netconf` subsystem, or closed the channel before answering | `SubsystemUnavailable { stderr, ssh }` |
| the device closed the subsystem after writing to stderr, or after saying something over SSH | `Closed { detail, ssh, .. }`, `detail` carrying the stderr text |
| the device closed the subsystem and said nothing | an empty read; the session makes it `Closed` *(§2)* |
| the login, the channel, the subsystem request or a send failed, after the device said something over SSH | `Closed { detail, ssh, .. }`, `detail` carrying russh's text |
| anything else | `Io` with russh's text |

russh's text — in `Io`, in the `detail` of `HostKey`, `Negotiation` and of a `Closed` a failure
becomes — goes through the filter where the transport takes it in, and so does the
`ssh_connect_failed` and `ssh_host_key_probe_failed` event built from it: the transport
has no policy to let anything through, and while connecting none is bound, so it is redacted.

**What the device says over SSH goes with the error a closed channel or connection brings**,
 in `ssh` (§8). The transport keeps the device's login banner (`SSH_MSG_USERAUTH_BANNER`,
several joined by a line break) and its disconnect message (`SSH_MSG_DISCONNECT`: reason code,
description, language), which russh hands to the client handler and its default dropped, and the
subsystem's `exit-status` and `exit-signal` from the channel. After the
device's EOF, `recv` reads on as before it: data that comes all the same is handed on, the exit
status and signal are kept, and the close — or a wait that runs out after the EOF — ends in the
close outcome. What arrives after `recv`
or `send` has returned comes with the next error, not the one before it; russh hands the
disconnect message to the handler as the connection ends, so it is there when the device sent it
before the channel closed. A key the device presented is recorded and read through a poisoned lock.


**`close`** sends EOF on the channel, reads what the device sends until it closes the
channel — the subsystem's exit status or signal come as it ends — and disconnects, and returns
what the device said over SSH; the wait is a read like any other, bounded by `per_rpc` and the
session's deadline, and a device that keeps the channel open past it is disconnected all the same.
Data the device sends after the session is over is no answer to anything and comes back as
`Closed { detail: "the device sent data after the session was closed", partial, ssh }`. russh fails
the EOF and the disconnect with `SendError` only when the SSH connection has already ended — after
`<close-session/>` the device may end it first — and that is the close having happened, not a
failure; any other failure is returned, carrying what the device said (`"disconnect"` in
`CleanupFailed` when it follows data after the close).

**`observe_host_key` solves a real ordering trap.** A consumer must not send a password
to a device it has not verified — but cannot verify the device without having seen its host key.
SSH solves this itself: **the host key is presented during key exchange, before
authentication.** The function runs KEX, reads the fingerprint and disconnects. **It takes no
credential parameter at all** — that a password cannot leak from here is a property of the
signature, not a rule anyone must remember. It runs under `timeouts` as `connect` does:
 they are validated the same way, and the TCP connection and key exchange end within
`connect`, counted from the start, and never past `total`. Running out is `Timeout { op: "ssh-connect" }`,
or `Timeout { op: "session-ttl" }` when `total` is what ran out. Before anything connects it
refuses, as `Transport(Io)`, what `connect` refuses of what it uses: `SshPolicy::Custom`
and `Timeouts` outside their frames.

It **pins nothing**. The transition observed → approved belongs to the consumer and requires a
human.

---

## 10. Low level and test tools

### `netconf::rpc` — message building and parsing

```rust
pub const BASE_1_0: &str; pub const BASE_1_1: &str;
pub fn client_hello(offer_1_1: bool) -> String;
pub fn wrap_rpc(message_id: u64, inner: &str) -> String;
pub fn parse_hello_capabilities(xml: &str) -> Result<Vec<String>, NetconfError>; // a Protocol error carries the hello in received, and what it quotes of it redacted
pub fn parse_rpc_reply(xml: &str) -> Result<Vec<DeviceError>, NetconfError>; // the checks in §2, a Protocol error carrying the reply; Ok = the warnings; the device's text in an error, and what a Protocol error quotes of the reply, redacted with redact_secrets
pub fn reply_message_id(xml: &str) -> Option<u64>; // digits, no leading zero, any u64 — the session itself compares the text, never this number
pub fn hello_session_id(xml: &str) -> Option<u64>; // read as RFC 6241's unsignedInt — digits, no leading zero, at most 4294967295
pub fn extract_compare_diff(xml: &str) -> Result<String, NetconfError>; // no <configuration-output> = Protocol; a Protocol error carries the reply in received, and what it quotes of it redacted
```

The parser is **lenient on purpose**: it matches on local element names and ignores prefixes and
namespaces, so both Junos' classic non-RFC replies and `rfc-compliant` mode parse. It never
panics on malformed input.

### `netconf::mock` — hardware-free protocol tests

```rust
pub type SentLog = Arc<Mutex<Vec<u8>>>;
pub struct MockTransport;
impl MockTransport {
 pub fn new(chunks: Vec<Vec<u8>>) -> Self;
 pub fn recording(chunks: Vec<Vec<u8>>) -> (Self, SentLog);
}
```

By splitting a reply into many small pieces you can verify that `Decoder` tolerates arbitrary
TCP boundaries. `recording()` gives a shared handle that can be inspected **after** the
transport has been moved into a session. `MockTransport::connect` connects to nothing and yields an
empty mock — use `new` with `NetconfSession::establish`. `recv` hands out the pieces in order, and
an empty `Bytes` — the peer closed — once they run out; `send` appends to the log and never fails.
Its `close` returns an empty `SshMessages`. The mock keeps no clock.

§10 is public surface like the rest: a change to it moves the floor.

---

## Known limits

- `SshPolicy::Custom` is not implemented — refused by `connect` and `observe_host_key`.
- `platform_hint`/`Platform` is reserved and not read.
- There is no keepalive.
- Policy enforcement reads set payloads only: a `Text` or `Xml` load — and `prepare_change` with
  either — requires `all_free(Rwd)`.
- russh 0.62 has no `hmac-md5`: a device that offers only that cannot be reached through
  `RusshTransport`.

