# How to use netconf

**In short:** this is the usage guide. [Home](Home.md) tells you what netconf is and what you can use it
for; here is **how** you actually do it, with examples. If you need the exact contract — every
signature, every field, every error variant — it is documented separately.

---

## Getting started

```toml
[dependencies]
netconf = { version = "0.5", features = ["russh-transport"] }
krypto  = "0.6"     # you need it for the password
```

**The feature flag is not optional if you are talking to real equipment.** Without
`russh-transport` you get the protocol layer and the simulated peer, but no SSH.

---

## Connecting to a box

```rust
use netconf::{Auth, ConnectOptions, NetconfSession, SshPolicy, Timeouts};
use netconf::russh_transport::RusshTransport;
use std::time::Duration;

let opts = ConnectOptions {
    host: "pe1.example.net".into(),
    port: 22,
    username: "netops".into(),
    auth: Auth::Password(krypto::SecretString::from_string(password)?),
    ssh_policy: SshPolicy::Modern,
    timeouts: Timeouts {
        connect:    Duration::from_secs(10),
        per_rpc:    Duration::from_secs(30),
        per_commit: Some(Duration::from_secs(120)), // the budget for commit RPCs; None = per_rpc
        total:      Duration::from_secs(300),
        max_total:  Duration::from_secs(300),
    },
    platform_hint: None,
    host_key: Some(known_fingerprint),   // required: the approved "SHA256:…" fingerprint; None is refused at connect
};

let mut session = NetconfSession::<RusshTransport>::connect(&opts).await?;
```

**The password must be a `krypto::SecretString`.** That is not a recommendation — the type system
does not accept an ordinary string. The password therefore cannot end up in a log by accident.

**The lifetime has TWO levels, and both are YOURS to set.** `max_total` is your absolute
ceiling — the adoption choice you make once (default 5 min, frame 1–10 min). `total` is THIS
session's TTL — the message about how long this particular task gets to live (≥ 1 s, ≤ the
ceiling): small tasks do not need long lives, a sequence with a commit-confirmed window needs
more. The clock starts when you connect; a reached deadline answers `Timeout { op: "session-ttl" }`
regardless of activity, and values outside the frames are refused at connect. Handle the
deadline deliberately: the next task gets a new session. *(New in 0.5.1 — before that, `total` was effectively an inactivity clock.)*

**`host_key`** is required: the fingerprint you expect, in the form `SHA256:<base64 without
padding>`, compared byte for byte. If the box presents a different key, the connection fails as
`Transport(HostKey { observed, .. })`, carrying the fingerprint it did present. `None` is refused
at connect, as `Transport(Io)`, before anything connects: `connect` authenticates, which means it
sends your password, so there is no unverified connection. The first time you meet a box, obtain
its fingerprint with `observe_host_key`, which runs the key exchange and disconnects without
logging in, and have a human approve it — see "Host key" further down.

### Old equipment

```rust
ssh_policy: SshPolicy::LegacyJunos,
```

Older boxes require SSH algorithms that modern libraries have stopped offering. `LegacyJunos` is a
**superset** of `Modern` — the modern ones are still negotiated first, the old ones are merely
allowed in addition.

**Set it per box, never globally.** And log when it is used:

```rust
if netconf::is_legacy(&algorithm) {
    tracing::warn!(algorithm, "outdated SSH algorithm in use");
}
```

The point is not to forbid the old ones — the span we support requires them. The point is that they
must be **visible**, so nobody discovers five years from now that half the network negotiated
something weak.

---

## Fetching something from the box

```rust
let config = session.get_configuration(None).await?;          // everything, or pass a filter
let out    = session.command("show l2circuit connections").await?;
```

> **What you fetch has the box's secrets redacted** (0.5.11), unless your policy says
> `allow_secrets()`. See "Redaction".

---

## Changing configuration safely

This is the main flow, and it is built around **a human seeing what will actually happen before it
happens**.

```rust
use netconf::{Format, LoadAction};

// Once, after connecting: bind the filter to the session (0.4.0).
// Without it, nothing is permitted (default-deny): no read, no show, no change.
session.set_policy(policy);

// Phase 1 — check against the filter, lock, load, fetch the diff
let prepared = session.prepare_change(
    &payload,
    Format::Set,
    LoadAction::Merge,
).await?;

// Show the operator the diff. Under the ordinary policy it is already redacted;
// only under allow_secrets is redacted_diff() a different string.
println!("{}", prepared.redacted_diff());

// Phase 2 — commit, but only if the box still shows the same diff
session.confirm_commit(&prepared, "l2circuit 13080042").await?;
```

**The filter is checked first, before anything is sent.** If the change is not allowed, you get
`NetconfError::Policy` and the box has seen nothing.

**The check lives in the library (0.4.0).** The policy is bound to the session with `set_policy` —
once — and every typed helper enforces it itself, whichever way in you take. With no policy
bound, nothing is permitted — not a read, not a `show` (0.5.11); if you deliberately want
everything, bind `ConfigPolicy::all_free(Rwd)` explicitly. (Raw `session.rpc()` is the low-level
layer and goes around the gates — not around the redaction.)

**Between phase 1 and 2 the candidate stays loaded and locked.** If you are not going to finish,
clean up:

```rust
session.abort_change().await?;    // discard + unlock
```

**If something changed in between, you get `NetconfError::Drift { fresh }`**, inside
`WithReplies`, which carries the box's answers to the discard and unlock that cleaned up after it. That is the drift
guard: the approval applied to a specific diff, and if the box no longer shows it, we do not
commit. Someone else may have been in. `fresh` is the diff the box shows now, redacted as the
approved one was, so a human can see what changed.

### Letting the box undo itself

```rust
session.commit_confirmed(10, Some("l2circuit 13080042")).await?;
// … verify that things actually work …
session.commit(None).await?;      // confirm — without this the box rolls back after 10 min
```

This is the safety net under everything else: if you lose the connection midway, or it turns out
the change took down the very thing you were working over, **the box reverts by itself**. Nobody
has to make it in time to save it.

### The individual operations, if you need them

`lock` · `unlock` · `load_configuration` · `commit_check` · `commit` · `commit_confirmed` ·
`rollback(n)` · `discard_changes` · `compare` — all exist separately. But use
`prepare_change`/`confirm_commit` when you can: that ordering is easy to get wrong by hand, and the
mistake is silent.

---

## The filter — what may be changed

The model is **where × what**: each rule says "at this place, these operations are allowed".
**Everything else is denied.** On top of that there is a floor no rule can override.

```rust
use netconf::{Access, ConfigPolicy, Match, Op, Scope};

// Most common: start from the floor and grant what you need
let policy = ConfigPolicy::with_default_floor()
    .grant(Scope::LogicalUnits, Access::Rwd)
    .grant(Scope::InterfaceDescriptions, Access::Rw);

// Or fully explicit
let policy = ConfigPolicy::with_default_floor()
    .allow("interfaces * unit *", Match::Subtree, &[Op::Set, Op::Delete]);

// Read, change nothing: show and configuration reads as the ordinary policy, and
// no command or change whatever you grant (0.5.11).
let policy = ConfigPolicy::read_only();

// Nothing at all — what a session without a policy has (0.5.11).
let policy = ConfigPolicy::all_deny();
```

**The floor:** `delete` of an entire protected top-level tree is denied no matter what you grant. A
bare `delete <tree>` rips out something that makes the box unreachable or unmanageable — that
mistake must not be possible to configure your way into.

**Unknown commands are rejected — the whole payload.**

```rust
match netconf::policy::parse_set_payload(&payload) {
    Err(e) => return Err(e.into()),   // unknown verb, empty path, unbalanced or single quote
    Ok(changes) => policy.check(&changes)?,
}
```

We never silently skip a line we do not understand. A line that is not understood would have gone
**unchecked** to the box — and that is the road around the whole filter.

**If you need "everything is allowed":**

```rust
let policy = ConfigPolicy::all_free(Access::Rwd);
```

It enforces only the access level, with no place or floor check. Choose it deliberately, not as a
shortcut because a rule was hard to write.

---

## Reads and commands — what is gated (0.5.0)

**Reading is open by default — except the sensitive trees.** `system`, `security`, `access`,
`groups`, `apply-groups` and `event-options` carry the box's secrets; reading them (via
`get_configuration` or `show configuration <tree>`) requires an explicit grant:

```rust
let policy = policy.allow_read("system");
```

`get_configuration(None)` (the full config) includes them — and requires a grant on all of them.

**Commands: only `show …` by default.** Ordinary `show` commands run under the device user's
OWN authorization on the box (the login class from RADIUS/TACACS) — netconf does not replicate
that, deliberately. Everything else (`request`, `clear`, `restart`, …) changes state and is
denied, unless the policy carries an explicit grant — or is the deliberate all/all rule:

```rust
let policy = policy.allow_command("request system reboot");   // rare, deliberate
```

> ⚠ What the default `show` scope should be will be revisited (Roger's note, 2026-08-16) —
> today's "all show is fine" is a first choice, not a verdict.

---

## Redaction — secrets in what you fetch

The filter above governs what you may **change**. This governs what is safe to **show**.

Configuration from a box contains the box's own secrets: obfuscated passwords, SNMP keys,
certificate blocks. They end up in a diff, in a `show` printout, in your log — and from there in a
log service and a backup.

**netconf redacts them before they reach you** (0.5.11). Everything the session returns has each
secret replaced by a marker that says what was there and how to read it:

```text
encrypted-password [SENSITIVE: hidden by netconf — allow_secrets() on the policy shows it]; ## SECRET-DATA
```

To read the secrets themselves, say so in the policy — and `all_free` redacts nothing:

```rust
let policy = ConfigPolicy::with_default_floor().allow_read("system").allow_secrets();
```

The functions below are the same filter, for text you hold yourself.

```rust
use netconf::{contains_secrets, redact_secrets};

if contains_secrets(&text) {
    tracing::warn!("output carried secrets — storing the redacted version");
}
let safe = redact_secrets(&text);
```

The redaction **preserves the line structure exactly** — line count, indentation, line breaks. A
redacted diff is still readable as a diff.

**If you need to control what is hidden:**

```rust
use netconf::Redactor;

let r = Redactor::strict();                          // SNMP community too
let r = Redactor::strict().snmp_community_visible(); // ← this is the default
```

> **Under `allow_secrets`, mind the split in `prepare_change`:** `prepared.diff` then carries the
> secrets and is what decides whether anything changed; `prepared.redacted_diff()` is the one you
> **store and display**. Under every other policy the two are the same string.

---

## Host key — who are you actually talking to

The first time you meet a box you do not have its fingerprint. Simply trusting the first thing you
see is weak, but requiring it up front makes it impossible to get started.

SSH solves this itself: **the box presents its key during the key exchange, before anyone logs in.**

```rust
use netconf::russh_transport::observe_host_key;

let fingerprint = observe_host_key(&host, 22, &SshPolicy::Modern, &timeouts).await?;
// show it to a human → the human approves → store it
```

**The function takes no password parameter at all.** That no secret can leak from it is a property
of the signature, not a rule you have to remember.

It runs under the same `timeouts` as a connection *(0.5.9)*: values outside the frames are refused
before anything connects, and the probe gives up within `connect`, never past `total` — as
`Timeout { op: "ssh-connect" }`, or `Timeout { op: "session-ttl" }` when `total` is what ran out.

It **pins nothing**. The transition from "observed" to "approved" is yours — and should require a
human. Then you pass it in as `host_key` when connecting.

If you are already connected:

```rust
let seen = session.transport().observed_host_key();
```

---

## Testing without equipment

The entire protocol layer can run against a simulated peer. That is how the library itself is
tested.

```rust
use netconf::mock::MockTransport;

// split the reply into many small pieces — this is how you verify framing is handled
let (transport, sent) = MockTransport::recording(vec![
    b"<hello>".to_vec(), b"...</hello>]]>]]>".to_vec(),
]);
let mut session = NetconfSession::establish(transport, true).await?;

// afterwards: inspect what the client actually sent
let bytes = sent.lock().unwrap().clone();
```

`recording()` gives you a shared handle that still works **after** the transport has been moved
into the session.

---

## Errors you can get

The branches mean different things:

| Error | Means | What to do |
|---|---|---|
| `Policy` | **your own** policy stopped it | fix the change — the box has seen nothing |
| `Drift` | the diff changed between approval and commit | have a human look at `fresh`, the diff the box shows now |
| `Device` | the box said no | read `message`/`path` — that is Junos answering |
| `Transport` | the network, SSH or the host key | see below |
| `Protocol` | we spoke wrongly, or the reply was incomprehensible | report it — this is a bug on our side; `received` is what the box sent |
| `Timeout` | the deadline ran out | `partial` is what had arrived of the message |
| `CommittedThenFailed` | the commit went in, then a later step failed | the change is live; `reply` is the box's answer to the commit |
| `WithReplies` | an operation failed after some of its requests went through | handle `error`; `replies` are the box's answers to those that went through |
| `CloseFailed` | `close()` failed | handle `error`; `end` has the warnings the session held |

`prepare_change` and `confirm_commit` discard and unlock after a failure. Their errors — a
`Drift` from `confirm_commit`, a `Protocol` or a `Timeout` from either, or the `CleanupFailed` that
carries one when the cleanup failed too — arrive inside `WithReplies` when a request went through,
with the box's answers to those: in `prepare_change` the lock and the load before the failure, in
both the discard and the unlock after it. When one of `abort_change`'s discard and unlock fails,
its error arrives inside `WithReplies` with the box's answer to the other.

`Transport::Negotiation` carries **what the peer actually offered**. Against an old box,
"negotiation failed" is useless; "it offered these four algorithms" tells you immediately that you
need `SshPolicy::LegacyJunos`.

Warnings from the box are **not** errors — Junos often emits commit warnings that are entirely
normal.

---

## Low level

If you need to build or parse NETCONF messages yourself, `netconf::rpc` is open — the greeting,
wrapping, capability parsing, reply parsing, diff extraction.

The parser is **lenient on purpose**: it matches on element names and ignores namespaces, so both
classic Junos and standard mode are understood. It never panics on broken input.

> **The stability status of the low-level layer is undecided.** It is public and in use, but nobody
> has said whether it may change in a 0.x release. Build on it with open eyes.

---

## Changelog

The history, one entry per release, is kept in one place: [CHANGELOG.md](../CHANGELOG.md).

**If you are upgrading to 0.4.0:** call `set_policy(...)` once after connecting, and drop the
policy argument from `prepare_change` calls. The other breaking changes are marked in the
changelog. The 0.3.0 language shift only affects anyone matching on the library's message texts.

---

## Limitations

- **The filter is enforced on what you submit, not on the resulting diff.** Changes in formats
  other than command form are therefore rejected outright.
- **A table of quirks per equipment generation**, and keepalive on long sessions.
