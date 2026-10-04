# How to use netconf

**In short:** this is the usage guide. [Home](Home.md) tells you what netconf is and what you can use it
for; here is **how** you actually do it, with examples. What the filter permits is described in
full in [Filter](Filter.md). The exact contract — every signature, every field, every error
variant — is in [API](API.md).

---

## Getting started

```toml
[dependencies]
netconf = { version = "0.5", features = ["russh-transport"] }
krypto  = "0.7"     # for the password
```

**The feature flag is not optional if you are talking to real equipment.** Without
`russh-transport` you get the protocol layer and the simulated transport, but no SSH.

The session is async. netconf brings no runtime of its own; with `russh-transport` it runs on
tokio.

---

## Connecting to a device

```rust
use netconf::russh_transport::RusshTransport;
use netconf::{Auth, ConnectOptions, NetconfSession, SshPolicy, Timeouts};
use std::time::Duration;

let opts = ConnectOptions {
    host: "pe1.example.net".into(),
    port: 830,
    username: "netops".into(),
    auth: Auth::Password(krypto::SecretString::from_string(password)?),
    ssh_policy: SshPolicy::Modern,
    timeouts: Timeouts {
        connect: Duration::from_secs(10),
        per_rpc: Duration::from_secs(30),
        per_commit: Some(Duration::from_secs(120)),
        total: Duration::from_secs(180),
        max_total: Duration::from_secs(300),
    },
    platform_hint: None,
    host_key: Some(approved_fingerprint), // "SHA256:…"
};

let mut session = NetconfSession::<RusshTransport>::connect(&opts).await?;
```

**The password must be a `krypto::SecretString`.** That is not a recommendation — the type system
does not accept an ordinary string, so the password cannot end up in a log by accident. It is used
for SSH password authentication and zeroized afterwards. SSH keys are not used.

**The port** is 830, the NETCONF port, or 22, where the `netconf` subsystem usually answers as
well. NETCONF runs as a subsystem on the SSH session. If the device refuses the subsystem, the error
is `TransportError::SubsystemUnavailable` — on Junos, `set system services netconf ssh` is missing.

**`host_key` is required.** It is the fingerprint you expect, `SHA256:<base64 without padding>`,
compared byte for byte. If the device presents a different key, the connection fails as
`TransportError::HostKey`, carrying the fingerprint it did present. `None` is refused before
anything connects: `connect` authenticates, which means it sends your password, so there is no
unverified connection. How you get the fingerprint the first time is under
[The host key](#the-host-key--who-are-you-talking-to).

**`platform_hint`** is reserved for a table of differences between equipment generations. It is
not read; use `None`.

### Time limits

There are **two levels, and both are yours to set:**

| Field | Means | Default |
|---|---|---|
| `max_total` | the absolute ceiling on any session, set once when you adopt netconf — 1 to 10 minutes | 5 min |
| `total` | **this** session's lifetime — at least 1 second, at most `max_total` | 5 min |
| `connect` | establishing the connection: TCP, SSH handshake, host key check, login and the subsystem | 30 s |
| `per_rpc` | each single read and send of a request | 60 s |
| `per_commit` | each read and send of `commit` and `commit_confirmed`; `None` is `per_rpc` | `None` |

The clock starts when you connect. When `total` runs out, the session answers
`Timeout { op: "session-ttl", .. }` regardless of activity — the next task gets a new session.
Small tasks do not need long lives; a sequence with a commit-confirmed window needs more. No wait
ever runs past the session's deadline.

Values outside the ranges are refused at connect, with a message that says what was given and what
the range is. Nothing is silently clamped. To change only some of them:

```rust
let timeouts = Timeouts {
    total: Duration::from_secs(20),
    ..Timeouts::default()
};
```

### Old equipment

```rust
ssh_policy: SshPolicy::LegacyJunos,
```

Older devices require SSH algorithms that modern libraries have stopped offering. `LegacyJunos` is
a **superset** of `Modern`: the modern algorithms are still negotiated first, and SHA-1 key
exchange, `ssh-rsa`, CBC ciphers and `hmac-sha1` are allowed in addition. No policy offers 3DES.
`SshPolicy::Custom` is refused at connect: netconf does not negotiate with an algorithm list other
than one it implements.

**Set it per device, never globally.** A connection under `LegacyJunos` is logged with
`legacy = true`; the first one to each device as a warning. To mark your own events by
algorithm name, the list is `netconf::LEGACY_ALGORITHMS`:

```rust
if netconf::is_legacy(algorithm) {
    tracing::warn!(algorithm, "SSH algorithm outside today's recommendations");
}
```

The point is not to forbid the old algorithms — the range of equipment requires them. The point is
that they must be **visible**, so nobody discovers five years from now that half the network
negotiated something weak.

If negotiation fails, `TransportError::Negotiation` carries **what the device offered**. Against
an old box, "negotiation failed" is useless; "it offered these four algorithms" tells you at once
that it needs `LegacyJunos`.

---

## The host key — who are you talking to

The first time you meet a device you do not have its fingerprint. Simply trusting the first thing
you see is weak, but requiring it up front makes it impossible to get started.

SSH solves this itself: **the device presents its key during the key exchange, before anyone logs
in.**

```rust
use netconf::russh_transport::observe_host_key;

let fingerprint = observe_host_key(host, 830, &SshPolicy::Modern, &Timeouts::default()).await?;
// show it to a person → the person approves it → store it
```

**The function takes no password parameter at all.** That no secret can leak from it is a property
of the signature, not a rule you have to remember. It runs the key exchange, reads the
fingerprint and disconnects. It runs under the same `timeouts` as a connection: `connect` bounds
it, and `total` too.

It **pins nothing**. The step from "observed" to "approved" is yours — and should require a person.
Then you pass the fingerprint as `host_key` when connecting.

If you are already connected:

```rust
let seen: Option<String> = session.transport().observed_host_key();
```

---

## Binding a policy

**Nothing works until you bind a policy.** A session without one refuses every read, every
command and every change.

```rust
use netconf::{Access, ConfigPolicy, Scope};

session.set_policy(
    ConfigPolicy::with_default_floor()
        .grant(Scope::LogicalUnits, Access::Rwd)
        .grant(Scope::InterfaceDescriptions, Access::Rw),
);
```

Bind it once, after connecting. Every typed helper on the session checks it itself, before
anything is sent. If something is refused, you get `NetconfError::Policy` with the reason, and the
device has seen nothing. How to build a policy is [further down](#building-a-policy).

---

## Reading

```rust
let interfaces = session
    .get_configuration(Some("<configuration><interfaces/></configuration>"))
    .await?;
let circuits = session.command("show l2circuit connections").await?;
let up = session.command("show interfaces terse | match ge-").await?;
```

Both return the device's reply as text: XML from `get_configuration`, the command's output inside
the `<rpc-reply>` from `command`. Parsing it is your job.

- **`get_configuration(None)`** reads the whole configuration. That includes the sensitive trees
  (`system`, `security`, `access`, `groups`, `apply-groups`, `event-options`), and so requires
  `allow_read` on every one of them. A filter that names only other trees needs no grant.
- **`command`** runs `show …` by default; everything else needs a grant. Pipes are allowed when
  they only filter or format what is shown. `show configuration <tree>` is gated like
  `get_configuration`.

**What you read has the device's secrets redacted**, unless your policy says `allow_secrets()`. See
[Redaction](#redaction).

---

## Changing configuration safely

This is the main flow, and it is built around **a person seeing what will actually happen before
it happens**.

```rust
use netconf::{Format, LoadAction};

let payload = "set interfaces ge-0/0/1 unit 123 description \"customer A\"\n\
               set interfaces ge-0/0/1 unit 123 vlan-id 123";

// Phase 1: check against the policy, lock, load, fetch the diff.
let prepared = session
    .prepare_change(payload, Format::Set, LoadAction::Merge)
    .await?;

// Show the diff to the person who approves it.
println!("{}", prepared.redacted_diff());

// Phase 2: commit, if the device still shows the same diff, then unlock.
let replies = session.confirm_commit(&prepared, "ge-0/0/1.123 for customer A").await?;
```

**The policy is checked first, before anything is sent.** If the change is not allowed, you get
`NetconfError::Policy`, and the device has not even been locked. Only `Format::Set` can be checked;
`Text` and `Xml` require `ConfigPolicy::all_free(Access::Rwd)`.

**Between phase 1 and 2 the candidate stays loaded and locked.** If you are not going to commit,
clean up:

```rust
session.abort_change().await?; // discard, then unlock
```

**If the device changed in between, nothing is committed.** `confirm_commit` fetches a fresh diff
and compares it with the approved one, byte for byte, on the diff as the device wrote it — so a
change inside a value the policy redacts counts too. If they differ, it discards and unlocks, and
returns `NetconfError::Drift { fresh }` inside `NetconfError::WithReplies`. `fresh` is the diff the
device shows now, redacted as the approved one was, so a person can see what changed.

```rust
match session.confirm_commit(&prepared, "ge-0/0/1.123").await {
    Ok(replies) => { /* committed and unlocked */ }
    Err(NetconfError::WithReplies { error, .. }) if matches!(*error, NetconfError::Drift { .. }) => {
        if let NetconfError::Drift { fresh } = *error {
            println!("the device changed since approval:\n{fresh}");
        }
    }
    Err(e) => { /* see Errors */ }
}
```

`prepare_change`, `confirm_commit` and `abort_change` return the device's answers to each request
they made, by RPC name — `"lock"`, `"load-configuration"`, `"commit-configuration"`, `"unlock"`,
`"discard-changes"`. A failure before the commit is cleaned up: they discard and unlock before
they return, so the device is not left locked with a candidate nobody approved.

**Approval across a restart.** If the approval is stored and the commit happens in a new process,
`PreparedChange::from_diff(stored_diff)` rebuilds the change from the stored diff. The fresh diff is
then compared redacted, so it sees what the stored diff can show.

`prepared.diff` is what the policy let through; `prepared.redacted_diff()` is always redacted. They
are the same string unless the policy has `allow_secrets()` — then the diff carries the device's
secrets, netconf logs a `secrets_in_diff` warning (never the content), and `redacted_diff()` is the
one to **show, log and store**.

### Letting the device undo it

```rust
session.commit_confirmed(10, Some("ge-0/0/1.123")).await?;
// … verify that the service works …
session.commit(None).await?; // confirms; without it the device rolls back after 10 minutes
```

This is the safety net under everything else: if you lose the connection midway, or the change took
down the very thing you were working over, **the device reverts by itself**. Nobody has to make it
in time to save it.

**The confirming commit checks the device first.** It commits only if the device's last commit is
still the confirmed one and the candidate is clean. Otherwise it is withheld as
`NetconfError::ChangedSinceConfirmed`, which carries both commit entries and the diff — and the
device rolls the confirmed commit back when its time runs out. A confirming commit would otherwise
also commit whatever someone else loaded in between. While a confirmed commit is waiting,
`session.confirmed_commit()` returns it.

### The individual operations

`lock` · `unlock` · `load_configuration` · `compare` · `commit_check` · `commit` ·
`commit_confirmed` · `rollback` · `discard_changes` — all exist separately, and each returns the
device's `<rpc-reply>`:

```rust
session.lock().await?;
session
    .load_configuration("delete interfaces ge-0/0/1 unit 123", LoadAction::Merge, Format::Set)
    .await?;
let diff = session.compare().await?;
session.commit_check().await?;
session.commit(Some("remove ge-0/0/1.123")).await?;
session.unlock().await?;
```

Use `prepare_change` and `confirm_commit` when you can: the ordering is easy to get wrong by hand,
and the mistake is silent. Note that `load_configuration` takes the action before the format.

- `compare()` returns the diff text alone, empty when there is no change.
- `rollback(0)` discards the candidate's changes. `rollback(n)` for `n > 0` loads an older
  configuration whole, which the filter cannot read, and requires `all_free(Rwd)`.
- `session.set_synchronize_commits(true)` sends every commit as `commit synchronize`, for a device
  with two routing engines. A device configured with `system commit synchronize` does that itself
  and needs nothing from the session.

---

## Building a policy

The model is **where × what**: each rule says "at this place, these operations are allowed".
**Everything else is denied.** On top of that there is a floor no rule can override. The full
rules are in [Filter](Filter.md).

```rust
use netconf::{Access, ConfigPolicy, Match, Op, Scope};

// The common case: start from the floor and grant what you need.
let policy = ConfigPolicy::with_default_floor()
    .grant(Scope::LogicalUnits, Access::Rwd)
    .grant(Scope::InterfaceDescriptions, Access::Rw);

// Paths of your own.
let policy = ConfigPolicy::with_default_floor()
    .allow("interfaces * unit *", Match::Subtree, &[Op::Set, Op::Delete])
    .allow("protocols l2circuit neighbor *", Match::Subtree, &[Op::Set]);

// A sensitive tree to read, and a command beyond `show`.
let policy = ConfigPolicy::with_default_floor()
    .grant(Scope::Protocols, Access::Rw)
    .allow_read("system")
    .allow_command("request system storage cleanup");

// Read, change nothing — whatever is granted.
let policy = ConfigPolicy::read_only().allow_read("system");

// Nothing at all — what a session without a policy has.
let policy = ConfigPolicy::all_deny();

// Everything, the filter off. Choose it deliberately.
let policy = ConfigPolicy::all_free(Access::Rwd);
```

**The floor:** deleting an entire protected top-level tree — `delete interfaces`,
`delete protocols` — is refused no matter what you grant. That mistake must not be possible to
configure your way into. Only `all_free` has no floor.

**Unknown input rejects the whole payload** — an unknown verb, an empty path, an unbalanced or
single quote, a `/*` comment, a control character. A line that is not understood would otherwise go
**unchecked** to the device, and that is the road around the whole filter.

**Ask the policy what it permits.** `policy.describe()` gives a summary for a log or an operator,
and `rules()`, `protected_roots()`, `read_allows()` and `command_allows()` give it as data.

You can run the same check yourself, without a session — to validate a payload before you ever
connect:

```rust
fn check(payload: &str, policy: &ConfigPolicy) -> Result<(), String> {
    let changes = netconf::policy::parse_set_payload(payload).map_err(|e| e.to_string())?;
    policy.check(&changes).map_err(|v| v.reason)
}
```

`policy.check_command(cmd)` does the same for a command.

---

## Redaction

The filter governs what you may **change**. Redaction governs what is safe to **show**.

Configuration from a device contains the device's own secrets: obfuscated passwords, SNMP keys,
certificate blocks. They end up in a diff, in a `show` printout, in your log — and from there in a
log service and a backup.

**netconf redacts them before they reach you.** Everything the session returns — replies, the
diff, the device's hello, the device's text in an error — has each secret replaced by a marker that
says what was there and how to read it:

```text
encrypted-password [SENSITIVE: hidden by netconf — allow_secrets() on the policy shows it]; ## SECRET-DATA
```

The redaction **preserves the line structure exactly** — line count, indentation, line endings,
statement names. A redacted diff is still readable as a diff.

To read the secrets themselves, say so in the policy. `all_free` redacts nothing.

```rust
let policy = ConfigPolicy::with_default_floor()
    .allow_read("system")
    .allow_secrets();
```

The same filter is available for text you hold yourself:

```rust
use netconf::{contains_secrets, redact_secrets, Redactor};

if contains_secrets(text) {
    tracing::warn!("the text carries secrets — keeping the redacted version");
}
let safe = redact_secrets(text);

let strict = Redactor::strict().redact(text); // the SNMP community too
```

`redact_secrets` is the filter the session uses, which leaves the SNMP v2c community readable.
`Redactor::strict()` hides it as well. What is taken out, and why, is listed in
[Filter](Filter.md#the-read-filter--secrets-in-what-you-fetch).

---

## Warnings, session facts and closing

**Warnings from the device are not errors.** Junos often answers with warnings that are entirely
normal — a commit warning, a statement with no effect. The call succeeds, and the warnings are
kept:

```rust
for w in session.take_warnings() {
    tracing::info!(message = ?w.message, "device warning");
}
```

The reply a call returns holds its own warnings as well. `take_warnings` also has those of the
requests a call makes inside it, which you do not see — the diff read by `prepare_change`, the
commit history read by `commit`.

**What the session knows about the device:**

```rust
let id: Option<u64> = session.session_id();   // the device's session id
let caps: &[String] = session.capabilities(); // what the device announced
let hello: String = session.hello();          // its whole <hello>, redacted
let framing = session.framing();              // end-of-message or chunked
```

**Close the session** when you are done. `close()` sends `<close-session/>`, waits for the answer
and closes SSH. It returns every warning the session still holds, and what the device said over
SSH:

```rust
let end = session.close().await?;
for w in end.warnings {
    tracing::info!(message = ?w.message, "device warning");
}
```

If the close fails, the error is `NetconfError::CloseFailed`, which carries the same `SessionEnd`.

---

## Logging

netconf logs through [`tracing`](https://crates.io/crates/tracing) and never decides where it ends
up: attach a subscriber in your program. Without one, the logging is close to free. Every event has
an `event` field:

| `event` | When |
|---|---|
| `ssh_connect` | a connection starts — with `legacy = true` under `LegacyJunos` |
| `ssh_connect_failed`, `ssh_auth_failed` | the connection or the login failed |
| `ssh_host_key_verified`, `ssh_host_key_mismatch` | the host key matched, or did not |
| `ssh_session_established`, `ssh_session_closed` | the session is up, or closed |
| `ssh_host_key_probe`, `ssh_host_key_enrollment`, `ssh_host_key_observed`, `ssh_host_key_probe_failed` | `observe_host_key` |
| `netconf_subsystem_stderr` | the device wrote on the subsystem's stderr |
| `secrets_in_diff` | a diff carries secrets because the policy lets them through — never the content |

A password is never logged. A host or username with a control character is refused before it is
logged.

---

## Testing without equipment

The entire protocol layer runs against a simulated transport. That is how the library itself is
tested.

```rust
use netconf::mock::MockTransport;
use netconf::{ConfigPolicy, NetconfSession};

let (transport, sent) = MockTransport::recording(vec![
    // The device's hello, split in two: the session puts the pieces together.
    b"<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities>".to_vec(),
    b"<capability>urn:ietf:params:netconf:base:1.0</capability></capabilities>\
      <session-id>4711</session-id></hello>]]>]]>"
        .to_vec(),
    // The reply to the first request.
    b"<rpc-reply message-id=\"1\"><ok/></rpc-reply>]]>]]>".to_vec(),
]);

let mut session = NetconfSession::establish(transport, true).await?;
assert_eq!(session.session_id(), Some(4711));

session.set_policy(ConfigPolicy::with_default_floor());
session.lock().await?;

// What the client sent: its hello, then the lock.
let bytes = sent.lock().unwrap().clone();
assert!(String::from_utf8_lossy(&bytes).contains("<lock>"));
```

`recording()` gives you a shared handle to what was sent, which still works **after** the transport
has been moved into the session. Splitting the device's messages into small pieces is how you
verify that the framing is handled.

---

## Errors you can get

`NetconfError` tells the causes apart, so you can act on them without parsing text. It is
`#[non_exhaustive]`, so a `match` needs a wildcard arm.

| Error | Means | What to do |
|---|---|---|
| `Policy` | **your own** policy stopped it | fix the change or the policy — the device has seen nothing |
| `Drift` | the diff changed between approval and commit | have a person look at `fresh`, the diff the device shows now |
| `ChangedSinceConfirmed` | the device changed after a confirmed commit | it rolls back by itself; look at what changed |
| `Device` | the device said no | read `message`, `path` and `explanation()` — that is Junos answering; further errors are in `also` |
| `Transport` | the network, SSH, the login or the host key | see below |
| `Protocol` | the device's answer could not be read, or did not belong to the request | `received` is what the device sent |
| `Timeout` | a time limit ran out | `op` says which; `partial` is what had arrived |
| `CommittedThenFailed` | the commit went in, then a later step failed | the change is live; `reply` is the device's answer to the commit |
| `CommitUnanswered` | a commit was sent and no readable answer came back | the device has not said whether it took effect — check it |
| `WithReplies` | an operation failed after some of its requests went through | handle `error`; `replies` are the device's answers to those |
| `CleanupFailed` | an operation failed, and the cleanup after it failed too | handle `error`; `cleanup` is each step that failed |
| `CloseFailed` | `close()` failed | handle `error`; `end` has the warnings the session held |

`Transport` carries a `TransportError`:

| `TransportError` | Means |
|---|---|
| `HostKey` | the device's key is not the one you pinned; `observed` is the one it presented |
| `Negotiation` | no common SSH algorithms; `offered` is what the device offered |
| `AuthRejected` | the login was refused; `remaining_methods` is what the device accepts, and `partial_success` says the password was accepted but more is required |
| `SubsystemUnavailable` | logged in, but the device has no NETCONF over SSH |
| `Closed` | the device ended the connection; `ssh` has what it said |
| `Io` | anything else on the way — the connection broke, the address was wrong |

```rust
match e {
    NetconfError::Policy(reason) => { /* the device has seen nothing */ }
    NetconfError::Device(d) => { /* d.message, d.path, d.explanation() */ }
    NetconfError::Transport(TransportError::HostKey { observed, .. }) => { /* … */ }
    NetconfError::CommittedThenFailed { reply, error } => { /* the change is live */ }
    _ => { /* … */ }
}
```

The text of every error is redacted under the policy, as a reply is.

---

## Low level

If you need to build or parse NETCONF messages yourself, `netconf::rpc` and `netconf::framing` are
open — the hello, wrapping, capability parsing, reply parsing, diff extraction, and the framing of
RFC 6242 in both modes. `session.rpc(xml)` sends any request and returns the reply.

`session.rpc` goes **around** the policy — it is the layer the typed helpers are built on — but not
around the redaction.

The parser is **lenient on purpose**: it matches on element names and ignores namespaces, so both
classic Junos and standard mode are understood. It never panics on broken input.

---

## Limitations

- **The filter is enforced on what you submit, not on the resulting diff.** That is why only set
  format can be checked, and other formats need `all_free(Rwd)`.
- **No table of differences between equipment generations.** `platform_hint` is reserved for it.
- **No keepalive.** A session lives for one task, within `total`, and the next task gets a new one.
