# netconf — a narrow NETCONF client for Junos

[![docs.rs](https://docs.rs/netconf/badge.svg)](https://docs.rs/netconf)

> **This repository is a mirror.** Development happens elsewhere and is pushed here;
> every sync overwrites what is here, so a pull request cannot be merged and a commit
> made here is lost. Issues are read — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
> form a change has to arrive in, and [SECURITY.md](SECURITY.md) for vulnerabilities.

An asynchronous NETCONF client (RFC 6241/6242) built for one job: letting a program
change network equipment **without being trusted to do it responsibly.**

- **Type:** Rust library
- **License:** MIT or Apache-2.0, at your choice
- **Transport:** pluggable. A mock transport is built in; real SSH lives behind the
  `russh-transport` feature
- **Secrets:** the device password is taken *only* as a `krypto` secret type and never
  becomes an ordinary `String`
- **Safety:** `#![forbid(unsafe_code)]`

## Status

**Pre-release — beta.** netconf is not yet in a release state. It is in beta testing, and not
ready for uncritical use in production.

## Why this crate exists

We had to talk to the network, and for that we needed a gateway — something we actually
trusted to stand between software and live equipment.

The obvious approach is to let the application that has the intent also hold the
connection. That is exactly what we did not want. An application grows, gets new
callers, gets a bug, gets an operator in a hurry. Whatever is wrong up there ends up
pointed at the network, and the network does not get a second chance.

So the connection was pulled out into a small, generic module that does nothing but
speak the protocol — and that carries a set of filters for what is allowed to pass.

**The filter is not configuration. It is the product.** A consumer of this crate is
expected to hardcode the policy it wants, in its own source, and hand it to the session.
From then on the rule is fixed: no request the consumer's own code can construct — not
through a bug, not through a caller it did not anticipate, not through input that got
further than it should have — reaches the equipment unless the policy already allowed
it. The protection sits *below* the thing that might be wrong.

That is the whole idea. Everything else here exists to make it hold.

## How the protection is shaped

- **Default-deny.** A session without a policy permits nothing — no read, no `show`,
  no command, no write. Not a warning, not a default-permit with a log line — it
  refuses, as `ConfigPolicy::all_deny()` does. The consumer defines the policy it uses.
- **An absolute floor.** Some things cannot be permitted at all, no matter what policy
  a consumer writes. A consumer can only ever narrow what it is allowed to do. The one
  exception is `all_free`, which turns the filter off — a choice made out loud, never
  a way around.
- **Fail-closed parsing.** If a request cannot be understood well enough to judge it,
  it is refused. An unparsed request is never an allowed request.
- **Reads are gated too.** Configuration is not only dangerous to write. Sensitive
  subtrees are gated, and what does come back has the device's secrets redacted before
  it reaches the consumer, unless the policy says otherwise.
- **Commits are compared first.** Changes go through a compare-then-commit sequence with
  a drift check, so a change is not applied on top of a device that moved underneath it.
- **The host key is verified**, with a credential-free path for first enrollment so that
  learning a device's identity does not require handing over a password first.

## Getting started

```toml
[dependencies]
netconf = "0.6"

# Real SSH against a device. Without this feature the crate builds without russh
# or tokio, which is what the offline tests use.
netconf = { version = "0.6", features = ["russh-transport"] }
```

```rust,no_run
# async fn ex<T: netconf::NetconfTransport>(t: T) -> Result<(), netconf::NetconfError> {
let mut session = netconf::NetconfSession::establish(t, true).await?;
let reply = session.rpc("<get-configuration/>").await?;  // raw XML out; the caller parses it
session.close().await?;
# Ok(()) }
```

The full public surface is in [`docs/API.md`](docs/API.md), and a test enforces that the
document and the code agree. [`docs/Usage.md`](docs/Usage.md) is the guide;
[`docs/Filter.md`](docs/Filter.md) documents the filter rules.

## What the crate does not do

These are not gaps waiting to be filled. They are the reason the crate is small enough
to reason about.

- **No YANG model layer.** Requests go out as XML and replies come back as XML. What the
  content means is the caller's business.
- **No multi-vendor abstraction.** Junos is what is built today, alongside the mock
  transport. Everything above the wire is written against a transport trait, so another
  vendor can be added — but no layer here pretends the vendors are the same, because with
  one vendor that layer costs more than it gives.
- **No SSH keys.** Device authentication is a transient password, taken as a secret type
  and wiped. Key-based auth is a different trust model and is not offered.
- **No connection pooling, no retry policy, no scheduler.** A session is a session.

## Test

```bash
cargo test                                  # the whole suite, mock transport, no hardware
cargo test --features russh-transport       # also compiles and tests the SSH transport
cargo clippy --all-targets -- -D warnings
```

## Author

**Roger Jorgensen** — rogerj@gmail.com

Design, architecture and structure; the decision to put the filter below the consumer
rather than inside it, and what that has to guarantee to be worth anything; the contracts
the crate presents outwards; and the decisions about what it does and deliberately does
not do.

The code is written by Claude AI (Opus and Fable).

Reviewed independently by Fable, Opus and Gemini.

## License

MIT **or** Apache-2.0, at the recipient's choice.
See [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE).

Both permit the same use. They differ on patents, and that is the reason for offering both:
MIT is silent on them, Apache-2.0 grants one explicitly and withdraws it from anyone who sues
over it (§3). Organisations differ on which of the two their own rules already accept.
Offering both means you take the one you are already cleared for, without having to ask.

### Contributions

**Reports are what is wanted here — not patches.** If something behaves differently from what
the documentation says, or a guarantee does not hold, say so and show how to see it. That is
the most useful thing anyone outside can send. The crate is deliberately narrow, with one
canonical way of doing each thing, so a fix has to fit that canon — and it is quicker and safer
for the fix to be made here than for a patch to be reviewed and reshaped into it.

Code is not refused. It is simply not what is being asked for, and it is not prioritised.
**If you do send it, it is accepted only under the same terms as the crate.** By submitting
code for inclusion you license it as MIT **or** Apache-2.0, at the recipient's choice, with no
additional conditions. Code offered on other terms cannot be merged — not as a judgement on it,
but because the choice this crate gives its users only holds if it holds for every line in it.
A single file on other terms breaks that promise for everyone downstream.

[CONTRIBUTING.md](CONTRIBUTING.md) says how to file a report. [SECURITY.md](SECURITY.md) covers
vulnerabilities, which do not go in the issue tracker.
