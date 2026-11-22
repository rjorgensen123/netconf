# Development

How netconf's code is laid out, and the rules a change has to follow. Several of the rules are
held by tests, named as the guard under the rule. A guard checks what is said beside it; where
that is only a part of the rule, the text says which part. What netconf is and how to use it is in
the [README](README.md) and under [`docs/`](docs/Home.md).

## Layout

| Path | What it is |
|---|---|
| `src/` | The crate. `lib.rs` is the root: `VERSION`, the modules and the re-exports. Each module is one area: `change` (compare-then-commit: `prepare_change`, `confirm_commit`), `error` (the error model), `framing` (RFC 6242 framing, end-of-message and chunked), `junos` (typed Junos helpers on the generic RPC layer), `mock` (`MockTransport`, an in-memory transport for tests), `policy` (`ConfigPolicy`, the configuration filter), `redact` (the read filter: redacting the device's secrets out of configuration and diff text), `rpc` (building and parsing NETCONF messages), `russh_transport` (the real SSH transport, feature `russh-transport`), `session` (`NetconfSession`: the hello, framing selection, generic RPC), `transport` (the `NetconfTransport` trait and the connect options); private: `wire` (what the device writes on the wire, read strictly) |
| `tests/` | Integration tests, one file per area; unit tests sit in `junos`, `wire`, `transport` and `russh_transport` |
| `docs/` | `API.md` is the contract; `Usage.md` is the guide, with the examples; `Filter.md` tells the filter rules in prose; `Home.md` says what the crate is; `Reviews.md` lists the reviews |
| `.gitea/workflows/`, `.github/workflows/` | CI on Gitea and on GitHub, with the same jobs in both |
| `deny.toml` | The `cargo deny` configuration: advisories, licenses, banned crates and sources |
| `.cargo/` | `config.toml` (crates.io for a bare `cargo publish`), `audit.toml` (the exception for `cargo audit`) |

## Fixed design constraints

- **netconf is narrow, and built for Junos.** A YANG model layer and a multi-vendor abstraction
  are non-goals; what is built is Junos and Junos Evo, beside the in-memory `MockTransport`. There
  is no connection pooling, no retry policy and no scheduler. This rule has no guard: it is read
  against the code.
- **The device password is the only authentication, and it is taken only as a
  `krypto::SecretString`.** SSH keys are not used, and netconf holds no private key. For the SSH
  login `RusshTransport` makes one transient copy, wiped when dropped (`Zeroizing`), and russh keeps
  its own while it logs in. `Auth` and `ConnectOptions` have no `Debug` and no `Clone`. The type
  system holds the first sentence; the rest has no guard: it is read against the code.
- **The configuration filter is default-deny, with an absolute floor, and it is not relaxed from
  outside.** A session without a policy permits nothing. Under every policy but `all_free`,
  `delete` of a protected top-level tree is refused; only the consumer's own source sets the floor
  aside, with `ConfigPolicy::new` (a floor of its own) or `all_free` (no filter). The raw `rpc` is
  the one deliberate way around the filter: no policy is asked, the text must be one request, and
  the reply is redacted. Guards: `nothing_is_permitted_without_a_policy` in `tests/junos.rs`, which
  fails when one of the six helpers it calls is not refused on a session without a policy, or when
  anything is sent, and
  `absolute_floor_denies_deleting_a_top_level_tree` in `tests/policy.rs`, which fails when `delete`
  of a tree of the default floor passes. The rest has no guard: it is read against the code.
- **Fail-closed.** What cannot be understood well enough to judge is refused, an unknown verb
  included, and what the filter judges is what is sent. Guard, for the unknown verb:
  `unknown_verb_gives_parse_error_not_silent_skip` in `tests/policy.rs`, which fails when a payload
  with one is parsed. The rest has no guard: it is read against the code.
- **The read filter redacts the device's secrets in what comes back: the value, never the
  structure.** This holds for the replies, `PreparedChange::diff` and the raw `rpc` reply alike,
  unless the policy has `allow_secrets` or is `all_free`. Guard, for `command`, `get_configuration`
  and the raw `rpc`:
  `what_the_device_returns_is_redacted_unless_the_policy_allows_secrets` in `tests/junos.rs`, which
  fails when a `$9$` password comes back as it was.
- **The NETCONF layer is written against the `NetconfTransport` trait, and the transport owns
  time.** Only `src/russh_transport.rs` uses russh. `NetconfSession` keeps no clock:
  `RusshTransport` enforces the time limits, `MockTransport` does not. The session sends one
  request at a time, and none on top of one that got no answer; the framing is chosen from the
  capabilities the hello announces. Guards: `after_a_timeout_the_session_sends_nothing_more` in
  `tests/session.rs`, which fails when a request after one that timed out is not refused, and
  `both_1_1_negotiates_chunked`, which fails when a hello that announces 1.1 does not give chunked
  framing. The rest has no guard: it is read against the code.
- **Compare-then-commit: what is committed is exactly what the operator saw, or nothing.**
  `confirm_commit` commits only when a fresh diff equals the approved one, compared as the device
  wrote it; a change rebuilt with `PreparedChange::from_diff` is compared redacted on both sides. On
  drift it discards and unlocks. Guard: `drift_between_review_and_commit_aborts` in
  `tests/change.rs`, which fails when a diff that drifted is committed.
- **The SSH policy is chosen per device, never globally, and russh's crypto backend is ring.**
  russh is taken with `default-features = false`, since its defaults bring in aws-lc-rs, and
  `deny.toml` bans `aws-lc-rs` and `aws-lc-sys`. The `rsa` crate comes in only through russh's RSA
  host-key support, where it verifies a device's host key; no RSA private-key operation runs, and
  the exception for RUSTSEC-2023-0071 rests on that. Guards: `rsa_is_never_a_direct_dependency` in
  `tests/rsa_fence.rs`, which fails when a line of `Cargo.toml` begins `rsa ` or `rsa=`, and
  `our_own_code_never_calls_rsa`, which fails when a `.rs` file under `src/` contains `use rsa` or
  `rsa::`. The aws-lc ban is checked by the `deny` job in CI. That the policy is per device has no
  guard: it is read against the code.
- **Logging goes through the `tracing` facade, and the consumer attaches the subscriber.** netconf
  writes nothing to standard output or standard error itself, and its events are part of the
  contract (below). Guard, in part: the event tests in `tests/ssh_policy.rs`, run with
  `russh-transport`, such as `a_refused_connect_is_one_log_line`, which fails when a refused
  `connect` logs anything but one `ssh_connect_refused` with its fields.
- **No `unsafe`, and no public item without a doc comment:** `src/lib.rs` has
  `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`. The compiler holds both.
- **The SSH transport is optional:** the feature `russh-transport`, off by default. Without it the
  crate builds without russh and tokio; CI lints and tests both ways. netconf's own dependency on
  zeroize comes with the feature too, but zeroize is built either way, through krypto. That a build
  without the feature leaves russh and tokio out has no guard: it is read against `Cargo.toml`.
- **The Rust version is `rust-version` in `Cargo.toml`, and every CI job uses exactly that one.**
  The jobs run on `ubuntu-latest`, in the `rust:1-bookworm` container. Guard: the CI step «Use the
  Rust the crate asks for», which fails when `rustc` is not that version once it is installed.

## Input

**Input is validated before it is used,** fail-closed; unknown values and verbs are refused.
`docs/API.md` states this rule at its top, for type, length, range and character set; length is
bounded only where the next paragraph says. There is no guard for the rule as a whole: it is read
against the code, and the checks (`check_target`, `Timeouts::validate`, the commit comment,
`parse_set_payload`) have tests of their own.

**An input a change adds gets an upper bound, an error that says when it is hit, and a line in
`docs/API.md`.** Refused past a bound today: a message from the device over `DEFAULT_MAX_MESSAGE`
(64 MiB) or in more than `MAX_CHUNKS` chunks, a commit comment over `MAX_COMMIT_COMMENT`
characters, and `Timeouts` with a ceiling outside one to ten minutes. Capped, and the text says
so: the device's stderr at 4096 bytes a session, and what it sends after the close at
`DEFAULT_MAX_MESSAGE`. Among inputs with no length limit: the host and the username (checked for
being empty and for control characters, the host for whitespace too), a set payload, a filter, a
command and the raw `rpc` request. Guards, for the message size, the chunk count and the commit
comment: `chunked_over_max_gives_protocol`, `eom_without_terminator_over_max_gives_protocol` and
`a_whole_eom_message_over_max_gives_protocol` in `tests/framing.rs`, which fail when a decoder lets
a chunk or a message past the cap it was given through (they set a small cap; the 64 MiB value has
no guard); `a_message_in_too_many_chunks_gives_protocol` there, which fails when a message in more
than `MAX_CHUNKS` chunks is not refused; and `a_commit_comment_is_at_most_512_characters` in
`tests/junos.rs`, which fails when a comment over the limit is not refused, or is sent.

**No input makes the crate panic.** `src/error.rs`, `src/framing.rs`, `src/rpc.rs` and
`docs/API.md` state it, each for its part: malformed input, the de-framer and the parser. Guards,
for single cases: `chunked_hostile_chunk_size_gives_protocol_not_panic`
in `tests/framing.rs` and `malformed_xml_is_protocol_error` in `tests/rpc_error.rs`, which fail when
a hostile chunk size or an unfinished reply panics or is accepted. There is no corpus and no
random-input guard: the rule as a whole is read against the code.

## Answers

**An error names what failed.** `NetconfError` has three branches a consumer tells apart without
parsing text, `Transport`, `Protocol` and `Device`, and variants of their own for a timeout, a
refused request, the outcomes around a commit, a partial failure or a failed cleanup, and a failed
close; §8 of `docs/API.md` gives each text. Guards, for the text: `every_branch_names_itself` in
`tests/error_text.rs`, which fails when the text of a `Protocol`, `Policy`, `Timeout`, `Transport`,
`Device` or `ChangedSinceConfirmed` error does not begin with its prefix, and
`the_detail_survives_the_prefix`, which fails when the detail of a `Protocol`, `Policy` or
`Timeout` error is dropped from its text.

**No log event carries a secret the crate can recognize, and an error carries the device's
content redacted like a reply.** No event carries configuration or diff content, or the text the
device writes on stderr. An error carries what the device said in fields of its own, through the
same filter as a reply, so under `allow_secrets` or `all_free` it holds the secrets the reply
would. Device text is made printable before it goes into an error's text or a log line. Guards,
in part: `error_info_is_redacted_like_the_rest` and
`a_protocol_error_from_a_public_parser_carries_the_document_redacted` in `tests/rpc_error.rs`,
which fail when a `$9$` value reaches the `info` of an `<rpc-error>`, or the document a public
parser's `Protocol` error carries; `the_log_does_not_carry_what_the_device_wrote_on_stderr` in
`tests/russh_loopback.rs`, which fails when the `netconf_subsystem_stderr` event carries the text.

## The public surface

**`docs/API.md` is the contract, and its version is a floor.** The authoritative source is
`src/lib.rs` and `CHANGELOG.md`; on divergence the code wins. The version at the top is the lowest
netconf the contract describes: it is raised only when the public surface itself changes, to the
crate version at that moment, and it is never ahead of `Cargo.toml`. Guard:
`every_public_name_is_in_the_contract_docs` in `tests/docs.rs`, which fails when a name it collects
is not in `docs/API.md`: the `pub use` lists and the `pub mod` and `pub const` lines of
`src/lib.rs`, and the `pub fn`, `pub async fn`, `pub const fn`, `pub const`, `pub struct`,
`pub enum`, `pub trait` and `pub type` lines of the eleven module files it names. It collects no
enum variants, fields or trait methods. No test reads the floor or checks what the document says
about behaviour: that is read against the code.

**The log events are part of the contract,** in the logging section of `docs/API.md`. Guard, in
part: the event tests named above check the name and fields of what they capture; no test compares
the events with the document.

**A `#[non_exhaustive]` type can grow in any release,** among them `NetconfError`,
`TransportError`, `ParseError` and `Scope`. Guard, for `ParseError` only: the `compile_fail`
doctest in `src/policy.rs`, which fails when a `match` on it without a wildcard arm compiles; it
runs with `cargo test --locked --doc`.

**Code examples live in `docs/Usage.md`; the README has two.** In `src/`, the only example in a doc
comment is the pair on `ParseError` in `src/policy.rs`; `src/redact.rs` shows a redacted diff, as
text. No test compiles the examples in the README or the guide. This rule has no guard: it is read
against the code.

## Dependencies

`Cargo.lock` is committed, and CI lints, tests and documents with `--locked`. The `deny` job runs
`cargo deny check` against `deny.toml`, with every feature on: advisories (yanked crates refused;
two exceptions, each with its reason), a license allow list, banned crates (`aws-lc-rs`,
`aws-lc-sys`) and sources. `.cargo/audit.toml` holds the RSA exception for `cargo audit`, which CI
does not run. `Cargo.toml` gives the reason beside the dependencies that need one: russh is taken
with `default-features = false`, and krypto comes from crates.io as published, with no `path` and
no `registry`.

**A new crate gets a row in `THIRD_PARTY_LICENSES.md`.** Guard: the tests in
`tests/third_party.rs`, which fail when a crate in `Cargo.lock` has no row, a row names a crate
that is not in `Cargo.lock`, or a row has no license.

**Dependencies come from crates.io only.** `deny.toml` allows no other registry and no git source,
and `publish = ["crates-io"]` and `.cargo/config.toml` send the crate to crates.io only. Guard, for
the sources: the `deny` job in CI.

## Language, changelog and commits

- Everything in the repository is in English: code and names, comments, documentation,
  `CHANGELOG.md` and commit messages.
- Every change has an entry in `CHANGELOG.md`, in the same commit: a bullet that begins with its
  date, under the heading of the version being built, and it says in a few lines what changed for
  the one who uses netconf. A change that breaks an existing use is marked **Breaking**. The
  heading gets its date at the release. Older entries have other forms.
- An entry that is written is not rewritten. When a later change overtakes it, the new entry says
  so and refers back.
- An entry refers to nothing outside netconf: no case or issue numbers and no other systems.
- The documentation says what the code does, and no more. The repository carries no notes on the
  state of the work: nothing in it says what has been run or what is left to do. The Status section
  of the README says how mature the crate is, which is another thing.
- A commit message is short and names nothing outside the crate.
- The developer approves every changelog entry and every commit message before the commit is made.

## Reviews

A review of netconf is added to `docs/Reviews.md` with its date, reviewer, version and kind, and
its reviewer is named in the Reviews section of `README.md` and `docs/Home.md`.

## Versions and comments

- The version is written in `Cargo.toml`, and `CHANGELOG.md` has a heading for it; the code
  derives it from there, `VERSION` being `env!("CARGO_PKG_VERSION")`. Guards:
  `changelog_has_an_entry_for_the_current_version` in `tests/version.rs`, which fails when
  `CHANGELOG.md` has no `## [<version>]` heading, and `version_constant_mirrors_cargo_toml`, which
  fails when `VERSION` is not the version in `Cargo.toml`. Written by hand, with no guard: the
  dependency lines in `README.md` and `docs/Usage.md`, the table in `SECURITY.md`, and the title
  and the floor of `docs/API.md`.
- Every `.rs` file in `src/` and `tests/` starts with its SPDX line,
  `// SPDX-License-Identifier: MIT OR Apache-2.0`. This rule has no guard: it is read against the
  code.
- A doc comment or comment marks the version in which a behaviour is new or changed: `(x.y.z)`.
  This rule has no guard: it is read against the code.
- A comment is in English. A new one says in a sentence or two what the thing is, and why when that
  is not obvious, with no status and no history; many existing comments are longer and tell what
  the code did before. This rule has no guard: it is read against the code.

## Tests

- CI runs, the same in both workflow files:
  - in the `build-test` job: `cargo fmt --all --check`,
    `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked --all-targets`,
    `cargo test --locked --doc` (the doctests, which `--all-targets` skips),
    `cargo test --locked --all-targets --features russh-transport`,
    `cargo clippy --all-targets --locked --features russh-transport -- -D warnings` and
    `cargo doc --locked --no-deps --all-features` with `RUSTDOCFLAGS` set to `-D warnings`;
  - in the `deny` job: `cargo deny check`, with a pinned cargo-deny checked against its SHA-256.
- Each point of a change gets one simple test of its own.
- A new rule the code is to hold gets a test that fails when the rule is broken.
- CI runs on a push to `main` and on pull requests. `.gitea/workflows/ci.yml` and
  `.github/workflows/ci.yml` run the same jobs with the same steps but the checkout; the GitHub file
  also has a `permissions` block.
