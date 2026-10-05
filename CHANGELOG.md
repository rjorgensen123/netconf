# Changelog — netconf

Every notable change to this crate is recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/).

> **Note:** before 1.0 the API can change between minor versions. `docs/API.md` names the
> version its contract applies from, and that number moves only when the public surface does.

## [0.6.1] — 2026-10-05

The public surface is that of 0.6.0, and the contract floor in `docs/API.md` stays 0.6.0.

### Security

- russh moves from 0.62 to 0.64. The 0.62 line does not get the fixes for russh's advisories of
  2026-09-30, and none of the four can be reached through netconf:
  - GHSA-47hw-gvq5-r2gm — russh calls a client's channel callbacks for channels it never opened.
    netconf's handler overrides none of them, and netconf reads from the channel it opened,
    which russh feeds only for known channels.
  - GHSA-35g8-35p8-c8fw — memory exhaustion in russh's server. netconf is an SSH client only.
  - GHSA-w3jg-pjxf-73p4 — only `mlkem768x25519-sha256`, which no policy offers.
  - GHSA-p8qx-h547-fjw9 — needs the MAC `none` on both sides, which no policy offers.

### Changed

- `rust-version` is 1.89, the Rust russh 0.64 needs. It read 1.75, which the dependencies had
  outgrown: 0.6.0 needed 1.85, as the crate without `russh-transport` still does.
- A host certificate is refused, by `connect` and by `observe_host_key`, pinned or not, even
  when the key it carries is the pinned one. The error is `HostKey`, with the fingerprint of that
  key in `observed`, and no certificate algorithm is advertised under any policy. russh 0.64
  can hand a client a certificate; netconf pins keys and knows no authority to trust. russh 0.62
  advertised no host certificate algorithm, so no device could present one before either.
- The documentation and comments that describe russh name 0.64.
- `Option::is_none_or` replaces `map_or(true, …)`, and `iter::repeat_n` replaces
  `repeat(…).take(…)`, in `junos.rs` and `redact.rs`: clippy asks for both now that
  `rust-version` allows them. The behaviour is the same.

## [0.6.0] — 2026-10-05

The first release on crates.io. netconf is pre-release, in beta, as the README says. The public
surface is that of 0.5.14.

### Changed

- The publishing destination is crates.io, and only crates.io: `publish` in `Cargo.toml` names
  `crates-io` alone, and `.cargo/config.toml` makes it what a bare `cargo publish` means.
- The description in `Cargo.toml` begins with «Pre-release (beta).», so the crates.io page says
  so too.
- The keywords are `netconf`, `junos`, `juniper`, `ssh` and `network-automation`.
- docs.rs builds the documentation with every feature, so the `russh-transport` module is
  documented too, and `documentation` in `Cargo.toml` points there.
- Every public item has a doc comment, the crate documentation describes the `russh-transport`
  feature, and `#![deny(missing_docs)]`, which was a warning, makes a public item without one a
  build error.
- The dependency lines in `README.md` and `docs/Usage.md` read `0.6`, and the README has a
  docs.rs badge. The contract floor in `docs/API.md` is 0.6.0, the first version on crates.io.
- `SECURITY.md` names 0.6.x as the supported release.

## [0.5.14] — 2026-10-04 (the repository starts over)

### Note — the history starts here, on purpose

The repository this crate lived in was cleaned out and started fresh at this version. The
earlier commits were written while a larger private system was being built, and they describe
it: sibling services, internal documents, decisions that belong to that system rather than to
this crate, and messages largely in a language this crate no longer uses. Carrying them along
would have mixed design for other things into a crate meant to stand on its own.

What each release changed is in this file. The code is what it was — `src/` at 0.5.14 is
`src/` at 0.5.13, unchanged. Only the commit history was left behind, and the untouched
original is archived where the people who need it can reach it.

### Changed

- `docs/Usage.md` and `docs/Filter.md` are rewritten from the code as it is, and every example
  in `Usage.md` compiles against the crate. `docs/API.md` is checked against the public surface
  in both directions: what it described that the code does not have is gone, and what the code
  has that it did not describe is in. It carries no version history any more; its contract
  floor stays 0.5.13, since the public surface did not change.
- The README says the repository is a mirror, as `CONTRIBUTING.md` already did.
- A redaction test uses a generated md5-crypt hash of a dummy word.

### Added

- A GitHub Actions workflow, `.github/workflows/ci.yml`.

### Removed

- `.dockerignore`. It served a build setup outside this repository.

## [0.5.13] — 2026-10-04

### Changed — the configuration filter: more floor, rename and copy, logical systems

- The floor holds `logical-systems`, `tenants`, `virtual-chassis`,
  `multi-chassis`, `fabric`, `dynamic-profiles` and `accounting-options`, and
  `wildcard delete <tree> *` with a literal `*`, as it holds `delete <tree>`.
  `apply-groups-except` is a known top-level hierarchy.
- `rename` and `copy` were a `Set` of the path as written. They have a filter
  of their own: the target is the path with as many words at its end replaced
  by those after `to`; `rename` is a `Delete` of the source and a `Set` of the
  target, `copy` a `Set` of the target. `load_configuration` reads the candidate
  configuration first, and refuses the payload when a target is there already:
  a rename or a copy creates, it does not overwrite.
- What stands under `logical-systems <name>` and `tenants <name>` is judged as
  it would be at the top level — by the floor, the rules, and the read grants
  on the CLI and in XML — and the system itself is not deleted. A read of a
  whole system needs every read grant, as the whole configuration does.
- `show ephemeral-configuration` was an ordinary `show`; it is a configuration
  read, judged as `show configuration` is.

### Changed — a `#` comment in a set payload is dropped before it is judged

A `#` that did not begin the line was read as part of the path: `delete
protocols # x` was a deletion of `protocols # x`, below the top-level tree, and
the floor did not refuse it, while the device may read the line as `delete
protocols`. A `#` outside a quoted string now makes the rest of its line a
comment; the line is judged without it, so the floor refuses `delete protocols
# x`, and `load_configuration` sends the set payload without its comments, so
the device reads what the policy judged. Inside `"…"`, `#` is text.

### Changed — an error carries what the device sent, beside the words

An answer from netconf carries what the device said, and an error is an answer.
Several errors were built from what the device sent and then dropped it: the
diff a confirming commit was withheld over, the fresh diff the drift guard
refused, the reply a protocol error was about, the bytes a frame broke on, the
part of a message that had arrived when time ran out or the device closed. The
operator was told that something was wrong and not what the device had said, and
could not decide what to do about it. What the device sent now goes with the
error, in fields of its own beside the explanation, so a consumer can take it out
as data; the error's text takes it along, made printable, so it stands on its own.

- `NetconfError::Protocol(String)` is `Protocol { detail, received }`. `received`
  holds what the device sent: the reply whose `message-id` is not the request's,
  that is not UTF-8, that does not parse, is incomplete, holds no element or is
  not an `<rpc-reply>` — whose root is now named in the text; the hello without
  capabilities, the hello that is not UTF-8 and the data after it; the compare
  reply with no `<configuration-output>`; the `<get-commit-information>` reply
  with no entry; and the de-framer's buffer when a frame breaks, with the bytes
  found where it broke named in the text. Every other protocol error on what the
  device sent carries it too: an unknown entity, a parse error or text that does
  not decode in a hello, a reply, a compare reply or the commit information, and
  every chunk-size the de-framer refuses. Bytes that are not UTF-8 are written as
  `\xNN`, so none is lost.
- `NetconfError::Timeout(&'static str)` is `Timeout { op, partial }`, and a peer
  that closes before a message is complete is the new
  `TransportError::Closed { detail, partial, ssh }`, where it was `Io`. `partial`
  is what had arrived of the message.
- `NetconfError::Drift` is `Drift { fresh }`, the diff the device shows now.
- `NetconfError::ChangedSinceConfirmed(String)` carries a `DeviceChanged`: which
  check failed (`ConfirmedCheck`), the commit entry recorded after the confirmed
  commit and the device's last entry now, and the diff. For changes in the
  candidate the diff is the one the check read. For a commit made after the
  confirmed one, it is fetched as `show | compare rollback N`, N being the place
  the confirmed commit has in the commit history just read, found by every field
  but its sequence number; when the confirmed commit is no longer in the history,
  there is nothing to compare with, and the error says so. When fetching the
  diff fails, the answer is still `ChangedSinceConfirmed`, with no diff and the
  error the request came back with in `DeviceChanged::diff_error`: the device
  changed whatever the fetch did.
- A `DeviceError`'s text shows `info`, `app_tag` and `error_type` when the device
  set them; `info` is where Junos names the statement it objected to.

Everything the device sent goes through the policy's filter before it leaves the
session, as a reply does: the device's secrets redacted unless the policy has
`allow_secrets` or is `all_free`. The parsing, the de-framer and the transport
build their errors without a policy; the session filters them on the way out,
and during `connect` and `establish`, with no policy bound yet, redacts them.
`SshMessages`, `ExitSignal` and `SshDisconnect` are new, for what the device
says over SSH; `TransportError::SubsystemUnavailable` gained `ssh`.

### Changed — nothing in an `<rpc-error>`, or around it, is dropped

The parser kept the `<rpc-error>` fields it knew and nothing else. A child it
did not know — Junos's `<source-daemon>` — was dropped, and so was text outside
the fields; `<error-info>` was flattened to its text, so a lock's
`<session-id>7</session-id>` reached the caller as `7`; and the rest of the
reply — a commit's `<commit-results>` naming the routing engine, a load's error
count — was thrown away once the errors were read. Now:

- `DeviceError::other` holds every child of the `<rpc-error>` that is not a
  known field, as its name and its text, and text outside every element as
  `#text`, in the device's order, made printable like the fields.
- `DeviceError::info` keeps the names of the elements in it: `bad-element:
  vlan-id`, `session-id: 7`, nested names joined by `/`, parts by ` · `.
- A field the device sends more than once keeps the first in its place, and each
  later one goes into `other` by its name; each used to overwrite the one before.
  An empty field — `<error-message/>` — is present and empty, where it read as
  absent.
- A comment or processing instruction inside an `<rpc-error>` is in `other` as
  `#comment` or `#pi`; one outside the errors makes the rest of the reply worth
  carrying.
- `DeviceError::rest`, on the first error, is the reply with every `<rpc-error>`
  cut out, when what is left is more than `<ok/>`.
- `rpc::parse_rpc_reply` returns the warnings it has read, where it returned
  `()`.

Through a session, `other` and `rest` come with the device's secrets redacted
unless the policy lets them through, on errors and on the warnings
`take_warnings` hands over.

### Changed — the device's answer to a commit, and to `<close-session/>`, reaches the caller

`commit_check` returned `()`, and the reply — what the check found, one
`<routing-engine>` for each it checked on — was dropped, and so did every typed
helper but the reads. Every helper now returns the device's `<rpc-reply>`,
redacted as `rpc()`'s is: `commit_check`, `commit`, `commit_confirmed`, `lock`,
`unlock`, `load_configuration`, `rollback` and `discard_changes`. Every call
gives what the device answered, whether Junos answers `<commit-results>` or
`<ok/>`.

The operations made of several requests keep their answers too.
`prepare_change` puts the answers to its lock and load in
`PreparedChange::replies`; `confirm_commit` returns the answers to the commit and
the unlock, and `abort_change` those to the discard and the unlock, each as `(RPC
name, reply)` in the order sent. When such an operation fails after requests
that went through, their answers — before the failure, and from the cleanup
after it — go with the error in the new `NetconfError::WithReplies`; a drift
caught by `confirm_commit` comes in it, with the cleanup's answers.

When the commit succeeded and a step after it failed — the unlock in
`confirm_commit`, the reading of the commit history after `commit_confirmed` —
the error was the later step's alone, and the answer to the commit was dropped.
`CommittedThenFailed` is a struct variant, `{ reply, error }`, carrying both.

The record `commit_confirmed` keeps of the device's last commit, which the
confirming commit is checked against, was kept inside the session.
`NetconfSession::confirmed_commit` reads it, as the policy lets it through. In
the record, a value in CDATA, a field that is there and empty, and text outside
every field (as `#text`) are kept, where they were skipped; an empty first
`<commit-history/>` is an entry with nothing in it, which is no record, where it
was skipped and the next entry taken for the device's last commit.

`close()` ignored whether `<close-session/>` could be sent, whether the reply
came in time, and what it held; the warnings the session held were dropped with
it, and so was what the device said over SSH as it ended. It now returns a
`SessionEnd` — the warnings the session held, those `take_warnings` had not
handed over and those in the reply to `<close-session/>`, and what the device
said over SSH, which the transport returns as it closes —
`Result<SessionEnd, _>` where it returned `Result<(), _>`. What goes wrong is
reported as for any request: a failed send, a timeout, a reply left incomplete
or that cannot be read, and an `<rpc-error>`, the device refusing. A device that
ends the session without replying has ended it, unless it left a message
incomplete or said something over SSH as it ended — an exit status or signal, a
disconnect message — and then that is reported; the login banner does not
count. The transport is closed either way, and every failure is the new
`NetconfError::CloseFailed`, carrying the error and the `SessionEnd`, so the
warnings reach the caller then too.

### Changed — what the device says over SSH goes with the error

russh hands the client handler the device's login banner and its disconnect
message — reason code, description, language — and the handler's defaults
dropped both; the channel's `exit-status` and `exit-signal`, where the device
says how the subsystem ended, were skipped like housekeeping, and `recv`
returned at the device's EOF, before an exit status sent after it arrived. A
device that explained itself and hung up left the caller with «peer closed» or
russh's own text.

`RusshTransport` now keeps all four, in an `SshMessages`. A channel the device
closes, a failed send, and a login, channel or subsystem request that fails after
the device has said something over SSH become `TransportError::Closed`, carrying
it; `SubsystemUnavailable` carries it in `ssh`. After the EOF, `recv` reads on as
before it: data that comes all the same is handed on, where it was dropped, the
exit status and signal are kept, and the close — or a wait that runs out after
the EOF — ends in the close outcome. A channel the device closed after writing
to stderr is `Closed` too, where it was `Io`, with the same text in `detail`.
Through a session, the banner, the disconnect description and the exit signal's
message come with the device's secrets redacted unless the policy lets them
through.

`NetconfTransport::close` returns what the device said over SSH, `SshMessages`,
where it returned `()`; it is what `close()` hands over. `RusshTransport::close`
sent EOF and disconnected with both results ignored. It now sends EOF, reads
what the device sends until it closes the channel — the subsystem's exit status
or signal, which come as it ends — and disconnects; data the device sends after
the session is over comes back as `Closed`, in `partial`. russh fails the EOF and
the disconnect with `SendError` only when the SSH connection has already ended,
which after `<close-session/>` the device may have done; that is the close
having happened, and is not reported as a failure. Any other failure is.

The host key the device presented was recorded only when the lock around the
record was not poisoned, so the error that followed could lack it; it is
recorded and read through a poisoned lock.

### Added — the device's hello, whole

The session read the capabilities and the session id out of the device's hello
and dropped the rest: Junos writes the login's user and class in comments
there, a capability in CDATA was skipped, and a session id that is not a number
read as none. `NetconfSession::hello` returns the hello as the device sent it,
redacted as a reply is, and a capability in CDATA is a capability.

### Changed — the read filter redacts the statements Junos keeps a secret in, by name

A statement was a secret one when a hyphen-separated part of its name was
`password`, `secret`, `key` or `passphrase`. That caught `host key`,
`key-chain kc key 0`, `license keys`, `system login password` and the crate's
own error texts, and redacted the rest of the line. The filter now knows the
statements Junos keeps a secret in, by their exact names, and where the name
alone does not say it, by their context: `key` after `md5 N`, `password` after
`firewall-user`, `client` or `archive-sites <url>`, `value` after
`authentication-key N`. Tokens that authenticate to a service are on the list
by their exact names (`token`, `api-token`, `authentication-token` and the
like); `token-bucket` is not one.
The context is the words before the name on the line, the text-format blocks
the line is inside or the `[edit …]` banner of a diff, and in XML the parent
element. `docs/Filter.md` has the list. The nets stay: hashes, PEM blocks, key
blobs, the password in a URL and the `SECRET-DATA` mark. `ssh-rsa` and the
other public keys are no longer statements; the key-blob net still takes their
blob. Under `strict()` the SNMP community is `community` and `community-name`,
no longer any name ending in `-community`. A `{` that opens a block stays with
the statement when its value goes.

- A line that went on past the end of a PEM block went out as it was: the PEM
  rule returned before the others. It is one rule among them.
- A secret element whose start tag the line end cut, its attribute on the next
  line, went out with its value. It opens the element as a whole tag does.

### Fixed — the read filter lets no secret through in the shapes it missed

The filter that redacts the device's secrets missed some shapes, and a second
pass over its output could redact more. The filter alone decides what passes;
without a policy that lets secrets through, they are redacted, and redacting too
much of a line of prose is the direction it errs in.

- An XML secret element with an attribute, its value on the lines after it —
  `<authentication-key junos:changed="changed">` — went out with its value: the
  statement rule took `<authentication-key` for a statement and cut the tag's
  `>` off, so the element rule saw no element. A statement word that ends inside
  a tag has its value after the tag now, and no name is read out of the
  element's name in a tag. Markup is read only as XML writes it: a comment, a
  CDATA section, a processing instruction, a tag that is not well formed and
  text that came from `&lt;…&gt;` are text, and a statement name in them is
  read like any other. A name with a tag straight after it,
  `password<secret>`, is an element's text and has no value.
- On the line that closes a secret element opened on an earlier line, what
  followed the closing tag went out as it was; it is read like any line. Several
  secret elements can be open at once, each until its own closing tag, and one
  whose opening tag went with a statement's value on the same line is carried
  all the same.
- Text that looked like the marker got a pass: a value beginning with it was
  taken for one already redacted, and the `SECRET-DATA` net skipped a line
  holding it. Neither happens: text that looks like the marker is read like any
  other.
- A second pass over the filter's output could redact more: over a `$9$` it
  had redacted, it took `$9$[SENSITIVE:` for a new value and the marker grew,
  and a marker one rule put in could make a word of what it was glued to, or
  end a value another rule had measured. `contains_secrets` was then true on
  redacted text, `PreparedChange::has_secrets` true under a redacting policy,
  the `secrets_in_diff` warning fired, and `redacted_diff` differed from
  `diff`. Each line is now read until the rules find nothing more to redact in
  it, every rule reading the line as it stands, and the secret elements a line
  leaves open are read on the line as it goes out: a second pass changes
  nothing.
- The `SECRET-DATA` net fires unless a secret statement on the line is written
  as a word of its own with a value after it, whatever another rule changed; it
  stood down whenever a line had changed.
- An annotation inside a quoted value ended the value: `secret "a ## b";` kept
  `b"`. An annotation is a word of its own, as Junos writes it, and past one
  the line is read on.
- A keyword glued to a control character, or to punctuation, was not a
  keyword. Control characters separate words, and a name is read out of
  whatever is glued to it.
- `compare` redacted the diff with its entities decoded, while `rpc`,
  `get_configuration` and `command` redacted XML with them encoded, so
  `&#x24;9&#x24;` and `authentication-&#107;ey` hid a value and a keyword. Every
  line is read with its entities decoded, and what is not redacted goes out as
  it came in. The filter now works on the decoded line, and puts the line back
  together from its own text and the marker.
- `$sha1$` hashes — a four-character tag — and the password in a URL's user
  information (`scp://user:password@host`) are redacted.
- A long line with many SSH key blobs took time that grew with the square of
  its length; the blobs are found in one pass.

### Changed — the device's error text and russh's text go through the filter

`path`, `message` and `info` in an `<rpc-error>` were redacted whatever the
policy said, and the redaction ran over text already made printable;
`error-type`, `-tag`, `-severity` and `-app-tag` were made printable and never
filtered. Every field follows the policy as everything else does — filtered as
the device wrote it, then made printable — so `allow_secrets` and `all_free` let
them through. A `message-id` that is not the request's, and what the XML parser
quotes of the document in a parse error — an end tag, an entity's name — went
into a `Protocol` error's text made printable and unfiltered; they are filtered
as the reply is first. `rpc::parse_rpc_reply`, `parse_hello_capabilities` and
`extract_compare_diff`, with no policy bound, redact them with
`redact_secrets`. russh's error text, which `classify_connect_err` and the
transport passed on as it was, and logged in `ssh_connect_failed`, is redacted
where the transport takes it in: the transport has no policy, and while
connecting none is bound. The text of an `Io` error, which a transport other
than russh's hands on as it got it, went out of the session as it was; it
passes the session's filter as what the device sent does, and is redacted while
connecting. A capability is made printable.

### Changed — a commit's seconds are in the record of it

Junos gives a commit's time twice in `<get-commit-information>`: as text in
`<date-time>`, and as a number of seconds in the `junos:seconds` attribute on it
— the one a program can read without parsing a date. The record of a commit
dropped the attribute with every other. It is the field `seconds` after
`date-time` now, in `confirmed_commit()` and in `DeviceChanged::confirmed` and
`now`, read strictly as a number, and what is not one goes as it stood; it is
filtered and made printable as the rest of the record is, and the check of the
record against the device's takes it in. No other attribute is kept.

## [0.5.12] — 2026-10-03

### Fixed — the drift guard compares the diffs as the device wrote them

0.5.11 redacted every reply before it left the crate, and the drift guard in
`confirm_commit` compared what came out: the approved diff and the fresh one,
both redacted. A change inside a value the policy redacts — a password changed
on the device between approval and commit — read as the same marker on both
sides, and the commit went through. The state a change is approved in has to be
the state it is committed in. `prepare_change` now keeps the diff as the device
wrote it in a private field of `PreparedChange`, for this comparison alone, and
`confirm_commit` compares raw with raw. What the consumer sees is unchanged:
`diff` is redacted as before, `Debug` shows nothing else. `PreparedChange` is
built by `prepare_change` or by `from_diff`, for a diff the consumer stored at
approval, which is then compared with the fresh diff redacted the same way; a
struct literal no longer compiles.

### Added — the confirming commit checks that the device has not changed

A confirmed commit is live until it is confirmed or rolled back, and the
`commit` that confirms it commits whatever the candidate holds at that moment.
Nothing checked that the device was still as it was. After `commit_confirmed`
the session now reads `<get-commit-information/>` and keeps the device's last
commit — the confirmed one — as its record. The `commit` that is to confirm it
reads the commit information again, and the candidate's diff, before it
commits: another commit on the device, or changes loaded in the candidate,
withhold it as `NetconfError::ChangedSinceConfirmed`, with a text that names the
two commit entries or the number of changed lines, and the device rolls the
confirmed commit back by itself when its timeout runs out. Unchanged, it
confirms and the record is cleared. The record is the session's; a plain
commit with nothing pending makes no check. If the record cannot be read after
`commit_confirmed`, that is `CommittedThenFailed`: the confirmed commit is live.
Both readings are made raw, for the crate's own comparison, and never leave it.

### Changed — `LegacyJunos` offers everything russh has for the R14 to Evo span

The legacy policy appended only the SHA-1 tail — `diffie-hellman-group14-sha1`,
`diffie-hellman-group1-sha1`, `ssh-rsa` — to the modern lists, and the
documentation said russh had no Diffie-Hellman group exchange, no
`dh-group18-sha512` and no `ssh-dss`. russh 0.62 implements all three; the
policy was what held them back. `LegacyJunos` now also offers
`diffie-hellman-group18-sha512` and `diffie-hellman-group-exchange-sha256` at
full strength, `diffie-hellman-group-exchange-sha1` in the SHA-1 tail, and
`ssh-dss` as the last host-key algorithm. Modern algorithms are still
negotiated first. `LEGACY_ALGORITHMS` names the two SHA-1 and DSA additions, so
`is_legacy` marks them; the two at full strength are not legacy. `Modern` is
unchanged. The one algorithm russh lacks is `hmac-md5`.

### Fixed — the CLI read gate judged every word after `configuration` as a tree

`show configuration protocols bgp group x` was refused because `group` is a
prefix of `groups`: the abbreviation-tolerant rule for sensitive trees was
applied to every token of the path, while only the first names a tree. It is
applied to the first token alone now. The XML gate was given the same fix for
its own reason in 0.5.7; the CLI gate kept the false refusal. `show
configuration groups x` is refused as before.

### Fixed — `show sys rollback 1` is a read of the whole configuration

0.5.11 made `show system rollback <n>` a read of the whole configuration, but
only written out in full and in lowercase, while the gate is otherwise
abbreviation-tolerant on the refusal side (`show conf sys`). `show sys rollback
1` and `show sy rol 1` passed as ordinary `show`s. The two keywords are now
matched as prefixes on the refusal side, as `configuration` is.

### Fixed — a control character written as a character reference is refused in a filter

The `get` filter refused a control character in text, but `&#12;` and `&#xD;`
were resolved after that check and sent as the character they stand for. A
resolved reference is held to the same rule as text, in element content and in
attribute values.

### Fixed — an unknown entity anywhere in a reply is refused

The contract has said since 0.5.5 that an entity other than the five
predefined ones and character references is refused. It was, inside an
`<rpc-error>`'s fields, in a compare diff and in a `<capability>`; anywhere
else in a reply or a hello — `&nbsp;` in `<data>` — it passed through. Every
entity reference in a reply or a hello is now resolved, and an unknown one is
`Protocol` wherever it stands.

### Fixed — `reply_message_id` reads the whole range this crate writes

It read the attribute with the reader shared with the chunk-size and the
session-id, which stops at 4294967295 as those RFCs do. The session counts its
`message-id` in `u64`, so an id above that — written by this crate — read as
`None`. The function now reads any `u64`, with the same strictness. The session
itself compares the text and never used this number.

### Fixed — more of the device's text is made printable

0.5.11 made the device's text printable in errors and logs, and missed two
sources: the algorithm names a device announces in its key-exchange init, which
`Negotiation.offered` carried as written — russh checks only that they are
ASCII, and ASCII has control characters — and the tag names quick-xml quotes in
a parse error, which went into `Protocol` as the device wrote them. Both are
made printable now, as stderr and the `rpc-error` fields are.

### Fixed — a refused connect no longer spends the device's legacy warning

`connect` logged its `ssh_connect` event, and under a legacy policy the one
warning the device gets, before it refused a missing host-key pin or a `Custom`
policy. A refused connect therefore used the warning up, and the connect that
then went through was logged at info as if the warning had been given. The
event is logged after the refusals.

### Changed — async-trait 0.1.92 in the lockfile

Rust 1.99's clippy refuses a `#[must_use]` on a function whose return type is
already `#[must_use]`, and async-trait 0.1.91 put one on every method it
expanded, so the crate did not build under `-D warnings` on a current
toolchain. 0.1.92 no longer emits it. `Cargo.toml` asked for `0.1` all along;
only the lockfile moves.

## [0.5.11] — 2026-10-03

### Changed — a session without a policy permits nothing

A session with no policy bound refused configuration changes and ran reads and
`show` under the default rules. The consumer defines the policy it uses, and
until it does netconf does nothing on its behalf: `ConfigPolicy::all_deny()`
permits nothing — no read, no `show`, no command, no change, whatever is granted
— and a session without a bound policy behaves as it. Bind it to say the same
thing out loud; it is a `const fn`.

Every typed helper now passes the session's policy before anything goes on the
wire, through one gate. No policy, or `all_deny`, refuses everything, with the
words `load_configuration` used: `no policy bound to the session — nothing is
permitted, as under ConfigPolicy::all_deny() …`. A policy that can change
nothing — `read_only`, `all_free(Ro)`, rules without a change grant — refuses
`load_configuration`, `commit`, `commit_confirmed` and a `rollback` to a previous
configuration, which loads one whole and so needs `all_free(Rwd)` as a `Text` or
`Xml` load does; `rollback(0)` only discards. Raw `rpc()` goes around the gates
as before.

### Changed — what the device returns is redacted before it leaves the crate

Data the consumer asked for was returned raw — `show` output, configuration, the
compare diff, the raw `rpc` reply — and the redaction was the consumer's to apply
before showing or storing it. The device's secrets now stay in the crate: every
reply passes `redact_secrets` in the one place every reply passes, unless the
session's policy lets them through — `ConfigPolicy::allow_secrets()`, the grant
for it, or `all_free`, which redacts nothing. `secrets_allowed()` says which. A
session with no policy bound has nothing that lets them out.

The marker says what was there and how to read it: `REDACTED` is
`[SENSITIVE: hidden by netconf — allow_secrets() on the policy shows it]` in
place of `[REDACTED]`. The drift protection is unaffected: a fresh diff under
the same policy reads the same way as the approved one, so `confirm_commit`
compares like with like. `PreparedChange::diff` is the diff as the policy let it
through; `redacted_diff()` equals it unless the policy lets secrets through, and
the `secrets_in_diff` warning fires only then.

### Changed — `read_only` takes no command or change grant

`read_only()` was `all_free(Ro)`: it read the sensitive trees ungated and,
against its own documentation, let an `allow_command` grant through, so
`read_only().allow_command("request system reboot")` permitted the reboot. It is
now the ordinary policy's reading side alone: `show` with its read-only pipes,
configuration reads with the sensitive trees behind `allow_read`, the device's
secrets redacted unless `allow_secrets`, and no other command and no change
whatever is granted. `is_read_only()` says so; `all_free_access()` is `None` for
it. The four kinds of policy — the ordinary one, `read_only`, `all_free`,
`all_deny` — are one private mode, and `describe()` names each.

### Changed — the command gate reads a command as the device does

A command is one line of printable ASCII and a tab; anything else refuses it.
U+2028 and U+2029 are not control characters, so `is_control` let them through,
while some readers take them for a line break — the gap a carriage return had in
0.5.7. The Junos CLI is ASCII; a non-ASCII value belongs in a configuration
payload, where the set parser now refuses the two separators as it refuses a
control character and reads other UTF-8 as a value.

Keywords are compared exactly, as the device reads them: `show`, `configuration`
and its prefixes, and the pipe names are lowercase, and a command grant matches
the command's words as written. `SHOW`, `show Configuration system` and
`| MATCH` were folded to lowercase and let through; the refusal now says when
only the case is wrong. A quote belongs in a pipe's pattern and nowhere else —
`show "configuration" system` was a read of `system` the gate did not see as one.
`show system rollback <n>` shows a previous configuration whole and is a read of
the whole configuration, sensitive trees included. `| compare` may name a
rollback and nothing else: a file on the device is not read through it.

### Fixed — the chunked de-framer resumes between reads

The chunked parser walked every chunk header from the start of the buffer on
every read, because it kept no position between reads. The data was copied
once, as 0.5.7 says, but the walk itself cost chunks × reads: a reply arriving
in many small chunks over many reads de-framed in quadratic time. The `Decoder`
now keeps the walk's position, the chunk ranges found so far and their total,
and resumes there; a header cut off by the end of the buffer is the only one
read twice. A newline that ends a read is kept rather than discarded as
whitespace, since it may be the first byte of the next header.

### Fixed — a number from the device is read as its RFC writes it

The chunk-size, the hello's `session-id` and the public `reply_message_id` used
`str::parse`, which reads `007` as 7, `+7` as 7 and, after a `trim`, `" 7 "` as
7. RFC 6242 §4.2 forbids a leading zero in the chunk-size outright and caps it
at 4294967295; RFC 6241 types the session-id as an `unsignedInt`. One strict
reader now serves all three: decimal digits, no sign, no whitespace, no leading
zero, at most 4294967295. A chunk-size written otherwise is `Protocol`; a
session-id written otherwise is no session-id, which is tolerated as before.

The reply's `message-id` is not read as a number at all. RFC 6241 §4.1 has the
device echo the attribute as sent, and this crate writes it, so the text is the
request's or it is not: `007`, `+7` and `" 7 "` all passed for 7.

### Fixed — the `get` filter is read strictly, and what was read is what is sent

The gate read the filter with quick-xml while the original text went to the
device, and the parser is lenient in places the gate is not: `<system\x0c/>`
named a target `system\x0c`, on nobody's list, while the device may read it as
`system`. Whether it does is beside the point. The filter sent is now serialized
from what the gate read, so the two cannot differ, and the reading is strict:
elements, attributes and text only; every element and attribute name an ASCII
XML name with an optional prefix; every attribute quoted, given once and without
`<`; the five predefined entities and character references only; no comment,
CDATA, declaration, doctype or processing instruction; no control character.
Whitespace between elements is not kept.

### Changed — text the device wrote is made printable in errors and logs

Text the device wrote goes into error messages and log lines: stderr from a
refused subsystem, a closed channel's last words, the fields of an `rpc-error`,
an unknown entity's name, a `message-id` that does not match. Each is now made
printable at the point it is built or logged, through one function: a control
character, or U+2028/U+2029, is written out as an escape — `\n`, `\r`, `\t`,
`\u{XXXX}` — and the device's text stays on its own line and shows what it
holds. Redaction of the `rpc-error` fields runs first, as before.

### Documentation

README, CONTRIBUTING and `docs/Filter.md` said no policy can lower the floor.
`all_free` can, by design, and they now say what it is: the one policy that turns
the filter off, chosen out loud — netconf then runs without the feature it exists
for, and the floor, the read gate and the redaction hold for every other policy.
`docs/API.md` and `docs/Usage.md` follow the changes above.

## [0.5.10] — 2026-10-01

### Fixed — the unknown verb in a parse error is redacted

`parse_set_payload` built `ParseError::UnknownVerb` from the word as written, while
the variants that carry a line — `EmptyPath`, `UnbalancedQuote`, `SingleQuote`,
`Comment` — were built from the line redacted with `redact_secrets`. The error
text ends up in `NetconfError::Policy` and from there in the consumer's log, so a
secret written where the verb belongs went there whole: `$9$hunter2 x` was
`unknown verb «$9$hunter2»`. The contract promises that no error text carries a
secret the crate can recognize.

The word is now redacted the same way, at both places it is built — a single
unknown verb and `wildcard` followed by anything but `delete`. `$9$hunter2 x` is
`unknown verb «$9$[REDACTED]»`. A word with nothing to redact — `edit`, `SET`,
`frobnicate` — comes through as written, and so does the hint `Display` gives for
it.

## [0.5.9] — 2026-09-30

### Fixed — when connecting gives up, the device sees the connection end

russh runs an SSH session in a task of its own, which owns the socket, and giving
up on a wait did not stop it. When `connect` gave up — its `Timeouts::connect`
running out, the session deadline, or a failure — the task kept the TCP
connection until russh's inactivity timer ran out: set to `total`, and restarted
whenever the device sends anything. A device stalling the key exchange under a
2 s `connect` and a 20 s `total` saw the connection close after 20 s, not 2 s.
The host-key probe did the same. russh 0.62 has no call that ends the task from
outside.

`connect` and `observe_host_key` now open the TCP connection themselves, hand
russh the stream and keep a second handle on the socket. Every way out before
the session is established shuts the socket down, and the device sees the
connection end at once. An established session is handed the connection and ends
it as before, through `close`.

### Fixed — the host-key probe runs under the session's `Timeouts`

`observe_host_key` took `Timeouts::connect` alone and never validated `Timeouts`:
`total` did not bound it, and a `connect` of any size was waited out in full. It
now runs under the same limits as `connect`: `Timeouts` outside their frames are
refused before anything connects, with `validate`'s message, and the TCP
connection and key exchange end within `connect`, counted from the start, and
never past `total`. Running out is `Timeout("ssh-connect")`, or
`Timeout("session-ttl")` when `total` is what ran out; the probe's own
`Timeout("ssh-host-key-probe")` is gone. A consumer that matched on it matches
`"ssh-connect"` instead.

### Fixed — `docs/Filter.md` said a top-level tree can never be deleted

`docs/Filter.md` wrongly said a top-level tree can never be deleted, however the
policy is set up; the policy module's header said the same. `all_free` can, by
design: it is the one policy that may delete everything on the device, a
top-level tree included. The floor holds for every other policy. Both now say so;
the code and `docs/API.md` already did, and nothing in the filter changes.

`docs/Filter.md` also states the case rule `docs/API.md` already described, which
holds whatever the policy: verbs are lowercase only, paths are compared exactly
with case, and the floor ignores case.

## [0.5.8] — 2026-09-30

Bugfix release after the first runs against real devices.

### Fixed — every wait while connecting ends within `Timeouts::connect`

`connect` bounded the TCP connection and the SSH handshake by `Timeouts::connect`,
and the wait for the subsystem answer, but not authentication or opening the
channel. russh bounds neither itself, beyond an inactivity timer that restarts on
activity and is set to the session's TTL. A device that took the handshake and
never answered the login held `connect` for the whole TTL, and it then came back as
`AuthRejected` with no methods — russh reports a session that ended during the
login as a login turned down — a false «wrong password».

The connection phase as a whole — the TCP connection, the handshake and host key
check, authentication, opening the channel and the device's answer to the subsystem
request — now ends within one `Timeouts::connect`, counted from when the connection
is started, and never past the session's deadline; the TCP connection and the
handshake used to be able to outlast a `total` shorter than `connect`. Running out
is `Timeout("ssh-connect")`, or `Timeout("ssh-subsystem")` while waiting for the
subsystem answer, or `Timeout("session-ttl")` when the deadline is what ran out.
The hello is not part of the phase and runs under `per_rpc`, as it always did; the
documentation of `Timeouts::connect` said it covered the hello, and now says what it
covers.

### Fixed — wrong credentials are their own error

A login the device did not let through came back as `TransportError::Io` with a
text naming the methods the device accepts. The text was right, but a consumer
could tell wrong credentials from a broken connection only by parsing it. It is now
`TransportError::AuthRejected { username, remaining_methods, partial_success }`,
carrying what the device said, with the same text as before. The `ssh_auth_failed`
event is unchanged.

### Fixed — a device without NETCONF over SSH is told apart, and at once

`connect` asked for the `netconf` subsystem and took russh's `Ok` for the device's
answer. It is not one: russh 0.62's `request_subsystem` queues the request and
returns at once, and the device's `SSH_MSG_CHANNEL_SUCCESS` or
`SSH_MSG_CHANNEL_FAILURE` arrives later, on the channel. A device without NETCONF
over SSH refuses the subsystem and leaves the channel open, so the session was
logged as established — `ssh_session_established`, «NETCONF subsystem opened» —
and the hello then waited out `per_rpc` for a reply that was never coming, ending as
`Timeout("rpc-recv")`, which named neither the cause nor the fix.

`connect` now reads the answer before it returns. A refusal, or a channel that ends
before the answer, is the new `TransportError::SubsystemUnavailable { stderr }`,
whose text reads «the device did not offer the NETCONF subsystem — NETCONF over SSH
is not enabled on the device (Junos: `set system services netconf ssh`)», followed
by anything the device wrote on stderr. It comes back as soon as the device answers,
and `ssh_session_established` is logged only when the answer is yes. The wait is
bounded by `Timeouts::connect` and the session deadline; running out is
`Timeout("ssh-subsystem")`. Data that arrives before the answer can only come from a
subsystem that runs, and is handed to the first read.

## [0.5.7] — 2026-09-27

### Added — commit RPCs have their own time budget

A commit on a device can take far longer than an ordinary RPC, and a commit that
outlasted `per_rpc` came back as `CommitUnanswered` with the device possibly still
committing. The new `Timeouts::per_commit: Option<Duration>` takes the place of
`per_rpc` for `commit` and `commit_confirmed` — and so for the commit inside
`confirm_commit`: each single read and send of a commit waits up to it.
`commit_check` commits nothing and stays on `per_rpc`, as does every other request.
`None`, the default, runs commits under `per_rpc` exactly as before. When it is set,
`validate` refuses it at connect unless it is at least one second and no more than
`max_total`; like every wait, it never runs past the session's deadline. The
session tells the transport a commit is in flight through a sealed trait method
that cannot be called or overridden outside the crate, so `RusshTransport` applies
the budget and a transport implemented elsewhere applies what it was given to every
RPC alike.

**This breaks code that builds `Timeouts` field by field.** A struct literal that
names `connect`, `per_rpc`, `total` and `max_total` no longer compiles: add
`per_commit: None` to keep today's behaviour, or end the literal with
`..Timeouts::default()`.

### Added — commits can be synchronized to both Routing Engines, off by default

The new `NetconfSession::set_synchronize_commits(true)` makes `commit` and
`commit_confirmed` — and so `confirm_commit` — send `<synchronize/>` first inside
`<commit-configuration>`: the Junos `commit synchronize`, which commits on both
Routing Engines of a device that has two. It is off by default and the consumer's
choice, since a dual-RE device configured with `system commit synchronize`
synchronizes every commit by itself, which is the recommended setup. Off, every
commit is sent byte for byte as before, and `commit_check` is unchanged either way.

### Fixed — a set-format load says its format is text

`load_configuration` with `Format::Set` sent `<load-configuration action="set">`
and nothing more. The Junos XML protocol documentation says an application that
uploads configuration mode commands must include both `action="set"` and
`format="text"` in the opening tag, and `format` defaults to `xml` on the device.
The reference clients, PyEZ and ncclient, send both. The set-format load now opens
with `<load-configuration action="set" format="text">`. The payload, its escaping
and the policy check are unchanged, and the `LoadAction` is still not used.

### Fixed — every `<rpc-error>` is reported, and some tags are explained

A reply's first error was reported and the rest of its `<rpc-error>`s dropped:
further errors — one per failing line of a load, say — and every warning. Warnings
on a successful reply never reached the caller at all, since the typed helpers
return `()`. Now nothing is dropped. The `Device` error is the first error, and the
new `DeviceError::also` holds every other `<rpc-error>` of the reply, errors and
warnings, in the device's order. Warnings on a reply that succeeded are kept by the
session and handed over by the new `take_warnings()`.

The `error-tag` of some errors is translated: `DeviceError::explanation()` gives
the meaning of `lock-denied`, `in-use`, `access-denied`, `invalid-value`,
`data-exists`, `data-missing`, `unknown-element`, `bad-element` and
`operation-not-supported`, and the error text shows it next to the device's own
message with RFC 6241, Appendix A as the reference. Other tags read as before.

### Changed — `read_only` reads everything; `with_default_floor` is the ordinary policy

`read_only()` was `with_default_floor()` under another name: the default floor, no
change grants, and the sensitive trees behind an `allow_read` grant. It now means
what its name is for — read everything, change nothing, as a deliberate choice. It
is `all_free(Ro)`: every read is allowed, the sensitive trees and the device's
secrets included, and no change is. `with_default_floor()` is the ordinary policy
that anyone gets and the base to grant from. A policy built as
`read_only().grant(...)` must be built on `with_default_floor()` instead, since
grants on an all-free policy have no effect. From the internal review of
2026-09-26 (X3).

### Fixed — every part of a command is checked, pipes included

The command gate looked only at the text before the first `|`; the pipe went to the
device as written, so `show … | save`, `| append`, `| tee` and `| request` passed
as a plain `show`. Every part is now checked. A pipe is only valid on `show`, and
each one must be a read-only filter named in the new `READ_ONLY_PIPES`, written in
full; anything else is refused before the command is sent. A `|` inside a
double-quoted string, as in `match "ge|xe"`, does not split the command. Strings
are read by the set parser's quoting rule, `\"` included, and a quote that does
not close refuses the command: an open string hid every `|` after it from the
check, while the device ran them as pipes. From the internal review of 2026-09-26
(S4).

### Fixed — a control character in a command is refused

A carriage return or a newline in a command passed the command gate:
`show interfaces\rrequest system reboot` was read as one `show` and sent, and XML
makes the carriage return a newline before the device reads the text. A command is
one line, and a control character other than a tab now refuses it before anything
is sent. From the follow-up to the internal review of 2026-09-26.

### Fixed — a read filter is one closed XML tree, read by one parser

`get_configuration` put its filter inside `<get-configuration>` as it was given,
while the read gate found the filter's elements with a scanner of its own. The two
could disagree about what the filter was: markup that closed `<get-configuration>`,
or the end-of-message sequence, went to the device as more than a filter, past a
gate that had read something else. The filter is now read once, with quick-xml,
for both: it must be well-formed XML whose elements all close inside it, with no
declaration, doctype or processing instruction and no `]]>]]>`, or the read is
refused as `Policy` before anything is sent. From the internal review of 2026-09-26
(S2).

### Fixed — a `/*` comment, `edit` and a lone carriage return are refused, not read past

A set payload line that began with `/*` was skipped by the policy check and then
sent to the device with the rest — unchecked. A comment is not sent to a device; it
goes in a quoted string. A `/*` outside a quoted string now refuses the payload with
the new `ParseError::Comment`; inside `"…"` it is ordinary text. And `edit`, which
makes the following lines relative to a new context on the device while the filter
reads every line as a full path, is no longer a verb: it is refused, with a message
saying every line must carry its full path. `#` lines are still skipped.

A carriage return did the same. The parser splits a payload with `str::lines`,
which does not end a line at a lone `\r`, while XML turns one into a newline
(XML 1.0 §2.11) before the device reads the payload: `#\rdelete protocols` was a
skipped `#` line to the filter and a `delete protocols` to the device, and
`set … description x\rdelete system` one `set` to the filter and two statements to
the device — through a consumer's floor check as well, since that check runs the
same parser. A control character other than a tab, on any line, now refuses the
payload before any line is parsed, with the new `ParseError::ControlCharacter`: the
line number and the code point, never the line, which may hold a secret. The rule
is the command gate's (see above). A line still ends with `\n` or `\r\n`, the two
line ends `str::lines` and XML agree on. Both new variants arrive in a `ParseError`
that is now `#[non_exhaustive]` (see below). From the internal review of 2026-09-26
(S5) and its follow-up.

### Changed — `ParseError` is `#[non_exhaustive]`

`ParseError` was the one public error enum that was not, so every variant added to
it — `SingleQuote`, `Comment` and `ControlCharacter` in this release — broke a
consumer that matched it exhaustively. It is now `#[non_exhaustive]`, like
`NetconfError`, `TransportError` and `Scope`: a match outside the crate needs a
wildcard arm, once, and a later variant needs no change.

### Fixed — a compare reply without a diff is an error, not «no change»

`extract_compare_diff` — and so `compare()` — returned `""` both for an empty
`<configuration-output/>` and for a reply with no `<configuration-output>` at all:
one holding only `<ok/>`, only warnings, or a diff in some other element. A
consumer could not tell the two apart, and neither could the drift check, which
compared `""` with an approved `""` and committed — the loaded payload, and in a
shared candidate whatever else was in it. Absent is not empty. A reply without the
element is now `NetconfError::Protocol`, saying the element is missing;
`prepare_change` and `confirm_commit` return it after discarding and unlocking,
and nothing is committed. An empty element is still `""`. From the internal
review of 2026-09-26 (B2), and Roger's rule of the same day: netconf reports what
it gets from the device, without judgement of its own.

### Fixed — the change flow reports everything that came back

Parts of what came back from a change were dropped. A commit that succeeded,
followed by an unlock that failed, came back as the unlock's error alone, with no
word that the change was committed. A commit that got no readable answer came back
as a plain timeout or transport error, like any other request. The cleanup after a
failure — discard and unlock — threw its own errors away, and `abort_change`
dropped a failed discard and reported success.

Three new `NetconfError` variants carry it: `CommittedThenFailed` (the commit
succeeded, then a later step failed, which is inside), `CommitUnanswered` (a commit
got no readable answer; inside is what happened instead), and `CleanupFailed` (a
failure, and every cleanup step that failed after it). `commit` and
`commit_confirmed` report `CommitUnanswered`; a refusal from the device is still
its own `Device` error. Where the cleanup goes through, the error is unchanged.
From the internal review of 2026-09-26 (B3).

### Changed — the host-key comparison uses krypto's `ct_eq`

The pinned host-key fingerprint was compared with a hand-written constant-time
loop, a second copy of what krypto provides as `ct_eq`. It now uses `ct_eq`,
which has the same result — unequal lengths are unequal, otherwise every byte is
compared — and is built on `subtle`, which keeps the optimiser from turning it
back into an early exit. From the internal review of 2026-09-26 (D7).

### Fixed — a large reply no longer costs quadratic time to de-frame

Every read made the decoder start over: end-of-message framing searched the whole
buffer for `]]>]]>` again, and chunked framing copied every complete chunk again.
A large configuration arriving in many pieces therefore cost time in proportion to
its size squared. The end-of-message search now resumes where it stopped, and
chunked data is copied once, when the whole message is in. Nothing about what is
accepted or refused changes. From the internal review of 2026-09-26 (B7).

### Fixed — rare PEM and XML shapes no longer pass redaction untouched

A PEM line whose BEGIN marker had no closing hyphens, with the END marker on the
same line, was returned unchanged, key body included. A line where one block ended
and the next began — a chain whose newlines were lost — left the next block's body
unredacted, and body text on the BEGIN or END line of a multi-line block went out
too, as did an XML secret's value on the opening tag's own line. PEM handling now
walks a line marker by marker, so any number of blocks can end and begin on one
line; all of these redact, and a plain PEM label is still kept. From the internal
review of 2026-09-26 (S9).

### Fixed — a name that looks like free text no longer stops redaction

Redaction stopped scanning a line at `description`, `annotate` or `comment`, on the
view that the rest was an operator's free text. The same words are also names in a
path — a user called `comment`, an IKE policy called `description` — and a secret
statement after such a name was never looked at, so a cleartext value went out
unredacted. The scan no longer stops. Descriptions are still left alone: a value
with spaces is quoted and is one token, which cannot match a statement name. From
the internal review of 2026-09-26 (S8).

### Fixed — a filter element is matched exactly, so a BGP group read works

The read gate matched every element in a `get_configuration` filter as a possible
abbreviation of a sensitive tree, so `<group>` — as in `protocols bgp group` —
counted as a prefix of `groups` and the read was refused. XML element names are
never abbreviated, so they are now matched exactly. `show configuration <tree>`
keeps the abbreviation-tolerant rule, where `sys` still counts as `system`, and
the public `check_config_read` is unchanged. From the internal review of
2026-09-26 (B8).

### Fixed — data after the hello is not misread in chunked framing

The hello is end-of-message framed, and the session switches to chunked once both
sides have announced 1.1. `Decoder::set_mode` documents that it may only be called
with nothing buffered, but nothing checked, so bytes a device sent after its hello
— in the same read, before any request — were kept and parsed as chunked. The
switch to chunked now refuses with `Protocol` when anything but whitespace is
still buffered; whitespace is skipped by the chunked reader, as before. `set_mode`
itself is unchanged. From the internal review of 2026-09-26 (B5).

### Changed — the `legacy` tag is documented as what it is

The docs said anything using a legacy SSH algorithm is marked `legacy`, and that
every event of such a connection carries the tag. The transport marks by policy:
a device on `LegacyJunos` gets `legacy = true` on its `ssh_connect` event whether
or not an old algorithm is what gets negotiated, since the transport does not learn
which one was, and the other events name the policy rather than carry the tag.
`is_legacy` is for a consumer marking its own events by algorithm name. The docs
now say so; behaviour is unchanged. From the internal review of 2026-09-26 (D4).

### Fixed — three policy refusals no longer carry a run of spaces

The refusals for reading the full configuration, reading a sensitive tree, and a
command outside the rule set each had some twenty spaces in the middle of the
sentence: the string literals had lost their line continuations. The wording is
unchanged. From the internal review of 2026-09-26 (D6).

### Changed — two doc comments now say what the code does

`SshPolicy` said `LegacyJunos` offers 3DES, which no policy has done since 0.3.2,
and did not name group1-sha1, which it does offer; `Modern` is described in full as
well. `LoadAction::Override` said the filter refuses it, but the filter never sees
the action — a Set load ignores it, and Text and Xml need `all_free(Rwd)` anyway.
Documentation only. From the internal review of 2026-09-26 (D3, D5).

### Fixed — a host or username that cannot be right is refused before it is logged

`connect()` and `observe_host_key()` logged the host and username verbatim before
checking anything, so a control character in either — a newline above all — could
forge a log line of its own, and an empty value surfaced later as a baffling
connection or authentication error. Both are now checked first: neither may be
empty or hold a control character, and a host may not hold whitespace. The
refusal does not echo the value. From the internal review of 2026-09-26 (S11).

### Fixed — `observe_host_key` refuses what `connect` refuses

`connect()` refuses `SshPolicy::Custom`, which is not implemented, and timeouts
that can never succeed. `observe_host_key()` did neither: `Custom` quietly fell
back to russh's default algorithm list, and a zero `connect` timeout failed as
though the device had not answered. The probe now refuses both before anything
goes on the wire, in the same words as `connect()`. It still validates only the
`connect` timeout, the one it uses. From the internal review of 2026-09-26 (B10).

### Fixed — a send is bounded like a read

`send()` checked the session deadline before it started and then waited as long as
the SSH channel took. A device that stops reading fills the window, and the send
then waited for space that never came — bounded only by russh's inactivity timer,
which is set to the whole TTL. A send now gets the same budget as a read, the
smaller of `per_rpc` and the time left, and a timeout is `Timeout("rpc-send")`, or
`Timeout("session-ttl")` when the deadline is what ran out. From the internal
review of 2026-09-26 (B6).

### Fixed — a malformed `message-id` is refused, not read as missing

A reply whose `message-id` was present but not a number — empty, `abc`, `-1` —
was read as having no `message-id` at all, and a missing one is tolerated because
Junos omits it on some replies. So the malformed reply went through without the
check that ties it to the request. Only an absent `message-id` is tolerated now;
a malformed one is `Protocol`. The public `rpc::reply_message_id` is unchanged.
From the internal review of 2026-09-26 (B4).

### Fixed — an empty command grant grants nothing

`allow_command("")`, or a prefix of only whitespace, allowed every operational
command: a grant with no tokens is a prefix of all of them, so `request`, `clear`
and `restart` went through. An empty string is exactly what a missing
configuration value turns into. A blank prefix is now not recorded, and the
matcher skips a grant with no tokens regardless. From the internal review of
2026-09-26 (S3).

### Fixed — text on stderr can no longer take the session down

The netconf subsystem's stderr is kept for the error text, capped at 4096 bytes.
The cap cut with `String::truncate`, which panics when the length falls inside a
character, and `from_utf8_lossy` turns every invalid byte into the three-byte
U+FFFD — so a device writing more than the cap in non-ASCII text or binary noise
panicked the thread reading from it. The cut now steps back to the nearest
character boundary. From the internal review of 2026-09-26 (B1).

### Fixed — a single quote is refused, not misread

Only `"` quotes a value. A `'` outside a double-quoted string was read as ordinary
text, so `description 'Link to router one'` came out as four tokens — `'Link`, `to`,
`router`, `one'` — and the policy decided on a path the operator had not written.
It then let the line through, because the extra pieces fell inside a subtree that
was already granted. No bypass was found: the policy decides on the prefix, which
was read correctly, and a quoted top-level name such as `delete 'system'` matched no
rule. But the filter was passing on something it had misread, which is the one
thing it exists not to do.

The whole payload is now refused with the new `ParseError::SingleQuote`, the same
way an unbalanced `"` is, and the refused line is redacted before it reaches the
error text. Inside a `"…"` string `'` is still an ordinary character, so
`"Roger's link"` is unaffected.

Found by the second external review as NC-06, which proposed accepting `'` as a
quote character. That would widen what the filter accepts, and `"` is the only
quote character by decision; this goes the other way.

### Fixed — a list secret no longer leaves a stray bracket

A secret given as a list, `secret [ "$9$a" "$9$b" ];`, came out of redaction as
`secret [REDACTED]];`. The trailing-punctuation strip kept the list's own closing
`]` as if it were punctuation. A closing bracket that balances an opening one inside
the value now goes with the value, so the line reads `secret [REDACTED];`. A value
that is not a list keeps its punctuation exactly as before, and a second pass still
changes nothing. Left over from the first external review (2.3/3.5).

### Fixed — a field name inside the message no longer empties it

`<error-message>bad <bad-element>unit</bad-element> here</error-message>` came back
with no message at all. `bad-element` is also a field the parser reads under
`error-info`, so meeting it inside the message opened a new field, threw away the
text before it and never closed the message. A field that is already open now
keeps collecting until its own closing tag, so the message reads `bad unit here`.
`bad-element` under `error-info` is read exactly as before. Left over from the
first external review (2.5).

### Changed — a refusal for the wrong case says so

Verbs and paths are still compared exactly, and `SET` or `Interfaces` is still
refused. Junos names are case-sensitive — `policy-statement EXPORT` and `export`
are different things — so a loose match would let a rule for one approve the
other. What changes is the reason. `unknown verb «SET»` now adds that verbs are
lowercase, and a default-deny on `Interfaces` adds that paths are case-sensitive
and the same path in lowercase would be allowed. Neither hint approves anything,
and neither appears when case is not the reason. From the first external review
(6.2).

### Changed — krypto is built against the published crate

The krypto dependency no longer names a local path. The published 0.5.6 already
declared it that way, since a path is stripped when a crate is packaged; the
repository now says the same.

## [0.5.6] — 2026-09-22 (where a dependency comes from, and three regressions)

### Changed — krypto is taken from crates.io, not from a private registry

The dependency named a private registry. That did two kinds of damage, and only
the first was ever written down.

- It wrote that registry's URL into the **packaged crate**, in a generated
  `Cargo.toml` and `Cargo.lock` that no amount of searching the repository will
  show you. A publish would have carried a private address out with it.
- It **split the dependency graph.** Consumers reach krypto twice — directly, and
  again through nettls, which takes it from crates.io. The same version from two
  sources is two different types to rustc, so the build fails with
  `expected krypto::secret::SecretBuf, found krypto::SecretBuf` about code that is
  byte-for-byte identical. Two consumers were failing exactly that way.

Two guards now hold it, rather than care: `deny.toml` allows crates.io alone, so
naming a private registry on any dependency fails `cargo deny check` in plain
words; and `publish` in the manifest lists the one destination this crate may go
to, refusing any other outright. A repo-local `.cargo/config.toml` says which
registry a bare publish means here, so the choice belongs to the crate and not to
whichever machine runs the command.

### Fixed — a second review, of the fixes themselves

All three arrived with the previous round of fixes. Each is confirmed by a test
that fails without it.

- **An empty reply was read as a protocol violation.** A device with nothing to
  say answers `<rpc-reply/>`, which the parser reports as an empty element and
  never as an opening one. The root-element check only ever saw opening elements,
  so an ordinary answer looked like a document with no elements in it.
- **A child closed its parent, and a secret walked out.** The multi-line state
  ended its block on any closing tag whose text merely *contained* the element
  name, so `</key-algorithm>` closed a `<key>` and the value on the next line left
  the crate in cleartext. The closing tag's own name is now compared exactly.
- **The `## SECRET-DATA` net ate the statement name on a diff line.** A compare
  diff prefixes each line with its own marker, and that marker is a token: the net
  spliced at the statement name rather than at the value, so the operator was left
  with `-  [REDACTED];` and no way to see which field had changed — in the very
  diff this crate exists to produce.

### Fixed — findings from an external review

These shipped early, inside 0.5.5: that version was cut while they still sat under
«Unreleased», so its own entry below understates what it contains.

An external code and security review of 0.5.5 found these. Each is confirmed by a
test that fails without the fix, and none of the 134 tests that existed before
caught any of them.

- **A namespace prefix walked past the read gate.** The gate read the token before
  the colon, so `<junos:system/>` presented itself as `junos` and a sensitive tree
  could be read without a grant. Any prefix at all was enough.
- **A failure left the device locked.** `confirm_commit` returned straight out on a
  transport error, leaving the configuration locked with an unreviewed candidate
  and nothing able to clear it but a person.
- **`Format::Xml` could not work.** The payload was XML-escaped like text, so the
  device received `&lt;system/&gt;` and answered with a syntax error.
- **Redaction was not idempotent** on any line ending in punctuation — which is
  most of them — adding a bracket on every pass. Fixing it exposed a second fault
  in the `## SECRET-DATA` safety net, which then ate the statement name.
- **A secret in a Junos set ate the closing bracket**, and a comma likewise.
- **A grant that could delete a unit could not create one.**
- **An empty quoted value was dropped**, shortening the path and changing which
  rule the policy matched.
- **Replies were never matched to requests.** `message-id` was written and never
  read, so any message on the channel was taken as the answer.
- **A document that was not an `<rpc-reply>` read as a successful one.**
- **An attribute on an XML tag protected the secret under it.**
- **A secret split across lines in XML went out whole.** Redaction works line by
  line, so a value on its own line between an opening and a closing tag had no
  statement name beside it, and only the `$9$` and key-blob heuristics could catch
  it. The state now follows a secret element across lines, as it already did for
  PEM blocks.
- **Two of the four timeouts were never validated.**
- **Four RFC deviations:** whitespace between messages was fatal, a chunk size of 0
  could be produced, `close()` did not wait for the reply, and `<session-id>` was
  dropped.
- **The floor compared case-sensitively.** Default-deny caught the difference, but
  a floor that holds only because another rule also happens to is not a floor.
- **`/* ... */` comment lines refused the whole payload** as an unknown verb.
- **Markup inside `<error-message>` destroyed the message.** The field being read
  was identified only by which field it was, not by which element opened it, so a
  nested tag cleared the text accumulated so far and its closing tag ended the
  field early. The device explained itself and the caller got `None`.
- **`<error-app-tag>` and `<error-info>` were parsed past** — and `<error-info>` is
  where Junos names the statement it actually objected to.

### Changed
- A doc comment claimed the drift check uses SHA-256. It does not, and never did:
  the check is a byte comparison of the diff strings.
- `MockTransport` lost a `closed` field that nothing read, kept alive only by a
  `let _ =` that silenced the warning about it.
- `ConnectOptions::host_key` documented `None` as enrollment mode, which
  `connect()` refuses: it authenticates, so it sends the password, and handing one
  to an unverified device is what pinning exists to prevent. The documentation now
  says what the code does and points at `observe_host_key`.
- `KNOWN_TOP_LEVEL_HIERARCHIES` read as though the engine consulted it. It does
  not — enforcement is default-deny — and it now says what it is for: telling «a
  hierarchy I did not grant» apart from «a hierarchy that does not exist», which
  default-deny cannot do on its own.
- The decoder clears its buffer instead of draining it when a message consumes all
  of it, which is the ordinary case in a request/response protocol.
- `NetconfError::Device` now carries a boxed `DeviceError`. Adding the two missing
  RFC fields made that variant the largest by a wide margin, and an unboxed one
  makes every `Result` in the crate carry its size on the success path too. The
  error is the cold path; the indirection costs nothing that matters.

## [0.5.5] — 2026-09-21 (preparing the crate to stand on its own)

The housekeeping below is what this entry was written to describe. It is not all
that 0.5.5 contains: the review fixes listed under 0.5.6 were finished and merged
before this version was cut, while they still sat under «Unreleased», and they
went out with it. So the sentence that used to stand here — no behaviour changes,
no change to the public API — was true of the housekeeping and untrue of the
release.

### Changed
- **`krypto` 0.6 → 0.7.** The dependency pointed at a version that no longer exists,
  so the manifest would not resolve at all: *«failed to select a version for the
  requirement `krypto = "^0.6"` … candidate versions found which didn't match:
  0.7.0»*.
- **The manifest describes the crate in English**, without an internal codename, and
  carries `keywords` and `categories` for the first time.
- **`authors` and the MIT copyright name the author personally**, not a company.
  `LICENSE-MIT` and `LICENSE-APACHE` are now byte-identical to the sibling crates'.
- **The documentation is English only.** Every document had a Norwegian and an English
  twin. The English ones were kept under the plain names and the Norwegian ones removed.
  The doc guard checked both and now checks the one.
- **The README says what the crate is for**: why the filter sits below the consumer
  rather than inside it, and who wrote what.
- **The test suite is in English** — comments, assertion messages and fifteen test
  names. No assertion changed, so the suite proves what it proved before: 118 tests.
  Test data that named an application or a real customer-ID format is now generic.
- **The test infrastructure too.** `mock.rs` and the twelve unit tests behind the
  `russh-transport` feature were still in Norwegian, names included. With the feature
  on the suite is 133 tests; without it, 119.
- **The source is English too** — all twelve modules, comments and all. The reasoning
  in them is the most valuable thing in the file, so it is translated rather than
  trimmed. Two user-facing strings were still Norwegian: the protocol errors for a
  chunk size and a message above the maximum.

### Added
- **A test for `commit_check`.** It was the one Junos helper with no test at all,
  and the RPC form is the whole of what it does: send the wrong element and the
  device either commits or validates nothing, while the caller is told neither.
  The test pins `<check/>` and that the request does not look like a commit.
- **Tests for what the errors say**, not only which variant they are. Coverage of
  `error.rs` was 27%: eight of the ten `Display` branches had never been rendered.
  A `Display` that dropped `offered` or `observed` — the two fields that exist so
  the operator has something to act on — was invisible to every test. Now 100%.
- **Tests for the fail-fast policy layer.** `prepare_change` refuses before the
  device is locked; `load_configuration` refuses again as defence in depth. The
  depth layer was covered, the first one only partly: neither «no policy bound»
  nor «raw XML without a deliberate all_free(Rwd)» was exercised there. Both are
  now, and both assert the device was never locked.
- **Tests for XML entity resolution on the way in.** Escaping outbound was covered;
  decoding inbound was not, and that is the direction that reads bytes from a device.
  It matters most in the compare diff, which is hashed to decide whether the
  candidate drifted: an entity resolved inconsistently would either refuse a sound
  change or accept an unsound one. The fail-closed branch for an unknown entity is
  covered too.

### Removed
- **`MockTransport::sent_snapshot`.** It was superseded by `recording()`, which hands
  back a shared handle to the same bytes before the transport is moved into a session.
  Nothing used the older one. Out of the crate and out of the contract.

### Removed
- **Notes about what had and had not been tried against real equipment**, in the README,
  the documents and the source, along with the `TODO(lab)` markers. They dated from
  before the crate stood on its own.

---

Releases before 0.5.5 are not in this file. They were written while the crate was being built
inside a larger private system, and they describe it: sibling services, internal documents,
case numbers from a tracker nobody outside can reach, and much of it in another language. Most
of it is noise to someone reading the crate, and the part that is not noise is already somewhere
better.

Dropping them lost no design reason. Those reasons live in the doc comments, where a reader
meets them next to the thing they explain — why the filter is default-deny and the floor holds
on its own, why a set payload is the only format it reads, why an unknown verb refuses the whole
payload, why the host key is pinned and observed on a path that takes no password. All of it is
in `src/`, stated more fully there than it ever was here.

0.5.5 is where the crate as it exists now begins: it is the release that prepared it to stand on
its own.
