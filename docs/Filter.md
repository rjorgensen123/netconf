# The filter — what netconf will not let you do

**In short:** netconf has a built-in filter that decides what may be changed, read and run on a
device. It is not a warning you can click away. It is a boundary in the library, bound to the
session, and it is checked **before** anything is sent.

This is probably the reason you want netconf instead of speaking NETCONF yourself.

There are two filters:

- **the policy** — what may be **changed**, which configuration may be **read**, and which
  operational **commands** may run
- **the read filter** — which of the device's **secrets** are taken out of what comes back

## The problem it solves

Automation that can change anything is going to, one day. Not because anyone wants it to, but
because a payload was built wrong, a variable was empty, or someone tested against the wrong box.

The worst mistakes are silent, too. `delete interfaces` is a valid command. It does exactly what it
says. The box just is not reachable afterwards.

The filter makes that class of mistake **impossible** — no matter what the layer above decides to
send.

## The policy is bound to the session

A policy is bound once, with `session.set_policy(policy)`, and every typed helper on the session
enforces it itself. **A session with no policy bound permits nothing** — no read, no `show`, no
change — exactly as `ConfigPolicy::all_deny()`. The consumer decides what is permitted; until it
does, netconf does nothing on its behalf.

There are four kinds of policy:

| Policy | Permits |
|---|---|
| `ConfigPolicy::with_default_floor()` | the ordinary policy: reads and `show`, plus whatever you grant, under the floor. `ConfigPolicy::new(&[...])` is the same with a floor of your own |
| `ConfigPolicy::read_only()` | reads and `show`, and **no change and no other command, whatever is granted** — `allow_command` and change grants have no effect on it |
| `ConfigPolicy::all_free(access)` | the access level alone, on any path — no rules, no floor, nothing redacted. The filter is off, deliberately |
| `ConfigPolicy::all_deny()` | nothing at all — what a session without a policy has |

`all_free(Access::Rwd)` is the one policy with full control: it may delete anything, run any
command, and load formats the filter cannot read. Choose it deliberately, never as a shortcut
because a rule was hard to write.

The raw `session.rpc()` is the low-level layer and goes **around** the policy. It does not go
around the read filter.

## Changes: where × what

A policy is a list of rules. Each rule says: **at this place, these operations are allowed.**

```
   WHERE                              WHAT
   a path in the configuration   →    Op::Set · Op::Delete
```

**Everything not expressly allowed is denied.** That is not a setting; it is the starting point.

### Two ways to hit a place

A rule pattern is a path of words, where `*` matches any one word — `interfaces * unit *`. It
points at **the node itself** or at **everything below it**, and the difference is the whole point:

| `Match` | Means |
|---|---|
| `Match::Node` | exactly this node — a path of the same length |
| `Match::Subtree` | strictly below it — a longer path with the same beginning |

So a rule that allows deletion *below* a protocol does **not** allow deleting the protocol. You can
clean up inside, but not rip out. That granularity is what lets a filter be useful and safe at the
same time.

```rust
let policy = ConfigPolicy::with_default_floor()
    .allow("interfaces * unit *", Match::Subtree, &[Op::Set, Op::Delete]);
```

### Ready-made scopes

You do not need to write paths for the common cases. `grant(scope, access)` adds the rules for a
named place:

| `Scope` | Rules |
|---|---|
| `LogicalUnits` | `interfaces * unit *` and everything below it. A bare unit can be created; with `Rwd` the unit itself can be deleted too |
| `InterfaceDescriptions` | `interfaces * description` and `interfaces * unit * description` — set and, with `Rwd`, delete |
| `Protocols` | everything below `protocols *` — never the protocol node itself, which other services share |

| `Access` | Grants |
|---|---|
| `Ro` | no change at all — reading is governed separately, see below |
| `Rw` | `Op::Set` |
| `Rwd` | `Op::Set` and `Op::Delete` |

### Every verb has a class

Every Junos set-format verb is known and classified, verified against both classic Junos and Evo:

| Class | Verbs |
|---|---|
| `Op::Set` | `set`, `insert`, `copy`, `replace`, `annotate`, `activate`, `protect` |
| `Op::Delete` | `delete`, `wildcard delete`, `deactivate`, `unprotect`, `rename` |

`deactivate` counts as deletion, since it removes the effect, and `unprotect` too, since it is the
precondition for deleting something protected.

`rename <path> to <name>` deletes its source and writes its target; `copy <path> to <name>` writes
its target. The words after `to` replace as many words at the end of the path:
`rename interfaces ge-0/0/0 unit 0 to unit 1` writes `interfaces ge-0/0/0 unit 1`. Neither may
write a target that is there already: before the payload is sent, the candidate configuration is
read, and a target found there — or written by an earlier line of the same payload — refuses the
whole payload. A rename or a copy creates; it does not overwrite.

`edit`, `top`, `up` and `exit` are not verbs here. They move the context the following lines are
read in, and the filter reads every line as a full path. Write every line with its full path.

## The floor — what no rule can allow

Under `with_default_floor()` and `read_only()`, **an entire protected top-level tree cannot be
deleted**, whatever the rules grant. `delete system`, `delete interfaces`, `delete protocols` and
the like are refused — in any case, `delete System` too — and so are `deactivate`, `rename` and
`wildcard delete <tree> *` of the tree. The floor exists because precisely those commands make a
box unreachable or unmanageable in one second.

The protected trees are the public constant `netconf::policy::DEFAULT_PROTECTED_ROOTS`:

`system`, `interfaces`, `chassis`, `vmhost`, `protocols`, `routing-options`, `routing-instances`,
`security`, `groups`, `apply-groups`, `class-of-service`, `policy-options`, `firewall`, `snmp`,
`services`, `forwarding-options`, `vlans`, `bridge-domains`, `access`, `logical-systems`,
`tenants`, `virtual-chassis`, `multi-chassis`, `fabric`, `dynamic-profiles`,
`accounting-options`

**Logical systems and tenants** hold a configuration of the same kind as the top level. Under
`logical-systems <name>` and `tenants <name>`, the system itself cannot be deleted or emptied with
`*`, and what stands under it is judged as it would be at the top level — by the floor, by the
rules and by the read grants. `delete logical-systems LS1 protocols` is refused as
`delete protocols` is.

**Note what the floor is *not*:**

- **Changes are not blocked.** You can modify below `system` if your policy allows it. The floor is
  about ripping out whole trees, not about touching them.
- **Deleting an individual interface is not blocked.** Physical interfaces and `irb` can be
  deleted — that is often exactly what you want. `lo0` deserves caution, but is not absolutely
  protected.

The principle is deliberate: **do not make the library useless.** Only what makes the box
unmanageable is hard-blocked. The rest is kept safe by everything else being denied by default.

`all_free` has no floor. It is the one policy for deleting everything on the box — the deliberate
choice of full control, not something a rule adds up to.

## What the filter can read

**Only set format is checked.** A `Format::Set` payload is parsed, and every line is checked
against the policy before anything is sent. `Format::Text` and `Format::Xml` cannot be read into
changes, so they are refused unless the policy is `all_free(Rwd)`. `rollback(n)` with `n > 0` loads
a previous configuration whole, which the filter cannot read either, and has the same rule;
`rollback(0)` discards the candidate's changes and changes nothing.

**A policy that can change nothing commits nothing.** `load_configuration`, `prepare_change`,
`commit` and `commit_confirmed` are refused before anything is sent under a policy with no change
grant — `read_only`, `all_free(Ro)`, or rules that permit no operation.

### Unknown input is rejected — the whole payload

If the parser meets any of these, **the whole payload is rejected**, not just the line:

- a verb it does not know — `edit` included
- a line with no path after the verb
- an unbalanced quote
- a `'` outside a quoted string
- a `/*` comment outside a quoted string
- a control character other than a tab, or the Unicode line and paragraph separators U+2028 and
  U+2029

A line ends with a newline, or with a carriage return and a newline. A carriage return anywhere
else is refused, because the box reads it as a line break and the filter would not: the line after
it would reach the box unchecked. NUL, vertical tab, form feed and the other control characters are
refused too. A tab is whitespace, and passes.

Only `"` quotes a value, and `\"` inside a string is a quote that does not close it. A `'` is
refused rather than read as text, because read as text it splits `'a b c'` into three tokens and
the policy decides on a path nobody wrote. Inside a `"…"` string it is an ordinary character, so
`"Roger's link"` works as it should.

A `#` outside a quoted string makes the rest of its line a comment, and a line that begins with `#`
is a comment whole. The payload is sent **without** its comments, so the device reads exactly what
the policy judged.

That sounds strict, and it is meant to. The alternative is skipping the line you did not
understand — and then it goes **unchecked** to the box. That is not a gap in the filter; it is the
road around it.

### Case — lowercase verbs, and paths as written

**Verbs are lowercase only.** `SET` is not a verb the filter knows, so the whole payload is
rejected, and the refusal says that `SET` is not `set`.

**Paths are compared exactly, case included.** Junos names are case-sensitive: `policy-statement
EXPORT` and `policy-statement export` are two different things, and a rule for one must not let the
other through. When a path is refused and the same path in lowercase would have been allowed, the
refusal says so — the hint allows nothing.

The floor is the one exception: it ignores case, so `delete System` is refused by the floor
itself, not just because no rule happens to allow it.

## Reading configuration

**Reading is open — except the sensitive trees.** These carry the box's authentication secrets and
key material, and reading them requires an explicit grant, `allow_read(tree)`:

`system`, `security`, `access`, `groups`, `apply-groups`, `event-options`

They are the public constant `netconf::policy::SENSITIVE_READ_ROOTS`. Reading the **whole**
configuration includes them, and so requires a grant on every one.

The gate applies to `get_configuration` and to configuration read through a command:

- **`get_configuration(Some(filter))`** — the filter is XML, read strictly: elements, attributes
  and text only; no declaration, doctype, processing instruction, comment or CDATA; every element
  closed. Every element name in it, nested ones included, is checked exactly, and what goes to the
  device is written out from what was read, so the gate and the device cannot disagree about it.
  `None` is the whole configuration.
- **`show configuration <tree>`** and **`show ephemeral-configuration [instance <name>] [merge]
  <tree>`** — the first word of the path is the tree. Junos abbreviations are honoured on the
  refusing side, so `show conf sys` is a read of `system`.
- **`show system rollback <n>`** shows a previous configuration whole, and is a read of the whole
  configuration.

Under `all_free` every read is open.

## Operational commands

**By default, only `show`.** An ordinary `show` runs under the device user's own authorization on
the box — the login class from RADIUS or TACACS+ — and netconf does not try to replicate that.
Everything else (`request`, `clear`, `restart`, …) changes state and is refused unless the policy
grants it:

```rust
let policy = ConfigPolicy::with_default_floor().allow_command("request system storage cleanup");
```

A grant is a prefix of whole words, compared as written. An empty grant grants nothing.
`read_only` refuses every command but `show` whatever is granted; `all_free(Rwd)` runs every
command.

What a command must look like:

- **One line of printable ASCII.** A tab is allowed; any other control character, and anything
  outside ASCII, refuses the command.
- **Keywords as the device reads them** — lowercase and unabbreviated. `SHOW` and `sh` are refused.
- **Quotes only in a pipe's pattern**, as in `| match "ge|xe"`. A `|` inside a quoted string does not
  split the command, and a quote that does not close refuses it.
- **Pipes only on `show`, and only read-only ones:** `compare`, `count`, `display`, `except`, `find`,
  `last`, `match`, `no-more`, `resolve`, `trim` — lowercase, the public constant
  `netconf::policy::READ_ONLY_PIPES`. `save`, `append` and `tee` write files on the device,
  `request` messages its users, `hold` and `refresh` keep the command running; those, and anything
  not on the list, are refused. `| compare` may name a rollback and nothing else: `| compare` or
  `| compare rollback <n>`.

## The read filter — secrets in what you fetch

The policy governs what you may **change**. The read filter governs what is safe to **show**.

Configuration from a box carries the box's own secrets, and they end up in a diff, in a log, in a
backup. **The session redacts them in everything it returns:** `show` output, configuration, the
compare diff, the raw `rpc` reply, the device's hello, and the device's text in an error — what it
wrote in an `<rpc-error>`, what it said over SSH, a message cut short. Each secret is replaced by a
marker that says what was there and how to read it:

```text
encrypted-password [SENSITIVE: hidden by netconf — allow_secrets() on the policy shows it]; ## SECRET-DATA
```

The marker is the public constant `netconf::REDACTED`. To read the secrets themselves, the policy
has to say so — `allow_secrets()` — and `all_free` redacts nothing. A session with no policy bound
redacts.

**The structure stays.** The redaction replaces the value, never the structure: the line count,
the indentation and the line endings, the statement name, `;`, the braces, the `[edit …]` banners,
the diff markers and the `## SECRET-DATA` annotation are all kept. A redacted diff is still readable
as a diff — you can see *which* field changed, not what it changed to. In doubt it redacts too much
rather than too little.

### What is taken out

- **the statements that carry a secret** — the list below — in set format, in text format and in
  XML
- **hashed and obfuscated values** — `$9$…`, `$8$…`, `$6$…`, `$5$…`, `$1$…`, `$0$…`, `$2a$…`,
  `$sha1$…`, wherever they stand. Standing alone, the value goes and the `$tag$` stays, so you can
  see which form it is. The `$junos-…` variables of dynamic profiles are not matched.
- **certificates and private keys** — PEM blocks, across lines. The `-----BEGIN …-----` and
  `-----END …-----` markers stay; the body goes.
- **SSH key blobs** — base64 that begins as an SSH public key does, whatever statement it is under
- **the password in a URL** — `scp://user:password@host/path`. The user, the host and the path stay.
- **anything Junos marks `## SECRET-DATA`** (or `/* SECRET-DATA */`) — a safety net that catches a
  secret leaf even when the list does not know it

The text is read as XML writes it: an entity is read as the character it stands for, so
`&#x24;9&#x24;` is a `$9$`; a statement name glued to punctuation or a control character is still
the name; an element is read by its local name, with any namespace prefix and attributes, and a
value that runs over several lines is redacted on all of them. A secret in a comment, in a CDATA
section or in text that came from `&lt;…&gt;` is read like any other text, and text that looks like
the marker gets no pass. Text the filter does not touch goes out exactly as it came in, and a second
pass over the filter's output changes nothing.

### The statements that carry a secret

A statement is redacted by its exact name, from the list below, and only where Junos keeps a
secret in it: a word that merely holds `key`, `secret` or `password` is none of them. Where the
name alone does not say it, its context does — the words before it on the line in set format, the
blocks it is inside in text format (or the `[edit …]` banner of a compare diff), and its parent
element in XML. From the statement on, the rest of the line goes, up to a Junos annotation.

| Statement | Context | Where Junos has it |
|---|---|---|
| `encrypted-password` | any | `system root-authentication`, `system login user U authentication` |
| `plain-text-password-value` | any | the same, as a value given in cleartext |
| `authentication-key` | any | `protocols bgp`, `ospf`, `isis`, `rip`, `ldp`, `rsvp`, `msdp`; `vrrp-group`; `snmp v3 usm … authentication-md5/-sha`; `system ntp authentication-key N` |
| `hello-authentication-key` | any | `protocols isis … level N` |
| `simple-password` | any | `protocols ospf … authentication` |
| `key` | after `md5 N` | `protocols ospf … authentication md5 N key` |
| `key` | after `authentication` or `encryption` | the manual key of an IPsec security association |
| `ascii-text`, `hexadecimal` | after `pre-shared-key` or `key` | the form a pre-shared or manual key is given in |
| `value` | after `authentication-key N` (and `type T`) | `system ntp authentication-key N type T value` |
| `pre-shared-key` | any | `security ike policy`, `services ipsec-vpn ike policy`, `security macsec connectivity-association` |
| `cak` | any | `security macsec … pre-shared-key cak` |
| `secret` | any | `system radius-server`, `tacplus-server`, `accounting destination … server`; `access radius-server`, `access profile … radius-server`; `security authentication-key-chains key-chain K key N`; `system services outbound-ssh client` |
| `chap-secret`, `pap-password` | any | `access profile P client C` |
| `default-chap-secret`, `local-password`, `default-pap-password` | any | `ppp-options chap` and `pap` on an interface |
| `passphrase` | any | `event-options policy P then event-script F remote-execution remote-hostname H` |
| `shared-secret` | any | L2TP, `access profile P client C l2tp` |
| `authentication-password`, `privacy-key`, `privacy-password` | any | `snmp v3 usm … user U` |
| `password` | after `firewall-user`, `admin-search` or `authentication` | `access profile … firewall-user`, `ldap-options search admin-search`, `dhcp-relay authentication` |
| `password` | after `proxy`, or `client` with or without its name | `system proxy`, `system services dynamic-dns client H`, `security ike gateway G aaa client` |
| `password` | after `archive-sites <url>` or `url <url>` | `system archival configuration archive-sites`, `event-options destinations`, a URL with a password beside it |
| `challenge-password` | any | a certificate enrollment |
| `token`, `api-token`, `bearer-token`, `access-token`, `auth-token`, `authentication-token`, `refresh-token`, `oauth-token` | any | a token that authenticates to a service; `authentication-token` under `services security-intelligence url`. A name that merely holds `token`, `token-bucket`, is none of them |
| `community`, `community-name` | not under `policy-options` | `snmp community`, `snmp v3 snmp-community`; only with `Redactor::strict()` |

These look like secrets and are not, and go out as they came in: `community` (an SNMP v2c community),
`hash-key`, the name of a `key-chain` and the `key N` index in it, `authentication-key-chain`,
`load-key-file`, `license keys`, a host key, `key-exchange`, `hostkey-algorithm`, `key-type`,
`authentication-order`, `authentication-method pre-shared-keys`, `system login password`, which is
the password policy, and `system master-password`, a container for how the master password is used.

The public keys under `system login user U authentication ssh-rsa` (and `ssh-dss`, `ssh-ecdsa`,
`ssh-ed25519`) are not on the list. The key-blob rule still takes the base64 blob out of them, and
where Junos marks them `## SECRET-DATA` in text format, the net takes their value there.

> **The SNMP v2c community stays readable.** That is a deliberate choice: a v2c community is never
> encrypted on the wire, and hiding it would be false safety for something that is a shared secret
> among the people who run the network anyway. The session always reads with this default. For text
> you hold yourself, `Redactor::strict()` hides the community as well; a BGP community under
> `policy-options` is never touched.

### The read filter and the drift guard

`prepare_change` returns the diff as the policy lets it through, and `confirm_commit` commits only
if the device still shows the same diff. The comparison is made on the diff **as the device wrote
it**, so a change inside a value the policy redacts is still caught, even though both diffs show the
same marker. See [Usage](Usage.md#changing-configuration-safely).

## Who sets the policy

netconf gives you **the mechanism** — the model, the enforcement, the floor and the read filter.
Which rules apply is your program's business.

That is deliberate: a library that decided your policy would be useless to anyone with a slightly
different need. And a policy that could be changed from outside would not be a boundary.

**The filter answers for itself.** A policy can be read back — `rules()`, `protected_roots()`,
`read_allows()`, `command_allows()`, `all_free_access()`, `secrets_allowed()` — and `describe()`
gives a human-readable summary for a log or an operator:

```text
secrets: redacted — allow_secrets() lets them through
allow [Set, Delete] at "interfaces * unit *" (Subtree)
allow [Set] at "interfaces * unit *" (Node)
allow [Delete] at "interfaces * unit *" (Node)
floor: delete of 26 protected top-level trees is always denied
```

So a consumer with a dynamic rule system can pick a policy per task and still show what applies —
the crate answers that question about itself rather than asking you to trust a document.
