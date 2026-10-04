# The filter — what netconf will not let you do

**In short:** netconf has a built-in filter that decides what can be changed on a box at all. It is
not a warning you can click away — it is a boundary in the library, and it is checked **before**
anything is sent.

This is probably the reason you want netconf instead of speaking NETCONF yourself.


> **0.4.0:** the policy is bound to the session (`set_policy`) and enforced **inside the
> library** — with no policy bound, nothing is permitted (default-deny; since 0.5.11 not a read
> or a `show` either, exactly as `all_deny`). And the filter can
> **answer for itself**: `rules()`/`protected_roots()`/`all_free_access()` give structured
> reads, `describe()` a human-readable summary — so a dynamic rule system in the consumer can
> pick a filter per task and still show what applies.

## The problem it solves

Automation that can change anything is going to, one day. Not because anyone wants it to, but
because a payload was built wrong, a variable was empty, or someone tested against the wrong box.

The worst mistakes are silent, too. `delete interfaces` is a valid command. It does exactly what it
says. The box just is not reachable afterwards.

The filter makes that class of mistake **impossible** — no matter what the layer above decides to
send.

## The model: where × what

A policy is a list of rules. Each rule says: **at this place, these operations are allowed.**

```
   WHERE                              WHAT
   a path in the configuration   →    read · modify · delete
```

**Everything not expressly allowed is denied.** That is not a setting; it is the starting point.

### Two ways to hit a place

Paths can point at **the node itself** or at **everything below it**, and the difference is the
whole point:

| | Means |
|---|---|
| `self` | exactly this node |
| `subtree` | everything below it |

So a rule that allows deletion *below* a protocol does **not** allow deleting the protocol. You can
clean up inside, but not rip out. That granularity is what lets a filter be useful and safe at the
same time.

### Ready-made levels

You do not need to write paths for the common cases:

| Level | Gives |
|---|---|
| **Ro** | read |
| **Rw** | read and modify |
| **Rwd** | read, modify and delete |

combined with named areas — logical units, protocols, interface descriptions.

## The floor — what no rule can allow

`all_free` may delete anything, a top-level tree included; the floor holds for every other policy:
**there, an entire top-level tree cannot be deleted.**

`all_free` is the one policy for deleting everything on the box — the deliberate choice of full
control, not something a rule adds up to. Under every other policy, `delete system`,
`delete interfaces`, `delete protocols` and the like are denied, in any case — `delete System`
too — whatever the rules grant. The floor exists because precisely those commands make a box
unreachable or unmanageable in one second.

**Note what the floor is *not*:**

- **Changes are not blocked.** You can modify below `system` if your policy allows it. The floor is
  about ripping out whole trees, not about touching them.
- **Deleting an individual interface is not blocked.** Physical interfaces and `irb` can be
  deleted — that is often exactly what you want. `lo0` deserves caution, but is not absolutely
  protected.

The principle is deliberate: **do not make the library useless.** Only what makes the box
unmanageable is hard-blocked. The rest is kept safe by everything else being denied by default.

## Unknown commands are rejected — the whole payload

If the filter meets a verb it does not know, a `/*` comment outside a quoted string, an empty path, an unbalanced quote, a single
quote outside a string, or a control character other than a tab, **the whole payload is rejected**. Not just that line.

A line ends with a newline, or with a carriage return and a newline. A carriage return anywhere
else is refused, because the box reads it as a line break and the filter would not: the line
after it would reach the box unchecked. NUL, vertical tab, form feed and the other control
characters are refused too. A tab is whitespace, and passes.

Only `"` quotes a value. A `'` is refused rather than read as text, because read as text it
splits `'a b c'` into three tokens and the policy decides on a path nobody wrote. Inside a
`"…"` string it is an ordinary character, so `"Roger's link"` works as it should.

That sounds strict, and it is meant to. The alternative is skipping the line you did not
understand — and then it goes **unchecked** to the box. That is not a gap in the filter; it is the
road around it.

All Junos set-format verbs are known and classified, verified against both classic Junos and Evo.
`deactivate` counts as deletion (it removes the effect), and `unprotect` likewise (it is the
precondition for deleting something protected). `rename` counts as deleting its source and writing its target,
and `copy` as writing its target; neither may write a target that is there already, which is
checked on the box before the line is sent (0.5.13).

## Case — lowercase verbs, and paths as written

**Verbs are lowercase only.** `SET` is not a verb the filter knows, so the whole payload is
rejected, and the refusal says that `SET` is not `set`.

**Paths are compared exactly, case included.** Junos names are case-sensitive: `policy-statement
EXPORT` and `policy-statement export` are two different things, and a rule for one must not let the
other through. When a path is refused and the same path in lowercase would have been allowed, the
refusal says so — the hint allows nothing.

The floor is the one exception: it ignores case, so `delete System` is refused by the floor
itself, not just because no rule happens to allow it.

## The read filter — secrets in what you fetch

The filter above governs what you may **change**. There is another for what is safe to **show**.

Configuration from a box carries the box's own secrets, and they end up in a diff, in a log, in a
backup. The read filter removes them:

- obfuscated password hashes and encrypted passwords
- authentication keys, key-chain secrets
- RADIUS, TACACS and access secrets
- IKE/IPsec pre-shared keys
- certificates and private keys, including multi-line PEM blocks
- SSH keys and base64 blobs
- SNMPv3 auth and privacy keys
- hashes such as `$sha1$` (0.5.13), and the password in a URL like `scp://user:password@host`
  (0.5.13)

And a safety net: Junos itself marks hidden values, and those are caught even when we do not know
the field beforehand.

Some ways of writing a secret that hid it from the filter no longer do (0.5.13): an XML entity is
read as the character it stands for, a name glued to a control character or punctuation is still
the name, and a secret element with attributes is read whatever line its value is on, its start
tag cut by the line end too. Markup is read only as XML writes it, so a secret in a comment, in a
CDATA section or in text that came from `&lt;…&gt;` is read like any other text. Text that looks
like the marker gets no pass. Text with no statement from the list below, no hash, no key blob, no
PEM block, no password in a URL and no `SECRET-DATA` mark goes out as it came in, and a second
pass over the filter's output changes nothing.

### The statements that carry a secret (0.5.13)

A statement is redacted by its exact name, from the list below, and only where Junos keeps a
secret in it: a word that merely holds `key`, `secret` or `password` is none of them. Where the
name alone does not say it, its context does — the words before it on the line in set format, the
blocks it is inside in text format (or the `[edit …]` banner of a compare diff), and its parent
element in XML. From the statement on, the rest of the line goes, as before.

In text format Junos marks these leaves itself with `## SECRET-DATA`, and the filter reads that
mark as a net under the list: a leaf the list does not know is caught there. In set format and in
XML there is no mark, so the list carries it; a value Junos shows encrypted (`$9$…`) or hashed
(`$1$`, `$5$`, `$6$`, `$8$`, `$sha1$`) is caught by the hash rule wherever it stands.

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
| `community`, `community-name` | not under `policy-options` | `snmp community`, `snmp v3 snmp-community`; only under `strict()` |

These look like secrets and are not, and go out as they came in: `community` (an SNMP v2c community,
by default), `hash-key`, the name of a `key-chain` and the `key N` index in it,
`authentication-key-chain`, `load-key-file`, `license keys`, a host key, `key-exchange`,
`hostkey-algorithm`, `key-type`, `authentication-order`, `authentication-method pre-shared-keys`,
`system login password`, which is the password policy, and `system master-password`, a container
for how the master password is used.

The public keys under `system login user U authentication ssh-rsa` (and `ssh-dss`, `ssh-ecdsa`,
`ssh-ed25519`) are not on the list. The key-blob net still takes the base64 blob out of them, and
where Junos marks them `## SECRET-DATA` in text format, the net takes their value there.

> **The SNMP v2c community stays readable.** That is a deliberate choice: a v2c community is never
> encrypted, and hiding it would be false safety for something that is a shared secret anyway. If
> you need it hidden regardless, a stricter mode exists.

**The redaction is applied to everything netconf returns** (0.5.11): `show` output, configuration,
the compare diff — and the box's text in an error, the hello, what it said over SSH, and russh's
own text (0.5.13). The filter decides, both ways: the box's error text is redacted under a
policy that redacts, and let through under one that lets secrets through. Each secret is replaced by a marker that says what was there and how to read it.
To read the secrets themselves, the policy has to say so — `allow_secrets()` — and `all_free`
redacts nothing. The guard against someone else having been on the box between approval and
execution still works: a fresh diff under the same policy reads the same way as the approved one.

## Who sets the policy

netconf gives you **the mechanism** — the model, the enforcement, the floor and the read filter.
Which rules apply is your program's business.

That is deliberate: a library that decided your policy would be useless to anyone with a slightly
different need. And a policy that could be changed from outside would not be a boundary.

*The complete list of protected trees is the public constant `DEFAULT_PROTECTED_ROOTS`,
and a policy will tell you its own floor through `protected_roots()` — the crate answers
that question about itself rather than asking you to trust a document.*
