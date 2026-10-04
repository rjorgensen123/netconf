# NETCONF

**In short:** a building block that talks to Juniper network equipment using **NETCONF over SSH** —
across both older and newer equipment generations. Think of it as the interpreter between your
program and the actual boxes in the network.

## Why does it exist?

Because talking to network equipment is easier said than done — and because the hard parts are not
where you expect them.

The command set itself is stable and well described. The problems live elsewhere: **old boxes
negotiate SSH differently from new ones**, and require algorithms modern libraries have stopped
offering. **The replies do not always follow the standard** — equipment omits fields, uses its own
namespaces, and sends warnings that look like errors. And **messages are split arbitrarily** by the
network, so a naive reader breaks on a message that arrived in two pieces.

The library gathers that knowledge in one place. The rest of the system can say "do this" without
knowing every quirk.

## What can you use it for?

| | |
|---|---|
| **Connect to a box and speak NETCONF** | handles the greeting, negotiation and message framing itself |
| **Fetch configuration or run a command** | and get the reply back as text |
| **Change configuration safely** | load, see what would actually change, approve, then commit |
| **Let the change roll back by itself** | the box reverts on its own if nobody confirms within the deadline |
| **Deny changes that are not allowed** | a filter that stops dangerous changes *before* they are sent — see **[The filter](Filter.md)** |
| **Hide secrets in what you fetch** | passwords and keys from the box are removed before they reach you, unless your policy asks for them |
| **Verify who you are talking to** | the box's identity can be pinned, so you notice if someone swaps it |
| **Test everything without equipment** | a simulated peer ships with the crate, so the protocol can be tested without a network |

**[How to use netconf](Usage.md)** shows how each of them is done, with examples.
**[API](API.md)** is the contract — the whole public surface, precise enough to reimplement from.

**[The filter](Filter.md)** is worth a read of its own. It is the built-in boundary for what can be
changed on a box at all — and probably the reason you want netconf instead of speaking NETCONF
yourself.

## What it does not do

Just as important as what it can:

- **It has no opinion about what you configure.** It does not know what a circuit or a customer is —
  it sends what you ask, and stops what you have told it to stop.
- **It is Juniper-specific for now — a deliberate boundary.** Juniper devices
  across the board (SRX/EX/MX/everything), Junos and Junos Evo, plus the simulated peer (`mock`) —
  that IS netconf today. No cross-vendor abstraction, no YANG modelling: such a layer costs more
  than it gives with one vendor. Should more vendors ever be needed, *extending netconf* is the
  likely road — future work, far ahead.
- **It does not decide your security policy.** It gives you the filter; which rules apply is your
  program's business.
- **It does not manage multiple boxes.** One session per connection, no pooling, no queue. That
  belongs in the layer above.
- **It does not use SSH keys.** Password authentication only, because access is per user against
  RADIUS or TACACS+.

## What it is built on

| Purpose | Standard |
|---|---|
| The protocol | [RFC 6241](https://www.rfc-editor.org/rfc/rfc6241) — NETCONF |
| Message framing | [RFC 6242](https://www.rfc-editor.org/rfc/rfc6242) — NETCONF over SSH |
| Transport | SSH (the `netconf` subsystem) |
| Secrets | [krypto](https://crates.io/crates/krypto) — device passwords never cross the API boundary as plain text |

**About `krypto`:** the library accepts device passwords **exclusively** as krypto's secret type.
That is not a recommendation, it is enforced by the type system — you *cannot* pass a password as
an ordinary string.

**About old equipment:** the outdated SSH algorithms that older boxes require are **not
forbidden** — the span we support requires them. But they are **visible**: the library can tell you
when one of them is in use, so you can log it. And the choice is made **per box**, never globally.

`#![forbid(unsafe_code)]` — the library contains zero `unsafe`.

## How it is meant to be used

The crate is a building block, not a service. It expects to sit underneath something that
owns the intent — a component that is the only one in its system allowed to reach network
equipment, and that hardcodes the policy it wants enforced.

That arrangement is the point. The consumer decides what is permitted once, in its own
source; everything it does afterwards is checked against that decision down here, where a
mistake further up cannot reach past it.

## Author

**Roger Jorgensen** — rogerj@gmail.com

Design, architecture and structure; the decision to put the filter below the consumer
rather than inside it, and what that has to guarantee to be worth anything; the contracts
the crate presents outwards; and the decisions about what it does and deliberately does
not do.

The code is written by Claude AI (Opus and Fable).

Reviewed independently by Fable, Opus and Gemini.

## License

Open source: **MIT / Apache-2.0** — your choice. Free to use and build on.
