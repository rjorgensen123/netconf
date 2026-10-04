# Contributing

## This repository is a mirror

The work happens elsewhere, and this repository is a copy that is pushed here. Every
sync overwrites what is here.

That has a consequence worth knowing before you spend time on it: **a pull request
opened here cannot be merged, and anything committed here is overwritten at the next
sync.** That is not a judgement on the change — the mechanism has nowhere to put it.

So if you have a change, it has to arrive in a form that survives the sync. An issue
with a description, a diff, or a patch works. A pull request does not.

## What is welcome

**Bug reports.** If something does not behave as the documentation says, or a
guarantee does not hold, open an issue. These get looked at first.

**Questions about the contract.** If the API documentation is unclear or wrong about
what a function does, that is worth an issue on its own — the docs are checked against
the code by a test, but a test cannot tell whether a sentence is *true*.

**Security findings.** Not as an issue — see [SECURITY.md](SECURITY.md), which also
says what a report must contain.

## Code and features

Neither is refused. Both are low priority.

**Code.** If you have written something, describe it in an issue and attach the diff.
It will be read. Whether it lands, and when, depends on whether it fits what the crate
is for — and on time, of which there is not much. Do not expect a quick answer, and do
not take silence as rejection.

Code is accepted only under the crate's own terms: MIT **or** Apache-2.0, at the
recipient's choice. See [Contributions](README.md#contributions) in the README for
what that means and why.

**Feature requests.** Possible, and worth asking about — but read what the crate is
deliberately not, in the README, before you write one. A YANG model layer and a
multi-vendor abstraction are not omissions waiting to be filled; they are the reason
the crate is small enough to reason about. Say what you are trying to do rather than
which function you want — the problem is easier to judge than the solution.

**One request will not be granted:** a way to relax the configuration filter from
outside. The filter is bound to the session, it is default-deny, and it has an absolute
floor that holds under every policy but `all_free` — the one policy that turns the
filter off, chosen out loud. That is the crate's whole reason for existing. A
consumer chooses what to permit by building a policy, never by getting around one.

## If you are filing an issue

Say which version. It is in `Cargo.toml`, and the crate exposes it.

Include what someone else needs to see the same thing: the calls you made, the XML in
and out if it is relevant, and the actual output or error. A failing test is the
clearest form there is.
