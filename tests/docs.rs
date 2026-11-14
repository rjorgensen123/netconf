// SPDX-License-Identifier: MIT OR Apache-2.0
//! Doc guard (0.5.1): the public functions, constants, types, traits and modules
//! the test finds in the crate's sources must appear by name in the shipped
//! contract doc (`docs/API.md`); enum variants, fields and trait methods are not
//! collected.
//! A surface change that skips the docs fails `cargo test` — the same fence
//! `tests/version.rs` puts around the changelog.
//!
//! The contract doc is the crate's own; nothing outside it is checked from here.

use std::collections::BTreeSet;
use std::fs;

fn read(rel: &str) -> String {
    fs::read_to_string(format!("{}/{rel}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

fn ident_prefix(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// Every root re-export/const/module, and every `pub fn/const/struct/enum/
/// trait/type` in the public modules.
fn pub_names() -> BTreeSet<String> {
    let mut names = BTreeSet::new();

    let lib = read("src/lib.rs");
    let mut rest = lib.as_str();
    while let Some(i) = rest.find("pub use ") {
        rest = &rest[i + 8..];
        let (Some(open), Some(close)) = (rest.find('{'), rest.find('}')) else {
            break;
        };
        if open < close {
            for n in rest[open + 1..close].split(',') {
                let n = n.trim();
                if !n.is_empty() {
                    names.insert(n.to_string());
                }
            }
        }
        rest = &rest[close..];
    }
    for line in lib.lines() {
        let l = line.trim_start();
        for p in ["pub mod ", "pub const "] {
            if let Some(r) = l.strip_prefix(p) {
                names.insert(ident_prefix(r));
            }
        }
    }

    for f in [
        "change.rs",
        "error.rs",
        "framing.rs",
        "junos.rs",
        "mock.rs",
        "policy.rs",
        "redact.rs",
        "rpc.rs",
        "russh_transport.rs",
        "session.rs",
        "transport.rs",
    ] {
        let t = read(&format!("src/{f}"));
        for line in t.lines() {
            let l = line.trim_start();
            // `pub const fn ` stands before `pub const `, and the first prefix that
            // matches is the only one read, so a const fn gives its own name.
            for p in [
                "pub fn ",
                "pub async fn ",
                "pub const fn ",
                "pub const ",
                "pub struct ",
                "pub enum ",
                "pub trait ",
                "pub type ",
            ] {
                if let Some(r) = l.strip_prefix(p) {
                    let name = ident_prefix(r);
                    if !name.is_empty() {
                        names.insert(name);
                    }
                    break;
                }
            }
        }
    }
    names
}

#[test]
fn every_public_name_is_in_the_contract_docs() {
    let names = pub_names();
    assert!(
        names.len() >= 100,
        "the extractor found suspiciously few names ({}) — is it broken?",
        names.len()
    );
    // The session's requests are `pub async fn`, and `all_deny` is a `pub const fn`;
    // both kinds must be collected by their names.
    for function in [
        "prepare_change",
        "confirm_commit",
        "commit_confirmed",
        "observe_host_key",
        "all_deny",
    ] {
        assert!(
            names.contains(function),
            "the extractor did not collect the function {function} — is it broken?"
        );
    }
    // One document, so no loop: clippy rejects a for-loop over a single element,
    // and that lint has broken this crate's CI before.
    let doc = "docs/API.md";
    let text = read(doc);
    let missing: Vec<&String> = names
        .iter()
        .filter(|n| !text.contains(n.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "{doc} does not mention these public names: {missing:?} — \
         the contract doc must follow the surface"
    );
}
