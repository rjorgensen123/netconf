// SPDX-License-Identifier: MIT OR Apache-2.0
//! The RSA fence: the `rsa` crate is in the tree ONLY transitively, through
//! russh's host-key support. The tests below fail the build if that changes —
//! and the failure messages carry the whole reasoning, so whoever hits the fence
//! in two years does not have to dig through history to understand why.

/// The entire explanation — one source, used by both tests.
const WHY: &str = "\n\
    ── WHY THIS TEST IS FAILING ────────────────────────────────────────────────\n\
    netconf has no use for RSA of its own. The `rsa` crate is in the tree only\n\
    through russh's support for RSA HOST KEYS, where the device's signature is\n\
    VERIFIED — a public-key operation. The crate holds no RSA private key and\n\
    performs no RSA private-key operation; its own authentication is the device\n\
    password.\n\
    \n\
    This test failed because something now USES rsa directly.\n\
    \n\
    DO THIS — do NOT delete the test:\n\
      1. Find out why rsa came into use. Is it genuinely needed?\n\
      2. If rsa MUST be used: say so in DEVELOPMENT.md, where this constraint is\n\
         written down, and update this fence deliberately.\n\
    ────────────────────────────────────────────────────────────────────────────";

#[test]
fn rsa_is_never_a_direct_dependency() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("Cargo.toml must exist");
    for line in manifest.lines() {
        let l = line.trim_start();
        assert!(
            !(l.starts_with("rsa ") || l.starts_with("rsa=")),
            "`rsa` has become a DIRECT dependency in Cargo.toml.{WHY}"
        );
    }
}

#[test]
fn our_own_code_never_calls_rsa() {
    let src = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut stack = vec![src.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src/ must be readable") {
            let p = entry.expect("entry").path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") {
                let code = std::fs::read_to_string(&p).expect("readable file");
                assert!(
                    !code.contains("use rsa") && !code.contains("rsa::"),
                    "{} uses the `rsa` crate directly.{WHY}",
                    p.display()
                );
            }
        }
    }
}
