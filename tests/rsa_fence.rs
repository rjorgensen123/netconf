// SPDX-License-Identifier: MIT OR Apache-2.0
//! The RSA fence: the `rsa` crate is in the tree ONLY transitively, through
//! russh's host-key support. The tests below fail the build if that changes —
//! and the failure messages carry the whole reasoning, so whoever hits the fence
//! in two years does not have to dig through history to understand why.

/// The entire explanation — one source, used by both tests.
const WHY: &str = "\n\
    ── WHY THIS TEST IS FAILING ────────────────────────────────────────────────\n\
    The `rsa` crate has a KNOWN, UNFIXED vulnerability: RUSTSEC-2023-0071,\n\
    «Marvin» — a timing side channel in RSA PRIVATE KEY operations (decryption\n\
    and signing). An attacker who can send many chosen ciphertexts and measure\n\
    the response time precisely can reconstruct plaintext step by step. The fix\n\
    requires rewriting the crate in constant time, and has not arrived in years.\n\
    \n\
    We have considered and ACCEPTED that the crate sits in the dependency tree\n\
    (see .cargo/audit.toml) — but that assessment rests on ONE premise:\n\
    \n\
        WE NEVER PERFORM RSA PRIVATE KEY OPERATIONS.\n\
    \n\
    Today `rsa` enters only through russh's support for RSA HOST KEYS, where we\n\
    do nothing but VERIFY the device's signature — a pure public-key operation,\n\
    with no secret to leak. Marvin is therefore out of reach here.\n\
    \n\
    This test failed because something now USES rsa directly — and at that point\n\
    the assessment no longer holds: a single RSA decryption or signature with a\n\
    private key turns Marvin into a real attack against us.\n\
    \n\
    DO THIS — do NOT delete the test:\n\
      1. Find out why rsa came into use. Is it genuinely needed? (Our own\n\
         signatures are Ed25519 through `krypto` — use those.)\n\
      2. If rsa MUST be used: redo the Marvin assessment, write it down in\n\
         .cargo/audit.toml, and update this fence deliberately.\n\
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
