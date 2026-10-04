// SPDX-License-Identifier: MIT OR Apache-2.0
//! Version guard. The version lives in ONE place, `Cargo.toml`; everything else
//! that states it is derived from there, so there is nothing to keep in step by
//! hand. What is checked here is the one thing that cannot be derived: that the
//! changelog has an entry for the version being built.

#[test]
fn changelog_has_an_entry_for_the_current_version() {
    let changelog = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/CHANGELOG.md"))
        .expect("CHANGELOG.md must exist");
    let heading = format!("## [{}]", env!("CARGO_PKG_VERSION"));
    assert!(
        changelog.contains(&heading),
        "CHANGELOG.md has no «{heading}» entry"
    );
}

/// 0.5.1: the `VERSION` constant must mirror Cargo.toml (the About anchor —
/// and the anchor that says which filter/feature set is active).
#[test]
fn version_constant_mirrors_cargo_toml() {
    assert_eq!(netconf::VERSION, env!("CARGO_PKG_VERSION"));
}
