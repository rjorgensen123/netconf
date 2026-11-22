// SPDX-License-Identifier: MIT OR Apache-2.0
//! Third-party guard.
//!
//! `THIRD_PARTY_LICENSES.md` lists every package in `Cargo.lock` other than
//! `netconf` itself, each with the license it declares. A dependency added
//! without a row, a row left behind for a dependency that is gone, and a row
//! without a license all fail here. The published crate carries both files, so
//! nothing here is skipped.

use std::collections::BTreeSet;
use std::fs;

const DOCUMENT: &str = "THIRD_PARTY_LICENSES.md";
const RUST_SECTION: &str = "Rust crates";
const OWN_PACKAGE: &str = "netconf";

fn read(rel: &str) -> String {
    fs::read_to_string(format!("{}/{rel}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// The table rows, as cells, under `## <title>` in the document; the header
/// row and the separator row are left out.
fn rows(title: &str) -> Vec<Vec<String>> {
    let text = read(DOCUMENT);
    let body = text
        .split("\n## ")
        .find_map(|part| part.strip_prefix(&format!("{title}\n")))
        .unwrap_or_else(|| panic!("{DOCUMENT} has no section '## {title}'"));
    let rows: Vec<Vec<String>> = body
        .lines()
        .filter(|line| line.starts_with('|'))
        .filter(|line| !line.chars().all(|c| matches!(c, '|' | '-' | ':' | ' ')))
        .map(|line| {
            line.trim()
                .trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().to_string())
                .collect()
        })
        .skip(1)
        .collect();
    assert!(
        !rows.is_empty(),
        "the section '## {title}' in {DOCUMENT} has no table rows"
    );
    rows
}

/// The first cell of each row: the crate name.
fn listed(title: &str) -> BTreeSet<String> {
    rows(title).into_iter().map(|row| row[0].clone()).collect()
}

/// Every package name in `Cargo.lock`, `netconf` itself excluded.
fn lock_packages() -> BTreeSet<String> {
    let names: BTreeSet<String> = read("Cargo.lock")
        .lines()
        .filter_map(|line| line.strip_prefix("name = \""))
        .filter_map(|rest| rest.strip_suffix('"'))
        .filter(|name| *name != OWN_PACKAGE)
        .map(str::to_string)
        .collect();
    // Positive control: an empty set would let the comparisons pass for nothing.
    assert!(
        names.contains("quick-xml"),
        "Cargo.lock does not look as expected"
    );
    names
}

#[test]
fn every_crate_in_the_lock_file_is_listed() {
    let listed = listed(RUST_SECTION);
    let missing: Vec<String> = lock_packages().difference(&listed).cloned().collect();
    assert!(
        missing.is_empty(),
        "in Cargo.lock but not in {DOCUMENT} under '## {RUST_SECTION}': {missing:?} — \
         give each a row with the license it declares"
    );
}

#[test]
fn every_listed_crate_is_in_the_lock_file() {
    let in_lock = lock_packages();
    let stale: Vec<String> = listed(RUST_SECTION).difference(&in_lock).cloned().collect();
    assert!(
        stale.is_empty(),
        "in {DOCUMENT} under '## {RUST_SECTION}' but not in Cargo.lock: {stale:?}"
    );
}

#[test]
fn every_row_names_a_license() {
    for row in rows(RUST_SECTION) {
        assert!(
            row.len() == 3,
            "a row under '## {RUST_SECTION}' in {DOCUMENT} does not have three cells: {row:?}"
        );
        assert!(
            !row[1].is_empty(),
            "{} under '## {RUST_SECTION}' in {DOCUMENT} has no license",
            row[0]
        );
    }
}
