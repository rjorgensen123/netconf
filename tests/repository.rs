// SPDX-License-Identifier: MIT OR Apache-2.0
//! Repository guard: rules about the files around the code. They cover the SPDX line
//! of every source file, the versions the documents and the manifest comment state by
//! hand, and the two CI files.

use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};

const SPDX_LINE: &str = "// SPDX-License-Identifier: MIT OR Apache-2.0";
const API: &str = "docs/API.md";
const GITEA_CI: &str = ".gitea/workflows/ci.yml";
const GITHUB_CI: &str = ".github/workflows/ci.yml";

fn read(rel: &str) -> String {
    fs::read_to_string(format!("{}/{rel}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// The manifest as it was written, and its file name: the published crate carries it as
/// `Cargo.toml.orig` beside a rewritten `Cargo.toml` without comments, so
/// `Cargo.toml.orig` is read when it exists and `Cargo.toml` otherwise.
fn manifest() -> (&'static str, String) {
    let orig = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml.orig");
    let name = if orig.exists() {
        "Cargo.toml.orig"
    } else {
        "Cargo.toml"
    };
    (name, read(name))
}

/// Every `.rs` file under `dir`, at any depth.
fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("cannot read an entry of {}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

#[test]
fn every_source_file_starts_with_its_spdx_line() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for dir in ["src", "tests"] {
        rust_files(&root.join(dir), &mut files);
    }
    files.sort();
    // Positive control: finding no files would let the check pass for nothing.
    assert!(
        files.len() >= 20,
        "found {} .rs files under src/ and tests/, fewer than the 20 expected",
        files.len()
    );
    let without: Vec<String> = files
        .iter()
        .filter(|path| {
            let text = fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            text.lines().next() != Some(SPDX_LINE)
        })
        .map(|path| {
            path.strip_prefix(root)
                .unwrap_or(path)
                .display()
                .to_string()
        })
        .collect();
    assert!(
        without.is_empty(),
        "these files do not begin with the line `{SPDX_LINE}`: {without:?}"
    );
}

/// The version a reader is told to ask for: `major.minor` for a release, and the whole
/// version for a pre-release.
fn requirement() -> String {
    if env!("CARGO_PKG_VERSION_PRE").is_empty() {
        format!(
            "{}.{}",
            env!("CARGO_PKG_VERSION_MAJOR"),
            env!("CARGO_PKG_VERSION_MINOR")
        )
    } else {
        env!("CARGO_PKG_VERSION").to_string()
    }
}

/// Whether the value of a dependency line, the text after its `=`, names `wanted`: as
/// `"wanted"`, or as `version = "wanted"` inside braces, with at most a comment after it.
fn names_requirement(value: &str, wanted: &str) -> bool {
    let quoted = format!("\"{wanted}\"");
    let value = value.trim_start();
    let rest = if let Some(inner) = value.strip_prefix('{') {
        let Some((items, rest)) = inner.split_once('}') else {
            return false;
        };
        if !items
            .split(',')
            .any(|item| item.trim() == format!("version = {quoted}"))
        {
            return false;
        }
        rest
    } else if let Some(rest) = value.strip_prefix(quoted.as_str()) {
        rest
    } else {
        return false;
    };
    let rest = rest.trim_start();
    rest.is_empty() || rest.starts_with('#')
}

#[test]
fn the_dependency_lines_name_this_version() {
    let netconf = requirement();
    let (manifest_name, manifest) = manifest();
    let krypto = manifest
        .lines()
        .find_map(|line| line.strip_prefix("krypto = \""))
        .and_then(|rest| rest.split_once('"'))
        .map(|(requirement, _)| requirement.to_string())
        .filter(|requirement| !requirement.is_empty())
        .unwrap_or_else(|| panic!("{manifest_name} has no line `krypto = \"…\"`"));

    let mut faults = Vec::new();
    for (file, fewest_netconf_lines) in [("README.md", 2), ("docs/Usage.md", 1)] {
        let (mut netconf_lines, mut krypto_lines) = (0, 0);
        for (number, line) in read(file).lines().enumerate() {
            let (wanted, value) = if let Some(value) = line.strip_prefix("netconf = ") {
                netconf_lines += 1;
                (&netconf, value)
            } else if let Some(value) = line
                .strip_prefix("krypto")
                .filter(|rest| rest.starts_with(' '))
                .and_then(|rest| rest.trim_start_matches(' ').strip_prefix('='))
            {
                krypto_lines += 1;
                (&krypto, value)
            } else {
                continue;
            };
            if !names_requirement(value, wanted) {
                faults.push(format!(
                    "{file}:{}: `{line}` does not name \"{wanted}\"",
                    number + 1
                ));
            }
        }
        assert!(
            netconf_lines >= fewest_netconf_lines,
            "{file} has {netconf_lines} lines beginning `netconf = `, fewer than the \
             {fewest_netconf_lines} expected"
        );
        assert!(
            krypto_lines >= 1,
            "{file} has no line beginning `krypto` followed by spaces and `=`"
        );
    }
    assert!(
        faults.is_empty(),
        "dependency lines that do not name this version (netconf \"{netconf}\", krypto \
         \"{krypto}\" as in {manifest_name}):\n{}",
        faults.join("\n")
    );
}

#[test]
fn security_md_names_this_version() {
    let (major, minor) = (
        env!("CARGO_PKG_VERSION_MAJOR"),
        env!("CARGO_PKG_VERSION_MINOR"),
    );
    let text = read("SECURITY.md");
    let section = text
        .split("\n## ")
        .find_map(|part| part.strip_prefix("Supported versions\n"))
        .expect("SECURITY.md has no section '## Supported versions'");
    let table: Vec<Vec<String>> = section
        .lines()
        .filter(|line| line.starts_with('|'))
        .map(|line| {
            line.trim()
                .trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().to_string())
                .collect()
        })
        .collect();
    assert!(
        table.len() >= 2
            && table[1]
                .iter()
                .all(|cell| !cell.is_empty() && cell.chars().all(|c| matches!(c, '-' | ':'))),
        "the table under '## Supported versions' in SECURITY.md has no header and separator row"
    );
    let expected = [
        vec![format!("{major}.{minor}.x"), "yes".to_string()],
        vec![format!("< {major}.{minor}"), "no".to_string()],
    ];
    assert_eq!(
        table[2..],
        expected[..],
        "the rows of the table under '## Supported versions' in SECURITY.md do not name \
         this version"
    );
}

/// A version: major, minor and patch, and the pre-release part after a `-`, if any.
#[derive(Debug, PartialEq, Eq)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Option<String>,
}

/// Reads `major.minor.patch` with an optional `-pre`; anything else is `None`.
fn parse_version(text: &str) -> Option<Version> {
    let (numbers, pre) = match text.split_once('-') {
        Some((numbers, pre)) if !pre.is_empty() => (numbers, Some(pre.to_string())),
        Some(_) => return None,
        None => (text, None),
    };
    let numbers: Vec<u64> = numbers
        .split('.')
        .map(|part| {
            if !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()) {
                part.parse().ok()
            } else {
                None
            }
        })
        .collect::<Option<_>>()?;
    let [major, minor, patch] = numbers[..] else {
        return None;
    };
    Some(Version {
        major,
        minor,
        patch,
        pre,
    })
}

/// Whether `a` is ahead of `b`. Major, minor and patch compare as numbers; with those
/// equal, a version with a pre-release part comes before the one without, and two
/// pre-release parts compare as text.
fn is_ahead(a: &Version, b: &Version) -> bool {
    let order = (a.major, a.minor, a.patch)
        .cmp(&(b.major, b.minor, b.patch))
        .then_with(|| match (&a.pre, &b.pre) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(a_pre), Some(b_pre)) => a_pre.cmp(b_pre),
        });
    order == Ordering::Greater
}

/// The word in front of each place `phrase` stands in `text`.
fn words_before<'a>(text: &'a str, phrase: &str) -> Vec<&'a str> {
    text.match_indices(phrase)
        .map(|(at, _)| text[..at].rsplit(' ').next().unwrap_or(""))
        .collect()
}

#[test]
fn the_contract_floor_is_not_ahead_of_the_crate() {
    let text = read(API);
    // The top: everything before the first `## ` heading, on one line.
    let top = text.split("\n## ").next().unwrap_or("");
    let flat = top.split_whitespace().collect::<Vec<_>>().join(" ");

    let title: Vec<String> = top
        .lines()
        .next()
        .filter(|line| line.starts_with("# "))
        .and_then(|line| line.strip_suffix(')'))
        .and_then(|line| line.rsplit_once("(v"))
        .map(|(_, version)| version.to_string())
        .into_iter()
        .collect();
    let lowest: Vec<String> = words_before(&flat, " is the LOWEST")
        .into_iter()
        .filter_map(|word| word.strip_prefix('v').map(str::to_string))
        .collect();
    let onwards: Vec<String> = flat
        .match_indices(" onwards")
        .filter_map(|(at, _)| {
            let mut before = flat[..at].rsplit(' ');
            let version = before.next()?;
            (before.next() == Some("from")).then(|| version.to_string())
        })
        .collect();
    let last_changed: Vec<String> =
        words_before(&flat, " is where the public surface last changed")
            .into_iter()
            .map(str::to_string)
            .collect();

    let places = [
        ("the title `(vX)`", title),
        ("«vX is the LOWEST»", lowest),
        ("«from X onwards»", onwards),
        ("«X is where the public surface last changed»", last_changed),
    ];
    let missing: Vec<&str> = places
        .iter()
        .filter(|(_, found)| found.is_empty())
        .map(|(place, _)| *place)
        .collect();
    assert!(
        missing.is_empty(),
        "the top of {API} does not state the floor in: {missing:?}"
    );
    let floor = &places[0].1[0];
    assert!(
        places
            .iter()
            .all(|(_, found)| found.iter().all(|v| v == floor)),
        "the top of {API} does not state one floor: {:?}",
        places
            .iter()
            .map(|(place, found)| format!("{place}: {found:?}"))
            .collect::<Vec<_>>()
    );

    let crate_version = env!("CARGO_PKG_VERSION");
    let floor_version = parse_version(floor)
        .unwrap_or_else(|| panic!("the floor in {API}, `{floor}`, is not a version"));
    let own_version = parse_version(crate_version)
        .unwrap_or_else(|| panic!("the crate version `{crate_version}` is not a version"));
    assert!(
        !is_ahead(&floor_version, &own_version),
        "the floor in {API}, {floor}, is ahead of the crate version {crate_version}"
    );
}

#[test]
fn the_rust_version_comment_matches_rust_version() {
    let (name, manifest) = manifest();
    let lines: Vec<&str> = manifest.lines().collect();
    let (at, version) = lines
        .iter()
        .enumerate()
        .find_map(|(at, line)| {
            let version = line.strip_prefix("rust-version = \"")?.strip_suffix('"')?;
            (!version.is_empty()).then_some((at, version))
        })
        .unwrap_or_else(|| panic!("{name} has no line `rust-version = \"…\"`"));
    let mut comment: Vec<&str> = lines[..at]
        .iter()
        .rev()
        .take_while(|line| line.trim_start().starts_with('#'))
        .copied()
        .collect();
    comment.reverse();
    assert!(
        comment.iter().any(|line| line.contains(version)),
        "the comment lines directly above `rust-version = \"{version}\"` in {name} do not \
         name {version}: {comment:?}"
    );
}

/// The lines of a workflow file the two CI files must share, with their line numbers.
/// Left out: blank lines, comment lines, every checkout step, and the top-level
/// `permissions:` block.
fn shared_lines(text: &str) -> Vec<(usize, &str)> {
    let mut kept = Vec::new();
    let mut checkout_indent: Option<usize> = None;
    let mut in_permissions = false;
    for (number, line) in text.lines().enumerate() {
        let unindented = line.trim_start_matches(' ');
        if line.trim().is_empty() || unindented.starts_with('#') {
            continue;
        }
        let indent = line.len() - unindented.len();
        let trimmed = line.trim();
        if in_permissions {
            if indent > 0 {
                continue;
            }
            in_permissions = false;
        }
        if let Some(step_indent) = checkout_indent {
            if !(trimmed.starts_with("- name:") && indent == step_indent) {
                continue;
            }
            checkout_indent = None;
        }
        if trimmed.starts_with("- name: Checkout") {
            checkout_indent = Some(indent);
            continue;
        }
        if indent == 0 && trimmed.starts_with("permissions:") {
            in_permissions = true;
            continue;
        }
        kept.push((number + 1, line));
    }
    kept
}

#[test]
fn both_ci_files_run_the_same_steps() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    match (root.join(GITEA_CI).exists(), root.join(GITHUB_CI).exists()) {
        (true, true) => {}
        (false, false) => {
            eprintln!("the published crate does not carry the CI files: nothing to compare");
            return;
        }
        (gitea, _) => {
            let (present, absent) = if gitea {
                (GITEA_CI, GITHUB_CI)
            } else {
                (GITHUB_CI, GITEA_CI)
            };
            panic!("{present} exists and {absent} does not");
        }
    }
    let (gitea_text, github_text) = (read(GITEA_CI), read(GITHUB_CI));
    let (gitea, github) = (shared_lines(&gitea_text), shared_lines(&github_text));
    let show = |file: &str, lines: &[(usize, &str)], at: usize| match lines.get(at) {
        Some((number, line)) => format!("{file}:{number}: {line}"),
        None => format!("{file}: no more lines"),
    };
    if let Some(at) = (0..gitea.len().max(github.len()))
        .find(|&at| gitea.get(at).map(|l| l.1) != github.get(at).map(|l| l.1))
    {
        panic!(
            "the CI files differ with blank lines, comments, the checkout steps and the \
             top-level `permissions:` block left out; the first difference:\n{}\n{}",
            show(GITEA_CI, &gitea, at),
            show(GITHUB_CI, &github, at)
        );
    }
}
