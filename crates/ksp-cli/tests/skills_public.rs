//! A shipped operator skill must not name anything the public tree lacks.
//!
//! # Why this is a test and not a shell check
//!
//! `scripts/ksp-skills.sh` already fails when a skill's frontmatter disagrees
//! with its folder or when it names a `ksp` subcommand the binary does not have.
//! It does not check for internal references, and the sync does — but the sync
//! runs at publish time, which is the worst moment to learn that a skill cites a
//! document the public tree does not contain. By then the skill has been written,
//! reviewed and merged, and the fix is a second commit to a file whose whole
//! purpose was to be readable by an outsider.
//!
//! So the same rule runs twice: here, on every `cargo test`, and in the sync, on
//! every publish. The two cannot disagree, because this test reads the marker
//! list from the sync's own configuration rather than restating it. A marker
//! added to `forbidden_after_scrub` is enforced here the same day, with no second
//! edit and no chance of the two lists drifting apart.
//!
//! # What the public tree is
//!
//! `bruj0/keyspout-upstream` is edited; `bruj0/keyspout` is generated from it by
//! `scripts/public/sync.py`. A skill ships to the generated tree, so a path that
//! resolves only in the upstream tree is a dangling reference for every reader of
//! the public one.
//!
//! # Why the markers are not written out in this file
//!
//! This file is itself copied to the public tree and scrubbed, so a marker
//! spelled literally here would fail the very check it implements. It reads them
//! from the configuration instead, which is also the only way the two guards stay
//! in step. The self-test below proves the detector works without naming a marker
//! in its source.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The skip notice goes to stderr on purpose: a test that returns early without
// saying so is indistinguishable from one that checked and found nothing, and
// `cargo test` shows stderr for a passing test only when it is asked to. The
// notice is the whole point of the early return.
#![allow(clippy::print_stderr)]

use std::path::{Path, PathBuf};

use serde_json::Value;

/// The repository root, derived from this test binary's location.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives two levels below the workspace root")
        .to_path_buf()
}

/// The sync's configuration, or `None` in a tree that does not carry it.
///
/// The sync tooling is upstream-only: it names the markers it removes, so it
/// cannot ship. A checkout without it is the generated public tree, where the
/// skills are derived and never edited by hand. The tests below skip there and
/// say so, rather than passing silently on an empty marker list.
fn sync_config() -> Option<Value> {
    let path = repo_root().join("scripts/public/sync.json");
    let text = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&text).ok()
}

/// The markers a scrubbed file must not contain, as the sync defines them.
fn forbidden_markers(config: &Value) -> Vec<String> {
    config["forbidden_after_scrub"]
        .as_array()
        .expect("forbidden_after_scrub is an array")
        .iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

/// Every file under `skills/`, excluding hidden directories.
///
/// The walk prunes hidden directories during traversal rather than filtering
/// afterwards, for the reason `agent_contract.rs` gives: a `target/` or
/// `node_modules/` holds tens of gigabytes, and enumerating it to discard it is
/// the cost the pruning exists to avoid.
fn skill_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if name.starts_with('.') || name == "target" || name == "node_modules" {
                    continue;
                }
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&repo_root().join("skills"), &mut out);
    out
}

/// The markers present in `text`, as `marker` pairs.
fn markers_in(text: &str, markers: &[String]) -> Vec<String> {
    markers
        .iter()
        .filter(|marker| text.contains(marker.as_str()))
        .cloned()
        .collect()
}

/// No shipped skill names an internal path.
///
/// A skill is prose an outside operator's agent executes. A citation into the
/// specification tree, a research document or a path on the author's machine is
/// unreadable there: the reader cannot open it, cannot check the claim, and has
/// no way to tell a stale reference from a missing one.
#[test]
fn no_shipped_skill_names_an_internal_path() {
    let Some(config) = sync_config() else {
        eprintln!(
            "skipped: no scripts/public/sync.json in this tree, so the marker list \
             is not available. This is the generated public tree, where skills are \
             derived and not edited."
        );
        return;
    };
    let markers = forbidden_markers(&config);
    assert!(
        !markers.is_empty(),
        "forbidden_after_scrub is empty, so this test would pass without checking \
         anything. A guard with no markers guards nothing."
    );

    let files = skill_files();
    assert!(
        !files.is_empty(),
        "skills/ holds no files. If the tree really has no skills yet this test is \
         vacuous, and a vacuous pass is worse than a stated skip."
    );

    let mut offenders = Vec::new();
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            // A binary asset cannot carry a readable citation.
            continue;
        };
        for marker in markers_in(&text, &markers) {
            let line = text
                .lines()
                .position(|content| content.contains(&marker))
                .map_or(0, |index| index + 1);
            let name = path.strip_prefix(repo_root()).unwrap_or(path);
            offenders.push(format!("{}:{line}: names {marker:?}", name.display()));
        }
    }

    assert!(
        offenders.is_empty(),
        "a shipped skill must not name an internal path: the reader of the public \
         tree cannot open it. Found: {offenders:#?}"
    );
}

/// The scan can fail, proven without naming a marker in this file.
///
/// A scan that never fires is indistinguishable from a scan with nothing to find,
/// and the two are told apart only by feeding it something it must reject. The
/// needle comes from the configuration, so this test carries no marker of its own
/// and cannot be the offender it is looking for.
#[test]
fn the_scan_rejects_a_marker_it_was_given() {
    let Some(config) = sync_config() else {
        eprintln!("skipped: no scripts/public/sync.json in this tree");
        return;
    };
    let markers = forbidden_markers(&config);
    let Some(needle) = markers.first() else {
        panic!("forbidden_after_scrub is empty, so there is nothing to detect");
    };

    let clean = "Run `ksp status --json` and report the capability line.";
    assert!(
        markers_in(clean, &markers).is_empty(),
        "a sentence that names no internal path was reported as an offender, so \
         the scan matches too much and the guard above cannot be trusted"
    );

    let dirty = format!("See {needle} for the reasoning.");
    assert_eq!(
        markers_in(&dirty, &markers),
        vec![needle.clone()],
        "the scan failed to report {needle:?} in a string that contains it"
    );
}

/// The sync scrubs the skills, so the publish-time guard reaches them.
///
/// This test's own rule is enforced twice, and the second half is only real while
/// `skills/` stays in the scrub list. Removing it would leave the commit-time
/// check as the only one, and a skill edited between the two would publish with
/// the reference intact.
///
/// The pattern is matched by prefix rather than by a full glob: a pattern that
/// reaches a skill file always starts with a prefix of the path it covers, so a
/// prefix test is enough to catch a pattern that was removed or narrowed to
/// another directory. Reimplementing the sync's glob here would be a second
/// matcher to keep in step with the first.
#[test]
fn the_sync_scrubs_the_skills_tree() {
    let Some(config) = sync_config() else {
        eprintln!("skipped: no scripts/public/sync.json in this tree");
        return;
    };
    let patterns: Vec<String> = config["scrub"]
        .as_array()
        .expect("scrub is an array")
        .iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect();

    let sample = "skills/keyspout-status/SKILL.md";
    let covered = patterns.iter().any(|pattern| {
        let prefix = pattern.split('*').next().unwrap_or("");
        sample.starts_with(prefix)
    });

    assert!(
        covered,
        "no `scrub` pattern reaches {sample}, so the publish-time marker check skips \
         the skills tree. Patterns: {patterns:?}"
    );
}
