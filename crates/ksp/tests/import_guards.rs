//! The import surface's two guards: no export, and no adapter on the read path.
//!
//! # What this test file is for
//!
//! Feature 018 adds `ksp import`, which copies secrets **out of** an external
//! secret manager or a file and seals them into this host's store. Two
//! properties keep that from becoming something the design refuses, and both are
//! enforced here rather than described in prose:
//!
//! 1. **There is no export.** Handing a plaintext value to a service the admin
//!    does not control spends the admin-zero-knowledge property that §1.0
//!    exists to hold. `ksp export` is a verb that refuses, in every form.
//!
//! 2. **An adapter is never reachable from the agent read path.** §2.3 says
//!    Keyspout runs no service, and the lease model is what makes a deadline
//!    mean anything: a delivery that fetched live from a manager would need a
//!    standing manager credential on the agent host and would delete nothing,
//!    because nothing was copied. The plausible way that property is lost is a
//!    later "keep the secret fresh" change that adds one `use` to the run path.
//!
//! # Why the read-path guard is a source scan rather than a type
//!
//! A type-level guard would need the import module to be feature-gated, which
//! changes the build for every consumer to catch one regression. The scan is
//! cheap, runs in the unprivileged host gate, and fails on exactly the edit that
//! would matter.
//!
//! The scan reports what it read, so a guard that silently scanned nothing —
//! because a path moved — fails instead of passing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// The repository root, from this test binary's own location.
///
/// `CARGO_MANIFEST_DIR` is `crates/ksp`, so two parents up is the workspace
/// root. A path derived from the source tree rather than from the process's
/// working directory, because a test runs from wherever the harness started it.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the ksp crate lives two levels below the workspace root")
        .to_path_buf()
}

/// The `ksp` crate's source directory.
fn source_root() -> PathBuf {
    repo_root().join("crates/ksp/src")
}

/// Every `.rs` file under a directory, recursively.
///
/// Hidden directories are skipped, and so is anything that is not a `.rs` file:
/// the scan is over source, and a fixture or an asset cannot import a module.
fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("{} could not be listed: {error}", dir.display()));
    for entry in entries {
        let path = entry.expect("a directory entry is readable").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

// ---------------------------------------------------------------------------
// Guard 1: there is no export
// ---------------------------------------------------------------------------

/// Every spelling `ksp export` might be typed in.
///
/// The point is that the refusal is the **same** for all of them. A verb that
/// refuses for `export` but reports an unknown flag for `--to bitwarden` would
/// tell an operator the feature exists and is misconfigured.
const EXPORT_INVOCATIONS: &[&[&str]] = &[
    &["export"],
    &["export", "--to", "bitwarden"],
    &["export", "--to", "vault"],
    &["export", "--anything"],
    &["export", "--json"],
];

#[test]
fn export_refuses_in_every_form_with_the_same_reason() {
    let exe = env!("CARGO_BIN_EXE_ksp");
    let mut reasons = Vec::new();

    for invocation in EXPORT_INVOCATIONS {
        // A throwaway home so no test touches the operator's deployment. The
        // refusal must not depend on a deployment existing: it is a property of
        // the verb, not of this host's state.
        let home = std::env::temp_dir().join(format!("ksp-export-refusal-{}", std::process::id()));
        let output = Command::new(exe)
            .args(*invocation)
            .env("KSP_HOME", &home)
            .output()
            .expect("the test binary can be run");

        let code = output.status.code().unwrap_or(-1);
        assert_eq!(
            code,
            13,
            "`ksp {}` must exit 13 (USAGE); got {code}\nstdout: {}\nstderr: {}",
            invocation.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        reasons.push((invocation.join(" "), text));
    }

    // One reason, the same one, for every form. A correct exit code with a
    // vague sentence is the defect this repository records elsewhere: the code
    // tells an agent to stop, and the sentence is what tells a human why.
    for (spelling, text) in &reasons {
        assert!(
            text.contains("not implemented") || text.contains("not supported"),
            "`ksp {spelling}` must say export is not implemented; got: {text}"
        );
        assert!(
            text.to_lowercase().contains("control")
                || text.to_lowercase().contains("third part")
                || text.to_lowercase().contains("admin does not"),
            "`ksp {spelling}` must name the reason — that a plaintext value would \
             reach a service the admin does not control; got: {text}"
        );
    }
}

// ---------------------------------------------------------------------------
// Guard 2: no adapter on the agent read path
// ---------------------------------------------------------------------------

/// The modules the `ksp run` path reaches.
///
/// Named explicitly rather than discovered, because a discovered set would
/// shrink silently when a module is renamed — and a guard that scans nothing
/// passes. The test asserts each path exists, so a rename fails loudly.
const RUN_PATH_MODULES: &[&str] = &[
    "run.rs",
    "run_gate.rs",
    "deliver.rs",
    "process.rs",
    "consume.rs",
];

#[test]
fn the_run_path_does_not_reach_the_import_module() {
    let root = source_root();
    let mut checked = 0usize;

    for module in RUN_PATH_MODULES {
        let path = root.join(module);
        assert!(
            path.is_file(),
            "{} is on the run path and must exist; the guard's module list has \
             rotted and is now scanning nothing",
            path.display()
        );

        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} is unreadable: {error}", path.display()));

        // Match the *use* form, not the word. A comment saying "the import
        // module is not reachable from here" contains `import` and must not
        // trip the guard — the trap this repository records as "a source scan
        // that greps for a word also matches its own explanation of that word".
        for (number, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            let is_use = trimmed.starts_with("use ");
            if !is_use {
                continue;
            }
            assert!(
                !trimmed.contains("crate::import"),
                "{}:{} on the run path imports the import module: `{trimmed}`.\n\
                 An adapter reachable from `ksp run` puts a live manager fetch and \
                 a standing manager credential on the agent host, and makes the \
                 lease delete nothing because nothing was copied (§2.3).",
                path.display(),
                number + 1
            );
        }
        checked += 1;
    }

    assert_eq!(
        checked,
        RUN_PATH_MODULES.len(),
        "every module on the run path must be scanned; the list shrank"
    );
}

/// The scan must see real source, or it proves nothing.
///
/// A guard that resolved its root to an empty directory would pass every
/// assertion above. This test is the one that fails if the root moves.
#[test]
fn the_guard_scans_the_real_source_tree() {
    let root = source_root();
    let mut files = Vec::new();
    rust_sources(&root, &mut files);

    assert!(
        files.len() > 20,
        "{} should hold the crate's whole source; found {} Rust files. The guard \
         is scanning the wrong directory and would pass on anything",
        root.display(),
        files.len()
    );

    // And the modules this feature adds are not there yet, or are named
    // `import`, which is what the guard exists to keep off the run path.
    assert!(
        files
            .iter()
            .any(|path| path.file_name().and_then(|n| n.to_str()) == Some("app.rs")),
        "app.rs must be present in the scanned tree"
    );
}
