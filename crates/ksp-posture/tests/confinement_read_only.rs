//! A ruleset whose rules are all read-only must still deny writes.
//!
//! One test in this file, on purpose: `restrict_self` is irreversible for the
//! process that calls it, so a second test here would inherit this test's
//! domain instead of the one it set up. The writable-rule control lives in
//! `confinement_writable.rs` for the same reason — a spec that grants a write
//! handles write rights, which is exactly what hid this defect.
//!
//! The defect was a missing *right*, not a missing *path*: the handled set was
//! the union of what the rules granted, so an all-read-only spec handled no
//! write at all and Landlock restricted only what was handled. Each denial is
//! asserted separately — a read, a create and a delete — because the read
//! denial kept working throughout and would have carried the rest.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The whole file exercises the Landlock mechanism, which is Linux-only
// (NFR-003). The crate-level gate also removes the imports and the helper
// from a non-Linux build, where they would otherwise be unused.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};

use ksp_posture::confinement::{ConfinementRule, ConfinementSpec, restrict_then_launch};

/// A directory under the test's own root.
fn directory(root: &Path, name: &str) -> PathBuf {
    let path = root.join(name);
    std::fs::create_dir_all(&path).expect("the test directory is created");
    path
}

#[test]
fn a_read_only_ruleset_denies_the_writes_it_does_not_grant() {
    let root = std::env::temp_dir().join(format!("ksp-confinement-ro-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let granted = directory(&root, "granted");
    let outside = directory(&root, "outside");

    for path in [
        granted.join("readable.txt"),
        outside.join("plain.txt"),
        outside.join("deletable.txt"),
    ] {
        std::fs::write(&path, b"x").expect("the fixture file is written");
    }

    // The shape `ksp run` builds: the loader paths so the process can still
    // resolve what it loads, and the paths the run just read from. Every rule
    // is read-only, so no rule grants a write anywhere.
    let mut rules = Vec::new();
    for system in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"] {
        let candidate = Path::new(system);
        if candidate.is_dir() {
            rules.push(ConfinementRule::read_only(candidate));
        }
    }
    rules.push(ConfinementRule::read_only(&granted));

    let confined = restrict_then_launch(&ConfinementSpec::required(rules));
    let _confined = confined.expect("a required spec applies on a kernel with Landlock");

    // The rule's own grant still holds, so the fix denies nothing it was asked
    // to allow.
    assert!(
        std::fs::read(granted.join("readable.txt")).is_ok(),
        "a read-only rule refused a read beneath its own path"
    );

    // Everything else is denied, for reading *and* for writing.
    assert!(
        std::fs::read(outside.join("plain.txt")).is_err(),
        "a read outside the rules was permitted"
    );
    assert!(
        std::fs::write(outside.join("created.txt"), b"y").is_err(),
        "a create outside the rules was permitted: the ruleset handled no write right, \
         so it denied none"
    );
    assert!(
        std::fs::remove_file(outside.join("deletable.txt")).is_err(),
        "a delete outside the rules was permitted, which is the operation a consume \
         performs after it has already handed the secret to a child"
    );
}
