//! A writable rule must keep granting writes, and nothing else gains any.
//!
//! A separate binary from `confinement_read_only.rs` because a ruleset is
//! irreversible and because this spec's writable rule is precisely what made
//! the earlier defect invisible: a spec that grants one write handles write
//! rights for the whole ruleset, so writes outside it are denied by
//! construction. This test therefore guards the opposite direction — that the
//! fix denies no grant.

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
fn a_writable_rule_still_grants_a_write_and_a_delete() {
    let root = std::env::temp_dir().join(format!("ksp-confinement-rw-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let writable = directory(&root, "writable");
    let outside = directory(&root, "outside");
    std::fs::write(writable.join("deletable.txt"), b"x").expect("the fixture file is written");

    let mut rules = Vec::new();
    for system in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"] {
        let candidate = Path::new(system);
        if candidate.is_dir() {
            rules.push(ConfinementRule::read_only(candidate));
        }
    }
    rules.push(ConfinementRule::writable(&writable));

    let confined = restrict_then_launch(&ConfinementSpec::required(rules));
    let _confined = confined.expect("a required spec applies on a kernel with Landlock");

    assert!(
        std::fs::write(writable.join("created.txt"), b"y").is_ok(),
        "a writable rule refused a create beneath its path"
    );
    assert!(
        std::fs::remove_file(writable.join("deletable.txt")).is_ok(),
        "a writable rule refused a delete beneath its path"
    );
    assert!(
        std::fs::write(outside.join("created.txt"), b"y").is_err(),
        "a write outside the rules was permitted, so a writable rule widened the ruleset"
    );
}
