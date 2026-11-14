//! `ksp status` names the barrier's two controls, not only its mechanism.
//!
//! # Why one line was not enough
//!
//! `barrier: barrier mlock (...); adapter mlock (weakened)` told an operator
//! that the posture was weaker than the capability names and nothing else. Two
//! independent controls decide whether a process holding a passphrase can be
//! dumped — `RLIMIT_CORE` excludes a core dump, and `ptrace` refusal excludes a
//! debugger — and either can be absent while the other holds. A single
//! `weakened` word cannot say which.
//!
//! These tests drive the real binary so the assertion is about the document an
//! operator reads, not about a struct a test built by hand.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Stdio};

fn ksp() -> &'static str {
    env!("CARGO_BIN_EXE_ksp")
}

/// A home with a capability configuration, which `ksp status` reads.
fn configured(home: &Path) {
    let _ = Command::new(ksp())
        .env("KSP_HOME", home)
        .arg("init")
        .output();
}

fn status(home: &Path) -> String {
    configured(home);
    let output = Command::new(ksp())
        .env("KSP_HOME", home)
        .env("LC_ALL", "C")
        .arg("status")
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");
    assert!(
        output.status.success(),
        "status must answer even when the host is weak: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The line whose key is `key`, if the document has one.
fn line<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find(|candidate| {
        candidate
            .strip_prefix(key)
            .is_some_and(|rest| rest.starts_with(':'))
    })
}

/// The core-dump exclusion and the `ptrace` refusal are two answers, and the
/// document carries both.
#[test]
fn status_names_the_core_dump_and_ptrace_controls_separately() {
    let home = tempfile::tempdir().expect("home");
    let text = status(home.path());

    let core = line(&text, "core dumps")
        .unwrap_or_else(|| panic!("a core-dump line is required, got:\n{text}"));
    // The positive phrase, not the token: `"not excluded".contains("excluded")`
    // is true, so a bare `contains` passes on the exact inversion this test
    // exists to catch. A mutation that printed `not excluded` proved it.
    assert!(
        core.contains("excluded (RLIMIT_CORE = 0)"),
        "RLIMIT_CORE = 0 succeeded, so the line says the dump is excluded: {core}"
    );
    assert!(
        !core.contains("not excluded"),
        "a control that applied is never rendered as absent: {core}"
    );

    let ptrace =
        line(&text, "ptrace").unwrap_or_else(|| panic!("a ptrace line is required, got:\n{text}"));
    // Same trap: `not refused` contains `refused`.
    assert!(
        !ptrace.contains("not refused"),
        "a control that applied is never rendered as absent: {ptrace}"
    );
    assert!(
        ptrace.contains("refused with"),
        "the attach path was refused, so the line says so: {ptrace}"
    );

    // The mechanism differs by platform, and naming the wrong one would be a
    // claim about a call this build cannot make.
    let named = if cfg!(target_os = "macos") {
        "PT_DENY_ATTACH"
    } else {
        "PR_SET_DUMPABLE"
    };
    assert!(
        ptrace.contains(named),
        "the ptrace line names {named} on this platform: {ptrace}"
    );

    // Misfit D: `weakened` was the whole answer. It may stay as a summary, but
    // it must never be the only thing a reader is given.
    let barrier = line(&text, "barrier").expect("the barrier line is still printed");
    assert!(
        barrier.contains("weakened") || barrier.contains("full"),
        "the mechanism line keeps its own claim: {barrier}"
    );
    assert!(
        !barrier.contains("core") && !barrier.contains("ptrace"),
        "the controls are named on their own lines, not folded into this one: {barrier}"
    );
}

/// Darwin has no `memfd_secret`, and a status line must not imply otherwise.
#[test]
fn the_barrier_line_names_no_mechanism_this_platform_lacks() {
    if !cfg!(target_os = "macos") {
        return;
    }
    let home = tempfile::tempdir().expect("home");
    let text = status(home.path());
    let barrier = line(&text, "barrier").expect("the barrier line is printed");
    assert!(
        !barrier.contains("memfd_secret"),
        "this host cannot create a secret memory fd, so the barrier is not one: {barrier}"
    );
    assert!(
        barrier.contains("mlock"),
        "the mechanism in force is named: {barrier}"
    );
}

/// Every mention of a mechanism this host lacks also says it did not run.
///
/// FR-010 asks an unavailable capability to name what the build could have
/// offered, so `memfd_secret` does appear on a Mac — as a mechanism that did not
/// run. What must never appear is a line that reads as though it did. Asserting
/// the absence alone would forbid the disclosure the design requires; asserting
/// the pairing is the claim worth pinning.
#[test]
fn a_mechanism_this_host_lacks_is_never_reported_as_used() {
    if !cfg!(target_os = "macos") {
        return;
    }
    let home = tempfile::tempdir().expect("home");
    let text = status(home.path());
    for mention in text
        .lines()
        .filter(|line| line.contains("memfd_secret") || line.contains("Landlock"))
    {
        assert!(
            mention.contains("did not run"),
            "a mechanism this host lacks is disclosed as absent, not as used: {mention}"
        );
    }
}
