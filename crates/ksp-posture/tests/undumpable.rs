//! The barrier's two dump controls, observed in a process of their own.
//!
//! # Why these tests re-execute
//!
//! `PT_DENY_ATTACH` and `RLIMIT_CORE = 0` act on the **calling** process, and
//! `PT_DENY_ATTACH` cannot be reversed. A test that applied the barrier in
//! process would restrict its own harness: the first failure after the call
//! would be unreadable, because a debugger that attaches to inspect it is
//! killed. Feature 002 recorded exactly this trap after two tests reported that
//! `establish()` "does nothing" while having applied a ruleset to themselves.
//!
//! So the parent spawns this same test binary with `--ignored --exact`, the
//! child applies the barrier, and the child reports by **exit code and stdout**.
//! Nothing asserts after the call.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::{Command, Stdio};

use ksp_posture::barrier::{BarrierPreference, allocate};
use ksp_posture::memlock::{ControlOutcome, ptrace_mechanism};

/// Set in the child so the ignored test knows it was asked to run.
const CHILD_VARIABLE: &str = "KSP_BARRIER_CHILD";
/// Where the child writes its report. A file rather than stdout because
/// `std::process::exit` skips destructors, and a report that depends on a buffer
/// being flushed at exit is a report that can vanish exactly when it matters.
const REPORT_VARIABLE: &str = "KSP_BARRIER_REPORT";
/// The child's own test name, which `--exact` matches.
const CHILD_TEST: &str = "child_applies_the_barrier_and_reports_each_control";

/// A control's state as one token, so the parent parses rather than greps prose.
fn label(outcome: &ControlOutcome) -> String {
    match outcome {
        ControlOutcome::Applied => "applied".to_owned(),
        ControlOutcome::Unavailable { reason } => format!("unavailable: {reason}"),
    }
}

/// The value the parent reads for `key` out of the child's stdout.
fn reported<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
}

/// Both controls applied, in a process that is not the harness.
///
/// On Darwin this is the claim that the host refuses a dump *and* a debugger
/// attach; on Linux it is the same claim through `PR_SET_DUMPABLE`. A host that
/// can only do one of them fails here, which is the point: one control is not
/// the conjunction the barrier's name implies.
#[test]
fn a_child_process_reports_both_controls_applied() {
    let report_path =
        std::env::temp_dir().join(format!("ksp-barrier-{}.report", std::process::id()));
    let exe = std::env::current_exe().expect("the test binary has a path");
    let output = Command::new(exe)
        .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
        .env(CHILD_VARIABLE, "1")
        .env(REPORT_VARIABLE, &report_path)
        .stdin(Stdio::null())
        .output()
        .expect("the child runs");

    let stdout = std::fs::read_to_string(&report_path).unwrap_or_default();
    let _ = std::fs::remove_file(&report_path);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "the child must exit 0; it exited {:?}\nreport:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );

    let core = reported(&stdout, "core_limit")
        .unwrap_or_else(|| panic!("the child reports the core-dump control:\n{stdout}"));
    assert_eq!(
        core, "applied",
        "RLIMIT_CORE = 0 succeeds on a host that can refuse a dump, got {core:?}"
    );

    let ptrace = reported(&stdout, "ptrace")
        .unwrap_or_else(|| panic!("the child reports the ptrace control:\n{stdout}"));
    assert_eq!(
        ptrace,
        "applied",
        "the attach refusal this target provides ({}) must apply, got {ptrace:?}",
        ptrace_mechanism()
    );

    assert_eq!(
        reported(&stdout, "both"),
        Some("true"),
        "the derived answer is true only when both controls applied:\n{stdout}"
    );
}

/// The child end. Ignored so a plain `cargo test` cannot restrict the harness.
///
/// It reports and exits. It never asserts: a panic after `PT_DENY_ATTACH` is
/// exactly the unreadable failure this whole file avoids.
#[test]
#[ignore = "spawned by a_child_process_reports_both_controls_applied: the barrier is irreversible"]
fn child_applies_the_barrier_and_reports_each_control() {
    if std::env::var(CHILD_VARIABLE).as_deref() != Ok("1") {
        // `cargo test --ignored` runs ignored tests without a parent. Doing
        // nothing is the honest answer: the child is never a test on its own.
        return;
    }

    let report_path = std::env::var(REPORT_VARIABLE).expect("the parent names the report path");
    let mut report = String::new();

    let region = match allocate(32, BarrierPreference::AllowFallback) {
        Ok(region) => region,
        Err(error) => {
            // Before the barrier applied: this report is still readable.
            report.push_str(&format!("allocation_failed={error}\n"));
            std::fs::write(&report_path, report).expect("write the report");
            std::process::exit(2);
        }
    };

    let posture = region.undumpable();
    report.push_str(&format!("core_limit={}\n", label(&posture.core_limit)));
    report.push_str(&format!("ptrace={}\n", label(&posture.ptrace)));
    report.push_str(&format!("both={}\n", region.is_undumpable()));
    report.push_str(&format!("mechanism={}\n", ptrace_mechanism()));
    std::fs::write(&report_path, report).expect("write the report");

    // No assertion, no unwrap, no panic past this point.
    std::process::exit(0);
}

/// The derived answer is the conjunction, asserted for all three combinations.
///
/// `is_undumpable()` used to answer "did one call succeed". It now answers
/// "cannot a dump or a debugger read this process", so a host that holds one
/// control and not the other is *not* undumpable — and this test refuses to let
/// the name drift back to the weaker meaning.
#[test]
fn only_both_controls_make_the_process_undumpable() {
    use ksp_posture::UndumpablePosture;

    let applied = || ControlOutcome::Applied;
    let absent = || ControlOutcome::Unavailable {
        reason: "EPERM".to_owned(),
    };

    let both = UndumpablePosture {
        core_limit: applied(),
        ptrace: applied(),
    };
    assert!(both.is_undumpable(), "both applied is the only true case");

    let core_only = UndumpablePosture {
        core_limit: applied(),
        ptrace: absent(),
    };
    assert!(
        !core_only.is_undumpable(),
        "a core-dump exclusion without an attach refusal is still dumpable"
    );
    assert!(
        core_only.to_string().contains("EPERM"),
        "the missing half brings its reason: {core_only}"
    );

    let ptrace_only = UndumpablePosture {
        core_limit: absent(),
        ptrace: applied(),
    };
    assert!(
        !ptrace_only.is_undumpable(),
        "an attach refusal without the core limit is still dumpable by a signal"
    );
}

/// A refusal names a remedy that exists on the host it is printed on.
///
/// FR-012, and the measured failure it closes: the message told an operator to
/// raise `LimitMEMLOCK=` for "the unit that runs `ksp`", which is a systemd
/// directive and means nothing on macOS. A remedy an operator cannot carry out
/// is worse than none, because it closes the investigation.
#[test]
fn a_lock_refusal_names_a_remedy_this_platform_has() {
    use ksp_posture::memlock::{LockabilityRefusal, MemlockObservation};

    let refusal = LockabilityRefusal {
        requested_bytes: 4096,
        observed: MemlockObservation {
            soft_bytes: Some(8 * 1024 * 1024),
            hard_bytes: Some(8 * 1024 * 1024),
        },
        cause: "ENOMEM".to_owned(),
    };
    let text = refusal.to_string();
    assert!(
        text.contains("4096") && text.contains("ENOMEM"),
        "the refusal still says what failed and why: {text}"
    );

    if cfg!(target_os = "macos") {
        assert!(
            text.contains("launchctl limit memlock"),
            "the knob macOS actually has is named: {text}"
        );
        // The sentence may *mention* systemd to explain why the familiar
        // instruction is absent; what it must not do is send the operator to
        // that directive as the fix.
        assert!(
            !text.contains("LimitMEMLOCK="),
            "no systemd directive as the remedy on a host without systemd: {text}"
        );
    } else if cfg!(target_os = "linux") {
        assert!(
            text.contains("LimitMEMLOCK="),
            "the systemd directive is the Linux remedy: {text}"
        );
        assert!(
            !text.contains("launchctl"),
            "no launchd advice on a host without launchd: {text}"
        );
    }
}
