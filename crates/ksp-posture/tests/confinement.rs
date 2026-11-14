//! Acceptance tests for Landlock confinement (Misfit G).
//!
//! Each test corresponds to a numbered acceptance criterion in the work package
//! prompt.
//!
//! # Why the probes re-execute this test binary
//!
//! `landlock_restrict_self(2)` is **irreversible** and process-wide, and
//! [`ksp_posture::descriptors::sanitize`] closes every descriptor it does not
//! keep — including the test harness's own output pipe. Neither can run inside the
//! shared test process without poisoning every later test in the binary.
//!
//! Each probe therefore re-executes this binary with its inputs in environment
//! variables and `--exact` naming the probe test. The probe asserts nothing itself; it prints a
//! single result token on stdout and exits, and the parent asserts on the token.
//! That keeps the assertion in the parent — where a failure is reported properly —
//! and keeps the irreversible syscall in a process that exists only for it.
//!
//! A probe test run *without* the env var returns immediately, so the plain
//! `cargo test` pass over this file is a no-op for them.

// A test reports a failure by panicking, and the panic message is what says why.
// The `println!` calls are the probe protocol — the parent asserts on the tokens a
// probe prints — and the `eprintln!` calls are skips a reader must be able to see:
// a silently unobserved half of criterion 3 would be worse than a noisy one.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::Path;
use std::process::{Command, Output};

#[cfg(target_os = "linux")]
use ksp_posture::adapters::{ConfinementAdapter, LANDLOCK_CONFINEMENT};
#[cfg(target_os = "linux")]
use ksp_posture::confinement::{ConfinementRule, ConfinementSpec, restrict_then_launch};

/// Re-executes this test binary to run `probe` in a fresh process.
fn run_probe(probe: &str, env: &[(&str, &str)]) -> Output {
    let exe = std::env::current_exe().expect("the test binary path must be known");
    let mut command = Command::new(exe);
    command
        .arg("--exact")
        .arg(probe)
        .arg("--nocapture")
        .arg("--test-threads=1");
    for (key, value) in env {
        command.env(key, value);
    }
    command
        .output()
        .expect("the probe process must be spawnable")
}

/// The token a probe prints; the parent greps for it.
#[cfg(target_os = "linux")]
fn probe_stdout(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Builds a levels tree shaped like the vault layout: a root with two sibling
/// level directories, each holding a file only that level should reach.
///
/// `0711` on the root is deliberate: it is the mode FR-041 discusses, and the
/// tests assert what it does and does not imply rather than assuming.
fn levels_tree() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let root = tempfile::tempdir().expect("create a temporary root");
    let base = root.path().to_path_buf();

    let level_a = base.join("agent-a");
    let level_b = base.join("agent-b");
    std::fs::create_dir(&level_a).expect("create agent-a");
    std::fs::create_dir(&level_b).expect("create agent-b");
    std::fs::write(level_a.join("own-secret"), b"a").expect("write agent-a secret");
    std::fs::write(level_b.join("sibling-secret"), b"b").expect("write agent-b secret");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o711))
            .expect("set 0711 on the levels root");
    }

    (root, level_a, level_b)
}

/// Reports the errno as a probe token, so the parent asserts on the kernel's
/// answer rather than on a formatted message.
#[cfg(target_os = "linux")]
fn errno_token(err: &std::io::Error) -> String {
    match err.raw_os_error() {
        Some(code) => format!("errno={code}"),
        None => format!("errno=none kind={:?}", err.kind()),
    }
}

// ---------------------------------------------------------------------------
// Probe: does a confined process see EACCES on a sibling path?
// ---------------------------------------------------------------------------

/// Probe for criterion 1. Run by the parent with the env vars set.
#[test]
#[cfg(target_os = "linux")]
fn probe_sibling_access() {
    let (Ok(level_a), Ok(sibling)) = (
        std::env::var("KSP_PROBE_GRANTED"),
        std::env::var("KSP_PROBE_SIBLING"),
    ) else {
        // Not the parent's invocation: nothing to do.
        return;
    };

    let spec = ConfinementSpec::required([ConfinementRule::read_only(Path::new(&level_a))]);
    let Ok(_confined) = restrict_then_launch(&spec) else {
        println!("PROBE harness-error");
        return;
    };

    // The granted path must still be reachable, otherwise a denial below would
    // prove nothing about the rules.
    match std::fs::File::open(Path::new(&level_a).join("own-secret")) {
        Ok(_) => println!("PROBE granted=ok"),
        Err(err) => {
            println!("PROBE granted={}", errno_token(&err));
            return;
        }
    }

    match std::fs::File::open(&sibling) {
        Ok(_) => println!("PROBE sibling=allowed"),
        Err(err) => println!("PROBE sibling={}", errno_token(&err)),
    }

    // Opening the sibling *directory* must also be denied; a directory handle
    // would give the child an `openat` route around a file-only denial.
    let sibling_dir = Path::new(&sibling)
        .parent()
        .expect("the sibling file has a parent");
    match std::fs::read_dir(sibling_dir) {
        Ok(_) => println!("PROBE sibling_dir=allowed"),
        Err(err) => println!("PROBE sibling_dir={}", errno_token(&err)),
    }
}

// ---------------------------------------------------------------------------
// Probe: a required spec must apply even where all_threads is unsupported
// ---------------------------------------------------------------------------

/// Probe for the pre-V8 regression.
///
/// `landlock` accepts `all_threads` only from ABI V8 (Linux 7.0). Under
/// `HardRequirement` the flag is *rejected* on older kernels, and an earlier
/// revision turned that rejection into a refusal — so on the stock Ubuntu 24.04
/// kernel 6.8 / ABI V4 (DEVELOPMENT.md §2.1, the plan's target) a required run
/// was refused even though every filesystem right it asked for was available.
/// `all_threads` only widens the domain to sibling threads of the parent; the
/// confined child inherits the forking thread's domain, so its loss is reported
/// rather than fatal (FR-040 scopes refusal to the `file` Landlock rights).
///
/// On this ABI-V8 host the flag succeeds, so this probe passes either way. It is
/// written as an explicit probe so that a CI host on an older kernel fails when
/// the fatal branch comes back — that is the only place the regression is
/// observable.
#[test]
#[cfg(target_os = "linux")]
fn probe_required_spec_applies_regardless_of_thread_scope_support() {
    let Ok(target) = std::env::var("KSP_PROBE_GRANTED") else {
        return;
    };

    let spec = ConfinementSpec::required([ConfinementRule::read_only(Path::new(&target))]);
    match restrict_then_launch(&spec) {
        Ok(confined) => {
            // The outcome must be honest about what the kernel granted.
            println!(
                "PROBE applied=ok state={} all_threads={} abi={}",
                confined.applied().posture().state,
                confined.applied().applied_to_all_threads(),
                confined.applied().abi(),
            );
        }
        Err(err) => println!("PROBE applied=refused reason={err}"),
    }
}

/// The regression guard for the pre-V8 refusal: a **required** spec whose rights
/// are all available must apply, and the thread-scope loss must be reported
/// instead of becoming a refusal.
#[test]
#[cfg(target_os = "linux")]
fn a_required_spec_applies_when_the_thread_scope_flag_is_unsupported() {
    let dir = tempfile::tempdir().expect("create a temporary directory");

    let output = run_probe(
        "probe_required_spec_applies_regardless_of_thread_scope_support",
        &[("KSP_PROBE_GRANTED", &dir.path().display().to_string())],
    );
    let observed = probe_stdout(&output);

    assert!(
        observed.contains("PROBE applied=ok"),
        "a required spec must apply when only the thread-scope flag is unsupported; \
         observed: {observed}"
    );
    assert!(
        !observed.contains("PROBE applied=refused"),
        "the thread-scope flag is not one of the `file` Landlock rights FR-040 \
         scopes a refusal to; observed: {observed}"
    );
    // The reported state is real, not a constant.
    assert!(
        observed.contains("state=enforced"),
        "the applied ruleset must report what the kernel enforced; observed: {observed}"
    );
}

// ---------------------------------------------------------------------------
// Probe: does the adapter name itself on the posture it produced?
// ---------------------------------------------------------------------------

/// Probe for FR-007. Run by the parent with the env var set.
///
/// The adapter calls `establish`, which applies the ruleset to **this** process.
/// That is why it needs a probe of its own: the restriction is irreversible, so
/// it must happen in a process that exists only for it.
#[test]
#[cfg(target_os = "linux")]
fn probe_the_adapter_names_itself_on_the_posture() {
    let Ok(target) = std::env::var("KSP_PROBE_GRANTED") else {
        return;
    };

    let spec = ConfinementSpec::required([ConfinementRule::read_only(Path::new(&target))]);
    match LANDLOCK_CONFINEMENT.establish(&spec) {
        Ok(confined) => {
            let posture = confined.applied().posture();
            println!(
                "PROBE posture adapter={:?} guarantee={} state={}",
                posture.adapter,
                posture.guarantee.label(),
                posture.state,
            );
        }
        Err(err) => println!("PROBE posture=refused reason={err}"),
    }
}

/// The production route stamps the adapter that ran on the posture.
///
/// This is the test that would have caught the defect: the posture constructors
/// hard-coded `adapter: None` with no argument that could override it, so every
/// real run rendered `no adapter` while the suite passed against structs the
/// tests had assembled themselves. Here the value comes out of
/// `LANDLOCK_CONFINEMENT::establish` and nothing in this file names an adapter.
#[test]
#[cfg(target_os = "linux")]
fn the_confinement_posture_names_the_adapter_that_ran() {
    let dir = tempfile::tempdir().expect("create a temporary directory");

    let output = run_probe(
        "probe_the_adapter_names_itself_on_the_posture",
        &[("KSP_PROBE_GRANTED", &dir.path().display().to_string())],
    );
    let observed = probe_stdout(&output);

    let named = format!(
        "PROBE posture adapter=Some({:?})",
        LANDLOCK_CONFINEMENT.name()
    );
    assert!(
        observed.contains(&named),
        "the posture must name the adapter that established it; expected `{named}`; \
         observed: {observed}"
    );
    assert!(
        !observed.contains("adapter=None"),
        "a posture produced by an adapter must never render `no adapter`; observed: {observed}"
    );
    let level = format!("guarantee={}", LANDLOCK_CONFINEMENT.guarantee().label());
    assert!(
        observed.contains(&level),
        "the posture must carry the adapter's own guarantee; expected `{level}`; \
         observed: {observed}"
    );
}

/// Criterion 1 — the Misfit G test.
///
/// A confined process opening a **sibling level's path** receives `EACCES` from
/// the **kernel**. The assertion is on the errno, because a client-side check
/// would produce a different or no errno at all.
#[test]
#[cfg(target_os = "linux")]
fn a_confined_process_is_denied_a_sibling_path_by_the_kernel() {
    let (_root, level_a, level_b) = levels_tree();
    let sibling = level_b.join("sibling-secret");

    let output = run_probe(
        "probe_sibling_access",
        &[
            ("KSP_PROBE_GRANTED", &level_a.display().to_string()),
            ("KSP_PROBE_SIBLING", &sibling.display().to_string()),
        ],
    );
    let observed = probe_stdout(&output);

    assert!(
        observed.contains("PROBE granted=ok"),
        "the granted level must stay reachable, or the denial proves nothing; observed: {observed}"
    );
    assert!(
        observed.contains(&format!("PROBE sibling=errno={}", libc::EACCES)),
        "the kernel must deny the sibling file with EACCES; observed: {observed}"
    );
    assert!(
        observed.contains(&format!("PROBE sibling_dir=errno={}", libc::EACCES)),
        "the kernel must also deny the sibling directory, so no openat route exists; \
         observed: {observed}"
    );
    assert!(
        !observed.contains("PROBE sibling=allowed"),
        "the sibling path was readable from a confined process; observed: {observed}"
    );
}

// ---------------------------------------------------------------------------
// Probe: is the restriction in force before the child executes?
// ---------------------------------------------------------------------------

/// Probe for criterion 2: apply the rules, then launch a child that reports what
/// *it* can reach.
///
/// The child is a separate `sh` process, so its denial can only come from an
/// inherited Landlock domain — an in-process check could not reach it.
#[test]
#[cfg(target_os = "linux")]
fn probe_child_order() {
    let (Ok(level_a), Ok(sibling)) = (
        std::env::var("KSP_PROBE_GRANTED"),
        std::env::var("KSP_PROBE_SIBLING"),
    ) else {
        return;
    };

    // A confined launch needs execute access to the binary it runs as well as to
    // the level. Omitting the runtime paths makes `spawn` fail with EACCES, which
    // is itself proof the rules were already in force — but it would not observe
    // what the *child* can read, so the runtime paths are granted here.
    let mut rules = vec![ConfinementRule::read_only(Path::new(&level_a))];
    for runtime in [
        "/bin",
        "/usr/bin",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
    ] {
        let path = Path::new(runtime);
        if path.exists() {
            rules.push(ConfinementRule::read_only(path));
        }
    }

    let spec = ConfinementSpec::required(rules);
    let Ok(confined) = restrict_then_launch(&spec) else {
        println!("PROBE harness-error");
        return;
    };

    // `od` is used rather than `cat` so the child's own exit status distinguishes
    // "read succeeded" from "read failed", without needing a shell builtin that
    // might swallow the errno.
    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg(format!(
        "if od -An -c {sibling} >/dev/null 2>&1; then echo CHILD=readable; else echo CHILD=denied; fi",
        sibling = shell_quote(&sibling),
    ));

    let mut child = match confined.launch(command) {
        Ok(child) => child,
        Err(err) => {
            println!("PROBE launch-error={err}");
            return;
        }
    };
    // The child writes to the inherited stdout, which the parent captures.
    let _ = child.wait();
}

/// Criterion 2 — the confinement is applied **before** the child is launched.
///
/// The ordering is structural: the only value that can launch a child is produced
/// by `restrict_then_launch`, which applies the ruleset first. This test observes
/// the effect rather than trusting the shape — the launched child reports `denied`
/// for a sibling path, which is only possible if the domain was already in force
/// when it executed.
#[test]
#[cfg(target_os = "linux")]
fn a_launched_child_inherits_the_restriction_from_before_its_exec() {
    let (_root, level_a, level_b) = levels_tree();
    let sibling = level_b.join("sibling-secret");

    // Control first: unconfined, the same child command must read the sibling.
    let control = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "if od -An -c {sibling} >/dev/null 2>&1; then echo CHILD=readable; else echo CHILD=denied; fi",
            sibling = shell_quote(&sibling),
        ))
        .output()
        .expect("the control child must run");
    assert!(
        String::from_utf8_lossy(&control.stdout).contains("CHILD=readable"),
        "the unconfined control must read the sibling, otherwise the confined \
         result would be explained by something other than Landlock"
    );

    let output = run_probe(
        "probe_child_order",
        &[
            ("KSP_PROBE_GRANTED", &level_a.display().to_string()),
            ("KSP_PROBE_SIBLING", &sibling.display().to_string()),
        ],
    );
    let observed = probe_stdout(&output);

    assert!(
        observed.contains("CHILD=denied"),
        "a child launched after the ruleset must already be denied; observed: {observed}"
    );
}

/// Quotes a path for `/bin/sh -c`, so an unusual temporary-directory name cannot
/// split the script.
fn shell_quote(path: impl AsRef<Path>) -> String {
    format!(
        "'{}'",
        path.as_ref().display().to_string().replace('\'', r"'\''")
    )
}

// ---------------------------------------------------------------------------
// Probe: does sanitation remove an inherited sibling descriptor?
// ---------------------------------------------------------------------------

/// Probe for the inherited-descriptor case.
///
/// Sanitation closes the harness's output pipe, so the result is written to a
/// file the parent names — not to stdout.
#[test]
fn probe_sanitation() {
    let (Ok(target), Ok(report_path)) = (
        std::env::var("KSP_PROBE_SIBLING"),
        std::env::var("KSP_PROBE_REPORT"),
    ) else {
        return;
    };

    let file = std::fs::File::open(&target).expect("open the sibling before sanitation");
    let fd = {
        use std::os::unix::io::AsRawFd;
        file.as_raw_fd()
    };
    // `sanitize` closes the number, so the `File` must not also close it.
    let _file = std::mem::ManuallyDrop::new(file);
    let was_open = ksp_posture::descriptors::is_open(fd);

    let report = ksp_posture::descriptors::sanitize(
        &ksp_posture::descriptors::DescriptorPolicy::standard_streams_only(),
    );

    // `sanitize` closed every descriptor it does not keep, so open the report
    // file only afterwards.
    let mut result = String::new();
    result.push_str(&format!("was_open={was_open}\n"));
    match report {
        Ok(report) => {
            result.push_str(&format!("closed_includes={}\n", report.closed_includes(fd)));
            result.push_str(&format!(
                "still_open={}\n",
                ksp_posture::descriptors::is_open(fd)
            ));
        }
        Err(err) => result.push_str(&format!("error={err}\n")),
    }
    std::fs::write(&report_path, result).expect("write the sanitation report");
}

/// An inherited descriptor for a sibling path defeats the rules, which is why
/// sanitation belongs to the same fix (FR-039).
///
/// The descriptor is opened while still unconfined. After sanitation it is
/// closed, so a confined child cannot reach the sibling through it.
#[test]
fn sanitation_removes_an_inherited_sibling_descriptor() {
    let (root, _level_a, level_b) = levels_tree();
    let sibling = level_b.join("sibling-secret");
    let report_path = root.path().join("sanitation-report.txt");

    let output = run_probe(
        "probe_sanitation",
        &[
            ("KSP_PROBE_SIBLING", &sibling.display().to_string()),
            ("KSP_PROBE_REPORT", &report_path.display().to_string()),
        ],
    );
    assert!(
        output.status.success(),
        "the sanitation probe must exit cleanly; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report = std::fs::read_to_string(&report_path).expect("the probe must write its report");
    assert!(
        report.contains("was_open=true"),
        "the probe must start with the sibling descriptor open; report: {report}"
    );
    assert!(
        report.contains("closed_includes=true"),
        "the sibling descriptor must be reported closed; report: {report}"
    );
    assert!(
        report.contains("still_open=false"),
        "the kernel must report the sibling descriptor closed; report: {report}"
    );
}

// ---------------------------------------------------------------------------
// Criterion 3 — owner enumeration versus non-owner listing
// ---------------------------------------------------------------------------

/// Criterion 3 (owner half) — a `0711` parent lets its **owner** enumerate.
///
/// This is a property of the filesystem mode. It is asserted separately from the
/// non-owner half because the two are genuinely different facts and FR-041
/// requires both. Enumeration is **not** an access control: the owner sees the
/// sibling level's name, and the confined child is still denied its contents.
#[test]
fn a_0711_parent_lets_the_owner_enumerate() {
    let (_root, level_a, level_b) = levels_tree();
    let base = level_a.parent().expect("the levels root");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(base)
            .expect("stat the levels root")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o711, "the root must be 0711, got {mode:o}");
    }

    let observed = std::fs::read_dir(base)
        .expect("the owner must be able to list a 0711 directory it owns")
        .map(|entry| entry.expect("each entry must be readable").file_name())
        .collect::<Vec<_>>();

    assert!(
        observed.contains(&std::ffi::OsString::from("agent-a")),
        "the owner must see its own level; saw {observed:?}"
    );
    assert!(
        observed.contains(&std::ffi::OsString::from("agent-b")),
        "the owner enumerates a sibling level too — which is why the listing is \
         not an access control; saw {observed:?}"
    );
    assert!(level_b.exists());
}

/// Criterion 3 (non-owner half) — a non-owner cannot list the `0711` parent.
///
/// Run through `setpriv` because a test process cannot assume another uid without
/// `CAP_SETUID`. When `setpriv` or the privilege is unavailable the test says so
/// instead of passing silently, and the mode assertion in the owner test still
/// pins the configured state.
#[test]
fn a_0711_parent_hides_the_listing_from_a_non_owner() {
    let (_root, level_a, _level_b) = levels_tree();
    let base = level_a.parent().expect("the levels root");

    let probe = format!(
        "python3 -c 'import os,sys\n\
         try:\n    os.listdir(sys.argv[1])\n    print(\"LISTED\")\n\
         except PermissionError:\n    print(\"DENIED\")' {path}",
        path = shell_quote(base)
    );

    let output = Command::new("setpriv")
        .args([
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
            "/bin/sh",
            "-c",
            &probe,
        ])
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("DENIED"),
                "a non-owner must not list a 0711 directory; got {stdout:?}"
            );
            assert!(
                !stdout.contains("LISTED"),
                "a non-owner must not list a 0711 directory; got {stdout:?}"
            );
        }
        Ok(output) => {
            // Without the privilege to drop privileges the half cannot be
            // observed. Saying so is honest; asserting a pass would not be.
            eprintln!(
                "note: the non-owner half was not observed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("note: setpriv is unavailable; the non-owner half was not observed");
        }
        Err(err) => panic!("running setpriv failed unexpectedly: {err}"),
    }
}
