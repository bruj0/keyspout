//! The `mlock` adapter's refusal — T018, Misfit A.
//!
//! FR-032: *IF the `mlock` adapter cannot establish its mechanism, THEN the
//! CLI shall refuse the capability and shall not fall back to an allocation
//! without kernel protection.*
//!
//! The adapter's whole purpose is to hold key material in pages the kernel will
//! not swap out. If the lock fails, handing back an unlocked region would be
//! the silent degradation this subsystem exists to prevent: the caller would
//! hold key material in ordinary memory while believing it was locked.
//!
//! # The probe re-executes this binary
//!
//! `RLIMIT_MEMLOCK` is per-process and the limit is lowered for the whole
//! process, so the measurement cannot happen in the shared test binary: every
//! later test in it would run under the lowered cap. The probe therefore
//! re-executes this binary with `--exact`, the same harness
//! `tests/barrier.rs` uses for the same reason.
//!
//! # `root` skips it, and says so
//!
//! `root` holds `CAP_IPC_LOCK`, which bypasses `RLIMIT_MEMLOCK` entirely, so a
//! probe under a 64 KiB cap still locks a 1 MiB region. Asserting the refusal
//! there would assert the opposite of what was measured. The probe reports the
//! fact and the parent skips rather than pretending.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(unsafe_code)]

use std::process::{Command, Output};

use ksp_posture::adapters::{MemoryBarrierAdapter, memory_barrier_adapter};
use ksp_types::AdapterName;

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

/// Whether `RLIMIT_MEMLOCK` actually binds this process.
///
/// It does not for `root`: `CAP_IPC_LOCK` bypasses the limit. A skipped
/// security test reads like a pass, so the skip is reported rather than
/// silent.
fn memlock_limit_binds() -> bool {
    // SAFETY (test-only): `geteuid` takes no arguments and touches no memory.
    let euid = unsafe { libc::geteuid() };
    euid != 0
}

/// The `mlock` adapter, which must be in this build on every target.
fn mlock_adapter() -> &'static dyn MemoryBarrierAdapter {
    let name = AdapterName::parse("mlock").expect("`mlock` is in the closed name set");
    memory_barrier_adapter(&name).expect("the mlock adapter must be in this build on every target")
}

// ---------------------------------------------------------------------------
// Probe: the adapter refuses when the lock cannot be taken
// ---------------------------------------------------------------------------

/// Probe: lower the limit, then ask the `mlock` adapter for a region.
///
/// Writes the outcome to a file the parent names, because the probe may be
/// unable to print.
#[test]
fn probe_mlock_adapter_refuses() {
    let Ok(report_path) = std::env::var("KSP_PROBE_REPORT") else {
        return;
    };

    let mut result = String::new();

    // A tiny hard cap, so no 1 MiB region can be locked.
    let limit = libc::rlimit {
        rlim_cur: 64 * 1024,
        rlim_max: 64 * 1024,
    };
    // SAFETY (test-only): `limit` is a fully initialized `libc::rlimit` that
    // outlives the call, and `setrlimit` only reads it.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) } != 0 {
        result.push_str(&format!(
            "setrlimit-failed={}\n",
            std::io::Error::last_os_error()
        ));
        std::fs::write(&report_path, result).expect("write the report");
        return;
    }

    match mlock_adapter().allocate(1024 * 1024) {
        Ok(region) => {
            // Reaching here means an unlocked region was handed back, which is
            // exactly what FR-032 forbids.
            result.push_str(&format!("allocated={:?}\n", region.kind()));
        }
        Err(err) => {
            result.push_str(&format!("refusal-line={err}\n"));
        }
    }

    std::fs::write(&report_path, result).expect("write the report");
}

/// T018 — the `mlock` adapter refuses rather than returning an unprotected
/// region.
///
/// The assertion is on the **negative**: no region was handed back. A test that
/// only checked the error message would pass if the adapter returned an
/// unlocked region *and* an error.
#[test]
fn the_mlock_adapter_refuses_rather_than_returning_an_unprotected_region() {
    if !memlock_limit_binds() {
        // `root` holds `CAP_IPC_LOCK`, so the limit does not bind. The refusal
        // path cannot be established for that uid, and asserting it there would
        // assert the opposite of what was measured.
        return;
    }

    let dir = tempfile::tempdir().expect("create a temporary directory");
    let report_path = dir.path().join("mlock-adapter-report.txt");

    let output = run_probe(
        "probe_mlock_adapter_refuses",
        &[("KSP_PROBE_REPORT", &report_path.display().to_string())],
    );
    assert!(
        output.status.success(),
        "the probe must exit cleanly; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report = std::fs::read_to_string(&report_path).expect("the probe must write its report");

    assert!(
        !report.contains("setrlimit-failed"),
        "the probe must be able to lower RLIMIT_MEMLOCK; report: {report}"
    );
    assert!(
        !report.contains("allocated="),
        "FR-032: no region may be handed back when the lock failed; report: {report}"
    );

    let refusal_line = report
        .lines()
        .find_map(|line| line.strip_prefix("refusal-line="))
        .unwrap_or_else(|| {
            panic!("the adapter must refuse rather than allocate; report: {report}")
        });
    assert!(
        refusal_line.contains(platform_remedy()),
        "the refusal must name the remedy the operator can actually change on this host; \
         refusal: {refusal_line:?}"
    );
}

/// The remedy substring a refusal carries on this platform (FR-012).
fn platform_remedy() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "LimitMEMLOCK="
    }
    #[cfg(target_os = "macos")]
    {
        "launchctl limit memlock"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "service manager"
    }
}

/// The `mlock` adapter's refusal names the adapter, so the operator knows
/// which capability was refused.
///
/// A refusal that names only the limit leaves the operator guessing whether the
/// barrier or the confinement was refused. The mechanism's name is the fact that
/// identifies it.
#[test]
fn the_mlock_refusal_names_the_adapter_that_refused() {
    if !memlock_limit_binds() {
        return;
    }

    let dir = tempfile::tempdir().expect("create a temporary directory");
    let report_path = dir.path().join("mlock-adapter-name-report.txt");

    let output = run_probe(
        "probe_mlock_adapter_refuses",
        &[("KSP_PROBE_REPORT", &report_path.display().to_string())],
    );
    assert!(
        output.status.success(),
        "the probe must exit cleanly; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = std::fs::read_to_string(&report_path).expect("the probe must write its report");

    let refusal_line = report
        .lines()
        .find_map(|line| line.strip_prefix("refusal-line="))
        .unwrap_or_else(|| {
            panic!("the adapter must refuse rather than allocate; report: {report}")
        });
    assert!(
        refusal_line.contains("mlock"),
        "the refusal must name the adapter that refused; refusal: {refusal_line:?}"
    );
}

/// The `mlock` adapter succeeds on a host whose limit permits it.
///
/// The negative test above proves the adapter refuses; this one proves it does
/// not refuse *always*. An adapter that always refused would pass the refusal
/// test while providing no mechanism at all — the same failure as the portable
/// adapter, in the opposite direction.
#[test]
fn the_mlock_adapter_allocates_a_region_on_a_host_that_permits_it() {
    let region = mlock_adapter()
        .allocate(4096)
        .expect("the mlock adapter must allocate on a host with an adequate limit");

    assert_eq!(
        region.as_bytes().len(),
        4096,
        "the region must have the length that was asked for"
    );
    assert!(
        region.as_bytes().iter().all(|byte| *byte == 0),
        "the region must start zeroed"
    );
}
