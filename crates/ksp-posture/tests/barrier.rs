//! Acceptance tests for the memory barrier and the lockability check
//! (Misfit K).
//!
//! Criteria 4 and 5 live here. Both need a *lowered* `RLIMIT_MEMLOCK`, and the
//! limit is per-process, so each probe re-executes this binary in a fresh process
//! — the same harness the confinement tests use, for the same reason: a probe must
//! not leave the shared test process with a lowered limit or an unmapped secret
//! region.
//
// The two probes lower `RLIMIT_MEMLOCK` through `libc::setrlimit`, which is an
// FFI call and therefore needs `unsafe`. The workspace denies `unsafe_code`, so
// the exemption is scoped to this test binary — the production library keeps the
// strict setting and confines its own `unsafe` to one audited module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(unsafe_code)]

use std::process::{Command, Output};

use ksp_posture::barrier::{self, BarrierKind, BarrierPreference};
use ksp_posture::memlock::MemlockObservation;

/// The remedy substring a refusal must carry on the host it runs on.
///
/// FR-012: the sentence differs per platform because the knob does. Linux edits
/// the systemd directive; macOS raises the `launchctl` limit, because there is
/// no systemd unit there to change.
fn expected_remedy() -> &'static str {
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

// ---------------------------------------------------------------------------
// Probe: a lowered RLIMIT_MEMLOCK must refuse rather than degrade
// ---------------------------------------------------------------------------

/// Probe for criterion 4.
///
/// Lowers `RLIMIT_MEMLOCK` to 64 KiB, then asks for a 1 MiB region. The kernel
/// must refuse, and the refusal must name the remedy this platform has. Writes the outcome to a
/// file the parent names, because the probe may be unable to print.
#[test]
fn probe_mlock_refusal() {
    let Ok(report_path) = std::env::var("KSP_PROBE_REPORT") else {
        return;
    };

    let mut result = String::new();

    // A tiny hard cap, so neither mechanism can satisfy a 1 MiB request.
    let limit = libc::rlimit {
        rlim_cur: 64 * 1024,
        rlim_max: 64 * 1024,
    };
    // SAFETY (test-only): `limit` is a fully initialized `libc::rlimit` that
    // outlives the call, and `setrlimit` only reads it.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
    if rc != 0 {
        result.push_str(&format!(
            "setrlimit-failed={}\n",
            std::io::Error::last_os_error()
        ));
        std::fs::write(&report_path, result).expect("write the report");
        return;
    }

    let observed = MemlockObservation::read().expect("the lowered limit must be readable");
    result.push_str(&format!("observed={observed}\n"));

    match barrier::allocate(1024 * 1024, BarrierPreference::AllowFallback) {
        Ok(region) => {
            // Reaching here means a 1 MiB region exists under a 64 KiB cap, which
            // is exactly the silent degradation FR-009 forbids.
            result.push_str(&format!("allocated={:?}\n", region.kind()));
        }
        Err(err) => {
            // The refusal is written on its own line, prefixed, so the parent can
            // assert the directive appears *in the refusal* and not merely in the
            // `observed=` line above it. Without that separation the assertion
            // would pass even if the refusal message had lost the directive.
            result.push_str(&format!("refusal-line={err}\n"));
            result.push_str(&format!("absent={}\n", err.is_mechanism_absent()));
        }
    }

    std::fs::write(&report_path, result).expect("write the report");
}

/// Whether `RLIMIT_MEMLOCK` actually binds this process.
///
/// It does not for `root`: `CAP_IPC_LOCK` bypasses the limit, so a probe that
/// lowers the cap to 64 KiB still locks a 1 MiB region. The suite runs as `root`
/// for the cross-principal tests, so these probes are only meaningful where the
/// limit binds — and they say so rather than asserting the opposite of what they
/// measured. The refusal's wording is covered for every uid by
/// `ksp_posture::memlock`'s unit tests, which need no privilege.
fn memlock_limit_binds() -> bool {
    // SAFETY (test-only): `geteuid` takes no arguments and touches no memory.
    #[allow(unsafe_code)]
    let euid = unsafe { libc::geteuid() };
    euid != 0
}

/// Criterion 4 — an `mlock` failure aborts naming the remedy and the observed value, and does
/// not fall back to unlocked memory.
///
/// Asserts the platform's remedy substring, and asserts the *negative*: no
/// region was handed back. A test that only checked the message would pass if the
/// code also returned an unlocked region.
#[test]
fn an_unlockable_region_aborts_naming_limitmemlock_and_returns_no_region() {
    if !memlock_limit_binds() {
        return;
    }
    let dir = tempfile::tempdir().expect("create a temporary directory");
    let report_path = dir.path().join("mlock-report.txt");

    let output = run_probe(
        "probe_mlock_refusal",
        &[("KSP_PROBE_REPORT", &report_path.display().to_string())],
    );
    assert!(
        output.status.success(),
        "the probe must exit cleanly; status: {:?}; stdout: {}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = std::fs::read_to_string(&report_path).expect("the probe must write its report");

    assert!(
        !report.contains("setrlimit-failed"),
        "the probe must be able to lower RLIMIT_MEMLOCK; report: {report}"
    );
    assert!(
        report.contains("65280") || report.contains("65536"),
        "the observed limit must be the lowered cap; report: {report}"
    );
    let refusal_line = report
        .lines()
        .find_map(|line| line.strip_prefix("refusal-line="))
        .unwrap_or_else(|| panic!("the region must be refused, not allocated; report: {report}"));
    assert!(
        refusal_line.contains(expected_remedy()),
        "the refusal itself must name the remedy this platform has (FR-012), not only the \
         observed-limit line; refusal: {refusal_line:?}"
    );
    assert!(
        refusal_line.contains("65536") || refusal_line.contains("65280"),
        "the refusal must state the current limit; refusal: {refusal_line:?}"
    );
    assert!(
        !report.contains("allocated="),
        "no region may be handed back when the lock failed; report: {report}"
    );
    assert!(
        !report.contains("absent=true"),
        "a too-small limit is not an absent mechanism, so it must not select the \
         fallback; report: {report}"
    );
}

// ---------------------------------------------------------------------------
// Probe: require the primary barrier on a host that cannot provide it
// ---------------------------------------------------------------------------

/// Probe for the `RequireSecret` refusal.
#[test]
fn probe_require_secret_under_pressure() {
    let Ok(report_path) = std::env::var("KSP_PROBE_REPORT") else {
        return;
    };

    let mut result = String::new();
    let limit = libc::rlimit {
        rlim_cur: 64 * 1024,
        rlim_max: 64 * 1024,
    };
    // SAFETY (test-only): as in `probe_mlock_refusal` — `limit` outlives the
    // call and `setrlimit` only reads it.
    #[allow(unsafe_code)]
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) } != 0 {
        result.push_str("setrlimit-failed\n");
        std::fs::write(&report_path, result).expect("write the report");
        return;
    }

    match barrier::allocate(1024 * 1024, BarrierPreference::RequireSecret) {
        Ok(region) => result.push_str(&format!("allocated={:?}\n", region.kind())),
        Err(err) => result.push_str(&format!("refusal-line={err}\n")),
    }
    std::fs::write(&report_path, result).expect("write the report");
}

/// A run that requires the primary barrier must refuse rather than demote onto
/// ordinary memory.
#[test]
fn requiring_the_primary_barrier_refuses_instead_of_demoting() {
    if !memlock_limit_binds() {
        return;
    }
    let dir = tempfile::tempdir().expect("create a temporary directory");
    let report_path = dir.path().join("require-report.txt");

    let output = run_probe(
        "probe_require_secret_under_pressure",
        &[("KSP_PROBE_REPORT", &report_path.display().to_string())],
    );
    assert!(
        output.status.success(),
        "the probe must exit cleanly; status: {:?}; stdout: {}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = std::fs::read_to_string(&report_path).expect("the probe must write its report");
    assert!(
        report.contains("refusal-line="),
        "a required barrier must refuse when it cannot be established; report: {report}"
    );
    assert!(
        !report.contains("allocated="),
        "a required barrier must never degrade onto the fallback; report: {report}"
    );
}

// ---------------------------------------------------------------------------
// Criterion 5 — the fallback is reported as weaker
// ---------------------------------------------------------------------------

/// Criterion 5 — the sealed-`memfd` fallback is reported as a **weaker** barrier,
/// never as equivalent to `memfd_secret`.
///
/// The two postures must differ, and the difference must be observable in three
/// independent places: the kind, whether that kind is primary, and whether it
/// supports sealing. A test that compared only the kind would pass if `is_primary`
/// were implemented as `true` for both.
#[test]
fn the_sealed_memfd_fallback_is_reported_as_a_weaker_barrier() {
    let region = barrier::allocate(4096, BarrierPreference::AllowFallback)
        .expect("a barrier must be obtainable on this host");

    // Assert the properties that make the two kinds non-equivalent, on the kind
    // the host actually produced, without assuming which one that is. The
    // closed set has three mechanisms: the two `memfd` ones and the portable
    // `mlock` one, and a host with neither `memfd` produces the third.
    let actual = region.kind();
    assert!(
        matches!(
            actual,
            BarrierKind::MemfdSecret | BarrierKind::SealedMemfd | BarrierKind::Mlock
        ),
        "the barrier kind must be one of the declared mechanisms, got {actual:?}"
    );

    // The two kinds must disagree on both ordering facts.
    assert!(
        BarrierKind::MemfdSecret.is_primary(),
        "memfd_secret is the primary barrier"
    );
    assert!(
        !BarrierKind::SealedMemfd.is_primary(),
        "the sealed-memfd fallback must never report itself as primary"
    );
    assert_ne!(
        BarrierKind::MemfdSecret.is_primary(),
        BarrierKind::SealedMemfd.is_primary()
    );

    // `mlock` is a real mechanism and a weaker one, so it is never primary
    // either. A run that chose it must not be reported as holding key
    // material out of the kernel's reach.
    assert!(
        !BarrierKind::Mlock.is_primary(),
        "mlock must never report itself as the primary barrier"
    );

    // `memfd_secret` does not support F_SEAL; claiming it does would describe a
    // mechanism the kernel does not have (DEVELOPMENT.md §7.1).
    assert!(
        !BarrierKind::MemfdSecret.supports_sealing(),
        "memfd_secret has no F_SEAL support"
    );
    assert!(
        BarrierKind::SealedMemfd.supports_sealing(),
        "the fallback's whole point is the seals it applies"
    );
    assert!(
        !BarrierKind::Mlock.supports_sealing(),
        "mlock has no F_SEAL support: it locks pages, it does not seal a file"
    );

    // And the identity strings differ, so a status line cannot render them the
    // same way by accident.
    assert_ne!(
        BarrierKind::MemfdSecret.as_str(),
        BarrierKind::SealedMemfd.as_str()
    );
    assert_ne!(
        BarrierKind::MemfdSecret.as_str(),
        BarrierKind::Mlock.as_str()
    );

    // The region under test reports the kind it produced, and the reported region
    // exposes the locks/dump facts rather than assuming them.
    assert_eq!(region.kind(), actual);
    assert!(
        region.as_bytes().iter().all(|byte| *byte == 0),
        "the region must start zeroed"
    );
}

/// The fallback must still be lockable: a sealed `memfd` under a permissive limit
/// is ordinary memory that *is* locked, and the region reports it.
///
/// The dump-exclusion facts are Linux-only, because the mechanisms that
/// provide them are: Darwin has no `MADV_DONTDUMP` and no `PR_SET_DUMPABLE`. A
/// host without them must report that the exclusion was **not** applied rather
/// than claiming it was — a region that reported itself as excluded from dumps
/// on a host that cannot exclude it would be a false security claim.
#[test]
fn a_sealed_memfd_region_reports_its_security_properties() {
    let region = barrier::allocate(8192, BarrierPreference::AllowFallback)
        .expect("a barrier must be obtainable on this host");

    assert_eq!(region.as_bytes().len(), 8192);
    assert!(
        region.is_guarded(),
        "guard pages must bracket the region on a host that permits mprotect"
    );

    #[cfg(target_os = "linux")]
    {
        assert!(
            region.is_excluded_from_dumps(),
            "MADV_DONTDUMP must be applied to the region"
        );
        // `PR_SET_DUMPABLE=0` is process-wide and one-way, so it is applied once
        // and reported; asserting it here is safe because it does not affect
        // assertions.
        assert!(region.is_undumpable(), "PR_SET_DUMPABLE=0 must be applied");
    }
    #[cfg(target_os = "macos")]
    {
        assert!(
            !region.is_excluded_from_dumps(),
            "this host has no MADV_DONTDUMP, so the region must not claim to be \
             excluded from dumps"
        );
        // Both dump controls exist on Darwin, and the attach refusal is
        // `ptrace(PT_DENY_ATTACH)` rather than `prctl`. The region reports each
        // control, so a host that holds one and not the other is visible here
        // instead of being averaged into one boolean.
        assert!(
            region.undumpable().core_limit.is_applied(),
            "RLIMIT_CORE = 0 must be applied"
        );
        assert!(
            region.undumpable().ptrace.is_applied(),
            "PT_DENY_ATTACH must be applied"
        );
        assert!(
            region.is_undumpable(),
            "both controls applied, so the process cannot be dumped by either route"
        );
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        assert!(
            !region.is_excluded_from_dumps(),
            "this host has no MADV_DONTDUMP, so the region must not claim to be \
             excluded from dumps"
        );
        assert!(
            !region.is_undumpable(),
            "this target provides neither control, so the process must not claim \
             to be undumpable"
        );
    }

    assert!(
        region.observed_memlock().admits_bytes(8192),
        "the region must fit the observed limit"
    );
}

/// A region is wiped before its mapping dies, so the bytes are not left in the
/// pages for whatever maps them next.
#[test]
fn a_region_is_wiped_when_dropped() {
    let mut region =
        barrier::allocate(1024, BarrierPreference::AllowFallback).expect("allocate a region");
    region.as_bytes_mut().fill(0xAA);
    assert!(region.as_bytes().iter().all(|byte| *byte == 0xAA));

    region.wipe();
    assert!(
        region.as_bytes().iter().all(|byte| *byte == 0),
        "an explicit wipe must zero every byte"
    );
}
