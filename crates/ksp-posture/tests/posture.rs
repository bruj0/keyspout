//! Acceptance tests for posture reporting — criteria 6, 7 and 8.
//!
//! These are pure decisions over declared inputs, so they need no subprocess and
//! no privilege: the whole point of `PostureDecision::for_requirement` is that it
//! is a total function of the confinement posture and the requirement.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use ksp_posture::adapters::confinement::LandlockConfinement;
use ksp_posture::barrier::BarrierKind;
use ksp_posture::memlock::MemlockObservation;
use ksp_posture::posture::{
    BackendShape, BarrierPosture, ConfinementPosture, ConfinementState, HostPosture,
    LandlockObservation, PostureDecision, Requirement, RunDecision,
};
use ksp_types::{GuaranteeLevel, LeaseCapability, admits};

/// The adapter name and level an enforced posture must carry.
const LANDLOCK_NAME: &str = LandlockConfinement::NAME;

/// The measured LXC limit, so the tests use the deployment class they describe.
fn lxc_memlock() -> MemlockObservation {
    MemlockObservation {
        soft_bytes: Some(8 * 1024 * 1024),
        hard_bytes: Some(8 * 1024 * 1024),
    }
}

fn modern_kernel() -> LandlockObservation {
    LandlockObservation::Available {
        effective_abi: 8,
        kernel_abi: None,
    }
}

/// Criterion 6 (optional half) — an unavailable Landlock produces a **warning** on
/// an optional run.
#[test]
fn unavailable_landlock_warns_on_an_optional_run() {
    let posture = ConfinementPosture::unavailable(LandlockObservation::NotImplemented, false);
    let decision = PostureDecision::for_requirement(&posture, Requirement::Optional);

    assert_eq!(
        decision,
        RunDecision::ProceedWithWarning,
        "an optional run must warn rather than refuse (FR-040)"
    );
    assert!(decision.warns());
    assert!(decision.may_proceed());
}

/// Criterion 6 (required half) — the same posture produces a **refusal** on a
/// required run.
///
/// The two halves are separate tests sharing one posture constructor, so a change
/// that made both warn (or both refuse) would fail one of them.
#[test]
fn unavailable_landlock_refuses_on_a_required_run() {
    let posture = ConfinementPosture::unavailable(LandlockObservation::NotImplemented, true);
    let decision = PostureDecision::for_requirement(&posture, Requirement::Required);

    assert!(
        matches!(decision, RunDecision::Refuse { .. }),
        "a required run must refuse when confinement is unavailable (FR-040), got {decision:?}"
    );
    assert!(!decision.may_proceed());
    assert!(!decision.warns());
}

/// The two halves differ on the *same* posture, which is what makes the
/// requirement — not the posture — the deciding input.
#[test]
fn the_requirement_is_what_separates_a_warning_from_a_refusal() {
    let posture = ConfinementPosture::unavailable(LandlockObservation::NotEnabled, false);
    assert_ne!(
        PostureDecision::for_requirement(&posture, Requirement::Optional),
        PostureDecision::for_requirement(&posture, Requirement::Required)
    );
}

/// A weakened posture is not rounded up to enforced: it warns when optional and
/// refuses when required, exactly like an unavailable one. Partial enforcement
/// that reports "enforced" is the failure mode `HardRequirement` exists to
/// prevent.
#[test]
fn a_weakened_posture_is_not_treated_as_enforced() {
    let posture =
        ConfinementPosture::weakened(modern_kernel(), true, LANDLOCK_NAME, GuaranteeLevel::Full);
    assert_eq!(posture.state, ConfinementState::Weakened);
    assert!(
        !matches!(
            PostureDecision::for_requirement(&posture, Requirement::Required),
            RunDecision::Proceed
        ),
        "a partially enforced ruleset must not let a required run proceed"
    );
}

/// Criterion 7 — a required-confinement run on a remote `NativeExpiry` backend is
/// **not** rejected solely for missing local Landlock.
///
/// The independence is structural: `for_requirement` takes no backend argument. So
/// this test asserts two things separately — that the confinement decision refuses,
/// and that the *backend* admission is unaffected — and that the second is
/// computed by a different function over a different type.
#[test]
fn missing_local_landlock_does_not_reject_a_remote_native_expiry_backend() {
    let posture = ConfinementPosture::unavailable(LandlockObservation::NotImplemented, true);

    // The confinement decision, computed with no knowledge of the backend.
    let confinement = PostureDecision::for_requirement(&posture, Requirement::Required);
    assert!(
        matches!(confinement, RunDecision::Refuse { .. }),
        "a required local run must refuse without confinement"
    );

    // Backend admission, computed with no knowledge of the confinement. A remote
    // NativeExpiry backend admits its lease regardless of local Landlock.
    let capability = LeaseCapability::NativeExpiry;
    assert!(
        admits(&capability, Duration::from_secs(60)),
        "a qualifying remote NativeExpiry backend must still admit its lease"
    );
    assert!(
        admits(&capability, Duration::from_secs(86_400)),
        "and any other duration, because the backend enforces the deadline itself"
    );

    // Neither decision can be derived from the other: the refused confinement and
    // the admitted lease coexist.
    assert!(matches!(confinement, RunDecision::Refuse { .. }));
    assert!(admits(&capability, Duration::from_secs(60)));

    // The backend shape is a distinct axis; naming it changes nothing about the
    // confinement decision, which cannot see it.
    assert_ne!(BackendShape::Local, BackendShape::RemoteWithNativeExpiry);
    assert_eq!(
        confinement,
        PostureDecision::for_requirement(&posture, Requirement::Required),
        "the confinement decision must be reproducible without a backend"
    );
}

/// Criterion 8 — `ConfinementPosture` and `BarrierPosture` are reported
/// separately: a run can be **fully confined** while its barrier is
/// `SealedMemfd`.
#[test]
fn a_run_can_be_fully_confined_with_a_sealed_memfd_barrier() {
    let posture = HostPosture::new(
        ConfinementPosture::enforced(modern_kernel(), true, LANDLOCK_NAME, GuaranteeLevel::Full),
        BarrierPosture::of(BarrierKind::SealedMemfd, lxc_memlock()),
    );

    assert_eq!(
        posture.confinement.state,
        ConfinementState::Enforced,
        "the confinement half is fully enforced"
    );
    assert_eq!(
        posture.barrier.kind,
        Some(BarrierKind::SealedMemfd),
        "the barrier half is the weaker mechanism"
    );
    assert!(
        !posture.barrier.is_primary(),
        "the fallback must not be reported as the primary barrier"
    );

    // The strongest statement: a fully confined run passes a required decision,
    // while its barrier is still the fallback. If either half implied the other,
    // this combination could not exist.
    assert_eq!(
        PostureDecision::for_requirement(&posture.confinement, Requirement::Required),
        RunDecision::Proceed
    );
    assert_ne!(posture.barrier.kind, Some(BarrierKind::MemfdSecret));
}

/// The inverse must be representable too, otherwise "separate" would mean "one
/// implies the other".
#[test]
fn a_run_can_have_the_primary_barrier_without_any_confinement() {
    let posture = HostPosture::new(
        ConfinementPosture::unavailable(LandlockObservation::NotImplemented, false),
        BarrierPosture::of(BarrierKind::MemfdSecret, lxc_memlock()),
    );

    assert_eq!(posture.confinement.state, ConfinementState::Unavailable);
    assert!(posture.barrier.is_primary());
}

/// The rendered posture keeps the two facts apart, so a status line cannot merge
/// them into one claim.
#[test]
fn the_rendered_posture_names_both_facts_separately() {
    let posture = HostPosture::new(
        ConfinementPosture::enforced(modern_kernel(), true, LANDLOCK_NAME, GuaranteeLevel::Full),
        BarrierPosture::unavailable(lxc_memlock()),
    );

    let rendered = posture.to_string();
    assert!(
        rendered.contains("confinement enforced"),
        "got {rendered:?}"
    );
    assert!(rendered.contains("barrier unavailable"), "got {rendered:?}");
    assert!(
        rendered.contains("LimitMEMLOCK="),
        "the barrier half must carry the observed limit; got {rendered:?}"
    );
    assert!(
        rendered.contains("HardRequirement"),
        "the confinement half must carry the compatibility level in force; got {rendered:?}"
    );
}

/// The posture types must report the mechanism, not a generic "secure" claim. A
/// rendered posture that said "secure" would be the exact overstatement the
/// subsystem exists to prevent.
#[test]
fn no_posture_rendering_claims_security_or_erasure() {
    let postures = [
        HostPosture::new(
            ConfinementPosture::enforced(
                modern_kernel(),
                true,
                LANDLOCK_NAME,
                GuaranteeLevel::Full,
            ),
            BarrierPosture::of(BarrierKind::MemfdSecret, lxc_memlock()),
        ),
        HostPosture::new(
            ConfinementPosture::weakened(
                modern_kernel(),
                false,
                LANDLOCK_NAME,
                GuaranteeLevel::Full,
            ),
            BarrierPosture::of(BarrierKind::SealedMemfd, lxc_memlock()),
        ),
        HostPosture::new(
            ConfinementPosture::unavailable(LandlockObservation::NotImplemented, false),
            BarrierPosture::unavailable(lxc_memlock()),
        ),
    ];

    for posture in postures {
        let rendered = posture.to_string().to_lowercase();
        for forbidden in ["secure", "authenticated", "erased", "erasure"] {
            assert!(
                !rendered.contains(forbidden),
                "a posture must not claim {forbidden:?}; rendered {rendered:?}"
            );
        }
    }
}

/// Landlock's own observation is reported separately from what this run's ruleset
/// enforced, so "the host supports Landlock" never stands in for "this run is
/// confined".
#[test]
fn the_landlock_observation_is_distinct_from_the_enforced_state() {
    let supported_but_unenforced = ConfinementPosture {
        state: ConfinementState::Unavailable,
        landlock: modern_kernel(),
        required: false,
        adapter: None,
        guarantee: ksp_types::GuaranteeLevel::None,
    };
    assert!(supported_but_unenforced.landlock.is_available());
    assert_eq!(
        supported_but_unenforced.state,
        ConfinementState::Unavailable
    );
    assert_eq!(supported_but_unenforced.landlock.effective_abi(), Some(8));
    assert_eq!(
        supported_but_unenforced.compat_level_name(),
        "SoftRequirement"
    );
}
