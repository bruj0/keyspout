//! The acceptance criteria for WP10, driven through the public API.
//!
//! Most of these tests are about the *absence* of a claim, and absence is the
//! easiest kind of property to test vacuously: a report that omitted the lag
//! field entirely would pass a "no number is reported" assertion. So the lag and
//! the retention are asserted as *present and unknown*, and the forbidden-
//! phrasing test runs over the serialized report rather than over prose.
//!
//! A test reports a failure by panicking, and the panic message is what says why.
//! The production code keeps the strict lints.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use ksp_backend::admission::{Classification, FileEvidence, classify_file};
use ksp_backend::proof::{GateRefusal, ProofObservation};
use ksp_backend::status::{
    ArmingDisclosure, AuditDisclosure, BindingDisclosure, CanaryResult, CleanupLag, Freshness,
    PASSPHRASE_SENTENCE, PermissionDisclosure, PostureDisclosure, ProofDisclosure, Retention,
    StatusDisclosure, StatusFacts, StatusReport, admission_floor,
};
use ksp_posture::{
    BarrierKind, BarrierPosture, ConfinementPosture, ConfinementState, LandlockObservation,
    MemlockObservation,
};
use ksp_types::LeaseCapability;

/// The whole document, with an empty layout measurement.
///
/// The permission disclosure is S1's: it has its own tests in `ksp-posture` and
/// `ksp`. This file is about what the status surface says, so the measurement
/// is empty and the shape of the document is what is asserted.
fn report_builder(
    classification: &Classification,
    posture: PostureDisclosure,
    freshness: Freshness,
    canary: Option<CanaryResult>,
) -> StatusReport {
    ksp_backend::status::report(
        classification,
        StatusFacts {
            arming: ArmingDisclosure::None {
                reason: "no verified arming record names this deployment".to_string(),
            },
            proof: ProofDisclosure {
                newest_success: None,
                freshness: None,
                absent_reason: Some("no sweep proof exists".to_string()),
                newest_failure: None,
                malformed: 0,
            },
            audit: AuditDisclosure {
                chains: Vec::new(),
                records: 0,
                segments: 0,
                unreadable: 0,
                unattributed: 0,
                broken: None,
                absent_reason: Some("no audit log exists here".to_string()),
            },
            posture,
            freshness,
            canary,
            permissions: PermissionDisclosure::new(Vec::new()),
            binding: BindingDisclosure::None,
            capabilities: Vec::new(),
        },
    )
}

fn day() -> Duration {
    Duration::from_secs(24 * 3_600)
}

/// A backend that declares a daily sweep.
fn scheduled() -> Classification {
    Classification {
        capability: LeaseCapability::Scheduled { interval: day() },
        mechanism: "temporary key with a declared sweep cadence",
        declared_cadence: Some(day()),
        proven_cadence: Some(day()),
        proof_age: Some(0),
        cleanup_lag: None,
        retention: None,
        state: None,
    }
}

fn confined() -> ConfinementPosture {
    ConfinementPosture {
        state: ConfinementState::Enforced,
        landlock: LandlockObservation::Available {
            effective_abi: 8,
            kernel_abi: None,
        },
        required: true,
        adapter: Some("landlock"),
        guarantee: ksp_types::GuaranteeLevel::Full,
    }
}

fn weakened() -> ConfinementPosture {
    ConfinementPosture {
        state: ConfinementState::Weakened,
        landlock: LandlockObservation::NotEnabled,
        required: false,
        adapter: None,
        guarantee: ksp_types::GuaranteeLevel::None,
    }
}

fn memlock() -> MemlockObservation {
    MemlockObservation {
        soft_bytes: Some(8 * 1024 * 1024),
        hard_bytes: Some(8 * 1024 * 1024),
    }
}

/// Both dump controls applied, which is the shape a protected host reports.
///
/// The posture is a fact about the process, not about the store, so these tests
/// fix it here rather than deriving it from the host they run on.
fn undumpable() -> ksp_posture::UndumpablePosture {
    ksp_posture::UndumpablePosture {
        core_limit: ksp_posture::ControlOutcome::Applied,
        ptrace: ksp_posture::ControlOutcome::Applied,
    }
}

fn posture(confinement: ConfinementPosture, barrier: BarrierPosture) -> PostureDisclosure {
    PostureDisclosure {
        confinement,
        barrier,
        undumpable: undumpable(),
    }
}

fn unconfined_barrier() -> BarrierPosture {
    BarrierPosture::unavailable(memlock())
}

fn good() -> StatusReport {
    report_builder(
        &scheduled(),
        posture(
            confined(),
            BarrierPosture::of(BarrierKind::SealedMemfd, memlock()),
        ),
        Freshness::Available { revision: 7 },
        None,
    )
}

// ---------------------------------------------------------------------------
// Criteria 1, 2 — capability, mechanism and the evidence behind them
// ---------------------------------------------------------------------------

#[test]
fn status_reports_the_effective_capability_and_its_mechanism() {
    let report = good();
    assert_eq!(
        report.backend.capability,
        LeaseCapability::Scheduled { interval: day() }
    );
    assert_eq!(
        report.backend.mechanism,
        "temporary key with a declared sweep cadence"
    );
}

#[test]
fn status_reports_the_evidence_the_capability_came_from() {
    let report = good();
    let evidence = &report.backend.evidence;
    assert!(
        evidence.contains("declared cadence"),
        "the evidence names what it read: {evidence}"
    );
    assert!(
        evidence.contains("86400"),
        "and quotes the cadence it found: {evidence}"
    );
}

#[test]
fn a_file_backend_with_no_mechanism_says_so_in_its_evidence() {
    // The classification is the authority; this surface quotes it rather than
    // re-deriving or softening it.
    let classification = classify_file(FileEvidence::default());
    let disclosure = StatusDisclosure::from_classification(&classification);
    assert_eq!(disclosure.capability, LeaseCapability::None);
    assert!(
        disclosure.evidence.contains("no declared cadence"),
        "{}",
        disclosure.evidence
    );
}

#[test]
fn the_proven_cadence_is_reported_beside_the_declared_one() {
    // FR-057: a schedule that says 60 s and a run that proves 300 s are both named,
    // and admission uses the proven one. Averaging or picking the declaration would
    // hide the disagreement.
    let classification = classify_file(FileEvidence {
        declared_cadence: Some(Duration::from_secs(60)),
        proof: Some(ProofObservation {
            interval: Duration::from_secs(300),
            age: 10,
            grace: 150,
        }),
        refusal: None,
    });
    assert_eq!(
        classification.capability,
        LeaseCapability::Scheduled {
            interval: Duration::from_secs(300)
        }
    );
    assert_eq!(
        classification.declared_cadence,
        Some(Duration::from_secs(60))
    );
    assert_eq!(
        classification.proven_cadence,
        Some(Duration::from_secs(300))
    );
    assert_eq!(classification.proof_age, Some(10));

    let disclosure = StatusDisclosure::from(&classification);
    assert_eq!(disclosure.declared_cadence_secs, Some(60));
    assert_eq!(disclosure.proven_cadence_secs, Some(300));
    assert_eq!(disclosure.proof_age_secs, Some(10));
    assert_eq!(
        disclosure.admission_minimum_secs,
        Some(600),
        "2 x proven, not 2 x declared"
    );
    assert!(
        disclosure.evidence.contains("declared cadence 60s"),
        "{}",
        disclosure.evidence
    );
    assert!(
        disclosure.evidence.contains("proven cadence 300s"),
        "{}",
        disclosure.evidence
    );
}

#[test]
fn a_stale_proof_reports_its_age_without_admitting() {
    let classification = classify_file(FileEvidence {
        declared_cadence: Some(Duration::from_secs(300)),
        proof: Some(ProofObservation {
            interval: Duration::from_secs(300),
            age: 900,
            grace: 150,
        }),
        refusal: None,
    });
    assert_eq!(classification.capability, LeaseCapability::None);
    assert_eq!(
        classification.proven_cadence,
        Some(Duration::from_secs(300))
    );
    assert_eq!(classification.proof_age, Some(900));

    let disclosure = StatusDisclosure::from(&classification);
    assert_eq!(disclosure.proven_cadence_secs, Some(300));
    assert_eq!(disclosure.proof_age_secs, Some(900));
    assert_eq!(
        disclosure.admission_minimum_secs, None,
        "a stale proof admits nothing, so there is no floor to print"
    );
}

#[test]
fn a_declaration_without_a_proof_is_none_and_says_which_fact_is_missing() {
    let classification = classify_file(FileEvidence {
        declared_cadence: Some(Duration::from_secs(300)),
        proof: None,
        refusal: Some(GateRefusal::NoProof),
    });
    assert_eq!(classification.capability, LeaseCapability::None);
    assert!(classification.mechanism.contains("no sweep proof"));
    let disclosure = StatusDisclosure::from(&classification);
    assert_eq!(disclosure.declared_cadence_secs, Some(300));
    assert_eq!(disclosure.proven_cadence_secs, None);
    assert!(disclosure.evidence.contains("no proven cadence"));
}

// ---------------------------------------------------------------------------
// Criteria 3, 6, 8 — the lag is unknown, and it is not the cadence
// ---------------------------------------------------------------------------

#[test]
fn the_cleanup_lag_is_present_and_unknown() {
    let report = good();
    // Present: the field exists on a real report and says "unknown"...
    assert_eq!(report.backend.cleanup_lag, CleanupLag::Unknown);
    assert_eq!(report.backend.cleanup_lag.to_string(), "unknown");
    // ...and the type has no other value to give.
    let serialized = serde_json::to_value(&report).unwrap();
    assert_eq!(
        serialized["backend"]["cleanup_lag"], "Unknown",
        "the lag is reported, and it is not a number"
    );
    assert!(
        !serialized["backend"]["cleanup_lag"].is_number(),
        "no bound, deadline or measurement may appear here"
    );
}

#[test]
fn the_declared_cadence_is_reported_as_a_configuration_statement() {
    let report = good();
    assert_eq!(report.backend.declared_cadence_secs, Some(86_400));
}

#[test]
fn the_cadence_and_the_lag_are_separate_fields_and_never_the_same_value() {
    let report = good();
    // If the cadence were presented as a lag, one of these would have to give.
    assert_eq!(report.backend.declared_cadence_secs, Some(86_400));
    assert_eq!(report.backend.cleanup_lag, CleanupLag::Unknown);
    assert_ne!(
        report.backend.admission_minimum_secs,
        Some(86_400),
        "48h is the floor, not the cadence, and neither is a lag"
    );
}

// ---------------------------------------------------------------------------
// Criterion 5 — the admission minimum
// ---------------------------------------------------------------------------

#[test]
fn status_reports_the_admission_minimum_when_the_capability_is_scheduled() {
    let report = good();
    assert_eq!(report.backend.admission_minimum_secs, Some(172_800));
    assert_eq!(admission_floor(day()), Some(Duration::from_secs(172_800)));

    // A backend with no cadence has no floor to state, and says nothing rather
    // than inventing one.
    let file = classify_file(FileEvidence::default());
    let disclosure = StatusDisclosure::from_classification(&file);
    assert_eq!(disclosure.declared_cadence_secs, None);
    assert_eq!(disclosure.admission_minimum_secs, None);
}

#[test]
fn a_backend_that_admits_nothing_reports_no_admission_minimum() {
    // A declared cadence beside a `None` capability: reporting a 48h floor here
    // would invite the reader to conclude a 48h lease is acceptable, when the
    // capability says no lease is.
    let classification = Classification {
        capability: LeaseCapability::None,
        mechanism: "no configured logical expiry",
        declared_cadence: Some(day()),
        proven_cadence: None,
        proof_age: None,
        cleanup_lag: None,
        retention: None,
        state: None,
    };
    let disclosure = StatusDisclosure::from(&classification);

    assert_eq!(disclosure.capability, LeaseCapability::None);
    assert_eq!(disclosure.admission_minimum_secs, None);
    // The cadence is still disclosed as a configuration statement — it is the
    // *floor* that would be a claim, not the cadence.
    assert_eq!(disclosure.declared_cadence_secs, Some(86_400));
    assert!(disclosure.evidence.contains("86400"));
}

// ---------------------------------------------------------------------------
// Criterion 4 — retention is known or unknown, never assumed
// ---------------------------------------------------------------------------

#[test]
fn retention_is_reported_as_known_with_its_reason() {
    let mut classification = scheduled();
    classification.retention = Some(Duration::from_secs(30 * 86_400));
    let disclosure = StatusDisclosure::from_classification(&classification);

    match &disclosure.retention {
        Retention::Known {
            window_secs,
            reason,
        } => {
            assert_eq!(*window_secs, 30 * 86_400);
            assert!(!reason.is_empty(), "a known retention names its source");
            // It names the *classification* it was told, not a configuration
            // this surface never read and cannot vouch for.
            assert!(
                reason.contains("classification"),
                "the reason names where the number came from: {reason}"
            );
            assert!(
                !reason.contains("configuration states"),
                "this surface cannot vouch for what a configuration says: {reason}"
            );
        }
        other => panic!("expected a known retention, got {other:?}"),
    }
}

#[test]
fn retention_is_reported_as_unknown_rather_than_assumed_absent() {
    let disclosure = StatusDisclosure::from_classification(&scheduled());
    match &disclosure.retention {
        Retention::Unknown { reason } => {
            assert!(
                reason.contains("no retention window"),
                "unknown says why it cannot be known: {reason}"
            );
        }
        other => panic!("expected an unknown retention, got {other:?}"),
    }
    // And "unknown" is not "no copies survive".
    let json = serde_json::to_string(&disclosure).unwrap();
    assert!(!json.contains("\"window_secs\":0"));
}

// ---------------------------------------------------------------------------
// Criteria 9, 10 — the two postures, reported apart
// ---------------------------------------------------------------------------

#[test]
fn a_weakened_confinement_is_reported_as_weakened_not_enforced() {
    let report = report_builder(
        &scheduled(),
        posture(weakened(), unconfined_barrier()),
        Freshness::RollbackDetectionUnavailable,
        None,
    );
    assert_eq!(report.posture.confinement.state, ConfinementState::Weakened);

    let enforced = good();
    assert_eq!(
        enforced.posture.confinement.state,
        ConfinementState::Enforced
    );
    assert_ne!(
        report.posture.confinement.state, enforced.posture.confinement.state,
        "a weakened posture must not be rounded up to an enforced one"
    );

    let json = serde_json::to_value(&report).unwrap();
    let confinement = json["posture"]["confinement"].as_str().unwrap();
    assert!(
        confinement.contains("weakened"),
        "the rendered posture says weakened: {confinement}"
    );
}

#[test]
fn the_barrier_posture_is_a_separate_field_from_confinement() {
    // SealedMemfd with full confinement is representable, and the two are read
    // from different fields.
    let report = good();
    assert_eq!(report.posture.barrier.kind, Some(BarrierKind::SealedMemfd));
    assert_eq!(report.posture.confinement.state, ConfinementState::Enforced);

    let json = serde_json::to_value(&report).unwrap();
    assert!(json["posture"]["barrier"].is_string());
    assert!(json["posture"]["confinement"].is_string());
    assert_ne!(
        json["posture"]["barrier"], json["posture"]["confinement"],
        "one posture cannot stand in for the other"
    );

    // A confined run with no barrier is equally representable: neither implies
    // the other.
    let mixed = report_builder(
        &scheduled(),
        posture(confined(), unconfined_barrier()),
        Freshness::RollbackDetectionUnavailable,
        None,
    );
    assert_eq!(mixed.posture.confinement.state, ConfinementState::Enforced);
    assert_eq!(mixed.posture.barrier.kind, None);
}

// ---------------------------------------------------------------------------
// Criterion 11 — freshness is unavailable, and says so
// ---------------------------------------------------------------------------

#[test]
fn freshness_reports_rollback_detection_unavailable_without_a_checkpoint() {
    let disclosure = report_builder(
        &scheduled(),
        posture(confined(), unconfined_barrier()),
        Freshness::RollbackDetectionUnavailable,
        None,
    );
    assert_eq!(
        disclosure.freshness,
        Freshness::RollbackDetectionUnavailable
    );

    let json = serde_json::to_string(&disclosure).unwrap();
    assert!(
        json.contains("RollbackDetectionUnavailable"),
        "the unavailable case is named, not omitted: {json}"
    );
    assert!(
        !json.contains("in force"),
        "an absent checkpoint must not imply the guarantee holds"
    );
}

// ---------------------------------------------------------------------------
// Criteria 7, 12 — no erasure claim, no timing guarantee, canary is a canary
// ---------------------------------------------------------------------------

#[test]
fn the_serialized_report_contains_no_erasure_or_timing_claim() {
    let disclosure = report_builder(
        &scheduled(),
        posture(
            confined(),
            BarrierPosture::of(BarrierKind::SealedMemfd, memlock()),
        ),
        Freshness::Available { revision: 3 },
        Some(CanaryResult {
            found: false,
            observed_at: 1_700_000_000,
            version: 3,
        }),
    );
    let json = serde_json::to_string(&disclosure).unwrap().to_lowercase();

    for forbidden in [
        "erased",
        "erasure",
        "guaranteed",
        "guarantee",
        "max lag",
        "maximum lag",
        "worst case",
        "worst-case",
        "deadline",
        "bound",
        "proves",
        "exactly once",
        "deleted",
        "removed",
        "destroyed",
    ] {
        assert!(
            !json.contains(forbidden),
            "status must not contain {forbidden:?}: {json}"
        );
    }
}

#[test]
fn a_canary_result_is_reported_as_a_canary_result() {
    let report = report_builder(
        &scheduled(),
        posture(confined(), unconfined_barrier()),
        Freshness::Available { revision: 3 },
        Some(CanaryResult {
            found: false,
            observed_at: 1_700_000_000,
            version: 3,
        }),
    );

    let canary = report.canary.as_ref().expect("the canary ran");
    assert!(!canary.found);
    assert_eq!(canary.version, 3);
    assert_eq!(canary.observed_at, 1_700_000_000);

    // Absence seen by one lookup is not an erasure claim.
    let json = serde_json::to_string(&report).unwrap().to_lowercase();
    assert!(json.contains("\"found\":false"));
    assert!(!json.contains("erased"));
    assert!(
        !json.contains("\"absent\":true"),
        "the canary reports what it saw, not a conclusion"
    );
}

#[test]
fn a_report_with_no_canary_says_so_rather_than_implying_one_ran() {
    let report = good();
    assert!(report.canary.is_none());
    let json = serde_json::to_value(&report).unwrap();
    assert!(json["canary"].is_null());
}

// ---------------------------------------------------------------------------
// Acceptance 4 and misfit I — the passphrase claim, and no blank where an
// absence belongs
// ---------------------------------------------------------------------------

/// Acceptance 4: the wording is a deliverable, so it is asserted as wording.
#[test]
fn the_passphrase_claim_names_what_it_protects_and_what_it_does_not() {
    let report = good();
    assert_eq!(report.passphrase, PASSPHRASE_SENTENCE);
    assert!(PASSPHRASE_SENTENCE.contains("protects the key file at rest"));
    assert!(PASSPHRASE_SENTENCE.contains("does not protect a process that already holds the key"));
    assert!(PASSPHRASE_SENTENCE.contains("a captured ciphertext pair"));
    assert!(PASSPHRASE_SENTENCE.contains("a same-UID process that is not confined"));
    // Misfit I is an operator reading the claim as a boundary, so the sentence
    // must not contain the reading it exists to prevent.
    for overclaim in ["cannot read", "cannot open", "the agent cannot"] {
        assert!(
            !PASSPHRASE_SENTENCE.contains(overclaim),
            "the claim must not imply {overclaim:?}"
        );
    }
    // The sentence travels in the serialized document too, so a JSON consumer
    // reads the same claim a human does.
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("protects the key file at rest"), "{json}");
    assert!(
        json.contains("not a moment by which a copy is gone"),
        "the schedule note travels too: {json}"
    );
}

/// T056: a document with nothing to report still names each absence and why.
#[test]
fn an_absent_schedule_proof_and_head_each_carry_a_reason() {
    let report = good();
    match &report.arming {
        ArmingDisclosure::None { reason } => assert!(!reason.is_empty(), "the absence is named"),
        other => panic!("expected no arming, got {other:?}"),
    }
    assert!(report.proof.newest_success.is_none());
    assert!(
        report
            .proof
            .absent_reason
            .as_deref()
            .is_some_and(|reason| !reason.is_empty()),
        "an absent proof carries the reason it is absent"
    );
    assert!(report.audit.chains.is_empty());
    assert!(
        report
            .audit
            .absent_reason
            .as_deref()
            .is_some_and(|reason| !reason.is_empty()),
        "an absent head carries the reason it is absent"
    );
    assert!(!report.last_trigger_note.is_empty());
    assert!(!report.schedule_note.is_empty());
}
