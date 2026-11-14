#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use ksp_backend::admission::{
    AdmissionError, CapabilityState, FileEvidence, S3Configuration, S3Evidence,
    ValkeyConfiguration, admit_at_gate, classify_file, classify_s3, classify_valkey, next_action,
};
use ksp_backend::arming::{ArmError, ArmRecord, ArmingStore, Durability, arm_intent};
use ksp_backend::proof::{GateRefusal, ProofObservation};
use ksp_backend::status::StatusDisclosure;
use ksp_types::{
    ActorId, AdmissionRefusal, DeletionIntent, LeaseCapability, Level, OpaqueSecretId, VaultId,
};

const DAY: Duration = Duration::from_secs(86_400);

fn s3_config() -> S3Configuration {
    S3Configuration {
        interval: Some(DAY),
        cleanup_expected: true,
    }
}
fn s3_evidence() -> S3Evidence {
    S3Evidence {
        versioned: false,
        soft_delete: false,
        lifecycle_covers_prefix: true,
        lifecycle_expiration: true,
        canary_absent: false,
    }
}

#[test]
fn file_refuses_a_lease_and_names_none() {
    let file = classify_file(FileEvidence::default());
    assert_eq!(file.capability, LeaseCapability::None);
    let refusal = admit_at_gate(&file, DAY).unwrap_err().to_string();
    assert!(refusal.contains("None"), "{refusal}");
}

#[test]
fn s3_hidden_copies_remain_none_even_when_a_canary_is_absent() {
    for evidence in [
        S3Evidence {
            versioned: true,
            canary_absent: true,
            ..s3_evidence()
        },
        S3Evidence {
            soft_delete: true,
            canary_absent: true,
            ..s3_evidence()
        },
    ] {
        let classified = classify_s3(s3_config(), evidence).unwrap();
        assert_eq!(classified.capability, LeaseCapability::None);
    }
}

#[test]
fn s3_requires_cleanup_and_a_cadence_and_names_the_boundary() {
    let no_cleanup = classify_s3(
        S3Configuration {
            cleanup_expected: false,
            ..s3_config()
        },
        S3Evidence {
            lifecycle_covers_prefix: false,
            lifecycle_expiration: false,
            ..s3_evidence()
        },
    )
    .unwrap();
    assert_eq!(no_cleanup.capability, LeaseCapability::None);
    assert!(matches!(
        classify_s3(
            S3Configuration {
                cleanup_expected: false,
                ..s3_config()
            },
            s3_evidence()
        ),
        Err(AdmissionError::ConfigurationMismatch(_))
    ));
    let no_cadence = classify_s3(
        S3Configuration {
            interval: None,
            ..s3_config()
        },
        s3_evidence(),
    )
    .unwrap();
    assert_eq!(no_cadence.capability, LeaseCapability::None);
    let classified = classify_s3(s3_config(), s3_evidence()).unwrap();
    let floor = DAY * 2;
    for duration in [
        floor - Duration::from_secs(1),
        floor,
        floor + Duration::from_secs(1),
    ] {
        let refusal = admit_at_gate(&classified, duration)
            .unwrap_err()
            .to_string();
        assert!(
            refusal.contains("None") && refusal.contains("deadline"),
            "{refusal}"
        );
    }
    let status = StatusDisclosure::from(&classified);
    assert_eq!(status.capability, LeaseCapability::None);
    // No floor, because the loop above refused every duration including the
    // floor itself. A minimum reported beside a `None` capability would tell a
    // reader that some lease length is acceptable, which is what this backend
    // refuses to say. (The assertion here previously expected `Some(floor)`. It
    // contradicted this test's own premise.)
    assert_eq!(status.admission_minimum_secs, None);
    assert_eq!(status.declared_cadence_secs, Some(DAY.as_secs()));
    // The lag is always unknown; retention is never assumed to be "no".
    assert_eq!(status.cleanup_lag, ksp_backend::status::CleanupLag::Unknown);
    assert!(matches!(
        status.retention,
        ksp_backend::status::Retention::Unknown { .. }
    ));
}

#[test]
fn the_admission_floor_boundary_is_two_times_the_declared_cadence() {
    // The pure floor is exercised against an abstract `Scheduled` capability.
    // The concrete S3 backend cannot supply one -- object-age expiration does
    // not arm an exact deadline -- so the boundary lives in `ksp_types` and
    // must hold regardless of which backend produced the capability.
    let capability = LeaseCapability::Scheduled { interval: DAY };
    let floor = DAY * 2;

    assert!(!ksp_types::admits(
        &capability,
        floor - Duration::from_secs(1)
    ));
    assert!(ksp_types::admits(&capability, floor));
    assert!(ksp_types::admits(
        &capability,
        floor + Duration::from_secs(1)
    ));

    // A refusal must name the cadence and the minimum.
    let refusal = ksp_types::admit_decision(&capability, floor - Duration::from_secs(1));
    let ksp_types::AdmissionDecision::Refused(AdmissionRefusal::BelowFloor {
        requested,
        floor: stated,
    }) = refusal
    else {
        panic!("expected a below-floor refusal, got {refusal:?}");
    };
    assert_eq!(requested, floor - Duration::from_secs(1));
    assert_eq!(stated, floor);
}

#[test]
fn known_mismatches_fail_admission_and_unknowns_stay_unknown() {
    assert!(matches!(
        classify_s3(
            s3_config(),
            S3Evidence {
                lifecycle_covers_prefix: false,
                lifecycle_expiration: false,
                ..s3_evidence()
            }
        ),
        Err(AdmissionError::ConfigurationMismatch(_))
    ));
    let conflicting = ValkeyConfiguration {
        logical_expiry: true,
        append_only: false,
        append_fsync_always: false,
        waitaof_supported: false,
    };
    assert!(matches!(
        classify_valkey(conflicting),
        Err(AdmissionError::ConfigurationMismatch(_))
    ));
    let eligible = ValkeyConfiguration {
        logical_expiry: true,
        append_only: true,
        append_fsync_always: true,
        waitaof_supported: true,
    };
    let classified = classify_valkey(eligible).unwrap();
    assert_eq!(classified.capability, LeaseCapability::NativeExpiry);
    assert!(admit_at_gate(&classified, Duration::from_millis(1)).is_ok());
    assert_eq!(
        StatusDisclosure::from(&classified).cleanup_lag,
        ksp_backend::status::CleanupLag::Unknown
    );
}

#[derive(Default)]
struct LostReply {
    bytes: Mutex<HashMap<String, Vec<u8>>>,
    lose_once: Mutex<bool>,
}
impl ArmingStore for LostReply {
    fn arm_once(&self, identity: &str, bytes: &[u8], _: i64) -> Result<Durability, ArmError> {
        let mut stored = self.bytes.lock().unwrap();
        if let Some(previous) = stored.get(identity) {
            if previous != bytes {
                return Err(ArmError::IdentityConflict);
            }
        } else {
            stored.insert(identity.to_owned(), bytes.to_vec());
        }
        if std::mem::take(&mut *self.lose_once.lock().unwrap()) {
            return Err(ArmError::Uncertain);
        }
        Ok(Durability::LocalSync)
    }
    fn read_arm(&self, identity: &str) -> Result<Option<Vec<u8>>, ArmError> {
        Ok(self.bytes.lock().unwrap().get(identity).cloned())
    }
}
fn intent() -> DeletionIntent {
    DeletionIntent {
        intent_id: "intent-1".into(),
        vault_id: VaultId::new("vault-1"),
        user_id: ksp_types::PrincipalId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        level: Level::Agent(
            ksp_types::AgentId::parse("00000000-0000-4000-8000-0000000000a1").unwrap(),
        ),
        secret_id: OpaqueSecretId::new("opaque-1"),
        version: 3,
        deadline: 1_800_000_000,
        authorized_deleters: vec![ActorId::User(
            ksp_types::PrincipalId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        )],
    }
}
#[test]
fn the_arm_record_and_the_intent_carry_no_key_material() {
    let signer = SigningKey::from_bytes(&[7; 32]);
    let record = ArmRecord::sign(
        "operation-1".into(),
        intent(),
        "signer-1".into(),
        None,
        &signer,
    )
    .unwrap();
    let bytes = record.to_bytes().unwrap();

    // The record's own fields are the whole of its content. A field that
    // carried key material would have to appear here.
    let fields = [
        record.operation_identity.as_str(),
        record.intent.intent_id.as_str(),
        record.signer_key_id.as_str(),
    ];
    for field in fields {
        assert!(
            !field.contains("secret") && !field.contains("key"),
            "an arming field must not name key material: {field}"
        );
    }

    // The serialized bytes must not contain the signing key. The private key
    // is `[7u8; 32]`; a 32-byte run of `0x07` anywhere in the record would
    // mean the private key leaked into the artifact.
    let private = [7u8; 32];
    assert!(
        !bytes.windows(private.len()).any(|window| window == private),
        "the serialized arm record must not contain the signing private key"
    );

    // Nor the public key derived from it, and nor the signature over a
    // preimage that could be replayed as a decryption capability.
    let public = signer.verifying_key().to_bytes();
    assert!(
        !bytes.windows(public.len()).any(|window| window == public),
        "the serialized arm record must not contain the signing public key"
    );

    // The intent's own serialized form must also be key-free.
    let intent_bytes = ksp_types::cbor::encode(&record.intent).unwrap();
    assert!(
        !intent_bytes
            .windows(private.len())
            .any(|window| window == private),
        "the serialized deletion intent must not contain key material"
    );
}

#[test]
fn lost_acknowledgement_reconciles_exact_bytes_without_duplication() {
    let signer = SigningKey::from_bytes(&[7; 32]);
    let record = ArmRecord::sign(
        "operation-1".into(),
        intent(),
        "signer-1".into(),
        None,
        &signer,
    )
    .unwrap();
    let bytes = record.to_bytes().unwrap();
    let store = LostReply {
        bytes: Mutex::new(HashMap::new()),
        lose_once: Mutex::new(true),
    };
    assert!(matches!(
        arm_intent(&store, &record),
        Err(ArmError::Uncertain)
    ));
    let ack = arm_intent(&store, &record).unwrap();
    assert_eq!(ack.operation_identity, "operation-1");
    assert_eq!(ack.version, 3);
    assert_eq!(store.bytes.lock().unwrap().len(), 1);
    assert_eq!(store.bytes.lock().unwrap().get("operation-1"), Some(&bytes));
    let other = ArmRecord::sign(
        "operation-1".into(),
        DeletionIntent {
            deadline: 1_900_000_000,
            ..intent()
        },
        "signer-1".into(),
        None,
        &signer,
    )
    .unwrap();
    assert!(matches!(
        arm_intent(&store, &other),
        Err(ArmError::IdentityConflict)
    ));
}

/// An arm record written before the use bound existed must still decode.
///
/// The counter lives in this record rather than in the record format precisely
/// so that an arm written by an older build keeps working: it is time-bounded
/// only, which is what `remaining_uses: None` means. A field that failed to
/// decode would strand every armed lease on an upgraded host.
#[test]
fn an_arm_record_without_a_use_bound_still_decodes() {
    let signer = SigningKey::from_bytes(&[7; 32]);
    let record = ArmRecord::sign(
        "operation-1".into(),
        intent(),
        "signer-1".into(),
        None,
        &signer,
    )
    .unwrap();

    // The bytes of a record written by a build that had no counter: the same
    // fields, with `remaining_uses` absent rather than null. That is what an
    // older build wrote, and `#[serde(default)]` is what makes it decode.
    #[derive(serde::Serialize)]
    struct LegacyArm<'a> {
        operation_identity: &'a str,
        intent: &'a ksp_types::DeletionIntent,
        signer_key_id: &'a str,
        signature: &'a [u8],
    }
    let legacy = ksp_types::cbor::encode(&LegacyArm {
        operation_identity: &record.operation_identity,
        intent: &record.intent,
        signer_key_id: &record.signer_key_id,
        signature: &record.signature,
    })
    .unwrap();

    let decoded =
        ArmRecord::from_bytes(&legacy).expect("an arm record without a use bound must decode");
    assert_eq!(
        decoded.remaining_uses, None,
        "an arm with no counter is time-bounded only"
    );
    assert_eq!(decoded.operation_identity, record.operation_identity);
}

/// A raised counter must fail verification.
///
/// The counter is inside the signed preimage because a counter outside it could
/// be raised by anyone who can write the journal, which would extend a copy's
/// life — the opposite of what the bound is for. A planted record can only make
/// the sweep attempt a removal the kernel refuses; a raised counter would make it
/// never attempt one.
#[test]
fn a_raised_use_bound_does_not_verify() {
    let signer = SigningKey::from_bytes(&[7; 32]);
    let verifying = signer.verifying_key();
    let record = ArmRecord::sign(
        "operation-1".into(),
        intent(),
        "signer-1".into(),
        Some(3),
        &signer,
    )
    .unwrap();
    assert!(record.verify(&verifying), "the record as signed verifies");

    let raised = ArmRecord {
        remaining_uses: Some(99),
        ..record.clone()
    };
    assert!(
        !raised.verify(&verifying),
        "a counter raised after signing must not verify"
    );

    // And a record that claims a bound it never signed — the legacy shape with a
    // counter added — is refused too.
    let mut forged = record.clone();
    forged.remaining_uses = None;
    forged.signature = {
        // Re-sign the three-field legacy preimage with the same key, then claim a
        // counter. This is the exact attack the two-shape verifier must refuse.
        let mut signed = Vec::from(ksp_types::DOMAIN_DELETE_INTENT);
        signed.extend(
            ksp_types::cbor::encode(&(
                forged.operation_identity.as_str(),
                &forged.intent,
                forged.signer_key_id.as_str(),
            ))
            .unwrap(),
        );
        ed25519_dalek::Signer::sign(&signer, &signed)
            .to_bytes()
            .to_vec()
    };
    assert!(
        forged.verify(&verifying),
        "a genuine legacy record with no counter verifies"
    );
    forged.remaining_uses = Some(5);
    assert!(
        !forged.verify(&verifying),
        "a legacy signature must not authorise a bound it never covered"
    );
}

// --- 007 WP02: the capability state names the cause, and the next action is
// derived from it (misfits D and F). ---

/// A proof that is fresh, in scope and verified.
fn fresh_proof(interval: Duration) -> ProofObservation {
    ProofObservation {
        interval,
        age: 0,
        grace: 5,
    }
}

/// An arming is recorded and no proof exists yet.
///
/// The state names the cause, and the action says what makes a proof appear
/// rather than telling the operator to wait for a run nothing has scheduled.
/// The action cannot name the interval: `next_action` takes only the state, and
/// the state carries no interval. That is deliberate — a second input is a
/// second place for the line to drift from.
#[test]
fn an_arming_with_no_proof_is_declared_no_proof_and_names_the_first_firing() {
    let classification = classify_file(FileEvidence {
        declared_cadence: Some(Duration::from_secs(3_600)),
        proof: None,
        refusal: None,
    });
    assert_eq!(
        classification.state,
        Some(CapabilityState::DeclaredNoProof),
        "an arming with no proof has a named cause"
    );
    let action = next_action(&classification.state.unwrap()).expect("there is a next step");
    assert!(
        action.contains("first firing"),
        "the action says a proof appears after the first firing: {action}"
    );
}

/// A proof older than its own bound is stale, and the action says so.
///
/// Misfit D: a laptop asleep past the bound wakes to `None`. The action must
/// name the bound and the interval, not tell the operator to keep waiting.
#[test]
fn a_stale_proof_is_named_stale_and_the_action_names_the_bound() {
    let interval = Duration::from_secs(3_600);
    let classification = classify_file(FileEvidence {
        declared_cadence: Some(interval),
        proof: Some(ProofObservation {
            interval,
            // interval + grace + 1
            age: 3_606,
            grace: 5,
        }),
        refusal: None,
    });
    match classification.state {
        Some(CapabilityState::StaleProof { age, bound }) => {
            assert_eq!(age, 3_606);
            assert_eq!(bound, 3_605, "the bound is interval plus grace");
        }
        other => panic!("expected StaleProof, got {other:?}"),
    }
    let action = next_action(&classification.state.unwrap()).expect("there is a next step");
    assert!(
        action.contains("late") || action.contains("stale"),
        "the action says the run is late: {action}"
    );
}

/// A proof that exists but does not verify is its own cause.
#[test]
fn an_unverified_proof_is_named_unverified() {
    let classification = classify_file(FileEvidence {
        declared_cadence: Some(Duration::from_secs(3_600)),
        proof: None,
        refusal: Some(GateRefusal::Unverified {
            scope: "p/vault-1/p/agent-*".to_string(),
        }),
    });
    assert_eq!(
        classification.state,
        Some(CapabilityState::UnverifiedProof),
        "an unverified proof is not the same cause as no proof"
    );
}

/// A run recorded without a schedule names no cadence.
///
/// This is the case a `next:` line that assumes every `None` means "wait" gets
/// wrong: waiting produces another unscheduled run.
#[test]
fn a_run_without_a_schedule_is_named_no_cadence() {
    let classification = classify_file(FileEvidence {
        declared_cadence: None,
        proof: None,
        refusal: Some(GateRefusal::NoCadence),
    });
    assert_eq!(classification.state, Some(CapabilityState::NoCadence));
    let action = next_action(&classification.state.unwrap()).expect("there is a next step");
    assert!(
        !action.contains("wait"),
        "waiting for the next firing produces another unscheduled run: {action}"
    );
}

/// An unreadable proof area is a permission question, not a run question.
#[test]
fn an_unreadable_proof_area_is_named_unreadable() {
    let classification = classify_file(FileEvidence {
        declared_cadence: Some(Duration::from_secs(3_600)),
        proof: None,
        refusal: Some(GateRefusal::Unreadable),
    });
    assert_eq!(
        classification.state,
        Some(CapabilityState::UnreadableProofs)
    );
    let action = next_action(&classification.state.unwrap()).expect("there is a next step");
    assert!(
        action.contains("permission") || action.contains("read"),
        "the action names a permission check, not a run: {action}"
    );
}

/// A fresh, in-scope, verified proof is the only state that needs no action.
#[test]
fn a_fresh_verified_proof_is_proven_and_needs_no_action() {
    let classification = classify_file(FileEvidence {
        declared_cadence: Some(Duration::from_secs(3_600)),
        proof: Some(fresh_proof(Duration::from_secs(3_600))),
        refusal: None,
    });
    assert_eq!(classification.state, Some(CapabilityState::Proven));
    assert_eq!(
        next_action(&classification.state.unwrap()),
        None,
        "a proven schedule needs no next step"
    );
}

/// The capability enum is not extended: it still has exactly three values.
///
/// A second capability enum beside `LeaseCapability` is the defect the
/// CONTEXT.md entry for Capability State forbids.
#[test]
fn the_state_explains_the_capability_without_replacing_it() {
    let proven = classify_file(FileEvidence {
        declared_cadence: Some(Duration::from_secs(3_600)),
        proof: Some(fresh_proof(Duration::from_secs(3_600))),
        refusal: None,
    });
    assert!(matches!(
        proven.capability,
        LeaseCapability::Scheduled { .. }
    ));
    assert_eq!(proven.state, Some(CapabilityState::Proven));

    let none = classify_file(FileEvidence::default());
    assert_eq!(none.capability, LeaseCapability::None);
    assert_eq!(none.state, Some(CapabilityState::NoArming));
}

/// A corrupt proof is not a verification failure.
///
/// The two causes need different remedies: a corrupt file is fixed by re-running
/// the sweep, a verification failure by checking the pinned anchor. Reporting
/// one as the other sends the operator to the wrong place.
#[test]
fn a_malformed_proof_is_its_own_cause_and_not_a_verification_failure() {
    let classification = classify_file(FileEvidence {
        declared_cadence: Some(Duration::from_secs(3_600)),
        proof: None,
        refusal: Some(GateRefusal::Malformed),
    });
    assert_eq!(
        classification.state,
        Some(CapabilityState::MalformedProof),
        "a corrupt proof is not a proof that failed to verify"
    );
    let action = next_action(&classification.state.unwrap()).expect("there is a next step");
    assert!(
        action.contains("decoded") || action.contains("corrupt"),
        "the action names the file, not the anchor: {action}"
    );
    assert!(
        !action.contains("anchor"),
        "a corrupt file is not fixed by checking the anchor: {action}"
    );
}

/// A stale refusal that arrives without the proof itself keeps its own cause.
///
/// `evidence.proof` is normally set when a proof was read, but the refusal can
/// carry the staleness on its own. Reporting that as "no run has proven it"
/// would be false: a run did happen, and it is late.
#[test]
fn a_stale_refusal_without_a_proof_is_still_stale() {
    let classification = classify_file(FileEvidence {
        declared_cadence: Some(Duration::from_secs(3_600)),
        proof: None,
        refusal: Some(GateRefusal::Stale {
            age: 7_200,
            bound: 3_605,
            interval: 3_600,
        }),
    });
    assert_eq!(
        classification.state,
        Some(CapabilityState::StaleProof {
            age: 7_200,
            bound: 3_605
        }),
        "a run happened and is late; it is not an unproven arming"
    );
}

/// A future-skew refusal without a proof is a clock problem, not an arming one.
#[test]
fn a_future_skew_refusal_without_a_proof_is_a_clock_problem() {
    let classification = classify_file(FileEvidence {
        declared_cadence: Some(Duration::from_secs(3_600)),
        proof: None,
        refusal: Some(GateRefusal::FutureSkew {
            skew: 9_000,
            grace: 5,
        }),
    });
    assert_eq!(classification.state, Some(CapabilityState::FutureSkewProof));
    let action = next_action(&classification.state.unwrap()).expect("there is a next step");
    assert!(
        action.contains("clock"),
        "the action names the clock, not the interval: {action}"
    );
}
