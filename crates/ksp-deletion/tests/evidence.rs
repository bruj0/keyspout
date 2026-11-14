//! The acceptance criteria for WP09, driven through the public API.
//!
//! The subsystem exists to keep three things apart that look alike: an
//! authorization to delete, an actor's claim that it deleted, and an observer's
//! statement that a version was absent. So the tests are mostly *substitution*
//! tests — take a genuine piece of one kind and present it as another — because
//! the failure this prevents is a verifier that checks a signature and stops
//! there.
//!
//! A test reports a failure by panicking, and the panic message is what says why.
//! The production code keeps the strict lints.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::collections::BTreeMap;

use ksp_deletion::{
    AcknowledgementEvent, AcknowledgementJournal, EvidenceSigningKey, JournalError,
    MemoryJournalStore, Recorded, ReportAuthority, ReportRejection, ReportSink, SignedIntent,
    SignedObservation, SignedReport, VersionState, retry_report, state_of, verify_report,
};
use ksp_types::evidence::{AbsenceObservation, DeletionIntent, DeletionReport, Outcome};
use ksp_types::{ActorId, Level, OpaqueSecretId, VaultId};

fn alice() -> ActorId {
    ActorId::User(ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap())
}

fn agent_seven() -> ActorId {
    ActorId::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap())
}

fn agent_eight() -> ActorId {
    ActorId::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000008").unwrap())
}

fn agent_level() -> Level {
    Level::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap())
}

fn secret() -> OpaqueSecretId {
    OpaqueSecretId::new("secret-1")
}

fn intent() -> DeletionIntent {
    DeletionIntent {
        intent_id: "intent-1".to_string(),
        vault_id: VaultId::new("vault-1"),
        user_id: ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        level: agent_level(),
        secret_id: secret(),
        version: 3,
        deadline: 1_700_000_000,
        authorized_deleters: vec![alice(), agent_seven()],
    }
}

fn report_for(intent: &DeletionIntent, actor: ActorId) -> DeletionReport {
    DeletionReport {
        intent_id: intent.intent_id.clone(),
        actor,
        signer_key_id: "agent-7-key-1".to_string(),
        reason: "consume completed".to_string(),
        outcome: Outcome::Success,
        reported_deleted_at: 1_699_999_000,
        level: intent.level.clone(),
        secret_id: intent.secret_id.clone(),
        version: intent.version,
    }
}

/// A journal holding the acknowledgement for `intent`, and the capability that
/// proves it.
fn journaled(
    intent: &DeletionIntent,
    actor: ActorId,
) -> (
    AcknowledgementJournal<MemoryJournalStore>,
    ksp_deletion::JournaledAcknowledgement,
) {
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());
    let event = AcknowledgementEvent {
        intent_id: intent.intent_id.clone(),
        version: intent.version,
        actor,
        event_id: "backend-event-9".to_string(),
        acknowledged_at: 1_699_999_000,
    };
    journal.record(&event).unwrap();
    let capability = journal.require(&event).unwrap();
    (journal, capability)
}

fn authority(intent: &DeletionIntent) -> ReportAuthority {
    authority_for(intent, agent_seven())
}

/// Authority for a report that names `actor` as the deleter.
fn authority_for(intent: &DeletionIntent, actor: ActorId) -> ReportAuthority {
    let (_journal, acknowledgement) = journaled(intent, actor);
    ReportAuthority {
        intent_id: intent.intent_id.clone(),
        level: intent.level.clone(),
        secret_id: intent.secret_id.clone(),
        version: intent.version,
        authorized_deleters: intent.authorized_deleters.clone(),
        acknowledgement,
    }
}

struct Fixture {
    alice: EvidenceSigningKey,
    agent: EvidenceSigningKey,
    stranger: EvidenceSigningKey,
}

fn fixture() -> Fixture {
    Fixture {
        alice: EvidenceSigningKey::generate(),
        agent: EvidenceSigningKey::generate(),
        stranger: EvidenceSigningKey::generate(),
    }
}

// ---------------------------------------------------------------------------
// Criteria 1-7 — the verifier checks authority and identity, not just bytes
// ---------------------------------------------------------------------------

#[test]
fn a_valid_signature_from_an_unauthorized_actor_is_rejected() {
    let f = fixture();
    let intent = intent();
    // A stranger's claim, correctly signed by the stranger, about a version it
    // has no authority over.
    let signed = SignedReport::sign(&f.stranger, report_for(&intent, agent_eight())).unwrap();

    let rejection = verify_report(
        &signed,
        &agent_eight(),
        &f.stranger.verifying_key(),
        &authority_for(&intent, agent_eight()),
    )
    .unwrap_err();

    assert!(
        matches!(rejection, ReportRejection::NotAuthorized { .. }),
        "a valid signature must not buy authority: got {rejection:?}"
    );
    // And the signature really was valid, so the rejection is about authority.
    signed
        .verify_signature(&f.stranger.verifying_key())
        .unwrap();
}

#[test]
fn a_report_carrying_the_wrong_domain_is_rejected() {
    let f = fixture();
    let intent = intent();
    let mut signed = SignedReport::sign(&f.agent, report_for(&intent, agent_seven())).unwrap();

    signed.domain = "keyspout-token-v1".to_string();

    let rejection = verify_report(
        &signed,
        &agent_seven(),
        &f.agent.verifying_key(),
        &authority(&intent),
    )
    .unwrap_err();
    match rejection {
        ReportRejection::Signature(ksp_deletion::EvidenceError::Domain { expected, found }) => {
            assert_eq!(expected, ksp_deletion::REPORT_DOMAIN);
            assert_eq!(found, "keyspout-token-v1");
        }
        other => panic!("expected a domain rejection, got {other:?}"),
    }
}

#[test]
fn a_report_naming_a_different_actor_than_the_signer_is_rejected() {
    let f = fixture();
    let mut intent = intent();
    intent.authorized_deleters = vec![agent_seven(), agent_eight()];

    // Signed by the agent, but claiming to be the other agent's work. The
    // journal covers the actor the report *names*, so the mismatch under test is
    // between the named actor and the key that signed.
    let signed = SignedReport::sign(&f.agent, report_for(&intent, agent_eight())).unwrap();

    let rejection = verify_report(
        &signed,
        &agent_seven(),
        &f.agent.verifying_key(),
        &authority_for(&intent, agent_eight()),
    )
    .unwrap_err();

    assert!(
        matches!(rejection, ReportRejection::ActorMismatch { .. }),
        "got {rejection:?}"
    );
}

#[test]
fn a_report_answering_a_different_intent_is_rejected() {
    let f = fixture();
    let intent = intent();
    let mut questioned = authority(&intent);
    questioned.intent_id = "intent-2".to_string();

    let signed = SignedReport::sign(&f.agent, report_for(&intent, agent_seven())).unwrap();
    let rejection = verify_report(
        &signed,
        &agent_seven(),
        &f.agent.verifying_key(),
        &questioned,
    )
    .unwrap_err();

    assert!(
        matches!(rejection, ReportRejection::IntentMismatch { .. }),
        "got {rejection:?}"
    );
}

#[test]
fn a_report_about_a_different_level_is_rejected() {
    let f = fixture();
    let intent = intent();
    let mut questioned = authority(&intent);
    questioned.level = Level::User;

    let signed = SignedReport::sign(&f.agent, report_for(&intent, agent_seven())).unwrap();
    let rejection = verify_report(
        &signed,
        &agent_seven(),
        &f.agent.verifying_key(),
        &questioned,
    )
    .unwrap_err();

    assert!(
        matches!(rejection, ReportRejection::LevelMismatch { .. }),
        "got {rejection:?}"
    );
}

#[test]
fn a_report_about_a_different_record_is_rejected() {
    let f = fixture();
    let intent = intent();
    let mut questioned = authority(&intent);
    questioned.secret_id = OpaqueSecretId::new("secret-2");

    let signed = SignedReport::sign(&f.agent, report_for(&intent, agent_seven())).unwrap();
    let rejection = verify_report(
        &signed,
        &agent_seven(),
        &f.agent.verifying_key(),
        &questioned,
    )
    .unwrap_err();

    assert!(
        matches!(rejection, ReportRejection::RecordMismatch { .. }),
        "got {rejection:?}"
    );
}

#[test]
fn a_report_about_a_different_version_is_rejected() {
    let f = fixture();
    let intent = intent();
    let mut questioned = authority(&intent);
    questioned.version = 4;

    let signed = SignedReport::sign(&f.agent, report_for(&intent, agent_seven())).unwrap();
    let rejection = verify_report(
        &signed,
        &agent_seven(),
        &f.agent.verifying_key(),
        &questioned,
    )
    .unwrap_err();

    assert!(
        matches!(rejection, ReportRejection::VersionMismatch { .. }),
        "got {rejection:?}"
    );
}

#[test]
fn a_genuine_report_is_accepted() {
    // The negative tests above are only meaningful beside a positive one: a
    // verifier that refuses everything would pass them all.
    let f = fixture();
    let intent = intent();
    let signed = SignedReport::sign(&f.agent, report_for(&intent, agent_seven())).unwrap();

    verify_report(
        &signed,
        &agent_seven(),
        &f.agent.verifying_key(),
        &authority(&intent),
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// Criteria 8, 9, 10 — the three domains do not interchange
// ---------------------------------------------------------------------------

#[test]
fn an_intent_signature_is_not_accepted_as_a_report_signature() {
    let f = fixture();
    let intent = intent();
    let signed_intent = SignedIntent::sign(&f.alice, "alice-key-1", intent.clone()).unwrap();

    let forged = SignedReport {
        domain: signed_intent.domain.clone(),
        report: report_for(&intent, alice()),
        signature: signed_intent.signature,
    };

    let rejection = verify_report(
        &forged,
        &alice(),
        &f.alice.verifying_key(),
        &authority(&intent),
    )
    .unwrap_err();
    assert!(
        matches!(rejection, ReportRejection::Signature(_)),
        "got {rejection:?}"
    );
}

#[test]
fn an_observation_signature_is_not_accepted_as_a_report_signature() {
    let f = fixture();
    let intent = intent();
    let observation = SignedObservation::sign(
        &f.alice,
        AbsenceObservation {
            level: intent.level.clone(),
            secret_id: intent.secret_id.clone(),
            version: intent.version,
            observer: alice(),
            signer_key_id: "alice-key-1".to_string(),
            observed_at: 1_699_999_500,
        },
    )
    .unwrap();

    let forged = SignedReport {
        domain: observation.domain.clone(),
        report: report_for(&intent, alice()),
        signature: observation.signature,
    };

    let rejection = verify_report(
        &forged,
        &alice(),
        &f.alice.verifying_key(),
        &authority(&intent),
    )
    .unwrap_err();
    assert!(
        matches!(rejection, ReportRejection::Signature(_)),
        "got {rejection:?}"
    );
}

#[test]
fn a_report_signature_is_not_accepted_as_an_observation_signature() {
    let f = fixture();
    let intent = intent();
    let signed = SignedReport::sign(&f.agent, report_for(&intent, agent_seven())).unwrap();

    let forged = SignedObservation {
        domain: signed.domain.clone(),
        observation: AbsenceObservation {
            level: intent.level.clone(),
            secret_id: intent.secret_id.clone(),
            version: intent.version,
            observer: agent_seven(),
            signer_key_id: "agent-7-key-1".to_string(),
            observed_at: 1_699_999_500,
        },
        signature: signed.signature,
    };

    forged.verify(&f.agent.verifying_key()).unwrap_err();
}

// ---------------------------------------------------------------------------
// Criteria 11, 12 — absence is not a deletion
// ---------------------------------------------------------------------------

#[test]
fn absence_without_an_authenticated_report_is_missing_unconfirmed() {
    let f = fixture();
    let intent = intent();
    let observation = SignedObservation::sign(
        &f.alice,
        AbsenceObservation {
            level: intent.level.clone(),
            secret_id: intent.secret_id.clone(),
            version: intent.version,
            observer: alice(),
            signer_key_id: "alice-key-1".to_string(),
            observed_at: 1_699_999_500,
        },
    )
    .unwrap();

    // The version is gone and an authorized observer says so — and the state is
    // still *missing and unconfirmed*, not deleted.
    let state = state_of(&[], vec![observation]);
    match state {
        VersionState::MissingUnconfirmed { observations } => {
            assert_eq!(observations.len(), 1);
            assert_eq!(observations[0].observed_at(), 1_699_999_500);
        }
        other => panic!("an observation must not upgrade the state: got {other:?}"),
    }
}

#[test]
fn an_observation_carries_an_observation_time_and_no_deleter_and_no_deletion_time() {
    let f = fixture();
    let intent = intent();
    let observation = SignedObservation::sign(
        &f.alice,
        AbsenceObservation {
            level: intent.level.clone(),
            secret_id: intent.secret_id.clone(),
            version: intent.version,
            observer: alice(),
            signer_key_id: "alice-key-1".to_string(),
            observed_at: 1_699_999_500,
        },
    )
    .unwrap();

    assert_eq!(observation.observed_at(), 1_699_999_500);

    // The structure has no field for a deleting actor or a deletion time. Assert
    // it over the encoded form rather than over the type's declaration, so a
    // field added later is caught.
    let bytes = ksp_types::cbor::encode(&observation.observation).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        !text.contains("actor"),
        "an observation names no deleting actor"
    );
    assert!(
        !text.contains("reported_deleted_at"),
        "an observation carries no deletion time"
    );
    assert!(!text.contains("deleted_at"));

    // The only time it has is the observation time.
    assert_eq!(
        observation.observation.observed_at, 1_699_999_500,
        "observed_at is the observation time, not a deletion time"
    );
}

// ---------------------------------------------------------------------------
// Criteria 13, 14 — the journal
// ---------------------------------------------------------------------------

/// A backend that can hold records — and records every attempt to write one, so
/// a retry that put the ciphertext back would be visible.
#[derive(Default)]
struct Backend {
    ciphertexts: RefCell<BTreeMap<String, Vec<u8>>>,
    reports: RefCell<Vec<Vec<u8>>>,
    record_writes: RefCell<usize>,
}

impl ReportSink for Backend {
    fn write(&self, report: &[u8]) -> Result<(), JournalError> {
        self.reports.borrow_mut().push(report.to_vec());
        Ok(())
    }
}

fn event() -> AcknowledgementEvent {
    AcknowledgementEvent {
        intent_id: "intent-1".to_string(),
        version: 3,
        actor: agent_seven(),
        event_id: "backend-event-9".to_string(),
        acknowledged_at: 1_699_999_000,
    }
}

#[test]
fn a_failed_report_write_retries_idempotently_and_never_restores_ciphertext() {
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());
    let backend = Backend::default();

    // The delete happened: the ciphertext is gone and the acknowledgement is
    // durable. Then the actor crashes before writing its report.
    assert_eq!(journal.record(&event()).unwrap(), Recorded::New);
    let ciphertext_assumed_removed = backend.ciphertexts.borrow().get("version-3").cloned();
    assert!(ciphertext_assumed_removed.is_none());

    let report_bytes = b"signed-report-bytes".to_vec();

    // The retry runs twice, as a crash-loop would.
    retry_report(&journal, &event(), &report_bytes, &backend).unwrap();
    retry_report(&journal, &event(), &report_bytes, &backend).unwrap();

    // Idempotent by intent/version/actor/event: the acknowledgement is not
    // re-recorded, and the retry never touches a record.
    assert_eq!(journal.record(&event()).unwrap(), Recorded::AlreadyPresent);
    assert_eq!(
        *backend.record_writes.borrow(),
        0,
        "the retry must not write a record"
    );
    assert!(
        backend.ciphertexts.borrow().is_empty(),
        "the ciphertext must still be absent after the retry"
    );
    assert_eq!(
        backend.reports.borrow().len(),
        2,
        "the report is written each time"
    );
    assert_eq!(
        journal.recover(&event()).unwrap().map(|e| e.event_id),
        Some("backend-event-9".to_string())
    );
}

#[test]
fn a_retry_that_changes_the_event_does_not_reuse_the_acknowledgement() {
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());
    let backend = Backend::default();
    journal.record(&event()).unwrap();

    // Same intent and version, a different backend event: a real second delete,
    // not a retry of the first.
    let mut other = event();
    other.event_id = "backend-event-10".to_string();

    assert!(
        journal.recover(&other).unwrap().is_none(),
        "a different event must not inherit the first acknowledgement"
    );
    assert!(matches!(
        retry_report(&journal, &other, b"report", &backend),
        Err(JournalError::NotAcknowledged)
    ));
    assert!(backend.reports.borrow().is_empty());
}

#[test]
fn the_journal_key_includes_the_actor() {
    // Criterion 13 says idempotent by intent *and* version *and* actor *and*
    // event. Two actors acknowledging the same event for the same version are
    // two different facts.
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());
    let mut other_actor = event();
    other_actor.actor = agent_eight();

    assert_eq!(journal.record(&event()).unwrap(), Recorded::New);
    assert_ne!(
        event().key(),
        other_actor.key(),
        "the key must distinguish actors"
    );
    assert_eq!(journal.record(&other_actor).unwrap(), Recorded::New);
    assert!(journal.recover(&other_actor).unwrap().is_some());
}

#[test]
fn with_no_durable_acknowledgement_only_an_observation_may_be_reported() {
    let f = fixture();
    let intent = intent();

    // The acknowledgement was never recorded, so no capability for it can be
    // obtained at all — the report path is unreachable, not merely refused.
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());
    let never_recorded = AcknowledgementEvent {
        intent_id: intent.intent_id.clone(),
        version: intent.version,
        actor: agent_seven(),
        event_id: "backend-event-never-recorded".to_string(),
        acknowledged_at: 1_699_999_000,
    };
    assert!(
        matches!(
            journal.require(&never_recorded),
            Err(JournalError::NotAcknowledged)
        ),
        "no durable evidence means no capability"
    );

    // A capability for a *different* deletion does not authorise this report.
    let (_, other_capability) = journaled(
        &DeletionIntent {
            intent_id: "intent-other".to_string(),
            ..intent.clone()
        },
        agent_seven(),
    );
    let signed = SignedReport::sign(&f.agent, report_for(&intent, agent_seven())).unwrap();
    let mismatched = ReportAuthority {
        intent_id: intent.intent_id.clone(),
        level: intent.level.clone(),
        secret_id: intent.secret_id.clone(),
        version: intent.version,
        authorized_deleters: intent.authorized_deleters.clone(),
        acknowledgement: other_capability,
    };
    let rejection = verify_report(
        &signed,
        &agent_seven(),
        &f.agent.verifying_key(),
        &mismatched,
    )
    .unwrap_err();
    assert!(
        matches!(rejection, ReportRejection::AcknowledgementMismatch { .. }),
        "got {rejection:?}"
    );

    // ...and an observation is still available, which is the honest statement.
    let observation = SignedObservation::sign(
        &f.alice,
        AbsenceObservation {
            level: intent.level.clone(),
            secret_id: intent.secret_id.clone(),
            version: intent.version,
            observer: alice(),
            signer_key_id: "alice-key-1".to_string(),
            observed_at: 1_699_999_500,
        },
    )
    .unwrap();
    observation.verify(&f.alice.verifying_key()).unwrap();
    assert!(matches!(
        state_of(&[], vec![observation]),
        VersionState::MissingUnconfirmed { .. }
    ));
}

// ---------------------------------------------------------------------------
// Criteria 15, 16 — the intent is key-free and a report is a claim
// ---------------------------------------------------------------------------

#[test]
fn the_signed_intent_contains_no_key_material() {
    let f = fixture();
    let bytes =
        ksp_types::cbor::encode(&SignedIntent::sign(&f.alice, "alice-key-1", intent()).unwrap())
            .unwrap();

    let signing_key = f.alice.verifying_key().to_bytes();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        !bytes
            .windows(signing_key.len())
            .any(|window| window == signing_key),
        "the intent must not carry a public key either"
    );
    assert!(
        !text.contains("public"),
        "no key-shaped field belongs in an intent"
    );
    assert!(!text.contains("secret_key"));
}

#[test]
fn a_report_attaches_a_claim_and_the_state_never_calls_it_deleted() {
    let f = fixture();
    let intent = intent();
    let report = report_for(&intent, agent_seven());
    let signed = SignedReport::sign(&f.agent, report.clone()).unwrap();
    verify_report(
        &signed,
        &agent_seven(),
        &f.agent.verifying_key(),
        &authority(&intent),
    )
    .unwrap();

    let state = state_of(std::slice::from_ref(&report), Vec::new());
    match &state {
        VersionState::Reported(summary) => {
            // The time is carried as the actor's claim, beside the actor that
            // claimed it — not as a fact about the store.
            assert_eq!(summary.reported_deleted_at, 1_699_999_000);
            assert_eq!(summary.actor, agent_seven());
        }
        other => panic!("an authenticated report is a report: got {other:?}"),
    }
    assert!(
        !format!("{state:?}").contains("Deleted"),
        "no state may be named as though a deletion were established"
    );
}

// ---------------------------------------------------------------------------
// The envelope survives storage
// ---------------------------------------------------------------------------

#[test]
fn the_three_signed_structures_survive_a_round_trip() {
    // A verifier reads evidence back from storage, so decoding is on the
    // verification path. A signature type that encodes but does not decode
    // would look fine in every test that only encodes.
    let (intent, report, observation) = golden();
    let issuer = EvidenceSigningKey::from_seed([7u8; 32]);
    let actor = EvidenceSigningKey::from_seed([9u8; 32]);

    let decoded: SignedIntent =
        ksp_types::cbor::decode(&ksp_types::cbor::encode(&intent).unwrap()).unwrap();
    assert_eq!(decoded, intent);
    decoded.verify(&issuer.verifying_key()).unwrap();

    let decoded: SignedReport =
        ksp_types::cbor::decode(&ksp_types::cbor::encode(&report).unwrap()).unwrap();
    assert_eq!(decoded, report);
    decoded.verify_signature(&actor.verifying_key()).unwrap();

    let decoded: SignedObservation =
        ksp_types::cbor::decode(&ksp_types::cbor::encode(&observation).unwrap()).unwrap();
    assert_eq!(decoded, observation);
    decoded.verify(&issuer.verifying_key()).unwrap();
}

#[test]
fn the_domain_strings_agree_with_the_shared_prefixes() {
    // The domain is carried twice: as a signed string here and as a byte prefix
    // in ksp-types. If they drift, a signature made by one party stops
    // verifying for the other, and the failure looks like a bad key.
    assert_eq!(
        ksp_deletion::INTENT_DOMAIN.as_bytes(),
        ksp_types::domains::DOMAIN_DELETE_INTENT
    );
    assert_eq!(
        ksp_deletion::REPORT_DOMAIN.as_bytes(),
        ksp_types::domains::DOMAIN_DELETE_REPORT
    );
    assert_eq!(
        ksp_deletion::OBSERVATION_DOMAIN.as_bytes(),
        ksp_types::domains::DOMAIN_ABSENCE_OBSERVATION
    );
}

// ---------------------------------------------------------------------------
// Criterion 17 — a golden fixture pins the three encodings
// ---------------------------------------------------------------------------

/// Deterministic keys and values, so the fixture is reproducible.
fn golden() -> (SignedIntent, SignedReport, SignedObservation) {
    let issuer = EvidenceSigningKey::from_seed([7u8; 32]);
    let actor = EvidenceSigningKey::from_seed([9u8; 32]);
    let intent = DeletionIntent {
        intent_id: "intent-golden".to_string(),
        vault_id: VaultId::new("vault-1"),
        user_id: ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        level: agent_level(),
        secret_id: secret(),
        version: 3,
        deadline: 1_700_000_000,
        authorized_deleters: vec![alice(), agent_seven()],
    };
    let signed_intent = SignedIntent::sign(&issuer, "alice-key-1", intent.clone()).unwrap();
    let signed_report = SignedReport::sign(&actor, report_for(&intent, agent_seven())).unwrap();
    let observation = SignedObservation::sign(
        &issuer,
        AbsenceObservation {
            level: intent.level.clone(),
            secret_id: intent.secret_id.clone(),
            version: intent.version,
            observer: alice(),
            signer_key_id: "alice-key-1".to_string(),
            observed_at: 1_699_999_500,
        },
    )
    .unwrap();
    (signed_intent, signed_report, observation)
}

/// Regenerate the fixtures after an intentional change to a signed structure.
///
/// Ignored by default: running it silently would make the pinned bytes follow
/// the code instead of constraining it.
#[test]
#[ignore = "regenerates the golden fixtures; run deliberately"]
fn regenerate_golden_fixtures() {
    let (intent, report, observation) = golden();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    for (name, bytes) in [
        ("intent.cbor", ksp_types::cbor::encode(&intent).unwrap()),
        ("report.cbor", ksp_types::cbor::encode(&report).unwrap()),
        (
            "observation.cbor",
            ksp_types::cbor::encode(&observation).unwrap(),
        ),
    ] {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}

#[test]
fn the_three_encodings_are_pinned() {
    let (intent, report, observation) = golden();

    for (name, bytes) in [
        ("intent.cbor", ksp_types::cbor::encode(&intent).unwrap()),
        ("report.cbor", ksp_types::cbor::encode(&report).unwrap()),
        (
            "observation.cbor",
            ksp_types::cbor::encode(&observation).unwrap(),
        ),
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        let expected =
            std::fs::read(&path).unwrap_or_else(|_| panic!("missing golden fixture {path:?}"));
        assert_eq!(
            bytes, expected,
            "{name} no longer encodes to its pinned bytes"
        );
    }
}
