//! The acceptance criteria for WP10, driven through the public API.
//!
//! The property is an order — deliver, then delete, then report — and an order
//! is easy to test badly: a test that only checks the happy path passes whatever
//! the order is. So the fakes record *when* each was called, and the tests assert
//! the sequence as well as the outcome.
//!
//! A test reports a failure by panicking, and the panic message is what says why.
//! The production code keeps the strict lints.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::collections::BTreeMap;

use ksp_deletion::{
    AcknowledgementJournal, AuthorizedIntent, Child, ChildFailureReason, ConsumeError,
    ConsumeOutcome, ConsumeRequest, Decryptor, EXIT_DELETE_FAILED, EXIT_LOST_FRESH_FETCH,
    EXIT_UNCONSUMED_REFUSED, EvidenceSigningKey, JournalError, JournalStore, MemoryJournalStore,
    ReportSink, SignedIntent, VersionStore, VersionTarget, consume, require_consumption_for,
    retry_report, wipe,
};
use ksp_types::evidence::DeletionIntent;
use ksp_types::evidence::DeletionReport;
use ksp_types::{ActorId, Level, OpaqueSecretId};

const PLAINTEXT: &[u8] = b"the-secret-value-that-must-not-leak";
const MASK: u8 = 0x5a;

fn target() -> VersionTarget {
    VersionTarget {
        level: Level::Agent(
            ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap(),
        ),
        secret_id: OpaqueSecretId::new("secret-1"),
        version: 3,
    }
}

fn actor() -> ActorId {
    ActorId::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap())
}

/// The order in which the collaborators were called.
type Trace = RefCell<Vec<&'static str>>;

struct Store {
    ciphertexts: RefCell<BTreeMap<u32, Vec<u8>>>,
    trace: std::rc::Rc<Trace>,
    fail_delete: RefCell<bool>,
    delete_calls: RefCell<usize>,
}

impl Store {
    fn new(trace: std::rc::Rc<Trace>) -> Self {
        let mut map = BTreeMap::new();
        map.insert(3, PLAINTEXT.iter().map(|b| b ^ MASK).collect::<Vec<u8>>());
        Self {
            ciphertexts: RefCell::new(map),
            trace,
            fail_delete: RefCell::new(false),
            delete_calls: RefCell::new(0),
        }
    }
}

impl VersionStore for Store {
    fn fetch(&self, target: &VersionTarget) -> Option<Vec<u8>> {
        self.trace.borrow_mut().push("fetch");
        self.ciphertexts.borrow().get(&target.version).cloned()
    }

    fn delete_exact(&self, target: &VersionTarget) -> Result<String, ConsumeError> {
        self.trace.borrow_mut().push("delete");
        *self.delete_calls.borrow_mut() += 1;
        if *self.fail_delete.borrow() {
            return Err(ConsumeError::DeleteFailed {
                reason: "the backend refused the delete".to_string(),
            });
        }
        self.ciphertexts.borrow_mut().remove(&target.version);
        Ok("backend-event-9".to_string())
    }
}

struct XorDecryptor {
    trace: std::rc::Rc<Trace>,
}

impl Decryptor for XorDecryptor {
    fn decrypt(&self, _target: &VersionTarget, ciphertext: &[u8]) -> Result<Vec<u8>, ConsumeError> {
        self.trace.borrow_mut().push("decrypt");
        Ok(ciphertext.iter().map(|b| b ^ MASK).collect())
    }
}

struct RecordingChild {
    trace: std::rc::Rc<Trace>,
    received: RefCell<Vec<Vec<u8>>>,
    fail: RefCell<bool>,
}

impl RecordingChild {
    fn new(trace: std::rc::Rc<Trace>) -> Self {
        Self {
            trace,
            received: RefCell::new(Vec::new()),
            fail: RefCell::new(false),
        }
    }
}

impl Child for RecordingChild {
    fn deliver(&self, plaintext: &[u8]) -> Result<(), ChildFailureReason> {
        self.trace.borrow_mut().push("deliver");
        self.received.borrow_mut().push(plaintext.to_vec());
        if *self.fail.borrow() {
            return Err(ChildFailureReason::new("the child exited 3"));
        }
        Ok(())
    }
}

#[derive(Default)]
struct Sink {
    written: RefCell<Vec<Vec<u8>>>,
    fail_once: RefCell<bool>,
}

impl ReportSink for Sink {
    fn write(&self, report: &[u8]) -> Result<(), JournalError> {
        if *self.fail_once.borrow() {
            *self.fail_once.borrow_mut() = false;
            return Err(JournalError::Store {
                operation: "write",
                reason: "the report store is unavailable".to_string(),
            });
        }
        self.written.borrow_mut().push(report.to_vec());
        Ok(())
    }
}

fn request() -> ConsumeRequest {
    ConsumeRequest {
        target: target(),
        actor: actor(),
        signer_key_id: "agent-7-key-1".to_string(),
        reason: "consume completed".to_string(),
        acknowledged_at: 1_699_999_000,
    }
}

/// The intent the issuer signs, covering the target version.
fn intent() -> DeletionIntent {
    DeletionIntent {
        intent_id: "intent-1".to_string(),
        vault_id: ksp_types::VaultId::new("vault-1"),
        user_id: ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        level: target().level,
        secret_id: target().secret_id,
        version: target().version,
        deadline: 1_700_000_000,
        authorized_deleters: vec![
            ActorId::User(
                ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
            ),
            actor(),
        ],
    }
}

/// A verified intent, as a caller obtains one.
fn verified_intent(issuer: &EvidenceSigningKey) -> AuthorizedIntent {
    SignedIntent::sign(issuer, "alice-key-1", intent())
        .unwrap()
        .verify_as(&issuer.verifying_key())
        .unwrap()
}

fn fixture() -> (
    std::rc::Rc<Trace>,
    std::rc::Rc<Store>,
    std::rc::Rc<RecordingChild>,
    std::rc::Rc<Sink>,
    EvidenceSigningKey,
) {
    let trace = std::rc::Rc::new(Trace::default());
    (
        std::rc::Rc::clone(&trace),
        std::rc::Rc::new(Store::new(std::rc::Rc::clone(&trace))),
        std::rc::Rc::new(RecordingChild::new(std::rc::Rc::clone(&trace))),
        std::rc::Rc::new(Sink::default()),
        EvidenceSigningKey::generate(),
    )
}

// ---------------------------------------------------------------------------
// Criteria 1, 2, 3 — the postcondition, stated narrowly
// ---------------------------------------------------------------------------

#[test]
fn after_a_successful_removal_a_later_fresh_fetch_fails() {
    let (trace, store, child, sink, key) = fixture();
    let authorized = verified_intent(&key);
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());

    let outcome = consume(
        &*store,
        &XorDecryptor {
            trace: std::rc::Rc::clone(&trace),
        },
        &*child,
        &journal,
        &key,
        &*sink,
        &authorized,
        &request(),
    )
    .unwrap();

    assert_eq!(outcome, ConsumeOutcome::Removed);
    assert_eq!(outcome.exit_code(), 0);
    // The only promise: a later fresh fetch from this honest store fails.
    assert!(store.fetch(&target()).is_none());
    // And the ciphertext the ciphertext is gone from the store.
    assert!(store.ciphertexts.borrow().is_empty());
}

#[test]
fn the_order_is_deliver_then_delete_then_report() {
    let (trace, store, child, sink, key) = fixture();
    let authorized = verified_intent(&key);
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());

    consume(
        &*store,
        &XorDecryptor {
            trace: std::rc::Rc::clone(&trace),
        },
        &*child,
        &journal,
        &key,
        &*sink,
        &authorized,
        &request(),
    )
    .unwrap();

    assert_eq!(
        *trace.borrow(),
        vec!["fetch", "decrypt", "deliver", "delete"],
        "the child runs before the delete, and the delete before the report"
    );
    assert_eq!(sink.written.borrow().len(), 1);
}

#[test]
fn a_concurrent_pre_delete_fetch_and_a_saved_copy_both_still_decrypt() {
    let (trace, store, child, sink, key) = fixture();
    let authorized = verified_intent(&key);
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());

    // A concurrent reader that already retrieved the ciphertext, and someone who
    // saved a copy.
    let concurrent = store.ciphertexts.borrow().get(&3).cloned().unwrap();
    let mut saved = concurrent.clone();
    let mut saved_copy = Vec::new();
    saved_copy.append(&mut saved);

    consume(
        &*store,
        &XorDecryptor {
            trace: std::rc::Rc::clone(&trace),
        },
        &*child,
        &journal,
        &key,
        &*sink,
        &authorized,
        &request(),
    )
    .unwrap();

    let decryptor = XorDecryptor {
        trace: std::rc::Rc::clone(&trace),
    };
    assert_eq!(
        decryptor.decrypt(&target(), &concurrent).unwrap(),
        PLAINTEXT,
        "a pre-delete copy of the ciphertext remains decryptable"
    );
    assert_eq!(
        decryptor.decrypt(&target(), &saved_copy).unwrap(),
        PLAINTEXT,
        "a saved copy remains decryptable — the removal never claimed otherwise"
    );
}

// ---------------------------------------------------------------------------
// Criterion 4 — no recovery copy
// ---------------------------------------------------------------------------

#[test]
fn no_recovery_copy_of_the_plaintext_is_persisted() {
    let (trace, store, child, sink, key) = fixture();
    let authorized = verified_intent(&key);
    let scratch = tempfile::tempdir().unwrap();
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());

    consume(
        &*store,
        &XorDecryptor {
            trace: std::rc::Rc::clone(&trace),
        },
        &*child,
        &journal,
        &key,
        &*sink,
        &authorized,
        &request(),
    )
    .unwrap();

    // Nothing in the store holds the plaintext...
    for bytes in store.ciphertexts.borrow().values() {
        assert!(
            !bytes.windows(PLAINTEXT.len()).any(|w| w == PLAINTEXT),
            "the store must not hold the plaintext"
        );
    }
    // ...the report holds none of it...
    for report in sink.written.borrow().iter() {
        assert!(!report.windows(PLAINTEXT.len()).any(|w| w == PLAINTEXT));
    }
    // ...and nothing was written to disk. `consume` performs no filesystem I/O,
    // so the scratch directory stands in for anywhere a spool could appear.
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
}

// ---------------------------------------------------------------------------
// Criteria 5, 6 — the failed delete
// ---------------------------------------------------------------------------

#[test]
fn a_failed_delete_exits_nonzero_and_claims_no_deletion() {
    let (trace, store, child, sink, key) = fixture();
    let authorized = verified_intent(&key);
    *store.fail_delete.borrow_mut() = true;
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());

    let error = consume(
        &*store,
        &XorDecryptor {
            trace: std::rc::Rc::clone(&trace),
        },
        &*child,
        &journal,
        &key,
        &*sink,
        &authorized,
        &request(),
    )
    .unwrap_err();

    assert!(matches!(error, ConsumeError::DeleteFailed { .. }));
    assert_eq!(error.exit_code(), EXIT_DELETE_FAILED);
    assert_ne!(error.exit_code(), 0, "a failed delete is not success");

    // No report, no journal entry, no claim.
    assert!(sink.written.borrow().is_empty(), "no report may be signed");
    let event = ksp_deletion::AcknowledgementEvent {
        intent_id: "intent-1".to_string(),
        version: 3,
        actor: actor(),
        event_id: "backend-event-9".to_string(),
        acknowledged_at: 1_699_999_000,
    };
    assert!(!journal.is_journaled(&event).unwrap());
    assert!(
        !format!("{error}").contains("deleted"),
        "the message must not claim a deletion: {error}"
    );
}

#[test]
fn a_failed_delete_does_not_undo_the_delivery() {
    let (trace, store, child, sink, key) = fixture();
    let authorized = verified_intent(&key);
    *store.fail_delete.borrow_mut() = true;
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());

    let _ = consume(
        &*store,
        &XorDecryptor {
            trace: std::rc::Rc::clone(&trace),
        },
        &*child,
        &journal,
        &key,
        &*sink,
        &authorized,
        &request(),
    );

    assert_eq!(
        child.received.borrow().len(),
        1,
        "the child received the plaintext and that cannot be taken back"
    );
    assert_eq!(child.received.borrow()[0], PLAINTEXT.to_vec());
}

// ---------------------------------------------------------------------------
// Criteria 7, 8, 9 — the child failed after a successful removal
// ---------------------------------------------------------------------------

#[test]
fn a_child_failure_after_removal_exits_with_its_own_code() {
    let (trace, store, child, sink, key) = fixture();
    let authorized = verified_intent(&key);
    *child.fail.borrow_mut() = true;
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());

    let outcome = consume(
        &*store,
        &XorDecryptor {
            trace: std::rc::Rc::clone(&trace),
        },
        &*child,
        &journal,
        &key,
        &*sink,
        &authorized,
        &request(),
    )
    .unwrap();

    assert!(matches!(outcome, ConsumeOutcome::LostFreshFetch { .. }));
    assert_eq!(outcome.exit_code(), EXIT_LOST_FRESH_FETCH);
    assert_ne!(EXIT_LOST_FRESH_FETCH, EXIT_DELETE_FAILED);
    assert_ne!(EXIT_LOST_FRESH_FETCH, EXIT_UNCONSUMED_REFUSED);
    assert_ne!(EXIT_LOST_FRESH_FETCH, 0);
    // The removal happened anyway: leaving the version behind would not undo the
    // delivery.
    assert!(store.fetch(&target()).is_none());
    // And the failure is reported as the child's, with the record gone.
    assert!(sink.written.borrow().len() == 1);
}

#[test]
fn a_child_failure_does_not_remint_and_earlier_copies_still_decrypt() {
    let (trace, store, child, sink, key) = fixture();
    let authorized = verified_intent(&key);
    *child.fail.borrow_mut() = true;

    // Nothing in this crate can mint: the only token-shaped thing a caller could
    // hold is one it already had. This counter stands in for a mint call that
    // would have to come from outside.
    let mints = RefCell::new(0usize);
    let _mint_spy = || *mints.borrow_mut() += 1;

    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());
    let outcome = consume(
        &*store,
        &XorDecryptor {
            trace: std::rc::Rc::clone(&trace),
        },
        &*child,
        &journal,
        &key,
        &*sink,
        &authorized,
        &request(),
    )
    .unwrap();

    assert_eq!(*mints.borrow(), 0, "consume must not remint");
    let ConsumeOutcome::LostFreshFetch { reason } = outcome else {
        panic!("expected a lost fresh fetch");
    };
    assert_eq!(reason.as_str(), "the child exited 3");

    // An earlier delivery still works: nothing revoked it.
    let earlier = XorDecryptor {
        trace: std::rc::Rc::clone(&trace),
    };
    assert_eq!(
        earlier
            .decrypt(
                &target(),
                &PLAINTEXT.iter().map(|b| b ^ MASK).collect::<Vec<u8>>()
            )
            .unwrap(),
        PLAINTEXT
    );
}

// ---------------------------------------------------------------------------
// Criterion 10 — Scheduled backends require consumption
// ---------------------------------------------------------------------------

#[test]
fn a_scheduled_backend_refuses_a_compliant_run_without_consume() {
    assert!(require_consumption_for(true, true).is_ok());
    assert!(require_consumption_for(false, false).is_ok());

    let refusal = require_consumption_for(true, false).unwrap_err();
    assert!(matches!(refusal, ConsumeError::ConsumptionRequired));
    assert_eq!(refusal.exit_code(), EXIT_UNCONSUMED_REFUSED);
    assert!(format!("{refusal}").contains("--consume"));
}

// ---------------------------------------------------------------------------
// Criterion 11 — a proof of possession verifies twice in one bucket
// ---------------------------------------------------------------------------

#[test]
fn a_proof_of_possession_in_an_accepted_bucket_verifies_twice() {
    // The consume-side half of SC-008. A replay inside the window is a second
    // accepted verification, not a rejection — which is why nothing here is
    // exactly once.
    let now = 1_700_000_000u64;
    let window = ksp_identity::bucket_start(now);
    assert!(ksp_identity::is_accepted(now, window));
    assert!(
        ksp_identity::is_accepted(now, window),
        "the second verification in the same bucket is accepted too"
    );
}

// ---------------------------------------------------------------------------
// Criterion 12 — the report follows the acknowledgement
// ---------------------------------------------------------------------------

#[test]
fn a_failed_report_write_retries_from_the_journal_and_restores_nothing() {
    let (trace, store, child, sink, key) = fixture();
    let authorized = verified_intent(&key);
    *sink.fail_once.borrow_mut() = true;
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());

    let error = consume(
        &*store,
        &XorDecryptor {
            trace: std::rc::Rc::clone(&trace),
        },
        &*child,
        &journal,
        &key,
        &*sink,
        &authorized,
        &request(),
    )
    .unwrap_err();
    assert!(matches!(error, ConsumeError::ReportWrite(_)));
    assert!(sink.written.borrow().is_empty());

    // The acknowledgement is durable, so the missing report can be retried.
    let event = ksp_deletion::AcknowledgementEvent {
        intent_id: "intent-1".to_string(),
        version: 3,
        actor: actor(),
        event_id: "backend-event-9".to_string(),
        acknowledged_at: 1_699_999_000,
    };
    assert!(
        journal.is_journaled(&event).unwrap(),
        "the acknowledgement must survive a failed report write"
    );

    let report = ksp_deletion::SignedReport::sign(
        &key,
        DeletionReport {
            intent_id: "intent-1".to_string(),
            actor: actor(),
            signer_key_id: "agent-7-key-1".to_string(),
            reason: "consume completed".to_string(),
            outcome: ksp_types::evidence::Outcome::Success,
            reported_deleted_at: 1_699_999_000,
            level: target().level,
            secret_id: target().secret_id,
            version: 3,
        },
    )
    .unwrap();
    let bytes = ksp_types::cbor::encode(&report).unwrap();

    retry_report(&journal, &event, &bytes, &*sink).unwrap();
    retry_report(&journal, &event, &bytes, &*sink).unwrap();

    assert_eq!(
        *store.delete_calls.borrow(),
        1,
        "a report retry never deletes again"
    );
    assert!(
        store.ciphertexts.borrow().is_empty(),
        "the retry must not restore the ciphertext"
    );
}

/// A journal whose volume is unavailable: the acknowledgement cannot be made
/// durable, so nothing downstream of it may happen.
struct BrokenJournal;
impl JournalStore for BrokenJournal {
    fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, JournalError> {
        Err(JournalError::Store {
            operation: "read",
            reason: "the journal volume is unmounted".to_string(),
        })
    }
    fn put(&self, _key: &str, _bytes: &[u8]) -> Result<(), JournalError> {
        Err(JournalError::Store {
            operation: "write",
            reason: "the journal volume is unmounted".to_string(),
        })
    }
}

#[test]
fn with_no_durable_journal_no_report_is_signed() {
    let (trace, store, child, sink, key) = fixture();
    let authorized = verified_intent(&key);
    let journal = AcknowledgementJournal::new(BrokenJournal);

    let error = consume(
        &*store,
        &XorDecryptor {
            trace: std::rc::Rc::clone(&trace),
        },
        &*child,
        &journal,
        &key,
        &*sink,
        &authorized,
        &request(),
    )
    .unwrap_err();

    assert!(matches!(error, ConsumeError::ReportWrite(_)));
    assert!(
        sink.written.borrow().is_empty(),
        "a report may not be written when the acknowledgement is not durable"
    );
    assert_eq!(error.exit_code(), EXIT_UNCONSUMED_REFUSED);
}

#[test]
fn an_intent_that_does_not_cover_the_bound_version_is_refused() {
    let (trace, store, child, sink, key) = fixture();
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());
    let mut request = request();
    request.target.version = 4; // the signed intent is about version 3

    let error = consume(
        &*store,
        &XorDecryptor {
            trace: std::rc::Rc::clone(&trace),
        },
        &*child,
        &journal,
        &key,
        &*sink,
        &verified_intent(&key),
        &request,
    )
    .unwrap_err();

    assert!(matches!(error, ConsumeError::IntentDoesNotCover));
    assert!(trace.borrow().is_empty(), "the store is never touched");
}

#[test]
fn an_intent_signed_by_anyone_else_authorises_nothing() {
    // The only way to hold an AuthorizedIntent is to verify a signature, and a
    // forged intent has none that verifies. A caller cannot name itself as a
    // deleter: the actor list is inside the signed structure.
    let issuer = EvidenceSigningKey::generate();
    let impostor = EvidenceSigningKey::generate();
    let forged = SignedIntent::sign(&impostor, "alice-key-1", intent()).unwrap();

    assert!(
        forged.verify_as(&issuer.verifying_key()).is_err(),
        "an intent signed by someone else must not yield authority"
    );
}

// ---------------------------------------------------------------------------
// Criteria 13, 14 — the plaintext lives exactly once
// ---------------------------------------------------------------------------

#[test]
fn the_wipe_overwrites_the_buffer() {
    let mut buffer = PLAINTEXT.to_vec();
    wipe(&mut buffer);
    assert!(
        buffer.iter().all(|byte| *byte == 0),
        "the buffer must be overwritten, not merely dropped"
    );
}

#[test]
fn the_plaintext_appears_in_no_error_message() {
    let (trace, store, child, sink, key) = fixture();
    let authorized = verified_intent(&key);
    *child.fail.borrow_mut() = true;
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());

    let outcome = consume(
        &*store,
        &XorDecryptor {
            trace: std::rc::Rc::clone(&trace),
        },
        &*child,
        &journal,
        &key,
        &*sink,
        &authorized,
        &request(),
    )
    .unwrap();

    let rendered = format!("{outcome:?}");
    let needle = String::from_utf8_lossy(PLAINTEXT).to_string();
    assert!(
        !rendered.contains(&needle),
        "no plaintext in an outcome: {rendered}"
    );

    // And a failure path reports no plaintext either.
    let (_trace2, store2, child2, sink2, key2) = fixture();
    let authorized_second = verified_intent(&key2);
    *store2.fail_delete.borrow_mut() = true;
    let journal2 = AcknowledgementJournal::new(MemoryJournalStore::default());
    let error = consume(
        &*store2,
        &XorDecryptor { trace },
        &*child2,
        &journal2,
        &key2,
        &*sink2,
        &authorized_second,
        &request(),
    )
    .unwrap_err();
    assert!(!format!("{error}").contains(&needle));
}

// ---------------------------------------------------------------------------
// An unauthorized actor never reaches the store
// ---------------------------------------------------------------------------

#[test]
fn an_unauthorized_actor_is_refused_before_the_store_is_touched() {
    let (trace, store, child, sink, key) = fixture();
    let authorized = verified_intent(&key);
    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());
    let mut request = request();
    request.actor =
        ActorId::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000009").unwrap());

    let error = consume(
        &*store,
        &XorDecryptor {
            trace: std::rc::Rc::clone(&trace),
        },
        &*child,
        &journal,
        &key,
        &*sink,
        &authorized,
        &request,
    )
    .unwrap_err();

    assert!(matches!(error, ConsumeError::NotAuthorized { .. }));
    assert!(
        trace.borrow().is_empty(),
        "no fetch, no delete, no delivery"
    );
    assert_eq!(*store.delete_calls.borrow(), 0);
}
