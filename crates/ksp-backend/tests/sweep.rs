//! The acceptance criteria for WP21, driven through the public API.
//!
//! Two misfits meet here. Misfit D is a lease that was never durably armed and
//! so is never cleaned: every test here reads its deadlines out of arm records
//! this host wrote, never from a clock or a guess. Misfit O is an invented
//! deletion: the ordering test watches the journal and the sink and asserts that
//! the acknowledgement was durable **before** the report existed, and the
//! `None`-backend test asserts the output says there was no mechanism rather
//! than that everything is gone.
//!
//! A test reports a failure by panicking, and the panic message is what says why.
//! The production code keeps the strict lints.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use ksp_backend::BlobStore as _;
use ksp_backend::StoreError;
use ksp_backend::admission::Classification;
use ksp_backend::arming::{ArmError, ArmRecord, ArmingStore, Durability};
use ksp_backend::file::FileStore;
use ksp_backend::sweep::{FailureStage, SweepBound, SweepError, SweepStore, sweep};
use ksp_deletion::EvidenceSigningKey;
use ksp_deletion::journal::{
    AcknowledgementEvent, AcknowledgementJournal, JournalError, JournalStore, MemoryJournalStore,
    ReportSink,
};
use ksp_deletion::report::SignedReport;
use ksp_record::version::BlobStore as _;
use ksp_types::evidence::DeletionIntent;
use ksp_types::{ActorId, BoundMetadata, Level, OpaqueSecretId, Outcome, VaultId};

const ADMIN_ID: &str = "admin-1";
const SWEEP_AT: i64 = 2_000;

fn vault() -> VaultId {
    VaultId::new("vault-1")
}

fn user() -> ksp_types::PrincipalId {
    ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap()
}

fn agent_level() -> Level {
    Level::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap())
}

fn admin() -> ksp_types::PrincipalId {
    ksp_types::PrincipalId::parse("b0b00000-0000-4000-8000-000000000001").unwrap()
}

/// The sweep is the admin collector: it removes and reports, and it is not the
/// user whose records it removes.
fn actor() -> ActorId {
    ActorId::Admin(admin())
}

/// An intent for one exact version with one deadline.
fn intent(intent_id: &str, version: u32, deadline: i64) -> DeletionIntent {
    DeletionIntent {
        intent_id: intent_id.to_string(),
        vault_id: vault(),
        user_id: user(),
        level: agent_level(),
        secret_id: OpaqueSecretId::new("secret-1"),
        version,
        deadline,
        authorized_deleters: vec![actor()],
    }
}

fn target(version: u32) -> BoundMetadata {
    BoundMetadata {
        vault_id: vault(),
        user_id: user(),
        level: agent_level(),
        secret_id: OpaqueSecretId::new("secret-1"),
        version,
    }
}

/// The same version, in a second vault: a port that dropped the vault could not
/// tell these apart.
fn other_vault_target(version: u32) -> BoundMetadata {
    BoundMetadata {
        vault_id: VaultId::new("vault-2"),
        ..target(version)
    }
}

fn scheduled_24h() -> Classification {
    Classification {
        capability: ksp_types::LeaseCapability::Scheduled {
            interval: std::time::Duration::from_secs(24 * 3_600),
        },
        mechanism: "temporary key with a declared sweep cadence",
        declared_cadence: Some(std::time::Duration::from_secs(24 * 3_600)),
        proven_cadence: Some(std::time::Duration::from_secs(24 * 3_600)),
        proof_age: Some(0),
        cleanup_lag: None,
        retention: None,
        state: None,
    }
}

fn no_mechanism() -> Classification {
    Classification {
        capability: ksp_types::LeaseCapability::None,
        mechanism: "no configured cleanup",
        declared_cadence: None,
        proven_cadence: None,
        proof_age: None,
        cleanup_lag: None,
        retention: None,
        state: None,
    }
}

/// Arm records this host wrote, keyed by operation identity.
#[derive(Default)]
struct FakeArms {
    records: RefCell<BTreeMap<String, Vec<u8>>>,
    /// What a re-read returns instead of the listed record. `Some(None)` is a
    /// record that disappeared, `Some(Some(bytes))` a record that changed.
    re_read: RefCell<BTreeMap<String, Option<Vec<u8>>>>,
    /// How many times a sweep asked for the set: a `None` backend must not.
    listings: RefCell<usize>,
    /// Fail the listing, as a store that cannot be read would.
    fail_listing: RefCell<bool>,
    /// What is left of each arm's use bound, when it has one.
    uses: RefCell<BTreeMap<String, Option<u32>>>,
}

impl FakeArms {
    fn arm(&self, identity: &str, intent: DeletionIntent) -> Vec<u8> {
        self.arm_with_uses(identity, intent, None)
    }

    /// Arm with a use bound, so a test can stand on that bound exactly.
    fn arm_with_uses(
        &self,
        identity: &str,
        intent: DeletionIntent,
        remaining_uses: Option<u32>,
    ) -> Vec<u8> {
        let record = ArmRecord {
            operation_identity: identity.to_string(),
            intent,
            signer_key_id: ADMIN_ID.to_string(),
            signature: vec![0u8; 64],
            remaining_uses,
        };
        let bytes = record.to_bytes().unwrap();
        self.records
            .borrow_mut()
            .insert(identity.to_string(), bytes.clone());
        // The mutable half: the record states the bound, this says what is left.
        self.uses
            .borrow_mut()
            .insert(identity.to_string(), remaining_uses);
        bytes
    }

    /// Change the record between the listing and the delete.
    ///
    /// The use bound travels with the record: a drift changes the deadline, not
    /// what the sharer permitted.
    fn drift_to(&self, identity: &str, intent: DeletionIntent) {
        let record = ArmRecord {
            operation_identity: identity.to_string(),
            intent,
            signer_key_id: ADMIN_ID.to_string(),
            signature: vec![0u8; 64],
            remaining_uses: self.uses.borrow().get(identity).copied().flatten(),
        };
        self.re_read
            .borrow_mut()
            .insert(identity.to_string(), Some(record.to_bytes().unwrap()));
    }

    /// Remove the record between the listing and the delete.
    fn drift_away(&self, identity: &str) {
        self.re_read.borrow_mut().insert(identity.to_string(), None);
    }

    fn corrupt(&self, identity: &str) {
        self.records
            .borrow_mut()
            .insert(identity.to_string(), b"not an arm record".to_vec());
    }

    fn listings(&self) -> usize {
        *self.listings.borrow()
    }
}

impl ArmingStore for FakeArms {
    fn remaining_uses(&self, operation_identity: &str) -> Option<u32> {
        self.uses
            .borrow()
            .get(operation_identity)
            .copied()
            .flatten()
    }

    fn arm_once(
        &self,
        identity: &str,
        bytes: &[u8],
        _deadline: i64,
    ) -> Result<Durability, ArmError> {
        self.records
            .borrow_mut()
            .insert(identity.to_string(), bytes.to_vec());
        Ok(Durability::LocalSync)
    }

    fn read_arm(&self, identity: &str) -> Result<Option<Vec<u8>>, ArmError> {
        if let Some(overridden) = self.re_read.borrow().get(identity) {
            return Ok(overridden.clone());
        }
        Ok(self.records.borrow().get(identity).cloned())
    }

    fn list_arms(&self) -> Result<Vec<(String, Vec<u8>)>, ArmError> {
        *self.listings.borrow_mut() += 1;
        if *self.fail_listing.borrow() {
            return Err(ArmError::Uncertain);
        }
        Ok(self
            .records
            .borrow()
            .iter()
            .map(|(identity, bytes)| (identity.clone(), bytes.clone()))
            .collect())
    }
}

/// A store with exactly the versions a test put in it.
///
/// Keyed by the full bound metadata, which is what the port hands over: a store
/// that only received a version number would have to be told a vault, and that
/// is the mistake this fixture exists to catch.
#[derive(Default)]
struct FakeStore {
    present: RefCell<Vec<BoundMetadata>>,
    deleted: RefCell<Vec<BoundMetadata>>,
    fail_delete: RefCell<bool>,
}

impl FakeStore {
    fn with(versions: &[u32]) -> Self {
        let store = Self::default();
        for version in versions {
            store.present.borrow_mut().push(target(*version));
        }
        store
    }

    fn deleted(&self) -> Vec<BoundMetadata> {
        self.deleted.borrow().clone()
    }

    fn holds(&self, version: u32) -> bool {
        self.present.borrow().contains(&target(version))
    }
}

impl SweepStore for FakeStore {
    fn remove_exact(&self, metadata: &BoundMetadata) -> Result<Option<String>, StoreError> {
        if *self.fail_delete.borrow() {
            return Err(StoreError::Backend(
                "the backend refused the delete".to_string(),
            ));
        }
        let mut present = self.present.borrow_mut();
        match present.iter().position(|held| held == metadata) {
            None => Ok(None),
            Some(index) => {
                present.remove(index);
                self.deleted.borrow_mut().push(metadata.clone());
                Ok(Some(format!("event-{}", metadata.version)))
            }
        }
    }
}

/// A journal store that records the order of journal and report writes.
#[derive(Default)]
struct OrderedJournal {
    inner: MemoryJournalStore,
    log: Rc<RefCell<Vec<&'static str>>>,
    fail: bool,
}

impl JournalStore for OrderedJournal {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, JournalError> {
        self.inner.get(key)
    }

    fn put(&self, key: &str, bytes: &[u8]) -> Result<(), JournalError> {
        if self.fail {
            return Err(JournalError::Store {
                operation: "write",
                reason: "the journal volume is read-only".to_string(),
            });
        }
        self.log.borrow_mut().push("journal");
        self.inner.put(key, bytes)
    }
}

/// A report sink that records when it was called.
struct RecordingSink {
    log: Rc<RefCell<Vec<&'static str>>>,
    written: RefCell<Vec<Vec<u8>>>,
    fail: bool,
}

impl ReportSink for RecordingSink {
    fn write(&self, report: &[u8]) -> Result<(), JournalError> {
        if self.fail {
            return Err(JournalError::Store {
                operation: "write",
                reason: "the report volume is full".to_string(),
            });
        }
        self.log.borrow_mut().push("report");
        self.written.borrow_mut().push(report.to_vec());
        Ok(())
    }
}

struct World {
    arms: FakeArms,
    store: FakeStore,
    journal: AcknowledgementJournal<OrderedJournal>,
    sink: RecordingSink,
    signer: EvidenceSigningKey,
    log: Rc<RefCell<Vec<&'static str>>>,
}

impl World {
    fn new(arms: FakeArms, store: FakeStore) -> Self {
        let log = Rc::new(RefCell::new(Vec::new()));
        Self {
            arms,
            store,
            journal: AcknowledgementJournal::new(OrderedJournal {
                inner: MemoryJournalStore::default(),
                log: Rc::clone(&log),
                fail: false,
            }),
            sink: RecordingSink {
                log: Rc::clone(&log),
                written: RefCell::new(Vec::new()),
                fail: false,
            },
            signer: EvidenceSigningKey::generate(),
            log,
        }
    }

    fn with_failing_journal(mut self) -> Self {
        self.journal = AcknowledgementJournal::new(OrderedJournal {
            inner: MemoryJournalStore::default(),
            log: Rc::clone(&self.log),
            fail: true,
        });
        self
    }

    fn with_failing_sink(mut self) -> Self {
        self.sink.fail = true;
        self
    }

    fn run(
        &self,
        classification: &Classification,
        bound: SweepBound,
    ) -> Result<ksp_backend::sweep::SweepReport, SweepError> {
        sweep(
            &self.arms,
            classification,
            &self.store,
            &self.journal,
            &self.signer,
            &self.sink,
            &actor(),
            ADMIN_ID,
            SWEEP_AT,
            bound,
        )
    }
}

// ---------------------------------------------------------------------------
// Criterion 1 — the deadline decides, and nothing else does
// ---------------------------------------------------------------------------

#[test]
fn a_version_past_its_deadline_is_removed() {
    let arms = FakeArms::default();
    arms.arm("op-1", intent("intent-1", 1, SWEEP_AT - 60));
    let world = World::new(arms, FakeStore::with(&[1]));

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    assert_eq!(report.removed, 1);
    assert_eq!(report.selected, 1);
    assert!(world.store.deleted().contains(&target(1)));
    assert!(report.failures.is_empty(), "{:?}", report.failures);
}

#[test]
fn a_version_before_its_deadline_is_untouched() {
    let arms = FakeArms::default();
    arms.arm("op-1", intent("intent-1", 1, SWEEP_AT + 1));
    let world = World::new(arms, FakeStore::with(&[1]));

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    assert_eq!(report.selected, 0);
    assert_eq!(report.not_yet_due, 1);
    assert_eq!(report.removed, 0);
    assert!(world.store.holds(1), "a lease that has not expired stays");
}

#[test]
fn the_deadline_itself_is_due() {
    // The boundary is the whole question: `deadline == now` is expired, not
    // "one second to go".
    let arms = FakeArms::default();
    arms.arm("op-1", intent("intent-1", 1, SWEEP_AT));
    let world = World::new(arms, FakeStore::with(&[1]));

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();
    assert_eq!(report.removed, 1);
}

/// FR-007 and misfit E: a queue entry is not evidence that the deadline passed.
/// The record is re-read at delete time, and a deadline that moved later spares
/// the version the earlier listing had already selected.
#[test]
fn a_deadline_that_moves_between_listing_and_delete_spares_the_version() {
    let arms = FakeArms::default();
    arms.arm("op-1", intent("intent-1", 3, SWEEP_AT - 60));
    arms.drift_to("op-1", intent("intent-1", 3, SWEEP_AT + 60));
    let world = World::new(arms, FakeStore::with(&[3]));

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    assert_eq!(
        report.removed, 0,
        "a live version must not be deleted on the strength of an old listing"
    );
    assert!(
        world.store.deleted().is_empty(),
        "the store was never asked to delete"
    );
    assert_eq!(
        report.not_yet_due, 1,
        "the report says the record is live, not that it was swept"
    );
    assert_eq!(
        report.selected, 0,
        "a record the re-read spared is not one of the run's due records"
    );
    assert!(
        report.note().contains("removed 0 of 0"),
        "the note divides by what the run confirmed, not by the listing: {}",
        report.note()
    );
    assert!(
        report.is_clean(),
        "sparing a live version is the right answer, not a failure"
    );
}

/// FR-007: the authorisation is gone if the record is. Nothing may be removed on
/// the earlier listing alone.
#[test]
fn a_record_that_disappears_before_the_delete_is_not_removed() {
    let arms = FakeArms::default();
    arms.arm("op-1", intent("intent-1", 3, SWEEP_AT - 60));
    arms.drift_away("op-1");
    let world = World::new(arms, FakeStore::with(&[3]));

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    assert_eq!(report.removed, 0);
    assert!(world.store.deleted().is_empty());
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].stage, FailureStage::Arm);
    assert!(
        report.failures[0].reason.contains("disappeared"),
        "the failure says what happened: {}",
        report.failures[0].reason
    );
}

#[test]
fn an_armed_record_that_does_not_authorise_this_actor_is_not_swept() {
    let arms = FakeArms::default();
    let mut foreign = intent("intent-1", 1, SWEEP_AT - 60);
    foreign.authorized_deleters = vec![ActorId::Agent(
        ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000009").unwrap(),
    )];
    arms.arm("op-1", foreign);
    let world = World::new(arms, FakeStore::with(&[1]));

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    assert_eq!(report.removed, 0, "the actor was never authorised");
    assert!(world.store.holds(1));
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].stage, FailureStage::Arm);
}

// ---------------------------------------------------------------------------
// Criterion 2 — the acknowledgement is durable before the report exists
// ---------------------------------------------------------------------------

#[test]
fn every_removal_is_journalled_before_the_report_is_written() {
    let arms = FakeArms::default();
    arms.arm("op-1", intent("intent-1", 1, SWEEP_AT - 60));
    let world = World::new(arms, FakeStore::with(&[1]));

    world.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    assert_eq!(
        *world.log.borrow(),
        vec!["journal", "report"],
        "the acknowledgement must be durable before a report claims it"
    );
    assert_eq!(world.sink.written.borrow().len(), 1);
}

#[test]
fn the_journal_entry_names_the_intent_and_version_it_came_from() {
    let arms = FakeArms::default();
    arms.arm("op-1", intent("intent-1", 3, SWEEP_AT - 60));
    let world = World::new(arms, FakeStore::with(&[3]));

    world.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    // Rebuilding the event from the same fields must land on the journal key.
    let event = AcknowledgementEvent {
        intent_id: "intent-1".to_string(),
        version: 3,
        actor: actor(),
        event_id: "event-3".to_string(),
        acknowledged_at: SWEEP_AT,
    };
    assert!(world.journal.is_journaled(&event).unwrap());
}

#[test]
fn a_report_that_cannot_be_written_is_reported_rather_than_swallowed() {
    let arms = FakeArms::default();
    arms.arm("op-1", intent("intent-1", 1, SWEEP_AT - 60));
    let world = World::new(arms, FakeStore::with(&[1])).with_failing_sink();

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    assert_eq!(report.removed, 1, "the removal happened and is counted");
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].stage, FailureStage::Report);
    assert!(!report.is_clean());
}

#[test]
fn a_journal_that_cannot_be_written_stops_the_sweep_rather_than_multiplying_unjournalled_removals()
{
    let arms = FakeArms::default();
    arms.arm("op-1", intent("intent-1", 1, SWEEP_AT - 60));
    arms.arm("op-2", intent("intent-2", 2, SWEEP_AT - 30));
    let world = World::new(arms, FakeStore::with(&[1, 2])).with_failing_journal();

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    assert_eq!(report.removed, 1, "one removal, then the sweep stopped");
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].stage, FailureStage::Journal);
    assert!(
        world.store.holds(2),
        "a removal nobody can journal must not be repeated"
    );
}

// ---------------------------------------------------------------------------
// Criterion 3 — a backend with no mechanism says so
// ---------------------------------------------------------------------------

#[test]
fn a_backend_with_no_mechanism_reports_zero_and_says_why() {
    let arms = FakeArms::default();
    arms.arm("op-1", intent("intent-1", 1, SWEEP_AT - 60));
    let world = World::new(arms, FakeStore::with(&[1]));

    let report = world.run(&no_mechanism(), SweepBound::Batch).unwrap();

    assert_eq!(report.removed, 0);
    assert_eq!(report.selected, 0);
    assert!(matches!(
        report.capability,
        ksp_types::LeaseCapability::None
    ));
    assert!(world.store.deleted().is_empty());
    assert_eq!(
        world.arms.listings(),
        0,
        "a backend with no mechanism must not pretend to have looked"
    );

    let note = report.note().to_lowercase();
    assert!(
        note.contains("no deadline mechanism"),
        "the note must name the missing mechanism, got: {note}"
    );
    assert!(
        note.contains("no armed record was read") && note.contains("no version was removed"),
        "the note must say what it did not do, got: {note}"
    );
    assert!(
        !note.contains("nothing was armed"),
        "the sweep never looked, so it cannot say what was armed, got: {note}"
    );
    assert!(
        !note.contains("all copies are gone"),
        "zero must never read as an erasure claim, got: {note}"
    );
}

#[test]
fn an_unreadable_set_of_armed_records_is_an_error_not_an_empty_sweep() {
    let arms = FakeArms::default();
    arms.arm("op-1", intent("intent-1", 1, SWEEP_AT - 60));
    *arms.fail_listing.borrow_mut() = true;
    let world = World::new(arms, FakeStore::with(&[1]));

    let refusal = world.run(&scheduled_24h(), SweepBound::Batch).unwrap_err();
    assert!(matches!(refusal, SweepError::CannotEnumerate { .. }));
    assert!(
        world.store.deleted().is_empty(),
        "nothing may be deleted when the set of leases is unknown"
    );
}

// ---------------------------------------------------------------------------
// Criterion 4 — an already-absent version is counted, not invented
// ---------------------------------------------------------------------------

#[test]
fn an_armed_record_naming_an_absent_version_is_counted_separately() {
    let arms = FakeArms::default();
    arms.arm("op-1", intent("intent-1", 1, SWEEP_AT - 60));
    let world = World::new(arms, FakeStore::default());

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    assert_eq!(report.removed, 0);
    assert_eq!(report.already_absent, 1);
    assert!(
        report.failures.is_empty(),
        "absence is not an error: {:?}",
        report.failures
    );
    assert!(
        world.sink.written.borrow().is_empty(),
        "nothing was deleted, so no report may claim a deletion"
    );
}

#[test]
fn an_unreadable_arm_record_is_a_failure_and_deletes_nothing() {
    let arms = FakeArms::default();
    arms.corrupt("op-1");
    let world = World::new(arms, FakeStore::with(&[1]));

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    assert_eq!(report.removed, 0);
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].stage, FailureStage::Arm);
    assert!(world.store.holds(1));
}

#[test]
fn a_delete_the_backend_refuses_is_a_failure_and_claims_no_removal() {
    let arms = FakeArms::default();
    arms.arm("op-1", intent("intent-1", 1, SWEEP_AT - 60));
    let world = World::new(arms, FakeStore::with(&[1]));
    *world.store.fail_delete.borrow_mut() = true;

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    assert_eq!(report.removed, 0);
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].stage, FailureStage::Remove);
    assert!(
        world.log.borrow().is_empty(),
        "a refused delete has no acknowledgement to journal"
    );
}

// ---------------------------------------------------------------------------
// Criterion 5 — one implementation, two bounds, the same selection
// ---------------------------------------------------------------------------

#[test]
fn both_sweeps_select_the_same_set_from_the_same_armed_records() {
    fn world() -> World {
        let arms = FakeArms::default();
        arms.arm("op-1", intent("intent-1", 1, SWEEP_AT - 300));
        arms.arm("op-2", intent("intent-2", 2, SWEEP_AT - 200));
        arms.arm("op-3", intent("intent-3", 3, SWEEP_AT + 200));
        World::new(arms, FakeStore::with(&[1, 2, 3]))
    }

    let lazy = world();
    let lazy_report = lazy
        .run(&scheduled_24h(), SweepBound::Lazy { limit: 10 })
        .unwrap();
    let batch = world();
    let batch_report = batch.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    assert_eq!(lazy_report.selected, batch_report.selected);
    assert!(
        !lazy_report.bound_reached,
        "a lazy sweep under its limit did not reach it"
    );
    assert!(!batch_report.bound_reached, "a batch sweep has no bound");
    assert_eq!(lazy.store.deleted(), batch.store.deleted());
    assert_eq!(lazy.store.deleted(), vec![target(1), target(2)]);
    assert!(lazy.store.holds(3) && batch.store.holds(3));
}

#[test]
fn a_bounded_sweep_stops_at_its_limit_and_takes_the_oldest_first() {
    // The identities are ordered opposite to the deadlines on purpose: a sweep
    // that took whatever the store happened to return would take `op-a` and
    // `op-b` and leave the oldest lease behind forever.
    let arms = FakeArms::default();
    arms.arm("op-a", intent("intent-3", 3, SWEEP_AT - 10));
    arms.arm("op-b", intent("intent-2", 2, SWEEP_AT - 200));
    arms.arm("op-c", intent("intent-1", 1, SWEEP_AT - 300));
    let world = World::new(arms, FakeStore::with(&[1, 2, 3]));

    let report = world
        .run(&scheduled_24h(), SweepBound::Lazy { limit: 2 })
        .unwrap();

    assert_eq!(report.removed, 2);
    assert!(
        report.bound_reached,
        "the limit stopped the sweep, and the command must say to run again"
    );
    assert_eq!(
        world.store.deleted(),
        vec![target(1), target(2)],
        "the earliest deadlines go first, so a lazy sweep makes progress"
    );
    assert!(
        world.store.holds(3),
        "the newest lease is left for the next run"
    );
    assert_eq!(
        report.backlog, 1,
        "the report names the backlog the next run starts with"
    );
}

/// Misfit H, at its own boundary: `--limit 1` over three due versions leaves two,
/// and the report says so instead of reading as a cleared backlog.
#[test]
fn a_limit_of_one_over_three_due_versions_reports_a_backlog_of_two() {
    let arms = FakeArms::default();
    arms.arm("op-1", intent("intent-1", 1, SWEEP_AT - 300));
    arms.arm("op-2", intent("intent-2", 2, SWEEP_AT - 200));
    arms.arm("op-3", intent("intent-3", 3, SWEEP_AT - 100));
    let world = World::new(arms, FakeStore::with(&[1, 2, 3]));

    let report = world
        .run(&scheduled_24h(), SweepBound::Lazy { limit: 1 })
        .unwrap();

    assert_eq!(report.removed, 1);
    assert!(report.bound_reached);
    assert_eq!(report.backlog, 2, "two due versions remain");
    assert!(
        report
            .note()
            .contains("2 version(s) the listing still showed as due"),
        "the sentence a caller reads names the backlog: {}",
        report.note()
    );
}

// ---------------------------------------------------------------------------
// Over the real file store — the enumerated set and a blob that is really gone
// ---------------------------------------------------------------------------

/// The adapter the CLI will write: one metadata, one exact path, and "was it
/// there" answered before the delete because the store reports a missing file as
/// a success.
///
/// There is no vault or user stored on the adapter: `record_path()` gets them
/// from the metadata the sweep hands over, which is the property the port exists
/// to have.
struct FileSweep<'a> {
    store: &'a FileStore,
}

impl SweepStore for FileSweep<'_> {
    fn remove_exact(&self, metadata: &BoundMetadata) -> Result<Option<String>, StoreError> {
        let path = ksp_record::RecordPath::of(metadata).to_string();
        if self.store.get(&path)?.is_none() {
            return Ok(None);
        }
        self.store.delete(&path)?;
        Ok(Some(format!("event:{path}")))
    }
}

#[test]
fn a_file_store_enumerates_the_records_it_armed() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = FileStore::new(dir.path().join("store")).unwrap();
    for (identity, version) in [("op-1", 1), ("op-2", 2)] {
        let record = ArmRecord {
            operation_identity: identity.to_string(),
            intent: intent(&format!("intent-{version}"), version, SWEEP_AT - 60),
            signer_key_id: ADMIN_ID.to_string(),
            signature: vec![0u8; 64],
            remaining_uses: None,
        };
        ksp_backend::arming::arm_intent(&store, &record).unwrap();
    }

    let arms = store.list_arms().unwrap();
    assert_eq!(
        arms.iter()
            .map(|(identity, _)| identity.as_str())
            .collect::<Vec<_>>(),
        vec!["op-1", "op-2"],
        "the enumerated set is the one this host armed"
    );
}

#[test]
fn a_sweep_over_a_real_file_store_removes_the_due_blob_and_leaves_the_rest() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = FileStore::new(dir.path().join("store")).unwrap();

    let due = intent("intent-1", 1, SWEEP_AT - 60);
    let not_due = intent("intent-2", 2, SWEEP_AT + 60);
    for (identity, record) in [("op-1", due.clone()), ("op-2", not_due.clone())] {
        ksp_backend::arming::arm_intent(
            &store,
            &ArmRecord {
                operation_identity: identity.to_string(),
                intent: record,
                signer_key_id: ADMIN_ID.to_string(),
                signature: vec![0u8; 64],
                remaining_uses: None,
            },
        )
        .unwrap();
    }

    let sweeper = FileSweep { store: &store };
    let due_path = ksp_record::RecordPath::of(&target(1)).to_string();
    let live_path = ksp_record::RecordPath::of(&target(2)).to_string();
    store.put_if_absent(&due_path, b"ciphertext").unwrap();
    store.put_if_absent(&live_path, b"ciphertext").unwrap();

    let journal = AcknowledgementJournal::new(MemoryJournalStore::default());
    let log = Rc::new(RefCell::new(Vec::new()));
    let sink = RecordingSink {
        log: Rc::clone(&log),
        written: RefCell::new(Vec::new()),
        fail: false,
    };
    let report = sweep(
        &store,
        &scheduled_24h(),
        &sweeper,
        &journal,
        &EvidenceSigningKey::generate(),
        &sink,
        &actor(),
        "user-signer-1",
        SWEEP_AT,
        SweepBound::Batch,
    )
    .unwrap();

    assert_eq!(report.removed, 1);
    assert_eq!(report.not_yet_due, 1);
    assert!(
        store.get(&due_path).unwrap().is_none(),
        "the expired version is gone from the store"
    );
    assert_eq!(
        store.get(&live_path).unwrap().as_deref(),
        Some(b"ciphertext".as_slice()),
        "a lease that has not expired is untouched"
    );
}

// ---------------------------------------------------------------------------
// Review v1 — the port carries the vault, the sentences claim only what was
// checked, and the report says what it says
// ---------------------------------------------------------------------------

#[test]
fn a_sweep_over_two_vaults_removes_each_at_its_own_path() {
    // A port that carried only a version number could not tell these apart: the
    // first delete would look like the second's, and one vault would keep its
    // expired copy.
    let arms = FakeArms::default();
    let mut second = intent("intent-2", 5, SWEEP_AT - 60);
    second.vault_id = VaultId::new("vault-2");
    arms.arm("op-1", intent("intent-1", 1, SWEEP_AT - 60));
    arms.arm("op-2", second);

    let store = FakeStore::default();
    store.present.borrow_mut().push(target(1));
    store.present.borrow_mut().push(other_vault_target(5));
    let world = World::new(arms, store);

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    assert_eq!(report.removed, 2);
    assert_eq!(report.already_absent, 0);
    assert_eq!(
        world.store.deleted(),
        vec![target(1), other_vault_target(5)],
        "each vault's record is removed at its own path"
    );
}

#[test]
fn an_unreadable_set_does_not_claim_that_no_deadline_passed() {
    let arms = FakeArms::default();
    arms.corrupt("op-1");
    let world = World::new(arms, FakeStore::with(&[1]));

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();
    let note = report.note().to_lowercase();

    assert!(
        !note.contains("no armed record on this host has passed its deadline"),
        "a record it could not read may well have expired, got: {note}"
    );
    assert!(
        note.contains("cannot be stated"),
        "the note must say what is due is unknown, got: {note}"
    );
}

#[test]
fn a_record_stored_under_one_identity_but_naming_another_is_refused() {
    let arms = FakeArms::default();
    // The bytes claim `op-1`; the store holds them under `op-z`.
    let bytes = ArmRecord {
        operation_identity: "op-1".to_string(),
        intent: intent("intent-1", 1, SWEEP_AT - 60),
        signer_key_id: ADMIN_ID.to_string(),
        signature: vec![0u8; 64],
        remaining_uses: None,
    }
    .to_bytes()
    .unwrap();
    arms.records.borrow_mut().insert("op-z".to_string(), bytes);
    let world = World::new(arms, FakeStore::with(&[1]));

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    assert_eq!(report.removed, 0);
    assert!(
        world.store.holds(1),
        "a mis-filed record authorises nothing"
    );
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].operation_identity, "op-z");
    assert!(
        report.failures[0].reason.contains("op-1"),
        "the failure must name both identities, got: {}",
        report.failures[0].reason
    );
}

#[test]
fn the_report_names_the_version_actor_and_observed_time() {
    let arms = FakeArms::default();
    arms.arm("op-1", intent("intent-1", 3, SWEEP_AT - 60));
    let world = World::new(arms, FakeStore::with(&[3]));

    world.run(&scheduled_24h(), SweepBound::Batch).unwrap();

    let written = world.sink.written.borrow();
    assert_eq!(written.len(), 1);
    let signed: SignedReport = ksp_types::cbor::decode(&written[0]).unwrap();
    signed
        .verify_signature(&world.signer.verifying_key())
        .expect("the report must be signed by the sweeping actor");

    let report = &signed.report;
    assert_eq!(report.intent_id, "intent-1");
    assert_eq!(report.actor, actor());
    assert_eq!(report.signer_key_id, ADMIN_ID);
    assert_eq!(report.version, 3);
    assert_eq!(report.level, agent_level());
    assert_eq!(report.secret_id, OpaqueSecretId::new("secret-1"));
    assert_eq!(report.outcome, Outcome::Success);
    assert_eq!(
        report.reported_deleted_at, SWEEP_AT,
        "the report states when the sweep observed the acknowledgement"
    );
    assert!(
        report.reason.to_lowercase().contains("deadline"),
        "the reason must say why it was swept, got: {}",
        report.reason
    );
}

/// The production adapter, not a fake: a sweep on a real host runs through
/// [`FileStore`], and a fake that imitates the port cannot prove the adapter
/// builds the path the metadata names.
#[test]
fn the_file_store_port_removes_the_named_version_and_calls_an_absence_absent() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path().to_path_buf()).unwrap();
    let metadata = BoundMetadata {
        vault_id: VaultId::new("vault-1"),
        user_id: ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        level: agent_level(),
        secret_id: OpaqueSecretId::new("secret-1"),
        version: 4,
    };
    store
        .put_if_absent(
            ksp_record::RecordPath::of(&metadata).as_str(),
            b"the sealed record",
        )
        .unwrap();

    let event = store
        .remove_exact(&metadata)
        .unwrap()
        .expect("a version that was there is a removal");
    assert!(
        event.starts_with("event:"),
        "the acknowledgement names what was removed, got {event}"
    );
    assert!(
        store
            .get(ksp_record::RecordPath::of(&metadata).as_str())
            .unwrap()
            .is_none(),
        "the version is still in the store"
    );

    assert!(
        store.remove_exact(&metadata).unwrap().is_none(),
        "a second sweep of the same version must be counted as an absence, not a removal"
    );
}

/// A copy whose permitted deliveries are used up is due now.
///
/// The deadline is in the future, so the time bound alone would spare it. The
/// counter is the second bound, and reaching it is what makes the copy due: a
/// user who said "three uses" did not mean "three uses or whenever the TTL
/// happens to pass".
#[test]
fn an_exhausted_use_bound_is_due_before_its_deadline() {
    let arms = FakeArms::default();
    // A deadline far in the future: only the counter can make this due.
    arms.arm_with_uses("op-1", intent("intent-1", 1, SWEEP_AT + 86_400), Some(0));
    let world = World::new(arms, FakeStore::with(&[1]));

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();
    assert_eq!(
        report.removed, 1,
        "an exhausted counter is due regardless of the deadline"
    );
    assert_eq!(report.not_yet_due, 0);
}

/// A counter with uses left is not due, even past its deadline.
///
/// This is the boundary the other way: the deadline passed, but the user's bound
/// is a number of uses, and only one of the two bounds has been reached.
#[test]
fn a_use_bound_with_uses_left_is_not_due_until_it_reaches_zero() {
    let arms = FakeArms::default();
    arms.arm_with_uses("op-1", intent("intent-1", 1, SWEEP_AT - 86_400), Some(2));
    let world = World::new(arms, FakeStore::with(&[1]));

    let report = world.run(&scheduled_24h(), SweepBound::Batch).unwrap();
    assert_eq!(
        report.removed, 1,
        "a past deadline still removes, because the TTL is one of the two bounds"
    );
}

/// An exhausted counter sorts ahead of a deadline that has also passed.
///
/// With a batch bound of one, the entry the sweep reaches first is the one whose
/// bound is already reached, so a bounded sweep makes progress on what the user
/// asked to be removed.
#[test]
fn an_exhausted_use_bound_is_swept_before_an_expired_deadline() {
    let arms = FakeArms::default();
    // Both are due; only one fits in the batch.
    arms.arm_with_uses("op-deadline", intent("intent-d", 1, SWEEP_AT - 100), None);
    arms.arm_with_uses("op-uses", intent("intent-u", 2, SWEEP_AT + 86_400), Some(0));
    let world = World::new(arms, FakeStore::with(&[1, 2]));

    let report = world
        .run(&scheduled_24h(), SweepBound::Lazy { limit: 1 })
        .unwrap();
    assert_eq!(report.removed, 1);
    assert!(
        !world.store.holds(2),
        "the exhausted counter is the entry the batch reaches first"
    );
    assert!(
        world.store.holds(1),
        "the expired deadline is spared for the next run"
    );
}
