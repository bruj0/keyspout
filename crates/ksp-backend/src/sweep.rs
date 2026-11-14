//! The foreground **lease sweep**: what this host armed, and what has expired.
//!
//! A client that armed a deadline is not running at the deadline. On a store with
//! `NativeExpiry` the store performs the destruction; on a store where this host
//! is the only actor that can delete, someone has to actually do it — and that
//! someone is a foreground invocation the operator schedules. This module is that
//! invocation's body, and its contract is honest about exactly three things: what
//! it removed, when it decided, and whether the backend has a mechanism at all.
//!
//! # The two misfits this answers
//!
//! - **Misfit D (a lease that is never cleaned)** — every deadline read here comes
//!   out of an arm record this host wrote ([`ArmingStore::list_arms`]). Nothing is
//!   inferred from a clock, a record's absence or a token.
//! - **Misfit O (an invented deletion)** — a removal is journalled through S4
//!   *before* any report claims it, and a record that is already absent is counted
//!   as absent rather than as a removal. The sweep never infers an erasure or a
//!   deletion time; the time it records is when it observed the acknowledgement.
//!
//! # One implementation, two bounds
//!
//! `secret purge-expired` and `secret gc` are the same sequence with a different
//! [`SweepBound`]. They cannot drift because there is nothing to drift: the bound
//! decides when to stop, not what to look at.
//!
//! # What zero means
//!
//! A backend classified `None` has no deadline mechanism, so nothing was armed
//! for it to clean. The report says `capability=None` with zero counts and the
//! command exits success — it did everything that could be done. It must never
//! read as "all copies are gone": [`SweepReport::note`] states the mechanism that
//! is missing, not an absence of records.
//!
//! A backend where the arm record itself expires at the deadline (the `valkey`
//! arming sets a TTL on it) will list nothing after the deadline has passed. The
//! sweep then reports zero expired leases and says so; it does not claim the
//! store cleaned anything, and it does not claim there was nothing to clean.

use ksp_deletion::journal::{
    AcknowledgementEvent, AcknowledgementJournal, JournalStore, ReportSink, retry_report,
};
use ksp_deletion::{EvidenceSigningKey, SignedReport};
use ksp_types::evidence::DeletionIntent;
use ksp_types::{ActorId, BoundMetadata, DeletionReport, LeaseCapability, Outcome, cbor};

use crate::admission::Classification;
use crate::arming::{ArmError, ArmRecord, ArmingStore};
use crate::store::StoreError;

/// How much of the due set one invocation may remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepBound {
    /// `secret purge-expired`: stop after this many removals, so a foreground
    /// command on a large backlog stays bounded and the next run continues.
    ///
    /// The limit bounds *deletions*, not records examined: a due record whose
    /// version is already gone costs one lookup and does not count, so a backlog
    /// of absences is walked in one invocation by design. The alternative — a
    /// limit that counted those too — would let a stale set of arm records stall
    /// every future sweep on the same head.
    Lazy {
        /// The most versions this invocation removes.
        limit: usize,
    },
    /// `secret gc`: every due record.
    Batch,
}

impl SweepBound {
    fn is_reached(&self, removed: usize) -> bool {
        match self {
            Self::Lazy { limit } => removed >= *limit,
            Self::Batch => false,
        }
    }
}

/// The one capability a sweep has over storage.
///
/// Deliberately not a general store: a sweep may remove one exact version and
/// learn whether it was there. It cannot read a record, cannot write one, and
/// cannot list, so "the sweep restored ciphertext" and "the sweep deleted the
/// wrong version" are both outside what the type can express.
pub trait SweepStore {
    /// Remove exactly this version.
    ///
    /// The bound metadata is the whole identity — vault, user, level, secret and
    /// version — because `record_path()` needs all five. A port that handed over
    /// a bare target would leave the adapter unable to build a path without being
    /// told a vault out of band.
    ///
    /// `Ok(Some(event_id))` means the backend acknowledged removing something.
    /// `Ok(None)` means there was nothing there to remove — counted as
    /// [`SweepReport::already_absent`], never as a removal, because this host did
    /// not observe a deletion and will not claim one.
    fn remove_exact(&self, metadata: &BoundMetadata) -> Result<Option<String>, StoreError>;
}

/// Where a sweep stopped, when it did not finish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureStage {
    /// The armed record itself could not be used: unreadable bytes, or an intent
    /// that never authorised this actor.
    Arm,
    /// The backend refused the delete, or failed while performing it.
    Remove,
    /// The acknowledgement could not be made durable, so no report may follow.
    Journal,
    /// The report could not be written. The acknowledgement is durable, so the
    /// evidence exists and S4's retry can write the report later.
    Report,
}

/// One record the sweep could not finish, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepFailure {
    /// The operation identity of the armed record this concerned.
    pub operation_identity: String,
    /// Where the sweep stopped.
    pub stage: FailureStage,
    /// What the backend or the journal said.
    pub reason: String,
}

/// What one sweep did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepReport {
    /// The capability the backend was classified with. `None` means there was no
    /// mechanism, not that nothing was armed.
    pub capability: LeaseCapability,
    /// Records the run treated as due: selected from the listing and then
    /// confirmed by the delete-time re-read. A record that re-read as not due
    /// is counted in `not_yet_due` instead, so `removed + already_absent +
    /// failures` never exceeds this number.
    pub selected: usize,
    /// Versions this invocation removed.
    pub removed: usize,
    /// Due records naming a version that was already gone.
    pub already_absent: usize,
    /// Armed records whose deadline had not passed when the run decided.
    ///
    /// Counted at selection, and again for a record that re-read as not due at
    /// delete time. A record that moved between the two is counted here because
    /// it is live at the moment that matters.
    pub not_yet_due: usize,
    /// Everything that did not finish, in the order it happened.
    pub failures: Vec<SweepFailure>,
    /// Whether the bound stopped this invocation before the due set ran out.
    ///
    /// Not a failure: `secret purge-expired` is bounded on purpose and the next
    /// run continues from the same place. It is reported so the command can say
    /// "run again" rather than implying it swept everything.
    pub bound_reached: bool,
    /// Due versions still to remove when the bound stopped this invocation.
    ///
    /// Reported so a bounded run cannot look like a completed one. The count
    /// comes from the listing and is not re-read — the next run re-reads each
    /// candidate before deleting, so this is what it starts with, not a
    /// promise that all of them are still due. Zero for a batch sweep.
    pub backlog: usize,
}

impl SweepReport {
    /// A report for a backend with no deadline mechanism.
    ///
    /// Zero counts and `capability=None`, with `not_yet_due` also zero because
    /// the armed records were not read: a mechanism that does not exist cannot
    /// have a backlog.
    fn no_mechanism() -> Self {
        Self {
            capability: LeaseCapability::None,
            selected: 0,
            removed: 0,
            already_absent: 0,
            not_yet_due: 0,
            failures: Vec::new(),
            bound_reached: false,
            backlog: 0,
        }
    }

    /// Whether the sweep finished everything it started.
    ///
    /// Reaching the bound is not a failure: the bound is what the command asked
    /// for. A failure is a record that could not be finished for a reason.
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }

    /// The sentence the command prints beside the counts.
    ///
    /// It names what happened or what could not happen, and it never turns a
    /// count into a claim about copies that are not on this host.
    pub fn note(&self) -> String {
        if matches!(self.capability, LeaseCapability::None) {
            return "this backend has no deadline mechanism, so no sweep can remove anything here: \
                    no armed record was read and no version was removed. It says nothing about \
                    whether a copy still exists"
                .to_string();
        }
        let mut note = format!(
            "removed {} of {} expired lease(s) on this host; {} were already absent",
            self.removed, self.selected, self.already_absent
        );
        if self.selected == 0 && self.not_yet_due == 0 {
            if self.failures.is_empty() {
                note.push_str(
                    "; no armed record on this host has passed its deadline, which is not \
                     evidence that the store cleaned anything",
                );
            } else {
                note.push_str(
                    "; no readable armed record has passed its deadline, and what is due cannot \
                     be stated while records this host armed cannot be read",
                );
            }
        }
        if self.bound_reached {
            note.push_str(&format!(
                "; the bound was reached with {} version(s) the listing still showed as due, \
                 so this run is not a cleared backlog; the next one re-reads each before \
                 deleting and continues from here",
                self.backlog
            ));
        }
        if !self.failures.is_empty() {
            note.push_str(&format!("; {} did not finish", self.failures.len()));
        }
        note
    }
}

/// Why a sweep did not run at all.
#[derive(Debug, thiserror::Error)]
pub enum SweepError {
    /// The armed records could not be enumerated.
    ///
    /// An empty list and an unreadable list are different facts, and only the
    /// first may be reported as "nothing is due".
    #[error("the armed records this host wrote could not be read: {reason}")]
    CannotEnumerate {
        /// The store's reason.
        reason: String,
    },
}

/// One due record, with the intent it was armed under.
struct Due {
    operation_identity: String,
    intent: DeletionIntent,
    /// The use bound was reached, so the copy is due regardless of the deadline.
    uses_exhausted: bool,
}

/// Run one sweep.
///
/// `at` is the instant the sweep decides at, passed in rather than read here so a
/// test can stand at a boundary exactly. `actor` must be one of the intent's
/// authorised deleters; a record that does not name it is a failure, not a
/// deletion.
#[allow(clippy::too_many_arguments)]
pub fn sweep<S: JournalStore>(
    arming: &dyn ArmingStore,
    classification: &Classification,
    store: &dyn SweepStore,
    journal: &AcknowledgementJournal<S>,
    signer: &EvidenceSigningKey,
    sink: &dyn ReportSink,
    actor: &ActorId,
    signer_key_id: &str,
    at: i64,
    bound: SweepBound,
) -> Result<SweepReport, SweepError> {
    // A backend with no mechanism is not a sweep with nothing to do: there is no
    // mechanism, so nothing was armed and nothing is claimed. The armed records
    // are not even read, because reading them would suggest a backlog exists.
    if matches!(classification.capability, LeaseCapability::None) {
        return Ok(SweepReport::no_mechanism());
    }

    let arms = arming
        .list_arms()
        .map_err(|error| SweepError::CannotEnumerate {
            reason: match error {
                ArmError::Unsupported => {
                    "this store cannot enumerate the records it armed".to_string()
                }
                other => other.to_string(),
            },
        })?;

    let mut report = SweepReport {
        capability: classification.capability,
        selected: 0,
        removed: 0,
        already_absent: 0,
        not_yet_due: 0,
        failures: Vec::new(),
        bound_reached: false,
        backlog: 0,
    };

    // Earliest deadline first, so a bounded sweep makes progress instead of
    // re-reading the same head of the set on every run. The identity breaks a
    // tie deterministically.
    let mut due: Vec<Due> = Vec::new();
    for (operation_identity, bytes) in arms {
        let record = match ArmRecord::from_bytes(&bytes) {
            Ok(record) => record,
            Err(error) => {
                report.failures.push(SweepFailure {
                    operation_identity,
                    stage: FailureStage::Arm,
                    reason: error.to_string(),
                });
                continue;
            }
        };
        if record.operation_identity != operation_identity {
            let reason = format!(
                "the record names operation identity {} but is stored under this one",
                record.operation_identity
            );
            report.failures.push(SweepFailure {
                operation_identity,
                stage: FailureStage::Arm,
                reason,
            });
            continue;
        }
        // Two bounds, and either one makes the copy due. A counter at zero means
        // the permitted deliveries are used up, which is due now regardless of
        // the deadline; `None` is a time-bounded arm and keeps the old rule.
        //
        // The *remaining* count comes from the store, not from the record: the
        // record states the bound it was armed with and is create-only, so the
        // mutable half is the counter file beside it. A record that claims a
        // bound the store has no counter for is treated as unbounded rather than
        // as exhausted, because inventing a removal is the wrong direction.
        let uses_exhausted = record.remaining_uses.is_some()
            && arming.remaining_uses(&operation_identity) == Some(0);
        if !uses_exhausted && record.intent.deadline > at {
            report.not_yet_due += 1;
            continue;
        }
        due.push(Due {
            operation_identity,
            intent: record.intent,
            uses_exhausted,
        });
    }
    // An exhausted counter is due *now*, so it sorts before any deadline: the
    // bound that is already reached is the earliest bound there is.
    due.sort_by(|left, right| {
        right
            .uses_exhausted
            .cmp(&left.uses_exhausted)
            .then_with(|| left.intent.deadline.cmp(&right.intent.deadline))
            .then_with(|| left.operation_identity.cmp(&right.operation_identity))
    });
    report.selected = due.len();

    let mut pending = due.into_iter();
    while let Some(entry) = pending.next() {
        if bound.is_reached(report.removed) {
            report.bound_reached = true;
            // The entry in hand was never examined, and neither was anything
            // after it: that is the backlog the next run starts with.
            report.backlog = 1 + pending.count();
            break;
        }

        // Re-read at delete time (FR-007). The list was a snapshot, and another
        // run or a changed arming can have changed what is due since; a queue
        // entry alone is not evidence that the deadline has passed. The re-read
        // record is authoritative from here: it decides both the deadline and
        // who may delete.
        let record = match arming.read_arm(&entry.operation_identity) {
            Ok(Some(bytes)) => match ArmRecord::from_bytes(&bytes) {
                Ok(record) if record.operation_identity == entry.operation_identity => record,
                Ok(_) => {
                    report.failures.push(SweepFailure {
                        operation_identity: entry.operation_identity,
                        stage: FailureStage::Arm,
                        reason: "the record now names another operation identity".to_string(),
                    });
                    continue;
                }
                Err(error) => {
                    report.failures.push(SweepFailure {
                        operation_identity: entry.operation_identity,
                        stage: FailureStage::Arm,
                        reason: error.to_string(),
                    });
                    continue;
                }
            },
            Ok(None) => {
                report.failures.push(SweepFailure {
                    operation_identity: entry.operation_identity,
                    stage: FailureStage::Arm,
                    reason: "the armed record disappeared before the delete, so nothing was \
                             removed on the strength of the earlier listing"
                        .to_string(),
                });
                continue;
            }
            Err(error) => {
                report.failures.push(SweepFailure {
                    operation_identity: entry.operation_identity,
                    stage: FailureStage::Arm,
                    reason: format!("the armed record could not be re-read: {error}"),
                });
                continue;
            }
        };

        // The same two bounds as the listing, re-read: a counter that reached
        // zero is due regardless of the deadline, and a counter raised since the
        // listing spares the version. Sparing a live version is the harmless
        // direction in both cases.
        // Due when the counter is exhausted, or when the deadline has passed.
        // An unbounded arm (`remaining_uses: None`) has no counter to consult, so
        // only the deadline can make it due — which is the rule it always had.
        let uses_exhausted = record.remaining_uses.is_some()
            && arming.remaining_uses(&entry.operation_identity) == Some(0);
        if !uses_exhausted && record.intent.deadline > at {
            report.not_yet_due += 1;
            report.selected = report.selected.saturating_sub(1);
            continue;
        }

        let intent = record.intent;

        // The intent's own list decides who may delete this version. A sweep
        // that ignored it would be a second authorisation path.
        if !intent.authorized_deleters.contains(actor) {
            report.failures.push(SweepFailure {
                operation_identity: entry.operation_identity,
                stage: FailureStage::Arm,
                reason: "the intent does not authorise this actor to delete the version"
                    .to_string(),
            });
            continue;
        }

        let metadata = BoundMetadata {
            vault_id: intent.vault_id.clone(),
            user_id: intent.user_id,
            level: intent.level.clone(),
            secret_id: intent.secret_id.clone(),
            version: intent.version,
        };

        // 1. Remove exactly this version, and learn whether anything was there.
        let event_id = match store.remove_exact(&metadata) {
            Ok(Some(event_id)) => event_id,
            Ok(None) => {
                report.already_absent += 1;
                continue;
            }
            Err(error) => {
                report.failures.push(SweepFailure {
                    operation_identity: entry.operation_identity,
                    stage: FailureStage::Remove,
                    reason: error.to_string(),
                });
                continue;
            }
        };

        // The version is gone from this moment, so it is counted even if the
        // evidence below cannot be written: a count that waited for the journal
        // would under-report what this invocation did.
        report.removed += 1;

        // 2. Journal the acknowledgement before any report can claim it. A
        //    failure here stops the sweep: continuing would multiply removals
        //    that no evidence covers, and the first failure already says the
        //    journal is unusable.
        let event = AcknowledgementEvent {
            intent_id: intent.intent_id.clone(),
            version: metadata.version,
            actor: *actor,
            event_id,
            acknowledged_at: at,
        };
        if let Err(error) = journal.record(&event) {
            report.failures.push(SweepFailure {
                operation_identity: entry.operation_identity,
                stage: FailureStage::Journal,
                reason: error.to_string(),
            });
            break;
        }

        // 3. Sign and persist the report. A failure here does not stop the sweep:
        //    the acknowledgement is durable, so the evidence exists and S4's
        //    retry can write the report later. It is still reported.
        match signed_report(signer, signer_key_id, actor, &intent, at) {
            Ok(bytes) => {
                if let Err(error) = retry_report(journal, &event, &bytes, sink) {
                    report.failures.push(SweepFailure {
                        operation_identity: entry.operation_identity,
                        stage: FailureStage::Report,
                        reason: error.to_string(),
                    });
                }
            }
            Err(reason) => report.failures.push(SweepFailure {
                operation_identity: entry.operation_identity,
                stage: FailureStage::Report,
                reason,
            }),
        }
    }

    Ok(report)
}

/// The signed report for one swept version.
///
/// `reported_deleted_at` is the instant this sweep observed the acknowledgement,
/// which is the only deletion time an actor may state: it is a claim about what
/// the actor saw, not evidence that nothing survives elsewhere.
fn signed_report(
    signer: &EvidenceSigningKey,
    signer_key_id: &str,
    actor: &ActorId,
    intent: &DeletionIntent,
    at: i64,
) -> Result<Vec<u8>, String> {
    let report = DeletionReport {
        intent_id: intent.intent_id.clone(),
        actor: *actor,
        signer_key_id: signer_key_id.to_string(),
        reason: "the armed lease deadline passed; removed by the foreground sweep".to_string(),
        outcome: Outcome::Success,
        reported_deleted_at: at,
        level: intent.level.clone(),
        secret_id: intent.secret_id.clone(),
        version: intent.version,
    };
    let signed = SignedReport::sign(signer, report).map_err(|error| error.to_string())?;
    cbor::encode(&signed).map_err(|error| error.to_string())
}
