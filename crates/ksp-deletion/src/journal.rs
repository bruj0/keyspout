//! The durable **acknowledgement journal**.
//!
//! An actor can receive a delete acknowledgement and then crash before signing
//! its report. Two naive recoveries are both wrong: re-uploading the ciphertext
//! puts back what was removed, and inventing a deletion time claims something
//! the actor cannot substantiate.
//!
//! The journal is the third option. The acknowledgement is written durably
//! *before* the report, keyed so a retry is idempotent by intent, version, actor
//! and event. A retry can then write the missing report and nothing else.
//!
//! The "never restores ciphertext" rule is structural rather than a check: no
//! function in this crate takes a store that can write a record, so there is no
//! API through which a retry could put one back.

use std::collections::BTreeMap;

use ksp_types::ActorId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The durable fact that a backend acknowledged a delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcknowledgementEvent {
    /// The intent the deletion was attempted under.
    pub intent_id: String,
    /// The exact version that was removed.
    pub version: u32,
    /// The actor that performed the delete.
    pub actor: ActorId,
    /// The backend's event identifier for this delete.
    pub event_id: String,
    /// When the backend acknowledged.
    pub acknowledged_at: i64,
}

impl AcknowledgementEvent {
    /// The idempotency key: intent, version, actor and event.
    ///
    /// Deliberately not the acknowledgement time. A retry that observed the
    /// same delete must land on the same key even if it read the clock again.
    pub fn key(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.intent_id.as_bytes());
        hasher.update([0]);
        hasher.update(self.version.to_be_bytes());
        hasher.update([0]);
        hasher.update(self.actor.to_string().as_bytes());
        hasher.update([0]);
        hasher.update(self.event_id.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// Why a journal operation failed.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The store could not read or write.
    #[error("the acknowledgement journal could not be {operation}: {reason}")]
    Store {
        /// What was attempted.
        operation: &'static str,
        /// The store's reason.
        reason: String,
    },
    /// The stored bytes were not a valid event.
    #[error("the journal holds an unreadable acknowledgement")]
    Corrupt,
    /// No durable acknowledgement exists, so no report may be written.
    #[error("no durable acknowledgement exists for this deletion")]
    NotAcknowledged,
}

/// Whether a write actually added an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    /// The acknowledgement was not previously known.
    New,
    /// The same acknowledgement was already durable, so a retry is a no-op.
    AlreadyPresent,
}

/// Proof that a durable acknowledgement exists.
///
/// The field is private and there is no public constructor, so the only way to
/// obtain one is [`AcknowledgementJournal::require`]. A caller cannot assert
/// that an acknowledgement happened; it has to have one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournaledAcknowledgement {
    event: AcknowledgementEvent,
}

impl JournaledAcknowledgement {
    /// The event that was found durable.
    pub fn event(&self) -> &AcknowledgementEvent {
        &self.event
    }
}

/// Durable byte storage for the journal.
pub trait JournalStore {
    /// Read a key.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, JournalError>;
    /// Write a key. Writing an existing key must not corrupt it; the journal
    /// compares the value and reports a conflict instead.
    fn put(&self, key: &str, bytes: &[u8]) -> Result<(), JournalError>;
}

/// An in-memory store, for tests and for a host that has no durable volume.
///
/// A host must not treat this as durable: it is here so the journal's rules can
/// be exercised, and it makes no claim to survive a restart.
#[derive(Debug, Default)]
pub struct MemoryJournalStore {
    entries: std::sync::Mutex<BTreeMap<String, Vec<u8>>>,
}

impl JournalStore for MemoryJournalStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, JournalError> {
        Ok(self
            .entries
            .lock()
            .map_err(|_| JournalError::Store {
                operation: "read",
                reason: "the journal lock was poisoned".to_owned(),
            })?
            .get(key)
            .cloned())
    }

    fn put(&self, key: &str, bytes: &[u8]) -> Result<(), JournalError> {
        self.entries
            .lock()
            .map_err(|_| JournalError::Store {
                operation: "write",
                reason: "the journal lock was poisoned".to_owned(),
            })?
            .insert(key.to_owned(), bytes.to_vec());
        Ok(())
    }
}

/// The journal over a store.
pub struct AcknowledgementJournal<S: JournalStore> {
    store: S,
}

impl<S: JournalStore> AcknowledgementJournal<S> {
    /// Wrap a store.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Write the acknowledgement durably.
    ///
    /// Idempotent: the second write of the same event reports
    /// [`Recorded::AlreadyPresent`] rather than adding a second entry, so a
    /// retry cannot grow the journal.
    pub fn record(&self, event: &AcknowledgementEvent) -> Result<Recorded, JournalError> {
        let key = event.key();
        if let Some(existing) = self.store.get(&key)? {
            let stored: AcknowledgementEvent =
                ksp_types::cbor::decode(&existing).map_err(|_| JournalError::Corrupt)?;
            // The key is a digest, so a collision would be the only way to find
            // a different event here. Refuse rather than silently overwrite.
            if stored != *event {
                return Err(JournalError::Corrupt);
            }
            return Ok(Recorded::AlreadyPresent);
        }
        let bytes = ksp_types::cbor::encode(event).map_err(|_| JournalError::Store {
            operation: "encode",
            reason: "the acknowledgement could not be encoded".to_owned(),
        })?;
        self.store.put(&key, &bytes)?;
        Ok(Recorded::New)
    }

    /// Whether a durable acknowledgement exists for this key.
    ///
    /// This is what makes a report permissible at all: without it the actor has
    /// no evidence that the delete happened.
    pub fn is_journaled(&self, event: &AcknowledgementEvent) -> Result<bool, JournalError> {
        Ok(self.store.get(&event.key())?.is_some())
    }

    /// Require durable evidence for this deletion, or refuse.
    ///
    /// This is the only way to obtain a [`JournaledAcknowledgement`], and a
    /// report cannot be verified without one.
    pub fn require(
        &self,
        event: &AcknowledgementEvent,
    ) -> Result<JournaledAcknowledgement, JournalError> {
        match self.recover(event)? {
            Some(event) => Ok(JournaledAcknowledgement { event }),
            None => Err(JournalError::NotAcknowledged),
        }
    }

    /// Recover the acknowledgement a lost report should have carried.
    pub fn recover(
        &self,
        event: &AcknowledgementEvent,
    ) -> Result<Option<AcknowledgementEvent>, JournalError> {
        match self.store.get(&event.key())? {
            None => Ok(None),
            Some(bytes) => Ok(Some(
                ksp_types::cbor::decode(&bytes).map_err(|_| JournalError::Corrupt)?,
            )),
        }
    }
}

/// Where a retried report is written.
///
/// The only capability a retry is given. It cannot write a record, so a retry
/// cannot restore ciphertext.
pub trait ReportSink {
    /// Write the report.
    fn write(&self, report: &[u8]) -> Result<(), JournalError>;
}

/// Retry a report write that failed after the acknowledgement was durable.
///
/// The retry is gated on the journal: if the acknowledgement was never durable,
/// there is nothing to substantiate a report and the call refuses. The only
/// capability it is given is a [`ReportSink`], which cannot write a record — so
/// "the retry never restores ciphertext" holds because no API could.
pub fn retry_report<S: JournalStore>(
    journal: &AcknowledgementJournal<S>,
    event: &AcknowledgementEvent,
    signed_report: &[u8],
    sink: &dyn ReportSink,
) -> Result<(), JournalError> {
    journal.require(event)?;
    sink.write(signed_report)
}
