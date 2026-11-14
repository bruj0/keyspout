//! Deletion evidence: what is *claimed* about a version, kept apart from what is
//! known.
//!
//! Three structures live here and they are not interchangeable:
//!
//! - a [`SignedIntent`] authorises an attempt to delete one exact version;
//! - a [`SignedReport`] is one actor's signed claim about a deletion it
//!   performed, written after a durable acknowledgement;
//! - a [`SignedObservation`] records that a version was absent when someone
//!   looked, and nothing more.
//!
//! One more lives beside them: a [`SignedAuditRecord`] in a per-writer
//! [`AuditChain`] records what a component *did*, including the operations that
//! failed or were refused. It is not deletion evidence and cannot be presented as
//! any: the domain is a signed field, so a record made under the audit domain does
//! not verify as a report about a version.
//!
//! A signed report attributes a claim. It does not prove destruction, and no
//! type, field or message here says otherwise. Where no authenticated report
//! exists, a version is [`VersionState::MissingUnconfirmed`] — never "deleted".

#![deny(missing_docs)]

pub mod audit;
pub mod consume;
pub mod intent;
pub mod journal;
pub mod observation;
pub mod report;
pub mod signing;
pub mod verify;

pub use audit::{
    AUDIT_DOMAIN, Attribution, AuditChain, Break, ChainError, Frame, PinRole, PinStatus, PinnedKey,
    Pins, REDACTED_FIELD_MARKERS, RawField, RawFieldValue, RawRecord, SegmentReader,
    SignedAuditRecord, TornCause, VerifiedChain, VerifyCounts, VerifyReport, attribute, frames,
    verify_records, verify_segment,
};
pub use consume::{
    Child, ChildFailureReason, ConsumeError, ConsumeOutcome, ConsumeRequest, Decryptor,
    EXIT_DELETE_FAILED, EXIT_LOST_FRESH_FETCH, EXIT_UNCONSUMED_REFUSED, VersionStore,
    VersionTarget, consume, require_consumption_for, wipe,
};
pub use intent::{AuthorizedIntent, INTENT_DOMAIN, SignedIntent};
pub use journal::{
    AcknowledgementEvent, AcknowledgementJournal, JournalError, JournalStore,
    JournaledAcknowledgement, MemoryJournalStore, Recorded, ReportSink, retry_report,
};
pub use observation::{
    OBSERVATION_DOMAIN, SignedObservation, SignedReportSummary, VersionState, state_of,
};
pub use report::{REPORT_DOMAIN, SignedReport};
pub use signing::{EvidenceError, EvidenceSignature, EvidenceSigningKey};
pub use verify::{ReportAuthority, ReportRejection, verify_report};
