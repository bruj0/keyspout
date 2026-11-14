//! Consume: retrieve, decrypt, deliver, delete the exact version, then report.
//!
//! # The order is the deliverable
//!
//! 1. the plaintext is handed to the child, and no recovery copy is persisted;
//! 2. the exact version that was delivered is deleted;
//! 3. the acknowledgement is journaled, and only then is a report signed.
//!
//! The child runs **before** the delete. The delivery must not be lost because a
//! delete failed, and the delete must not happen before the child received what
//! it was promised.
//!
//! # The honest postcondition
//!
//! After a successful removal the only thing that is true is that **later fresh
//! fetches fail** from an honest store. Also true, and stated just as plainly:
//!
//! - a concurrent pre-delete fetch that already retrieved the ciphertext remains
//!   decryptable;
//! - a saved copy of the ciphertext remains decryptable;
//! - a holder with both the recipient key and the ciphertext can decrypt outside
//!   this path, which is outside the expiry claim;
//! - nothing here is exactly once, and no part of this module says it is;
//! - no automatic remint occurs. A lost capability requires a separate
//!   authorized operation.

use std::fmt;

use ksp_types::evidence::{DeletionReport, Outcome};
use ksp_types::{ActorId, Level, OpaqueSecretId};
use zeroize::Zeroize;

use crate::journal::{
    AcknowledgementEvent, AcknowledgementJournal, JournalError, JournalStore, ReportSink,
    retry_report,
};
use crate::report::SignedReport;
use crate::signing::EvidenceSigningKey;

/// Exit code for a delete that failed. The record may still be there, so a
/// retry may succeed.
pub const EXIT_DELETE_FAILED: i32 = 9;

/// Exit code for a child that failed **after** a successful removal. The record
/// is gone, so the caller must ask for a new delivery — this is not a retry.
pub const EXIT_LOST_FRESH_FETCH: i32 = 10;

/// Exit code for a compliant run that was not allowed to consume.
pub const EXIT_UNCONSUMED_REFUSED: i32 = 11;

/// The exact version a delivery is bound to.
///
/// Deliberately a whole target rather than a bare version number: the delete
/// must not act on "the current version", which may have moved between the
/// fetch and the delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionTarget {
    /// The level the version lives at.
    pub level: Level,
    /// The record the version belongs to.
    pub secret_id: OpaqueSecretId,
    /// The exact version.
    pub version: u32,
}

/// Why a consume could not complete.
#[derive(Debug, thiserror::Error)]
pub enum ConsumeError {
    /// The version was not there to retrieve.
    #[error("the bound version was not present in the store")]
    NotPresent,
    /// The ciphertext could not be decrypted.
    #[error("the retrieved ciphertext could not be decrypted")]
    Decryption,
    /// The store refused or failed the delete.
    #[error("the delete of the bound version failed: {reason}")]
    DeleteFailed {
        /// The store's reason.
        reason: String,
    },
    /// The acknowledgement was not durable, so no report may be signed.
    #[error("the delete acknowledgement was not recorded durably")]
    NotAcknowledged,
    /// The report could not be persisted after the acknowledgement.
    #[error("the report could not be written: {0}")]
    ReportWrite(#[from] JournalError),
    /// The canonical encoding of the report failed.
    #[error("the deletion report could not be encoded")]
    ReportEncoding,
    /// The actor is not authorized to delete this version.
    #[error("{actor} is not an authorized deleter for this version")]
    NotAuthorized {
        /// The actor the request names.
        actor: ActorId,
    },
    /// The intent is not about the version this run is bound to.
    #[error("the signed intent does not name this level, record and version")]
    IntentDoesNotCover,
    /// A compliant run was asked not to consume on a backend that requires it.
    #[error(
        "a Scheduled backend requires --consume: the record would otherwise expire with no actor report"
    )]
    ConsumptionRequired,
}

impl ConsumeError {
    /// The process exit code this failure maps to.
    pub fn exit_code(&self) -> i32 {
        match self {
            // Everything except a failed delete happens before or after the
            // removal, and none of it claims a deletion.
            Self::DeleteFailed { .. } => EXIT_DELETE_FAILED,
            Self::NotPresent
            | Self::Decryption
            | Self::NotAcknowledged
            | Self::ReportWrite(_)
            | Self::ReportEncoding
            | Self::NotAuthorized { .. }
            | Self::IntentDoesNotCover
            | Self::ConsumptionRequired => EXIT_UNCONSUMED_REFUSED,
        }
    }
}

/// What became of the run.
///
/// There is no "delivered" variant that also promises the record is gone for
/// everyone: [`ConsumeOutcome::Removed`] says a later fresh fetch will fail, and
/// nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeOutcome {
    /// The child received the plaintext and the version was removed. A later
    /// fresh fetch from an honest store will fail; earlier copies still decrypt.
    Removed,
    /// The version was removed, and the child then failed. The caller must ask
    /// for a new delivery; nothing is reminted automatically.
    LostFreshFetch {
        /// The child's reported reason, which never contains plaintext.
        reason: ChildFailureReason,
    },
}

impl ConsumeOutcome {
    /// The process exit code for this outcome.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Removed => 0,
            Self::LostFreshFetch { .. } => EXIT_LOST_FRESH_FETCH,
        }
    }
}

/// Why the child failed, as the child reported it.
///
/// A caller-supplied string, which is why it is a distinct type: nothing in this
/// module builds one from plaintext, and the doc comment is the only place a
/// reason is described.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildFailureReason(String);

impl ChildFailureReason {
    /// Record a reason. Callers must not pass plaintext.
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }

    /// The reason, for a log or an error message.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ChildFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What the store must provide: the ciphertext, and a delete of one exact
/// version that reports whether the backend acknowledged it.
pub trait VersionStore {
    /// Retrieve the ciphertext for exactly this version, or `None`.
    fn fetch(&self, target: &VersionTarget) -> Option<Vec<u8>>;
    /// Delete exactly this version.
    ///
    /// The returned identifier is the backend's acknowledgement. An error means
    /// no acknowledgement was received, which is not the same as "the record is
    /// still there" — it means nothing may be claimed either way.
    fn delete_exact(&self, target: &VersionTarget) -> Result<String, ConsumeError>;
}

/// The decrypting capability a caller wires.
pub trait Decryptor {
    /// Decrypt the ciphertext for the bound version.
    fn decrypt(&self, target: &VersionTarget, ciphertext: &[u8]) -> Result<Vec<u8>, ConsumeError>;
}

/// The child, which receives the plaintext exactly once.
pub trait Child {
    /// Hand the plaintext to the child.
    ///
    /// A failure here does not stop the delete: the child was handed the secret,
    /// and leaving the version in the store would not undo that.
    fn deliver(&self, plaintext: &[u8]) -> Result<(), ChildFailureReason>;
}

/// What a wipe left behind, for a test to inspect.
///
/// Compiled only under `cfg(test)` or the `test-observer` feature, both of which
/// are absent from a shipped build: a retained copy of a delivered secret would
/// be a recovery copy, which is the thing this module exists to not create.
#[cfg(any(test, feature = "test-observer"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WipeObservation {
    /// How long the buffer was.
    pub len: usize,
    /// Its contents immediately after the wipe.
    pub after: Vec<u8>,
}

#[cfg(any(test, feature = "test-observer"))]
thread_local! {
    static LAST_WIPE: std::cell::RefCell<Option<WipeObservation>> =
        const { std::cell::RefCell::new(None) };
}

/// The most recent wipe, if any.
#[cfg(any(test, feature = "test-observer"))]
pub fn last_wipe() -> Option<WipeObservation> {
    LAST_WIPE.with(|slot| slot.borrow().clone())
}

/// Forget the most recent wipe, so a test can prove a later call wiped.
#[cfg(any(test, feature = "test-observer"))]
pub fn forget_last_wipe() {
    LAST_WIPE.with(|slot| *slot.borrow_mut() = None);
}

/// Overwrite a buffer in place.
///
/// Named so the wipe is a visible act rather than a comment, and so a test can
/// show it happens.
pub fn wipe(buffer: &mut Vec<u8>) {
    // Zero the slice in place rather than calling `Vec::zeroize`, which zeroes
    // and then *clears*: a cleared vector still owns the allocation, so clearing
    // would look like erasure while leaving the bytes to be read until reuse.
    buffer.as_mut_slice().zeroize();
    #[cfg(any(test, feature = "test-observer"))]
    LAST_WIPE.with(|slot| {
        *slot.borrow_mut() = Some(WipeObservation {
            len: buffer.len(),
            after: buffer.clone(),
        });
    });
}

/// Everything a consume needs that is not authority.
///
/// There is deliberately no actor list and no intent identity here: both come
/// from the [`AuthorizedIntent`], which can only be obtained by verifying the
/// issuer's signature. A request that carried its own list would let a caller
/// authorise itself.
pub struct ConsumeRequest {
    /// The exact version the delivery is bound to.
    pub target: VersionTarget,
    /// The actor performing the delete, which signs the report.
    pub actor: ActorId,
    /// The key ID the actor signs with.
    pub signer_key_id: String,
    /// The reason recorded in the report.
    pub reason: String,
    /// When the backend acknowledged, as the caller observed it.
    pub acknowledged_at: i64,
}

/// Run the consume sequence.
///
/// The plaintext exists only inside this call: it is delivered, then wiped, and
/// it is never written anywhere. `sink` is the only place the report goes.
#[allow(clippy::too_many_arguments)]
pub fn consume<S: JournalStore>(
    store: &dyn VersionStore,
    decryptor: &dyn Decryptor,
    child: &dyn Child,
    journal: &AcknowledgementJournal<S>,
    signer: &EvidenceSigningKey,
    sink: &dyn ReportSink,
    authorized: &crate::intent::AuthorizedIntent,
    request: &ConsumeRequest,
) -> Result<ConsumeOutcome, ConsumeError> {
    // Both checks read the *issuer's* signed intent, not the request. They run
    // before the fetch so an unauthorised request never touches the store.
    if !authorized.authorizes(&request.actor) {
        return Err(ConsumeError::NotAuthorized {
            actor: request.actor,
        });
    }
    if !authorized.covers(
        &request.target.level,
        &request.target.secret_id,
        request.target.version,
    ) {
        return Err(ConsumeError::IntentDoesNotCover);
    }

    // 1. Retrieve the exact bound version.
    let ciphertext = store
        .fetch(&request.target)
        .ok_or(ConsumeError::NotPresent)?;

    // 2. Decrypt. The plaintext lives in one buffer for the rest of the call.
    let mut plaintext = zeroize::Zeroizing::new(decryptor.decrypt(&request.target, &ciphertext)?);

    // 3. Deliver, before any delete. The outcome is remembered rather than
    //    returned: the version must be removed even when the child failed.
    let child_failure = child.deliver(&plaintext).err();

    // The plaintext has served its purpose. Wipe before the delete so a failure
    // below cannot leave it live in this process.
    wipe(&mut plaintext);

    // 4. Delete exactly this version, and stop here if the backend did not
    //    acknowledge. The child's effects are not undone, and nothing claims a
    //    deletion.
    let event_id = store
        .delete_exact(&request.target)
        .map_err(|error| match error {
            ConsumeError::DeleteFailed { reason } => ConsumeError::DeleteFailed { reason },
            other => ConsumeError::DeleteFailed {
                reason: other.to_string(),
            },
        })?;

    // 5. Journal the acknowledgement durably, before the report exists.
    let event = AcknowledgementEvent {
        intent_id: authorized.intent_id().to_string(),
        version: request.target.version,
        actor: request.actor,
        event_id,
        acknowledged_at: request.acknowledged_at,
    };
    journal.record(&event).map_err(ConsumeError::ReportWrite)?;

    // 6. Sign the report only now that the acknowledgement is durable, and
    //    persist it. A failed write is retried from the journal, which can only
    //    write the report — it cannot restore the ciphertext.
    let report = DeletionReport {
        intent_id: authorized.intent_id().to_string(),
        actor: request.actor,
        signer_key_id: request.signer_key_id.clone(),
        reason: request.reason.clone(),
        outcome: Outcome::Success,
        reported_deleted_at: request.acknowledged_at,
        level: request.target.level.clone(),
        secret_id: request.target.secret_id.clone(),
        version: request.target.version,
    };
    let signed = SignedReport::sign(signer, report).map_err(|_| ConsumeError::ReportEncoding)?;
    let bytes = ksp_types::cbor::encode(&signed).map_err(|_| ConsumeError::ReportEncoding)?;
    retry_report(journal, &event, &bytes, sink).map_err(ConsumeError::ReportWrite)?;

    Ok(match child_failure {
        None => ConsumeOutcome::Removed,
        Some(reason) => ConsumeOutcome::LostFreshFetch { reason },
    })
}

/// Whether a run may proceed without consuming.
///
/// A `Scheduled` backend removes records on its own cadence, so a compliant run
/// that does not consume leaves the version to expire with no actor report. The
/// refusal targets the unmodified compliant client, which is the only population
/// the system can influence; it does not force a modified client to consume, and
/// it does not bound the backend's cleanup lag.
pub fn require_consumption_for(
    cleanup_is_scheduled: bool,
    consuming: bool,
) -> Result<(), ConsumeError> {
    if cleanup_is_scheduled && !consuming {
        return Err(ConsumeError::ConsumptionRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::journal::MemoryJournalStore;

    struct OneVersion(Vec<u8>);
    impl VersionStore for OneVersion {
        fn fetch(&self, _target: &VersionTarget) -> Option<Vec<u8>> {
            Some(self.0.clone())
        }
        fn delete_exact(&self, _target: &VersionTarget) -> Result<String, ConsumeError> {
            Ok("event".to_string())
        }
    }

    struct Copy;
    impl Decryptor for Copy {
        fn decrypt(&self, _t: &VersionTarget, c: &[u8]) -> Result<Vec<u8>, ConsumeError> {
            Ok(c.to_vec())
        }
    }

    struct Quiet;
    impl Child for Quiet {
        fn deliver(&self, _plaintext: &[u8]) -> Result<(), ChildFailureReason> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct Nowhere;
    impl ReportSink for Nowhere {
        fn write(&self, _report: &[u8]) -> Result<(), JournalError> {
            Ok(())
        }
    }

    #[test]
    fn the_plaintext_buffer_is_wiped_by_the_consume_call_not_only_by_drop() {
        // Criterion 13. A `Zeroizing` wrapper would erase the buffer on drop
        // whatever this function does, so the observation has to be taken inside
        // the call: without an explicit wipe there is no observation at all.
        forget_last_wipe();
        let secret = b"delivered-once".to_vec();
        let store = OneVersion(secret.clone());
        let journal = AcknowledgementJournal::new(MemoryJournalStore::default());
        let key = EvidenceSigningKey::from_seed([3u8; 32]);
        let issuer = EvidenceSigningKey::from_seed([4u8; 32]);
        let signed = crate::intent::SignedIntent::sign(
            &issuer,
            "k-1",
            ksp_types::evidence::DeletionIntent {
                intent_id: "i-1".to_string(),
                vault_id: ksp_types::VaultId::new("v-1"),
                user_id: ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f")
                    .unwrap(),
                level: Level::User,
                secret_id: OpaqueSecretId::new("s-1"),
                version: 1,
                deadline: 1,
                authorized_deleters: vec![ActorId::User(
                    ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
                )],
            },
        )
        .unwrap();
        let authorized = signed.verify_as(&issuer.verifying_key()).unwrap();

        consume(
            &store,
            &Copy,
            &Quiet,
            &journal,
            &key,
            &Nowhere,
            &authorized,
            &ConsumeRequest {
                target: VersionTarget {
                    level: Level::User,
                    secret_id: OpaqueSecretId::new("s-1"),
                    version: 1,
                },
                actor: ActorId::User(
                    ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
                ),
                signer_key_id: "k-1".to_string(),
                reason: "consume".to_string(),
                acknowledged_at: 1,
            },
        )
        .unwrap();

        let observed = last_wipe().expect("consume must wipe the plaintext itself");
        assert_eq!(observed.len, secret.len(), "the buffer keeps its length");
        assert!(
            observed.after.iter().all(|byte| *byte == 0),
            "the buffer must be overwritten by the call, not left to the drop"
        );
    }
}
