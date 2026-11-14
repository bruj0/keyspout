//! The report verifier: authenticity **and** authority, checked separately.
//!
//! A valid signature proves *an actor said this*. It does not prove the actor
//! was allowed to act on this version, nor that the claim is about the version
//! the caller is asking about. Both are independent conditions, and every
//! rejection names which one failed.

use ed25519_dalek::VerifyingKey;
use ksp_types::ActorId;

use crate::report::SignedReport;
use crate::signing::EvidenceError;

/// Why a report was not accepted.
#[derive(Debug, thiserror::Error)]
pub enum ReportRejection {
    /// The signature does not verify.
    #[error("the report signature does not verify: {0}")]
    Signature(#[from] EvidenceError),
    /// The signer is not one of the version's authorized deleters.
    ///
    /// A valid signature from an unauthorized principal lands here, which is
    /// the whole point of checking authority apart from authenticity.
    #[error("{actor} is not an authorized deleter for this version")]
    NotAuthorized {
        /// The actor the report names.
        actor: ActorId,
    },
    /// The report names a different intent.
    #[error("the report answers intent {found} but intent {expected} was presented")]
    IntentMismatch {
        /// The intent the caller is verifying against.
        expected: String,
        /// The intent the report names.
        found: String,
    },
    /// The report names a different actor than the signature's principal.
    #[error("the report names {stated} but was verified as {signer}")]
    ActorMismatch {
        /// The actor the report names.
        stated: ActorId,
        /// The actor whose key verified.
        signer: ActorId,
    },
    /// The report is about a different level.
    #[error("the report is about level {found} but {expected} was expected")]
    LevelMismatch {
        /// The level the caller is asking about.
        expected: String,
        /// The level the report names.
        found: String,
    },
    /// The report is about a different record.
    #[error("the report is about record {found} but {expected} was expected")]
    RecordMismatch {
        /// The record the caller is asking about.
        expected: String,
        /// The record the report names.
        found: String,
    },
    /// The report is about a different version.
    #[error("the report is about version {found} but version {expected} was expected")]
    VersionMismatch {
        /// The version the caller is asking about.
        expected: u32,
        /// The version the report names.
        found: u32,
    },
    /// The durable acknowledgement is for a different deletion.
    #[error("the journaled acknowledgement is for {expected} but the report claims {found}")]
    AcknowledgementMismatch {
        /// What the journal recorded.
        expected: String,
        /// What the report claims.
        found: String,
    },
}

/// What the caller is asking about, and who may speak for it.
#[derive(Debug, Clone)]
pub struct ReportAuthority {
    /// The intent this report is expected to answer.
    pub intent_id: String,
    /// The level the version lives at.
    pub level: ksp_types::Level,
    /// The record the version belongs to.
    pub secret_id: ksp_types::OpaqueSecretId,
    /// The exact version.
    pub version: u32,
    /// The actors permitted to report on this version.
    pub authorized_deleters: Vec<ActorId>,
    /// The durable acknowledgement this report answers.
    ///
    /// A capability rather than a flag: it can only be obtained from a journal,
    /// so "there is no durable acknowledgement" is not something a caller can
    /// assert away. Where none exists, no report may be claimed at all — the
    /// ciphertext may have gone, but nothing recorded that this actor removed
    /// it, and a later absence observation is the only honest statement.
    pub acknowledgement: crate::journal::JournaledAcknowledgement,
}

/// Verify a report in full.
///
/// `signer` is the pinned key for `signer_actor`, never one taken from the
/// report. The checks run in the order that produces the most honest message:
/// authenticity first, then authority, then whether the claim is even about the
/// thing the caller asked for.
pub fn verify_report(
    report: &SignedReport,
    signer_actor: &ActorId,
    signer: &VerifyingKey,
    authority: &ReportAuthority,
) -> Result<(), ReportRejection> {
    // One domain check, in `signing::verify`, which names the mismatch. A second
    // copy here would be a rule with two definitions and one real effect.
    report.verify_signature(signer)?;

    let event = authority.acknowledgement.event();
    if event.intent_id != report.report.intent_id
        || event.version != report.report.version
        || event.actor != report.report.actor
    {
        return Err(ReportRejection::AcknowledgementMismatch {
            expected: format!(
                "intent {} version {} actor {}",
                event.intent_id, event.version, event.actor
            ),
            found: format!(
                "intent {} version {} actor {}",
                report.report.intent_id, report.report.version, report.report.actor
            ),
        });
    }
    if !authority.authorized_deleters.contains(&report.report.actor) {
        return Err(ReportRejection::NotAuthorized {
            actor: report.report.actor,
        });
    }
    if &report.report.actor != signer_actor {
        return Err(ReportRejection::ActorMismatch {
            stated: report.report.actor,
            signer: *signer_actor,
        });
    }
    if report.report.intent_id != authority.intent_id {
        return Err(ReportRejection::IntentMismatch {
            expected: authority.intent_id.clone(),
            found: report.report.intent_id.clone(),
        });
    }
    if report.report.level != authority.level {
        return Err(ReportRejection::LevelMismatch {
            expected: authority.level.to_string(),
            found: report.report.level.to_string(),
        });
    }
    if report.report.secret_id != authority.secret_id {
        return Err(ReportRejection::RecordMismatch {
            expected: authority.secret_id.to_string(),
            found: report.report.secret_id.to_string(),
        });
    }
    if report.report.version != authority.version {
        return Err(ReportRejection::VersionMismatch {
            expected: authority.version,
            found: report.report.version,
        });
    }
    Ok(())
}
