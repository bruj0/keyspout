//! The actor-signed, version-scoped **deletion report**.
//!
//! A report is one actor's signed claim about what that actor did. Its
//! `reported_deleted_at` is the actor's claim and **not** evidence that
//! anything was destroyed: a store can return a success for a delete it has not
//! durably applied, and a copy taken earlier survives any delete. Nothing in
//! this module reports otherwise, and no type here is named as though it did.
//!
//! A report is signed only **after** the backend acknowledged; see
//! [`crate::journal`] for the record that keeps that acknowledgement across a
//! crash.

use ed25519_dalek::VerifyingKey;
use ksp_types::evidence::DeletionReport;
use serde::{Deserialize, Serialize};

use crate::signing::{EvidenceError, EvidenceSignature, EvidenceSigningKey, sign, verify};

/// The domain a report signature is made under.
pub const REPORT_DOMAIN: &str = "keyspout-delete-report-v1";

#[derive(Serialize)]
struct ReportSubject<'a> {
    domain: &'a str,
    report: &'a DeletionReport,
}
/// An actor's signed claim about a deletion it performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReport {
    /// The domain this signature was made under.
    pub domain: String,
    /// The claim.
    pub report: DeletionReport,
    /// The actor's signature.
    pub signature: EvidenceSignature,
}

impl SignedReport {
    /// Sign the actor's own claim.
    ///
    /// Callers must have a durable acknowledgement before reaching here; this
    /// function cannot check that, which is why [`crate::journal`] exists and
    /// why `ReportAuthority` refuses a report with no journaled event.
    pub fn sign(actor: &EvidenceSigningKey, report: DeletionReport) -> Result<Self, EvidenceError> {
        let subject = ReportSubject {
            domain: REPORT_DOMAIN,
            report: &report,
        };
        let signature = sign(actor.key(), REPORT_DOMAIN, &subject)?;
        Ok(Self {
            domain: REPORT_DOMAIN.to_owned(),
            report,
            signature,
        })
    }

    /// Verify the signature alone.
    ///
    /// A valid signature is necessary and **not** sufficient: it says *an actor
    /// said this*, not *this actor was allowed to*. Use
    /// [`crate::verify::verify_report`] for the full decision.
    pub fn verify_signature(&self, actor: &VerifyingKey) -> Result<(), EvidenceError> {
        let subject = ReportSubject {
            domain: &self.domain,
            report: &self.report,
        };
        verify(
            actor,
            REPORT_DOMAIN,
            &subject,
            &self.domain,
            &self.signature,
        )
    }

    /// The domain string this type is pinned to.
    pub fn domain() -> &'static str {
        REPORT_DOMAIN
    }
}
