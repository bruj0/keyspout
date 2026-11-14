//! The **absence observation** and the state a version is actually in.
//!
//! An observation says one thing: this version was not there when someone
//! looked, at `observed_at`. It names no deleting actor and carries no deletion
//! time, because the observer knows neither. Native expiry removes a record with
//! no Keyspout actor running, so an absent version with no authenticated report
//! is **missing/unconfirmed** — never upgraded to a deletion.

use ed25519_dalek::VerifyingKey;
use ksp_types::evidence::{AbsenceObservation, DeletionReport};
use serde::{Deserialize, Serialize};

use crate::signing::{EvidenceError, EvidenceSignature, EvidenceSigningKey, sign, verify};

/// The domain an absence observation is made under.
pub const OBSERVATION_DOMAIN: &str = "keyspout-absence-observation-v1";

#[derive(Serialize)]
struct ObservationSubject<'a> {
    domain: &'a str,
    observation: &'a AbsenceObservation,
}
/// An observer's signed statement that a version was absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedObservation {
    /// The domain this signature was made under.
    pub domain: String,
    /// What was seen, and when.
    pub observation: AbsenceObservation,
    /// The observer's signature.
    pub signature: EvidenceSignature,
}

impl SignedObservation {
    /// Sign an observation.
    pub fn sign(
        observer: &EvidenceSigningKey,
        observation: AbsenceObservation,
    ) -> Result<Self, EvidenceError> {
        let subject = ObservationSubject {
            domain: OBSERVATION_DOMAIN,
            observation: &observation,
        };
        let signature = sign(observer.key(), OBSERVATION_DOMAIN, &subject)?;
        Ok(Self {
            domain: OBSERVATION_DOMAIN.to_owned(),
            observation,
            signature,
        })
    }

    /// Verify the observer's signature.
    pub fn verify(&self, observer: &VerifyingKey) -> Result<(), EvidenceError> {
        let subject = ObservationSubject {
            domain: &self.domain,
            observation: &self.observation,
        };
        verify(
            observer,
            OBSERVATION_DOMAIN,
            &subject,
            &self.domain,
            &self.signature,
        )
    }

    /// The domain string this type is pinned to.
    pub fn domain() -> &'static str {
        OBSERVATION_DOMAIN
    }

    /// The observation time. There is deliberately no accessor for a deletion
    /// time, because an observation does not have one.
    pub fn observed_at(&self) -> i64 {
        self.observation.observed_at
    }
}

/// What is known about one version.
///
/// The variant name is the answer: a version is either the subject of an
/// authenticated actor report, or it is missing and unconfirmed. There is no
/// `Deleted` variant without a report, so "the record is gone" cannot be
/// expressed as "it was deleted".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionState {
    /// An actor made an authenticated claim about this version.
    ///
    /// The claim is the actor's; the state says a report exists, not that
    /// anything was destroyed.
    Reported(SignedReportSummary),
    /// No authenticated actor report exists. Any observations made are carried
    /// alongside, and they do not change the state.
    MissingUnconfirmed {
        /// Observations that were offered, with their observation times only.
        observations: Vec<SignedObservation>,
    },
}

/// The parts of a report that a state decision needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedReportSummary {
    /// The actor that made the claim.
    pub actor: ksp_types::ActorId,
    /// The actor's claimed time.
    pub reported_deleted_at: i64,
    /// The version the claim is about.
    pub version: u32,
}

impl SignedReportSummary {
    /// Summarise an authenticated report.
    pub fn of(report: &DeletionReport) -> Self {
        Self {
            actor: report.actor,
            reported_deleted_at: report.reported_deleted_at,
            version: report.version,
        }
    }
}

/// Decide what an absent version's evidence amounts to.
///
/// `authenticated_reports` must contain only reports that already passed
/// [`crate::verify::verify_report`]; an unverified report is a claim by anyone.
/// Observations are carried into [`VersionState::MissingUnconfirmed`] because
/// they do not upgrade the state — an observation says the version was not
/// there, which is exactly what "missing" already meant.
pub fn state_of(
    authenticated_reports: &[DeletionReport],
    observations: Vec<SignedObservation>,
) -> VersionState {
    match authenticated_reports.first() {
        Some(report) => VersionState::Reported(SignedReportSummary::of(report)),
        None => VersionState::MissingUnconfirmed { observations },
    }
}
