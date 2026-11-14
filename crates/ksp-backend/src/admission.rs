//! Evidence-based Lease Capability classification and Admission Floor.

use std::time::Duration;

use ksp_types::{AdmissionDecision, AdmissionRefusal, LeaseCapability};

use crate::proof::{GateRefusal, ProofFreshness, ProofObservation};

/// Which single cause explains a [`LeaseCapability`], and the one action it implies.
///
/// This **explains** a capability; it never replaces one. `LeaseCapability` stays
/// the three-value enum it is, because several distinct causes produce `None` and
/// each needs a different next step. A second capability enum beside it would be
/// two answers to one question.
///
/// The action is derived from the state by [`next_action`], not stored beside it:
/// a next step maintained separately from the cause drifts from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityState {
    /// No arming is recorded and no proof exists.
    NoArming,
    /// An arming is recorded, but no run has proven it.
    DeclaredNoProof,
    /// A job was installed and declared loaded, with no proof yet.
    ///
    /// Unreachable until the install path lands: an install is a declaration, and
    /// a declaration never becomes evidence on its own.
    InstalledNoProof,
    /// A proof exists but is later than its own interval plus measured grace.
    StaleProof {
        /// Seconds since the run ended.
        age: i64,
        /// The bound that was exceeded: `interval + grace`.
        bound: i64,
    },
    /// A proof exists but does not verify against any pinned key.
    UnverifiedProof,
    /// A proof exists but could not be decoded.
    ///
    /// Distinct from [`Self::UnverifiedProof`]: a corrupt file is not a key
    /// mismatch, and the fix is the file rather than the anchor.
    MalformedProof,
    /// A proof exists but covers another deployment's scope.
    ScopeMismatchProof,
    /// A proof exists but is dated so far ahead that freshness cannot be decided.
    ///
    /// Distinct from staleness: the proof is not late, the clock is wrong, and a
    /// longer interval does not fix a clock.
    FutureSkewProof,
    /// A run completed, but not under a recorded schedule.
    NoCadence,
    /// The proof area could not be read, so nothing is known either way.
    UnreadableProofs,
    /// A fresh, in-scope, verified proof exists.
    Proven,
}

/// The one operator action implied by a state, or `None` when none is useful.
///
/// Takes the state and nothing else. That signature is the enforcement of misfit
/// F: there is no second place for the line to live, so it cannot drift from the
/// classifier that produced the state.
pub fn next_action(state: &CapabilityState) -> Option<String> {
    match state {
        CapabilityState::Proven => None,
        CapabilityState::NoArming => Some(
            "record a schedule with 'ksp backend arm-sweep', then let the job run once so a \
             proof exists"
                .to_string(),
        ),
        CapabilityState::DeclaredNoProof => Some(
            "a schedule is recorded but no run has proven it; the first proof appears after the \
             job's first firing"
                .to_string(),
        ),
        CapabilityState::InstalledNoProof => Some(
            "the job is installed and has not run yet; a proof appears after its first firing, \
             and an install is not evidence on its own"
                .to_string(),
        ),
        CapabilityState::StaleProof { age, bound } => Some(format!(
            "the newest run is late: it ended {age}s ago and the bound is {bound}s (interval \
             plus measured grace). A machine asleep past the bound wakes stale; a longer \
             interval is the lever, not a shorter wait"
        )),
        CapabilityState::UnverifiedProof => Some(
            "a proof exists but does not verify against any pinned key; check the admin anchor \
             this host pins"
                .to_string(),
        ),
        CapabilityState::MalformedProof => Some(
            "a proof exists but could not be decoded; the file is corrupt, not signed by the \
             wrong key, so re-run the sweep to write a readable proof"
                .to_string(),
        ),
        CapabilityState::ScopeMismatchProof => Some(
            "a proof exists but covers another deployment's scope; re-record the schedule for \
             this deployment's canonical scope"
                .to_string(),
        ),
        CapabilityState::FutureSkewProof => Some(
            "a proof is dated in the future beyond the grace, so freshness cannot be decided; \
             check this host's clock and the signer's"
                .to_string(),
        ),
        CapabilityState::NoCadence => Some(
            "a run completed but not under a recorded schedule, so it proves no cadence; record \
             a schedule and let the job run under it"
                .to_string(),
        ),
        CapabilityState::UnreadableProofs => Some(
            "the proof area could not be read, so nothing is known either way; check that this \
             account can read the sweeper proof directory"
                .to_string(),
        ),
    }
}

/// Classification from known configuration; never an erasure claim.
///
/// The declared and the proven cadence are separate fields on purpose: averaging them
/// or picking one would hide a disagreement that an operator has to see (FR-057). A
/// capability is `Scheduled` only when the proven cadence is fresh; the declared one
/// is what a run is *supposed* to keep, not what it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// What the backend is known to do about a lease's deadline.
    pub capability: LeaseCapability,
    /// The mechanism the capability rests on, in one sentence.
    pub mechanism: &'static str,
    /// The cadence the recorded arming declares, when one is recorded.
    pub declared_cadence: Option<Duration>,
    /// The cadence the newest usable sweep proof establishes, when one does.
    ///
    /// Reported even when it is stale: the proof still says what ran, and its age is
    /// the fact that explains the refusal.
    pub proven_cadence: Option<Duration>,
    /// The age of that proof on the reading principal's clock, in seconds.
    ///
    /// Signed: a negative age is a proof dated in the future, which is a skew to
    /// disclose rather than a freshness to trust.
    pub proof_age: Option<i64>,
    /// The cleanup lag, which is never a number.
    pub cleanup_lag: Option<Duration>,
    /// Retention the backend states, if it states one.
    pub retention: Option<Duration>,
    /// Which single cause explains `capability`, when one has been decided.
    ///
    /// `None` for a backend whose classifier does not name a cause. A caller that
    /// has no state cannot print one, so the unclassified path is a compile-time
    /// concern rather than a default.
    pub state: Option<CapabilityState>,
}

/// What the `file` backend's own evidence says, before any lease is requested.
///
/// The declaration is configuration and never sufficient. The proof is what admission
/// reads, and it is passed in rather than read here so this crate keeps one reader of
/// the proof directory — [`crate::proof::ProofGate`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileEvidence {
    /// The cadence the recorded arming declares, when one is recorded.
    pub declared_cadence: Option<Duration>,
    /// The newest successful, verified proof and its age, whether or not it is fresh.
    pub proof: Option<ProofObservation>,
    /// Why no proof could be observed, in the gate's own words.
    pub refusal: Option<GateRefusal>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    #[error("known {0} configuration contradicts the declared capability")]
    ConfigurationMismatch(&'static str),
    #[error("{capability:?} refuses the requested lease: {reason}")]
    CapabilityRefusal {
        capability: LeaseCapability,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct ValkeyConfiguration {
    pub logical_expiry: bool,
    pub append_only: bool,
    pub append_fsync_always: bool,
    pub waitaof_supported: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct S3Configuration {
    pub interval: Option<Duration>,
    pub cleanup_expected: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct S3Evidence {
    pub versioned: bool,
    pub soft_delete: bool,
    pub lifecycle_covers_prefix: bool,
    pub lifecycle_expiration: bool,
    pub canary_absent: bool,
}

/// Classify the `file` backend from the evidence this host holds.
///
/// A declaration is not evidence (misfit C): with no proof, or a proof that does not
/// verify, or one later than its measured bound, the capability is `None` however
/// well-formed the arming is.
pub fn classify_file(evidence: FileEvidence) -> Classification {
    let freshness = evidence.proof.map(|proof| proof.freshness());
    let capability = match (evidence.proof, freshness) {
        (Some(proof), Some(ProofFreshness::Fresh)) => LeaseCapability::Scheduled {
            interval: proof.interval,
        },
        _ => LeaseCapability::None,
    };
    let mechanism = match (evidence.proof, freshness) {
        (Some(_), Some(ProofFreshness::Fresh)) => "a signed sweep proof from the recorded schedule",
        (Some(_), Some(ProofFreshness::Stale)) => {
            "the newest sweep proof is later than its interval plus measured grace"
        }
        (Some(_), Some(ProofFreshness::FutureSkew)) => {
            "the newest sweep proof is dated beyond the grace on this clock"
        }
        (Some(_), None) => "the newest sweep proof could not be read",
        (None, _) => match &evidence.refusal {
            Some(GateRefusal::Unverified { .. }) => {
                "the newest sweep proof does not verify against any pinned key"
            }
            Some(GateRefusal::ScopeMismatch { .. }) => {
                "the newest sweep proof covers another deployment's scope"
            }
            Some(GateRefusal::NoSuccessfulProof) => {
                "no successful sweep run has been proven; a declaration is not evidence"
            }
            Some(GateRefusal::NoCadence) => {
                "a sweep run completed, but not under a recorded schedule, so it names no cadence"
            }
            Some(GateRefusal::Malformed) => "a sweep proof exists but could not be read",
            Some(GateRefusal::Unreadable) => {
                "the sweep proof directory could not be read; this is not evidence that no run happened"
            }
            Some(_) => "no sweep proof has been written; a declaration is not evidence",
            None if evidence.declared_cadence.is_some() => {
                "a schedule is recorded, but no run has proven it"
            }
            None => "no recorded sweep schedule and no sweep proof",
        },
    };
    Classification {
        capability,
        mechanism,
        declared_cadence: evidence.declared_cadence,
        proven_cadence: evidence.proof.map(|proof| proof.interval),
        proof_age: evidence.proof.map(|proof| proof.age),
        cleanup_lag: None,
        retention: None,
        state: Some(file_state(&evidence, freshness)),
    }
}

/// The single cause behind a `file` classification.
///
/// Chosen from the same evidence the capability and the mechanism are, so the
/// three cannot disagree. A stale proof reports its own bound rather than a
/// generic "stale": the operator needs the number to decide whether a longer
/// interval is the lever (misfit D).
fn file_state(evidence: &FileEvidence, freshness: Option<ProofFreshness>) -> CapabilityState {
    match (evidence.proof, freshness) {
        (Some(_), Some(ProofFreshness::Fresh)) => CapabilityState::Proven,
        (Some(proof), Some(ProofFreshness::Stale)) => CapabilityState::StaleProof {
            age: proof.age,
            bound: proof.bound(),
        },
        (Some(_), Some(ProofFreshness::FutureSkew)) => CapabilityState::FutureSkewProof,
        (Some(_), None) => CapabilityState::UnverifiedProof,
        (None, _) => match &evidence.refusal {
            Some(GateRefusal::Unverified { .. }) => CapabilityState::UnverifiedProof,
            Some(GateRefusal::ScopeMismatch { .. }) => CapabilityState::ScopeMismatchProof,
            Some(GateRefusal::NoCadence) => CapabilityState::NoCadence,
            Some(GateRefusal::Unreadable) => CapabilityState::UnreadableProofs,
            // A proof that could not be decoded is not a proof that failed to
            // verify: the fix is the file, not the anchor.
            Some(GateRefusal::Malformed) => CapabilityState::MalformedProof,
            // A stale or skewed refusal can reach here when the proof itself
            // was not carried in `evidence.proof`. Reporting it as "no run has
            // proven it" would be false, so it keeps its own cause.
            Some(GateRefusal::Stale { age, bound, .. }) => CapabilityState::StaleProof {
                age: *age,
                bound: *bound,
            },
            Some(GateRefusal::FutureSkew { .. }) => CapabilityState::FutureSkewProof,
            Some(GateRefusal::NoSuccessfulProof) => CapabilityState::DeclaredNoProof,
            Some(_) => CapabilityState::DeclaredNoProof,
            None if evidence.declared_cadence.is_some() => CapabilityState::DeclaredNoProof,
            None => CapabilityState::NoArming,
        },
    }
}

pub fn classify_valkey(config: ValkeyConfiguration) -> Result<Classification, AdmissionError> {
    if !config.logical_expiry {
        return Ok(Classification {
            capability: LeaseCapability::None,
            mechanism: "no configured logical expiry",
            declared_cadence: None,
            proven_cadence: None,
            proof_age: None,
            cleanup_lag: None,
            retention: None,
            // Valkey names no cause in this feature; the field says so rather
            // than inventing one.
            state: None,
        });
    }
    if !(config.append_only && config.append_fsync_always && config.waitaof_supported) {
        return Err(AdmissionError::ConfigurationMismatch("Valkey durability"));
    }
    Ok(Classification {
        capability: LeaseCapability::NativeExpiry,
        mechanism: "configured native logical expiry with local AOF fsync acknowledgement",
        declared_cadence: None,
        proven_cadence: None,
        proof_age: None,
        cleanup_lag: None,
        retention: None,
        // Valkey enforces the deadline itself, so there is no sweep cause to
        // name. The field says so rather than inventing one.
        state: None,
    })
}

pub fn classify_s3(
    config: S3Configuration,
    evidence: S3Evidence,
) -> Result<Classification, AdmissionError> {
    let none = || Classification {
        capability: LeaseCapability::None,
        mechanism: "no deadline-aware configured scheduled cleanup",
        declared_cadence: None,
        proven_cadence: None,
        proof_age: None,
        cleanup_lag: None,
        retention: None,
        state: None,
    };
    // A canary's absence is deliberately irrelevant to every classification.
    let _ = evidence.canary_absent;
    if evidence.versioned || evidence.soft_delete {
        return Ok(none());
    }
    if config.cleanup_expected
        && (!evidence.lifecycle_covers_prefix || !evidence.lifecycle_expiration)
    {
        return Err(AdmissionError::ConfigurationMismatch(
            "S3 lifecycle cleanup",
        ));
    }
    if !config.cleanup_expected && evidence.lifecycle_covers_prefix && evidence.lifecycle_expiration
    {
        return Err(AdmissionError::ConfigurationMismatch(
            "S3 lifecycle declaration",
        ));
    }
    if !(evidence.lifecycle_covers_prefix && evidence.lifecycle_expiration) {
        return Ok(none());
    }
    // S3's age-based lifecycle is not a per-intent deadline-aware collector.
    // It can delete before or after the intent deadline and does not establish
    // a configured sweep cadence. Keep records supported without admitting leases.
    match config.interval {
        Some(interval) if !interval.is_zero() => Ok(Classification {
            capability: LeaseCapability::None,
            mechanism: "S3 age-based lifecycle cannot arm an exact intent deadline",
            declared_cadence: Some(interval),
            proven_cadence: None,
            proof_age: None,
            cleanup_lag: None,
            retention: None,
            state: None,
        }),
        _ => Ok(none()),
    }
}

/// Backend-duration gate; policy/grants must still be checked by the caller.
pub fn admit_at_gate(
    classification: &Classification,
    requested: Duration,
) -> Result<AdmissionDecision, AdmissionError> {
    let capability = classification.capability;
    let decision = if requested.is_zero() {
        AdmissionDecision::Refused(AdmissionRefusal::NoMechanism)
    } else {
        ksp_types::admit_decision(&capability, requested)
    };
    if let AdmissionDecision::Refused(reason) = decision {
        let reason = match reason {
            AdmissionRefusal::NoMechanism => {
                format!("{}; capability {capability:?}", classification.mechanism)
            }
            AdmissionRefusal::BelowFloor { floor, .. } => format!(
                "cadence {:?}, minimum {:?}; capability {capability:?}",
                capability.interval(),
                floor
            ),
        };
        return Err(AdmissionError::CapabilityRefusal { capability, reason });
    }
    Ok(decision)
}
