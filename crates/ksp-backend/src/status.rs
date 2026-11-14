//! The status disclosure: what the system knows, kept apart from what it does not.
//!
//! # What this surface may never say
//!
//! It reports the effective capability, the mechanism, the evidence behind
//! them, the declared cadence and admission minimum, the cleanup lag, the
//! retention state, the two postures, the freshness state, and whether this home
//! is bound to a UNIX account the host can still resolve (FR-023).
//!
//! It does **not** report a maximum cleanup lag, a worst case, a bound, or a
//! deadline for the physical disappearance of a copy, and it does not assert
//! that anything was erased. There is no number to put in those places, and a
//! number there would be a claim the system cannot support: a declared cadence
//! is a statement about configuration, and even a truthful cadence is not a lag.
//!
//! Three shapes enforce that rather than merely describing it:
//!
//! - [`CleanupLag`] has no representable value other than [`CleanupLag::Unknown`],
//!   so "the lag is 24h" cannot be constructed;
//! - [`Retention`] separates a configuration we can read from one we cannot,
//!   so retention is never assumed to be "no";
//! - [`Freshness`] separates a host that can detect a replay from one that
//!   cannot, so an absent checkpoint is not silently a guarantee.
//!
//! A [`CanaryResult`] says what one lookup saw. A canary can reveal a mismatch;
//! it cannot prove that every copy, backup, replica, WAL segment and snapshot is
//! gone, so it is never rendered as an erasure claim.

use std::time::Duration;

use ksp_posture::{BarrierPosture, ConfinementPosture};
use ksp_types::LeaseCapability;
use serde::{Deserialize, Serialize};

use crate::admission::Classification;
use crate::proof::ProofFreshness;
use crate::sweeper::MeasuredUnitState;

/// The cleanup lag, which is always unknown.
///
/// A single-variant enum on purpose. The system cannot measure how long after a
/// delete a copy stops existing anywhere, so the only honest value is "unknown",
/// and making "unknown" the only constructible value is stronger than a field
/// that happens to be `None` today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CleanupLag {
    /// No measurement, no bound and no deadline is known.
    Unknown,
}

impl std::fmt::Display for CleanupLag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("unknown")
    }
}

/// Whether copies of a deleted version may survive, as far as configuration says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Retention {
    /// The configuration states a retention window, and why.
    Known {
        /// How long the store retains the object.
        window_secs: u64,
        /// The configuration that stated it.
        reason: String,
    },
    /// The configuration does not say, so nothing is assumed.
    Unknown {
        /// Why it cannot be known from here.
        reason: String,
    },
}

/// Whether this host can detect a replayed older policy.
///
/// A host without a trusted checkpoint cannot, and says so rather than implying
/// the guarantee holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Freshness {
    /// A trusted checkpoint exists, and rollback detection is in force at this
    /// revision.
    Available {
        /// The policy revision the checkpoint holds.
        revision: u64,
    },
    /// No trusted checkpoint is held here: a replayed older valid policy would
    /// also verify.
    RollbackDetectionUnavailable,
}

/// What one lookup saw, and nothing beyond it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryResult {
    /// Whether the probe found the version.
    pub found: bool,
    /// When the probe ran.
    pub observed_at: i64,
    /// The version probed.
    pub version: u32,
}

/// The backend's capability channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusDisclosure {
    /// The effective capability the admission gate concluded.
    pub capability: LeaseCapability,
    /// The mechanism behind it.
    pub mechanism: String,
    /// The evidence or configuration the conclusion was derived from.
    ///
    /// Reported as the classification's own words: this surface does not
    /// re-derive the capability or soften a known mismatch into a downgrade.
    pub evidence: String,
    /// The cadence the configuration declares, if it declares one.
    ///
    /// A configuration statement. It is not a lag, and it is reported in its own
    /// field so the two cannot be read as one.
    pub declared_cadence_secs: Option<u64>,
    /// The cadence the newest usable sweep proof establishes, if one does.
    ///
    /// Reported beside the declared cadence rather than in place of it: a disagreement
    /// is a fact the operator has to be able to see (FR-057).
    pub proven_cadence_secs: Option<u64>,
    /// The age of that proof on this principal's clock, in seconds.
    ///
    /// Signed, because a proof dated in the future is a skew to disclose and not a
    /// freshness to trust.
    pub proof_age_secs: Option<i64>,
    /// The admission floor the effective cadence implies (`2 x cadence`).
    pub admission_minimum_secs: Option<u64>,
    /// The cleanup lag, which is never a number.
    pub cleanup_lag: CleanupLag,
    /// The one operator action the classification's cause implies, if any.
    ///
    /// Carried from the classifier rather than derived here: a next step
    /// rendered from a source other than the classifier drifts from it.
    pub next_action: Option<String>,
    /// Whether copies may survive, known or unknown.
    pub retention: Retention,
}

/// The postures, reported separately because they answer different questions.
///
/// Confinement restricts *paths*; the barrier keeps key material out of ordinary
/// memory. Neither implies the other, and neither is reported as a capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureDisclosure {
    /// What the kernel enforces about paths.
    pub confinement: ConfinementPosture,
    /// What keeps key material out of ordinary memory.
    pub barrier: BarrierPosture,
    /// Each control that decides whether this process can be dumped.
    ///
    /// Carried beside the barrier rather than folded into it: the barrier names
    /// the *mechanism*, and either dump control can be absent while the
    /// mechanism holds. A reader who is told `weakened` and nothing else cannot
    /// tell which half failed (Misfit D, FR-013).
    pub undumpable: ksp_posture::UndumpablePosture,
}

/// The mode and ownership of every protected root, as measured.
///
/// S1 measures; this surface only carries the result. It is deliberately not
/// part of [`StatusDisclosure`]: that struct is the *capability* channel, and a
/// drifted directory changes no capability — it changes whether the run may
/// proceed at all, which is a separate answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDisclosure {
    /// One finding per row of the layout table, in table order.
    pub findings: Vec<ksp_posture::PermissionFinding>,
}

impl PermissionDisclosure {
    /// Wrap the findings of one measurement.
    pub fn new(findings: Vec<ksp_posture::PermissionFinding>) -> Self {
        Self { findings }
    }

    /// The rows that drifted.
    pub fn drifted(&self) -> impl Iterator<Item = &ksp_posture::PermissionFinding> {
        ksp_posture::drifted(&self.findings)
    }

    /// Whether no row drifted. A missing row is not drift.
    pub fn is_clear(&self) -> bool {
        self.drifted().next().is_none()
    }
}

/// Whether the home is bound to a UNIX account, and whether it still exists here.
///
/// FR-023: three states, not a boolean. "No account is bound" is a single-account
/// home and is not a boundary that weakened; "the named account is gone" is a home
/// whose recorded owner can no longer be resolved, so a `chown` to that file's
/// recorded uid would quietly be a different account's — the binding is
/// unverifiable, which is the answer an operator has to be able to act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BindingDisclosure {
    /// The deployment names no account: whoever created the vault owns it.
    None,
    /// The deployment names an account this host resolved to this uid.
    Verified {
        /// The account name recorded at enrolment.
        account: String,
        /// The uid `id` printed for it on this host.
        uid: u32,
    },
    /// The deployment names an account this host cannot resolve right now.
    Unverified {
        /// The account name recorded at enrolment.
        account: String,
        /// Why it did not resolve, in the probe's own words.
        reason: String,
    },
}

/// One finding on the wire.
///
/// Modes are rendered in octal because that is what `chmod`, `ls -l` and every
/// operator's muscle memory use; decimal `448` for `0700` would be a small,
/// avoidable mistranslation at exactly the moment someone is checking a
/// boundary.
#[derive(Serialize)]
struct FindingWire {
    path: String,
    kind: &'static str,
    verdict: &'static str,
    expected_mode: String,
    actual_mode: Option<String>,
    expected_owner: Option<u32>,
    actual_owner: Option<u32>,
    // Kept so a reader gets the sentence the refusal would print.
    description: String,
}

impl Serialize for PermissionDisclosure {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        let mut seq = serializer.serialize_seq(Some(self.findings.len()))?;
        for finding in &self.findings {
            let wire = FindingWire {
                path: finding.path.display().to_string(),
                kind: match finding.expected_kind {
                    ksp_posture::RootKind::Directory => "directory",
                    ksp_posture::RootKind::File => "file",
                },
                verdict: match finding.verdict {
                    ksp_posture::Verdict::Match => "match",
                    ksp_posture::Verdict::Drift => "drift",
                    ksp_posture::Verdict::Missing => "missing",
                    ksp_posture::Verdict::Narrowed => "narrowed",
                },
                expected_mode: format!("{:04o}", finding.expected_mode),
                actual_mode: finding.actual_mode.map(|mode| format!("{mode:04o}")),
                expected_owner: match finding.expected_owner {
                    ksp_posture::ExpectedOwner::Recorded(uid) => Some(uid),
                    ksp_posture::ExpectedOwner::Unrecorded => None,
                },
                actual_owner: finding.actual_owner,
                description: finding.describe(),
            };
            seq.serialize_element(&wire)?;
        }
        seq.end()
    }
}

impl From<&Classification> for StatusDisclosure {
    fn from(value: &Classification) -> Self {
        Self::from_classification(value)
    }
}

/// What a key-file passphrase protects, and what it does not.
///
/// FR-019 and misfit I: the danger is an operator reading "passphrase-protected" as
/// "the agent cannot reach the record". The wording is a deliverable, so it lives in
/// one constant that the renderer prints and a test asserts verbatim.
pub const PASSPHRASE_SENTENCE: &str = "protects the key file at rest; does not protect a process \
     that already holds the key, a captured ciphertext pair, or a same-UID process that is not \
     confined";

/// FR-006: a trigger is not evidence that a sweep completed.
///
/// Worded to avoid every claim the JSON-level test bans, so the sentence can travel in
/// the serialized report without weakening that test.
pub const LAST_TRIGGER_IS_NOT_EVIDENCE: &str = "a last trigger is when the manager started the job, not evidence that a sweep completed or \
     that any version is gone";

/// FR-035: an armed interval is a schedule, never a deletion time.
///
/// The floor's own sentence lives beside the floor, so this one does not repeat it.
pub const SCHEDULE_NOTE: &str =
    "an armed interval describes a schedule, not a moment by which a copy is gone";

/// A fact this host could observe, or the reason it could not.
///
/// `Unknown` is the point of the type: an unreadable directory, a query the host
/// cannot answer and a missing digest are all `Unknown` with a reason, never a default
/// that reads like a measurement (FR-005, misfit M).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Observed<T> {
    /// The host answered.
    Known(T),
    /// The host could not answer, and this is why.
    Unknown {
        /// The reason, never a generic "error".
        reason: String,
    },
}

/// The recorded schedule, and what the host could measure about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ArmingDisclosure {
    /// No verified arming record names this deployment.
    None {
        /// What was looked for and not found.
        reason: String,
    },
    /// A record whose signature verified and whose scope is this deployment's.
    Recorded {
        /// The form of schedule, in the record's own word.
        kind: String,
        /// The unit or job name the operator installs under.
        identifier: String,
        /// The interval the record declares. A schedule, never a lag.
        declared_interval_secs: u64,
        /// The writer's clock when it was recorded.
        recorded_at: i64,
        /// The key ID that signed it.
        signer_key_id: String,
        /// What the service manager reported, or why it could not answer.
        unit: MeasuredUnitState,
    },
    /// The records exist but none could be read as this deployment's.
    Unknown {
        /// The reason, in the reader's own words.
        reason: String,
    },
}

/// One sweep run, as its signed proof records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProofRecord {
    /// The run's own start, in the writer's clock.
    pub run_start: i64,
    /// The run's end.
    pub run_end: i64,
    /// Seconds between the run's end and this host's clock.
    ///
    /// Signed: a proof dated in the future is a skew to disclose, not freshness.
    pub age_secs: i64,
    /// The interval the arming declared to that run.
    pub declared_interval_secs: Option<u64>,
    /// The gap between this run and the successful one before it.
    pub realised_interval_secs: Option<u64>,
    /// Versions the run removed.
    pub removed: u32,
    /// Versions already absent when it looked.
    pub already_absent: u32,
    /// Versions whose deadline had not passed.
    pub not_yet_due: u32,
    /// Whether the run stopped at its bound.
    pub bound_reached: bool,
    /// One entry per failure, as exit classes.
    pub error_codes: Vec<i32>,
    /// The key ID that signed the proof.
    pub signer_key_id: String,
}

/// The newest sweep evidence, and what it does not say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProofDisclosure {
    /// The newest usable successful run: verified, in scope and naming a cadence.
    pub newest_success: Option<ProofRecord>,
    /// Where that run sits against the bound its own duration justifies.
    pub freshness: Option<ProofFreshness>,
    /// Why no usable success exists, in the gate's own words.
    pub absent_reason: Option<String>,
    /// The newest failed run for this scope: its counts, or why they are not shown.
    pub newest_failure: Option<Observed<ProofRecord>>,
    /// Proof files this host could not decode, counted rather than dropped.
    pub malformed: usize,
}

/// One audit chain's verified head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditChainHead {
    /// The actor and the signer that verified, never a file name.
    pub chain: String,
    /// The digest of the last record the walk verified, in lowercase hex.
    pub digest: String,
}

/// Where the audit log ends, and what that does not prove.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditDisclosure {
    /// One head per chain this host could verify.
    pub chains: Vec<AuditChainHead>,
    /// Records the walk verified.
    pub records: usize,
    /// Segments it walked.
    pub segments: usize,
    /// Entries it could not read, so a reader knows the walk was partial.
    pub unreadable: usize,
    /// Records that verified against no pinned key, or against one that may not sign
    /// them. A head over them ends a chain this host cannot fully attribute.
    pub unattributed: usize,
    /// The first chain that does not reach a head, when one does not.
    pub broken: Option<String>,
    /// Why no head could be read at all.
    pub absent_reason: Option<String>,
}

/// The whole disclosure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusReport {
    /// The platform the command is running on.
    ///
    /// FR-037: a reader must be able to tell a Linux host from a macOS host
    /// without reading the configuration, because the same document reports
    /// confinement on one and its absence on the other.
    pub platform: &'static str,
    /// The backend capability channel.
    pub backend: StatusDisclosure,
    /// The recorded schedule and the measured unit state.
    pub arming: ArmingDisclosure,
    /// The newest proof of each outcome, and the run window of the usable one.
    pub proof: ProofDisclosure,
    /// Where the audit log ends.
    pub audit: AuditDisclosure,
    /// The postures, separate from the capability.
    pub posture: PostureDisclosure,
    /// One disclosure per host capability: the platform, the order the
    /// configuration named, the adapter that ran and its guarantee level.
    ///
    /// Separate from [`posture`](Self::posture) because the two answer
    /// different questions. The posture says *what the kernel measured*; this
    /// says *what the operator asked for and what the host confirmed*. A reader
    /// that saw only the posture could not tell a configured `memfd_secret`
    /// from one that fell back, and a reader that saw only this could not tell
    /// whether the mechanism was enforced.
    ///
    /// Serialised as S5's own sentences, for the same reason the posture is:
    /// `ksp-posture` is the authority on what a capability disclosure means and
    /// takes no serialisation dependency (CF-001).
    #[serde(serialize_with = "serialize_capabilities")]
    pub capabilities: Vec<ksp_posture::CapabilityDisclosure>,
    /// Whether replay detection is in force.
    pub freshness: Freshness,
    /// The last canary lookup, if one ran. Never an erasure claim.
    pub canary: Option<CanaryResult>,
    /// The mode and ownership of every protected root.
    pub permissions: PermissionDisclosure,
    /// Whether this home is bound to a UNIX account that still exists here.
    pub binding: BindingDisclosure,
    /// What a key-file passphrase protects, verbatim (FR-019).
    pub passphrase: &'static str,
    /// That a last trigger is not evidence (FR-006).
    pub last_trigger_note: &'static str,
    /// That an interval is a schedule and the floor is policy (FR-009, FR-035).
    pub schedule_note: &'static str,
}

/// The facts the document is composed from, apart from the backend channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusFacts {
    /// The recorded schedule and its measured state.
    pub arming: ArmingDisclosure,
    /// The newest proof of each outcome.
    pub proof: ProofDisclosure,
    /// Where the audit log ends.
    pub audit: AuditDisclosure,
    /// The postures.
    pub posture: PostureDisclosure,
    /// One disclosure per host capability.
    pub capabilities: Vec<ksp_posture::CapabilityDisclosure>,
    /// Whether replay detection is in force.
    pub freshness: Freshness,
    /// The last canary lookup, if one ran.
    pub canary: Option<CanaryResult>,
    /// The mode and ownership of every protected root.
    pub permissions: PermissionDisclosure,
    /// Whether this home is bound to a UNIX account that still exists here.
    pub binding: BindingDisclosure,
}

/// The two postures serialize as the sentences S5 renders for them.
///
/// A manual impl rather than a derive: S5's types are the authority on what a
/// posture means, and S3 must not force a wire format onto them. Keeping the
/// typed fields means a caller can still ask `is this confined?` without parsing
/// a string.
impl Serialize for PostureDisclosure {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("PostureDisclosure", 3)?;
        state.serialize_field("confinement", &self.confinement.to_string())?;
        state.serialize_field("barrier", &self.barrier.to_string())?;
        state.serialize_field("undumpable", &self.undumpable.to_string())?;
        state.end()
    }
}

/// The capability disclosures as the sentences S5 renders for them.
fn serialize_capabilities<S: serde::Serializer>(
    capabilities: &[ksp_posture::CapabilityDisclosure],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let rendered: Vec<String> = capabilities.iter().map(ToString::to_string).collect();
    rendered.serialize(serializer)
}

impl StatusDisclosure {
    /// Derive the disclosure from an admission classification.
    ///
    /// The `evidence` string is the classification's own mechanism and cadence
    /// statement, quoted rather than reinterpreted.
    pub fn from_classification(value: &Classification) -> Self {
        let cadence_secs = value.declared_cadence.map(|cadence| cadence.as_secs());
        let proven_secs = value.proven_cadence.map(|cadence| cadence.as_secs());
        let declared = match value.declared_cadence {
            Some(cadence) => format!("declared cadence {}s", cadence.as_secs()),
            None => "no declared cadence".to_owned(),
        };
        let proven = match (value.proven_cadence, value.proof_age) {
            (Some(cadence), Some(age)) => {
                format!("proven cadence {}s, proof age {age}s", cadence.as_secs())
            }
            (Some(cadence), None) => format!("proven cadence {}s", cadence.as_secs()),
            (None, _) => "no proven cadence".to_owned(),
        };
        let evidence = format!("{}: {declared}; {proven}", value.mechanism);
        // A floor is only meaningful where admission can happen. `None` admits
        // no lease at all, so reporting "minimum 48h" beside it would invite the
        // reader to conclude a 48h lease is acceptable — the opposite of what
        // the capability says. The floor comes from the capability's own cadence,
        // which is the proven one whenever a proof exists.
        let admission_minimum_secs = match value.capability {
            LeaseCapability::None => None,
            _ => value
                .capability
                .interval()
                .and_then(admission_floor)
                .map(|f| f.as_secs()),
        };
        Self {
            capability: value.capability,
            mechanism: value.mechanism.to_owned(),
            evidence,
            declared_cadence_secs: cadence_secs,
            proven_cadence_secs: proven_secs,
            proof_age_secs: value.proof_age,
            admission_minimum_secs,
            next_action: value.state.as_ref().and_then(crate::admission::next_action),
            // Not copied from the classification: even when a classification
            // reported a lag, this surface would be asserting a measurement the
            // system cannot make.
            cleanup_lag: CleanupLag::Unknown,
            // The reason names where this surface got the number: the backend's
            // classification. It does not say "the configuration states it",
            // because this surface never read the configuration and cannot
            // vouch for what it would say.
            retention: match value.retention {
                Some(retention) => Retention::Known {
                    window_secs: retention.as_secs(),
                    reason: "reported by the selected backend's classification".to_owned(),
                },
                None => Retention::Unknown {
                    reason: "the selected backend's classification states no retention window"
                        .to_owned(),
                },
            },
        }
    }
}

/// Build a complete report.
///
/// Every fact is required: there is no default for a schedule nobody recorded, a
/// proof nobody read or a head nobody verified, so a caller cannot omit an unknown
/// and leave a blank that reads like "nothing to report".
pub fn report(classification: &Classification, facts: StatusFacts) -> StatusReport {
    StatusReport {
        platform: std::env::consts::OS,
        backend: StatusDisclosure::from_classification(classification),
        arming: facts.arming,
        proof: facts.proof,
        audit: facts.audit,
        posture: facts.posture,
        capabilities: facts.capabilities,
        freshness: facts.freshness,
        canary: facts.canary,
        permissions: facts.permissions,
        binding: facts.binding,
        passphrase: PASSPHRASE_SENTENCE,
        last_trigger_note: LAST_TRIGGER_IS_NOT_EVIDENCE,
        schedule_note: SCHEDULE_NOTE,
    }
}

/// The admission floor for a declared cadence, named once.
pub fn admission_floor(cadence: Duration) -> Option<Duration> {
    cadence.checked_mul(2)
}
