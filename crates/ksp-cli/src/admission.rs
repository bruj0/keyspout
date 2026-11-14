//! The one place the CLI turns a recorded schedule and a proof into a capability.
//!
//! Admission and `ksp status` read the same result here, so what an operator is told
//! and what a lease is allowed cannot drift apart. The gate itself lives in
//! `ksp-backend`; this module only supplies it with the deployment's scope and the
//! pinned anchor, and reads the declaration beside it for disclosure.

use std::time::Duration;

use ksp_backend::admission::{AdmissionError, Classification, FileEvidence, classify_file};
use ksp_backend::proof::{GateRefusal, ProofGate};
use ksp_backend::sweeper::{SignedArming, SweeperArming};
use ksp_types::LeaseCapability;

use crate::config::{BackendSelection, Layout};
use crate::deployment::{self, Deployment};
use crate::keys::Anchor;

/// A classification, plus the gate's own reason when it refused.
///
/// The refusal is carried rather than stringified at the call site: `token mint` has
/// to print what was observed — no proof, a failed signature, a stale proof with its
/// age and bound — and a generic "no mechanism" would erase exactly that.
pub struct Admission {
    /// What the backend is known to do about a deadline.
    pub classification: Classification,
    /// Why nothing is `Scheduled`, in the gate's words, when a proof exists or should.
    pub refusal: Option<GateRefusal>,
}

/// The prefix a proof for this deployment must name.
///
/// Derived from the deployment, not from the arming: a proof that names another
/// vault or another principal must not admit this deployment's leases (misfit O).
///
/// The shape itself is defined once, in
/// [`ksp_backend::sweeper::canonical_admission_scope`]. Writing the literal here
/// as well is how the parser and the admission check came to disagree.
pub fn deployment_scope(deployment: &Deployment) -> String {
    ksp_backend::sweeper::canonical_admission_scope(deployment.vault.as_str(), &deployment.user)
}

/// What the recorded schedules say about this deployment, and whether they could be
/// read at all.
pub enum ArmingLookup {
    /// A record verifies under the pinned anchor and names this deployment's scope.
    Recorded(Box<SweeperArming>),
    /// No record is recorded for this deployment.
    Absent,
    /// Files exist, but none is a record this host can accept as this deployment's.
    Unknown {
        /// Why nothing verified, in the reader's own words.
        reason: String,
    },
}

/// The verified arming that covers this deployment's whole agent namespace.
///
/// `None` when no record verifies under the pinned anchor or none names this
/// deployment's canonical scope. A narrower arming is not promoted into a deployment
/// declaration (FR-029): what a lease outside its scope would not have swept must not
/// be reported as swept.
pub fn recorded_arming(
    layout: &Layout,
    deployment: &Deployment,
    anchor: &Anchor,
) -> Option<SweeperArming> {
    match look_up_arming(layout, deployment, anchor) {
        ArmingLookup::Recorded(arming) => Some(*arming),
        ArmingLookup::Absent | ArmingLookup::Unknown { .. } => None,
    }
}

/// The same lookup, keeping the difference between "nothing was recorded" and "what is
/// here is not this deployment's".
///
/// Admission collapses the two because neither is evidence; disclosure must not, since
/// an operator looking at a directory full of files needs to know they were rejected
/// rather than that no one ever armed a sweep (FR-005, misfit M).
pub fn look_up_arming(layout: &Layout, deployment: &Deployment, anchor: &Anchor) -> ArmingLookup {
    // An arming may be signed by the admin or by the user, and which one decides
    // whose cleanup it describes. Both are tried: a user arming that the admin
    // anchor alone could not verify would make her own schedule invisible to her
    // own sweep.
    let mut keys: Vec<ed25519_dalek::VerifyingKey> = Vec::new();
    if let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&anchor.key.to_bytes()) {
        keys.push(key);
    }
    if let Some(user_key) = deployment.user_signing_key
        && let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&user_key.to_bytes())
    {
        keys.push(key);
    }
    if keys.is_empty() {
        return ArmingLookup::Unknown {
            reason: "the pinned keys are not valid keys, so no record can be verified".to_string(),
        };
    }
    let scope = deployment_scope(deployment);
    let entries = match std::fs::read_dir(layout.sweeper_armings_dir()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return ArmingLookup::Absent,
        Err(_) => {
            return ArmingLookup::Unknown {
                reason: "the arming records could not be read".to_string(),
            };
        }
    };
    let mut newest: Option<Box<SweeperArming>> = None;
    let mut saw_file = false;
    for entry in entries.flatten() {
        if entry
            .file_type()
            .map(|kind| kind.is_symlink())
            .unwrap_or(true)
        {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".cbor") {
            continue;
        }
        saw_file = true;
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        let Ok(signed) = SignedArming::from_bytes(&bytes) else {
            continue;
        };
        if !keys.iter().any(|key| signed.verify(key)) {
            continue;
        }
        let arming = signed.arming;
        if arming.backend != "file" || arming.scope != scope {
            continue;
        }
        if newest
            .as_ref()
            .map(|current| current.recorded_at < arming.recorded_at)
            .unwrap_or(true)
        {
            newest = Some(Box::new(arming));
        }
    }
    match newest {
        Some(arming) => ArmingLookup::Recorded(arming),
        None if saw_file => ArmingLookup::Unknown {
            reason: "arming records exist but none verifies as this deployment's schedule"
                .to_string(),
        },
        None => ArmingLookup::Absent,
    }
}

/// Classify the selected backend from this host's evidence at `now`.
pub fn classify(
    layout: &Layout,
    selection: &BackendSelection,
    now: i64,
) -> Result<Admission, AdmissionError> {
    match selection {
        BackendSelection::File { .. } => Ok(classify_file_at(layout, now)),
        // Valkey has no evidence channel of its own in this build: its configuration
        // already states whether the server enforces the deadline.
        other => Ok(Admission {
            classification: other.classification()?,
            refusal: None,
        }),
    }
}

/// The `file` classification, including the reason nothing is `Scheduled`.
pub fn classify_file_at(layout: &Layout, now: i64) -> Admission {
    let Ok((deployment, anchor)) = deployment::require(layout) else {
        return Admission {
            classification: classify_file(FileEvidence::default()),
            refusal: None,
        };
    };
    let scope = deployment_scope(&deployment);
    let record = recorded_arming(layout, &deployment, &anchor);
    let declared = record
        .as_ref()
        .map(|arming| Duration::from_secs(arming.interval_secs));
    // Two keys may sign a sweep proof, and which one did decides whose cleanup the
    // evidence describes. The admin's proof admits an admin-signed lease; the
    // user's admits a copy she bounded herself. A user arming writes no proof
    // until her sweep runs, so trying both is what lets her first sweep admit
    // her own copy without the admin having to arm anything.
    //
    // The admin anchor is tried first because it is the stronger claim: a host
    // that has both should report the admin's cadence, not the user's.
    let mut anchors: Vec<ed25519_dalek::VerifyingKey> = Vec::new();
    if let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&anchor.key.to_bytes()) {
        anchors.push(key);
    }
    if let Some(user_key) = deployment.user_signing_key
        && let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&user_key.to_bytes())
    {
        anchors.push(key);
    }

    let mut observed = None;
    let mut refusal = None;
    for key in &anchors {
        let gate = ProofGate {
            directory: layout.sweeper_proofs_dir(),
            anchor: key,
            scope: scope.clone(),
        };
        match gate.observe(now) {
            // A proof that is observed but not fresh still reports its age and
            // cadence; the refusal is the sentence a lease request prints. So an
            // `Ok` here is not "admitted": the observation carries its own
            // refusal, and dropping it would replace a stale proof's age and bound
            // with the generic "no mechanism" sentence.
            Ok(observation) => {
                refusal = observation.refusal();
                observed = Some(observation);
                break;
            }
            Err(cause) => {
                // Keep the first refusal: it is the admin's, which is the one an
                // operator expects to read when nothing has been proved at all.
                if refusal.is_none() {
                    refusal = Some(cause);
                }
            }
        }
    }
    let (proof, refusal) = if anchors.is_empty() {
        // A pinned anchor this host cannot decode names nothing to verify against.
        (None, Some(GateRefusal::Unverified { scope }))
    } else {
        (observed, refusal)
    };
    Admission {
        classification: classify_file(FileEvidence {
            declared_cadence: declared,
            proof,
            refusal: refusal.clone(),
        }),
        refusal,
    }
}

/// The capability a sweep run executes: the mechanism it is configured to keep.
///
/// Deliberately **not** the admission classification. Admission requires a proof, and
/// a run is what produces one: asking a run to prove itself before it may sweep would
/// make the first run a no-op that reports `not_yet_due = 0` without having looked.
pub fn sweep_classification(arming: Option<&SweeperArming>) -> Classification {
    let declared = arming.map(|arming| Duration::from_secs(arming.interval_secs));
    Classification {
        capability: declared
            .map(|interval| LeaseCapability::Scheduled { interval })
            .unwrap_or(LeaseCapability::None),
        mechanism: match declared {
            Some(_) => "a recorded sweep schedule this run serves",
            None => "no recorded sweep schedule for this deployment",
        },
        declared_cadence: declared,
        proven_cadence: None,
        proof_age: None,
        cleanup_lag: None,
        retention: None,
        state: None,
    }
}
