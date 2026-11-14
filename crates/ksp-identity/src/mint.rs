//! The mint sequence: authorise, arm durably, then — only then — publish.
//!
//! There is no distributed transaction between the Blob Store and the channel a
//! token leaves by. The sequence therefore orders the two irreversibly: the
//! deletion intent is armed and acknowledged first, and token bytes are
//! produced afterwards. The window this leaves is a token published for a lease
//! that turns out to be unreachable — recoverable by the sweep — rather than a
//! lease nobody can clean up because no byte ever named it (§0 of the design).
//!
//! [`MintAuthority`] is what makes the order a type invariant instead of a
//! convention: it has no public constructor, so [`mint`]'s publication closure
//! cannot be reached on a path that skipped the arm.

use ksp_backend::admission::{AdmissionError, Classification, admit_at_gate};
use ksp_backend::arming::{ArmError, ArmRecord, ArmingAcknowledgement, ArmingStore, arm_intent};
use ksp_types::evidence::DeletionIntent;
use ksp_types::{AdmissionDecision, AdmissionRefusal, LeaseCapability};

use crate::enrolment::{RecipientPublicKey, SigningSecretKey, VerifyingPublicKey};
use crate::fingerprint::{EnrolmentFingerprint, FingerprintSubject, KeyId};
use crate::issuance::{Issuance, IssuanceLedger, PublishError};
use crate::policy::{Policy, PolicyRequest, PolicyVerifier, VerificationOutcome};
use ksp_types::ActorId;

/// Exit code for a refusal that is about authorisation.
pub const EXIT_REFUSED: u8 = 2;
/// Exit code for a refusal that is about storage admission or lease duration.
pub const EXIT_INADMISSIBLE: u8 = 7;
/// Exit code for a failure that is neither the caller's request nor the store's
/// admission: the host could not record what it was about to publish.
///
/// The number is `exit::INTERNAL` in the CLI, which this module cannot import.
/// `crates/ksp-cli/src/exit.rs` asserts the two agree, so a drift is a failing
/// test rather than a changed contract.
pub const EXIT_INTERNAL: u8 = 1;

/// The four things a fingerprint must bind, plus the value the user confirmed.
///
/// The fingerprint is not read from the record: it is **recomputed** from the
/// claims this mint will act on and compared with the one the user confirmed
/// out of band. A substituted key therefore fails here even when the record's
/// own fingerprint field is genuine (Misfit Q).
#[derive(Debug)]
pub struct MintBinding {
    /// The user or agent the keys belong to.
    pub identity: ActorId,
    /// The agent's Ed25519 public key.
    pub signing_key: VerifyingPublicKey,
    /// The agent's X25519 public key.
    pub recipient_key: RecipientPublicKey,
    /// The ID naming the signing key.
    pub signing_key_id: KeyId,
    /// The ID naming the recipient key.
    pub recipient_key_id: KeyId,
    /// The fingerprint the user confirmed.
    pub confirmed_fingerprint: EnrolmentFingerprint,
}

impl MintBinding {
    /// Whether this binding reproduces the confirmed fingerprint.
    ///
    /// All four items take part: changing any one of them changes the digest.
    pub fn matches_confirmed_fingerprint(&self) -> bool {
        EnrolmentFingerprint::compute(&FingerprintSubject {
            identity: self.identity,
            signing_key: self.signing_key.to_bytes(),
            recipient_key: self.recipient_key.to_bytes(),
            signing_key_id: self.signing_key_id.clone(),
            recipient_key_id: self.recipient_key_id.clone(),
        })
        .is_ok_and(|recomputed| recomputed.matches(&self.confirmed_fingerprint))
    }
}

/// Everything one mint needs, gathered so the sequence reads as a sequence.
#[derive(Debug)]
pub struct MintRequest {
    /// The identity and keys the user confirmed.
    pub binding: MintBinding,
    /// What the policy is asked to authorise.
    pub policy_request: PolicyRequest,
    /// The key this mint intends to seal to.
    pub intended_recipient: RecipientPublicKey,
    /// The key-free intent to arm.
    pub intent: DeletionIntent,
    /// The idempotent identity of this mint, reused on every retry.
    pub operation_identity: String,
    /// How many deliveries the copy permits, when the sharer bounded it.
    ///
    /// `None` is a time-bounded lease, which is what every mint before this
    /// field existed produced. The bound is armed with the intent, so it is
    /// durable before any token bytes exist.
    pub remaining_uses: Option<u32>,
}

/// Why a mint stopped before it could publish anything.
#[derive(Debug, thiserror::Error)]
pub enum MintRefusal {
    /// The confirmed fingerprint does not bind the identity, both keys and both
    /// key IDs this mint would act on.
    #[error("the confirmed fingerprint does not bind the supplied identity and keys")]
    FingerprintMismatch,
    /// The key this mint would seal to is not the one the fingerprint binds.
    #[error("the sealing key is not the one the confirmed fingerprint binds")]
    RecipientKeyMismatch,
    /// The policy did not authorise this mint.
    #[error("policy refused the mint: {reason}")]
    Policy {
        /// The policy's stated reason.
        reason: String,
    },
    /// The selected backend cannot durably hold this lease.
    #[error("storage refused the lease: {reason}")]
    Inadmissible {
        /// The backend's stated reason.
        reason: String,
    },
    /// The lease is shorter than the backend's cleanup guarantee allows.    ///
    /// Seconds, not hours: rounding the request up to a whole hour would admit a
    /// 599 s lease under a 600 s floor, and both numbers are named so the operator
    /// can pick a duration rather than guess at one.
    #[error(
        "a {requested_secs}s lease is below the {floor_secs}s minimum: the backend sweeps every {cadence_secs}s and must sweep after the deadline"
    )]
    BelowSweepFloor {
        /// The duration the caller asked for.
        requested_secs: u64,
        /// Twice the proven cadence.
        floor_secs: u64,
        /// The cadence the proof establishes.
        cadence_secs: u64,
    },
    /// The delivery was sealed and this host could not record it.
    ///
    /// The artifact is dropped rather than handed out: a token with no ledger row
    /// is a live credential nothing on this host can revoke, so the failure is
    /// recorded and nothing is published.
    #[error("the delivery was sealed but not recorded, so no token was written: {reason}")]
    Ledger {
        /// The ledger's own reason.
        reason: String,
    },
    /// The operation identity already names different intent bytes.
    ///
    /// Reusing an identity is how a retry reconciles; reusing it for a *different*
    /// lease would overwrite the record the first lease depends on, leaving a
    /// live token with nothing armed against it.
    #[error("operation identity {operation_identity} already names a different deletion intent")]
    IdentityConflict {
        /// The identity that is already taken.
        operation_identity: String,
    },
    /// Arming was attempted but the acknowledgement was lost or contradicted.
    #[error("arming is uncertain: {0}")]
    Uncertain(#[from] ArmError),
}

impl MintRefusal {
    /// The process exit code this refusal maps to.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::FingerprintMismatch
            | Self::RecipientKeyMismatch
            | Self::Policy { .. }
            | Self::IdentityConflict { .. } => EXIT_REFUSED,
            // An empty identity is the caller's mistake, not the store's.
            Self::Uncertain(ArmError::InvalidIdentity) => EXIT_REFUSED,
            Self::Inadmissible { .. } | Self::BelowSweepFloor { .. } | Self::Uncertain(_) => {
                EXIT_INADMISSIBLE
            }
            // Neither the caller's request nor the store's admission: the host
            // sealed a delivery and could not record it.
            Self::Ledger { .. } => EXIT_INTERNAL,
        }
    }
}

/// Proof that an arm was acknowledged.
///
/// The field is private and there is no public constructor, so a caller cannot
/// conjure one — publication is unreachable except through [`arm`].
#[derive(Debug)]
pub struct MintAuthority {
    acknowledgement: ArmingAcknowledgement,
}

impl MintAuthority {
    /// The acknowledgement this authority rests on.
    pub fn acknowledgement(&self) -> &ArmingAcknowledgement {
        &self.acknowledgement
    }
}

/// What a completed mint hands back.
#[derive(Debug)]
pub struct MintOutcome<T> {
    /// What publication produced, or why sealing failed.
    ///
    /// Sealing runs after the arm, so its failure is reported as the outcome's
    /// value rather than as a refusal: the lease was armed and no token exists,
    /// which the sweep reconciles. The ledger holds no row in that case.
    pub token: T,
    /// The acknowledgement that licensed publication.
    pub acknowledgement: ArmingAcknowledgement,
}

/// T047: the duration gate, naming the cadence and the minimum on refusal.
fn admit(classification: &Classification, requested_secs: u64) -> Result<(), MintRefusal> {
    let requested = std::time::Duration::from_secs(requested_secs);
    let decision = admit_at_gate(classification, requested).map_err(|error| match error {
        // The admission rule stays in S3; only the wording is restated here, in
        // seconds, because the operator reading the refusal is choosing a `--ttl`
        // and the boundary it has to clear.
        AdmissionError::CapabilityRefusal {
            capability: LeaseCapability::Scheduled { interval },
            ..
        } => MintRefusal::BelowSweepFloor {
            requested_secs,
            floor_secs: interval.as_secs().saturating_mul(2),
            cadence_secs: interval.as_secs(),
        },
        AdmissionError::CapabilityRefusal { reason, .. } => MintRefusal::Inadmissible { reason },
        AdmissionError::ConfigurationMismatch(what) => MintRefusal::Inadmissible {
            reason: format!("the known {what} configuration contradicts its declared capability"),
        },
    })?;
    match decision {
        AdmissionDecision::Admitted => Ok(()),
        AdmissionDecision::Refused(AdmissionRefusal::BelowFloor { requested, floor }) => {
            Err(MintRefusal::BelowSweepFloor {
                requested_secs: requested.as_secs(),
                floor_secs: floor.as_secs(),
                cadence_secs: floor.as_secs() / 2,
            })
        }
        AdmissionDecision::Refused(AdmissionRefusal::NoMechanism) => {
            Err(MintRefusal::Inadmissible {
                reason: "the selected backend has no deadline mechanism".to_owned(),
            })
        }
    }
}

/// The public identifier of the key that signs an arm.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// T045 steps 4-6: sign the key-free intent, arm it, and accept only an
/// acknowledgement that matches the bytes this call signed.
pub fn arm(
    store: &dyn ArmingStore,
    signer: &SigningSecretKey,
    intent: DeletionIntent,
    operation_identity: &str,
    remaining_uses: Option<u32>,
) -> Result<MintAuthority, MintRefusal> {
    let record = sign_arm_record(signer, intent, operation_identity, remaining_uses)?;
    let bytes = record.to_bytes()?;

    // An identity is an idempotency key, not a label. Reading it first is what
    // makes reuse safe: `arm_intent` only compares what it reads back *after*
    // writing, so an overwriting store would report success while the earlier
    // lease lost the record that names it. Refuse before touching the store.
    if let Some(existing) = store.read_arm(operation_identity)?
        && existing != bytes
    {
        return Err(MintRefusal::IdentityConflict {
            operation_identity: operation_identity.to_owned(),
        });
    }

    // `arm_intent` then re-reads what it wrote, which is what turns a lost
    // acknowledgement into `Uncertain` rather than a silent success.
    let acknowledgement = arm_intent(store, &record)?;
    Ok(MintAuthority { acknowledgement })
}

/// T044: sign the key-free intent for arming.
///
/// Exposed so a caller can inspect or re-present exactly the bytes the arm
/// would write; the preimage itself stays in `ksp-backend`, so there is one
/// definition of what an arm signature covers.
/// The record names its signer by the **public key's hex**, not by the
/// deployment's key ID: the sweep holds no table that maps the one to the other,
/// and a reader can compare the bytes against the pin directly. The intent
/// alongside it carries the key ID, so both forms are present in what the two
/// artifacts say about who armed the lease.
pub fn sign_arm_record(
    signer: &SigningSecretKey,
    intent: DeletionIntent,
    operation_identity: &str,
    remaining_uses: Option<u32>,
) -> Result<ArmRecord, ArmError> {
    ArmRecord::sign(
        operation_identity.to_owned(),
        intent,
        hex(&signer.verifying_public().to_bytes()),
        remaining_uses,
        signer.dalek(),
    )
}

/// The whole sequence.
///
/// `publish` is passed the [`MintAuthority`], which exists only after the
/// acknowledgement, so no ordering mistake in the caller can produce token
/// bytes first. In production it is WP06's `seal`; in tests it records what it
/// was given.
#[allow(clippy::too_many_arguments)]
pub fn mint<T, E>(
    store: &dyn ArmingStore,
    ledger: &IssuanceLedger,
    signer: &SigningSecretKey,
    verifier: &PolicyVerifier,
    policy: &Policy,
    classification: &Classification,
    requested_secs: u64,
    at: u64,
    request: MintRequest,
    issuance: Issuance,
    publish: impl FnOnce(&MintAuthority) -> Result<T, E>,
) -> Result<MintOutcome<Result<T, E>>, MintRefusal> {
    // T042: the fingerprint gate runs first, before any write and any output,
    // so a substituted key costs the backend nothing to refuse.
    if !request.binding.matches_confirmed_fingerprint() {
        return Err(MintRefusal::FingerprintMismatch);
    }
    if request.intended_recipient.to_bytes() != request.binding.recipient_key.to_bytes() {
        return Err(MintRefusal::RecipientKeyMismatch);
    }

    // T043: the policy, including the level pair, grants and maximum TTL.
    match verifier.verify(policy, &request.policy_request, at) {
        VerificationOutcome::Fresh { .. } | VerificationOutcome::Stale { .. } => {}
        VerificationOutcome::Refused(refusal) => {
            return Err(MintRefusal::Policy {
                reason: refusal.to_string(),
            });
        }
    }

    admit(classification, requested_secs)?;

    let authority = arm(
        store,
        signer,
        request.intent,
        &request.operation_identity,
        request.remaining_uses,
    )?;
    // Seal, then record — and only when the seal produced something. The closure
    // reports failure as a value, because publication is the caller's step and
    // its error type is the caller's; a row written for a seal that failed would
    // be a phantom issuance, a lease nothing can revoke because no token exists.
    let token = match publish(&authority) {
        Ok(value) => ledger
            // The seal half of `PublishError` is uninhabited here by construction:
            // the value was produced before the call.
            .publish_recorded(issuance, || Ok::<T, std::convert::Infallible>(value))
            .map_err(|error| match error {
                PublishError::Seal(never) => match never {},
                PublishError::Ledger(cause) => MintRefusal::Ledger {
                    reason: cause.to_string(),
                },
            })
            .map(Ok)?,
        Err(error) => Err(error),
    };
    Ok(MintOutcome {
        token,
        acknowledgement: authority.acknowledgement().clone(),
    })
}
