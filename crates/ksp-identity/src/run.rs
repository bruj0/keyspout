//! The verification the compliant run path performs before it delivers anything.
//!
//! # The two refusals that must stay distinct
//!
//! Exit `6` means **this host has no key**: the enrolled agent Ed25519 key or the
//! matching X25519 recipient key is absent. Exit `8` means **this request is not
//! proven**: the proof is missing, malformed, signed by the wrong key, outside the
//! accepted buckets, or about a different delivery.
//!
//! Collapsing them would tell a user with an unprovisioned host that their proof
//! was bad, and a user whose proof was replayed that their key is missing. The
//! code keeps them apart and a test asserts they are distinguishable.
//!
//! # What this does not do
//!
//! A proof that verifies here may verify again. That is the documented property
//! of the five-bucket window, not an oversight: the proof authenticates a
//! compliant invocation, and the artifact's confidentiality comes from the HPKE
//! seal. Nothing in this module prevents replay and nothing here claims to.

use ksp_types::RecordVersion;

use crate::enrolment::{RecipientPublicKey, VerifyingPublicKey};
use crate::pop::{self, PopError, PopPreimage};
use crate::token::TokenSignature;

/// Exit code for "this host has no key".
pub const EXIT_MISSING_KEY: i32 = 6;

/// Exit code for "this request is not proven".
pub const EXIT_UNPROVEN: i32 = 8;

/// The keys this host holds, if any.
///
/// `None` is a real state — an unprovisioned host — and is what makes exit `6`
/// different from exit `8`.
#[derive(Debug, Clone, Copy)]
pub struct HostKeys<'a> {
    /// The enrolled agent's Ed25519 public key.
    pub signing_public: Option<&'a VerifyingPublicKey>,
    /// The agent's X25519 recipient key, needed to unwrap the delivery.
    pub recipient_public: Option<&'a RecipientPublicKey>,
}

/// What the run path is being asked to do.
#[derive(Debug, Clone)]
pub struct RunRequest {
    /// The delivery identifier the caller believes it is acting on.
    pub jti: String,
    /// The exact record version.
    pub record_version: RecordVersion,
    /// The record path.
    pub record_path: String,
    /// The argv that will be handed to the child, in order.
    pub argv: Vec<Vec<u8>>,
    /// The verifier's clock.
    pub now: u64,
}

/// What a proof presented alongside the request claims.
#[derive(Debug, Clone, Copy)]
pub struct PresentedProof<'a> {
    /// The preimage the signer says it signed.
    pub preimage: &'a PopPreimage,
    /// The signature over it.
    pub signature: &'a TokenSignature,
}

/// The outcome of the run path's verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// Every check passed; the delivery may be delivered.
    Deliver,
    /// Nothing may be delivered, for this reason.
    Refuse(RunRefusal),
}

impl RunOutcome {
    /// Whether the run may proceed.
    pub fn may_deliver(&self) -> bool {
        matches!(self, Self::Deliver)
    }

    /// The process exit code this outcome corresponds to.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Deliver => 0,
            Self::Refuse(refusal) => refusal.exit_code(),
        }
    }
}

/// Why the run path refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunRefusal {
    /// This host holds no enrolled agent signing key.
    #[error("this host holds no enrolled agent Ed25519 key")]
    MissingSigningKey,
    /// This host holds no matching X25519 recipient key.
    #[error("this host holds no matching X25519 recipient key, so nothing can be unwrapped")]
    MissingRecipientKey,
    /// No proof of possession was presented.
    #[error("no proof of possession was presented")]
    MissingProof,
    /// The proof could not be interpreted.
    #[error("the proof of possession is malformed: {cause}")]
    MalformedProof {
        /// What could not be read.
        cause: String,
    },
    /// The proof names an instant outside the five accepted buckets.
    #[error("the proof names instant {window_ts}, which is outside the accepted buckets for {now}")]
    OutsideWindow {
        /// The instant the proof names.
        window_ts: u64,
        /// The verifier's clock.
        now: u64,
    },
    /// The proof is about a different delivery than the request.
    #[error("the proof is about {field}, which does not match the request")]
    BindingMismatch {
        /// Which bound field disagreed.
        field: &'static str,
    },
    /// The signature did not verify against the enrolled key.
    #[error("the proof of possession did not verify against the enrolled agent key")]
    BadSignature,
}

impl RunRefusal {
    /// The process exit code.
    ///
    /// `6` for a host with no key, `8` for a request that is not proven. The two
    /// are never the same number, because they ask the user to do different
    /// things.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::MissingSigningKey | Self::MissingRecipientKey => EXIT_MISSING_KEY,
            Self::MissingProof
            | Self::MalformedProof { .. }
            | Self::OutsideWindow { .. }
            | Self::BindingMismatch { .. }
            | Self::BadSignature => EXIT_UNPROVEN,
        }
    }
}

/// The verification the compliant run path performs before delivering anything.
///
/// The order is the order a user would reason in: does this host have the keys at
/// all (6), was a proof presented (8), does it name an acceptable instant (8), is
/// it about *this* delivery (8), and does it verify (8).
pub fn verify_run(
    keys: HostKeys<'_>,
    request: &RunRequest,
    proof: Option<PresentedProof<'_>>,
) -> RunOutcome {
    let Some(signing_public) = keys.signing_public else {
        return RunOutcome::Refuse(RunRefusal::MissingSigningKey);
    };
    let Some(proof) = proof else {
        return RunOutcome::Refuse(RunRefusal::MissingProof);
    };

    // The proof is bound to the delivery, not merely to the token: a proof for
    // another `jti`, version, path or command does not authorise this one.
    if proof.preimage.jti() != request.jti {
        return RunOutcome::Refuse(RunRefusal::BindingMismatch { field: "jti" });
    }
    if proof.preimage.record_version() != request.record_version {
        return RunOutcome::Refuse(RunRefusal::BindingMismatch {
            field: "record_version",
        });
    }
    if proof.preimage.record_path() != request.record_path {
        return RunOutcome::Refuse(RunRefusal::BindingMismatch {
            field: "record_path",
        });
    }
    let expected_argv = match pop::argv_hash(&request.argv) {
        Ok(hash) => hash,
        Err(err) => {
            return RunOutcome::Refuse(RunRefusal::MalformedProof {
                cause: err.to_string(),
            });
        }
    };
    if proof.preimage.argv_hash() != &expected_argv {
        return RunOutcome::Refuse(RunRefusal::BindingMismatch { field: "argv_hash" });
    }

    // Set membership in the five buckets, never a duration comparison.
    if !pop::is_accepted(request.now, proof.preimage.window_ts()) {
        return RunOutcome::Refuse(RunRefusal::OutsideWindow {
            window_ts: proof.preimage.window_ts(),
            now: request.now,
        });
    }

    match pop::verify_pop(signing_public, proof.preimage, proof.signature) {
        Ok(()) => {}
        Err(PopError::Signature) => return RunOutcome::Refuse(RunRefusal::BadSignature),
        Err(err) => {
            return RunOutcome::Refuse(RunRefusal::MalformedProof {
                cause: err.to_string(),
            });
        }
    }

    // Last, because it is about what happens *after* verification: without the
    // recipient key the delivery cannot be unwrapped, so no secret is delivered.
    if keys.recipient_public.is_none() {
        return RunOutcome::Refuse(RunRefusal::MissingRecipientKey);
    }

    RunOutcome::Deliver
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_two_refusal_classes_have_distinct_exit_codes() {
        assert_eq!(RunRefusal::MissingSigningKey.exit_code(), 6);
        assert_eq!(RunRefusal::MissingRecipientKey.exit_code(), 6);
        assert_eq!(RunRefusal::MissingProof.exit_code(), 8);
        assert_eq!(RunRefusal::BadSignature.exit_code(), 8);
        assert_ne!(EXIT_MISSING_KEY, EXIT_UNPROVEN);
    }
}
