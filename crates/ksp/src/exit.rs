//! The exit-code contract, in one place.
//!
//! Every code the binary can return is a named constant here, and every
//! subsystem's typed failure maps to one of them through a function in this
//! module. A command never chooses an integer.
//!
//! Two of these codes exist because the failures they carry mean different
//! things to the caller:
//!
//! - [`DELETE_FAILED`]: the record may still be there, so a retry may succeed;
//! - [`LOST_FRESH_FETCH`]: the record is gone, so a retry cannot help and the
//!   caller must ask for a new delivery.
//!
//! Collapsing them would tell a calling agent to retry something that cannot
//! work, or to give up on something that would have.

use ksp_deletion::ConsumeError;
use ksp_identity::{MintRefusal, RunRefusal};

/// Success.
pub const SUCCESS: i32 = 0;

/// An unexpected internal failure. Not part of the published contract: it exists
/// so an unexpected path is still distinguishable from a defined refusal.
pub const INTERNAL: i32 = 1;

/// The policy denied the operation.
pub const POLICY_DENIAL: i32 = 2;

/// Key material the operation needs is missing.
pub const MISSING_KEY: i32 = 6;

/// The backend's capability or admission floor refused the lease.
pub const CAPABILITY_REFUSAL: i32 = 7;

/// The proof of possession was invalid or missing.
pub const UNPROVEN: i32 = 8;

/// The delete failed. The record may still be present.
pub const DELETE_FAILED: i32 = 9;

/// A child failed after a successful removal. The record is gone.
pub const LOST_FRESH_FETCH: i32 = 10;

/// A compliant run was refused because the backend requires consumption.
pub const UNCONSUMED_REFUSED: i32 = 11;

/// The audit log did not verify.
///
/// A code of its own rather than [`UNPROVEN`], which the contract defines as a
/// proof of possession: an agent debugging its key and an operator reading a
/// tampered log need different next steps, and one integer cannot say both.
pub const AUDIT_UNVERIFIED: i32 = 12;

/// The invocation was malformed, and the message names the accepted form.
///
/// A code of its own rather than [`INTERNAL`] or [`POLICY_DENIAL`], because an
/// agent branches on the integer without reading the message and the three mean
/// different next steps: fix the invocation, report a bug, or accept a decision.
/// Collapsing a typo into `INTERNAL` told a caller to report a crash; collapsing
/// it into `POLICY_DENIAL` told it a policy had decided something.
///
/// `3`, `4` and `5` are reserved by the design specification for token expiry, an
/// unreachable backend and a sealed vault. This code deliberately skips them, so
/// a future implementation of those features does not contradict a shipped
/// contract.
pub const USAGE: i32 = 13;

/// The outcome of one invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The operation completed.
    Success,
    /// The operation stopped and this is why.
    Failed(i32),
}

impl Outcome {
    /// The integer the process returns.
    pub fn code(self) -> i32 {
        match self {
            Self::Success => SUCCESS,
            Self::Failed(code) => code,
        }
    }

    /// Whether this outcome is a success.
    pub fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

/// Map a mint refusal to its code.
///
/// Delegates to the mint's own mapping rather than restating it: two copies of
/// a classification rule is two places to be wrong, and the subsystem is the
/// authority on which refusal is which.
pub fn from_mint(refusal: &MintRefusal) -> i32 {
    refusal.exit_code() as i32
}

/// Map a run refusal to its code.
pub fn from_run(refusal: &RunRefusal) -> i32 {
    refusal.exit_code()
}

/// Map a consume failure to its code.
pub fn from_consume(error: &ConsumeError) -> i32 {
    error.exit_code()
}

/// The code for an admission refusal.
pub fn from_admission() -> i32 {
    CAPABILITY_REFUSAL
}

/// A one-line description of a published code.
///
/// Codes are part of the contract, so the sentence names what the caller can do
/// rather than what went wrong inside: a retry is the difference between two of
/// these.
pub fn describe(code: i32) -> &'static str {
    match code {
        SUCCESS => "ok",
        INTERNAL => "unexpected internal failure",
        POLICY_DENIAL => "policy denied the operation",
        MISSING_KEY => "key material is missing or unreadable",
        CAPABILITY_REFUSAL => "the backend or the host layout cannot admit this lease",
        UNPROVEN => "the proof of possession was invalid or missing",
        DELETE_FAILED => "the delete failed; a retry may succeed",
        LOST_FRESH_FETCH => "the record was removed and the child failed; ask for a new delivery",
        UNCONSUMED_REFUSED => "a scheduled backend requires --consume",
        AUDIT_UNVERIFIED => "the audit log did not verify; the report names the finding",
        USAGE => "the invocation was malformed; the message names the accepted form",
        _ => "unrecognised outcome",
    }
}

/// The code for a policy refusal.
pub fn from_policy() -> i32 {
    POLICY_DENIAL
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn every_published_code_is_distinct() {
        let codes = [
            SUCCESS,
            POLICY_DENIAL,
            MISSING_KEY,
            CAPABILITY_REFUSAL,
            UNPROVEN,
            DELETE_FAILED,
            LOST_FRESH_FETCH,
            UNCONSUMED_REFUSED,
            AUDIT_UNVERIFIED,
        ];
        for (index, left) in codes.iter().enumerate() {
            for right in &codes[index + 1..] {
                assert_ne!(left, right, "two outcomes share a code");
            }
        }
    }

    #[test]
    fn the_lost_fresh_fetch_code_differs_from_the_delete_failure_code() {
        // The whole point: a caller that retries a lost fresh fetch wastes a
        // round trip, and a caller that gives up on a failed delete abandons a
        // delivery it could have had.
        assert_ne!(LOST_FRESH_FETCH, DELETE_FAILED);
        assert_ne!(LOST_FRESH_FETCH, SUCCESS);
        assert_ne!(DELETE_FAILED, SUCCESS);
    }

    #[test]
    fn the_published_codes_match_the_design_contract() {
        assert_eq!(SUCCESS, 0);
        assert_eq!(POLICY_DENIAL, 2);
        assert_eq!(MISSING_KEY, 6);
        assert_eq!(CAPABILITY_REFUSAL, 7);
        assert_eq!(UNPROVEN, 8);
        assert_eq!(AUDIT_UNVERIFIED, 12);
    }

    #[test]
    fn the_subsystem_codes_agree_with_this_module() {
        // The subsystems own their classifications; this module owns the
        // contract. If they drift, one of them is lying, and this is the cheap
        // place to find out.
        assert_eq!(
            ksp_identity::mint::EXIT_REFUSED as i32,
            POLICY_DENIAL,
            "the mint's authorisation refusal is a policy denial"
        );
        assert_eq!(
            ksp_identity::mint::EXIT_INADMISSIBLE as i32,
            CAPABILITY_REFUSAL
        );
        assert_eq!(
            ksp_identity::mint::EXIT_INTERNAL as i32,
            INTERNAL,
            "a mint the host could not record is an internal failure, not a refusal"
        );
        assert_eq!(ksp_identity::run::EXIT_MISSING_KEY, MISSING_KEY);
        assert_eq!(ksp_identity::run::EXIT_UNPROVEN, UNPROVEN);
        assert_eq!(ksp_deletion::EXIT_DELETE_FAILED, DELETE_FAILED);
        assert_eq!(ksp_deletion::EXIT_LOST_FRESH_FETCH, LOST_FRESH_FETCH);
        assert_eq!(ksp_deletion::EXIT_UNCONSUMED_REFUSED, UNCONSUMED_REFUSED);
    }

    #[test]
    fn an_outcome_reports_its_code() {
        assert_eq!(Outcome::Success.code(), 0);
        assert!(Outcome::Success.is_success());
        assert_eq!(Outcome::Failed(LOST_FRESH_FETCH).code(), LOST_FRESH_FETCH);
        assert!(!Outcome::Failed(POLICY_DENIAL).is_success());
    }
}
