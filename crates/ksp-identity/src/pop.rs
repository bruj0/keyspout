//! The proof of possession, the ordered-argv hash and the five-bucket window.
//!
//! # What the proof does, and what it does not
//!
//! The proof authenticates **a compliant invocation**: it says "the holder of
//! this agent's Ed25519 key asked for exactly this `jti`, this record version,
//! this path and this command, at about this time".
//!
//! It does **not** prevent replay, provide exactly-once delivery, or protect a
//! content key. A captured signature verifies twice inside an accepted bucket —
//! that is a documented property, not a defect, because the alternative story
//! would obscure concurrent reads and ciphertext that has already been fetched.
//! Recipient sealing is what protects a stolen artifact; the two controls are
//! independent, and a proof-of-possession check in the CLI cannot protect a
//! content key that is already exposed.
//!
//! # The preimage order is fixed, and built once
//!
//! `keyspout-pop-v1 || CBOR([jti, record_version, record_path, argv_hash,
//! window_ts])`. The signing path and the verifying path call the same function,
//! so a future field reorder cannot make a signature verify under a different
//! meaning.
//!
//! # The argv hash is over ordered byte strings
//!
//! SHA-256 over the canonical CBOR of the argv array. Never a concatenation — a
//! naive `"a" + "bc"` and `"ab" + "c"` would collide — and never sorted, so a
//! swapped pair of arguments produces a different hash. It depends on the argv
//! bytes only: not the working directory, not `argv[0]`, not the environment,
//! not the clock. The time is the separate `window_ts` field.

use ksp_types::{DOMAIN_POP, RecordVersion, cbor};
use sha2::{Digest, Sha256};

use crate::enrolment::{SigningSecretKey, VerifyingPublicKey};
use crate::token::TokenSignature;

/// The width of one acceptance bucket, in seconds.
pub const BUCKET_SECONDS: u64 = 30;

/// The offsets, in seconds, from the current bucket start that a proof may name.
///
/// Deliberately asymmetric: `+60` is accepted and `-90` is not. A symmetric
/// "within 60 seconds" test would accept `+90` and is not this.
pub const BUCKET_OFFSETS: [i64; 5] = [0, -30, 30, -60, 60];

/// The length of an argv hash.
pub const ARGV_HASH_LEN: usize = 32;

/// The start of the bucket containing `now`.
///
/// Pure arithmetic, so the boundary is directly testable.
pub fn bucket_start(now: u64) -> u64 {
    (now / BUCKET_SECONDS) * BUCKET_SECONDS
}

/// The five instants a proof presented at `now` may name.
///
/// A **set**, not a tolerance. The membership test below is what the verifier
/// uses; nothing here compares a duration.
pub fn accepted_buckets(now: u64) -> [u64; 5] {
    let start = bucket_start(now);
    // Never a signed cast: `start - 60` below the first minute would wrap to a
    // value near `u64::MAX` and the set would silently accept it. Saturating
    // arithmetic keeps every instant a real one — near the epoch the earlier
    // buckets do not exist, so they collapse onto bucket zero rather than
    // inventing instants in the far future.
    BUCKET_OFFSETS.map(|offset| {
        if offset < 0 {
            start.saturating_sub(offset.unsigned_abs())
        } else {
            start.saturating_add(offset as u64)
        }
    })
}

/// Whether `window_ts` is one of the five accepted instants for `now`.
///
/// Set membership. Not `abs(now - window_ts) <= 60`.
pub fn is_accepted(now: u64, window_ts: u64) -> bool {
    accepted_buckets(now).contains(&window_ts)
}

/// The hash of the ordered argv byte strings.
///
/// SHA-256 over the canonical CBOR encoding of the array, so `["ab", "c"]` and
/// `["a", "bc"]` differ structurally rather than relying on a separator.
pub fn argv_hash(argv: &[Vec<u8>]) -> Result<[u8; ARGV_HASH_LEN], PopError> {
    let encoded = cbor::encode(&argv).map_err(|err| PopError::Encoding {
        cause: err.to_string(),
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&encoded);
    Ok(hasher.finalize().into())
}

/// The hash of an argv given as text.
pub fn argv_hash_of(argv: &[&str]) -> Result<[u8; ARGV_HASH_LEN], PopError> {
    let owned: Vec<Vec<u8>> = argv.iter().map(|arg| arg.as_bytes().to_vec()).collect();
    argv_hash(&owned)
}

/// What one proof of possession is about.
///
/// The fields are private and [`new`](Self::new) computes the argv hash from the
/// argv it is given, so a caller cannot present a hash that describes a different
/// command than the one the proof was made for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopPreimage {
    jti: String,
    record_version: RecordVersion,
    record_path: String,
    argv_hash: [u8; ARGV_HASH_LEN],
    window_ts: u64,
}

impl PopPreimage {
    /// Build the preimage for one invocation.
    pub fn new(
        jti: impl Into<String>,
        record_version: RecordVersion,
        record_path: impl Into<String>,
        argv: &[Vec<u8>],
        window_ts: u64,
    ) -> Result<Self, PopError> {
        Ok(Self {
            jti: jti.into(),
            record_version,
            record_path: record_path.into(),
            argv_hash: argv_hash(argv)?,
            window_ts,
        })
    }

    /// The delivery identifier this proof is bound to.
    pub fn jti(&self) -> &str {
        &self.jti
    }

    /// The record version this proof is bound to.
    pub fn record_version(&self) -> RecordVersion {
        self.record_version
    }

    /// The record path this proof is bound to.
    pub fn record_path(&self) -> &str {
        &self.record_path
    }

    /// The argv hash this proof is bound to.
    pub fn argv_hash(&self) -> &[u8; ARGV_HASH_LEN] {
        &self.argv_hash
    }

    /// The bucket start this proof names.
    pub fn window_ts(&self) -> u64 {
        self.window_ts
    }

    /// The exact bytes that are signed and verified.
    ///
    /// **One** function: the signing path and the verifying path both call this,
    /// so the order `[jti, record_version, record_path, argv_hash, window_ts]`
    /// exists in exactly one place.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, PopError> {
        // A tuple serializes as a CBOR array of its elements, in order.
        let body = cbor::encode(&(
            &self.jti,
            self.record_version,
            &self.record_path,
            self.argv_hash,
            self.window_ts,
        ))
        .map_err(|err| PopError::Encoding {
            cause: err.to_string(),
        })?;
        let mut preimage = Vec::with_capacity(DOMAIN_POP.len() + body.len());
        preimage.extend_from_slice(DOMAIN_POP);
        preimage.extend_from_slice(&body);
        Ok(preimage)
    }
}

/// Sign a proof of possession with the agent's own Ed25519 key.
pub fn sign_pop(
    signing: &SigningSecretKey,
    preimage: &PopPreimage,
) -> Result<TokenSignature, PopError> {
    Ok(signing.sign_bytes(&preimage.signing_bytes()?))
}

/// Verify a proof of possession against the agent's enrolled public key.
pub fn verify_pop(
    signing_public: &VerifyingPublicKey,
    preimage: &PopPreimage,
    signature: &TokenSignature,
) -> Result<(), PopError> {
    let bytes = preimage.signing_bytes()?;
    if signing_public.verify(&bytes, &signature.to_bytes()) {
        Ok(())
    } else {
        Err(PopError::Signature)
    }
}

/// Why a proof could not be built or checked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PopError {
    /// The preimage or the argv could not be canonically encoded.
    #[error("the proof of possession could not be encoded: {cause}")]
    Encoding {
        /// The encoder's reason.
        cause: String,
    },
    /// The signature did not verify against the enrolled key.
    #[error("the proof of possession did not verify against the enrolled agent key")]
    Signature,
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_accepted_set_is_the_five_buckets_and_not_a_duration() {
        // 89 and 90 straddle the bucket boundary: at 89 the bucket start is 60,
        // at 90 it is 90. The accepted instants move with it.
        assert_eq!(bucket_start(89), 60);
        assert_eq!(bucket_start(90), 90);
        assert_eq!(accepted_buckets(89), [60, 30, 90, 0, 120]);
        assert_eq!(accepted_buckets(90), [90, 60, 120, 30, 150]);

        // +90 from the bucket start is never accepted, though a symmetric
        // "within 60 seconds" test would have accepted it at some instants.
        assert!(!is_accepted(90, 180));
        assert!(!is_accepted(89, 150));
    }

    #[test]
    fn the_argv_hash_separates_a_concatenation_from_its_parts() {
        let first = argv_hash_of(&["ab", "c"]).unwrap();
        let second = argv_hash_of(&["a", "bc"]).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn the_argv_hash_notices_swapped_arguments() {
        let first = argv_hash_of(&["one", "two"]).unwrap();
        let second = argv_hash_of(&["two", "one"]).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn the_preimage_is_deterministic() {
        let argv = vec![b"child".to_vec(), b"--flag".to_vec()];
        let first = PopPreimage::new("j", RecordVersion(1), "p/a", &argv, 60).unwrap();
        let second = PopPreimage::new("j", RecordVersion(1), "p/a", &argv, 60).unwrap();
        assert_eq!(
            first.signing_bytes().unwrap(),
            second.signing_bytes().unwrap()
        );
    }
}
