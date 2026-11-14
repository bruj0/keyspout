//! The enrolment fingerprint — the only way a key becomes trusted.
//!
//! A fingerprint is a single digest over **five** things, and every one of them
//! is load-bearing:
//!
//! 1. the identity (the user or agent the keys belong to),
//! 2. the Ed25519 signing public key,
//! 3. the X25519 recipient public key,
//! 4. the signing key's ID,
//! 5. the recipient key's ID.
//!
//! Dropping any one of them yields a *different* fingerprint, which is what
//! closes Misfit Q: an attacker who pairs Alice's legitimate Ed25519 key with a
//! substituted X25519 key produces a fingerprint that does not match the one
//! Alice read out of band. The type system contributes the rest — the two key
//! types are distinct, so a substitution does not even compile
//! (see [`crate::enrolment`]).
//!
//! # Out-of-band, or it is not verification
//!
//! Verification means the user compares this digest against a value she
//! received through a channel separate from the store. The system never
//! "verifies" a fingerprint against a copy of the key it is verifying; that
//! would be Misfit H wearing a different hat.
//!
//! # Why the domain and version are inside the digest
//!
//! A future change to what is bound — a sixth field, a different digest — must
//! make old and new fingerprints *incomparable* rather than silently equal. The
//! domain string and the format version are therefore part of the preimage, so
//! a change is detectable from the value itself.

use ksp_types::ActorId;
use ksp_types::cbor;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The domain string of the enrolment fingerprint.
///
/// Domain separation keeps a fingerprint digest from being confused with any
/// other digest the system computes.
pub const FINGERPRINT_DOMAIN: &[u8] = b"keyspout-enrolment-fingerprint-v1";

/// The wire format version of the fingerprint.
///
/// Inside the digest, so an incompatible change is visible in the value rather
/// than only in a version field beside it.
pub const FINGERPRINT_VERSION: u16 = 1;

/// The length of a fingerprint digest.
pub const FINGERPRINT_LEN: usize = 32;

/// The identifier of one key.
///
/// A key ID is *not* a key: it names which key is meant, and it is bound into
/// the fingerprint so that swapping two keys' IDs is as detectable as swapping
/// the keys themselves.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeyId(String);

impl KeyId {
    /// Wrap an already-chosen key identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Everything a fingerprint binds, with nothing optional.
///
/// There is no constructor that omits a field, and the type is only ever built
/// after the enrolment record's own presence checks have passed (see
/// [`crate::enrolment::TrustStore::import`]). A caller cannot compute a
/// fingerprint over "most of" an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintSubject {
    /// The user or agent these keys belong to.
    pub identity: ActorId,
    /// The Ed25519 public key, as its 32-byte encoding.
    pub signing_key: [u8; 32],
    /// The X25519 public key, as its 32-byte encoding.
    pub recipient_key: [u8; 32],
    /// The ID that names the signing key.
    pub signing_key_id: KeyId,
    /// The ID that names the recipient key.
    pub recipient_key_id: KeyId,
}

/// The five bound fields, in declaration order.
///
/// A fixed-order struct rather than a map: `ksp_types::cbor` documents that a
/// map has no guaranteed byte representation, so every hashed structure is a
/// struct with a stable field order or an explicit array.
#[derive(Serialize)]
struct Preimage<'a> {
    version: u16,
    identity_kind: &'a str,
    identity_value: &'a str,
    signing_key: [u8; 32],
    recipient_key: [u8; 32],
    signing_key_id: &'a str,
    recipient_key_id: &'a str,
}

/// The digest that binds an identity to both of its keys and both key IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolmentFingerprint([u8; FINGERPRINT_LEN]);

impl EnrolmentFingerprint {
    /// Compute the fingerprint of a complete subject.
    pub fn compute(subject: &FingerprintSubject) -> Result<Self, FingerprintError> {
        let (identity_kind, identity_value) = identity_parts(&subject.identity);
        let preimage = Preimage {
            version: FINGERPRINT_VERSION,
            identity_kind,
            identity_value: &identity_value,
            signing_key: subject.signing_key,
            recipient_key: subject.recipient_key,
            signing_key_id: subject.signing_key_id.as_str(),
            recipient_key_id: subject.recipient_key_id.as_str(),
        };
        let body = cbor::encode(&preimage).map_err(|err| FingerprintError::Encoding {
            cause: err.to_string(),
        })?;

        let mut hasher = Sha256::new();
        hasher.update(FINGERPRINT_DOMAIN);
        // The domain is length-delimited from the body so that a domain string
        // that happens to be a prefix of another cannot collide with it.
        hasher.update((FINGERPRINT_DOMAIN.len() as u64).to_be_bytes());
        hasher.update(&body);

        let digest = hasher.finalize();
        let mut bytes = [0u8; FINGERPRINT_LEN];
        bytes.copy_from_slice(&digest);
        Ok(Self(bytes))
    }

    /// Compare two fingerprints in constant time.
    ///
    /// A byte-by-byte comparison that returns early leaks how many leading bytes
    /// matched, which is enough to reconstruct a digest one byte at a time when
    /// the attacker can see the timing.
    pub fn matches(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }

    /// The raw digest.
    pub fn as_bytes(&self) -> &[u8; FINGERPRINT_LEN] {
        &self.0
    }

    /// The digest as lowercase hex, for the user to read out of band.
    ///
    /// A fingerprint is public material — it is what the user compares — so
    /// rendering it is not a leak. No key material passes through this type.
    pub fn to_hex(&self) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(FINGERPRINT_LEN * 2);
        for byte in self.0 {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

impl std::fmt::Display for EnrolmentFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Why a fingerprint could not be computed.
#[derive(Debug, thiserror::Error)]
pub enum FingerprintError {
    /// The preimage could not be canonically encoded.
    #[error("the fingerprint preimage could not be encoded: {cause}")]
    Encoding {
        /// The encoder's reason.
        cause: String,
    },
}

/// The tag and value an identity contributes to the fingerprint.
///
/// The tag is part of the digest, so a user and an agent that share an
/// identifier string still produce different fingerprints.
fn identity_parts(identity: &ActorId) -> (&'static str, String) {
    match identity {
        ActorId::User(id) => ("user", id.to_string()),
        ActorId::Agent(id) => ("agent", id.to_string()),
        ActorId::Admin(id) => ("admin", id.to_string()),
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use ksp_types::{AgentId, PrincipalId};

    fn principal(uuid: &str) -> PrincipalId {
        PrincipalId::parse(uuid).unwrap()
    }

    fn subject() -> FingerprintSubject {
        FingerprintSubject {
            identity: ActorId::User(principal("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f")),
            signing_key: [0x11; 32],
            recipient_key: [0x22; 32],
            signing_key_id: KeyId::new("alice-ed25519"),
            recipient_key_id: KeyId::new("alice-x25519"),
        }
    }

    fn fingerprint_of(subject: &FingerprintSubject) -> EnrolmentFingerprint {
        EnrolmentFingerprint::compute(subject).expect("the preimage must encode")
    }

    #[test]
    fn the_same_subject_always_yields_the_same_fingerprint() {
        assert_eq!(fingerprint_of(&subject()), fingerprint_of(&subject()));
    }

    /// Each of the five bound fields must change the digest. A fingerprint that
    /// ignored one of them would still be a stable digest, so stability alone
    /// proves nothing.
    #[test]
    fn every_bound_field_changes_the_fingerprint() {
        let base = fingerprint_of(&subject());

        let signing_key = FingerprintSubject {
            signing_key: [0x99; 32],
            ..subject()
        };
        assert_ne!(
            fingerprint_of(&signing_key),
            base,
            "the signing key is not bound"
        );

        let recipient_key = FingerprintSubject {
            recipient_key: [0x99; 32],
            ..subject()
        };
        assert_ne!(
            fingerprint_of(&recipient_key),
            base,
            "the recipient key is not bound"
        );

        let signing_key_id = FingerprintSubject {
            signing_key_id: KeyId::new("other-ed25519"),
            ..subject()
        };
        assert_ne!(
            fingerprint_of(&signing_key_id),
            base,
            "the signing key ID is not bound"
        );

        let recipient_key_id = FingerprintSubject {
            recipient_key_id: KeyId::new("other-x25519"),
            ..subject()
        };
        assert_ne!(
            fingerprint_of(&recipient_key_id),
            base,
            "the recipient key ID is not bound"
        );

        let identity = FingerprintSubject {
            identity: ActorId::User(principal("b0b00000-0000-4000-8000-000000000002")),
            ..subject()
        };
        assert_ne!(fingerprint_of(&identity), base, "the identity is not bound");
    }

    /// A user and an agent sharing one principal UUID must not collide: the
    /// role tag is part of the digest.
    #[test]
    fn the_identity_kind_is_part_of_the_digest() {
        let same = principal("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f");
        let user = FingerprintSubject {
            identity: ActorId::User(same),
            ..subject()
        };
        let agent = FingerprintSubject {
            identity: ActorId::Agent(AgentId::new(same)),
            ..subject()
        };
        assert_ne!(fingerprint_of(&user), fingerprint_of(&agent));
    }

    /// Misfit Q, measured: swapping in a different recipient key while keeping
    /// the legitimate signing key and every ID produces a different fingerprint,
    /// so the out-of-band comparison fails.
    #[test]
    fn a_substituted_recipient_key_does_not_match_the_verified_fingerprint() {
        let verified = fingerprint_of(&subject());
        let substituted = fingerprint_of(&FingerprintSubject {
            recipient_key: [0xAB; 32],
            ..subject()
        });
        assert!(
            !verified.matches(&substituted),
            "a substituted X25519 key must not verify against the original fingerprint"
        );
    }

    #[test]
    fn matching_is_reported_for_equal_fingerprints() {
        let a = fingerprint_of(&subject());
        let b = fingerprint_of(&subject());
        assert!(a.matches(&b));
        assert_eq!(a, b);
    }

    #[test]
    fn the_fingerprint_renders_as_hex_for_the_out_of_band_comparison() {
        let fingerprint = fingerprint_of(&subject());
        let hex = fingerprint.to_hex();
        assert_eq!(hex.len(), FINGERPRINT_LEN * 2);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(fingerprint.to_string(), hex);
    }
}
