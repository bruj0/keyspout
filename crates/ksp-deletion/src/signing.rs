//! The signing envelope shared by the three kinds of deletion evidence.
//!
//! Each kind has its own domain string and its own struct, and the domain is a
//! **signed field** rather than only a prefix. A signature is a value over
//! bytes, and bytes under a different prefix are a different message — but a
//! verifier that reconstructs the prefix itself cannot say *why* a foreign
//! signature failed. Carrying the domain inside the signed structure lets the
//! verifier distinguish "this is the wrong kind of evidence" from "this
//! signature is wrong", which is exactly the confusion this subsystem exists
//! to prevent.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ksp_types::cbor;

/// Why a signing or verification operation failed.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    /// The canonical encoding failed.
    #[error("evidence could not be encoded")]
    Encoding,
    /// The signature does not verify under the given key.
    #[error("the signature does not verify under the supplied key")]
    Signature,
    /// The 64-byte signature was malformed.
    #[error("the signature is not a valid 64-byte Ed25519 value")]
    MalformedSignature,
    /// The structure names a different evidence domain.
    #[error("expected the {expected} domain but the evidence names {found}")]
    Domain {
        /// The domain this verifier requires.
        expected: String,
        /// The domain the evidence carries.
        found: String,
    },
}

/// A 64-byte Ed25519 signature that survives serialization.
///
/// `serde` implements `Deserialize` for arrays only up to 32 bytes, so the
/// signature needs its own type rather than a bare `[u8; 64]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceSignature([u8; 64]);

impl EvidenceSignature {
    /// Wrap the raw bytes.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

impl serde::Serialize for EvidenceSignature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for EvidenceSignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <serde_bytes_like::Bytes>::deserialize(deserializer)?;
        let array: [u8; 64] = bytes
            .0
            .try_into()
            .map_err(|_| serde::de::Error::custom("an Ed25519 signature is 64 bytes"))?;
        Ok(Self(array))
    }
}

/// A `Vec<u8>` that deserializes from a CBOR byte string.
mod serde_bytes_like {
    use serde::de::{SeqAccess, Visitor};

    pub struct Bytes(pub Vec<u8>);

    impl<'de> serde::Deserialize<'de> for Bytes {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Bytes;

                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a byte string")
                }

                fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Bytes, E> {
                    Ok(Bytes(v.to_vec()))
                }

                fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Bytes, E> {
                    Ok(Bytes(v))
                }

                fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Bytes, A::Error> {
                    let mut out = Vec::new();
                    while let Some(byte) = seq.next_element::<u8>()? {
                        out.push(byte);
                    }
                    Ok(Bytes(out))
                }
            }
            deserializer.deserialize_bytes(V)
        }
    }
}

/// Build the bytes a signature covers: the domain, then the canonical encoding
/// of the structure that names it.
pub(crate) fn signing_preimage<T: serde::Serialize>(
    domain: &str,
    structure: &T,
) -> Result<Vec<u8>, EvidenceError> {
    let mut out = Vec::from(domain.as_bytes());
    out.extend(cbor::encode(structure).map_err(|_| EvidenceError::Encoding)?);
    Ok(out)
}

/// The signing half of an evidence envelope.
pub(crate) fn sign<T: serde::Serialize>(
    key: &SigningKey,
    domain: &str,
    structure: &T,
) -> Result<EvidenceSignature, EvidenceError> {
    let preimage = signing_preimage(domain, structure)?;
    Ok(EvidenceSignature::from_bytes(
        key.sign(&preimage).to_bytes(),
    ))
}

/// The verifying half of an evidence envelope.
///
/// Both the domain and the signature are checked. The domain is compared first
/// so a foreign signature is reported as foreign evidence rather than as a
/// generic failure — a caller that logs only "signature invalid" would lose the
/// distinction this subsystem is built to keep.
pub(crate) fn verify<T: serde::Serialize>(
    key: &VerifyingKey,
    domain: &str,
    structure: &T,
    carried_domain: &str,
    signature: &EvidenceSignature,
) -> Result<(), EvidenceError> {
    if carried_domain != domain {
        return Err(EvidenceError::Domain {
            expected: domain.to_owned(),
            found: carried_domain.to_owned(),
        });
    }
    let preimage = signing_preimage(carried_domain, structure)?;
    let parsed = Signature::from_bytes(&signature.0);
    key.verify_strict(&preimage, &parsed)
        .map_err(|_| EvidenceError::Signature)
}

/// A signing key for an actor.
///
/// Held only by the actor that signs its own evidence; nothing here can derive
/// another principal's key.
pub struct EvidenceSigningKey(SigningKey);

impl EvidenceSigningKey {
    /// Generate a key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        let key = Self(SigningKey::from_bytes(&bytes));
        zeroize::Zeroize::zeroize(&mut bytes);
        key
    }

    /// Adopt an existing 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    /// The public half, for a verifier to pin.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }

    /// Sign one of the evidence structures.
    pub(crate) fn key(&self) -> &SigningKey {
        &self.0
    }
}

impl std::fmt::Debug for EvidenceSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EvidenceSigningKey(<redacted>)")
    }
}
