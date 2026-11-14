//! The Ed25519 signature type shared by every signed structure.
//!
//! One type rather than one per structure: the enrolment record and the policy
//! both carry a 64-byte Ed25519 signature, and a second copy of the length
//! check below would be a second place for the check to drift.

use serde::{Deserialize, Serialize};

/// The number of bytes in an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// An Ed25519 signature over a signed structure.
///
/// Its own type because `serde` implements `Deserialize` for arrays only up to
/// 32 elements, and because a signature that silently arrived with the wrong
/// length is a refusal, not a truncated value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Signature([u8; SIGNATURE_LEN]);

impl Ed25519Signature {
    /// The raw signature bytes.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0
    }

    /// Wrap bytes that are already known to be a signature.
    pub fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }
}

impl Serialize for Ed25519Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Ed25519Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SignatureVisitor;

        impl<'de> serde::de::Visitor<'de> for SignatureVisitor {
            type Value = Ed25519Signature;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a {SIGNATURE_LEN}-byte Ed25519 signature")
            }

            fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                let bytes: [u8; SIGNATURE_LEN] = value
                    .try_into()
                    .map_err(|_| E::invalid_length(value.len(), &"a 64-byte Ed25519 signature"))?;
                Ok(Ed25519Signature(bytes))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut bytes = [0u8; SIGNATURE_LEN];
                for (index, slot) in bytes.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }
                Ok(Ed25519Signature(bytes))
            }
        }

        deserializer.deserialize_bytes(SignatureVisitor)
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_signature_round_trips_through_json() {
        let signature = Ed25519Signature::from_bytes([9u8; SIGNATURE_LEN]);
        let bytes = serde_json::to_vec(&signature).unwrap();
        let back: Ed25519Signature = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, signature);
    }

    #[test]
    fn a_short_signature_is_refused_rather_than_padded() {
        let short = serde_json::json!([1u8, 2, 3]);
        assert!(serde_json::from_value::<Ed25519Signature>(short).is_err());
    }
}
