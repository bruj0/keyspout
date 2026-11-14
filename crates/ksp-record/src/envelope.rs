//! The record envelope: the HPKE ciphertext that seals a content key.
//!
//! The envelope's associated data is the *same* canonical bound metadata
//! that the content blob authenticates. One binding, two consumers — a
//! second, looser binding would reintroduce the record-swap misfit.

use ksp_types::{BoundMetadata, ContentKey, HPKE_INFO_RECORD};

use crate::blob::ContentBlob;
use crate::kem::{self, KemError};

/// The canonical associated data for a bound metadata.
///
/// This delegates to [`BoundMetadata::bound_aad`], which is the single
/// function that produces the bound bytes. The content blob and the record
/// envelope both call it, so the two can never drift apart.
pub fn bound_aad(metadata: &BoundMetadata) -> Result<Vec<u8>, ksp_types::cbor::CborError> {
    metadata.bound_aad()
}

/// The HPKE envelope sealing a content key to one recipient key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEnvelope {
    /// The HPKE encapsulated secret.
    enc: Vec<u8>,
    /// The HPKE ciphertext holding the sealed content key.
    ciphertext: Vec<u8>,
}

impl RecordEnvelope {
    /// Seal a content key to a recipient's X25519 public key.
    ///
    /// The `info` label is the record label, and the associated data is
    /// the canonical bound metadata. A low-order recipient key produces the
    /// typed error and **no envelope** (FR-004).
    pub fn seal(
        content_key: &ContentKey,
        recipient_x25519: &[u8; 32],
        metadata: &BoundMetadata,
    ) -> Result<Self, KemError> {
        let aad = bound_aad(metadata).map_err(|e| KemError::BindingFailed(e.to_string()))?;

        let (enc, ciphertext) =
            kem::seal_content_key(recipient_x25519, HPKE_INFO_RECORD, &aad, content_key)?;

        Ok(Self { enc, ciphertext })
    }

    /// Open a sealed content key with the recipient's X25519 private key.
    pub fn open(
        &self,
        recipient_x25519_sk: &[u8; 32],
        metadata: &BoundMetadata,
    ) -> Result<ContentKey, KemError> {
        let aad = bound_aad(metadata).map_err(|e| KemError::BindingFailed(e.to_string()))?;

        kem::open_content_key(
            recipient_x25519_sk,
            &self.enc,
            HPKE_INFO_RECORD,
            &aad,
            &self.ciphertext,
        )
    }

    /// The encapsulated secret.
    pub fn enc(&self) -> &[u8] {
        &self.enc
    }

    /// The HPKE ciphertext.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The full serialized envelope: the encapsulated secret followed by the
    /// ciphertext.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.enc.len() + self.ciphertext.len());
        out.extend_from_slice(&self.enc);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse an envelope from its serialized form.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KemError> {
        if bytes.len() < kem::ENCAPSULATED_SECRET_LEN {
            return Err(KemError::Provider(hpke_rs::HpkeError::InvalidInput));
        }
        Ok(Self {
            enc: bytes[..kem::ENCAPSULATED_SECRET_LEN].to_vec(),
            ciphertext: bytes[kem::ENCAPSULATED_SECRET_LEN..].to_vec(),
        })
    }
}

/// A complete stored record: the content blob, the record envelope, and the
/// bound metadata that names it.
///
/// The record is immutable. The *version* is the unit a lease deletes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The bound metadata naming this record version.
    pub metadata: BoundMetadata,
    /// The AEAD ciphertext over the name and the value.
    pub blob: ContentBlob,
    /// The HPKE envelope sealing the content key.
    pub envelope: RecordEnvelope,
}

impl Record {
    /// The location of this record version.
    pub fn record_path(&self) -> crate::path::RecordPath {
        crate::path::RecordPath::of(&self.metadata)
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is
    // what says why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use ksp_types::{Level, OpaqueSecretId, PrincipalId, VaultId};

    fn metadata(version: u32) -> BoundMetadata {
        BoundMetadata {
            vault_id: VaultId::new("v-1"),
            user_id: PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
            level: Level::User,
            secret_id: OpaqueSecretId::new("s-1"),
            version,
        }
    }

    fn key_pair() -> ([u8; 32], [u8; 32]) {
        let mut sk = [0u8; 32];
        let mut pk = [0u8; 32];
        rand::fill(&mut sk);
        rand::fill(&mut pk);
        // A real X25519 public key is derived from the private key, so use
        // the provider to produce a valid pair.
        let derived = kem::public_key_for(&sk).unwrap();
        pk.copy_from_slice(&derived);
        (sk, pk)
    }

    #[test]
    fn the_envelope_round_trips_the_content_key() {
        let (sk, pk) = key_pair();
        let meta = metadata(1);
        let content_key = ContentKey::generate();

        let envelope = RecordEnvelope::seal(&content_key, &pk, &meta).unwrap();
        let opened = envelope.open(&sk, &meta).unwrap();
        assert_eq!(opened.as_bytes(), content_key.as_bytes());
    }

    #[test]
    fn an_envelope_relocated_to_another_version_fails_to_open() {
        let (sk, pk) = key_pair();
        let content_key = ContentKey::generate();

        let envelope = RecordEnvelope::seal(&content_key, &pk, &metadata(1)).unwrap();
        let result = envelope.open(&sk, &metadata(2));

        assert!(
            result.is_err(),
            "a relocated envelope must not open under another version's bound metadata"
        );
    }

    #[test]
    fn an_envelope_relocated_to_another_secret_fails_to_open() {
        let (sk, pk) = key_pair();
        let content_key = ContentKey::generate();

        let mut other = metadata(1);
        other.secret_id = OpaqueSecretId::new("s-2");

        let envelope = RecordEnvelope::seal(&content_key, &pk, &metadata(1)).unwrap();
        assert!(envelope.open(&sk, &other).is_err());
    }

    #[test]
    fn a_rewritten_principal_segment_fails_aad_verification() {
        // Misfit J: a rename that silently succeeded would let a record be
        // moved between principals or levels. The path segment is bound into
        // the AAD, so rewriting it without a re-seal must fail to open.
        let (sk, pk) = key_pair();
        let meta = metadata(1);
        let content_key = ContentKey::generate();
        let aad = bound_aad(&meta).unwrap();
        let envelope = RecordEnvelope::seal(&content_key, &pk, &meta).unwrap();
        let blob = ContentBlob::seal(&content_key, b"name", b"value", &aad).unwrap();

        let mut moved = meta.clone();
        moved.user_id = PrincipalId::parse("8a0e2d4c-1b3f-4a5e-9c7d-0e1f2a3b4c5d").unwrap();

        // The paths differ...
        assert_ne!(
            crate::path::RecordPath::of(&meta).as_str(),
            crate::path::RecordPath::of(&moved).as_str()
        );
        // ...and the bytes cannot be read under the new path's metadata.
        let moved_aad = bound_aad(&moved).unwrap();
        assert!(envelope.open(&sk, &moved).is_err());
        assert!(blob.open(&content_key, &moved_aad).is_err());
    }

    #[test]
    fn a_rewritten_agent_level_fails_aad_verification() {
        // The level is a path segment too. Moving a record from one agent's
        // level to another's is the same refusal.
        let (sk, pk) = key_pair();
        let owner = metadata(1);
        let content_key = ContentKey::generate();
        let envelope = RecordEnvelope::seal(&content_key, &pk, &owner).unwrap();

        let mut moved = owner.clone();
        moved.level = Level::Agent(ksp_types::AgentId::new(
            PrincipalId::parse("00000000-0000-4000-8000-000000000007").unwrap(),
        ));

        assert!(envelope.open(&sk, &moved).is_err());
    }

    #[test]
    fn the_bound_aad_is_the_same_for_the_blob_and_the_envelope() {
        // The whole point of the single binding: one function, two
        // consumers. If these ever differ, the record-swap misfit returns.
        let meta = metadata(1);
        let aad = bound_aad(&meta).unwrap();

        let content_key = ContentKey::generate();
        let blob = ContentBlob::seal(&content_key, b"name", b"value", &aad).unwrap();

        // The blob opens with exactly the AAD the envelope used.
        let (name, value) = blob.open(&content_key, &aad).unwrap();
        assert_eq!(name, b"name");
        assert_eq!(value, b"value");
    }

    #[test]
    fn a_low_order_recipient_key_produces_no_envelope() {
        let meta = metadata(1);
        let content_key = ContentKey::generate();
        let result = RecordEnvelope::seal(&content_key, &[0u8; 32], &meta);
        assert!(result.is_err());
    }

    #[test]
    fn the_envelope_round_trips_through_its_serialized_form() {
        let (sk, pk) = key_pair();
        let meta = metadata(1);
        let content_key = ContentKey::generate();

        let envelope = RecordEnvelope::seal(&content_key, &pk, &meta).unwrap();
        let parsed = RecordEnvelope::from_bytes(&envelope.to_bytes()).unwrap();
        let opened = parsed.open(&sk, &meta).unwrap();
        assert_eq!(opened.as_bytes(), content_key.as_bytes());
    }
}
