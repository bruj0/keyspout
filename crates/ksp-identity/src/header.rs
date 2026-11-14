//! The delivery header.
//!
//! The header is the fixed-order description of *one* delivery, and it is the
//! associated data of the HPKE envelope. Everything a verifier needs to decide
//! whether a delivery is the one it was promised lives here, so that a field the
//! envelope does not bind cannot be changed without the decryption failing.
//!
//! # Why both keys and both key IDs
//!
//! FR-022 lists the vault, the user, the issuer, the agent identity, **both**
//! agent public keys and **both** agent key IDs, the level, the opaque scope and
//! paths, the exact record versions, the expiry and the `jti`. Binding all four
//! key values is what closes Misfit Q: a header that named only the recipient key
//! would let an attacker pair the legitimate agent's Ed25519 key with a
//! substituted X25519 key, and the header would still look right.
//!
//! # Not a map
//!
//! This is a fixed-order struct, so `ksp_types::cbor` encodes it as a CBOR map
//! whose key order is the *declaration* order rather than an encoder's runtime
//! choice. Reordering two fields changes the AAD and the signature preimage, and
//! a golden fixture pins that.
//!
//! # The header names a key, never holds one
//!
//! Only public keys and key IDs appear. There is no field here that could carry
//! a private key or a content key, which is the first half of Misfit B; the
//! second half is that the content keys live only inside the envelope.

use ksp_types::{
    AgentId, BoundMetadata, Level, OpaqueSecretId, PrincipalId, RecordVersion, VaultId, cbor,
};
use serde::{Deserialize, Serialize};

use crate::enrolment::{RecipientPublicKey, VerifyingPublicKey};
use crate::fingerprint::KeyId;

/// The wire format version of a delivery header.
/// The header format this build writes.
///
/// Bumped to 2 when `source_level` was added. A token from an older build is
/// refused by `delivery::verify` with `UnsupportedVersion`, which is the
/// intended path: the source level cannot be inferred, and a token that does not
/// say where its value came from cannot be checked against a policy.
pub const HEADER_VERSION: u16 = 2;

/// One record version a delivery names.
///
/// A delivery binds an *exact* version, never "the current one": the version is
/// the unit a lease deletes, and a token that said "latest" would authorise
/// whatever happened to be there when it was used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectedRecord {
    /// The opaque secret identifier the record lives under.
    ///
    /// The canonical type, not a `String`: this value is interpolated into a
    /// record path, so a free-form string could name a different level.
    pub secret: OpaqueSecretId,
    /// The exact version.
    pub version: RecordVersion,
}

/// Everything one delivery binds.
///
/// The fields are private and the only constructor is [`DeliveryHeader::new`],
/// which fills the version and rejects an empty selection, so a caller cannot
/// sign a header that names no record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryHeader {
    version: u16,
    vault: VaultId,
    user: PrincipalId,
    issuer_key_id: KeyId,
    agent: AgentId,
    agent_signing_key: VerifyingPublicKey,
    agent_recipient_key: RecipientPublicKey,
    agent_signing_key_id: KeyId,
    agent_recipient_key_id: KeyId,
    level: Level,
    /// The level the value was **read from**, which is its provenance.
    ///
    /// `Admin` means the admin wrote and delegated the value, so a delivery of
    /// it needs a policy that grants the pair. `User` means the user owns it, and
    /// the user's own signature is the authority. A run cannot infer this from
    /// the target path, which names the agent level the copy was written at.
    source_level: Level,
    scope: String,
    records: Vec<SelectedRecord>,
    expires_at: u64,
    jti: String,
}

impl DeliveryHeader {
    /// Build a header for one delivery.
    ///
    /// `records` is the *selected* set: a token scoped to one version must not
    /// name another, so an empty selection is refused rather than signed.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault: VaultId,
        user: PrincipalId,
        issuer_key_id: KeyId,
        agent: AgentId,
        agent_signing_key: VerifyingPublicKey,
        agent_recipient_key: RecipientPublicKey,
        agent_signing_key_id: KeyId,
        agent_recipient_key_id: KeyId,
        level: Level,
        source_level: Level,
        scope: String,
        records: Vec<SelectedRecord>,
        expires_at: u64,
        jti: String,
    ) -> Result<Self, HeaderError> {
        Self::check_invariants(&records, &jti)?;
        Ok(Self {
            version: HEADER_VERSION,
            vault,
            user,
            issuer_key_id,
            agent,
            agent_signing_key,
            agent_recipient_key,
            agent_signing_key_id,
            agent_recipient_key_id,
            level,
            source_level,
            scope,
            records,
            expires_at,
            jti,
        })
    }

    /// The invariants a header must satisfy, checked wherever one is built or
    /// decoded.
    ///
    /// `Deserialize` is derived, so a decoded header bypasses [`new`](Self::new).
    /// Validating here as well is what keeps a hostile artifact from carrying a
    /// header that names no record.
    fn check_invariants(records: &[SelectedRecord], jti: &str) -> Result<(), HeaderError> {
        if records.is_empty() {
            return Err(HeaderError::NoRecords);
        }
        if jti.is_empty() {
            return Err(HeaderError::EmptyJti);
        }
        // A repeated *record* is an error; two different secrets at the same
        // version number are ordinary, because the version chain is per record
        // path.
        let mut seen: Vec<&SelectedRecord> = Vec::with_capacity(records.len());
        for record in records {
            if seen.contains(&record) {
                return Err(HeaderError::DuplicateRecord {
                    secret: record.secret.as_str().to_string(),
                    version: record.version.get(),
                });
            }
            let secret = record.secret.as_str();
            if secret.is_empty() || secret.contains('/') {
                return Err(HeaderError::InvalidSecretId {
                    secret: secret.to_string(),
                });
            }
            seen.push(record);
        }
        Ok(())
    }

    /// Re-check the invariants on a header that arrived by decoding.
    pub fn validate(&self) -> Result<(), HeaderError> {
        Self::check_invariants(&self.records, &self.jti)
    }

    /// The format version.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// The vault the delivery belongs to.
    pub fn vault(&self) -> &VaultId {
        &self.vault
    }

    /// The user whose authority is being exercised.
    pub fn user(&self) -> &PrincipalId {
        &self.user
    }

    /// The ID of the issuer key that signs this delivery.
    ///
    /// An ID, not a key: a verifier looks it up in the anchors it pinned.
    pub fn issuer_key_id(&self) -> &KeyId {
        &self.issuer_key_id
    }

    /// The agent the delivery is for.
    pub fn agent(&self) -> &AgentId {
        &self.agent
    }

    /// The agent's Ed25519 public key.
    pub fn agent_signing_key(&self) -> &VerifyingPublicKey {
        &self.agent_signing_key
    }

    /// The agent's X25519 public key — the key the envelope is sealed to.
    pub fn agent_recipient_key(&self) -> &RecipientPublicKey {
        &self.agent_recipient_key
    }

    /// The ID naming the agent's signing key.
    pub fn agent_signing_key_id(&self) -> &KeyId {
        &self.agent_signing_key_id
    }

    /// The ID naming the agent's recipient key.
    pub fn agent_recipient_key_id(&self) -> &KeyId {
        &self.agent_recipient_key_id
    }

    /// The level the copy is written at.
    pub fn level(&self) -> &Level {
        &self.level
    }

    /// The opaque scope the delivery claims.
    /// The level the delivered value was read from.
    ///
    /// This is the record's provenance, and it decides whether a run needs a
    /// policy: `Admin` does, `User` does not.
    pub fn source_level(&self) -> &Level {
        &self.source_level
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The record versions the delivery names.
    pub fn records(&self) -> &[SelectedRecord] {
        &self.records
    }

    /// When the delivery stops being valid.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// The delivery's unique identifier.
    ///
    /// Opaque and unique per delivery. It is *not* a nonce with exactly-once
    /// semantics: a proof of possession in the accepted window may be replayed,
    /// and nothing here claims otherwise.
    pub fn jti(&self) -> &str {
        &self.jti
    }

    /// The canonical bytes of this header.
    ///
    /// This is the envelope's associated data, so a change to any field above —
    /// scope, expiry, the selected versions, either key or either key ID — is an
    /// AAD mismatch rather than a silently accepted substitution.
    pub fn canonical(&self) -> Result<Vec<u8>, HeaderError> {
        cbor::encode(self).map_err(|err| HeaderError::Encoding {
            cause: err.to_string(),
        })
    }

    /// The record path this header's level, secret and version produce.
    ///
    /// Built here rather than accepted as a header field, so the path a
    /// consumer checks cannot disagree with the level and version the same
    /// header states.
    pub fn record_path(&self, record: &SelectedRecord) -> String {
        // Built from the same five-tuple the record is bound to, through the
        // one path definition in `ksp-record`. A second formatter here would
        // be a second layout.
        ksp_record::RecordPath::of(&BoundMetadata {
            vault_id: self.vault.clone(),
            user_id: self.user,
            level: self.level.clone(),
            secret_id: record.secret.clone(),
            version: record.version.get(),
        })
        .to_string()
    }
}

/// Why a header could not be built or encoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    /// The header names no record.
    #[error("a delivery header must name at least one record version")]
    NoRecords,
    /// The header carries no delivery identifier.
    #[error("a delivery header must carry a jti")]
    EmptyJti,
    /// The header names the same record twice.
    #[error("the header names {secret} at version {version} more than once")]
    DuplicateRecord {
        /// The repeated secret identifier.
        secret: String,
        /// The repeated version.
        version: u32,
    },
    /// A selected secret identifier is unusable as a path segment.
    #[error("secret identifier {secret:?} is empty or contains a path separator")]
    InvalidSecretId {
        /// The offending value.
        secret: String,
    },
    /// The header could not be canonically encoded.
    #[error("the delivery header could not be encoded: {cause}")]
    Encoding {
        /// The encoder's reason.
        cause: String,
    },
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn header() -> DeliveryHeader {
        DeliveryHeader::new(
            VaultId::new("v-1"),
            PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
            KeyId::new("admin-1"),
            AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap(),
            VerifyingPublicKey::from_bytes([1u8; 32]).unwrap(),
            RecipientPublicKey::from_bytes([2u8; 32]),
            KeyId::new("agent-7-ed"),
            KeyId::new("agent-7-x"),
            Level::Agent(AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap()),
            Level::User,
            "agent-00000000-0000-4000-8000-000000000007".to_string(),
            vec![SelectedRecord {
                secret: OpaqueSecretId::new("s-1"),
                version: RecordVersion(3),
            }],
            500,
            "jti-1".to_string(),
        )
        .unwrap()
    }

    #[test]
    fn a_header_with_no_records_is_refused() {
        let result = DeliveryHeader::new(
            VaultId::new("v-1"),
            PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
            KeyId::new("admin-1"),
            AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap(),
            VerifyingPublicKey::from_bytes([1u8; 32]).unwrap(),
            RecipientPublicKey::from_bytes([2u8; 32]),
            KeyId::new("agent-7-ed"),
            KeyId::new("agent-7-x"),
            Level::Agent(AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap()),
            Level::User,
            "agent-00000000-0000-4000-8000-000000000007".to_string(),
            vec![],
            500,
            "jti-1".to_string(),
        );
        assert_eq!(result.unwrap_err(), HeaderError::NoRecords);
    }

    #[test]
    fn a_header_without_a_jti_is_refused() {
        let mut result = header();
        result.jti = String::new();
        // The constructor is the only gate, so the check is asserted by
        // rebuilding rather than by mutating a valid header.
        assert_eq!(
            DeliveryHeader::new(
                result.vault.clone(),
                result.user,
                result.issuer_key_id.clone(),
                result.agent,
                result.agent_signing_key,
                result.agent_recipient_key,
                result.agent_signing_key_id.clone(),
                result.agent_recipient_key_id.clone(),
                result.level.clone(),
                result.source_level().clone(),
                result.scope.clone(),
                result.records.clone(),
                result.expires_at,
                String::new(),
            )
            .unwrap_err(),
            HeaderError::EmptyJti
        );
    }

    #[test]
    fn the_record_path_is_built_from_the_header_s_own_level_and_version() {
        let header = header();
        assert_eq!(
            header.record_path(&header.records()[0]),
            "p/v-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-00000000-0000-4000-8000-000000000007/s-1/3".to_string()
        );
    }

    #[test]
    fn the_header_is_encoded_deterministically() {
        let first = header().canonical().unwrap();
        let second = header().canonical().unwrap();
        assert_eq!(first, second);
    }
}
