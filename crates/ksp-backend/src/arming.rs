//! Durable Arming of key-free deletion intents with a stable Operation Identity.

use ed25519_dalek::{Signer, SigningKey};
use ksp_types::{DOMAIN_DELETE_INTENT, DeletionIntent};
use serde::{Deserialize, Serialize};

/// Storage durability actually acknowledged for this operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Durability {
    /// Directory and file synced to local storage.
    LocalSync,
    /// Local AOF fsync confirmed on the writing connection.
    LocalAofFsync,
    /// Service accepted an object write; remote retention remains unknown.
    RemoteAccepted,
}

/// A signed key-free request, serialized deterministically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmRecord {
    pub operation_identity: String,
    pub intent: DeletionIntent,
    pub signer_key_id: String,
    pub signature: Vec<u8>,
    /// How many deliveries this copy still permits, when the sharer bounded it.
    ///
    /// `None` is a time-bounded arm, which is what every record written before
    /// this field existed is: `#[serde(default)]` is what lets an older record
    /// decode instead of stranding an armed lease on an upgraded host.
    ///
    /// It lives here rather than in the record format because the arm record is
    /// already what the sweep reads to decide removal, and the record format has
    /// no version to add a field to.
    #[serde(default)]
    pub remaining_uses: Option<u32>,
}

impl ArmRecord {
    /// Sign intent fields, operation identity and the use bound.
    ///
    /// The counter is inside the preimage because a counter outside it could be
    /// *raised* by anyone who can write the journal, which would extend a copy's
    /// life — the opposite of what the bound is for. A planted record can only
    /// make the sweep attempt a removal the kernel refuses; a raised counter
    /// would make it never attempt one.
    ///
    /// `remaining_uses` is signed as it will be read, so a record whose counter
    /// is edited fails verification rather than silently outliving its bound.
    pub fn sign(
        operation_identity: String,
        intent: DeletionIntent,
        signer_key_id: String,
        remaining_uses: Option<u32>,
        signer: &SigningKey,
    ) -> Result<Self, ArmError> {
        if operation_identity.is_empty() || intent.intent_id.is_empty() {
            return Err(ArmError::InvalidIdentity);
        }
        let mut signed = Vec::from(DOMAIN_DELETE_INTENT);
        signed.extend(
            ksp_types::cbor::encode(&Self::preimage(
                &operation_identity,
                &intent,
                &signer_key_id,
                remaining_uses,
            ))
            .map_err(|_| ArmError::Encoding)?,
        );
        Ok(Self {
            operation_identity,
            intent,
            signer_key_id,
            signature: signer.sign(&signed).to_bytes().to_vec(),
            remaining_uses,
        })
    }

    /// The exact bytes a record's signature covers.
    ///
    /// One function, so the signer and any verifier cannot disagree about what
    /// was signed.
    fn preimage(
        operation_identity: &str,
        intent: &DeletionIntent,
        signer_key_id: &str,
        remaining_uses: Option<u32>,
    ) -> (String, DeletionIntent, String, Option<u32>) {
        (
            operation_identity.to_string(),
            intent.clone(),
            signer_key_id.to_string(),
            remaining_uses,
        )
    }

    /// Whether this record's signature covers its fields as they stand.
    ///
    /// A record written before the counter existed carries a signature over the
    /// three-field preimage, so a counter of `None` is verified against that
    /// shape and any other value is refused: an old record cannot claim a bound
    /// it never signed.
    pub fn verify(&self, signer: &ed25519_dalek::VerifyingKey) -> bool {
        let with_counter = {
            let mut signed = Vec::from(DOMAIN_DELETE_INTENT);
            let Ok(encoded) = ksp_types::cbor::encode(&Self::preimage(
                &self.operation_identity,
                &self.intent,
                &self.signer_key_id,
                self.remaining_uses,
            )) else {
                return false;
            };
            signed.extend(encoded);
            signed
        };
        if signer
            .verify_strict(
                &with_counter,
                &ed25519_dalek::Signature::from_slice(&self.signature)
                    .unwrap_or(ed25519_dalek::Signature::from_bytes(&[0; 64])),
            )
            .is_ok()
        {
            return true;
        }
        // The legacy shape: three fields, and only valid when no bound is claimed.
        if self.remaining_uses.is_some() {
            return false;
        }
        let mut legacy = Vec::from(DOMAIN_DELETE_INTENT);
        let Ok(encoded) = ksp_types::cbor::encode(&(
            self.operation_identity.as_str(),
            &self.intent,
            self.signer_key_id.as_str(),
        )) else {
            return false;
        };
        legacy.extend(encoded);
        signer
            .verify_strict(
                &legacy,
                &ed25519_dalek::Signature::from_slice(&self.signature)
                    .unwrap_or(ed25519_dalek::Signature::from_bytes(&[0; 64])),
            )
            .is_ok()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ArmError> {
        ksp_types::cbor::encode(self).map_err(|_| ArmError::Encoding)
    }

    /// Read a record this host wrote.
    ///
    /// Decoded, not verified, and with the journal shared that needs the argument
    /// stated rather than assumed. `store/intents/` is `1770` on the store's group
    /// and sticky, so any principal in that group can plant a record — and the
    /// same principal can already unlink a version in an `agent-<id>` level, which
    /// is `0730` on that group; a `user` level is `0700` and its owner's, so the
    /// sweep cannot reach one. A planted record can therefore make the sweep
    /// *attempt* a removal the kernel refuses, and no more: the intent's own
    /// `authorized_deleters` bounds the actor the sweep acts as, and the report it
    /// writes is signed by that actor, so a fabricated sweep leaves evidence
    /// naming it. The signature here is for the operator, not a gate.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArmError> {
        let record: Self = ksp_types::cbor::decode(bytes).map_err(|_| ArmError::Encoding)?;
        if record.operation_identity.is_empty() || record.intent.intent_id.is_empty() {
            return Err(ArmError::InvalidIdentity);
        }
        Ok(record)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmingAcknowledgement {
    pub operation_identity: String,
    pub intent_id: String,
    pub version: u32,
    pub deadline: i64,
    pub durability: Durability,
}

#[derive(Debug, thiserror::Error)]
pub enum ArmError {
    #[error("invalid operation or intent identity")]
    InvalidIdentity,
    #[error("failed to serialize a key-free deletion intent")]
    Encoding,
    #[error("arming is uncertain; do not publish a token")]
    Uncertain,
    #[error("the operation identity already belongs to different intent bytes")]
    IdentityConflict,
    #[error("the selected Blob Store cannot durably arm this lease")]
    Unsupported,
}

/// Atomic write plus durability confirmation; retries must not extend expiry.
pub trait ArmingStore {
    fn arm_once(
        &self,
        operation_identity: &str,
        bytes: &[u8],
        deadline: i64,
    ) -> Result<Durability, ArmError>;
    fn read_arm(&self, operation_identity: &str) -> Result<Option<Vec<u8>>, ArmError>;

    /// Every arm record this host wrote, as the bytes it wrote.
    ///
    /// A sweep cannot name an operation identity in advance, so it needs the set
    /// rather than one record. The default reports `Unsupported` rather than an
    /// empty list: "this store cannot enumerate" and "nothing was armed" are
    /// different facts, and only the second may be reported as a clear sweep.
    fn list_arms(&self) -> Result<Vec<(String, Vec<u8>)>, ArmError> {
        Err(ArmError::Unsupported)
    }

    /// How many deliveries the arm still permits, when it was bounded.
    ///
    /// Separate from the record because the record is create-only: an identity is
    /// an idempotency key, so rewriting it would let a retry replace the lease it
    /// was meant to repeat. The record states the bound; this reports what is
    /// left of it.
    ///
    /// The default is `None`, which is an unbounded arm: a store that does not
    /// implement this is one whose arms are time-bounded only, and reporting a
    /// bound it cannot see would invent one.
    fn remaining_uses(&self, operation_identity: &str) -> Option<u32> {
        let _ = operation_identity;
        None
    }
}

/// Reconcile the same signed intent after uncertain acknowledgement.
/// The same signature and bytes must be reused, rather than re-signing.
pub fn arm_intent(
    store: &dyn ArmingStore,
    record: &ArmRecord,
) -> Result<ArmingAcknowledgement, ArmError> {
    let bytes = record.to_bytes()?;
    let durability = store.arm_once(&record.operation_identity, &bytes, record.intent.deadline)?;
    let stored = store.read_arm(&record.operation_identity)?;
    if stored.as_deref() != Some(bytes.as_slice()) {
        return Err(ArmError::Uncertain);
    }
    Ok(ArmingAcknowledgement {
        operation_identity: record.operation_identity.clone(),
        intent_id: record.intent.intent_id.clone(),
        version: record.intent.version,
        deadline: record.intent.deadline,
        durability,
    })
}
