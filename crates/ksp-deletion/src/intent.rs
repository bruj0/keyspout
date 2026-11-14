//! The signed, key-free **deletion intent**.
//!
//! An intent is an *authorisation* to attempt cleanup of one exact version by a
//! deadline. It is not a tombstone and it is not a report: holding one proves
//! only that someone was permitted to try. The intent carries no key material,
//! because the store may hold it and the store must never learn a key.

use ed25519_dalek::VerifyingKey;
use ksp_types::domains::DOMAIN_DELETE_INTENT;
use ksp_types::evidence::DeletionIntent;
use serde::{Deserialize, Serialize};

use crate::signing::{EvidenceError, EvidenceSignature, EvidenceSigningKey, sign, verify};

/// The domain an intent signature is made under, as the string the structure
/// carries.
pub const INTENT_DOMAIN: &str = "keyspout-delete-intent-v1";

/// What the signature actually covers: the intent, the key ID that signed it,
/// and the domain.
#[derive(Serialize)]
struct IntentSubject<'a> {
    domain: &'a str,
    signer_key_id: &'a str,
    intent: &'a DeletionIntent,
}
/// A deletion intent with its issuer's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedIntent {
    /// The domain this signature was made under, carried so a verifier can
    /// name a foreign signature instead of guessing.
    pub domain: String,
    /// The key ID of the issuer that signed it.
    pub signer_key_id: String,
    /// The key-free authorisation.
    pub intent: DeletionIntent,
    /// The issuer's signature.
    pub signature: EvidenceSignature,
}

impl SignedIntent {
    /// Sign an intent. The issuer signs *before* any attempt, so the deadline
    /// exists before the store is touched.
    pub fn sign(
        issuer: &EvidenceSigningKey,
        signer_key_id: impl Into<String>,
        intent: DeletionIntent,
    ) -> Result<Self, EvidenceError> {
        let signer_key_id = signer_key_id.into();
        let subject = IntentSubject {
            domain: INTENT_DOMAIN,
            signer_key_id: &signer_key_id,
            intent: &intent,
        };
        let signature = sign(issuer.key(), INTENT_DOMAIN, &subject)?;
        Ok(Self {
            domain: INTENT_DOMAIN.to_owned(),
            signer_key_id,
            intent,
            signature,
        })
    }

    /// Verify the issuer's signature.
    ///
    /// `issuer` is the pinned key, never one taken from the structure.
    pub fn verify(&self, issuer: &VerifyingKey) -> Result<(), EvidenceError> {
        let subject = IntentSubject {
            domain: &self.domain,
            signer_key_id: &self.signer_key_id,
            intent: &self.intent,
        };
        verify(
            issuer,
            INTENT_DOMAIN,
            &subject,
            &self.domain,
            &self.signature,
        )
    }

    /// Verify the issuer's signature and keep the result.
    ///
    /// Returns an [`AuthorizedIntent`] rather than `()`, because every consumer
    /// that acts on an intent needs an authorisation it can name. Nothing else
    /// can produce one, so an operation cannot act on an intent that was never
    /// checked — and the actor list it consults is the issuer's, not the
    /// caller's.
    pub fn verify_as(&self, issuer: &VerifyingKey) -> Result<AuthorizedIntent, EvidenceError> {
        self.verify(issuer)?;
        Ok(AuthorizedIntent {
            intent: self.intent.clone(),
        })
    }

    /// The domain string this type is pinned to, so callers do not restate it.
    pub fn domain() -> &'static str {
        INTENT_DOMAIN
    }
}

/// An intent the issuer actually signed, and nothing else.
///
/// The field is private and there is no public constructor, so an operation that
/// needs authority has to hold a verified intent. A caller cannot present its own
/// actor list: the list it consults is the one inside the signed structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedIntent {
    intent: DeletionIntent,
}

impl AuthorizedIntent {
    /// The signed intent.
    pub fn intent(&self) -> &DeletionIntent {
        &self.intent
    }

    /// The intent's own identity, which retries reuse.
    pub fn intent_id(&self) -> &str {
        &self.intent.intent_id
    }

    /// The deadline the issuer set.
    pub fn deadline(&self) -> i64 {
        self.intent.deadline
    }

    /// Whether the issuer authorised `actor` to delete this version.
    pub fn authorizes(&self, actor: &ksp_types::ActorId) -> bool {
        self.intent.authorized_deleters.contains(actor)
    }

    /// Whether this intent is about exactly this version.
    pub fn covers(
        &self,
        level: &ksp_types::Level,
        secret_id: &ksp_types::OpaqueSecretId,
        version: u32,
    ) -> bool {
        &self.intent.level == level
            && &self.intent.secret_id == secret_id
            && self.intent.version == version
    }
}

/// The raw domain prefix S1 defines, for callers that need to build a preimage.
pub fn domain_prefix() -> &'static [u8] {
    DOMAIN_DELETE_INTENT
}
