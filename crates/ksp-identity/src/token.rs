//! The issuer's signature over a delivery, and the domain separation that makes
//! it non-interchangeable with any other signed structure.
//!
//! # The misfit this resolves
//!
//! Misfit M: a signer or verifier that omits protocol-specific domain separation
//! lets signed bytes be reused in another context. A proof-of-possession
//! signature captured from one compliant invocation could be presented as a
//! token signature, and a verifier that only checked "does this signature verify
//! over these bytes" would accept it.
//!
//! The fix is that the domain prefix is part of the preimage, and the preimage is
//! built in exactly one place. Verification recomputes it from the header and the
//! envelope it was given; it never takes the preimage on trust.
//!
//! # What the signature covers
//!
//! `keyspout-token-v1 || CBOR([header, envelope])` — the header and the sealed
//! envelope, as a two-element CBOR **array**. An array rather than a struct
//! because the two elements have different types and the order is the meaning:
//! the header first, the envelope second.
//!
//! The signature does **not** cover itself, and it is not stored inside the thing
//! it signs. A verifier therefore rebuilds the preimage from the parts, which is
//! what makes a signature lifted from another artifact useless.

use ksp_types::{
    DOMAIN_ABSENCE_OBSERVATION, DOMAIN_DELETE_INTENT, DOMAIN_DELETE_REPORT, DOMAIN_POP,
    DOMAIN_TOKEN, cbor,
};
use serde::Serialize;

use crate::enrolment::{SigningSecretKey, VerifyingPublicKey};
use crate::header::DeliveryHeader;

/// A signature over a delivery.
///
/// An alias for the crate's existing length-checked 64-byte Ed25519 type rather
/// than a second newtype: a duplicate would be a second place for the length
/// check to drift, and the underlying type is already the one this branch has.
pub type TokenSignature = crate::enrolment::EnrolmentSignature;

/// The sealed envelope a token carries.
///
/// A fixed-order struct rather than one byte blob: the HPKE output is an
/// encapsulated secret *and* a ciphertext, and concatenating them would need a
/// length prefix that could drift out of step with the encoding. Nesting them as
/// two fields of one CBOR structure keeps the artifact a single document and
/// makes the split unambiguous.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct DeliveryEnvelope {
    enc: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl DeliveryEnvelope {
    /// Collect a sealed envelope from the HPKE output.
    pub fn new(enc: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self { enc, ciphertext }
    }

    /// The encapsulated secret.
    pub fn enc(&self) -> &[u8] {
        &self.enc
    }

    /// The sealed content-key map.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// The exact bytes the issuer signs.
///
/// One function, so the signing path and the verifying path cannot disagree
/// about what was signed.
pub fn token_preimage(
    header: &DeliveryHeader,
    envelope: &DeliveryEnvelope,
) -> Result<Vec<u8>, TokenError> {
    // A Rust tuple serializes as a CBOR array of its elements, in order. The
    // two elements have different types, so a homogeneous `encode_array` call
    // would not express them.
    let body = cbor::encode(&(header, envelope)).map_err(|err| TokenError::Encoding {
        cause: err.to_string(),
    })?;
    let mut preimage = Vec::with_capacity(DOMAIN_TOKEN.len() + body.len());
    preimage.extend_from_slice(DOMAIN_TOKEN);
    preimage.extend_from_slice(&body);
    Ok(preimage)
}

/// Sign a delivery with the issuer's key.
pub fn sign_delivery(
    signer: &SigningSecretKey,
    header: &DeliveryHeader,
    envelope: &DeliveryEnvelope,
) -> Result<TokenSignature, TokenError> {
    let preimage = token_preimage(header, envelope)?;
    Ok(signer.sign_bytes(&preimage))
}

/// The domains this crate signs under.
///
/// An enum rather than a `&[u8]`: the set of domains is the crate's, not the
/// caller's. A raw byte slice would let a caller invent a domain and would make
/// it untrue that the admin key signs only the structures the design lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// The issuer's signature over a delivery.
    Token,
    /// A proof of possession.
    Pop,
    /// A deletion intent.
    DeleteIntent,
    /// A deletion report.
    DeleteReport,
    /// An absence observation.
    AbsenceObservation,
}

impl Domain {
    /// The versioned domain string, as `ksp_types` defines it.
    pub fn bytes(self) -> &'static [u8] {
        match self {
            Self::Token => DOMAIN_TOKEN,
            Self::Pop => DOMAIN_POP,
            Self::DeleteIntent => DOMAIN_DELETE_INTENT,
            Self::DeleteReport => DOMAIN_DELETE_REPORT,
            Self::AbsenceObservation => DOMAIN_ABSENCE_OBSERVATION,
        }
    }
}

/// Sign a body under a domain.
///
/// The crate's own structures build their preimage and call this. It is public
/// because the structures that sign under the *other* domains — proof of
/// possession, deletion intent and report, absence observation — belong to later
/// work packages and need the same primitive, and because a cross-protocol
/// rejection test has to be able to produce a genuine signature under the wrong
/// domain. It signs only a fully-formed preimage: the domain is the caller's
/// responsibility, which is why every in-crate caller passes a constant.
pub fn sign_with_domain(signer: &SigningSecretKey, domain: Domain, body: &[u8]) -> TokenSignature {
    let domain = domain.bytes();
    let mut preimage = Vec::with_capacity(domain.len() + body.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(body);
    signer.sign_bytes(&preimage)
}

/// Verify a body under an arbitrary domain.
///
/// The mirror of [`sign_with_domain`], used by the verifier of a domain this
/// work package does not own yet.
pub fn verify_with_domain(
    anchor: &VerifyingPublicKey,
    domain: Domain,
    body: &[u8],
    signature: &TokenSignature,
) -> bool {
    let domain = domain.bytes();
    let mut preimage = Vec::with_capacity(domain.len() + body.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(body);
    anchor.verify(&preimage, &signature.to_bytes())
}

/// Verify a delivery against a pinned issuer key.
///
/// The preimage is rebuilt from `header` and `envelope`, so a signature that was
/// made over different bytes — another header, another envelope, or a proof of
/// possession — does not verify.
pub fn verify_delivery(
    anchor: &VerifyingPublicKey,
    header: &DeliveryHeader,
    envelope: &DeliveryEnvelope,
    signature: &TokenSignature,
) -> Result<(), TokenError> {
    let preimage = token_preimage(header, envelope)?;
    if anchor.verify(&preimage, &signature.to_bytes()) {
        Ok(())
    } else {
        Err(TokenError::IssuerSignature)
    }
}

/// Why a delivery signature could not be produced or checked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// The preimage could not be canonically encoded.
    #[error("the token preimage could not be encoded: {cause}")]
    Encoding {
        /// The encoder's reason.
        cause: String,
    },
    /// The signature did not verify against the pinned issuer key.
    #[error("the delivery signature did not verify against the pinned issuer")]
    IssuerSignature,
}
