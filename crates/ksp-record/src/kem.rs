//! The KEM validation gate.
//!
//! # The problem this exists to solve
//!
//! `hpke_rs::HpkeError` has **no** `KemInvalidPublicKey` variant. Its
//! variants are `OpenError, InvalidConfig, InvalidInput, UnknownMode,
//! InconsistentPsk, MissingPsk, UnnecessaryPsk, InsecurePsk,
//! CryptoError(String), MessageLimitReached, InsufficientRandomness`. The
//! upstream mapping is:
//!
//! ```text
//! hpke-rs-crypto::error::Error::KemInvalidPublicKey
//!   => HpkeError::CryptoError("Invalid KEM public key".to_string())
//! ```
//!
//! So the provider's typed error is erased on the way up. FR-004 requires
//! the system to *return* `KemInvalidPublicKey` and emit no envelope, so
//! the application must call the provider trait **directly**.
//!
//! **Never** pattern-match `HpkeError::CryptoError(String)` to recover the
//! condition. That string is not a stable upstream API, and FR-004 must not
//! depend on it.
//!
//! # The two direction probes
//!
//! X25519 is scalar-multiplicative, so a low-order `pk` yields an all-zero
//! shared secret for **any** non-zero scalar. That gives a cheap pre-check
//! in each direction:
//!
//! - *Encapsulate direction*: evaluate `dh(pk_r, probe_sk)` with a fixed
//!   non-zero probe scalar before sealing. A healthy `pk_r` gives a non-zero
//!   result, which the adapter discards. The provider's internal check
//!   remains as defence in depth.
//! - *Decapsulate direction*: evaluate `dh(enc_pk, sk_r)` on the
//!   encapsulated ephemeral public key carried in the envelope, before
//!   opening anything. A low-order `enc_pk` is rejected with the typed
//!   error.

use hpke_rs::hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs::{Hpke, HpkeError, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_crypto::HpkeCrypto;
use hpke_rs_crypto::error::Error as ProviderError;
use hpke_rs_rust_crypto::HpkeRustCrypto;

use ksp_types::ContentKey;
use zeroize::Zeroizing;

/// The error returned by the KEM validation gate.
#[derive(Debug, thiserror::Error)]
pub enum KemError {
    /// The HPKE shared secret was all-zero in either direction.
    ///
    /// This is the typed error FR-004 requires. It is returned instead of
    /// emitting an envelope, in both directions.
    #[error("the HPKE shared secret was all zero; the public key is low order")]
    KemInvalidPublicKey,

    /// Any other provider failure.
    ///
    /// `HpkeError` derives only `Debug` — it does not implement
    /// `std::error::Error` — so it is carried by value and rendered with
    /// `Debug` rather than with `Display`.
    #[error("HPKE provider failure: {0:?}")]
    Provider(HpkeError),

    /// The provider failed for a reason the provider reports separately
    /// from the HPKE error type.
    ///
    /// The provider's error type derives only `Debug` — it does not
    /// implement `std::error::Error` — so it is carried by value and
    /// rendered with `Debug` rather than with `Display`.
    #[error("HPKE provider failure: {0:?}")]
    ProviderDetail(ProviderError),

    /// The bound metadata could not be serialized into the associated
    /// data. This is a local encoding failure, not a cryptographic one.
    #[error("the bound metadata could not be encoded: {0}")]
    BindingFailed(String),
}

/// The KEM, KDF and AEAD suite the record envelope uses.
///
/// It is fixed, not configurable: the design specifies RFC 9180 base mode
/// with X25519, HKDF-SHA256 and ChaCha20-Poly1305.
const KEM: KemAlgorithm = KemAlgorithm::DhKem25519;
const KDF: KdfAlgorithm = KdfAlgorithm::HkdfSha256;
const AEAD: AeadAlgorithm = AeadAlgorithm::ChaCha20Poly1305;

/// A fixed, non-zero probe scalar used for the encapsulate-direction
/// pre-check.
///
/// It is a constant, not a secret: it only has to be non-zero, so that
/// `dh(pk_r, probe_sk)` is the all-zero check the provider performs. It
/// never protects anything.
const PROBE_SK: [u8; 32] = [
    0x9a, 0x7e, 0x3b, 0x1c, 0x5d, 0x42, 0x8e, 0x19, 0x33, 0x67, 0x2a, 0x4c, 0x71, 0x05, 0x9b, 0xe8,
    0x12, 0x6d, 0x38, 0xa4, 0x50, 0x7f, 0x26, 0x9e, 0x31, 0xc8, 0x44, 0x0b, 0x73, 0x5a, 0xd9, 0x2e,
];

/// The length of an X25519 public key.
pub const X25519_PUBLIC_KEY_LEN: usize = 32;

/// The length of an X25519 private key.
pub const X25519_PRIVATE_KEY_LEN: usize = 32;

/// The length of an HPKE encapsulated secret for X25519.
pub const ENCAPSULATED_SECRET_LEN: usize = 32;

/// Build the HPKE context for the record suite.
fn context() -> Result<Hpke<HpkeRustCrypto>, KemError> {
    Hpke::<HpkeRustCrypto>::try_new(Mode::Base, KEM, KDF, AEAD).map_err(KemError::Provider)
}

/// Reject a public key whose shared secret would be all zero.
///
/// This is the encapsulate-direction pre-check. It calls the provider's own
/// `dh`, which performs the all-zero comparison, so the typed error comes
/// from the provider rather than from a re-implementation of the check.
fn check_public_key(public_key: &[u8; 32]) -> Result<(), KemError> {
    match HpkeRustCrypto::dh(KEM, public_key, &PROBE_SK) {
        Ok(shared) => {
            if shared.iter().all(|b| *b == 0) {
                Err(KemError::KemInvalidPublicKey)
            } else {
                Ok(())
            }
        }
        Err(ProviderError::KemInvalidPublicKey) => Err(KemError::KemInvalidPublicKey),
        Err(other) => Err(KemError::ProviderDetail(other)),
    }
}

/// Seal a plaintext to a recipient's X25519 public key.
///
/// Returns the encapsulated secret and the ciphertext. On a low-order
/// recipient key the typed [`KemError::KemInvalidPublicKey`] is returned and
/// **no envelope is produced** (FR-004).
pub fn seal_to(
    recipient_x25519: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), KemError> {
    // Encapsulate direction: reject a low-order recipient key before any
    // envelope exists.
    check_public_key(recipient_x25519)?;

    let mut hpke = context()?;
    let public_key = HpkePublicKey::new(recipient_x25519.to_vec());

    // The provider performs the same all-zero check internally, against the
    // ephemeral scalar it generates. The pre-check above is the explicit
    // gate; the provider's check is the defence in depth behind it.
    let (enc, ciphertext) = hpke
        .seal(&public_key, info, aad, plaintext, None, None, None)
        .map_err(KemError::Provider)?;

    Ok((enc, ciphertext))
}

/// Open a sealed plaintext with the recipient's X25519 private key.
///
/// On a low-order encapsulated ephemeral key the typed
/// [`KemError::KemInvalidPublicKey`] is returned and **no plaintext is
/// produced** (FR-004).
pub fn open_from(
    recipient_x25519_sk: &[u8; 32],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, KemError> {
    if enc.len() != ENCAPSULATED_SECRET_LEN {
        return Err(KemError::Provider(HpkeError::InvalidInput));
    }

    // Decapsulate direction: reject a low-order encapsulated ephemeral key
    // before opening anything.
    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(enc);
    match HpkeRustCrypto::dh(KEM, &enc_key, recipient_x25519_sk) {
        Ok(shared) => {
            if shared.iter().all(|b| *b == 0) {
                return Err(KemError::KemInvalidPublicKey);
            }
        }
        Err(ProviderError::KemInvalidPublicKey) => return Err(KemError::KemInvalidPublicKey),
        Err(other) => return Err(KemError::ProviderDetail(other)),
    }

    let hpke = context()?;
    let private_key = HpkePrivateKey::new(recipient_x25519_sk.to_vec());

    hpke.open(enc, &private_key, info, aad, ciphertext, None, None, None)
        .map_err(KemError::Provider)
}

/// Seal a content key to a recipient's X25519 public key.
pub fn seal_content_key(
    recipient_x25519: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    content_key: &ContentKey,
) -> Result<(Vec<u8>, Vec<u8>), KemError> {
    seal_to(recipient_x25519, info, aad, content_key.as_bytes())
}

/// Open a sealed content key with the recipient's X25519 private key.
pub fn open_content_key(
    recipient_x25519_sk: &[u8; 32],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<ContentKey, KemError> {
    let bytes = Zeroizing::new(open_from(recipient_x25519_sk, enc, info, aad, ciphertext)?);
    let mut key = [0u8; 32];
    if bytes.len() != key.len() {
        return Err(KemError::Provider(HpkeError::InvalidInput));
    }
    key.copy_from_slice(&bytes);
    Ok(ContentKey::from_bytes(key))
}

/// Derive the public key for an X25519 private key.
pub fn public_key_for(private_key: &[u8; 32]) -> Result<[u8; 32], KemError> {
    let public =
        HpkeRustCrypto::secret_to_public(KEM, private_key).map_err(KemError::ProviderDetail)?;
    let mut out = [0u8; 32];
    if public.len() != out.len() {
        return Err(KemError::Provider(HpkeError::InvalidInput));
    }
    out.copy_from_slice(&public);
    Ok(out)
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is
    // what says why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// A low-order X25519 point: the all-zero public key.
    ///
    /// `dh(zero, any_nonzero_scalar)` is the all-zero shared secret, which
    /// is exactly the condition the gate must reject.
    const LOW_ORDER_PUBLIC_KEY: [u8; 32] = [0u8; 32];

    fn key_pair() -> ([u8; 32], [u8; 32]) {
        // A random private key, with its public key derived by the
        // provider. This is the same construction the production code uses.
        let mut private = [0u8; 32];
        rand::fill(&mut private);
        let public = public_key_for(&private).expect("a valid private key yields a public key");
        (private, public)
    }

    #[test]
    fn a_healthy_key_seals_and_opens() {
        let (sk, pk) = key_pair();
        let (enc, ciphertext) =
            seal_to(&pk, b"info", b"aad", b"payload").expect("seal should succeed");
        let plaintext = open_from(&sk, &enc, b"info", b"aad", &ciphertext).expect("open");
        assert_eq!(plaintext, b"payload");
    }

    #[test]
    fn a_low_order_recipient_key_is_rejected_with_the_typed_error() {
        let error = seal_to(&LOW_ORDER_PUBLIC_KEY, b"info", b"aad", b"payload")
            .expect_err("a low-order recipient key must be rejected");

        assert!(
            matches!(error, KemError::KemInvalidPublicKey),
            "expected the typed error, got {error:?}"
        );
    }

    #[test]
    fn a_low_order_recipient_key_produces_no_envelope() {
        // The failure must be total: no encapsulated secret, no ciphertext.
        let result = seal_to(&LOW_ORDER_PUBLIC_KEY, b"info", b"aad", b"payload");
        let error = result.expect_err("a low-order recipient key must be rejected");
        assert!(matches!(error, KemError::KemInvalidPublicKey));
    }

    #[test]
    fn a_low_order_encapsulated_key_is_rejected_with_the_typed_error() {
        let (sk, _pk) = key_pair();

        // Craft an envelope whose encapsulated secret is the all-zero point.
        let low_order_enc = [0u8; 32];
        let error = open_from(&sk, &low_order_enc, b"info", b"aad", b"ciphertext")
            .expect_err("a low-order encapsulated key must be rejected");

        assert!(
            matches!(error, KemError::KemInvalidPublicKey),
            "expected the typed error, got {error:?}"
        );
    }

    #[test]
    fn a_low_order_encapsulated_key_produces_no_plaintext() {
        let (sk, _pk) = key_pair();
        let low_order_enc = [0u8; 32];
        let result = open_from(&sk, &low_order_enc, b"info", b"aad", b"ciphertext");
        assert!(result.is_err());
    }

    #[test]
    fn a_wrong_aad_fails_to_open() {
        let (sk, pk) = key_pair();
        let (enc, ciphertext) = seal_to(&pk, b"info", b"aad", b"payload").unwrap();
        let result = open_from(&sk, &enc, b"info", b"other-aad", &ciphertext);
        assert!(result.is_err(), "a different AAD must not open");
    }

    #[test]
    fn a_wrong_info_fails_to_open() {
        let (sk, pk) = key_pair();
        let (enc, ciphertext) = seal_to(&pk, b"info", b"aad", b"payload").unwrap();
        let result = open_from(&sk, &enc, b"other-info", b"aad", &ciphertext);
        assert!(result.is_err(), "a different info must not open");
    }

    #[test]
    fn a_malformed_encapsulated_secret_is_rejected() {
        let (sk, _pk) = key_pair();
        let result = open_from(&sk, b"too short", b"info", b"aad", b"ciphertext");
        assert!(result.is_err());
    }

    #[test]
    fn the_content_key_round_trips() {
        let (sk, pk) = key_pair();
        let content_key = ContentKey::generate();
        let (enc, ciphertext) = seal_content_key(&pk, b"info", b"aad", &content_key).expect("seal");
        let opened = open_content_key(&sk, &enc, b"info", b"aad", &ciphertext).expect("open");
        assert_eq!(opened.as_bytes(), content_key.as_bytes());
    }

    #[test]
    fn the_public_key_derivation_matches_the_provider() {
        let (sk, pk) = key_pair();
        let derived = public_key_for(&sk).unwrap();
        assert_eq!(&derived[..], &pk[..]);
    }
}
