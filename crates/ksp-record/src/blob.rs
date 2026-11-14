//! The content blob: the AEAD ciphertext over a record's name and value.
//!
//! The blob is bound to the *same* associated data as the record envelope.
//! One binding, two consumers — there is no second, looser binding
//! (FR-006). A ciphertext relocated to another record version's path
//! therefore fails to open, because the bound metadata is the AAD on both
//! sides.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use ksp_types::ContentKey;
use zeroize::Zeroizing;

/// The length of the content blob's nonce.
pub const CONTENT_BLOB_NONCE_LEN: usize = 12;

/// The error produced when a content blob cannot be sealed or opened.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    /// The content key could not be turned into an AEAD key.
    #[error("the content key is not a usable AEAD key")]
    InvalidKey,
    /// The nonce could not be generated.
    #[error("no randomness was available for the nonce")]
    NoRandomness,
    /// The ciphertext did not authenticate, or had the wrong shape.
    #[error("the content blob did not authenticate")]
    AuthenticationFailed,
}

/// The AEAD ciphertext over a record's name and value.
///
/// The name is inside the ciphertext, not beside it: a backend listing
/// discloses no secret name (FR-011).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentBlob {
    nonce: [u8; CONTENT_BLOB_NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl ContentBlob {
    /// Seal a record's name and value under a content key.
    ///
    /// `aad` is the canonical bound metadata. It is authenticated, not
    /// encrypted.
    pub fn seal(
        content_key: &ContentKey,
        name: &[u8],
        value: &[u8],
        aad: &[u8],
    ) -> Result<Self, BlobError> {
        let cipher = ChaCha20Poly1305::new(&cipher_key(content_key)?);

        let mut nonce_bytes = [0u8; CONTENT_BLOB_NONCE_LEN];
        rand::fill(&mut nonce_bytes);
        let nonce = blob_nonce(&nonce_bytes);

        // The plaintext is the length-prefixed name followed by the value.
        // The prefix makes the split unambiguous on the way back: a name
        // that contains the value's bytes cannot shift the boundary. The
        // name is encrypted with the value, so a reader of the ciphertext
        // learns neither.
        let mut plaintext = Zeroizing::new(Vec::with_capacity(4 + name.len() + value.len()));
        let name_len = u32::try_from(name.len()).map_err(|_| BlobError::InvalidKey)?;
        plaintext.extend_from_slice(&name_len.to_be_bytes());
        plaintext.extend_from_slice(name);
        plaintext.extend_from_slice(value);

        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad,
                },
            )
            .map_err(|_| BlobError::AuthenticationFailed)?;

        Ok(Self {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Open a content blob, returning the name and the value.
    pub fn open(
        &self,
        content_key: &ContentKey,
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), BlobError> {
        let cipher = ChaCha20Poly1305::new(&cipher_key(content_key)?);

        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &blob_nonce(&self.nonce),
                    Payload {
                        msg: &self.ciphertext,
                        aad,
                    },
                )
                .map_err(|_| BlobError::AuthenticationFailed)?,
        );

        // The name and the value are separated by the length prefix that
        // `seal` writes. See `split_name_and_value`.
        split_name_and_value(&plaintext).ok_or(BlobError::AuthenticationFailed)
    }

    /// The nonce, for serialization.
    pub fn nonce(&self) -> &[u8; CONTENT_BLOB_NONCE_LEN] {
        &self.nonce
    }

    /// The ciphertext bytes.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The full serialized blob: the nonce followed by the ciphertext.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.nonce.len() + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse a blob from its serialized form.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlobError> {
        if bytes.len() < CONTENT_BLOB_NONCE_LEN {
            return Err(BlobError::AuthenticationFailed);
        }
        let mut nonce = [0u8; CONTENT_BLOB_NONCE_LEN];
        nonce.copy_from_slice(&bytes[..CONTENT_BLOB_NONCE_LEN]);
        Ok(Self {
            nonce,
            ciphertext: bytes[CONTENT_BLOB_NONCE_LEN..].to_vec(),
        })
    }
}

/// Build the AEAD key from a content key.
///
/// The content key is exactly 32 bytes, which is the key length
/// ChaCha20-Poly1305 requires, so the conversion cannot fail.
fn cipher_key(content_key: &ContentKey) -> Result<Key, BlobError> {
    Key::try_from(content_key.as_bytes().as_slice()).map_err(|_| BlobError::InvalidKey)
}

/// Build the AEAD nonce from its raw bytes.
fn blob_nonce(bytes: &[u8; CONTENT_BLOB_NONCE_LEN]) -> Nonce {
    // The length is exactly the nonce length ChaCha20-Poly1305 requires.
    match Nonce::try_from(bytes.as_slice()) {
        Ok(nonce) => nonce,
        Err(_) => unreachable!("a 12-byte array is always a valid ChaCha20-Poly1305 nonce"),
    }
}

/// Split a sealed plaintext back into its name and its value.
///
/// The name is length-prefixed so that the split is unambiguous: a name
/// containing the value's bytes cannot shift the boundary.
fn split_name_and_value(plaintext: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if plaintext.len() < 4 {
        return None;
    }
    let name_len =
        u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]) as usize;
    let boundary = 4usize.checked_add(name_len)?;
    if boundary > plaintext.len() {
        return None;
    }
    Some((
        plaintext[4..boundary].to_vec(),
        plaintext[boundary..].to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is
    // what says why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn key() -> ContentKey {
        ContentKey::generate()
    }

    #[test]
    fn seals_and_opens_a_name_and_value() {
        let content_key = key();
        let blob = ContentBlob::seal(&content_key, b"db-password", b"hunter2", b"aad").unwrap();
        let (name, value) = blob.open(&content_key, b"aad").unwrap();
        assert_eq!(name, b"db-password");
        assert_eq!(value, b"hunter2");
    }

    #[test]
    fn a_different_aad_fails_to_open() {
        let content_key = key();
        let blob = ContentBlob::seal(&content_key, b"name", b"value", b"aad").unwrap();
        assert!(blob.open(&content_key, b"other-aad").is_err());
    }

    #[test]
    fn a_different_key_fails_to_open() {
        let content_key = key();
        let other_key = key();
        let blob = ContentBlob::seal(&content_key, b"name", b"value", b"aad").unwrap();
        assert!(blob.open(&other_key, b"aad").is_err());
    }

    #[test]
    fn the_name_is_not_recoverable_without_the_key() {
        let content_key = key();
        let blob = ContentBlob::seal(&content_key, b"db-password", b"hunter2", b"aad").unwrap();
        let bytes = blob.to_bytes();
        assert!(
            !bytes
                .windows(b"db-password".len())
                .any(|w| w == b"db-password"),
            "the name must not appear in the ciphertext"
        );
    }

    #[test]
    fn the_blob_round_trips_through_its_serialized_form() {
        let content_key = key();
        let blob = ContentBlob::seal(&content_key, b"name", b"value", b"aad").unwrap();
        let bytes = blob.to_bytes();
        let parsed = ContentBlob::from_bytes(&bytes).unwrap();
        let (name, value) = parsed.open(&content_key, b"aad").unwrap();
        assert_eq!(name, b"name");
        assert_eq!(value, b"value");
    }

    #[test]
    fn a_name_containing_the_value_bytes_does_not_shift_the_boundary() {
        let content_key = key();
        let blob = ContentBlob::seal(&content_key, b"aaaavalue", b"value", b"aad").unwrap();
        let (name, value) = blob.open(&content_key, b"aad").unwrap();
        assert_eq!(name, b"aaaavalue");
        assert_eq!(value, b"value");
    }
}
