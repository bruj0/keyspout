//! Typed, identity-bound key bundles that survive a foreground invocation.
//!
//! # The misfit
//!
//! Misfit R: every `ksp` operation is one process that exits. An agent's
//! Ed25519 and X25519 private halves are generated at enrolment, and unless
//! something writes them down they are gone when the process ends. A later
//! `ksp run` then has no key to prove possession with and no key to unwrap its
//! delivery, so every honest host would report exit `6`.
//!
//! # Why the seam lives here and not in the CLI
//!
//! These types own the bytes, and they are the only thing that may interpret
//! them. A public `private_bytes()` or a public export of raw halves would be
//! the unconstrained key oracle FR-001 rules out, which is exactly why
//! `SigningSecretKey::dalek()` and `AdminSigningKey::dalek()` are `pub(crate)`.
//! The CLI never sees a private byte: it hands bytes to the durable key file
//! (WP15) and gets a typed authority back.
//!
//! # What a bundle is not
//!
//! It is not a delivery artifact, not a user vault and not a trust anchor. The
//! fingerprint stored in a bundle is a *claim*; only the caller's pinned
//! fingerprint is evidence. A bundle therefore never becomes its own pin, and a
//! missing or mismatched file never causes a replacement identity to be
//! generated: a silent new key would make every captured artifact unopenable
//! while every command still reported success.
//!
//! # The wire form
//!
//! Each role has its **own** fixed-order struct, encoded through
//! [`ksp_types::cbor`]. The role is a field and the two structs have different
//! fields, so an agent bundle cannot be relabelled into an admin bundle:
//! decoding rejects an unexpected role and a field the role does not have.
//! Every field is mandatory, so a "missing half" bundle cannot be expressed.
//! Decoding re-encodes and compares, which rejects a non-canonical buffer and
//! trailing bytes.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use ksp_types::AgentId;

use crate::enrolment::{
    AdminSigningKey, AgentKeys, KEY_LEN, RecipientPublicKey, RecipientSecretKey, SigningSecretKey,
    VerifyingPublicKey,
};
use crate::fingerprint::{EnrolmentFingerprint, FingerprintSubject, KeyId};

/// The wire format version of a key bundle.
pub const KEY_BUNDLE_VERSION: u16 = 1;

/// The role string an agent bundle states.
const ROLE_AGENT: &str = "agent";

/// The role string an admin bundle states.
const ROLE_ADMIN: &str = "admin";

/// What the caller independently pins about an agent before loading its bundle.
///
/// Every field comes from a channel that is not the bundle: the fingerprint the
/// user confirmed out of band, the key IDs the enrolment record names, and the
/// two public keys it carries. A bundle that disagrees with this is refused
/// even when its own contents are internally consistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentityPin {
    /// The agent the bundle must belong to.
    pub identity: AgentId,
    /// The ID the enrolment record gives the signing key.
    pub signing_key_id: KeyId,
    /// The ID the enrolment record gives the recipient key.
    pub recipient_key_id: KeyId,
    /// The enrolled Ed25519 public key.
    pub signing_key: VerifyingPublicKey,
    /// The enrolled X25519 public key.
    pub recipient_key: RecipientPublicKey,
    /// The fingerprint the user verified out of band.
    pub confirmed_fingerprint: EnrolmentFingerprint,
}

/// What the caller independently pins about the admin signing authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSigningPin {
    /// The ID the trust anchor names.
    pub key_id: KeyId,
    /// The admin public key the host pinned before reading any file.
    pub signing_key: VerifyingPublicKey,
}

/// Why a key bundle could not be written or read back.
///
/// No variant carries key material: a `Display` implementation ends up in a
/// terminal, a log and an audit sink.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    /// The bundle states a format this build does not produce or read.
    #[error("the key bundle is format version {found}, this build understands {expected}")]
    UnsupportedVersion {
        /// The version the bundle states.
        found: u16,
        /// The version this build understands.
        expected: u16,
    },
    /// The bytes are not a key bundle, or not this role's bundle.
    #[error("the bytes are not a {expected} key bundle")]
    WrongRole {
        /// The role the caller asked for.
        expected: &'static str,
    },
    /// The bytes could not be decoded.
    #[error("the key bundle is not decodable")]
    Malformed,
    /// The bundle did not re-encode to the bytes it was read from.
    #[error("the key bundle is not canonical")]
    NonCanonical,
    /// The bundle belongs to a different identity.
    #[error("the key bundle belongs to a different identity")]
    IdentityMismatch,
    /// The bundle names different key IDs.
    #[error("the key bundle names different key IDs")]
    KeyIdMismatch,
    /// The bundle's stored public half disagrees with its private half.
    #[error("the key bundle's public half disagrees with its private half")]
    PublicKeyMismatch,
    /// The bundle does not reproduce the pinned fingerprint.
    #[error("the key bundle does not reproduce the confirmed fingerprint")]
    FingerprintMismatch,
    /// The bundle could not be encoded.
    #[error("the key bundle could not be encoded")]
    Encoding,
}

/// The agent bundle as it is written.
///
/// Every field is mandatory. There is no `Option` and no default, so a bundle
/// missing one half cannot be produced and cannot be read: the alternative
/// would be a partially reloaded identity.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentWire {
    version: u16,
    role: String,
    identity: String,
    signing_key_id: String,
    recipient_key_id: String,
    signing_key: [u8; KEY_LEN],
    recipient_key: [u8; KEY_LEN],
    signing_secret: [u8; KEY_LEN],
    recipient_secret: [u8; KEY_LEN],
    fingerprint: [u8; KEY_LEN],
}

impl Drop for AgentWire {
    fn drop(&mut self) {
        // Both private halves are erased on every path, including a failed
        // validation.
        self.signing_secret.zeroize();
        self.recipient_secret.zeroize();
    }
}

impl std::fmt::Debug for AgentWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AgentWire(<redacted>)")
    }
}

/// The admin bundle as it is written. There is no recipient half at all.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminWire {
    version: u16,
    role: String,
    key_id: String,
    signing_key: [u8; KEY_LEN],
    signing_secret: [u8; KEY_LEN],
}

impl Drop for AdminWire {
    fn drop(&mut self) {
        self.signing_secret.zeroize();
    }
}

impl std::fmt::Debug for AdminWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdminWire(<redacted>)")
    }
}

/// An agent's two private halves, bound to its identity, public keys and key IDs.
pub struct AgentKeyBundle {
    identity: AgentId,
    signing_key_id: KeyId,
    recipient_key_id: KeyId,
    signing_key: VerifyingPublicKey,
    recipient_key: RecipientPublicKey,
    fingerprint: EnrolmentFingerprint,
    signing_secret: SigningSecretKey,
    recipient_secret: RecipientSecretKey,
}

impl std::fmt::Debug for AgentKeyBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Named, never rendered: a derived Debug would print every private byte
        // in each panic message and test failure that touched a bundle.
        f.write_str("AgentKeyBundle(<redacted>)")
    }
}

impl AgentKeyBundle {
    /// Bind an already-generated agent key pair to the identity that owns it.
    ///
    /// The fingerprint is computed from the keys, never supplied: a caller
    /// cannot hand in a value that disagrees with what it describes.
    pub fn from_keys(
        keys: &AgentKeys,
        identity: AgentId,
        signing_key_id: KeyId,
        recipient_key_id: KeyId,
    ) -> Result<Self, BundleError> {
        let signing_key = keys.signing_public();
        let recipient_key = keys.recipient_public();
        let fingerprint = fingerprint_of(
            &identity,
            signing_key,
            recipient_key,
            &signing_key_id,
            &recipient_key_id,
        )?;

        // The halves are rebuilt from their own bytes so the bundle owns its
        // private material and the caller's `AgentKeys` is not aliased.
        let mut signing_bytes = keys.signing_secret().to_secret_bytes();
        let mut recipient_bytes = keys.recipient_secret().to_secret_bytes();
        let signing_secret = SigningSecretKey::from_secret_bytes(&signing_bytes);
        let recipient_secret = RecipientSecretKey::from_secret_bytes(recipient_bytes);
        signing_bytes.zeroize();
        recipient_bytes.zeroize();

        Ok(Self {
            identity,
            signing_key_id,
            recipient_key_id,
            signing_key,
            recipient_key,
            fingerprint,
            signing_secret,
            recipient_secret,
        })
    }

    /// The bytes for the durable key file. Never rendered, never logged.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, BundleError> {
        let mut signing_secret = self.signing_secret.to_secret_bytes();
        let mut recipient_secret = self.recipient_secret.to_secret_bytes();
        let wire = AgentWire {
            version: KEY_BUNDLE_VERSION,
            role: ROLE_AGENT.to_owned(),
            identity: self.identity.to_string(),
            signing_key_id: self.signing_key_id.as_str().to_owned(),
            recipient_key_id: self.recipient_key_id.as_str().to_owned(),
            signing_key: self.signing_key.to_bytes(),
            recipient_key: self.recipient_key.to_bytes(),
            signing_secret,
            recipient_secret,
            fingerprint: *self.fingerprint.as_bytes(),
        };
        signing_secret.zeroize();
        recipient_secret.zeroize();

        let bytes = ksp_types::cbor::encode(&wire).map_err(|_| BundleError::Encoding)?;
        Ok(Zeroizing::new(bytes))
    }

    /// Read a bundle back and verify it against the caller's pin.
    ///
    /// Every check runs before a value is returned, so a refusal yields neither
    /// a signing capability nor a recipient capability.
    pub fn from_bytes(bytes: &[u8], pin: &AgentIdentityPin) -> Result<Self, BundleError> {
        let wire: AgentWire = ksp_types::cbor::decode(bytes).map_err(|_| BundleError::Malformed)?;

        Self::validate_wire(&wire, bytes)?;

        let identity = AgentId::parse(&wire.identity).map_err(|_| BundleError::Malformed)?;
        if identity != pin.identity {
            return Err(BundleError::IdentityMismatch);
        }
        let signing_key_id = KeyId::new(wire.signing_key_id.clone());
        let recipient_key_id = KeyId::new(wire.recipient_key_id.clone());
        if signing_key_id != pin.signing_key_id || recipient_key_id != pin.recipient_key_id {
            return Err(BundleError::KeyIdMismatch);
        }

        // Both public halves are derived from the private halves. A bundle
        // whose halves disagree with each other is not one identity, and a
        // bundle that disagrees with the pin is not this identity.
        let signing_secret = SigningSecretKey::from_secret_bytes(&wire.signing_secret);
        let recipient_secret = RecipientSecretKey::from_secret_bytes(wire.recipient_secret);
        let derived_signing = signing_secret.verifying_public();
        let derived_recipient = recipient_secret.recipient_public();

        if derived_signing.to_bytes() != wire.signing_key
            || derived_recipient.to_bytes() != wire.recipient_key
            || derived_signing != pin.signing_key
            || derived_recipient != pin.recipient_key
        {
            return Err(BundleError::PublicKeyMismatch);
        }

        // The stored fingerprint is a claim; the recomputed one is what the pin
        // is compared against. A bundle never vouches for itself.
        let recomputed = fingerprint_of(
            &identity,
            derived_signing,
            derived_recipient,
            &signing_key_id,
            &recipient_key_id,
        )?;
        if recomputed.as_bytes() != &wire.fingerprint {
            return Err(BundleError::FingerprintMismatch);
        }
        if !recomputed.matches(&pin.confirmed_fingerprint) {
            return Err(BundleError::FingerprintMismatch);
        }

        Ok(Self {
            identity,
            signing_key_id,
            recipient_key_id,
            signing_key: derived_signing,
            recipient_key: derived_recipient,
            fingerprint: recomputed,
            signing_secret,
            recipient_secret,
        })
    }

    /// The role, version and canonical-encoding checks every read performs.
    fn validate_wire(wire: &AgentWire, bytes: &[u8]) -> Result<(), BundleError> {
        // A different stated format may mean something entirely different by
        // these fields, so it is refused before any of them is trusted.
        if wire.version != KEY_BUNDLE_VERSION {
            return Err(BundleError::UnsupportedVersion {
                found: wire.version,
                expected: KEY_BUNDLE_VERSION,
            });
        }
        // The role is checked next: the remaining fields only mean what they
        // mean if this is an agent bundle.
        if wire.role != ROLE_AGENT {
            return Err(BundleError::WrongRole {
                expected: ROLE_AGENT,
            });
        }

        // A buffer that decodes but does not re-encode to itself is not the
        // encoding this crate writes. Without this a store could hold two byte
        // sequences for one version.
        let canonical = ksp_types::cbor::encode(wire).map_err(|_| BundleError::Encoding)?;
        if canonical != bytes {
            return Err(BundleError::NonCanonical);
        }
        Ok(())
    }

    /// The agent this bundle belongs to.
    pub fn identity(&self) -> &AgentId {
        &self.identity
    }

    /// The Ed25519 public key.
    pub fn signing_public(&self) -> VerifyingPublicKey {
        self.signing_key
    }

    /// The X25519 public key.
    pub fn recipient_public(&self) -> RecipientPublicKey {
        self.recipient_key
    }

    /// The ID naming the signing key.
    pub fn signing_key_id(&self) -> &KeyId {
        &self.signing_key_id
    }

    /// The ID naming the recipient key.
    pub fn recipient_key_id(&self) -> &KeyId {
        &self.recipient_key_id
    }

    /// The fingerprint this bundle reproduces.
    pub fn fingerprint(&self) -> &EnrolmentFingerprint {
        &self.fingerprint
    }

    /// The signing half, ready to sign a domain-separated preimage.
    pub fn signing_secret(&self) -> &SigningSecretKey {
        &self.signing_secret
    }

    /// The recipient half, ready to unwrap a delivery.
    pub fn recipient_secret(&self) -> &RecipientSecretKey {
        &self.recipient_secret
    }
}

/// # Scoped key use
///
/// The bundle forwards both halves to a closure so a caller holding a verified
/// authority never needs to reach for a component first, and never holds a copy.
impl AgentKeyBundle {
    /// Use the Ed25519 seed without letting it outlive the call.
    ///
    /// The two accessors are deliberately distinct: forwarding both to one
    /// field would still produce a working key, so the pair is what keeps the
    /// signing half and the recipient half from being confused.
    pub fn with_signing_secret<R>(&self, f: impl FnOnce(&[u8; KEY_LEN]) -> R) -> R {
        self.signing_secret.with_secret(f)
    }

    /// Use the X25519 secret without letting it outlive the call.
    pub fn with_recipient_secret<R>(&self, f: impl FnOnce(&[u8; KEY_LEN]) -> R) -> R {
        self.recipient_secret.with_secret(f)
    }
}

/// The admin's signing authority, bound to its key ID and public key.
pub struct AdminKeyBundle {
    key_id: KeyId,
    signing_key: VerifyingPublicKey,
    signing_secret: AdminSigningKey,
}

/// # Scoped key use
///
/// The bundle forwards the admin's signing half so a caller holding the loaded
/// authority never reaches for a component first.
impl AdminKeyBundle {
    /// Use the Ed25519 seed without letting it outlive the call.
    ///
    /// Forwarded rather than re-derived: a bundle that generated or copied a
    /// key here would produce a signature the pinned anchor does not accept,
    /// which is the substitution this whole seam exists to make impossible.
    pub fn with_signing_secret<R>(&self, f: impl FnOnce(&[u8; KEY_LEN]) -> R) -> R {
        self.signing_secret.with_secret(f)
    }
}

impl std::fmt::Debug for AdminKeyBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdminKeyBundle(<redacted>)")
    }
}

impl AdminKeyBundle {
    /// Bind the admin signing key to the ID the trust anchor names.
    pub fn from_key(key: &AdminSigningKey, key_id: KeyId) -> Self {
        let mut seed = key.to_secret_bytes();
        let signing_secret = AdminSigningKey::from_secret_bytes(&seed);
        seed.zeroize();
        Self {
            key_id,
            signing_key: key.verifying_public(),
            signing_secret,
        }
    }

    /// The bytes for the durable key file. Never rendered, never logged.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, BundleError> {
        let mut signing_secret = self.signing_secret.to_secret_bytes();
        let wire = AdminWire {
            version: KEY_BUNDLE_VERSION,
            role: ROLE_ADMIN.to_owned(),
            key_id: self.key_id.as_str().to_owned(),
            signing_key: self.signing_key.to_bytes(),
            signing_secret,
        };
        signing_secret.zeroize();

        let bytes = ksp_types::cbor::encode(&wire).map_err(|_| BundleError::Encoding)?;
        Ok(Zeroizing::new(bytes))
    }

    /// Read the admin identity back and verify it against the pinned anchor.
    pub fn from_bytes(bytes: &[u8], pin: &AdminSigningPin) -> Result<Self, BundleError> {
        let wire: AdminWire = ksp_types::cbor::decode(bytes).map_err(|_| BundleError::Malformed)?;

        if wire.version != KEY_BUNDLE_VERSION {
            return Err(BundleError::UnsupportedVersion {
                found: wire.version,
                expected: KEY_BUNDLE_VERSION,
            });
        }
        if wire.role != ROLE_ADMIN {
            return Err(BundleError::WrongRole {
                expected: ROLE_ADMIN,
            });
        }

        let canonical = ksp_types::cbor::encode(&wire).map_err(|_| BundleError::Encoding)?;
        if canonical != bytes {
            return Err(BundleError::NonCanonical);
        }

        let key_id = KeyId::new(wire.key_id.clone());
        if key_id != pin.key_id {
            return Err(BundleError::KeyIdMismatch);
        }

        let signing_secret = AdminSigningKey::from_secret_bytes(&wire.signing_secret);
        let derived = signing_secret.verifying_public();
        if derived.to_bytes() != wire.signing_key || derived != pin.signing_key {
            return Err(BundleError::PublicKeyMismatch);
        }

        Ok(Self {
            key_id,
            signing_key: derived,
            signing_secret,
        })
    }

    /// The ID naming the admin key.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The admin public key.
    pub fn signing_key(&self) -> VerifyingPublicKey {
        self.signing_key
    }

    /// The admin signing key, ready to sign an enrolment or policy.
    pub fn into_key(self) -> AdminSigningKey {
        self.signing_secret
    }
}

/// The fingerprint an identity, both public keys and both key IDs produce.
fn fingerprint_of(
    identity: &AgentId,
    signing_key: VerifyingPublicKey,
    recipient_key: RecipientPublicKey,
    signing_key_id: &KeyId,
    recipient_key_id: &KeyId,
) -> Result<EnrolmentFingerprint, BundleError> {
    EnrolmentFingerprint::compute(&FingerprintSubject {
        identity: ksp_types::ActorId::Agent(*identity),
        signing_key: signing_key.to_bytes(),
        recipient_key: recipient_key.to_bytes(),
        signing_key_id: signing_key_id.clone(),
        recipient_key_id: recipient_key_id.clone(),
    })
    .map_err(|_| BundleError::Encoding)
}
