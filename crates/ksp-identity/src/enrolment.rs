//! The user vault, the enrolment record, the import refusal and the agent path.
//!
//! # Four items, four purposes
//!
//! A user vault holds four things and they are not interchangeable:
//!
//! | Item | Kind | Purpose |
//! |---|---|---|
//! | X25519 decryption keypair | asymmetric | the recipient key — content keys are sealed to it |
//! | Ed25519 signing keypair | asymmetric | the signing key — tokens and deletion intents are signed with it |
//! | UVK | symmetric, 256-bit | the vault key — seals the vault contents |
//! | Argon2id salt | random, unique per vault | the KDF salt, never reused or derived from a username |
//!
//! Private halves and the UVK are sealed under a key derived from the user's
//! password and never leave the machine. Only public keys and the fingerprint
//! are exported.
//!
//! # No implicit key conversion
//!
//! Misfit Q and FR-045 are one misfit seen from two sides. There is no code path
//! that converts an Ed25519 key to an X25519 key, derives one from the other, or
//! accepts one where the other is required — and the two key types are distinct
//! types, so a substitution does not compile. No public function takes a
//! `Vec<u8>` where a key is meant, because a byte vector could carry either.
//!
//! The compile-fail doctests on [`SigningSecretKey`], [`VerifyingPublicKey`] and
//! [`AdminSigningKey`] assert that over the public API surface, not by reading
//! the source.
//!
//! # The admin's key is separate
//!
//! The admin holds an Ed25519 signing key ([`AdminSigningKey`]). It signs
//! enrolment records and can never derive a user's X25519 decryption key or
//! Ed25519 token key (FR-001). It exposes no decryption operation, and it is a
//! different type from every user and agent key.

use std::collections::BTreeMap;

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::Signer;
use ksp_types::{ActorId, DOMAIN_ENROLMENT, DOMAIN_VAULT_AAD, cbor};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::fingerprint::{EnrolmentFingerprint, FingerprintSubject, KeyId};

/// The number of bytes in a private or public key.
pub const KEY_LEN: usize = 32;

/// The number of bytes a ChaCha20-Poly1305 tag adds to a ciphertext.
pub const TAG_LEN: usize = 16;

/// The number of bytes in an Ed25519 signature.
pub use crate::signature::SIGNATURE_LEN;

/// The number of bytes in the vault's KDF salt.
///
/// Sixteen bytes, freshly random for every vault. A salt derived from a
/// username, or shared between two vaults, would let one cracking effort cover
/// both.
pub const SALT_LEN: usize = 16;

/// The number of bytes in the vault's AEAD nonce.
pub const NONCE_LEN: usize = 12;

/// The number of bytes in the UVK.
pub const VAULT_KEY_LEN: usize = 32;

/// The minimum number of password bytes accepted by the vault.
///
/// Not a policy for strength — that is the user's judgement — but a refusal to
/// seal a vault behind an empty password, which would make the Argon2id work
/// factor the only remaining cost.
pub const MIN_PASSWORD_LEN: usize = 8;

/// The wire version of the sealed vault and the enrolment record.
pub const ENROLMENT_VERSION: u16 = 1;

// ---------------------------------------------------------------------------
// Key types — distinct, so a substitution does not compile
// ---------------------------------------------------------------------------

/// An Ed25519 signing secret key.
///
/// It signs. It cannot decrypt, and it cannot be turned into a
/// [`RecipientSecretKey`]:
///
/// ```compile_fail
/// use ksp_identity::enrolment::{RecipientSecretKey, SigningSecretKey};
///
/// let signing = SigningSecretKey::generate();
/// // No such conversion exists: the two key types are deliberately distinct.
/// let recipient: RecipientSecretKey = signing.into();
/// ```
pub struct SigningSecretKey(ed25519_dalek::SigningKey);

impl SigningSecretKey {
    /// Generate a fresh signing key from the operating system's randomness.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rand::fill(&mut bytes);
        let key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        bytes.zeroize_now();
        Self(key)
    }

    /// The matching public key.
    pub fn verifying_public(&self) -> VerifyingPublicKey {
        VerifyingPublicKey(self.0.verifying_key().to_bytes())
    }

    /// Sign a message.
    /// The underlying Ed25519 key, for a consumer that signs through its own
    /// preimage builder (S3's `ArmRecord::sign`).
    ///
    /// Crate-internal: exposing it publicly would be the unbounded signing
    /// oracle that the crate deliberately does not offer.
    pub(crate) fn dalek(&self) -> &ed25519_dalek::SigningKey {
        &self.0
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.0.sign(message).to_bytes()
    }

    /// Sign a fully-formed, domain-separated preimage.
    ///
    /// The agent's own key signs proofs of possession, deletion intents and
    /// deletion reports, so the primitive is exposed. The caller must supply a
    /// preimage built by this crate's one builder for that structure — the
    /// domain is what keeps the signatures non-interchangeable, and it is part
    /// of the bytes passed here.
    pub fn sign_bytes(&self, preimage: &[u8]) -> EnrolmentSignature {
        EnrolmentSignature::from_bytes(self.0.sign(preimage).to_bytes())
    }

    /// Rebuild the key from its 32-byte seed.
    ///
    /// Crate-internal: a public constructor from bytes would let any caller
    /// install an arbitrary signing key under an identity that was enrolled
    /// against a different one. The durable key bundle is the only consumer.
    pub(crate) fn from_secret_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(bytes))
    }

    /// The 32-byte seed, for the durable key bundle.
    ///
    /// Crate-internal for the same reason: the bundle is the only thing that
    /// may write a private half anywhere.
    pub(crate) fn to_secret_bytes(&self) -> [u8; KEY_LEN] {
        self.0.to_bytes()
    }
}

/// # Scoped key use
///
/// The private half is *lent* to one closure and never owned by the caller.
impl SigningSecretKey {
    /// Use the 32-byte seed without letting it outlive the call.
    ///
    /// The array `to_secret_bytes` returns is a copy, and `[u8; KEY_LEN]` is
    /// `Copy`, so `Zeroizing::new` would leave the local unerased. The copy is
    /// therefore named and erased explicitly, the way `VaultKey::generate`
    /// does it: the lend ends with the call and its buffer is wiped when this
    /// frame returns, including on the path where `f` panics.
    ///
    /// What this cannot do is stop a closure from copying the bytes out. What
    /// it removes is the *named* getter, so that reaching for the half is a
    /// visible `*seed` at a call site someone can grep, rather than an API any
    /// caller can reach for without noticing.
    pub fn with_secret<R>(&self, f: impl FnOnce(&[u8; KEY_LEN]) -> R) -> R {
        let mut seed = self.to_secret_bytes();
        let lent = Zeroizing::new(seed);
        seed.zeroize_now();
        f(&lent)
    }
}

/// # Scoped key use
///
/// The admin's signing half is lent to one closure, like every other half.
impl AdminSigningKey {
    /// Use the 32-byte seed without letting it outlive the call.
    ///
    /// The admin signs through typed methods (`sign_enrolment`, `Policy::new`)
    /// wherever a typed method exists. This accessor exists for the one shape
    /// that has none: S4's `SignedIntent::sign` takes an `EvidenceSigningKey`,
    /// which is built from a seed, and the admin is the only authority that may
    /// issue a deletion intent.
    ///
    /// The erasure is WP16's: the copy `to_secret_bytes` returns is named and
    /// erased in place, so the only copy that outlives the call is the one the
    /// lender holds and wipes on drop. What this cannot do is stop a closure
    /// from copying the bytes out; what it removes is the *named* getter, so
    /// reaching for the half is a visible `*seed` at a call site someone can
    /// grep.
    pub fn with_secret<R>(&self, f: impl FnOnce(&[u8; KEY_LEN]) -> R) -> R {
        let mut seed = self.0.to_secret_bytes();
        let lent = Zeroizing::new(seed);
        seed.zeroize_now();
        f(&lent)
    }

    /// Run a closure with the admin's signing key, borrowed for one call.
    ///
    /// The counterpart of [`UserVault::with_signing_key`]: the admin signs the
    /// material that carries her authority — a policy edge, and the delivery token
    /// that edge authorises (CF-020). Handing out the seed would let a caller keep a
    /// copy, so the key exists only for the length of the call.
    pub fn with_signing_key<R>(&self, f: impl FnOnce(&SigningSecretKey) -> R) -> R {
        self.with_secret(|seed| {
            let key = SigningSecretKey::from_secret_bytes(seed);
            f(&key)
        })
    }
}

/// An Ed25519 public key.
///
/// It verifies. It cannot stand in for a [`RecipientPublicKey`] — the two are
/// different types, so a substitution is a type error rather than a runtime
/// check:
///
/// ```compile_fail
/// use ksp_identity::enrolment::{SigningSecretKey, UnsignedEnrolment};
/// use ksp_identity::fingerprint::KeyId;
/// use ksp_types::{ActorId, PrincipalId};
///
/// let signing = SigningSecretKey::generate();
/// let public = signing.verifying_public();
/// // The third argument must be an X25519 recipient key; passing the Ed25519
/// // key here does not compile.
/// let _ = UnsignedEnrolment::bind(
///     ActorId::User(
///         PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
///     ),
///     public,
///     public,
///     KeyId::new("ed"),
///     KeyId::new("x"),
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyingPublicKey([u8; KEY_LEN]);

impl VerifyingPublicKey {
    /// Validate a 32-byte encoding as an Ed25519 public key.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Result<Self, EnrolmentError> {
        ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| {
            EnrolmentError::KeyEncoding {
                cause: "the bytes are not a valid Ed25519 public key".to_string(),
            }
        })?;
        Ok(Self(bytes))
    }

    /// The 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0
    }

    /// Verify a signature over `message`.
    ///
    /// `verify_strict` rejects small-order and non-canonical public keys, which
    /// the permissive form accepts.
    pub fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from_bytes(signature);
        key.verify_strict(message, &signature).is_ok()
    }
}

/// An X25519 recipient secret key.
///
/// It is the user's decryption key. It cannot sign, and it cannot be built from
/// an Ed25519 key.
pub struct RecipientSecretKey(x25519_dalek::StaticSecret);

impl RecipientSecretKey {
    /// Generate a fresh recipient key from the operating system's randomness.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rand::fill(&mut bytes);
        let secret = x25519_dalek::StaticSecret::from(bytes);
        bytes.zeroize_now();
        Self(secret)
    }

    /// The matching public key.
    pub fn recipient_public(&self) -> RecipientPublicKey {
        RecipientPublicKey(x25519_dalek::PublicKey::from(&self.0).to_bytes())
    }

    /// Rebuild the key from its 32-byte secret.
    ///
    /// Crate-internal: the durable key bundle is the only thing that may load
    /// a private half from bytes, and a public constructor would let a caller
    /// install a key no enrolment approved.
    pub(crate) fn from_secret_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(x25519_dalek::StaticSecret::from(bytes))
    }

    /// The 32-byte secret, for the durable key bundle.
    ///
    /// Crate-internal so that the private half is written only by the bundle
    /// that binds it to an identity.
    pub(crate) fn to_secret_bytes(&self) -> [u8; KEY_LEN] {
        self.0.to_bytes()
    }
}

/// # Scoped key use
///
/// The private half is *lent* to one closure and never owned by the caller.
impl RecipientSecretKey {
    /// Use the 32-byte secret without letting it outlive the call.
    ///
    /// Same arrangement as the signing half: the copy is erased in place once
    /// it has been moved into the lender, so the lend cannot leave a stray
    /// scalar behind, and the same caveat applies — a closure that copies the
    /// bytes out defeats it, which is why no named getter exists.
    pub fn with_secret<R>(&self, f: impl FnOnce(&[u8; KEY_LEN]) -> R) -> R {
        let mut secret = self.to_secret_bytes();
        let lent = Zeroizing::new(secret);
        secret.zeroize_now();
        f(&lent)
    }
}

/// An X25519 public key — the recipient key a delivery is sealed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientPublicKey([u8; KEY_LEN]);

impl RecipientPublicKey {
    /// Wrap a 32-byte X25519 public key.
    ///
    /// Every 32-byte string is a syntactically valid X25519 public key; the
    /// low-order-point rejection happens at the KEM, not here.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0
    }
}

/// The user's vault key (UVK) — a symmetric 256-bit secret.
///
/// It seals the vault contents. It is not a keypair, and it is not derived from
/// either keypair.
pub struct VaultKey(Zeroizing<[u8; VAULT_KEY_LEN]>);

impl VaultKey {
    /// Generate a fresh vault key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; VAULT_KEY_LEN];
        rand::fill(&mut bytes);
        // `[u8; 32]` is `Copy`, so `Zeroizing::new` takes a copy and the local
        // would otherwise outlive it unerased.
        let key = Self(Zeroizing::new(bytes));
        bytes.zeroize_now();
        key
    }

    /// The raw bytes.
    ///
    /// Exposed so the sealing path can use it. It is never rendered by any
    /// `Display` or `Debug` implementation.
    pub fn as_bytes(&self) -> &[u8; VAULT_KEY_LEN] {
        &self.0
    }
}

// The promise is discharged by the `Zeroizing` field; declaring it lets a test
// assert the erasure instead of trusting a comment.
impl zeroize::ZeroizeOnDrop for VaultKey {}

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A `Debug` implementation is the easiest way to leak a secret into a
        // log, so this one deliberately renders nothing of the value.
        f.write_str("VaultKey(<redacted>)")
    }
}

/// Erase a fixed-size buffer in place.
///
/// A free function because the call sites already own the buffer and only need
/// the erasure.
trait ZeroizeNow {
    fn zeroize_now(&mut self);
}

impl ZeroizeNow for [u8; KEY_LEN] {
    fn zeroize_now(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

// ---------------------------------------------------------------------------
// The user vault
// ---------------------------------------------------------------------------

/// A user's unsealed vault: both keypairs and the UVK, in memory only.
///
/// Dropping it erases all three: the private halves through the `Drop`
/// implementations of `ed25519_dalek::SigningKey` and
/// `x25519_dalek::StaticSecret`, and the UVK through `Zeroizing`. The test
/// module asserts the first two are `ZeroizeOnDrop` rather than taking it on
/// trust from a doc comment.
pub struct UserVault {
    signing: SigningSecretKey,
    recipient: RecipientSecretKey,
    vault_key: VaultKey,
}

impl UserVault {
    /// Generate a fresh vault: two independent keypairs and a 256-bit UVK.
    ///
    /// The two keypairs are independent — the recipient key is not derived from
    /// the signing key, and there is no conversion between them.
    pub fn generate() -> Self {
        Self {
            signing: SigningSecretKey::generate(),
            recipient: RecipientSecretKey::generate(),
            vault_key: VaultKey::generate(),
        }
    }

    /// The Ed25519 signing public key.
    pub fn signing_public(&self) -> VerifyingPublicKey {
        self.signing.verifying_public()
    }

    /// The X25519 recipient public key.
    pub fn recipient_public(&self) -> RecipientPublicKey {
        self.recipient.recipient_public()
    }

    /// The vault key.
    pub fn vault_key(&self) -> &VaultKey {
        &self.vault_key
    }

    /// Seal the private halves and the UVK under a password.
    ///
    /// `binding` is the identity and key-ID set this vault belongs to. It is the
    /// AEAD's associated data, so a sealed vault cannot be moved onto another
    /// identity: it would simply fail to open.
    pub fn seal(
        &self,
        password: &[u8],
        binding: &VaultBinding,
    ) -> Result<SealedVault, EnrolmentError> {
        if password.len() < MIN_PASSWORD_LEN {
            return Err(EnrolmentError::PasswordTooShort {
                minimum: MIN_PASSWORD_LEN,
            });
        }

        let mut salt = [0u8; SALT_LEN];
        rand::fill(&mut salt);
        let derived = derive_key(password, &salt)?;

        // signing || recipient || UVK. Every byte is a secret, so the buffer is
        // zeroized on drop whether the sealing succeeds or not.
        let mut plaintext = Zeroizing::new(Vec::with_capacity(KEY_LEN * 3));
        // `to_bytes()` returns `[u8; 32]` by value, so each call leaves a stack
        // copy of a private half behind unless it is wiped.
        let mut signing_bytes = self.signing.0.to_bytes();
        plaintext.extend_from_slice(&signing_bytes);
        signing_bytes.zeroize_now();
        let mut recipient_bytes = self.recipient.0.to_bytes();
        plaintext.extend_from_slice(&recipient_bytes);
        recipient_bytes.zeroize_now();
        plaintext.extend_from_slice(self.vault_key.as_bytes());

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::fill(&mut nonce_bytes);
        let nonce = Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| EnrolmentError::Seal {
            cause: "the nonce had the wrong length".to_string(),
        })?;

        let cipher = vault_cipher(&derived);
        let aad = binding.encode(ENROLMENT_VERSION)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| EnrolmentError::Seal {
                cause: "the vault did not encrypt".to_string(),
            })?;

        Ok(SealedVault {
            version: ENROLMENT_VERSION,
            salt,
            nonce: nonce_bytes,
            ciphertext,
        })
    }
}

/// # Scoped key use
///
/// The vault's halves are reachable only through these two closures.
impl UserVault {
    /// Use the Ed25519 seed without letting it outlive the call.
    pub fn with_signing_secret<R>(&self, f: impl FnOnce(&[u8; KEY_LEN]) -> R) -> R {
        self.signing.with_secret(f)
    }

    /// Use the X25519 secret without letting it outlive the call.
    pub fn with_recipient_secret<R>(&self, f: impl FnOnce(&[u8; KEY_LEN]) -> R) -> R {
        self.recipient.with_secret(f)
    }

    /// Run a closure with the user's signing key, borrowed for one call.
    ///
    /// A user signs its own leases: the deletion intent and the delivery artifact
    /// are statements by the principal who owns the record, and a verifier pins
    /// her public key from the policy. Handing out the seed instead would let a
    /// caller hold a copy outside the vault; this keeps the key inside the call.
    pub fn with_signing_key<R>(&self, f: impl FnOnce(&SigningSecretKey) -> R) -> R {
        self.signing.with_secret(|seed| {
            let key = SigningSecretKey::from_secret_bytes(seed);
            f(&key)
        })
    }
}

impl std::fmt::Debug for UserVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserVault(<redacted>)")
    }
}

/// What a sealed vault is bound to: the identity and the two key IDs.
///
/// Bound as associated data, so a sealed vault transplanted onto another
/// identity fails to open rather than silently opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultBinding {
    /// The user the vault belongs to.
    pub identity: ActorId,
    /// The ID that names the signing key.
    pub signing_key_id: KeyId,
    /// The ID that names the recipient key.
    pub recipient_key_id: KeyId,
}

impl VaultBinding {
    /// The canonical encoding used as the AEAD's associated data.
    ///
    /// `version` is the version of the vault being sealed or opened, not the
    /// constant: relabelling a sealed vault then changes its associated data
    /// and the vault fails to authenticate, instead of passing as the current
    /// format.
    fn encode(&self, version: u16) -> Result<Vec<u8>, EnrolmentError> {
        #[derive(Serialize)]
        struct Aad<'a> {
            domain: &'a [u8],
            version: u16,
            identity_kind: &'a str,
            identity_value: &'a str,
            signing_key_id: &'a str,
            recipient_key_id: &'a str,
        }

        let (kind, value) = identity_parts(&self.identity);
        cbor::encode(&Aad {
            domain: DOMAIN_VAULT_AAD,
            version,
            identity_kind: kind,
            identity_value: &value,
            signing_key_id: self.signing_key_id.as_str(),
            recipient_key_id: self.recipient_key_id.as_str(),
        })
        .map_err(|err| EnrolmentError::Encoding {
            cause: err.to_string(),
        })
    }
}

/// A user's vault, sealed under her password.
///
/// This is the only form of the vault that is ever written to disk: the
/// private halves and the UVK exist in the clear only while the vault is open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedVault {
    version: u16,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl SealedVault {
    /// The per-vault salt.
    ///
    /// Exposed so a test can assert two vaults use different salts. It is not a
    /// secret.
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// The wire version.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Reopen the vault with the password it was sealed under.
    pub fn unseal(
        &self,
        password: &[u8],
        binding: &VaultBinding,
    ) -> Result<UserVault, EnrolmentError> {
        if self.version != ENROLMENT_VERSION {
            return Err(EnrolmentError::UnsupportedVersion {
                found: self.version,
                expected: ENROLMENT_VERSION,
            });
        }

        // The ciphertext of a vault is exactly three keys plus a tag. Checking
        // before decrypting means a hostile file cannot cost a full decryption
        // and allocation before being refused.
        if self.ciphertext.len() != KEY_LEN * 3 + TAG_LEN {
            return Err(EnrolmentError::Unseal {
                cause: "the sealed vault has the wrong length".to_string(),
            });
        }

        let derived = derive_key(password, &self.salt)?;

        let cipher = vault_cipher(&derived);
        let nonce = Nonce::try_from(self.nonce.as_slice()).map_err(|_| EnrolmentError::Unseal {
            cause: "the nonce had the wrong length".to_string(),
        })?;
        let aad = binding.encode(self.version)?;

        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &self.ciphertext,
                        aad: &aad,
                    },
                )
                // One error for a wrong password and for a transplant: the AEAD
                // cannot tell them apart, and reporting which would be an oracle.
                .map_err(|_| EnrolmentError::Unseal {
                    cause: "the vault did not authenticate under this password and binding"
                        .to_string(),
                })?,
        );

        if plaintext.len() != KEY_LEN * 3 {
            return Err(EnrolmentError::Unseal {
                cause: "the vault plaintext had the wrong length".to_string(),
            });
        }

        let mut signing_bytes = [0u8; KEY_LEN];
        signing_bytes.copy_from_slice(&plaintext[..KEY_LEN]);
        let mut recipient_bytes = [0u8; KEY_LEN];
        recipient_bytes.copy_from_slice(&plaintext[KEY_LEN..KEY_LEN * 2]);
        let mut vault_key_bytes = [0u8; VAULT_KEY_LEN];
        vault_key_bytes.copy_from_slice(&plaintext[KEY_LEN * 2..]);

        let signing = SigningSecretKey(ed25519_dalek::SigningKey::from_bytes(&signing_bytes));
        let recipient = RecipientSecretKey(x25519_dalek::StaticSecret::from(recipient_bytes));
        signing_bytes.zeroize_now();
        recipient_bytes.zeroize_now();

        let vault_key = VaultKey(Zeroizing::new(vault_key_bytes));
        vault_key_bytes.zeroize_now();

        Ok(UserVault {
            signing,
            recipient,
            vault_key,
        })
    }
}

/// Derive the vault's sealing key from the password and salt.
///
/// Argon2id with the crate's fixed defaults (19 456 KiB, 2 passes, 1 lane,
/// version 19). The parameters are a **configuration decision recorded here**,
/// not a measurement: changing them changes every vault's derived key, so they
/// are part of the format.
fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, EnrolmentError> {
    let mut derived = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::default()
        .hash_password_into(password, salt, derived.as_mut())
        .map_err(|_| EnrolmentError::Kdf {
            cause: "Argon2id refused the password or salt".to_string(),
        })?;
    Ok(derived)
}

/// The AEAD that seals a vault under a 32-byte KDF output.
fn vault_cipher(derived: &[u8; KEY_LEN]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(&Key::from(*derived))
}

/// The tag and value an identity contributes to a binding or a fingerprint.
fn identity_parts(identity: &ActorId) -> (&'static str, String) {
    match identity {
        ActorId::User(id) => ("user", id.to_string()),
        ActorId::Agent(id) => ("agent", id.to_string()),
        ActorId::Admin(id) => ("admin", id.to_string()),
    }
}

// ---------------------------------------------------------------------------
// The enrolment record
// ---------------------------------------------------------------------------

/// An identity's keys and key IDs, bound together by a fingerprint, before the
/// admin signs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedEnrolment {
    version: u16,
    identity: ActorId,
    signing_key: VerifyingPublicKey,
    recipient_key: RecipientPublicKey,
    signing_key_id: KeyId,
    recipient_key_id: KeyId,
    fingerprint: EnrolmentFingerprint,
}

impl UnsignedEnrolment {
    /// Bind an identity to both public keys and both key IDs.
    ///
    /// This is the only constructor, and it computes the fingerprint itself.
    /// A caller cannot supply a fingerprint that disagrees with the keys, which
    /// is how Misfit Q would otherwise slip through.
    pub fn bind(
        identity: ActorId,
        signing_key: VerifyingPublicKey,
        recipient_key: RecipientPublicKey,
        signing_key_id: KeyId,
        recipient_key_id: KeyId,
    ) -> Result<Self, EnrolmentError> {
        let subject = FingerprintSubject {
            identity,
            signing_key: signing_key.to_bytes(),
            recipient_key: recipient_key.to_bytes(),
            signing_key_id: signing_key_id.clone(),
            recipient_key_id: recipient_key_id.clone(),
        };
        let fingerprint =
            EnrolmentFingerprint::compute(&subject).map_err(|err| EnrolmentError::Encoding {
                cause: err.to_string(),
            })?;
        Ok(Self {
            version: ENROLMENT_VERSION,
            identity,
            signing_key,
            recipient_key,
            signing_key_id,
            recipient_key_id,
            fingerprint,
        })
    }

    /// The binding fingerprint.
    pub fn fingerprint(&self) -> &EnrolmentFingerprint {
        &self.fingerprint
    }

    /// The identity.
    pub fn identity(&self) -> &ActorId {
        &self.identity
    }

    /// The Ed25519 public key.
    pub fn signing_key(&self) -> &VerifyingPublicKey {
        &self.signing_key
    }

    /// The X25519 public key.
    pub fn recipient_key(&self) -> &RecipientPublicKey {
        &self.recipient_key
    }

    /// The signing key's ID.
    pub fn signing_key_id(&self) -> &KeyId {
        &self.signing_key_id
    }

    /// The recipient key's ID.
    pub fn recipient_key_id(&self) -> &KeyId {
        &self.recipient_key_id
    }

    /// The wire version.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// The canonical bytes the admin signs.
    fn signing_preimage(&self) -> Result<Vec<u8>, EnrolmentError> {
        let body = cbor::encode(self).map_err(|err| EnrolmentError::Encoding {
            cause: err.to_string(),
        })?;
        let mut preimage = Vec::with_capacity(DOMAIN_ENROLMENT.len() + body.len());
        preimage.extend_from_slice(DOMAIN_ENROLMENT);
        preimage.extend_from_slice(&body);
        Ok(preimage)
    }

    /// Compute the fingerprint this record's own keys produce.
    fn recompute_fingerprint(&self) -> Result<EnrolmentFingerprint, EnrolmentError> {
        EnrolmentFingerprint::compute(&FingerprintSubject {
            identity: self.identity,
            signing_key: self.signing_key.to_bytes(),
            recipient_key: self.recipient_key.to_bytes(),
            signing_key_id: self.signing_key_id.clone(),
            recipient_key_id: self.recipient_key_id.clone(),
        })
        .map_err(|err| EnrolmentError::Encoding {
            cause: err.to_string(),
        })
    }
}

/// The admin's Ed25519 signing key.
///
/// It signs enrolment records and nothing else. It exposes no decryption
/// operation and cannot derive any user's key (FR-001).
///
/// There is no method that opens a vault, and no method that produces a
/// recipient secret from the admin's signing secret:
///
/// ```compile_fail
/// use ksp_identity::{AdminSigningKey, VaultBinding};
///
/// let admin = AdminSigningKey::generate();
/// let binding = VaultBinding {
///     identity: ksp_types::ActorId::User(
///         ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
///     ),
///     signing_key_id: ksp_identity::KeyId::new("alice-ed25519-1"),
///     recipient_key_id: ksp_identity::KeyId::new("alice-x25519-1"),
/// };
/// // No such method: the admin holds nothing a vault opens with.
/// let _ = admin.unseal(b"correct horse battery staple", &binding);
/// ```
///
/// And the admin's public key is not a recipient key:
///
/// ```compile_fail
/// use ksp_identity::{AdminSigningKey, RecipientPublicKey};
///
/// let admin = AdminSigningKey::generate();
/// let _: RecipientPublicKey = admin.verifying_public();
/// ```
pub struct AdminSigningKey(SigningSecretKey);

impl AdminSigningKey {
    /// Generate a fresh admin signing key.
    pub fn generate() -> Self {
        Self(SigningSecretKey::generate())
    }

    /// The admin's public key — the trust anchor a verifier pins.
    pub fn verifying_public(&self) -> VerifyingPublicKey {
        self.0.verifying_public()
    }

    /// Sign a fully-formed, domain-separated preimage.
    ///
    /// Crate-internal: the policy body signs through this, and nothing else does.
    /// A delivery token, a deletion intent and an arming record are signed by the
    /// key of the principal that acts — the user's for her own lease, the agent's
    /// for its report — so a public raw-signing oracle on the *admin* key would be
    /// the unconstrained authority FR-001 rules out.
    pub(crate) fn sign_bytes(&self, preimage: &[u8]) -> EnrolmentSignature {
        EnrolmentSignature::from_bytes(self.0.sign(preimage))
    }

    /// Sign an enrolment record.
    pub fn sign_enrolment(
        &self,
        unsigned: UnsignedEnrolment,
        issuer_key_id: KeyId,
    ) -> Result<EnrollmentRecord, EnrolmentError> {
        // `UnsignedEnrolment` is public and deserializable, so a caller can hand
        // us one whose fingerprint was computed over a different subject. A
        // signature would make that lie authoritative; refuse to mint it.
        let recomputed = unsigned.recompute_fingerprint()?;
        if !recomputed.matches(unsigned.fingerprint()) {
            return Err(EnrolmentError::BindingMismatch);
        }

        let signature = self.0.sign(&unsigned.signing_preimage()?);
        Ok(EnrollmentRecord {
            unsigned,
            issuer_key_id,
            issuer_signature: EnrolmentSignature::from_bytes(signature),
        })
    }

    /// Rebuild the admin key from its 32-byte seed.
    ///
    /// Crate-internal: the durable key bundle is the only caller. A public
    /// constructor would let any caller present a signing key as the admin's
    /// without the pinned anchor agreeing.
    pub(crate) fn from_secret_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        Self(SigningSecretKey::from_secret_bytes(bytes))
    }

    /// The 32-byte seed, for the durable key bundle.
    ///
    /// Crate-internal so the admin's private half is written only by the
    /// bundle that pins it to its public anchor.
    pub(crate) fn to_secret_bytes(&self) -> [u8; KEY_LEN] {
        self.0.to_secret_bytes()
    }
}

/// An identity's public keys, key IDs and fingerprint, signed by the admin.
///
/// This is the trust anchor an agent verifies against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentRecord {
    unsigned: UnsignedEnrolment,
    issuer_key_id: KeyId,
    issuer_signature: EnrolmentSignature,
}

/// The admin's signature over an enrolment record.
///
/// An alias rather than a second type: a signature is the same 64-byte Ed25519
/// value whatever structure it covers, and one length check is one place to be
/// right.
pub type EnrolmentSignature = crate::signature::Ed25519Signature;

impl EnrollmentRecord {
    /// The bound identity, keys, key IDs and fingerprint.
    pub fn enrolment(&self) -> &UnsignedEnrolment {
        &self.unsigned
    }

    /// The binding fingerprint.
    pub fn fingerprint(&self) -> &EnrolmentFingerprint {
        self.unsigned.fingerprint()
    }

    /// The identity this record enrolls.
    pub fn identity(&self) -> &ActorId {
        self.unsigned.identity()
    }

    /// The Ed25519 public key.
    pub fn signing_key(&self) -> &VerifyingPublicKey {
        self.unsigned.signing_key()
    }

    /// The X25519 public key.
    pub fn recipient_key(&self) -> &RecipientPublicKey {
        self.unsigned.recipient_key()
    }

    /// The ID of the admin key that signed this record.
    pub fn issuer_key_id(&self) -> &KeyId {
        &self.issuer_key_id
    }

    /// The admin's signature over the record.
    pub fn issuer_signature(&self) -> &EnrolmentSignature {
        &self.issuer_signature
    }

    /// The fingerprint re-derived from this record's own identity, keys and key IDs.
    ///
    /// Distinct from [`fingerprint`](Self::fingerprint), which is the value the
    /// record *claims*. A record deserialized from a file can carry a genuine
    /// claimed fingerprint beside a substituted key, so anything that acts on a
    /// record's keys — sealing to its recipient key, for instance — must compare
    /// against this re-derived value and not against the claim.
    pub fn binding_fingerprint(&self) -> Result<EnrolmentFingerprint, EnrolmentError> {
        self.unsigned.recompute_fingerprint()
    }

    /// Whether the admin's signature over this record is valid.
    ///
    /// `admin` is the pinned trust anchor, never a key taken from the record.
    ///
    /// The record's own fingerprint is re-derived from its own keys first. A
    /// signature only says the admin approved *some* bytes; it does not say the
    /// fingerprint in those bytes describes the keys beside it. Since the
    /// fingerprint is the value that travels out of band and is later confirmed
    /// against a transferring peer, a record whose fingerprint is decorative
    /// would let a substitute key ride a fingerprint the user already trusts.
    pub fn verify_issuer(&self, admin: &VerifyingPublicKey) -> Result<(), ImportRefusal> {
        let recomputed = self
            .binding_fingerprint()
            .map_err(|err| ImportRefusal::Encoding {
                cause: err.to_string(),
            })?;
        if !recomputed.matches(self.unsigned.fingerprint()) {
            return Err(ImportRefusal::BindingMismatch);
        }

        let preimage = self
            .unsigned
            .signing_preimage()
            .map_err(|err| ImportRefusal::Encoding {
                cause: err.to_string(),
            })?;
        if admin.verify(&preimage, &self.issuer_signature.to_bytes()) {
            Ok(())
        } else {
            Err(ImportRefusal::IssuerSignature)
        }
    }
}

/// The import-time form of an enrolment record.
///
/// Every field is optional, because the record may have arrived from a store,
/// a file or a peer and may be truncated or hostile. [`TrustStore::import`]
/// validates presence before anything is trusted; the in-memory
/// [`EnrollmentRecord`] has no optional fields, so once a record is trusted it
/// cannot be half-present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentRecordWire {
    /// The wire version.
    pub version: u16,
    /// The identity the record enrolls.
    pub identity: Option<ActorId>,
    /// The Ed25519 public key, if present.
    pub signing_key: Option<VerifyingPublicKey>,
    /// The X25519 public key, if present.
    pub recipient_key: Option<RecipientPublicKey>,
    /// The ID naming the signing key, if present.
    pub signing_key_id: Option<KeyId>,
    /// The ID naming the recipient key, if present.
    pub recipient_key_id: Option<KeyId>,
    /// The claimed fingerprint, if present.
    pub fingerprint: Option<EnrolmentFingerprint>,
    /// The admin's signature, if present.
    pub issuer_signature: Option<EnrolmentSignature>,
    /// The ID of the admin key that signed the record, if present.
    pub issuer_key_id: Option<KeyId>,
}

impl EnrollmentRecordWire {
    /// The wire form of a signed record.
    pub fn from_record(record: &EnrollmentRecord) -> Self {
        Self {
            version: record.unsigned.version(),
            identity: Some(*record.unsigned.identity()),
            signing_key: Some(*record.unsigned.signing_key()),
            recipient_key: Some(*record.unsigned.recipient_key()),
            signing_key_id: Some(record.unsigned.signing_key_id().clone()),
            recipient_key_id: Some(record.unsigned.recipient_key_id().clone()),
            fingerprint: Some(*record.fingerprint()),
            issuer_signature: Some(record.issuer_signature),
            issuer_key_id: Some(record.issuer_key_id.clone()),
        }
    }
}

/// Why an unverified key was not imported.
///
/// Every variant names **what was missing or wrong**, because "import failed"
/// leaves the user unable to tell a truncated file from a substituted key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportRefusal {
    /// The Ed25519 public key was absent.
    #[error("the record binds no Ed25519 signing public key")]
    MissingSigningKey,
    /// The X25519 public key was absent.
    #[error("the record binds no X25519 recipient public key")]
    MissingRecipientKey,
    /// The signing key's ID was absent.
    #[error("the record binds no Ed25519 signing key ID")]
    MissingSigningKeyId,
    /// The recipient key's ID was absent.
    #[error("the record binds no X25519 recipient key ID")]
    MissingRecipientKeyId,
    /// The identity was absent.
    #[error("the record names no identity")]
    MissingIdentity,
    /// The fingerprint was absent.
    #[error("the record carries no fingerprint to confirm")]
    MissingFingerprint,
    /// The admin's signature was absent.
    #[error("the record carries no issuer signature")]
    MissingIssuerSignature,
    /// The issuer key's ID was absent.
    #[error("the record names no issuer key ID")]
    MissingIssuerKeyId,
    /// The record is a format version this build does not understand.
    #[error("the record is format version {found}, this build understands {expected}")]
    UnsupportedVersion {
        /// The version the record declares.
        found: u16,
        /// The version this build understands.
        expected: u16,
    },
    /// The record's own fingerprint does not match its keys and IDs.
    #[error("the record's fingerprint does not bind its own keys and key IDs")]
    BindingMismatch,
    /// The fingerprint does not match the one the user confirmed out of band.
    #[error("the fingerprint does not match the value confirmed out of band")]
    FingerprintMismatch,
    /// The admin's signature did not verify against the pinned anchor.
    #[error("the issuer signature did not verify against the pinned trust anchor")]
    IssuerSignature,
    /// The record's canonical encoding failed.
    #[error("the record could not be canonically encoded: {cause}")]
    Encoding {
        /// The encoder's reason.
        cause: String,
    },
}

/// The verified records this host trusts, keyed by identity.
///
/// A record enters only through [`import`](Self::import), and only after the
/// user's out-of-band fingerprint confirmation matches. There is no
/// `insert`, no `put`, and no way to add a key that was not confirmed.
pub struct TrustStore {
    admin: VerifyingPublicKey,
    records: BTreeMap<String, EnrollmentRecord>,
    retired: BTreeMap<String, Vec<EnrollmentRecord>>,
}

impl TrustStore {
    /// A store that trusts records signed by `admin`.
    ///
    /// `admin` is the pinned anchor. Nothing imported from a record can change
    /// it.
    pub fn new(admin: VerifyingPublicKey) -> Self {
        Self {
            admin,
            records: BTreeMap::new(),
            retired: BTreeMap::new(),
        }
    }

    /// Import a record the user confirmed out of band.
    ///
    /// Every check runs before the store is touched, so a refused import leaves
    /// the store exactly as it was.
    pub fn import(
        &mut self,
        wire: &EnrollmentRecordWire,
        confirmed: &EnrolmentFingerprint,
    ) -> Result<&EnrollmentRecord, ImportRefusal> {
        let record = build_record(wire, confirmed, &self.admin)?;

        // Only now, with presence, binding, confirmation and the issuer
        // signature all verified, does the store change.
        let key = record.identity().to_string();
        self.records.insert(key.clone(), record);
        self.records.get(&key).ok_or(ImportRefusal::MissingIdentity)
    }

    /// The trusted record for an identity, if one was imported.
    pub fn get(&self, identity: &ActorId) -> Option<&EnrollmentRecord> {
        self.records.get(&identity.to_string())
    }

    /// How many identities are trusted.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the store holds no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Adopt a rotated enrolment for an identity this store already trusts.
    ///
    /// Signing happens in the caller, which holds the admin's *private* key; the
    /// store holds only the admin's public key and adjudicates. That split is
    /// why this is not `import` with a shortcut: the authority is the anchor the
    /// user already confirmed at provisioning and it signed the new record, so
    /// there is no new principal and no new fingerprint to read out of band.
    ///
    /// The previous record is **kept**, in [`retired`](Self::retired). Rotation
    /// changes what future minting uses; it does not revoke anything already
    /// captured (FR-050, SC-018). An artifact sealed to the old recipient key
    /// still opens with the old key, and a store that forgot the old record
    /// would make that look like corruption.
    pub fn rotate(&mut self, next: &EnrollmentRecord, at: u64) -> Result<Rotation, EnrolmentError> {
        let identity = *next.identity();
        let key = identity.to_string();

        let previous =
            self.records
                .get(&key)
                .cloned()
                .ok_or_else(|| EnrolmentError::NotTrusted {
                    identity: key.clone(),
                })?;

        next.verify_issuer(&self.admin)
            .map_err(|err| EnrolmentError::Rotation {
                cause: err.to_string(),
            })?;

        if next.fingerprint() == previous.fingerprint() {
            return Err(EnrolmentError::RotationUnchanged);
        }

        self.records.insert(key.clone(), next.clone());
        self.retired.entry(key).or_default().push(previous.clone());

        Ok(Rotation {
            identity,
            previous,
            current: next.clone(),
            at,
        })
    }

    /// Enrolments this identity used before its latest rotation.
    ///
    /// Ordered oldest first. They authorise no new minting; they are kept
    /// because the artifacts they sealed are still openable.
    pub fn retired(&self, identity: &ActorId) -> &[EnrollmentRecord] {
        self.retired
            .get(&identity.to_string())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// What one rotation changed.
///
/// Both records, because neither alone is the whole truth: `current` is what
/// future minting uses, and `previous` is what still opens the artifacts that
/// were already delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    /// The identity whose keys changed.
    pub identity: ActorId,
    /// The enrolment that was trusted before.
    pub previous: EnrollmentRecord,
    /// The enrolment that is trusted now.
    pub current: EnrollmentRecord,
    /// When the rotation happened, as the caller's clock reported it.
    pub at: u64,
}

/// Validate a wire record and rebuild the trusted form.
///
/// Split out so the presence, binding and signature checks are one readable
/// sequence, and so a test can drive them without a store.
fn build_record(
    wire: &EnrollmentRecordWire,
    confirmed: &EnrolmentFingerprint,
    admin: &VerifyingPublicKey,
) -> Result<EnrollmentRecord, ImportRefusal> {
    // Before any field is trusted: a record from a newer format may mean
    // something entirely different by the fields below.
    if wire.version != ENROLMENT_VERSION {
        return Err(ImportRefusal::UnsupportedVersion {
            found: wire.version,
            expected: ENROLMENT_VERSION,
        });
    }

    let identity = wire.identity.ok_or(ImportRefusal::MissingIdentity)?;
    let signing_key = wire.signing_key.ok_or(ImportRefusal::MissingSigningKey)?;
    let recipient_key = wire
        .recipient_key
        .ok_or(ImportRefusal::MissingRecipientKey)?;
    let signing_key_id = wire
        .signing_key_id
        .clone()
        .ok_or(ImportRefusal::MissingSigningKeyId)?;
    let recipient_key_id = wire
        .recipient_key_id
        .clone()
        .ok_or(ImportRefusal::MissingRecipientKeyId)?;
    let claimed = wire.fingerprint.ok_or(ImportRefusal::MissingFingerprint)?;
    let issuer_signature = wire
        .issuer_signature
        .ok_or(ImportRefusal::MissingIssuerSignature)?;
    let issuer_key_id = wire
        .issuer_key_id
        .clone()
        .ok_or(ImportRefusal::MissingIssuerKeyId)?;

    // Bind from the *keys*, never from the claimed fingerprint: the record does
    // not get to say what it binds.
    let unsigned = UnsignedEnrolment::bind(
        identity,
        signing_key,
        recipient_key,
        signing_key_id,
        recipient_key_id,
    )
    .map_err(|err| ImportRefusal::Encoding {
        cause: err.to_string(),
    })?;

    if !unsigned.fingerprint().matches(&claimed) {
        return Err(ImportRefusal::BindingMismatch);
    }

    // The out-of-band confirmation. A fingerprint that omits a field, or covers
    // different keys, cannot match.
    if !unsigned.fingerprint().matches(confirmed) {
        return Err(ImportRefusal::FingerprintMismatch);
    }

    let record = EnrollmentRecord {
        unsigned,
        issuer_key_id,
        issuer_signature,
    };
    record.verify_issuer(admin)?;
    Ok(record)
}

// ---------------------------------------------------------------------------
// The agent enrolment path
// ---------------------------------------------------------------------------

/// An agent's own key pair: an independent Ed25519 signing key and an
/// independent X25519 recipient key.
///
/// The agent generates these itself. There is no shared symmetric secret
/// between an agent and the issuer, and the agent path needs no user vault and
/// no password — enrolling an agent never unseals anything.
pub struct AgentKeys {
    signing: SigningSecretKey,
    recipient: RecipientSecretKey,
}

impl AgentKeys {
    /// Generate a fresh agent key pair on the agent's own machine.
    pub fn generate() -> Self {
        Self {
            signing: SigningSecretKey::generate(),
            recipient: RecipientSecretKey::generate(),
        }
    }

    /// The agent's Ed25519 public key.
    pub fn signing_public(&self) -> VerifyingPublicKey {
        self.signing.verifying_public()
    }

    /// The agent's X25519 public key.
    pub fn recipient_public(&self) -> RecipientPublicKey {
        self.recipient.recipient_public()
    }

    /// Bind this agent's own keys and key IDs into an enrolment ready for the
    /// admin to sign.
    ///
    /// Takes no vault, no password and no user key material.
    pub fn enrol(
        &self,
        identity: ksp_types::AgentId,
        signing_key_id: KeyId,
        recipient_key_id: KeyId,
    ) -> Result<UnsignedEnrolment, EnrolmentError> {
        UnsignedEnrolment::bind(
            ActorId::Agent(identity),
            self.signing_public(),
            self.recipient_public(),
            signing_key_id,
            recipient_key_id,
        )
    }

    /// The signing half, for a caller that must sign with it.
    ///
    /// Crate-internal so that an agent's private half is reached only through
    /// the bundle that bound it to a verified identity.
    pub(crate) fn signing_secret(&self) -> &SigningSecretKey {
        &self.signing
    }

    /// The recipient half, for a caller that must unwrap with it.
    pub(crate) fn recipient_secret(&self) -> &RecipientSecretKey {
        &self.recipient
    }
}

impl std::fmt::Debug for AgentKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AgentKeys(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a vault or an enrolment could not be produced.
///
/// No variant carries key material: a `Display` implementation ends up in logs
/// and terminals.
#[derive(Debug, thiserror::Error)]
pub enum EnrolmentError {
    /// A 32-byte encoding was not a valid key.
    #[error("a key could not be decoded: {cause}")]
    KeyEncoding {
        /// Which encoding failed and why.
        cause: String,
    },
    /// The password was shorter than the minimum.
    #[error("the password must be at least {minimum} bytes")]
    PasswordTooShort {
        /// The minimum accepted length.
        minimum: usize,
    },
    /// Argon2id could not derive the sealing key.
    #[error("the key derivation failed: {cause}")]
    Kdf {
        /// The KDF's reason.
        cause: String,
    },
    /// The vault could not be sealed.
    #[error("the vault could not be sealed: {cause}")]
    Seal {
        /// What failed.
        cause: String,
    },
    /// The vault could not be opened.
    #[error("the vault could not be opened: {cause}")]
    Unseal {
        /// What failed.
        cause: String,
    },
    /// A canonical encoding failed.
    #[error("the structure could not be canonically encoded: {cause}")]
    Encoding {
        /// The encoder's reason.
        cause: String,
    },
    /// An enrolment's fingerprint does not bind its own keys.
    #[error("the enrolment's fingerprint does not bind its own keys")]
    BindingMismatch,
    /// The structure is a format version this build does not understand.
    #[error("the structure is format version {found}, this build understands {expected}")]
    UnsupportedVersion {
        /// The version the structure declares.
        found: u16,
        /// The version this build understands.
        expected: u16,
    },
    /// A rotation named an identity this store does not trust.
    #[error("identity {identity} is not trusted, so it cannot be rotated")]
    NotTrusted {
        /// The identity the rotation named.
        identity: String,
    },
    /// A rotation would have replaced an enrolment with itself.
    #[error("the rotation's enrolment is the one already trusted")]
    RotationUnchanged,
    /// A rotation's enrolment did not verify against the pinned anchor.
    #[error("the rotated enrolment could not be accepted: {cause}")]
    Rotation {
        /// Why the new record was refused.
        cause: String,
    },
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use ksp_types::{AgentId, PrincipalId};

    fn binding(user: &str) -> VaultBinding {
        VaultBinding {
            identity: ActorId::User(PrincipalId::parse(user).unwrap()),
            signing_key_id: KeyId::new("ed"),
            recipient_key_id: KeyId::new("x"),
        }
    }

    #[test]
    fn a_vault_seals_and_reopens() {
        let vault = UserVault::generate();
        let signing_public = vault.signing_public();
        let recipient_public = vault.recipient_public();
        let vault_key = vault.vault_key().as_bytes().to_owned();
        let bind = binding("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f");

        let sealed = vault.seal(b"correct horse battery", &bind).unwrap();
        let reopened = sealed.unseal(b"correct horse battery", &bind).unwrap();

        assert_eq!(reopened.signing_public(), signing_public);
        assert_eq!(reopened.recipient_public(), recipient_public);
        assert_eq!(reopened.vault_key().as_bytes(), &vault_key);
    }

    #[test]
    fn a_wrong_password_does_not_open_the_vault() {
        let vault = UserVault::generate();
        let bind = binding("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f");
        let sealed = vault.seal(b"correct horse battery", &bind).unwrap();
        assert!(sealed.unseal(b"wrong password here", &bind).is_err());
    }

    /// A sealed vault transplanted onto another identity must fail to open: the
    /// binding is authenticated data.
    #[test]
    fn a_vault_sealed_for_one_identity_does_not_open_for_another() {
        let vault = UserVault::generate();
        let sealed = vault
            .seal(
                b"correct horse battery",
                &binding("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f"),
            )
            .unwrap();
        assert!(
            sealed
                .unseal(
                    b"correct horse battery",
                    &binding("b0b00000-0000-4000-8000-000000000002")
                )
                .is_err(),
            "a vault must not open under another identity's binding"
        );
    }

    #[test]
    fn a_short_password_is_refused() {
        let vault = UserVault::generate();
        match vault.seal(b"short", &binding("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f")) {
            Err(EnrolmentError::PasswordTooShort { minimum }) => {
                assert_eq!(minimum, MIN_PASSWORD_LEN)
            }
            other => panic!("expected a password refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_two_keypairs_are_independent() {
        let vault = UserVault::generate();
        assert_ne!(
            vault.signing_public().to_bytes(),
            vault.recipient_public().to_bytes(),
            "the recipient key must not be the signing key"
        );
    }

    #[test]
    fn a_sealed_record_does_not_render_secrets_in_debug() {
        let vault = UserVault::generate();
        assert_eq!(format!("{vault:?}"), "UserVault(<redacted>)");
        assert_eq!(format!("{:?}", vault.vault_key()), "VaultKey(<redacted>)");
        assert_eq!(
            format!("{:?}", AgentKeys::generate()),
            "AgentKeys(<redacted>)"
        );
    }

    #[test]
    fn an_agent_enrols_with_its_own_key_ids() {
        let keys = AgentKeys::generate();
        let unsigned = keys
            .enrol(
                AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap(),
                KeyId::new("bot-ed"),
                KeyId::new("bot-x"),
            )
            .unwrap();
        assert_eq!(unsigned.signing_key_id().as_str(), "bot-ed");
        assert_eq!(unsigned.recipient_key_id().as_str(), "bot-x");
        assert_eq!(
            unsigned.identity(),
            &ActorId::Agent(AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap())
        );
    }
}
