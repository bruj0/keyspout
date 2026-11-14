//! Identity: fingerprint-bound enrolment, the user vault and agent keys.
//!
//! This crate answers the first half of "who is speaking?" — it enrols a user or
//! an agent, binds that identity to a fingerprint, and refuses any key that was
//! not confirmed against that fingerprint out of band. Sealing a delivery to the
//! resulting recipient key, and verifying a policy against the resulting trust
//! anchor, belong to later work packages; this one establishes the anchor.
//!
//! # Two misfits
//!
//! - **Misfit H (trust anchor substituted)** — an agent that fetches "Alice's
//!   public key" from the artifact it is verifying has verified nothing. A key
//!   becomes trusted only by being confirmed against a fingerprint the user read
//!   through a separate channel, and [`enrolment::TrustStore`] has no other way
//!   to admit one.
//! - **Misfit Q (key substitution)** — pairing a legitimate Ed25519 key with a
//!   substituted X25519 key must not pass. The two key types are distinct, so
//!   the substitution does not compile; the fingerprint covers both keys and
//!   both key IDs, so a substitution that somehow existed would still not match
//!   the confirmed value.
//!
//! # What is deliberately absent
//!
//! There is no code path that converts an Ed25519 key to an X25519 key, derives
//! one from the other, or accepts a `Vec<u8>` where a key is meant. The admin
//! holds a signing key that cannot decrypt anything (FR-001).

pub mod checkpoint;
pub mod delivery;
pub mod enrolment;
pub mod fingerprint;
pub mod header;
pub mod issuance;
pub mod key_bundle;
pub mod mint;
pub mod policy;
pub mod pop;
pub mod recovery;
pub mod run;
pub mod scope;
pub mod signature;
pub mod token;

pub use enrolment::{
    AdminSigningKey, AgentKeys, ENROLMENT_VERSION, EnrollmentRecord, EnrollmentRecordWire,
    EnrolmentError, EnrolmentSignature, ImportRefusal, KEY_LEN, MIN_PASSWORD_LEN, NONCE_LEN,
    RecipientPublicKey, RecipientSecretKey, Rotation, SALT_LEN, SIGNATURE_LEN, SealedVault,
    SigningSecretKey, TAG_LEN, TrustStore, UnsignedEnrolment, UserVault, VAULT_KEY_LEN,
    VaultBinding, VaultKey, VerifyingPublicKey,
};
pub use fingerprint::{
    EnrolmentFingerprint, FINGERPRINT_DOMAIN, FINGERPRINT_LEN, FINGERPRINT_VERSION,
    FingerprintError, FingerprintSubject, KeyId,
};
pub use key_bundle::{
    AdminKeyBundle, AdminSigningPin, AgentIdentityPin, AgentKeyBundle, BundleError,
    KEY_BUNDLE_VERSION,
};
pub use recovery::{
    RecoveryError, RecoveryPhrase, recover_vault_bundle, reshare_vault_bundle, split_vault_bundle,
};
pub use scope::{Caller, Request, Scope, ScopeRefusal, resolve};

pub use checkpoint::{CheckpointError, CheckpointStore, MemoryCheckpointStore, TrustedCheckpoint};
pub use delivery::{
    DeliveryArtifact, DeliveryError, DownstreamCopy, SelectedContentKeys, VerifiedDelivery,
    VerifiedRecipientKey, downstream_copy, open, seal, verify,
};
pub use header::{DeliveryHeader, HEADER_VERSION, HeaderError, SelectedRecord};
pub use issuance::{
    AdminRevocation, GrantWithdrawal, Issuance, IssuanceLedger, LedgerEntry, LedgerError,
    LedgerListing, LedgerState, PublishError, REVOCATION_REACH, RevocationError, RevocationMark,
    RevocationReason, TokenStanding, admin_revoke, ledger_scope,
};
pub use mint::{
    EXIT_INADMISSIBLE, EXIT_REFUSED, MintAuthority, MintBinding, MintOutcome, MintRefusal,
    MintRequest, arm, mint, sign_arm_record,
};
pub use policy::{
    Freshness, POLICY_VERSION, Policy, PolicyBody, PolicyRefusal, PolicyRequest, PolicyVerifier,
    TrustAnchors, TrustedEnrolmentKeys, VerificationOutcome, Withdrawal, decode_policy,
    encode_policy,
};
pub use token::{
    DeliveryEnvelope, Domain, TokenError, TokenSignature, sign_delivery, sign_with_domain,
    verify_delivery, verify_with_domain,
};

pub use pop::{
    ARGV_HASH_LEN, BUCKET_OFFSETS, BUCKET_SECONDS, PopError, PopPreimage, accepted_buckets,
    argv_hash, argv_hash_of, bucket_start, is_accepted, sign_pop, verify_pop,
};
pub use run::{
    EXIT_MISSING_KEY, EXIT_UNPROVEN, HostKeys, PresentedProof, RunOutcome, RunRefusal, RunRequest,
    verify_run,
};
