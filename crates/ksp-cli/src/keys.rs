//! What this host pinned, and what a later process reloads against.
//!
//! # Two different files, two different jobs
//!
//! The protected key file holds a private half and is written by S6 (WP15). The
//! pin holds only public material and is written here. Keeping them apart is the
//! point: one write that replaced both would swap a key and the value it is
//! verified against in a single step, and nothing would notice.
//!
//! # The anchor is the root
//!
//! [`Anchor`] is the admin's Ed25519 public key, pinned before any artifact is
//! read. A delivery's own signature proves the artifact is internally
//! consistent; only the anchor proves *who* sealed it.
//!
//! # What the enrolment pin can and cannot do
//!
//! [`StoredEnrolment`] is the fingerprint an agent printed at `agent enroll`. A
//! reload compares the key file against it, so a missing, truncated or swapped
//! *key file* refuses. It cannot stop an attacker who can rewrite the pin too —
//! that is host compromise, and no client-side check survives it. The design
//! says so plainly: mode `0600` restricts file access, it does not encrypt a key.

use std::path::Path;

use ksp_identity::{
    AgentIdentityPin, EnrolmentFingerprint, KeyId, RecipientPublicKey, VerifyingPublicKey,
};
use ksp_types::AgentId;

/// Why pinned material could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinError {
    /// The file is not there.
    #[error("no pinned material is stored at this location")]
    Absent,
    /// The bytes are not the structure this build writes.
    #[error("the stored pin is not readable")]
    Unreadable,
    /// The stored key material is not a valid public half.
    #[error("the stored public key is not a valid key")]
    InvalidKey,
    /// The deployment names no user signing key, so nothing can verify her leases.
    ///
    /// A deployment that never enrolled its user has no key to pin; a lease
    /// presented here cannot be checked, and saying "unreadable" would send the
    /// operator looking for a corrupt file instead of at the missing enrolment.
    #[error("this deployment records no user signing key, so a lease cannot be verified")]
    Unenrolled,
}

/// The admin public key this host trusts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// The key ID the anchor names.
    pub key_id: KeyId,
    /// The key itself.
    pub key: VerifyingPublicKey,
}

/// The public halves and fingerprint an `agent enroll` printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEnrolment {
    /// The agent's principal UUID. This is the identity; the name below is not.
    pub identity: AgentId,
    /// The mutable display name the operator enrolled under.
    ///
    /// Nothing security-relevant reads it: it exists so a human can tell two
    /// agents apart on screen, and changing it changes no key, path or grant.
    pub display_name: Option<String>,
    /// The Ed25519 public key.
    pub signing_key: VerifyingPublicKey,
    /// The X25519 public key.
    pub recipient_key: RecipientPublicKey,
    /// The ID naming the signing key.
    pub signing_key_id: KeyId,
    /// The ID naming the recipient key.
    pub recipient_key_id: KeyId,
    /// The fingerprint the operator read out of band.
    pub fingerprint: EnrolmentFingerprint,
}

impl StoredEnrolment {
    /// The pin a key-file reload is checked against.
    ///
    /// Every field is taken from this file, never from the bundle being loaded:
    /// a bundle that supplied its own pin would be checked against itself.
    pub fn pin(&self) -> AgentIdentityPin {
        AgentIdentityPin {
            identity: self.identity,
            signing_key_id: self.signing_key_id.clone(),
            recipient_key_id: self.recipient_key_id.clone(),
            signing_key: self.signing_key,
            recipient_key: self.recipient_key,
            confirmed_fingerprint: self.fingerprint,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredAnchorWire {
    key_id: String,
    key: [u8; 32],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredEnrolmentWire {
    identity_kind: String,
    identity_value: String,
    #[serde(default)]
    display_name: Option<String>,
    signing_key: [u8; 32],
    recipient_key: [u8; 32],
    signing_key_id: String,
    recipient_key_id: String,
    fingerprint: EnrolmentFingerprint,
}

impl Anchor {
    /// Read the pinned anchor.
    pub fn load(path: &Path) -> Result<Self, PinError> {
        let bytes = std::fs::read(path).map_err(|_| PinError::Absent)?;
        let wire: StoredAnchorWire =
            ksp_types::cbor::decode(&bytes).map_err(|_| PinError::Unreadable)?;
        Ok(Self {
            key_id: KeyId::new(wire.key_id),
            key: VerifyingPublicKey::from_bytes(wire.key).map_err(|_| PinError::InvalidKey)?,
        })
    }

    /// Pin an anchor.
    ///
    /// The anchor is public, but replacing it is the one write that would make
    /// every later verification meaningless, so it is owner-only and never
    /// created implicitly.
    pub fn save(&self, path: &Path) -> Result<(), PinError> {
        let wire = StoredAnchorWire {
            key_id: self.key_id.as_str().to_string(),
            key: self.key.to_bytes(),
        };
        let bytes = ksp_types::cbor::encode(&wire).map_err(|_| PinError::Unreadable)?;
        // A public key is not a secret, and every principal verifies against it:
        // a user-level `secret share` fails if only the admin can read the pin.
        // What protects the pin is not its mode but the fact that it names one
        // key, and a swapped anchor is refused by the deployment's key ID.
        write_with_mode(path, &bytes, crate::layout::PUBLIC_FILE_MODE)
    }
}

impl StoredEnrolment {
    /// Read a stored enrolment.
    pub fn load(path: &Path) -> Result<Self, PinError> {
        let bytes = std::fs::read(path).map_err(|_| PinError::Absent)?;
        let wire: StoredEnrolmentWire =
            ksp_types::cbor::decode(&bytes).map_err(|_| PinError::Unreadable)?;
        let identity = match wire.identity_kind.as_str() {
            "agent" => AgentId::parse(&wire.identity_value).map_err(|_| PinError::InvalidKey)?,
            // A user enrolment is not an agent pin, and pretending it is would
            // let the run path load a key it must never use.
            _ => return Err(PinError::InvalidKey),
        };
        Ok(Self {
            identity,
            display_name: wire.display_name,
            signing_key: VerifyingPublicKey::from_bytes(wire.signing_key)
                .map_err(|_| PinError::InvalidKey)?,
            recipient_key: RecipientPublicKey::from_bytes(wire.recipient_key),
            signing_key_id: KeyId::new(wire.signing_key_id),
            recipient_key_id: KeyId::new(wire.recipient_key_id),
            fingerprint: wire.fingerprint,
        })
    }

    /// Store the enrolment.
    pub fn save(&self, path: &Path) -> Result<(), PinError> {
        let wire = StoredEnrolmentWire {
            identity_kind: "agent".to_string(),
            identity_value: self.identity.to_string(),
            display_name: self.display_name.clone(),
            signing_key: self.signing_key.to_bytes(),
            recipient_key: self.recipient_key.to_bytes(),
            signing_key_id: self.signing_key_id.as_str().to_string(),
            recipient_key_id: self.recipient_key_id.as_str().to_string(),
            fingerprint: self.fingerprint,
        };
        let bytes = ksp_types::cbor::encode(&wire).map_err(|_| PinError::Unreadable)?;
        // `0644`, not owner-only: an enrolment pin is public keys, key IDs and a
        // fingerprint, and it is what a *reload* verifies against — including an
        // `audit verify` run by the admin over records an agent wrote. An
        // owner-only pin made a two-account deployment's log unverifiable outside
        // the account that enrolled the agent, which is the opposite of a pin.
        write_with_mode(path, &bytes, crate::layout::PUBLIC_FILE_MODE)
    }
}

/// Write `bytes` to `path`, owner-only, replacing any existing file.
pub(crate) fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), PinError> {
    write_with_mode(path, bytes, 0o600)
}

/// Write `bytes` to `path` with an explicit mode, replacing any existing file.
///
/// The mode is applied with `chmod` after the write because `OpenOptions::mode`
/// is masked by the process's `umask`: a policy that must be readable by every
/// principal would silently become owner-only on a host with `umask 0077`, and
/// the principal it was written *for* would be the one who could not read it.
pub(crate) fn write_with_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<(), PinError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    // The parent is a layout row (`admin/` or `enrolments/`), so its mode comes
    // from the table rather than from the process's `umask` (misfit B).
    crate::layout::ensure_known_parent(path).map_err(|_| PinError::Unreadable)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .map_err(|_| PinError::Unreadable)?;
    file.write_all(bytes).map_err(|_| PinError::Unreadable)?;
    file.sync_all().map_err(|_| PinError::Unreadable)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|_| PinError::Unreadable)
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn enrolment() -> StoredEnrolment {
        let keys = ksp_identity::AgentKeys::generate();
        let unsigned = keys
            .enrol(
                AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap(),
                KeyId::new("s-1"),
                KeyId::new("r-1"),
            )
            .unwrap();
        StoredEnrolment {
            identity: AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap(),
            display_name: Some("agent-7".to_string()),
            signing_key: *unsigned.signing_key(),
            recipient_key: *unsigned.recipient_key(),
            signing_key_id: KeyId::new("s-1"),
            recipient_key_id: KeyId::new("r-1"),
            fingerprint: *unsigned.fingerprint(),
        }
    }

    #[test]
    fn an_anchor_round_trips_and_is_public_but_not_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin/anchor.cbor");
        let admin = ksp_identity::AdminSigningKey::generate();
        let anchor = Anchor {
            key_id: KeyId::new("admin-2026"),
            key: admin.verifying_public(),
        };
        anchor.save(&path).unwrap();

        assert_eq!(Anchor::load(&path).unwrap(), anchor);
        // A public key every principal verifies against: readable by all, written
        // by one. `0600` here made a two-account deployment unreadable to the
        // principal the tokens are minted for.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, crate::layout::PUBLIC_FILE_MODE);
        assert_eq!(
            mode & 0o222,
            0o200,
            "the anchor must not be writable by others"
        );
    }

    #[test]
    fn an_enrolment_round_trips_into_the_same_pin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enrolments/agent-7.cbor");
        let stored = enrolment();
        stored.save(&path).unwrap();

        let loaded = StoredEnrolment::load(&path).unwrap();
        assert_eq!(loaded, stored);
        assert_eq!(loaded.pin().confirmed_fingerprint, stored.fingerprint);
        assert_eq!(
            loaded.pin().identity.to_string(),
            "00000000-0000-4000-8000-000000000007"
        );
    }

    #[test]
    fn an_absent_pin_is_absence_rather_than_a_default() {
        // The failure this exists for: inventing a pin from nothing would let a
        // reload pass against a key file nobody vouched for.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enrolments/agent-7.cbor");
        assert_eq!(StoredEnrolment::load(&path).unwrap_err(), PinError::Absent);
        assert_eq!(Anchor::load(&path).unwrap_err(), PinError::Absent);
    }
}
