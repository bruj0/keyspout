//! Which deployment this host belongs to.
//!
//! Three identifiers every record path and every policy names: the vault, the
//! user and the admin key ID. They are written once at `admin init` and read
//! back by every later command, so a command that needs them cannot invent one.
//!
//! This is deliberately not part of the sealed vault: the vault is an encrypted
//! blob, and the identifiers are needed *before* a password is supplied (a token
//! mint has to know which vault it is naming). Nothing here is secret.

use ksp_identity::KeyId;
use ksp_types::{PrincipalId, VaultId};

use crate::config::Layout;
use crate::keys::{Anchor, PinError};

/// The identifiers one deployment uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployment {
    /// The vault every record lives in.
    pub vault: VaultId,
    /// The principal UUID of the admin that initialised the deployment.
    ///
    /// Distinct from [`Self::user`]: the admin sweeps and signs the reports, the
    /// user owns the records. One human may hold both roles, and the identifiers
    /// still stay apart.
    pub admin: PrincipalId,
    /// The principal UUID of the user whose authority the records belong to.
    pub user: PrincipalId,
    /// The user's mutable display name.
    ///
    /// Metadata, never an identity: no path, binding or grant is derived from
    /// it, and changing it does not move a record.
    pub user_name: Option<String>,
    /// The UNIX account this principal is bound to, when it is not the account
    /// that provisioned the deployment.
    ///
    /// A *binding*, not identity (FR-037): it is keyed by the principal UUID and
    /// names the host identity that owns the vault on the `file` backend. It is
    /// encrypted nowhere because it is not secret — and it is recorded rather
    /// than derived, so a deployment whose account no longer exists can be told
    /// apart from one that never named an account.
    pub user_account: Option<String>,
    /// The ID the admin key is pinned under.
    pub admin_key_id: KeyId,
    /// The ID the admin's **own vault** was enrolled under, when she has one.
    ///
    /// Distinct from [`Self::admin_key_id`]: that key signs policies and reports
    /// and lives in the keystore; this one is the admin's vault binding, and it
    /// exists so she can open her own records to publish them. Absent until
    /// `admin seal-vault` runs (CF-018).
    pub admin_vault_signing_key_id: Option<KeyId>,
    /// The ID the admin vault's X25519 key was enrolled under.
    pub admin_vault_recipient_key_id: Option<KeyId>,
    /// The admin vault's X25519 **public** key.
    ///
    /// Recorded so a publication can seal its content key to her without her
    /// password. Public material, and useless without the vault itself.
    pub admin_vault_recipient_key: Option<ksp_identity::RecipientPublicKey>,
    /// The ID the user's Ed25519 key was enrolled under.
    pub user_signing_key_id: Option<KeyId>,
    /// The user's Ed25519 **public** key, as enrolled.
    ///
    /// Recorded for the same reason as the recipient key: a policy that names her
    /// keys must not need her password to learn them (FR-020 — administration runs
    /// without any user password). Public, so it protects nothing by being here.
    pub user_signing_key: Option<ksp_identity::VerifyingPublicKey>,
    /// The ID the user's X25519 key was enrolled under.
    pub user_recipient_key_id: Option<KeyId>,
    /// The user's X25519 **public** key, as enrolled.
    ///
    /// Public, so it is not part of the sealed vault: `admin put` seals a record
    /// to it without her password, and a password it did not need would be a
    /// password asked for to protect nothing.
    pub user_recipient_key: Option<ksp_identity::RecipientPublicKey>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DeploymentWire {
    vault: String,
    admin: String,
    user: String,
    #[serde(default)]
    user_name: Option<String>,
    #[serde(default)]
    user_account: Option<String>,
    admin_key_id: String,
    #[serde(default)]
    admin_vault_signing_key_id: Option<String>,
    #[serde(default)]
    admin_vault_recipient_key_id: Option<String>,
    #[serde(default)]
    admin_vault_recipient_key: Option<[u8; 32]>,
    #[serde(default)]
    user_signing_key_id: Option<String>,
    #[serde(default)]
    user_signing_key: Option<[u8; 32]>,
    #[serde(default)]
    user_recipient_key_id: Option<String>,
    #[serde(default)]
    user_recipient_key: Option<[u8; 32]>,
}

impl Deployment {
    /// Read the deployment this host was initialised for.
    pub fn load(layout: &Layout) -> Result<Self, PinError> {
        let bytes = std::fs::read(layout.deployment_file()).map_err(|_| PinError::Absent)?;
        let wire: DeploymentWire =
            ksp_types::cbor::decode(&bytes).map_err(|_| PinError::Unreadable)?;
        Ok(Self {
            vault: VaultId::new(wire.vault),
            admin: PrincipalId::parse(&wire.admin).map_err(|_| PinError::Unreadable)?,
            user: PrincipalId::parse(&wire.user).map_err(|_| PinError::Unreadable)?,
            user_name: wire.user_name,
            user_account: wire.user_account,
            admin_key_id: KeyId::new(wire.admin_key_id),
            admin_vault_signing_key_id: wire.admin_vault_signing_key_id.map(KeyId::new),
            admin_vault_recipient_key_id: wire.admin_vault_recipient_key_id.map(KeyId::new),
            admin_vault_recipient_key: wire
                .admin_vault_recipient_key
                .map(ksp_identity::RecipientPublicKey::from_bytes),
            user_signing_key_id: wire.user_signing_key_id.map(KeyId::new),
            user_signing_key: wire
                .user_signing_key
                .map(ksp_identity::VerifyingPublicKey::from_bytes)
                .transpose()
                .map_err(|_| PinError::Unreadable)?,
            user_recipient_key_id: wire.user_recipient_key_id.map(KeyId::new),
            user_recipient_key: wire
                .user_recipient_key
                .map(ksp_identity::RecipientPublicKey::from_bytes),
        })
    }

    /// Record the deployment.
    ///
    /// `0644`, not owner-only: this file holds three identifiers and the user's
    /// *public* keys, and the user principal reads it before any password is
    /// supplied. A two-account deployment whose user cannot read the record of
    /// her own keys cannot open her vault, and the fix is not to hand her the
    /// provisioning account.
    pub fn save(&self, layout: &Layout) -> Result<(), PinError> {
        let wire = DeploymentWire {
            vault: self.vault.as_str().to_string(),
            admin: self.admin.to_string(),
            user: self.user.to_string(),
            user_name: self.user_name.clone(),
            user_account: self.user_account.clone(),
            admin_key_id: self.admin_key_id.as_str().to_string(),
            admin_vault_signing_key_id: self
                .admin_vault_signing_key_id
                .as_ref()
                .map(|id| id.as_str().to_string()),
            admin_vault_recipient_key_id: self
                .admin_vault_recipient_key_id
                .as_ref()
                .map(|id| id.as_str().to_string()),
            admin_vault_recipient_key: self.admin_vault_recipient_key.map(|key| key.to_bytes()),
            user_signing_key_id: self
                .user_signing_key_id
                .as_ref()
                .map(|id| id.as_str().to_string()),
            user_signing_key: self.user_signing_key.map(|key| key.to_bytes()),
            user_recipient_key_id: self
                .user_recipient_key_id
                .as_ref()
                .map(|id| id.as_str().to_string()),
            user_recipient_key: self.user_recipient_key.map(|key| key.to_bytes()),
        };
        let bytes = ksp_types::cbor::encode(&wire).map_err(|_| PinError::Unreadable)?;
        let path = layout.deployment_file();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| PinError::Unreadable)?;
        }
        crate::keys::write_with_mode(&path, &bytes, crate::layout::PUBLIC_FILE_MODE)
    }

    /// The pinned anchor, which must name the same key ID.
    pub fn anchor(layout: &Layout) -> Result<Anchor, PinError> {
        Anchor::load(&layout.admin_anchor_file())
    }
}

/// The deployment, or the reason it is not there.
/// The user's enrolled signing key, which verifies the leases she signs.
///
/// Public and recorded at enrolment. A lease and the intent beside it are signed
/// by the principal whose record is being shared — never by the admin, who signed
/// the policy and takes no part in the delivery — so this is the key a verifier
/// pins.
pub fn user_verifying_key(layout: &Layout) -> Result<ksp_identity::VerifyingPublicKey, PinError> {
    Deployment::load(layout)?
        .user_signing_key
        .ok_or(PinError::Unenrolled)
}

/// The deployment and its pinned anchor, which must name the same admin key.
pub fn require(layout: &Layout) -> Result<(Deployment, Anchor), PinError> {
    let deployment = Deployment::load(layout)?;
    let anchor = Deployment::anchor(layout)?;
    // A deployment whose ID and anchor disagree would seal records under one
    // identity and verify tokens against another's key.
    if anchor.key_id != deployment.admin_key_id {
        return Err(PinError::InvalidKey);
    }
    Ok((deployment, anchor))
}

/// Whether the account a binding names still resolves on this host (FR-023).
///
/// `id` rather than `/etc/passwd`: the question is whether the account exists for
/// the system's own resolver, and a name beginning with `-` is refused here rather
/// than handed to a tool that would read it as a flag. argv, never a shell, so the
/// name cannot become a command.
pub(crate) fn account_resolves(name: &str) -> bool {
    if name.is_empty() || name.starts_with('-') {
        return false;
    }
    std::process::Command::new("/usr/bin/id")
        .args(["-u", name])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn deployment() -> Deployment {
        Deployment {
            vault: VaultId::new("vault-1"),
            admin: PrincipalId::parse("b0b00000-0000-4000-8000-000000000001").unwrap(),
            user: PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
            user_name: Some("alice".to_string()),
            user_account: None,
            admin_key_id: KeyId::new("admin-2026"),
            admin_vault_signing_key_id: None,
            admin_vault_recipient_key_id: None,
            admin_vault_recipient_key: None,
            user_signing_key_id: None,
            user_signing_key: None,
            user_recipient_key_id: None,
            user_recipient_key: None,
        }
    }

    #[test]
    fn a_deployment_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        let stored = deployment();
        stored.save(&layout).unwrap();
        assert_eq!(Deployment::load(&layout).unwrap(), stored);
    }

    #[test]
    fn an_anchor_that_names_a_different_key_id_is_refused() {
        // The failure this exists for: a deployment file and an anchor from two
        // different installations, which would mint under one identity and
        // verify under another.
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        deployment().save(&layout).unwrap();

        let admin = ksp_identity::AdminSigningKey::generate();
        Anchor {
            key_id: KeyId::new("some-other-key"),
            key: admin.verifying_public(),
        }
        .save(&layout.admin_anchor_file())
        .unwrap();

        assert_eq!(require(&layout).unwrap_err(), PinError::InvalidKey);
    }
}
