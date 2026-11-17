//! The principal registry: who belongs to this deployment, and which account is who.
//!
//! # Why this is in the store and not in a home
//!
//! One deployment has one store and N principals, each with its own home. A list
//! kept in one home would be readable only by that home's account, and the
//! principal it named first would be the only one able to verify a fingerprint or
//! answer "which agent belongs to whom". So the canonical list lives beside the
//! records it governs, at `p/<vault>/<admin>/principals.cbor`, and every principal
//! reads it.
//!
//! # What it is not
//!
//! It holds public material only: principal ids, display names, UNIX account
//! bindings, public keys and key ids. No private key, no password and no secret id
//! is here, which is why `0644` is not a weakening — the file a sibling can read
//! is one that protects nothing by being unreadable.
//!
//! # The binding is recorded, not derived
//!
//! `account` names the UNIX account that owns a principal's home. It is recorded
//! so that a deployment whose account was deleted can be told apart from one that
//! never named an account, and so a command can resolve *which* principal it is
//! acting for: two principals that resolved to one account would make every
//! command ambiguous, and guessing would mint a grant in the wrong principal's
//! name.

use std::path::{Path, PathBuf};

use ksp_identity::{KeyId, RecipientPublicKey, VerifyingPublicKey};
use ksp_types::{PrincipalId, VaultId};

use crate::config::Layout;

/// What a registry entry is allowed to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryRole {
    /// The one principal that signs policy, arming records and sweep proofs.
    Admin,
    /// A principal whose records the deployment holds.
    User,
}

/// One principal in the deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    /// The principal UUID every record path names.
    pub principal: PrincipalId,
    /// Admin or user.
    pub role: RegistryRole,
    /// Mutable display name. Metadata, never an identity.
    pub name: Option<String>,
    /// The UNIX account that owns this principal's home, when one was recorded.
    pub account: Option<String>,
    /// The ID this principal's Ed25519 key is enrolled under.
    pub signing_key_id: KeyId,
    /// The Ed25519 **public** key, as enrolled.
    pub signing_key: VerifyingPublicKey,
    /// The ID this principal's X25519 key is enrolled under.
    ///
    /// Absent until the principal's vault exists: the admin's own vault arrives
    /// with the publication path, and an entry written before it has no recipient
    /// key to name.
    pub recipient_key_id: Option<KeyId>,
    /// The X25519 **public** key, as enrolled.
    pub recipient_key: Option<RecipientPublicKey>,
}

/// The deployment's principals, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalRegistry {
    /// The vault every record lives in.
    pub vault: VaultId,
    /// The principal that signs policy. Exactly one.
    pub admin: PrincipalId,
    /// Every principal, admin first as written.
    pub entries: Vec<RegistryEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RegistryWire {
    version: u32,
    vault: String,
    admin: String,
    entries: Vec<EntryWire>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct EntryWire {
    principal: String,
    role: RegistryRole,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    account: Option<String>,
    signing_key_id: String,
    signing_key: [u8; 32],
    #[serde(default)]
    recipient_key_id: Option<String>,
    #[serde(default)]
    recipient_key: Option<[u8; 32]>,
}

/// The one format version this build writes and reads.
const REGISTRY_VERSION: u32 = 1;

/// Why the registry could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// No registry exists at the expected path.
    #[error(
        "this deployment holds no principal registry at {path}: run `ksp admin init` to create \
         one"
    )]
    Absent {
        /// The path that was read.
        path: String,
    },
    /// The registry exists and is not one this build wrote.
    #[error("the principal registry at {path} is not readable by this build")]
    Unreadable {
        /// The path that was read.
        path: String,
    },
    /// The registry could not be written.
    #[error("the principal registry at {path} could not be written")]
    Write {
        /// The path that was written.
        path: String,
    },
    /// A registry that names a second admin.
    #[error(
        "a deployment has exactly one admin principal, and this registry already names {principal}"
    )]
    SecondAdmin {
        /// The admin already recorded.
        principal: PrincipalId,
    },
    /// The entry names a principal this deployment does not hold.
    #[error("the principal {principal} is not a member of this deployment")]
    UnknownPrincipal {
        /// The principal that was looked for.
        principal: PrincipalId,
    },
    /// The entry names a principal the registry already holds.
    #[error("the principal {principal} is already a member of this deployment")]
    DuplicatePrincipal {
        /// The principal that was already recorded.
        principal: PrincipalId,
    },
}

/// A uid that resolves to no principal, or to more than one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrincipalError {
    /// The registry could not be read.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// No entry binds this account.
    #[error(
        "no principal in this deployment is bound to the account with uid {uid}: enrol it with \
         `ksp admin user add --unix-user <account>`, or run this command as a bound account"
    )]
    NoBinding {
        /// The effective uid.
        uid: u32,
    },
    /// More than one entry binds this account.
    #[error(
        "the account with uid {uid} is bound to {count} principals ({principals}): a command \
         cannot tell which one it acts for, so remove the duplicate binding before continuing"
    )]
    Ambiguous {
        /// The effective uid.
        uid: u32,
        /// How many entries matched.
        count: usize,
        /// Their principal ids, comma-separated.
        principals: String,
    },
}

impl PrincipalRegistry {
    /// Where the registry lives.
    ///
    /// In the store, under the admin principal, so every principal can reach a
    /// path it already knows.
    pub fn path_of(layout: &Layout, vault: &VaultId, admin: PrincipalId) -> PathBuf {
        layout
            .store_root()
            .join(ksp_record::RecordPath::directory(vault, admin, None))
            .join("principals.cbor")
    }

    /// Where this deployment's registry lives, read from its own record.
    ///
    /// A home that holds no deployment has no registry to point at, which is the
    /// `Absent` case rather than a guessed path.
    pub fn path(layout: &Layout) -> Result<PathBuf, RegistryError> {
        let deployment =
            crate::deployment::Deployment::load(layout).map_err(|_| RegistryError::Absent {
                path: layout.deployment_file().display().to_string(),
            })?;
        Ok(Self::path_of(layout, &deployment.vault, deployment.admin))
    }

    /// The registry a fresh deployment writes: one admin, no users.
    pub fn new(vault: VaultId, admin: RegistryEntry) -> Result<Self, RegistryError> {
        if admin.role != RegistryRole::Admin {
            return Err(RegistryError::UnknownPrincipal {
                principal: admin.principal,
            });
        }
        Ok(Self {
            vault,
            admin: admin.principal,
            entries: vec![admin],
        })
    }

    /// Read the registry this deployment names.
    pub fn load(layout: &Layout) -> Result<Self, RegistryError> {
        let path = Self::path(layout)?;
        Self::load_at(&path)
    }

    /// Read the registry at an explicit path.
    ///
    /// The caller that already resolved the path uses this rather than resolving
    /// it twice: two resolutions can disagree, and the disagreement would be
    /// reported as a missing registry.
    pub fn load_at(path: &Path) -> Result<Self, RegistryError> {
        let bytes = std::fs::read(path).map_err(|_| RegistryError::Absent {
            path: path.display().to_string(),
        })?;
        let wire: RegistryWire =
            ksp_types::cbor::decode(&bytes).map_err(|_| RegistryError::Unreadable {
                path: path.display().to_string(),
            })?;
        if wire.version != REGISTRY_VERSION {
            return Err(RegistryError::Unreadable {
                path: path.display().to_string(),
            });
        }
        let admin = PrincipalId::parse(&wire.admin).map_err(|_| RegistryError::Unreadable {
            path: path.display().to_string(),
        })?;
        let entries = wire
            .entries
            .into_iter()
            .map(|entry| {
                Ok(RegistryEntry {
                    principal: PrincipalId::parse(&entry.principal).map_err(|_| {
                        RegistryError::Unreadable {
                            path: path.display().to_string(),
                        }
                    })?,
                    role: entry.role,
                    name: entry.name,
                    account: entry.account,
                    signing_key_id: KeyId::new(entry.signing_key_id),
                    signing_key: VerifyingPublicKey::from_bytes(entry.signing_key).map_err(
                        |_| RegistryError::Unreadable {
                            path: path.display().to_string(),
                        },
                    )?,
                    recipient_key_id: entry.recipient_key_id.map(KeyId::new),
                    recipient_key: entry.recipient_key.map(RecipientPublicKey::from_bytes),
                })
            })
            .collect::<Result<Vec<_>, RegistryError>>()?;
        Ok(Self {
            vault: VaultId::new(wire.vault),
            admin,
            entries,
        })
    }

    /// Write the registry this deployment names, with the mode every principal
    /// can read it under.
    pub fn save(&self, layout: &Layout) -> Result<(), RegistryError> {
        let path = Self::path_of(layout, &self.vault, self.admin);
        self.save_at(&path, layout)
    }

    /// Write the registry at an explicit path.
    pub fn save_at(&self, path: &Path, layout: &Layout) -> Result<(), RegistryError> {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        if self.admin_entries().count() != 1 {
            return Err(match self.admin_entries().next() {
                Some(entry) => RegistryError::SecondAdmin {
                    principal: entry.principal,
                },
                None => RegistryError::Unreadable {
                    path: Self::path_of(layout, &self.vault, self.admin)
                        .display()
                        .to_string(),
                },
            });
        }
        // The principal directory is created by the layout table's mode helper, so
        // the file's own mode is the only number this function has to state.
        crate::layout::ensure_principal_root(layout, &self.vault, self.admin).map_err(|_| {
            RegistryError::Write {
                path: path.display().to_string(),
            }
        })?;
        let wire = RegistryWire {
            version: REGISTRY_VERSION,
            vault: self.vault.as_str().to_string(),
            admin: self.admin.to_string(),
            entries: self
                .entries
                .iter()
                .map(|entry| EntryWire {
                    principal: entry.principal.to_string(),
                    role: entry.role,
                    name: entry.name.clone(),
                    account: entry.account.clone(),
                    signing_key_id: entry.signing_key_id.as_str().to_string(),
                    signing_key: entry.signing_key.to_bytes(),
                    recipient_key_id: entry
                        .recipient_key_id
                        .as_ref()
                        .map(|id| id.as_str().to_string()),
                    recipient_key: entry.recipient_key.map(|key| key.to_bytes()),
                })
                .collect(),
        };
        let bytes = ksp_types::cbor::encode(&wire).map_err(|_| RegistryError::Write {
            path: path.display().to_string(),
        })?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(crate::layout::REGISTRY_FILE_MODE)
            .open(path)
            .map_err(|_| RegistryError::Write {
                path: path.display().to_string(),
            })?;
        file.write_all(&bytes).map_err(|_| RegistryError::Write {
            path: path.display().to_string(),
        })?;
        file.sync_all().map_err(|_| RegistryError::Write {
            path: path.display().to_string(),
        })?;
        // `open(2)`'s mode is masked by the caller's `umask`; the explicit call is
        // what makes `0644` a fact rather than an intention.
        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(crate::layout::REGISTRY_FILE_MODE),
        )
        .map_err(|_| RegistryError::Write {
            path: path.display().to_string(),
        })
    }

    /// The admin entries. A valid registry has exactly one.
    pub fn admin_entries(&self) -> impl Iterator<Item = &RegistryEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.role == RegistryRole::Admin)
    }

    /// The entry for one principal, if it belongs to this deployment.
    pub fn entry(&self, principal: PrincipalId) -> Option<&RegistryEntry> {
        self.entries
            .iter()
            .find(|entry| entry.principal == principal)
    }

    /// Add a user principal, refusing a second admin and a duplicate principal.
    pub fn append(&mut self, entry: RegistryEntry) -> Result<(), RegistryError> {
        if entry.role == RegistryRole::Admin {
            return Err(RegistryError::SecondAdmin {
                principal: self.admin,
            });
        }
        if self
            .entries
            .iter()
            .any(|held| held.principal == entry.principal)
        {
            return Err(RegistryError::UnknownPrincipal {
                principal: entry.principal,
            });
        }
        self.entries.push(entry);
        Ok(())
    }

    /// The entries bound to `uid`, by resolving each recorded account.
    ///
    /// Account resolution needs the host's account database, so this is a
    /// best-effort match: an account that no longer resolves simply cannot be the
    /// caller.
    pub fn entries_for_uid(&self, uid: u32) -> Vec<&RegistryEntry> {
        self.entries
            .iter()
            .filter(|entry| {
                entry
                    .account
                    .as_deref()
                    .and_then(account_uid)
                    .is_some_and(|bound| bound == uid)
            })
            .collect()
    }
}

/// The uid a named UNIX account has, or `None` when it does not resolve.
///
/// `id` with an argv and no shell. A name beginning with `-` is refused here
/// rather than handed to a tool that would read it as a flag.
fn account_uid(name: &str) -> Option<u32> {
    if name.is_empty() || name.starts_with('-') {
        return None;
    }
    let output = std::process::Command::new("/usr/bin/id")
        .args(["-u", name])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()?.trim().parse().ok()
}

/// Which principal this invocation acts for.
///
/// Resolved from the effective uid against the recorded account bindings. There
/// is no default principal and no environment override: a command that mints a
/// grant must not be able to name the wrong principal by being run from the wrong
/// directory or with a stray variable set.
pub fn acting_principal(layout: &Layout) -> Result<PrincipalId, PrincipalError> {
    let path = PrincipalRegistry::path(layout)?;
    acting_principal_at(layout, &path)
}

/// Which principal this invocation acts for, with the registry path already
/// resolved.
pub fn acting_principal_at(layout: &Layout, path: &Path) -> Result<PrincipalId, PrincipalError> {
    let registry = PrincipalRegistry::load_at(path)?;
    let _ = layout;
    let uid = ksp_posture::permissions::effective_uid();
    let matches = registry.entries_for_uid(uid);
    match matches.len() {
        1 => Ok(matches[0].principal),
        0 => Err(PrincipalError::NoBinding { uid }),
        count => Err(PrincipalError::Ambiguous {
            uid,
            count,
            principals: matches
                .iter()
                .map(|entry| entry.principal.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        }),
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::parse(&format!("{byte:02x}000000-0000-4000-8000-000000000001")).unwrap()
    }

    fn entry(byte: u8, role: RegistryRole, account: Option<&str>) -> RegistryEntry {
        let signing = ksp_identity::SigningSecretKey::generate();
        let recipient = ksp_identity::RecipientSecretKey::generate();
        RegistryEntry {
            principal: principal(byte),
            role,
            name: Some(format!("p{byte}")),
            account: account.map(str::to_string),
            signing_key_id: KeyId::new(format!("sign-{byte}")),
            signing_key: signing.verifying_public(),
            recipient_key_id: Some(KeyId::new(format!("recv-{byte}"))),
            recipient_key: Some(recipient.recipient_public()),
        }
    }

    fn layout() -> (tempfile::TempDir, Layout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path().join("home"));
        std::fs::create_dir_all(layout.root()).unwrap();
        (dir, layout)
    }

    #[test]
    fn a_registry_round_trips_at_the_shared_path() {
        let (_dir, layout) = layout();
        let registry = PrincipalRegistry::new(
            VaultId::new("vault-1"),
            entry(1, RegistryRole::Admin, Some("root")),
        )
        .unwrap();
        let path = PrincipalRegistry::path_of(&layout, &VaultId::new("vault-1"), registry.admin);
        registry.save_at(&path, &layout).unwrap();
        assert_eq!(PrincipalRegistry::load_at(&path).unwrap(), registry);
        assert!(path.ends_with("p/vault-1/01000000-0000-4000-8000-000000000001/principals.cbor"));
        // Every principal reads it, so its mode is checked rather than assumed.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn a_second_admin_is_refused() {
        let (_dir, _layout) = layout();
        let mut registry =
            PrincipalRegistry::new(VaultId::new("vault-1"), entry(1, RegistryRole::Admin, None))
                .unwrap();
        let error = registry
            .append(entry(2, RegistryRole::Admin, None))
            .unwrap_err();
        assert!(matches!(error, RegistryError::SecondAdmin { .. }));
    }

    #[test]
    fn two_users_are_accepted_and_one_principal_is_not_added_twice() {
        let (_dir, layout) = layout();
        let mut registry =
            PrincipalRegistry::new(VaultId::new("vault-1"), entry(1, RegistryRole::Admin, None))
                .unwrap();
        registry.append(entry(2, RegistryRole::User, None)).unwrap();
        registry.append(entry(3, RegistryRole::User, None)).unwrap();
        let path = PrincipalRegistry::path_of(&layout, &VaultId::new("vault-1"), registry.admin);
        registry.save_at(&path, &layout).unwrap();
        assert_eq!(PrincipalRegistry::load_at(&path).unwrap().entries.len(), 3);
        let error = registry
            .append(entry(2, RegistryRole::User, None))
            .unwrap_err();
        assert!(matches!(error, RegistryError::UnknownPrincipal { .. }));
    }

    #[test]
    fn an_entry_bound_to_the_calling_account_is_the_acting_principal() {
        let (_dir, layout) = layout();
        let me = std::process::Command::new("/usr/bin/id")
            .arg("-un")
            .output()
            .unwrap();
        let account = String::from_utf8(me.stdout).unwrap().trim().to_string();
        let registry = PrincipalRegistry::new(
            VaultId::new("vault-1"),
            entry(1, RegistryRole::Admin, Some(&account)),
        )
        .unwrap();
        registry.save(&layout).unwrap();
        assert_eq!(
            acting_principal_at(
                &layout,
                &PrincipalRegistry::path_of(&layout, &VaultId::new("vault-1"), registry.admin)
            )
            .unwrap(),
            principal(1)
        );
    }

    #[test]
    fn an_account_bound_twice_is_ambiguous_rather_than_guessed() {
        let (_dir, layout) = layout();
        let me = std::process::Command::new("/usr/bin/id")
            .arg("-un")
            .output()
            .unwrap();
        let account = String::from_utf8(me.stdout).unwrap().trim().to_string();
        let mut registry = PrincipalRegistry::new(
            VaultId::new("vault-1"),
            entry(1, RegistryRole::Admin, Some(&account)),
        )
        .unwrap();
        registry
            .append(entry(2, RegistryRole::User, Some(&account)))
            .unwrap();
        let path = PrincipalRegistry::path_of(&layout, &VaultId::new("vault-1"), registry.admin);
        registry.save_at(&path, &layout).unwrap();
        let error = acting_principal_at(&layout, &path).unwrap_err();
        assert!(
            matches!(error, PrincipalError::Ambiguous { count: 2, .. }),
            "{error}"
        );
    }

    #[test]
    fn an_unbound_account_is_refused_and_names_the_uid() {
        let (_dir, layout) = layout();
        let registry = PrincipalRegistry::new(
            VaultId::new("vault-1"),
            entry(1, RegistryRole::Admin, Some("nobody")),
        )
        .unwrap();
        let path = PrincipalRegistry::path_of(&layout, &VaultId::new("vault-1"), registry.admin);
        registry.save_at(&path, &layout).unwrap();
        let error = acting_principal_at(&layout, &path).unwrap_err();
        let uid = ksp_posture::permissions::effective_uid();
        // The invoking account is not `nobody`, so no binding matches it.
        assert!(
            matches!(error, PrincipalError::NoBinding { uid: got } if got == uid),
            "{error}"
        );
    }
}
