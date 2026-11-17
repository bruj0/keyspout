//! Where the two ledgers live, and who may write each one.
//!
//! # Why this is a module and not two `Layout` methods
//!
//! A ledger's path names a **principal**, and the layout does not know one: the
//! issuance history belongs to the user who minted, the withdrawals to the admin who
//! decided. `Layout` can therefore only say "beside this home", which is what both
//! files used to be and what makes them unreadable to the other principal once the
//! store is shared (RP1, L1).
//!
//! # One writer, one file
//!
//! The two files never share a directory: a single `0600`-ish directory would give
//! both writers access to both files, and a ledger two accounts can append to is a
//! ledger whose order nobody can defend. Each file sits under the principal that
//! writes it and is `0640`, so the other reads through the store's group — `run` has
//! to see a withdrawal, and the admin's `audit verify` has to see an issuance.

use std::path::PathBuf;

use ksp_types::{PrincipalId, VaultId};

use crate::config::Layout;

/// Why the two ledger paths could not be discovered.
///
/// Each message names the accepted shape, because the caller's next question is which
/// value it was supposed to supply: a vault with no registry, a registry outside its
/// admin's directory, a registry that names the caller as its own admin, or one that does
/// not carry the pinned key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerPathsError {
    /// No registry was found under the vault's principals.
    #[error(
        "no principal registry exists under {path}, so the two ledger paths for vault {vault} cannot be resolved; the accepted shape is p/<vault>/<admin>/principals.cbor"
    )]
    NoRegistry {
        /// The vault whose registry is missing.
        vault: String,
        /// The directory that was searched.
        path: String,
    },
    /// A registry exists and cannot be read.
    #[error("the principal registry at {path} could not be read: {cause}")]
    Unreadable {
        /// The registry that was read.
        path: String,
        /// Why it refused.
        cause: String,
    },
    /// A registry was found outside the directory of the admin it names.
    #[error(
        "the registry at {path} names admin {admin} but does not live in that principal's own directory; the accepted shape is p/<vault>/<admin>/principals.cbor, because a registry in another principal's directory is one she can write"
    )]
    Planted {
        /// The registry that was found.
        path: String,
        /// The admin it claims.
        admin: String,
    },
    /// The registry names the caller's own principal as the admin.
    #[error(
        "the registry for vault {vault} names the calling user as its own admin; the accepted shape has two principals, so a registry that collapses them cannot be used to locate the admin's ledger"
    )]
    UserIsAdmin {
        /// The vault whose registry is malformed.
        vault: String,
    },
    /// The registry's admin entry does not carry the pinned anchor's key.
    #[error(
        "the registry at {path} does not carry the pinned admin key, so it belongs to another deployment and the ledger it would name is not this deployment's"
    )]
    ForeignRegistry {
        /// The registry that was found.
        path: String,
    },
}

/// The file the user principal appends her mint history to.
pub const ISSUANCE_FILE: &str = "issuance.jsonl";

/// The file the admin principal appends her withdrawals to.
pub const POLICY_EVENTS_FILE: &str = "policy-events.jsonl";

/// Both ledgers' paths, resolved once.
///
/// Resolved rather than derived at each read: a reader that rebuilt the path from a
/// different principal would read a different file and report an absent history as an
/// empty one, which is CF-014's shape — "not there" and "nothing recorded" are not the
/// same answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerPaths {
    issuance: PathBuf,
    policy_events: PathBuf,
}

impl LedgerPaths {
    /// The paths a deployment record names.
    pub fn for_deployment(layout: &Layout, deployment: &crate::deployment::Deployment) -> Self {
        Self::for_principals(layout, &deployment.vault, deployment.user, deployment.admin)
    }

    /// The paths for one vault and one user, with the admin authenticated, not merely found.
    ///
    /// This exists for a host that holds the store but no deployment record — an agent's
    /// host — and it takes the **user** as an argument rather than guessing: a vault can
    /// name more than one user principal, and picking one would name the wrong ledger
    /// directory and read its absence as "nothing recorded".
    ///
    /// # Why the first registry found is not believed
    ///
    /// A `principals.cbor` is an unauthenticated file inside a directory one principal
    /// owns. Reading whichever one `read_dir` produced first would let that principal
    /// plant a registry naming an admin of her choosing, and `run` would then read a
    /// ledger nobody wrote — reporting "not revoked" on the strength of an empty file,
    /// which is the one claim a withdrawal record exists to prevent (misfit D).
    ///
    /// Three facts are required, and each closes one way of placing a file elsewhere:
    ///
    /// 1. the registry sits in the directory **named for the admin it names**, so it is
    ///    that principal's own copy and not a neighbour's;
    /// 2. that admin is **not the caller's user**, so the copy is not hers to write;
    /// 3. the admin's entry carries the **pinned anchor's key**, so the registry is this
    ///    deployment's rather than a stranger's.
    ///
    /// Together with the store's own modes — `p/<vault>/` is `0711` and belongs to
    /// whoever provisioned the vault — a principal can neither create a directory
    /// beside her own nor rename hers, so she cannot satisfy (1) and (2) with a
    /// directory she controls.
    pub fn discover(
        layout: &Layout,
        vault: &VaultId,
        user: PrincipalId,
        anchor: &crate::keys::Anchor,
    ) -> Result<Self, LedgerPathsError> {
        // The recorded path first, and the listing only when there is no record to
        // read. `deployment.cbor` is public to the deployment and the directory chain
        // is `0711`, so every principal can *reach*
        // `p/<vault>/<admin>/principals.cbor`. Listing `p/<vault>/` is a different
        // question, and the answer is no: the directory belongs to the admin, `0711`
        // is traverse-without-list by design, and discovering by listing refused
        // `secret share` in every two-account deployment with "no principal registry
        // exists" while the registry sat where the record said it would (CF-106).
        let recorded = crate::registry::PrincipalRegistry::path(layout).ok();
        let root = layout.store_root().join("p").join(vault.as_str());
        if let Some(candidate) = recorded.as_deref()
            && let Some(found) = Self::believe(layout, candidate, vault, user, anchor)?
        {
            return Ok(found);
        }
        // A host that holds the store and no record — an agent's own host — has no
        // path to read, so the listing is the only route it has. The three placement
        // checks still run, which is what keeps a planted registry from being believed.
        let entries = std::fs::read_dir(&root).map_err(|_| LedgerPathsError::NoRegistry {
            vault: vault.as_str().to_string(),
            path: root.display().to_string(),
        })?;
        for entry in entries.flatten() {
            let candidate = entry.path().join("principals.cbor");
            if !candidate.is_file() {
                continue;
            }
            if let Some(found) = Self::believe(layout, &candidate, vault, user, anchor)? {
                return Ok(found);
            }
        }
        Err(LedgerPathsError::NoRegistry {
            vault: vault.as_str().to_string(),
            path: root.display().to_string(),
        })
    }

    /// The paths, if the registry at `candidate` passes all three placement checks.
    ///
    /// `Ok(None)` means the file is not there, which is the case a caller answers by
    /// trying elsewhere; every other way of failing to believe it is an error, because
    /// a registry that is present and wrong is evidence rather than absence.
    fn believe(
        layout: &Layout,
        candidate: &std::path::Path,
        vault: &VaultId,
        user: PrincipalId,
        anchor: &crate::keys::Anchor,
    ) -> Result<Option<Self>, LedgerPathsError> {
        if !candidate.is_file() {
            return Ok(None);
        }
        let registry = crate::registry::PrincipalRegistry::load_at(candidate).map_err(|error| {
            LedgerPathsError::Unreadable {
                path: candidate.display().to_string(),
                cause: error.to_string(),
            }
        })?;
        let admin = registry.admin;
        if !candidate
            .parent()
            .and_then(|directory| directory.file_name())
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == admin.to_string())
        {
            return Err(LedgerPathsError::Planted {
                path: candidate.display().to_string(),
                admin: admin.to_string(),
            });
        }
        if admin == user {
            return Err(LedgerPathsError::UserIsAdmin {
                vault: vault.as_str().to_string(),
            });
        }
        if !registry
            .entry(admin)
            .is_some_and(|recorded| recorded.signing_key == anchor.key)
        {
            return Err(LedgerPathsError::ForeignRegistry {
                path: candidate.display().to_string(),
            });
        }
        // Tested last, and it answers "not this one" rather than "refused". The three
        // checks above decide whether a file *is* a registry of this deployment; this one
        // asks whether it is a registry of the asked-about vault, and the recorded path
        // starts from the deployment rather than from the caller's argument. Without it a
        // question about `vault-a` would be answered with `vault-b`'s ledger paths.
        if &registry.vault != vault {
            return Ok(None);
        }
        Ok(Some(Self::for_principals(layout, vault, user, admin)))
    }

    /// The paths for one vault, its user and its admin.
    pub fn for_principals(
        layout: &Layout,
        vault: &VaultId,
        user: PrincipalId,
        admin: PrincipalId,
    ) -> Self {
        Self {
            issuance: Self::under(layout, vault, user, ISSUANCE_FILE),
            policy_events: Self::under(layout, vault, admin, POLICY_EVENTS_FILE),
        }
    }

    /// `p/<vault>/<principal>/<file>`.
    ///
    /// Not a `RecordPath`: a ledger is not a record at a level, and giving it a level
    /// would make it listable as one.
    fn under(layout: &Layout, vault: &VaultId, principal: PrincipalId, file: &str) -> PathBuf {
        layout
            .store_root()
            .join("p")
            .join(vault.as_str())
            .join(principal.to_string())
            .join(file)
    }

    /// The issuance ledger the user writes and this host reads.
    pub fn issuance(&self) -> &std::path::Path {
        &self.issuance
    }

    /// The withdrawals ledger the admin writes and this host reads.
    pub fn policy_events(&self) -> &std::path::Path {
        &self.policy_events
    }

    /// Both files as one reader's view, which is what every call site wants.
    pub fn as_ledger(&self) -> ksp_identity::IssuanceLedger {
        ksp_identity::IssuanceLedger::with_paths(&self.issuance, &self.policy_events)
    }

    /// Create either file if absent, with its mode and the store's group.
    ///
    /// The principal root above each file is the layout's `0711` — created here
    /// through `ensure_principal_root`, never through `create_dir_all`, because a
    /// directory created with the caller's `umask` would be `0755` and let the other
    /// principal *list* the ledger it may only read.
    ///
    /// `owner` is the `(uid, gid)` of the account that appends to that one file: the
    /// user for the issuance history, the admin for the withdrawals. Creating the
    /// other's file, or taking it over, is the siphon the one-writer rule prevents.
    pub fn prepare(
        &self,
        layout: &Layout,
        vault: &VaultId,
        user: PrincipalId,
        user_ids: (u32, u32),
        admin: PrincipalId,
        admin_ids: (u32, u32),
    ) -> Result<(), crate::layout::LayoutError> {
        for (principal, ids, path) in [
            (user, user_ids, &self.issuance),
            (admin, admin_ids, &self.policy_events),
        ] {
            crate::layout::ensure_principal_root(layout, vault, principal)?;
            crate::layout::ensure_ledger_file_in(layout, path, ids)?;
        }
        Ok(())
    }
}
