//! Where this host keeps its state, and how the selected backend is described.
//!
//! # One layout, named once
//!
//! Every path the binary uses is derived here. A command that built its own path
//! would be a second definition of the layout, and two definitions drift: the day
//! one of them moves, the other reads a file that is no longer written and
//! reports missing key material for a key it just stored.
//!
//! Nothing here selects a backend from a URL a token supplies. A token that could
//! name its own backend could point the reader at a store the attacker controls.

use std::path::{Path, PathBuf};

use ksp_backend::admission::Classification;
use ksp_backend::file::FileStore;
use ksp_backend::{
    AdmissionError, FileEvidence, ValkeyConfiguration, classify_file, classify_valkey,
};

/// The backend the configuration selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendSelection {
    /// A local directory. Always available; holds no deadline mechanism.
    File {
        /// Where the blobs and arms live.
        root: PathBuf,
    },
    /// A Valkey instance.
    Valkey {
        /// Whether logical expiry is configured.
        logical_expiry: bool,
        /// Whether the instance is append-only.
        append_only: bool,
        /// Whether every append is fsynced.
        append_fsync_always: bool,
        /// Whether `WAITAOF` is available.
        waitaof_supported: bool,
    },
}

impl BackendSelection {
    /// The capability classification this selection carries **by configuration alone**.
    ///
    /// For `file` that is `None`: a declaration is not evidence. The proof that can
    /// make it `Scheduled` is read by [`crate::admission::classify`], which has the
    /// deployment and the pinned anchor this function does not.
    pub fn classification(&self) -> Result<Classification, AdmissionError> {
        match self {
            Self::File { .. } => Ok(classify_file(FileEvidence::default())),
            Self::Valkey {
                logical_expiry,
                append_only,
                append_fsync_always,
                waitaof_supported,
            } => classify_valkey(ValkeyConfiguration {
                logical_expiry: *logical_expiry,
                append_only: *append_only,
                append_fsync_always: *append_fsync_always,
                waitaof_supported: *waitaof_supported,
            }),
        }
    }

    /// The name a status line reports.
    pub fn name(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
            Self::Valkey { .. } => "valkey",
        }
    }
}

/// The directories and files one host uses.
#[derive(Debug, Clone)]
pub struct Layout {
    root: PathBuf,
}

impl Layout {
    /// The layout rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The root itself.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The sealed user vault.
    pub fn vault_file(&self) -> PathBuf {
        self.root.join("vault.cbor")
    }

    /// The key root holding the admin signing identity.
    pub fn admin_key_root(&self) -> PathBuf {
        self.root.join("admin")
    }

    /// The trust anchor: the admin public key this host pins.
    pub fn admin_anchor_file(&self) -> PathBuf {
        self.root.join("admin-anchor.cbor")
    }

    /// The deployment identifiers written at `admin init`.
    pub fn deployment_file(&self) -> PathBuf {
        self.root.join("deployment.cbor")
    }

    /// The key root holding enrolled agent identities.
    pub fn agent_key_root(&self) -> PathBuf {
        self.root.join("agent")
    }

    /// Where signed enrolment records are kept.
    ///
    /// Deliberately outside the key roots: the record is the *pin* a reload is
    /// verified against, so it must be readable without the key file and must not
    /// be rewritten when the key file changes.
    pub fn enrolments_dir(&self) -> PathBuf {
        self.root.join("enrolments")
    }

    /// The signed enrolment record for one identity.
    pub fn enrolment_file(&self, identity: &str) -> PathBuf {
        self.enrolments_dir().join(format!("{identity}.cbor"))
    }

    /// The signed policy.
    pub fn policy_file(&self) -> PathBuf {
        self.root.join("policy.cbor")
    }

    /// The issuance ledger this host writes: what it minted and what it revoked.
    ///
    /// Beside the deployment because it is this host's own record, never a
    /// registry: no command publishes it and nothing listens for it.
    ///
    /// This is the principal's file. The admin's withdrawals live beside it, in
    /// [`Self::withdrawals_ledger`], so each file has exactly one writer.
    pub fn issuance_ledger(&self) -> PathBuf {
        self.root.join("issuance.jsonl")
    }

    /// The withdrawals the admin recorded, beside the issuance ledger.
    ///
    /// A separate file because the two writers are different accounts: the
    /// principal appends issuances and token marks, the admin appends grant
    /// withdrawals. Sharing one file would need it group-writable, and a mint
    /// history any group member can rewrite is one that member can forge.
    pub fn withdrawals_ledger(&self) -> PathBuf {
        self.root.join("withdrawals.jsonl")
    }

    /// The blob store root.
    pub fn store_root(&self) -> PathBuf {
        self.root.join("store")
    }

    /// The journal of deletion acknowledgements.
    pub fn journal_root(&self) -> PathBuf {
        self.root.join("journal")
    }

    /// The sweeper area: declarations, the unit template and the proofs.
    ///
    /// A sibling of the store rather than a directory inside it, because a proof
    /// covers a backend scope and not a vault, and every principal has to be able
    /// to read it.
    pub fn sweeper_root(&self) -> PathBuf {
        self.root.join("sweeper")
    }

    /// Where the sweeper writes one proof per run.
    pub fn sweeper_proofs_dir(&self) -> PathBuf {
        self.sweeper_root().join("proofs")
    }

    /// The recorded sweep schedules, one file per backend and scope.
    pub fn sweeper_armings_dir(&self) -> PathBuf {
        self.sweeper_root().join("armings")
    }

    /// The audit log's root.
    pub fn audit_root(&self) -> PathBuf {
        self.root.join("audit")
    }

    /// Which principal owns which protected root, recorded when it was created.
    ///
    /// Separate from `deployment.cbor`, which names the actors: this file records
    /// the *host* side — the uid and mode each root was made with — so a later
    /// measurement has something to compare against.
    pub fn layout_record_file(&self) -> PathBuf {
        self.root.join("layout.cbor")
    }

    /// The backend selection file.
    pub fn backend_file(&self) -> PathBuf {
        self.root.join("backend.cbor")
    }

    /// The capability configuration file.
    ///
    /// It is the one file in the home the operator is expected to edit, which
    /// is why its mode and owner are guarded before its content is read
    /// (FR-009, NFR-001).
    pub fn capability_config_file(&self) -> PathBuf {
        self.root.join(crate::capability_config::FILE_NAME)
    }
}

/// Read the backend selection, defaulting to the local store.
///
/// A missing file is the `file` backend rather than an error: the default has to
/// be the one that always works, or a fresh host cannot even run
/// `ksp backend test` to find out what it has.
pub fn read_backend(layout: &Layout) -> Result<BackendSelection, ConfigError> {
    match std::fs::read(layout.backend_file()) {
        Ok(bytes) => {
            let stored: StoredBackend =
                ksp_types::cbor::decode(&bytes).map_err(|_| ConfigError::BackendUnreadable)?;
            Ok(match stored {
                StoredBackend::File => BackendSelection::File {
                    root: layout.store_root(),
                },
                StoredBackend::Valkey {
                    logical_expiry,
                    append_only,
                    append_fsync_always,
                    waitaof_supported,
                } => BackendSelection::Valkey {
                    logical_expiry,
                    append_only,
                    append_fsync_always,
                    waitaof_supported,
                },
            })
        }
        Err(_) => Ok(BackendSelection::File {
            root: layout.store_root(),
        }),
    }
}

/// The stored form of a backend selection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case")]
enum StoredBackend {
    /// The local directory store.
    File,
    /// A Valkey instance.
    Valkey {
        /// Whether logical expiry is configured.
        logical_expiry: bool,
        /// Whether the instance is append-only.
        append_only: bool,
        /// Whether every append is fsynced.
        append_fsync_always: bool,
        /// Whether `WAITAOF` is available.
        waitaof_supported: bool,
    },
}

/// Why the configuration could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The selection file is present and is not one this build wrote.
    #[error("the backend selection is not readable")]
    BackendUnreadable,
    /// The selected backend could not be opened.
    #[error("the selected backend could not be opened")]
    StoreUnavailable,
    /// The local store directory could not be created.
    #[error("the local store directory could not be created")]
    StoreUnwritable,
}

/// Open the selected backend as a local store.
///
/// Only the `file` backend is built here. Valkey needs a live connection and is
/// opened by the caller that has one; conflating the two would make one failure
/// ambiguous between "no directory" and "no server".
pub fn open_file_store(layout: &Layout) -> Result<FileStore, ConfigError> {
    // The store row of the layout table, not `create_dir_all`: the latter takes
    // whatever `umask` the caller happens to have, which is how the store ended
    // up `0775` while the design said `0755` (misfit B).
    crate::layout::ensure_row(layout.root(), &layout.store_root())
        .map_err(|_| ConfigError::StoreUnwritable)?;
    FileStore::new(layout.store_root()).map_err(|_| ConfigError::StoreUnavailable)
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_fresh_host_defaults_to_the_local_store() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        assert_eq!(
            read_backend(&layout).unwrap(),
            BackendSelection::File {
                root: layout.store_root()
            }
        );
    }

    #[test]
    fn every_path_lives_under_the_root() {
        // A layout that escaped its root would write key material somewhere the
        // operator did not choose and cannot find.
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        for path in [
            layout.vault_file(),
            layout.admin_key_root(),
            layout.admin_anchor_file(),
            layout.agent_key_root(),
            layout.enrolments_dir(),
            layout.policy_file(),
            layout.store_root(),
            layout.journal_root(),
            layout.backend_file(),
            layout.sweeper_root(),
            layout.sweeper_proofs_dir(),
            layout.audit_root(),
            layout.layout_record_file(),
        ] {
            assert!(path.starts_with(dir.path()), "{path:?} escaped the root");
        }
    }

    #[test]
    fn an_agent_enrolment_record_is_not_inside_the_agent_key_root() {
        // The record is the pin a reload is checked against. Storing it beside
        // the key file would let one write replace the key and the value it is
        // verified against in one go.
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        assert!(
            !layout
                .enrolment_file("agent-7")
                .starts_with(layout.agent_key_root())
        );
    }

    #[test]
    fn the_file_backend_classifies_as_available_with_no_mechanism() {
        // The `file` backend has no deletion mechanism, so it cannot hold a
        // lease. That is a classification, not a failure.
        let selection = BackendSelection::File {
            root: PathBuf::from("/tmp/ksp"),
        };
        let classification = selection.classification().unwrap();
        assert_eq!(selection.name(), "file");
        assert_eq!(classification.capability, ksp_types::LeaseCapability::None);
    }
}
