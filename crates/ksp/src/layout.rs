//! The one table of protected roots, the one function that creates them, and
//! the measurement that says whether they still hold.
//!
//! # Why a table
//!
//! Misfit B: the admin ↔ user boundary is mode bits and ownership, and mode bits
//! drift. They drifted here in the most ordinary way possible — `store/` and
//! `enrolments/` were created by `create_dir_all` and therefore inherited the
//! process's `umask`, while the key roots were created `0700` by
//! `ksp-key-lifecycle`. Nothing failed; the boundary was simply wider than the
//! design said.
//!
//! A table is the fix rather than a `chmod` at each call site, because a mode
//! chosen at a call site is a second definition of the layout. Every root gets
//! one row stating its mode and the reason it is not more open, and creation
//! reads that row. [`ksp_posture::permissions`] then measures the result against
//! the same row.
//!
//! # What creation will not do
//!
//! It will not tighten a root that already exists. Doing so would silently
//! rewrite a boundary the caller was not asked about, and it would erase the
//! evidence that anything had drifted — the operator needs the drift reported,
//! not repaired behind their back. So [`ensure`] creates with the recorded mode
//! and [`audit`] reports everything else.
//!
//! It will also not follow a symlink. `lstat` is the measurement; a protected
//! root that is a symlink is drift, and creating *through* one would put the
//! boundary where the link points.

use std::path::{Path, PathBuf};

use ksp_deletion::AuditChain;

use ksp_posture::{ExpectedOwner, ExpectedRoot, PermissionFinding, RootKind};
use ksp_types::cbor;

use crate::config::Layout;

/// The deployment root: traverse for everyone, list for the owner only.
///
/// `0711` is deliberate. Non-owners reach a path they already know — which the
/// store's level directories need, because the admin has to traverse to the
/// levels it sweeps — and a non-owner cannot enumerate what is there.
pub const HOME_MODE: u32 = 0o711;

/// The admin key root. Only the admin principal reads it (FR-015).
pub const ADMIN_KEY_MODE: u32 = 0o700;

/// The agent key root. Same-user agents are bounded by Landlock, not by this; the
/// mode keeps another host account out of the key files.
pub const AGENT_KEY_MODE: u32 = 0o700;

/// Enrolment records are the pins a reload is verified against. Public material,
/// and readable without a key file — that is the point of keeping them apart.
pub const ENROLMENTS_MODE: u32 = 0o755;

/// The store root. Traversable by every principal, because each level directory
/// below it carries its own owner and mode.
///
/// Taken from the backend that creates it rather than restated here: two copies
/// of this number is two places for a `0775` to appear.
pub const STORE_MODE: u32 = ksp_backend::file::STORE_ROOT_MODE;

/// The sweeper area, and the proofs inside it: every principal may read the
/// proof that authorises its lease, which is why the store is not the place for
/// it.
pub const SWEEPER_MODE: u32 = 0o755;

/// The audit log's root: a parent of per-writer directories, and nothing else.
///
/// `0711`, not `0700`: each principal writes its own chain in its own directory
/// below this one, so every principal must be able to *traverse* it. None may
/// list it — a list of the chains is a list of who wrote, which the view already
/// discloses one record at a time and only inside a scope that permits it.
pub const AUDIT_MODE: u32 = 0o711;

/// One principal's own chain directory, inside the audit root.
///
/// `0700` and owned by that principal: a sibling cannot read another's records
/// even knowing the path, and the kernel is what refuses it.
pub const AUDIT_WRITER_MODE: u32 = 0o700;

/// The deletion journal: acknowledgements this host wrote about its own removals.
pub const JOURNAL_MODE: u32 = 0o700;

/// The arm journal inside the store: one create-new record per minted lease.
///
/// Group-writable *and* sticky (`1770`). Arming is the minting principal's own act —
/// `mint::arm` writes here before any token exists — so it cannot require the
/// admin, and the store group is the only set of writers there is. The sticky bit
/// is what keeps each record its author's: a sibling may add an intent but not
/// replace or remove one it did not write. Widening this to `0755` would hand every
/// local account the identities of pending deletions; clearing the sticky bit would
/// let one principal suppress another's arming.
///
/// Group read is required, not granted: a durable arm ends with an `fsync` of this
/// directory (`persist`), and a directory can only be opened for that with read
/// permission. A write-only journal would turn every share into `Uncertain` arming.
pub const ARM_JOURNAL_MODE: u32 = 0o1770;

/// Create one principal's own chain directory under the audit root.
///
/// `0700` and owned by the principal that writes there. The audit root is only
/// traversable (`0711`), so this directory is the boundary: a sibling cannot read
/// another's records even knowing the path, and only the owner may append.
///
/// Created by provisioning, not by the first append. The writer creates its own
/// directory when this is absent (`ensure_directory` in the chain), which needs
/// write on the audit root — and the moment any principal can write there is the
/// moment it can plant or rename a chain it does not own.
pub fn ensure_audit_writer(
    root: &Path,
    principal: ksp_types::PrincipalId,
    owner: (u32, u32),
) -> Result<PathBuf, LayoutError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let layout = Layout::new(root.to_path_buf());
    ensure_row(root, &layout.audit_root())?;
    let directory = AuditChain::new(layout.audit_root()).writer_root(principal);
    match std::fs::symlink_metadata(&directory) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(LayoutError::Unusable {
                    path: directory.display().to_string(),
                    kind: RootKind::Directory,
                });
            }
        }
        Err(_) => {
            std::fs::DirBuilder::new()
                .mode(AUDIT_WRITER_MODE)
                .create(&directory)
                .map_err(|_| LayoutError::Unwritable {
                    path: directory.display().to_string(),
                })?;
            std::fs::set_permissions(
                &directory,
                std::fs::Permissions::from_mode(AUDIT_WRITER_MODE),
            )
            .map_err(|_| LayoutError::Unwritable {
                path: directory.display().to_string(),
            })?;
        }
    }
    // The owner is set every time this is called with one, and never left to the
    // caller's umask: the first append must be the principal's, not provisioning's.
    std::os::unix::fs::chown(&directory, Some(owner.0), Some(owner.1)).map_err(|_| {
        LayoutError::Unwritable {
            path: directory.display().to_string(),
        }
    })?;
    Ok(directory)
}

/// The parent of one principal's level directories.
///
/// `0711`: a principal that can *name* a level traverses into it, and a principal
/// that cannot name one cannot enumerate the siblings it might guess. This is the
/// shared parent the design spec fixes at `0711`, and it is why removing a level
/// directory is not something a traversing principal can do.
pub const LEVEL_PARENT_MODE: u32 = 0o711;

/// One level directory. Owner-only: the level *is* the boundary between
/// principals, and its owner is the principal whose records live in it.
pub const LEVEL_MODE: u32 = 0o700;

/// One `agent-<id>` level: owner `rwx`, group `-wx`, no access for anyone else.
///
/// POSIX grants delete through write on the containing directory, not through a
/// file mode, so FR-015's admin delete needs a directory the admin may write.
/// The group is the **store root's** group — the deployment's shared group, since
/// the admin owns the store it sweeps — and provisioning keeps the user in it.
/// Group *read* is deliberately absent: the admin unlinks a version it knows from
/// the arming scope, and cannot list the level or read a copy. Nothing is widened
/// to `other`; `user/` and `admin/` keep `0700`.
pub const AGENT_LEVEL_MODE: u32 = 0o730;

/// The sealed vault. Ciphertext, but its salt and nonce narrow an offline guess.
pub const VAULT_MODE: u32 = 0o600;

/// The signed policy. Every principal must read what it may do, and none may
/// rewrite it without the admin key.
pub const POLICY_MODE: u32 = 0o644;

/// The issuance ledger: what this host minted, and what it revoked.
///
/// `0640` — owner read/write, group read — and the group is the store's, which is
/// the group both accounts are in.
///
/// Two files, and each has exactly one writer, which is why this mode is enough:
/// `issuance.jsonl` belongs to the user principal, who appends `Issued` inside the
/// mint's publication closure and `TokenRevoked` when she withdraws a token;
/// `withdrawals.jsonl` belongs to the admin, who appends `GrantWithdrawn` in
/// `admin revoke`. `run` reads both, so a withdrawal reaches the principal it
/// withdraws from.
///
/// A single shared file would have to be group-*writable*, and a mint history any
/// group member can rewrite is a history that member can forge: appending a
/// revocation is how a token stops working, and removing one is how it starts
/// again. Splitting it keeps the write bit with one account per file.
pub const ISSUANCE_LEDGER_MODE: u32 = 0o640;

/// A file whose content is public material every principal must read.
///
/// The deployment record and the pinned anchor are identifiers and public keys.
/// Keeping them owner-only does not protect a secret — there is none in them —
/// and it does stop the user principal from opening her own vault in a
/// two-account deployment, which is a boundary that refuses the wrong party.
pub const PUBLIC_FILE_MODE: u32 = 0o644;

/// One row of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootSpec {
    /// Where the root lives.
    pub path: PathBuf,
    /// The mode it is created with and measured against.
    pub mode: u32,
    /// Whether it is a directory this table creates or a file a command writes.
    pub kind: RootKind,
    /// Why it is not more open. The table *is* the boundary, so each row says.
    pub reason: &'static str,
    /// Whether a drift here refuses a delivery.
    ///
    /// FR-014 names a protected key file, the vault and a level root. The
    /// deployment root is this host's own choice of directory — an operator may
    /// legitimately point `KSP_HOME` at a `0700`, `0755` or `0711` path — so its
    /// mode is disclosed and not turned into a refusal.
    pub refusal: bool,
}

/// The table, in creation order: the root before its children.
///
/// File rows are measured, never created — an empty `vault.cbor` would be worse
/// than an absent one, and the command that writes it owns its mode.
pub fn table(root: &Path) -> Vec<RootSpec> {
    let layout = Layout::new(root.to_path_buf());
    vec![
        RootSpec {
            path: layout.root().to_path_buf(),
            mode: HOME_MODE,
            kind: RootKind::Directory,
            reason: "non-owners traverse known paths but cannot enumerate the deployment",
            // Advisory: FR-014 does not name the deployment root, and refusing
            // here would reject a home the operator created 0755 by hand.
            refusal: false,
        },
        RootSpec {
            path: layout.admin_key_root(),
            mode: ADMIN_KEY_MODE,
            kind: RootKind::Directory,
            reason: "holds the admin signing identity; no other principal may read or write it",
            refusal: true,
        },
        RootSpec {
            path: layout.agent_key_root(),
            mode: AGENT_KEY_MODE,
            kind: RootKind::Directory,
            reason: "holds agent key bundles; a sibling account must not read them",
            refusal: true,
        },
        RootSpec {
            path: layout.enrolments_dir(),
            mode: ENROLMENTS_MODE,
            kind: RootKind::Directory,
            reason: "public pins a reload is verified against; readable without a key file",
            refusal: true,
        },
        RootSpec {
            path: layout.store_root(),
            mode: STORE_MODE,
            kind: RootKind::Directory,
            reason: "traversable by every principal; each level directory carries its own owner",
            refusal: true,
        },
        RootSpec {
            path: layout.sweeper_root(),
            mode: SWEEPER_MODE,
            kind: RootKind::Directory,
            reason: "parents the proofs a reader must reach without entering the store",
            refusal: true,
        },
        RootSpec {
            path: layout.sweeper_proofs_dir(),
            mode: SWEEPER_MODE,
            kind: RootKind::Directory,
            reason: "one writer, every principal a reader: a proof authorises a lease",
            refusal: true,
        },
        RootSpec {
            path: layout.store_root().join("intents"),
            mode: ARM_JOURNAL_MODE,
            kind: RootKind::Directory,
            reason: "the arm journal: each principal arms its own leases, and the sticky bit keeps a sibling from removing a record it did not write",
            // A world-readable journal discloses which deletions are pending, and
            // a `0730` without the sticky bit lets one principal erase a sibling's
            // arming before the sweep reaches it.
            refusal: true,
        },
        RootSpec {
            path: layout.sweeper_armings_dir(),
            mode: SWEEPER_MODE,
            kind: RootKind::Directory,
            reason: "recorded schedules any principal may read; only the admin writes here",
            refusal: true,
        },
        RootSpec {
            path: layout.audit_root(),
            mode: AUDIT_MODE,
            kind: RootKind::Directory,
            reason: "append-only writer segments; another principal must not rewrite them",
            refusal: true,
        },
        RootSpec {
            path: layout.journal_root(),
            mode: JOURNAL_MODE,
            kind: RootKind::Directory,
            reason: "this host's own deletion acknowledgements, not a shared record",
            refusal: true,
        },
        // The two public files. They are rows so their *owners* are judged, and
        // their mode is the table's `0644` rather than a creation accident: the
        // user principal reads both before she has a password to offer, and an
        // owner-only anchor is how a two-account deployment refuses the party it
        // was written for.
        RootSpec {
            path: layout.admin_anchor_file(),
            mode: PUBLIC_FILE_MODE,
            kind: RootKind::File,
            reason: "the pinned admin public key; every principal verifies tokens against it",
            // FR-014's protected key file. A pin another principal can rewrite
            // pins nothing, so a widened anchor refuses a delivery like a widened
            // key root does.
            refusal: true,
        },
        RootSpec {
            path: layout.deployment_file(),
            mode: PUBLIC_FILE_MODE,
            kind: RootKind::File,
            reason: "the vault and principal identifiers, with the user's public keys",
            // The record every path is derived from. A deployment file another
            // principal can rewrite redirects records, so it refuses too.
            refusal: true,
        },
        RootSpec {
            path: layout.vault_file(),
            mode: VAULT_MODE,
            kind: RootKind::File,
            reason: "sealed vault: readable only by the principal that owns the password",
            refusal: true,
        },
        RootSpec {
            path: layout.policy_file(),
            mode: POLICY_MODE,
            kind: RootKind::File,
            reason: "signed policy: readable by every principal, replaceable only with the admin key",
            refusal: true,
        },
        RootSpec {
            path: layout.issuance_ledger(),
            mode: ISSUANCE_LEDGER_MODE,
            kind: RootKind::File,
            reason: "the principal's mint record: she writes it, the admin reads it",
            // A ledger writable by a third party is a mint history that party can
            // forge: appending a revocation is how a token stops working, and
            // removing one is how it starts again.
            refusal: true,
        },
        RootSpec {
            path: layout.withdrawals_ledger(),
            mode: ISSUANCE_LEDGER_MODE,
            kind: RootKind::File,
            reason: "the admin's withdrawal record: he writes it, the principal's run reads it",
            // The same argument in the other direction: a withdrawal another
            // principal can remove is a revocation that silently stops holding.
            refusal: true,
        },
    ]
}

/// Why the layout could not be created or recorded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LayoutError {
    /// A protected root is a symlink, or is not the kind of entry the table says.
    #[error("the protected root {path} is not the {kind} the layout requires")]
    Unusable {
        /// The path that could not be used.
        path: String,
        /// The kind the table requires.
        kind: RootKind,
    },
    /// A protected root could not be created.
    #[error("the protected root {path} could not be created")]
    Unwritable {
        /// The path that could not be created.
        path: String,
    },
    /// A caller asked for a directory the table does not name.
    #[error("{path} is not a protected root this layout knows")]
    UnknownRoot {
        /// The path that was not in the table.
        path: String,
    },
    /// A file's expected owner is already recorded as a different principal.
    #[error(
        "{path} is already recorded against another owner: a recorded owner is a claim from \
         the past, and replacing it would make a rebind invisible"
    )]
    OwnerRecorded {
        /// The path whose record conflicts.
        path: String,
    },
    /// The layout record could not be written.
    #[error("the layout record could not be written")]
    Record {
        /// Why it failed, in this crate's own words.
        reason: &'static str,
    },
}

/// The recorded owner of one root, as written when the root was created.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct RecordedRoot {
    path: String,
    mode: u32,
    owner: u32,
}

/// The on-disk record of which principal owns which root.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct LayoutRecord {
    roots: Vec<RecordedRoot>,
}

impl LayoutRecord {
    fn owner_of(&self, path: &Path) -> Option<u32> {
        let path = path.to_string_lossy();
        self.roots
            .iter()
            .find(|root| root.path == path)
            .map(|root| root.owner)
    }

    /// Add a row for a root nobody recorded yet.
    ///
    /// An existing row is never replaced: the recorded owner is a claim from the
    /// past, and silently re-recording it is how a rebind becomes invisible
    /// (FR-024).
    /// Replace an owner on purpose, or add the row if it was never recorded.
    fn replace_owner(&mut self, path: &Path, owner: u32) {
        let path = path.to_string_lossy();
        match self.roots.iter_mut().find(|root| root.path == path) {
            Some(existing) => existing.owner = owner,
            None => self.roots.push(RecordedRoot {
                path: path.to_string(),
                mode: 0,
                owner,
            }),
        }
    }

    fn record_once(&mut self, path: &Path, mode: u32, owner: u32) {
        let path = path.to_string_lossy().to_string();
        if self.roots.iter().any(|root| root.path == path) {
            return;
        }
        self.roots.push(RecordedRoot { path, mode, owner });
    }
}

/// Read the layout record, treating an unreadable one as empty.
///
/// An absent record is not an error: a home provisioned before this revision has
/// no record, and its roots are then reported with an unrecorded owner rather
/// than assumed to be owned by whoever reads them.
fn read_record(root: &Path) -> LayoutRecord {
    let path = Layout::new(root.to_path_buf()).layout_record_file();
    match std::fs::read(path) {
        Ok(bytes) => cbor::decode(&bytes).unwrap_or_default(),
        Err(_) => LayoutRecord::default(),
    }
}

/// Write the record, owner-only and atomically.
fn write_record(root: &Path, record: &LayoutRecord) -> Result<(), LayoutError> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let file = Layout::new(root.to_path_buf()).layout_record_file();
    let bytes = cbor::encode(record).map_err(|_| LayoutError::Record {
        reason: "the record could not be encoded",
    })?;

    // A sibling first, then a rename: a truncated record would report every root
    // as unrecorded, which reads like "nothing is checked" rather than "the
    // record is gone".
    //
    // The owner is carried over, because a rename does not change it and the
    // record has one owner for the life of the deployment: provisioning may run
    // the handover as root, and a root-owned record would make every later row a
    // principal creates fail on a rename it cannot do. Read before the staging
    // file is written, since the staging file replaces the owner with its
    // writer's.
    let existing = std::fs::metadata(&file).ok();
    let staged = file.with_extension("new");
    let mut handle = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&staged)
        .map_err(|_| LayoutError::Record {
            reason: "the staged record could not be opened",
        })?;
    handle.write_all(&bytes).map_err(|_| LayoutError::Record {
        reason: "the staged record could not be written",
    })?;
    handle.sync_all().map_err(|_| LayoutError::Record {
        reason: "the staged record could not be synced",
    })?;
    // A privileged writer stages a file it owns; the record stays the owner's it
    // already was. A non-owner cannot have got this far, and a no-op chown to
    // one's own uid is not an error.
    if let Some(existing) = existing
        && existing.uid() != staged_uid(&staged)
    {
        std::os::unix::fs::chown(&staged, Some(existing.uid()), Some(existing.gid())).map_err(
            |_| LayoutError::Record {
                reason: "the staged record could not be given back to its owner",
            },
        )?;
    }
    std::fs::rename(&staged, &file).map_err(|_| LayoutError::Record {
        reason: "the staged record could not be renamed",
    })?;

    // The record names owners; leaving it group-readable would publish the host's
    // uid layout to every account that can reach the root.
    let mode = std::fs::metadata(&file)
        .map(|md| md.mode() & 0o7777)
        .unwrap_or(0);
    if mode != 0o600 {
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).map_err(|_| {
            LayoutError::Record {
                reason: "the record could not be made owner-only",
            }
        })?;
    }
    Ok(())
}

/// The uid that owns `path`, or the caller's when it cannot be measured.
fn staged_uid(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;

    std::fs::metadata(path)
        .map(|metadata| metadata.uid())
        .unwrap_or_else(|_| ksp_posture::permissions::effective_uid())
}

/// Create every protected root that does not exist yet, with the table's mode.
///
/// Modes are applied with `chmod` after creation on purpose: `DirBuilder::mode`
/// is masked by the process's `umask`, so an inherited `umask 0002` would widen
/// a `0700` root to `0770` and the boundary would depend on how the operator
/// logged in. A `chmod` is not masked.
///
/// The store root's *group* is set explicitly for the same reason, and it is the
/// caller's own effective group rather than whatever the parent directory
/// carried. Both matter:
///
/// - A directory created under `/tmp` on macOS inherits `wheel`, because the
///   parent's group is `wheel`. The store's group is meant to be one both
///   accounts share, and `wheel` is a privileged system group an ordinary
///   account must not join. `admin user add` then tried to add the operator to
///   it and told them to run as root — accurate about what failed, dangerous
///   about what to do.
/// - The caller's effective group is the one group this process is certain to
///   belong to, so a store created with it is one the creator can share.
///
/// Only the store root is re-grouped. Every other root is `0700` or `0711` and
/// its group is irrelevant to the boundary, which is mode and owner bits.
pub fn ensure(root: &Path) -> Result<(), LayoutError> {
    let mut record = read_record(root);
    let mut created = false;

    for spec in table(root) {
        if spec.kind == RootKind::File {
            // The command that writes the file owns its mode; creating an empty
            // one here would replace "absent" with "corrupt".
            continue;
        }
        let made = create_missing(&spec, &mut record)?;
        if made && spec.path == Layout::new(root.to_path_buf()).store_root() {
            set_store_group(&spec.path)?;
        }
        created |= made;
    }

    if created {
        write_record(root, &record)?;
    }
    Ok(())
}

/// Give the store root the caller's own effective group.
///
/// The gid comes from the process, not from the parent directory: a parent's
/// group is a property of where the store happens to live, and the store's group
/// is a property of who has to share it.
///
/// A failure is reported rather than swallowed. A store created with the wrong
/// group is one where `admin user add` will try to add the operator to that
/// group, and the operator would learn about it two commands later with no
/// indication that the group was inherited rather than chosen.
fn set_store_group(path: &Path) -> Result<(), LayoutError> {
    use std::os::unix::fs::MetadataExt;

    let gid = ksp_posture::permissions::effective_gid();
    let current = std::fs::symlink_metadata(path)
        .map_err(|_| LayoutError::Unwritable {
            path: path.display().to_string(),
        })?
        .gid();
    if current == gid {
        return Ok(());
    }
    std::os::unix::fs::chown(path, None, Some(gid)).map_err(|_| LayoutError::Unwritable {
        path: path.display().to_string(),
    })
}

/// Create one row of the table if it is absent, leaving everything else alone.
///
/// This is what a command uses when it needs one directory and is not
/// provisioning the deployment: opening the store must not recreate a deleted
/// `admin/` under the caller's uid, because that would fabricate a key root the
/// layout record never described.
pub fn ensure_row(root: &Path, path: &Path) -> Result<(), LayoutError> {
    let specs = table(root);
    let spec =
        specs
            .iter()
            .find(|spec| spec.path == path)
            .ok_or_else(|| LayoutError::UnknownRoot {
                path: path.display().to_string(),
            })?;
    if spec.kind == RootKind::File {
        return Ok(());
    }

    let mut record = read_record(root);
    if create_missing(spec, &mut record)? {
        write_record(root, &record)?;
    }
    Ok(())
}

/// Create the directory that holds `file`, when that directory is a table row.
///
/// A file written into `<root>/admin/` or `<root>/enrolments/` needs its parent to
/// exist with the table's mode. `create_dir_all` would give it the caller's
/// `umask` — that is how `enrolments/` became `0775` — so the mode comes from the
/// row instead. A directory the table does not name is left to its owner: this
/// function exists to route layout directories through the table, not to police
/// a caller's own temporary path.
pub fn ensure_known_parent(file: &Path) -> Result<(), LayoutError> {
    let Some(dir) = file.parent() else {
        return Ok(());
    };
    // The deployment root is the ancestor whose table names `dir`. Starting at
    // the parent and *not* at `dir` matters: treating `dir` as a root would match
    // the home row of a table rooted there and create the directory `0711`
    // instead of the `0755` the table records for it.
    for ancestor in dir.ancestors().skip(1) {
        let Some(spec) = table(ancestor).into_iter().find(|row| row.path == dir) else {
            continue;
        };
        if spec.kind != RootKind::Directory {
            return Ok(());
        }
        return ensure_row(ancestor, &spec.path);
    }
    Ok(())
}

/// Create `spec` when nothing is at its path. Returns whether it created it.
fn create_missing(spec: &RootSpec, record: &mut LayoutRecord) -> Result<bool, LayoutError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    match std::fs::symlink_metadata(&spec.path) {
        Ok(metadata) => {
            // Never create through a symlink, and never accept a file where the
            // table says directory: either would put the boundary somewhere the
            // record does not describe.
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(LayoutError::Unusable {
                    path: spec.path.display().to_string(),
                    kind: spec.kind,
                });
            }
            Ok(false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .mode(spec.mode)
                .create(&spec.path)
                .map_err(|_| LayoutError::Unwritable {
                    path: spec.path.display().to_string(),
                })?;
            // `DirBuilder::mode` is masked by the umask; `chmod` is not.
            std::fs::set_permissions(&spec.path, std::fs::Permissions::from_mode(spec.mode))
                .map_err(|_| LayoutError::Unwritable {
                    path: spec.path.display().to_string(),
                })?;
            let owner = std::fs::metadata(&spec.path)
                .map(|md| md.uid())
                .map_err(|_| LayoutError::Unwritable {
                    path: spec.path.display().to_string(),
                })?;
            record.record_once(&spec.path, spec.mode, owner);
            Ok(true)
        }
        Err(_) => Err(LayoutError::Unwritable {
            path: spec.path.display().to_string(),
        }),
    }
}

/// The group an `agent-<id>` level is given: the store root's own.
///
/// The store root is the deployment's shared, traversable root and it belongs to
/// the principal that provisioned the store — the admin in the two-account
/// layout. Reading the group from the directory itself keeps the decision
/// per-deployment and deterministic: no host-wide group name, and no dependence
/// on which groups this process happens to carry.
fn agent_level_group(layout: &Layout) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(layout.store_root()).ok()?;
    (!metadata.file_type().is_symlink()).then(|| metadata.gid())
}

/// The mode one level directory is created with and measured against.
///
/// Only `agent-<id>` levels are widened: `user/` and `admin/` are never
/// reachable by another principal.
pub fn level_mode(level: &ksp_types::Level) -> u32 {
    match level {
        ksp_types::Level::Agent(_) => AGENT_LEVEL_MODE,
        _ => LEVEL_MODE,
    }
}

/// Create one ledger file, or repair its mode and group.
///
/// Provisioning calls this. The file is `0640` in the store's group, which is the
/// group both accounts are in: the writer appends, the other account reads. The
/// mode is set with `set_permissions`, never left to `open(2)`'s `mode`, which the
/// caller's `umask` masks — and the ledger refuses to append to a file with any
/// group or other write bit, so a widened file would make every later mint fail.
///
/// An empty file is a valid ledger: `refuse_a_torn_tail` treats zero bytes as a
/// clean start. Creating it here rather than at first append is what keeps the
/// deployment root `0711` a boundary — neither account needs write on it.
pub fn ensure_ledger_file(root: &Path, path: &Path, owner: (u32, u32)) -> Result<(), LayoutError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let layout = Layout::new(root.to_path_buf());
    let unwritable = || LayoutError::Unwritable {
        path: path.display().to_string(),
    };
    // `O_NOFOLLOW`: the ledger is a file this host chose, never whatever a symlink
    // at that path points at. `truncate(false)` because a re-run must not discard
    // the history it is meant to preserve.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o640)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| unwritable())?;
    file.set_permissions(std::fs::Permissions::from_mode(0o640))
        .map_err(|_| unwritable())?;
    let store_gid = std::fs::metadata(layout.store_root())
        .map(|metadata| metadata.gid())
        .unwrap_or(owner.1);
    std::os::unix::fs::chown(path, Some(owner.0), Some(store_gid)).map_err(|_| unwritable())?;
    // The owner is *replaced*, not recorded once: `admin init` created this file
    // as the account that provisioned the deployment, and `admin user add` moves
    // it to the account that writes it. Recording it a second time would be
    // refused as a conflicting claim, which is the right rule for a file whose
    // owner is meant to stay put and the wrong one for a handover.
    rebind_file_owner(root, path, owner.0)
}

/// Create the store's arm journal, or repair its mode and group.
///
/// Provisioning calls this; `share` does not. The mint arms as the user principal,
/// so the directory has to exist with the store's group already on it — a principal
/// cannot name that group on a directory she creates unless she belongs to it, and
/// the *owner* of this directory must not be her either: the sticky bit protects a
/// record from removal by anyone but the record's author and the directory's owner,
/// and the directory's owner is the deployment.
pub fn ensure_arm_journal(root: &Path) -> Result<PathBuf, LayoutError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    let layout = Layout::new(root.to_path_buf());
    let path = layout.store_root().join("intents");
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(LayoutError::Unusable {
                path: path.display().to_string(),
                kind: RootKind::Directory,
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .mode(ARM_JOURNAL_MODE)
                .create(&path)
                .map_err(|_| LayoutError::Unwritable {
                    path: path.display().to_string(),
                })?;
        }
        Err(_) => {
            return Err(LayoutError::Unwritable {
                path: path.display().to_string(),
            });
        }
    }

    // The store's group is the one the agent levels use, so the journal names the
    // same set of writers rather than a second, silently different one.
    let store_gid = std::fs::symlink_metadata(layout.store_root())
        .ok()
        .filter(|metadata| metadata.is_dir())
        .map(|metadata| metadata.gid());
    let journal_gid = std::fs::symlink_metadata(&path)
        .map(|metadata| metadata.gid())
        .map_err(|_| LayoutError::Unwritable {
            path: path.display().to_string(),
        })?;
    if let Some(gid) = store_gid
        && gid != journal_gid
    {
        std::os::unix::fs::chown(&path, None, Some(gid)).map_err(|_| LayoutError::Unwritable {
            path: path.display().to_string(),
        })?;
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(ARM_JOURNAL_MODE)).map_err(
        |_| LayoutError::Unwritable {
            path: path.display().to_string(),
        },
    )?;
    Ok(path)
}

/// Create one principal's level directory, and the traversable parent above it.
///
/// Returns the level's path. The two modes are the whole of the boundary: the
/// parent is traversable and not listable, and the level is owner-only. Creation
/// is `chmod`-exact for the same reason every other row is — an inherited `umask`
/// must not decide who can read a principal's records.
pub fn ensure_level(
    root: &Path,
    vault_id: &ksp_types::VaultId,
    principal: ksp_types::PrincipalId,
    level: &ksp_types::Level,
) -> Result<PathBuf, LayoutError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let layout = Layout::new(root.to_path_buf());
    // A fresh home may not have the store root yet. The table's row creates it
    // with the store's own mode and records its owner; letting the level's first
    // `create` build it would give the store whatever mode the caller passed.
    ensure_row(layout.root(), &layout.store_root())?;
    let relative = ksp_record::RecordPath::directory(vault_id, principal, Some(level));

    // Every directory on the way to the level, each with its own mode: the
    // ancestors are shared and traversable (`0711`), the level is the principal's
    // own (`0700`). `create` rather than `create_all`, because `create_all` takes
    // one mode for the whole chain and would give the level the parent's.
    let mut cursor = layout.store_root();
    let mut chain: Vec<(PathBuf, u32)> = Vec::new();
    let segments: Vec<&str> = relative
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    let agent_group = match level {
        ksp_types::Level::Agent(_) => agent_level_group(&layout),
        _ => None,
    };
    let level_mode = level_mode(level);
    for (index, segment) in segments.iter().enumerate() {
        cursor = cursor.join(segment);
        let last = index + 1 == segments.len();
        chain.push((
            cursor.clone(),
            if last { level_mode } else { LEVEL_PARENT_MODE },
        ));
    }

    let last_index = chain.len().saturating_sub(1);
    for (index, (path, mode)) in chain.iter().enumerate() {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(LayoutError::Unusable {
                        path: path.display().to_string(),
                        kind: RootKind::Directory,
                    });
                }
                // The level is the boundary, so its mode is repaired on every
                // write rather than only when it is created. Ancestors are left
                // as they are: they may belong to another principal, and a drift
                // there is `ksp status`'s finding, not this record's side effect.
                if index == last_index {
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode))
                        .map_err(|_| LayoutError::Unwritable {
                            path: path.display().to_string(),
                        })?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new()
                    .mode(*mode)
                    .create(path)
                    .map_err(|_| LayoutError::Unwritable {
                        path: path.display().to_string(),
                    })?;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode)).map_err(
                    |_| LayoutError::Unwritable {
                        path: path.display().to_string(),
                    },
                )?;
            }
            Err(_) => {
                return Err(LayoutError::Unwritable {
                    path: path.display().to_string(),
                });
            }
        }
    }

    if let Some(gid) = agent_group {
        std::os::unix::fs::chown(&cursor, None, Some(gid)).map_err(|_| {
            LayoutError::Unwritable {
                path: cursor.display().to_string(),
            }
        })?;
    }

    Ok(cursor)
}

/// The level rows this deployment can name without listing a parent.
///
/// A level is dynamic — one per enrolled agent — so it is not part of the static
/// table. The rows come from the deployment's user and the enrolment pins, never
/// from listing `p/<vault>/<principal>/`: its `0711` mode forbids that listing,
/// and a measurement that enumerated the store would contradict the mode it
/// measures. Only levels that exist are rows; a level with no records has no
/// boundary to report.
fn level_rows(root: &Path) -> Vec<RootSpec> {
    let layout = Layout::new(root.to_path_buf());
    let Ok(deployment) = crate::deployment::Deployment::load(&layout) else {
        // Without the deployment the vault, the owning principal and the agent
        // levels cannot be named. An empty list says so by measuring nothing;
        // it must not be read as every level matching. `run_status` measures the
        // layout before it confines the process, precisely so this read happens.
        return Vec::new();
    };
    let mut rows = Vec::new();

    let user = ksp_record::RecordPath::directory(
        &deployment.vault,
        deployment.user,
        Some(&ksp_types::Level::User),
    );
    let user = layout.store_root().join(user);
    if user.is_dir() {
        rows.push(RootSpec {
            path: user,
            mode: LEVEL_MODE,
            kind: RootKind::Directory,
            reason: "one principal's records: no other principal reads or writes here",
            refusal: true,
        });
    }

    let Ok(entries) = std::fs::read_dir(layout.enrolments_dir()) else {
        return rows;
    };
    let mut agents: Vec<ksp_types::AgentId> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "cbor") {
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .and_then(|stem| ksp_types::AgentId::parse(stem).ok())
            } else {
                None
            }
        })
        .collect();
    agents.sort_by_key(|agent| agent.to_string());
    for agent in agents {
        let level = ksp_types::Level::Agent(agent);
        let path =
            ksp_record::RecordPath::directory(&deployment.vault, deployment.user, Some(&level));
        let path = layout.store_root().join(path);
        if !path.is_dir() {
            continue;
        }
        rows.push(RootSpec {
            path,
            mode: level_mode(&level),
            kind: RootKind::Directory,
            reason: "a leased copy the admin may unlink through the store's group, never read",
            refusal: true,
        });
    }
    rows
}

/// Every row to measure: the static table plus the levels this host can name.
///
/// The levels are derived from the deployment and the enrolments, never by
/// listing a `0711` parent. When neither can be read — a store root that does
/// not exist yet, or a principal that cannot read `deployment.cbor` — no level
/// row is measured, and that is a smaller measurement, not a matching one. The
/// collector owns the deployment and sees every row; a non-owner's `status`
/// discloses the table it can name.
fn measured_rows(root: &Path) -> Vec<RootSpec> {
    let mut rows = table(root);
    rows.extend(level_rows(root));
    rows
}

/// Measure every row of the table against the disk and the layout record.
pub fn audit(root: &Path) -> Vec<PermissionFinding> {
    let record = read_record(root);
    let expected: Vec<ExpectedRoot> = measured_rows(root)
        .into_iter()
        .map(|spec| {
            let owner = match record.owner_of(&spec.path) {
                Some(uid) => ExpectedOwner::Recorded(uid),
                None => ExpectedOwner::Unrecorded,
            };
            ExpectedRoot {
                path: spec.path,
                mode: spec.mode,
                kind: spec.kind,
                owner,
            }
        })
        .collect();
    ksp_posture::audit(&expected)
}

/// Record which principal is expected to own one file row of the table.
///
/// Directories are recorded when they are created; the vault is written by the
/// admin and must belong to the user, so its expected owner is recorded here at
/// the moment the binding is made. An existing row is never replaced: a silently
/// updated owner is how a rebind becomes invisible (FR-024), so a conflicting
/// record is refused and the operator is told which claim already exists.
pub fn record_file_owner(root: &Path, path: &Path, owner: u32) -> Result<(), LayoutError> {
    let spec = table(root)
        .into_iter()
        .find(|spec| spec.path == path)
        .filter(|spec| spec.kind == RootKind::File)
        .ok_or_else(|| LayoutError::UnknownRoot {
            path: path.display().to_string(),
        })?;
    let mut record = read_record(root);
    match record.owner_of(&spec.path) {
        Some(existing) if existing == owner => return Ok(()),
        Some(_) => {
            return Err(LayoutError::OwnerRecorded {
                path: spec.path.display().to_string(),
            });
        }
        None => record.record_once(&spec.path, spec.mode, owner),
    }
    write_record(root, &record)
}

/// Move a directory row's recorded owner to the principal that now owns it.
///
/// The one place an existing claim *is* replaced. Provisioning makes this change
/// on purpose: `admin user add --unix-user` hands `agent/` and `enrolments/` to
/// the user, and a record that still named the admin would report the handover as
/// drift on the very next `status`. The difference from [`record_file_owner`] is
/// the caller, not the mechanism: a rebind is asked for by name, while a file's
/// expected owner is inferred once from the account that wrote it and must not
/// move behind the operator's back (FR-024).
pub fn rebind_directory_owner(root: &Path, path: &Path, owner: u32) -> Result<(), LayoutError> {
    let spec = table(root)
        .into_iter()
        .find(|spec| spec.path == path)
        .filter(|spec| spec.kind == RootKind::Directory)
        .ok_or_else(|| LayoutError::UnknownRoot {
            path: path.display().to_string(),
        })?;
    let mut record = read_record(root);
    record.replace_owner(&spec.path, owner);
    write_record(root, &record)
}

/// Replace the recorded owner of one file row, on purpose.
///
/// The file counterpart of [`rebind_directory_owner`]: a handover that moves a
/// file from the account that provisioned it to the account that writes it has to
/// *replace* the claim, because keeping the old owner would report the binding as
/// drift on the next `status` — the opposite of recording it.
pub fn rebind_file_owner(root: &Path, path: &Path, owner: u32) -> Result<(), LayoutError> {
    let spec = table(root)
        .into_iter()
        .find(|spec| spec.path == path)
        .filter(|spec| spec.kind == RootKind::File)
        .ok_or_else(|| LayoutError::UnknownRoot {
            path: path.display().to_string(),
        })?;
    let mut record = read_record(root);
    record.replace_owner(&spec.path, owner);
    write_record(root, &record)
}

/// Why a delivery may not proceed: one drifted root, named.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "a protected root has drifted, so no record will be read or written: {finding}",
    finding = .finding.describe()
)]
pub struct LayoutRefusal {
    /// The finding that stopped the delivery.
    pub finding: PermissionFinding,
}

/// The refusal a delivery or an administrative write must carry, if any.
///
/// Reports the *first* drifted root. A list would be friendlier and is what
/// `ksp status` is for; a refusal has one job, which is to name something the
/// operator can look at.
pub fn refusal(root: &Path) -> Option<LayoutRefusal> {
    let spec = measured_rows(root);
    audit(root)
        .into_iter()
        .find(|finding| {
            finding.verdict.is_drift()
                && spec
                    .iter()
                    .any(|row| row.path == finding.path && row.refusal)
        })
        .map(|finding| LayoutRefusal { finding })
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    /// The store root carries the caller's own group, not the parent's.
    ///
    /// A directory created under `/tmp` on macOS inherits `wheel`, because the
    /// parent's group is `wheel`. The store's group is meant to be one both
    /// accounts share, and `admin user add` then tried to add the operator to
    /// `wheel` and told them to run as root.
    ///
    /// # Why this fixture is `/tmp` and not a tempdir
    ///
    /// `tempfile` creates under `/var/folders/...`, whose group is the caller's
    /// own. A store created there inherits the right group by accident, so a
    /// fixture in a tempdir passes whether or not the fix is present — it cannot
    /// discriminate. `/tmp` is the directory that reproduces the defect, so the
    /// test creates its home there and removes it afterwards.
    ///
    /// The test skips when `/tmp`'s group already equals this process's, because
    /// then the fixture cannot distinguish the two behaviours either.
    #[test]
    fn the_store_root_carries_the_callers_own_group() {
        let tmp = Path::new("/tmp");
        let tmp_gid = match std::fs::metadata(tmp) {
            Ok(metadata) => metadata.gid(),
            Err(_) => return,
        };
        let mine = ksp_posture::permissions::effective_gid();
        if tmp_gid == mine {
            // The fixture cannot tell the two behaviours apart on this host.
            return;
        }

        let home = tmp.join(format!(
            "ksp-group-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.subsec_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&home);
        let outcome = ensure(&home);
        let store = Layout::new(home.clone()).store_root();
        let observed = std::fs::metadata(&store).map(|metadata| metadata.gid());
        let _ = std::fs::remove_dir_all(&home);

        outcome.unwrap();
        assert_eq!(
            observed.unwrap(),
            mine,
            "the store root must carry this process's group, not /tmp's ({tmp_gid})"
        );
    }

    /// A store created under a directory with a different group is re-grouped.
    ///
    /// The direct test of the mechanism: a parent whose group differs from the
    /// caller's, and a store created inside it. The assertion is on the store
    /// root only — re-grouping every root would be a second, unexplained change
    /// to a boundary whose subject is mode and owner bits.
    #[test]
    fn a_store_under_a_foreign_group_is_regrouped() {
        let tmp = Path::new("/tmp");
        let tmp_gid = match std::fs::metadata(tmp) {
            Ok(metadata) => metadata.gid(),
            Err(_) => return,
        };
        let mine = ksp_posture::permissions::effective_gid();
        if tmp_gid == mine {
            return;
        }

        let parent = tmp.join(format!(
            "ksp-regroup-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.subsec_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir(&parent).unwrap();
        // The parent inherits `/tmp`'s group, which is the defect's precondition.
        assert_eq!(
            std::fs::metadata(&parent).unwrap().gid(),
            tmp_gid,
            "the fixture needs a parent whose group differs from the caller's"
        );

        let home = parent.join("ksp");
        let outcome = ensure(&home);
        let store = Layout::new(home.clone()).store_root();
        let observed = std::fs::metadata(&store).map(|metadata| metadata.gid());
        let _ = std::fs::remove_dir_all(&parent);

        outcome.unwrap();
        assert_eq!(
            observed.unwrap(),
            mine,
            "a store under a foreign group must be re-grouped to the caller's"
        );
    }

    /// The group is set on the store root only, and only when it differs.
    ///
    /// Re-grouping every root would be a second, unexplained change to a boundary
    /// whose subject is mode and owner bits. `set_store_group` is a no-op when the
    /// group already matches, which is what makes a second `ensure` cheap.
    #[test]
    fn setting_the_store_group_twice_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("ksp");
        ensure(&home).unwrap();
        let store = Layout::new(home.clone()).store_root();

        let before = std::fs::metadata(&store).unwrap();
        set_store_group(&store).unwrap();
        let after = std::fs::metadata(&store).unwrap();
        assert_eq!(before.gid(), after.gid());
        assert_eq!(before.uid(), after.uid(), "the owner is not changed");
        assert_eq!(
            before.permissions().mode(),
            after.permissions().mode(),
            "the mode is not changed"
        );
    }

    /// FR-013/FR-024: a file's expected owner is recorded when it is bound, and a
    /// second, different claim is refused rather than silently replacing the first.
    #[test]
    fn a_file_owner_is_recorded_once_and_a_conflicting_claim_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("ksp");
        ensure(&home).unwrap();
        let vault = Layout::new(home.clone()).vault_file();
        std::fs::write(&vault, b"sealed").unwrap();

        record_file_owner(&home, &vault, 4242).unwrap();
        assert_eq!(read_record(&home).owner_of(&vault), Some(4242));
        // The same claim again is not a change.
        record_file_owner(&home, &vault, 4242).unwrap();

        let refused = record_file_owner(&home, &vault, 4343).unwrap_err();
        assert!(
            matches!(refused, LayoutError::OwnerRecorded { .. }),
            "{refused}"
        );
        assert!(
            refused.to_string().contains("rebind"),
            "the refusal says why it will not replace the claim: {refused}"
        );
        assert_eq!(
            read_record(&home).owner_of(&vault),
            Some(4242),
            "the first claim survives the refused second one"
        );

        // A directory is not a file row, and a path the table does not name is not
        // a root at all: neither can be recorded this way.
        assert!(matches!(
            record_file_owner(&home, &home.join("store"), 4242).unwrap_err(),
            LayoutError::UnknownRoot { .. }
        ));
        assert!(matches!(
            record_file_owner(&home, &home.join("nowhere"), 4242).unwrap_err(),
            LayoutError::UnknownRoot { .. }
        ));
    }

    /// Run this test in its own process, and say whether the body should run.
    ///
    /// `umask` is process-wide and libtest runs the rest of this binary in the
    /// same process: setting a mask here would change what every other test
    /// creates, which is the same class of cross-test interference that made
    /// `ksp-posture`'s Landlock tests confine their siblings.
    fn isolated_process(test_name: &str) -> bool {
        /// Set in the child so it runs the body instead of spawning again.
        const MARKER: &str = "KSP_UMASK_ISOLATED_CHILD";

        if std::env::var_os(MARKER).is_some() {
            return true;
        }
        let exe = std::env::current_exe().expect("the test binary has a path");
        let output = std::process::Command::new(exe)
            .args([test_name, "--exact", "--nocapture"])
            .env(MARKER, "1")
            .output()
            .expect("the test binary re-runs itself");
        assert!(
            output.status.success(),
            "the isolated child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }

    #[test]
    fn a_fresh_home_has_every_mode_in_the_table() {
        // Acceptance criterion 1, row by row: the table is the specification and
        // the code has to agree with it, not the other way round.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ksp");
        ensure(&root).unwrap();

        let expected = [
            (HOME_MODE, root.clone()),
            (ADMIN_KEY_MODE, root.join("admin")),
            (AGENT_KEY_MODE, root.join("agent")),
            (ENROLMENTS_MODE, root.join("enrolments")),
            (STORE_MODE, root.join("store")),
            (SWEEPER_MODE, root.join("sweeper")),
            (SWEEPER_MODE, root.join("sweeper/proofs")),
            (AUDIT_MODE, root.join("audit")),
            (JOURNAL_MODE, root.join("journal")),
        ];
        for (mode, path) in expected {
            assert_eq!(mode_of(&path), mode, "{path:?} has the wrong mode");
        }
        // The file rows are measured but never created here: an empty vault would
        // be worse than an absent one.
        assert!(!root.join("vault.cbor").exists());
        assert!(!root.join("policy.cbor").exists());
    }

    #[test]
    fn an_inherited_umask_does_not_decide_the_boundary() {
        // Misfit B's second target: `umask 0002` must not widen a key root. The
        // mode is applied with `chmod`, which the umask cannot mask.
        if !isolated_process("layout::tests::an_inherited_umask_does_not_decide_the_boundary") {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ksp");

        // SAFETY (test-only): `umask` takes no pointer and returns the previous
        // mask. This runs in a child process dedicated to this one test, so the
        // mask cannot reach the rest of the binary.
        #[allow(unsafe_code)]
        let previous = unsafe { libc::umask(0o0002) };
        let created = ensure(&root);
        // SAFETY (test-only): restore the mask before any assertion can panic.
        #[allow(unsafe_code)]
        unsafe {
            libc::umask(previous)
        };
        created.unwrap();

        assert_eq!(mode_of(&root.join("admin")), ADMIN_KEY_MODE);
        assert_eq!(mode_of(&root.join("store")), STORE_MODE);
        assert!(
            audit(&root)
                .iter()
                .all(|finding| finding.verdict != ksp_posture::Verdict::Drift),
            "an inherited umask must not produce drift"
        );
    }

    #[test]
    fn a_second_ensure_leaves_an_existing_root_alone() {
        // Creating is this module's job; silently repairing someone else's
        // directory would erase the drift the operator has to see.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ksp");
        ensure(&root).unwrap();
        std::fs::set_permissions(root.join("admin"), std::fs::Permissions::from_mode(0o775))
            .unwrap();

        ensure(&root).unwrap();
        assert_eq!(mode_of(&root.join("admin")), 0o775, "ensure repaired drift");
        assert!(refusal(&root).is_some());
    }

    #[test]
    fn a_widened_key_root_is_a_refusal_naming_the_path_and_the_modes() {
        // Acceptance criterion 2's second half, at the unit level: `chmod 0775`
        // on `admin/` must be reported, and the sentence must carry the
        // measurement rather than an accusation.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ksp");
        ensure(&root).unwrap();
        std::fs::set_permissions(root.join("admin"), std::fs::Permissions::from_mode(0o775))
            .unwrap();

        let refusal = refusal(&root).expect("a widened key root must refuse");
        let sentence = refusal.to_string();
        assert!(sentence.contains("admin"), "{sentence}");
        assert!(sentence.contains("0775"), "{sentence}");
        assert!(sentence.contains("0700"), "{sentence}");
        assert!(
            !sentence.contains("attack"),
            "a refusal reports a measurement, not an accusation: {sentence}"
        );
    }

    #[test]
    fn a_fresh_home_never_refuses() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ksp");
        ensure(&root).unwrap();
        assert!(refusal(&root).is_none());
    }

    #[test]
    fn the_record_keeps_the_first_owner_it_saw() {
        // A recorded owner is a claim from the past. Re-recording it on a later
        // run is how a rebind becomes invisible (FR-024).
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ksp");
        ensure(&root).unwrap();
        let first = read_record(&root);
        let admin = root.join("admin");
        let recorded = first.owner_of(&admin).expect("admin is recorded");

        let mut record = first.clone();
        record.record_once(&admin, ADMIN_KEY_MODE, recorded.wrapping_add(1));
        assert_eq!(record.owner_of(&admin), Some(recorded));
    }

    #[test]
    fn a_file_written_into_a_missing_layout_directory_gets_that_rows_mode() {
        // `StoredEnrolment::save` and `Anchor::save` create their parent. Doing
        // that with the *home* row's mode would leave `enrolments/` at `0711` —
        // narrower than the table, so no refusal, and wrong for every principal
        // that has to read a pin.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ksp");
        std::fs::create_dir_all(&root).unwrap();

        ensure_known_parent(&root.join("enrolments/agent-7.cbor")).unwrap();
        assert_eq!(mode_of(&root.join("enrolments")), ENROLMENTS_MODE);

        ensure_known_parent(&root.join("admin/anchor.cbor")).unwrap();
        assert_eq!(mode_of(&root.join("admin")), ADMIN_KEY_MODE);
    }

    #[test]
    fn a_file_outside_the_layout_creates_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let somewhere = temp.path().join("not-a-deployment");
        std::fs::create_dir_all(&somewhere).unwrap();
        let file = somewhere.join("nested/thing.cbor");

        ensure_known_parent(&file).unwrap();
        assert!(!somewhere.join("nested").exists());
    }

    #[test]
    fn a_symlinked_root_is_refused_rather_than_created_through() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ksp");
        std::fs::create_dir_all(&root).unwrap();
        let elsewhere = temp.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("admin")).unwrap();

        match ensure(&root) {
            Err(LayoutError::Unusable { path, .. }) => assert!(path.contains("admin")),
            other => panic!("a symlinked key root must be refused, got {other:?}"),
        }
    }

    #[test]
    fn an_unrecorded_root_is_still_measured_against_the_table() {
        // A home provisioned before this revision has no record. Its owner is
        // not judged; its mode still is.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ksp");
        ensure(&root).unwrap();
        std::fs::remove_file(root.join("layout.cbor")).unwrap();
        std::fs::set_permissions(root.join("store"), std::fs::Permissions::from_mode(0o775))
            .unwrap();

        let findings = audit(&root);
        let store = findings
            .iter()
            .find(|finding| finding.path.ends_with("store"))
            .unwrap();
        assert_eq!(store.verdict, ksp_posture::Verdict::Drift);
        assert_eq!(store.expected_owner, ExpectedOwner::Unrecorded);
        assert_eq!(
            store.actual_owner,
            Some(std::fs::metadata(&root).unwrap().uid())
        );
    }

    #[test]
    fn a_level_is_owner_only_under_a_traversable_parent() {
        use ksp_types::{Level, PrincipalId, VaultId};

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ksp");
        ensure(&root).unwrap();

        let vault = VaultId::new("v-1");
        let principal = PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap();
        let level = ensure_level(&root, &vault, principal, &Level::User).unwrap();

        // The shared parents are traversable and not enumerable; the level itself
        // is the principal's own.
        // `store/` is its own row; everything between it and the level is a
        // level parent.
        let store_root = root.join("store");
        let mut parent = level.parent().unwrap().to_path_buf();
        while parent != store_root {
            assert_eq!(
                mode_of(&parent),
                LEVEL_PARENT_MODE,
                "{parent:?} on the way to a level"
            );
            parent = parent.parent().unwrap().to_path_buf();
        }
        assert_eq!(mode_of(&level), LEVEL_MODE);
        assert!(
            level.to_string_lossy().contains(&principal.to_string()),
            "the level is keyed by the principal UUID: {level:?}"
        );
    }

    #[test]
    fn the_record_is_owner_only_and_hidden_from_group_readers() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ksp");
        ensure(&root).unwrap();
        let record = root.join("layout.cbor");
        assert_eq!(mode_of(&record), 0o600);
        assert_eq!(record.metadata().unwrap().uid(), mode_uid());
    }

    fn mode_uid() -> u32 {
        std::fs::metadata(".").unwrap().uid()
    }
}
