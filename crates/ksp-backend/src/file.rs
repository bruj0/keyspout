//! Durable local Blob Store for records; no lease capability in MVP.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use crate::arming::{ArmError, ArmingStore, Durability};
use crate::store::{BlobStore, StoreError, validate_path, validate_prefix};
use crate::sweep::SweepStore;
use ksp_types::BoundMetadata;

/// The reserved directory name for the store's own machinery.
///
/// The lock and replacement files live in a directory with this name
/// beside their target. A blob path may not contain a component with this
/// name, so the machinery can never collide with a stored blob: a suffix
/// on the target's own name would, because a blob may legitimately be
/// called `head.ksp-replacement` and the store would overwrite it.
const MACHINERY: &str = ".ksp-machinery";

/// The mode a store root is created with.
///
/// A store root is shared by design: every principal has to reach its own level
/// directory, so the root is traversable and the per-level directories below it
/// carry the boundary. This is the one definition of the number — the CLI's
/// layout table reads it rather than restating it.
pub const STORE_ROOT_MODE: u32 = 0o755;

/// The result of a listing that tolerates a directory it cannot read.
///
/// `paths` is what the walk reached; `unreadable` is what it could not enter. The
/// two are separate because they answer different questions, and a caller that
/// collapsed them would report a partial listing as complete — which is D4's
/// defect in another form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LenientListing {
    /// Every blob path the walk reached, relative to the store root, sorted.
    pub paths: Vec<String>,
    /// Directories the walk could not read, named by path, mode and owner.
    pub unreadable: Vec<UnreadableDirectory>,
}

/// A directory a listing could not enter.
///
/// The mode and owner are carried because a refusal that says only "unreadable"
/// sends the operator to `ls` with no idea what to look for. `0711` traversable
/// and `0700` readable-by-owner-only are different situations with different
/// fixes, and the caller cannot tell them apart from a path alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableDirectory {
    /// The path, relative to the store root.
    pub path: String,
    /// The directory's mode, masked to the permission bits.
    pub mode: u32,
    /// The uid that owns it.
    pub owner: u32,
    /// The filesystem's own reason, in its own words.
    ///
    /// Carried rather than dropped: `EACCES` is a permission this caller lacks,
    /// `ENOTDIR` is a path that is not a directory at all and `ELOOP` is a
    /// symlink cycle, and the three have different fixes. A mode and an owner
    /// describe the state but not the failure, and this is a report *about the
    /// failure*.
    pub reason: String,
}

impl UnreadableDirectory {
    /// Describe the directory at `target` relative to `root`.
    ///
    /// `error` is the filesystem's own words and is kept: it names the failure,
    /// where the mode and owner describe the state. Both are needed, because a
    /// `0700` on a directory this account owns is not the same problem as a
    /// `0700` on one it does not.
    ///
    /// The metadata is read defensively — a directory that cannot be listed is
    /// usually one whose metadata still can be — so an unreadable mode is
    /// reported as `0` rather than failing the whole listing.
    fn describe(root: &Path, target: &Path, error: &std::io::Error) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        let relative = target
            .strip_prefix(root)
            .unwrap_or(target)
            .to_string_lossy()
            .to_string();
        let (mode, owner) = std::fs::metadata(target)
            .map(|meta| (meta.mode() & 0o7777, meta.uid()))
            .unwrap_or((0, 0));
        Self {
            path: relative,
            mode,
            owner,
            reason: error.to_string(),
        }
    }
}

/// Local opaque blob storage, confined to a caller-selected root.
#[derive(Debug)]
pub struct FileStore {
    root: PathBuf,
}

impl FileStore {
    /// Create a store rooted at an existing, trusted directory.
    ///
    /// A missing root is created [`STORE_ROOT_MODE`] and then `chmod`-ed to it:
    /// `DirBuilder::mode` alone is masked by the process's `umask`, which is how a
    /// store root ends up `0775` on a host whose login shell sets `umask 0002`.
    pub fn new(root: PathBuf) -> Result<Self, StoreError> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        match fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(StoreError::Backend("file root is not a directory".into()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .mode(STORE_ROOT_MODE)
                    .create(&root)
                    .map_err(|_| StoreError::Backend("file root unavailable".into()))?;
                fs::set_permissions(&root, fs::Permissions::from_mode(STORE_ROOT_MODE))
                    .map_err(|_| StoreError::Backend("file root unavailable".into()))?;
            }
            Err(_) => return Err(StoreError::Backend("file root unavailable".into())),
        }
        Ok(Self { root })
    }

    /// The directory this store is rooted at.
    ///
    /// Exposed for the one file that is not a blob: the use counter, which lives
    /// under the reserved machinery directory and is read by the sweep rather
    /// than by the store's own listing.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, name: &str) -> Result<PathBuf, StoreError> {
        validate_path(name)?;
        let relative = Path::new(name);
        // `validate_path` already refuses `.` and `..`; the component walk is
        // the second half of the same rule, so a future change to one cannot
        // silently weaken the other.
        if !relative
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        {
            return Err(StoreError::Backend("invalid blob path".into()));
        }
        // The machinery directory is reserved. A blob may not be stored
        // there, because the store's own lock and replacement files live
        // there and a blob would be overwritten by them.
        if relative
            .components()
            .any(|c| c.as_os_str() == std::ffi::OsStr::new(MACHINERY))
        {
            return Err(StoreError::Backend("invalid blob path".into()));
        }
        let target = self.root.join(relative);
        self.confine(&target)?;
        Ok(target)
    }

    /// Refuse any path whose ancestors inside the root are symbolic links.
    ///
    /// A lexical check on the path components is a check, not containment: a
    /// symlink planted inside the root by anything sharing the root's owner
    /// would otherwise let `get` read a file outside it. Every ancestor is
    /// inspected with `symlink_metadata`, so the link itself is reported
    /// rather than followed.
    fn confine(&self, target: &Path) -> Result<(), StoreError> {
        let relative = target
            .strip_prefix(&self.root)
            .map_err(|_| StoreError::Backend("invalid blob path".into()))?;
        let mut current = self.root.clone();
        for component in relative.components() {
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(StoreError::Backend("blob path escapes the store".into()));
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(StoreError::Backend("blob path unavailable".into())),
            }
        }
        Ok(())
    }

    fn persist(parent: &Path) -> Result<(), StoreError> {
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| StoreError::Backend("file directory sync failed".into()))
    }

    /// The exclusive lock that serialises a conditional replace.
    ///
    /// The lock lives beside the target, not in it: the target may be
    /// replaced by a rename, which would otherwise replace the inode the
    /// lock is held on and silently release the lock for every other
    /// writer. A dedicated lock file keeps the lock valid across the
    /// replacement.
    /// The lock and the replacement file live in a reserved directory
    /// beside the target, not under a name derived from the target's own
    /// name. A derived name would collide: a blob may legitimately be
    /// called `head.ksp-lock`, and the store would overwrite it.
    fn sibling(&self, target: &Path, marker: &str) -> Result<PathBuf, StoreError> {
        let name = target
            .file_name()
            .ok_or_else(|| StoreError::Backend("invalid blob path".into()))?;
        let mut sibling = target.with_file_name(MACHINERY);
        sibling.push(name);
        sibling.push(marker);
        Ok(sibling)
    }

    fn lock_path(&self, target: &Path) -> Result<PathBuf, StoreError> {
        self.sibling(target, "ksp-lock")
    }

    /// Take the exclusive lock for a target path.
    ///
    /// The lock is advisory and per-open-file-description, so it excludes
    /// every other writer that takes the same lock the same way — which is
    /// every writer in this process and every other process using this
    /// store.
    fn lock(&self, target: &Path) -> Result<std::fs::File, StoreError> {
        let lock_path = self.lock_path(target)?;
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|_| StoreError::Backend("file directory unavailable".into()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|_| StoreError::Backend("file lock unavailable".into()))?;
        file.lock()
            .map_err(|_| StoreError::Backend("file lock unavailable".into()))?;
        Ok(file)
    }

    /// Every blob path under `prefix`, plus the directories the walk could not
    /// read.
    ///
    /// [`BlobStore::list`] fails the whole walk on the first unreadable directory.
    /// A caller that may *name* a level is not necessarily one that may *enumerate*
    /// it: the Level Parent is `0711` and the Level Directory `0700`, so an admin
    /// traverses another principal's directory and cannot list it. Collecting the
    /// failure is the honest answer; widening a mode is not.
    ///
    /// # Why this is inherent and not on the trait
    ///
    /// `EACCES` on a directory is a filesystem fact. S3 and Valkey have no
    /// directory permission to report and cannot model one, so putting this on
    /// `BlobStore` would make two backends carry a concept they do not have.
    /// `open_file_store` returns this concrete type, so an inherent method reaches
    /// the CLI without touching the swappable-integration boundary.
    pub fn list_lenient(&self, prefix: &str) -> Result<LenientListing, StoreError> {
        let mut found = Vec::new();
        let mut unreadable = Vec::new();
        validate_prefix(prefix)?;
        let prefix = prefix.strip_suffix('/').unwrap_or(prefix);

        fn visit(
            root: &Path,
            dir: &Path,
            prefix: &str,
            found: &mut Vec<String>,
            unreadable: &mut Vec<UnreadableDirectory>,
        ) {
            let entries = match fs::read_dir(dir) {
                Ok(entries) => entries,
                Err(error) => {
                    // The directory the request reached and could not read. Named
                    // with its mode and owner, because "unreadable" alone sends an
                    // operator to `ls` with no idea what to look for.
                    unreadable.push(UnreadableDirectory::describe(root, dir, &error));
                    return;
                }
            };
            for item in entries.flatten() {
                let Ok(kind) = item.file_type() else { continue };
                if item.file_name() == std::ffi::OsStr::new(MACHINERY) {
                    continue;
                }
                let path = item.path();
                let Ok(relative) = path.strip_prefix(root) else {
                    continue;
                };
                let relative = relative.to_string_lossy().to_string();
                if kind.is_dir() {
                    // Both directions, as `list` does: walk down to a prefix that
                    // starts with this directory, and below one that names a
                    // directory. Dropping the second made `admin list` print
                    // nothing on a store full of records.
                    if prefix.is_empty()
                        || prefix.starts_with(&relative)
                        || relative.starts_with(prefix)
                    {
                        let before = unreadable.len();
                        visit(root, &path, prefix, found, unreadable);
                        // A directory the request never reached is not the caller's
                        // finding to report; only the ones on the way count.
                        if unreadable.len() > before
                            && !(prefix.starts_with(&relative) || relative.starts_with(prefix))
                        {
                            unreadable.truncate(before);
                        }
                    }
                } else if kind.is_file() && relative.starts_with(prefix) {
                    found.push(relative);
                }
            }
        }

        visit(&self.root, &self.root, prefix, &mut found, &mut unreadable);
        found.sort();
        unreadable.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(LenientListing {
            paths: found,
            unreadable,
        })
    }
}

impl ksp_record::version::BlobStore for FileStore {
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let target = self.path(path)?;
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&target)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                return Err(StoreError::Backend("blob path escapes the store".into()));
            }
            Err(_) => return Err(StoreError::Backend("file read failed".into())),
        };
        let mut bytes = Vec::new();
        use std::io::Read;
        file.read_to_end(&mut bytes)
            .map_err(|_| StoreError::Backend("file read failed".into()))?;
        Ok(Some(bytes))
    }

    fn put_if_absent(&self, path: &str, bytes: &[u8]) -> Result<bool, StoreError> {
        let target = self.path(path)?;
        let parent = target
            .parent()
            .ok_or_else(|| StoreError::Backend("invalid parent".into()))?;
        fs::create_dir_all(parent)
            .map_err(|_| StoreError::Backend("file directory unavailable".into()))?;
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            // A record is its owner's: a level directory may be traversable (or,
            // for an agent level, group-writable by the sweep), and a record that
            // took the caller's umask would be readable through it.
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&target)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
            Err(_) => return Err(StoreError::Backend("file create failed".into())),
        };
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| StoreError::Backend("file write failed".into()))?;
        Self::persist(parent)?;
        Ok(true)
    }

    /// Replace bytes only when the current value matches `expected`.
    ///
    /// A read-then-write is not atomic, so the comparison and the
    /// replacement are performed while holding an exclusive lock on a lock
    /// file beside the target. The replacement itself is a `rename(2)` of a
    /// fully written temporary file, so a reader never observes a partial
    /// value.
    ///
    /// The lock file is not the target, so replacing the target does not
    /// release the lock for another writer.
    fn compare_and_set(
        &self,
        path: &str,
        expected: Option<&[u8]>,
        replacement: &[u8],
    ) -> Result<bool, StoreError> {
        let target = self.path(path)?;
        let parent = target
            .parent()
            .ok_or_else(|| StoreError::Backend("invalid parent".into()))?;
        fs::create_dir_all(parent)
            .map_err(|_| StoreError::Backend("file directory unavailable".into()))?;

        // The lock is taken before the current value is read, so the value
        // read here cannot change before the replacement.
        let _lock = self.lock(&target)?;

        let current = match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StoreError::Backend("blob path escapes the store".into()));
            }
            Ok(_) => {
                let mut bytes = Vec::new();
                use std::io::Read;
                std::fs::File::open(&target)
                    .and_then(|mut file| file.read_to_end(&mut bytes))
                    .map_err(|_| StoreError::Backend("file read failed".into()))?;
                Some(bytes)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(StoreError::Backend("file read failed".into())),
        };
        if current.as_deref() != expected {
            return Ok(false);
        }

        // Write the replacement beside the target and rename it over. The
        // temporary name is derived from the target's own name, so two
        // writers on the same path cannot collide: they are serialised by
        // the lock.
        let temporary = self.sibling(&target, "ksp-replacement")?;
        {
            let mut file = match OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                // The replacement inherits the record's owner-only mode, not the
                // writer's umask: it is renamed over the target.
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temporary)
            {
                Ok(file) => file,
                Err(_) => return Err(StoreError::Backend("file create failed".into())),
            };
            file.write_all(replacement)
                .and_then(|_| file.sync_all())
                .map_err(|_| StoreError::Backend("file write failed".into()))?;
        }
        fs::rename(&temporary, &target)
            .map_err(|_| StoreError::Backend("file replace failed".into()))?;
        Self::persist(parent)?;
        Ok(true)
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let mut found = Vec::new();
        validate_prefix(prefix)?;
        let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
        fn visit(
            root: &Path,
            dir: &Path,
            prefix: &str,
            found: &mut Vec<String>,
        ) -> Result<(), StoreError> {
            for item in
                fs::read_dir(dir).map_err(|_| StoreError::Backend("file listing failed".into()))?
            {
                let entry = item.map_err(|_| StoreError::Backend("file listing failed".into()))?;
                let kind = entry
                    .file_type()
                    .map_err(|_| StoreError::Backend("file listing failed".into()))?;
                // The machinery directory holds the store's own lock and
                // replacement files. A listing must report only the blobs
                // the store holds.
                if entry.file_name() == std::ffi::OsStr::new(MACHINERY) {
                    continue;
                }
                if kind.is_dir() {
                    // Descend only where the prefix can begin *or continue*.
                    // An `agent-<id>` level is `0730`: the sweep group may unlink
                    // a copy it cannot list, so a listing that wandered into
                    // every directory would fail for the one caller whose job is
                    // to delete from it. A directory the request does not reach is
                    // not read at all, and one it does reach still fails loudly.
                    //
                    // Both directions matter. The first (`prefix` starts with the
                    // directory) walks the ancestors on the way down; the second
                    // (the directory starts with `prefix`) walks *below* a prefix
                    // that names a directory, which is how every caller names a
                    // level: `list("p/<vault>/<user>/user")` must reach
                    // `…/user/<secret>/<version>`. Dropping it made `secret ls`
                    // and `admin list` print nothing on a store full of records.
                    let relative = entry
                        .path()
                        .strip_prefix(root)
                        .map_err(|_| StoreError::Backend("invalid path".into()))?
                        .to_string_lossy()
                        .to_string();
                    if prefix.is_empty()
                        || prefix.starts_with(&relative)
                        || relative.starts_with(prefix)
                    {
                        visit(root, &entry.path(), prefix, found)?;
                    }
                } else if kind.is_file() {
                    let relative = entry
                        .path()
                        .strip_prefix(root)
                        .map_err(|_| StoreError::Backend("invalid path".into()))?
                        .to_string_lossy()
                        .to_string();
                    if relative.starts_with(prefix) {
                        found.push(relative);
                    }
                }
            }
            Ok(())
        }
        visit(&self.root, &self.root, prefix, &mut found)?;
        found.sort();
        Ok(found)
    }
}

impl BlobStore for FileStore {
    fn delete(&self, path: &str) -> Result<(), StoreError> {
        let target = self.path(path)?;
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StoreError::Backend("blob path escapes the store".into()));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(StoreError::Backend("file delete failed".into())),
        }
        match fs::remove_file(&target) {
            Ok(()) => Self::persist(
                target
                    .parent()
                    .ok_or_else(|| StoreError::Backend("invalid parent".into()))?,
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(StoreError::Backend("file delete failed".into())),
        }
    }
}

impl ArmingStore for FileStore {
    /// Write the key-free arm record under the operation identity.
    ///
    /// The write is create-new: an existing record under the same identity
    /// is a different intent, and overwriting it would destroy the evidence
    /// of the earlier arm. The caller compares the bytes.
    fn arm_once(
        &self,
        identity: &str,
        bytes: &[u8],
        _deadline: i64,
    ) -> Result<Durability, ArmError> {
        if identity.is_empty() || identity.contains('/') || identity.contains("..") {
            return Err(ArmError::InvalidIdentity);
        }
        let path = format!("intents/{identity}");
        let target = self.path(&path).map_err(|_| ArmError::Uncertain)?;
        let parent = target.parent().ok_or(ArmError::Uncertain)?.to_path_buf();
        fs::create_dir_all(&parent).map_err(|_| ArmError::Uncertain)?;

        // The lock serialises the check and the write, so a concurrent
        // arming under the same identity cannot interleave with it.
        let _lock = self.lock(&target).map_err(|_| ArmError::Uncertain)?;

        let existing = match fs::read(&target) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(ArmError::Uncertain),
        };
        if let Some(existing) = existing {
            // Identical bytes are a retry of the same arming; different
            // bytes are a different intent under the same identity.
            return if existing == bytes {
                Ok(Durability::LocalSync)
            } else {
                Err(ArmError::IdentityConflict)
            };
        }

        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&target)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Lost the race. The caller reconciles by comparing bytes.
                return Err(ArmError::Uncertain);
            }
            Err(_) => return Err(ArmError::Uncertain),
        };
        // The journal is shared: the armer is the principal and the reader is the
        // sweep, which runs as the deployment's owner, so the record has to be
        // readable across accounts. `mode` on `open` would be masked by the
        // armer's umask — a principal who logs in with `umask 077` would arm a
        // record nobody else can read, and the sweep would report a failure
        // instead of a lease to remove. `fchmod` is not masked.
        file.set_permissions(std::fs::Permissions::from_mode(0o644))
            .map_err(|_| ArmError::Uncertain)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| ArmError::Uncertain)?;
        Self::persist(&parent).map_err(|_| ArmError::Uncertain)?;
        Ok(Durability::LocalSync)
    }

    fn read_arm(&self, identity: &str) -> Result<Option<Vec<u8>>, ArmError> {
        if identity.is_empty() || identity.contains('/') || identity.contains("..") {
            return Err(ArmError::InvalidIdentity);
        }
        let path = format!("intents/{identity}");
        let target = self.path(&path).map_err(|_| ArmError::Uncertain)?;
        match fs::read(&target) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(ArmError::Uncertain),
        }
    }

    fn remaining_uses(&self, operation_identity: &str) -> Option<u32> {
        crate::usebound::remaining(&self.root, operation_identity)
    }

    fn list_arms(&self) -> Result<Vec<(String, Vec<u8>)>, ArmError> {
        use ksp_record::version::BlobStore as _;

        let paths = self.list("intents/").map_err(|_| ArmError::Uncertain)?;
        let mut records = Vec::with_capacity(paths.len());
        for path in paths {
            let Some(identity) = path.strip_prefix("intents/") else {
                continue;
            };
            if identity.is_empty() || identity.contains('/') {
                continue;
            }
            // A path can vanish between the listing and the read; a record that
            // is already gone has nothing to sweep.
            if let Some(bytes) = self.get(&path).map_err(|_| ArmError::Uncertain)? {
                records.push((identity.to_string(), bytes));
            }
        }
        records.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(records)
    }
}

impl SweepStore for FileStore {
    /// Remove exactly the version the metadata names, and say whether it was there.
    ///
    /// The lookup exists to tell a removal from an absence: `delete` is happy
    /// either way, and counting an already-absent version as a removal would
    /// claim an observation this host did not make. The two calls are not one
    /// transaction, so a concurrent writer can win the race — a sweep is
    /// best-effort cleanup, and the report would then say "removed" about a
    /// version someone else had just written. That is a smaller error than
    /// deleting a version this host never checked for.
    fn remove_exact(&self, metadata: &BoundMetadata) -> Result<Option<String>, StoreError> {
        use ksp_record::version::BlobStore as _;

        let path = ksp_record::RecordPath::of(metadata).to_string();
        if self.get(&path)?.is_none() {
            return Ok(None);
        }
        self.delete(&path)?;
        Ok(Some(format!("event:{path}")))
    }
}
