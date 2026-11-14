//! The filesystem mechanics behind a protected key file.
//!
//! Every check in this module fails *closed*. A file that is a symlink, is a
//! directory, belongs to another account, is readable by a group, is larger
//! than a bundle, or was truncated is refused, and refusing means the caller
//! sees [`KeyError`] rather than a key it can sign with.
//!
//! The operations are not `canonicalize`-then-open. A path that was validated
//! and then re-opened can be replaced in between, so each file is opened with
//! `O_NOFOLLOW` and the checks run against the *descriptor's* metadata, which
//! is the object that will actually be read.
//!
//! Replacement is write-temp / `fsync` / install / `fsync`-parent. A failure
//! before the install step leaves the previous file untouched; a failure after
//! it is reported as [`KeyError::CommitUncertain`] rather than as success,
//! because a rename that has not been followed by a directory sync can still
//! be lost by a crash.

use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::{KeyError, KeyFileHooks, Stage};

/// The largest protected key file this build will read.
///
/// An agent bundle is ten short fields and an admin bundle five, so both are a
/// few hundred bytes. The bound exists so a substituted multi-gigabyte file
/// cannot be read into memory before it is refused.
pub const MAX_KEY_FILE_BYTES: u64 = 4096;

/// The only mode a protected key file may have.
const FILE_MODE: u32 = 0o600;

/// The only mode a key directory may have.
const DIR_MODE: u32 = 0o700;

/// How many temporary names to try before giving up.
const TEMP_ATTEMPTS: u32 = 16;

/// How a finished temporary file becomes the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Install {
    /// Refuse if anything is already at the target. Used for generation.
    New,
    /// Atomically replace whatever is at the target. Used for rotation.
    Replace,
}

/// Whether an identity string may be used as one path segment.
///
/// Rejects anything that could be read as structure rather than as a name: a
/// separator, a parent reference, a leading dot, a control character or an
/// over-long value. The check is on the *segment*, so the caller cannot smuggle
/// a second component in later.
///
/// The 96-byte bound is deliberately well below `NAME_MAX` (255), because the
/// archive name is this segment plus a hyphen plus a 64-character fingerprint
/// plus the suffix, and a name that exceeds the filesystem limit would fail at
/// rotation time instead of at enrolment time.
pub(crate) fn safe_segment(name: &str) -> Result<&str, KeyError> {
    const MAX_SEGMENT: usize = 96;

    if name.is_empty() || name.len() > MAX_SEGMENT {
        return Err(KeyError::InvalidName);
    }
    if name.starts_with('.') {
        return Err(KeyError::InvalidName);
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':');
    if !name.chars().all(allowed) {
        return Err(KeyError::InvalidName);
    }
    Ok(name)
}

/// Create `path` as an owner-only directory if it is absent, and refuse it if
/// it exists with anything other than owner-only permissions.
pub(crate) fn ensure_dir(path: &Path) -> Result<(), KeyError> {
    match fs::symlink_metadata(path) {
        Ok(md) => verify_dir(&md),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            DirBuilder::new()
                .mode(DIR_MODE)
                .create(path)
                .map_err(|_| KeyError::RootUnavailable)?;
            let md = fs::symlink_metadata(path).map_err(|_| KeyError::RootUnavailable)?;
            verify_dir(&md)
        }
        Err(_) => Err(KeyError::RootUnavailable),
    }
}

/// Validate an existing owner-only directory without creating it.
///
/// The read path uses this. Requiring `ensure_dir` there would make a reload
/// depend on write permission: a key root hardened to `0500`, or mounted
/// read-only, holds a perfectly readable key file and would still refuse.
pub(crate) fn validate_dir(path: &Path) -> Result<(), KeyError> {
    let md = fs::symlink_metadata(path).map_err(|_| KeyError::Missing)?;
    verify_dir(&md)
}

fn verify_dir(md: &Metadata) -> Result<(), KeyError> {
    if md.file_type().is_symlink() {
        return Err(KeyError::Symlink);
    }
    if !md.is_dir() {
        return Err(KeyError::NotADirectory);
    }
    // Group or world bits on a key directory would let another account create
    // or replace an entry inside it, which defeats the per-file ownership check
    // below. Refusing is the only safe answer; silently tightening someone
    // else's directory would change state we were not asked to change.
    if md.permissions().mode() & 0o077 != 0 {
        return Err(KeyError::RootUnavailable);
    }
    Ok(())
}

/// Check everything about a protected key file except its contents.
///
/// `read_protected` runs exactly this function on the descriptor it is about to
/// read, and the integration suite runs it on real files, so the checks a
/// reviewer has to believe are reached by tests rather than only by inspection.
pub fn verify_protected(path: &Path, expected_owner: u32) -> Result<(), KeyError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|err| open_refusal(path, err))?;
    let md = file.metadata().map_err(|_| KeyError::ReadFailed)?;
    verify_metadata(&md, expected_owner)
}

fn verify_metadata(md: &Metadata, expected_owner: u32) -> Result<(), KeyError> {
    if !md.file_type().is_file() {
        return Err(KeyError::NotRegularFile);
    }
    if md.uid() != expected_owner {
        return Err(KeyError::WrongOwner);
    }
    let mode = md.permissions().mode() & 0o777;
    if mode != FILE_MODE {
        return Err(KeyError::WrongMode { found: mode });
    }
    if md.len() > MAX_KEY_FILE_BYTES {
        return Err(KeyError::TooLarge {
            limit: MAX_KEY_FILE_BYTES,
        });
    }
    Ok(())
}

/// Read one protected key file, refusing everything that is not exactly a
/// complete owner-only regular file.
pub(crate) fn read_protected<H: KeyFileHooks>(
    path: &Path,
    expected_owner: u32,
    hooks: &H,
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    hooks.check(Stage::BeforeRead)?;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|err| open_refusal(path, err))?;

    // `file.metadata()` is the descriptor's own metadata: whatever path was
    // resolved a moment ago cannot be swapped underneath these checks.
    let md = file.metadata().map_err(|_| KeyError::ReadFailed)?;
    verify_metadata(&md, expected_owner)?;

    let mut buffer = Zeroizing::new(Vec::with_capacity(md.len() as usize));
    let read = file
        .take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut buffer)
        .map_err(|_| KeyError::ReadFailed)?;
    if (read as u64) > MAX_KEY_FILE_BYTES {
        return Err(KeyError::TooLarge {
            limit: MAX_KEY_FILE_BYTES,
        });
    }
    if read as u64 != md.len() {
        return Err(KeyError::Truncated);
    }

    hooks.check(Stage::AfterRead)?;
    Ok(buffer)
}

fn open_refusal(path: &Path, err: std::io::Error) -> KeyError {
    if err.raw_os_error() == Some(libc::ELOOP) {
        return KeyError::Symlink;
    }
    match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_symlink() => KeyError::Symlink,
        Ok(_) => KeyError::ReadFailed,
        Err(_) => KeyError::Missing,
    }
}

/// Write `bytes` to `target` through a synced temporary file and an atomic
/// install, then sync the directory so the name itself survives a crash.
pub(crate) fn write_protected<H: KeyFileHooks>(
    dir: &Path,
    target: &Path,
    bytes: &[u8],
    install: Install,
    hooks: &H,
) -> Result<(), KeyError> {
    ensure_dir(dir)?;
    let (temp_path, mut temp) = create_temp(dir, target)?;

    // Any failure below the install step removes the temporary file. A leftover
    // temp file is not another identity's key, but it is still secret material
    // on disk and it must not accumulate in the key root.
    let outcome = commit(&temp_path, &mut temp, target, bytes, install, hooks);
    if outcome.is_err() {
        drop(temp);
        let _ = fs::remove_file(&temp_path);
    }
    outcome
}

fn commit<H: KeyFileHooks>(
    temp_path: &Path,
    temp: &mut File,
    target: &Path,
    bytes: &[u8],
    install: Install,
    hooks: &H,
) -> Result<(), KeyError> {
    temp.write_all(bytes).map_err(|_| KeyError::WriteFailed)?;
    hooks.check(Stage::AfterWrite)?;
    temp.sync_all().map_err(|_| KeyError::WriteFailed)?;
    hooks.check(Stage::AfterFileSync)?;

    // Last chance to abort with the previous file exactly as it was.
    hooks.check(Stage::BeforeCommit)?;

    match install {
        Install::New => {
            // A hard link is an atomic, no-clobber install: two concurrent
            // generations of the same identity cannot both succeed, and no
            // reader ever observes a partially written file at the target.
            fs::hard_link(temp_path, target).map_err(|err| {
                if err.kind() == std::io::ErrorKind::AlreadyExists {
                    KeyError::AlreadyExists
                } else {
                    KeyError::WriteFailed
                }
            })?;
            // The target now holds a complete identity. Failing to unlink the
            // temporary name is a cleanup that did not happen, not a write that
            // did not happen: reporting `WriteFailed` here would tell the caller
            // no key exists while one does, and a retry would answer
            // `AlreadyExists`. That contradiction is what `CommitUncertain`
            // exists for.
            if fs::remove_file(temp_path).is_err() {
                return Err(KeyError::CommitUncertain);
            }
        }
        Install::Replace => {
            fs::rename(temp_path, target).map_err(|_| KeyError::WriteFailed)?;
        }
    }

    // Past this point the previous file is gone. A directory sync that fails
    // means the new name may not survive a crash, and reporting success would
    // claim a durable identity that may not be there next time.
    hooks
        .check(Stage::AfterCommit)
        .map_err(|_| KeyError::CommitUncertain)?;
    sync_dir(target.parent().unwrap_or(Path::new("."))).map_err(|_| KeyError::CommitUncertain)?;
    hooks
        .check(Stage::AfterDirSync)
        .map_err(|_| KeyError::CommitUncertain)?;
    Ok(())
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Create a unique owner-only temporary file beside the target.
///
/// The name is derived from the target plus the process id plus a counter, so
/// two concurrent writers converge on different names instead of one clobbering
/// the other's in-progress file. `create_new` makes the uniqueness a kernel
/// guarantee rather than a stat-then-create race.
fn create_temp(dir: &Path, target: &Path) -> Result<(PathBuf, File), KeyError> {
    let base = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(KeyError::InvalidName)?;
    let pid = std::process::id();

    for attempt in 0..TEMP_ATTEMPTS {
        let candidate = dir.join(format!(".{base}.tmp.{pid}.{attempt}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(KeyError::TempUnavailable),
        }
    }
    Err(KeyError::TempUnavailable)
}
