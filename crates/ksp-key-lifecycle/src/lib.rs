//! Durable, owner-only storage for an enrolled agent or a pinned admin key.
//!
//! # The misfit
//!
//! Misfit R: every `ksp` operation is one foreground process that exits. The
//! agent's Ed25519 and X25519 private halves are generated at enrolment, so
//! unless something writes them down they are gone when that process ends, and
//! every later `ksp run` has no key to prove possession with. S2 owns the bytes
//! and their encoding; this crate owns the *file*: where it lives, who may read
//! it, and how it is replaced without ever publishing a half-written identity.
//!
//! # What this crate does not do
//!
//! It does not parse, mint or export private material. Every byte that reaches
//! the filesystem comes from [`ksp_identity::AgentKeyBundle::to_bytes`] and
//! every byte read back goes through [`ksp_identity::AgentKeyBundle::from_bytes`]
//! with a caller-supplied pin. There is no `private_bytes()` here, so the CLI
//! never holds a private half it could format, log or pass in `argv`.
//!
//! It is not encryption at rest. Mode `0600` restricts access to the owning
//! account; it cannot defend against a compromise of that account or of the
//! host, and repeating the mode as a guarantee would be exactly the kind of
//! overstatement §0 rule 3 withdraws.
//!
//! It is not a revocation mechanism. Rotation writes a new identity and keeps
//! the old one, so an artifact sealed before rotation still opens offline with
//! the retained file (SC-018). Rotation changes what is *minted*, not what has
//! already been captured.
//!
//! # The misfits this addresses
//!
//! - **B / H**: a captured token survives deletion, so an agent must reload the
//!   *same* key rather than a fresh one. A missing file is therefore a failure,
//!   never an invitation to generate a replacement.
//! - **M**: the CLI reports *Missing Key Material*; the classification here is
//!   what produces that code, so a tampered file cannot be mistaken for a
//!   transient host fault.
//! - **Q**: a bundle is only usable after the caller's pinned identity, role,
//!   key IDs and derived public halves agree with it.

#![deny(missing_docs)]

pub mod file;

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use ksp_identity::{
    AdminKeyBundle, AdminSigningKey, AdminSigningPin, AgentIdentityPin, AgentKeyBundle, AgentKeys,
    BundleError, KeyId, UnsignedEnrolment,
};
use ksp_types::AgentId;

use file::Install;

pub use file::MAX_KEY_FILE_BYTES;

/// The suffix every protected key file carries.
const KEY_SUFFIX: &str = ".key";

/// How a failure must be reported by the caller.
///
/// The mapping to an exit status lives in the CLI, which owns the published
/// codes. This crate only says *which* code applies, so `6` is not duplicated
/// in a library that cannot see the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFailure {
    /// The stored identity is absent, unreadable, tampered with or does not
    /// match what the caller pinned. Reported as *Missing Key Material*.
    MissingKeyMaterial,
    /// The host prevented the operation for a reason that is not about the key
    /// itself: a refused directory, a failed write, an occupied slot.
    UnusableHost,
}

impl KeyFailure {
    /// Whether the stored identity is unusable as stored.
    pub fn is_missing_key_material(self) -> bool {
        matches!(self, Self::MissingKeyMaterial)
    }
}

/// Why the key lifecycle refused an operation.
///
/// No variant carries file contents, key bytes or a raw OS error string: these
/// values reach a terminal, an audit entry and possibly a JSON body, and §5.6
/// keeps raw `err.message` out of responses. The OS error *kind* is enough to
/// distinguish "no space" from "not permitted" while debugging.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// No protected key file exists at the expected path.
    #[error("no protected key file is stored for this identity")]
    Missing,
    /// The path is a symbolic link. Following it would let a local attacker
    /// redirect the reload to a file they control.
    #[error("the protected key file is a symbolic link")]
    Symlink,
    /// The path exists but is not a regular file.
    #[error("the protected key file is not a regular file")]
    NotRegularFile,
    /// The file belongs to a different account than the key root.
    #[error("the protected key file is owned by a different account")]
    WrongOwner,
    /// The file is readable or writable by a group or by everyone.
    #[error("the protected key file has mode {found:04o}, expected 0600")]
    WrongMode {
        /// The mode that was found, masked to the permission bits.
        found: u32,
    },
    /// The file is larger than any bundle this build writes.
    #[error("the protected key file exceeds {limit} bytes")]
    TooLarge {
        /// The largest accepted size.
        limit: u64,
    },
    /// The file is shorter than its own metadata claims.
    #[error("the protected key file ended before its recorded length")]
    Truncated,
    /// The bytes are not a bundle this build accepts, or not the pinned one.
    #[error("the protected key file does not hold the expected identity: {0}")]
    Bundle(#[from] BundleError),
    /// The bytes could not be read back from disk.
    #[error("the protected key file could not be read")]
    ReadFailed,
    /// The bytes could not be written and synced.
    #[error("the protected key file could not be written")]
    WriteFailed,
    /// A unique temporary file could not be created next to the target.
    #[error("a temporary key file could not be created")]
    TempUnavailable,
    /// A protected key file already exists. Generation never replaces one.
    #[error("a protected key file already exists for this identity")]
    AlreadyExists,
    /// The replacement was installed but the directory sync did not confirm it.
    /// The file may be a complete new identity or the previous one; the caller
    /// must report uncertainty rather than success.
    #[error("the protected key file replacement could not be confirmed as durable")]
    CommitUncertain,
    /// An identity or key ID cannot be used as a file name.
    #[error("the identity cannot be used as a key file name")]
    InvalidName,
    /// The key root is missing, refused, or writable by another account.
    #[error("the key root is missing or does not have owner-only permissions")]
    RootUnavailable,
    /// The key root exists but is not a directory.
    #[error("the key root is not a directory")]
    NotADirectory,
    /// The generated keys could not be bound to an enrolment record.
    #[error("the enrolment record could not be bound")]
    Enrolment,
    /// The rotation source and the replacement name different identities.
    #[error("the replacement belongs to a different identity")]
    IdentityMismatch,
}

impl KeyError {
    /// Which published failure classification this error belongs to.
    pub fn failure(&self) -> KeyFailure {
        match self {
            Self::Missing
            | Self::Symlink
            | Self::NotRegularFile
            | Self::WrongOwner
            | Self::WrongMode { .. }
            | Self::TooLarge { .. }
            | Self::Truncated
            | Self::Bundle(_)
            | Self::ReadFailed => KeyFailure::MissingKeyMaterial,
            Self::WriteFailed
            | Self::TempUnavailable
            | Self::AlreadyExists
            | Self::CommitUncertain
            | Self::InvalidName
            | Self::RootUnavailable
            | Self::NotADirectory
            | Self::Enrolment
            | Self::IdentityMismatch => KeyFailure::UnusableHost,
        }
    }
}

/// A point at which a test can make the write path fail.
///
/// The real filesystem is the only thing that can fail in production, and it
/// cannot be asked to fail on demand. Naming the stages explicitly lets a test
/// assert what a crash at that point leaves behind, which is the difference
/// between "we call `fsync`" and "a failure after `fsync` still reports
/// uncertainty".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Before the protected file is opened for reading.
    BeforeRead,
    /// After the file has been read completely.
    AfterRead,
    /// After the temporary file has been written, before it is synced.
    AfterWrite,
    /// After the temporary file has been synced, before it is installed.
    AfterFileSync,
    /// Immediately before the install step. Nothing at the target has changed.
    BeforeCommit,
    /// After the install step, before the parent directory is synced. The
    /// target already holds the new bytes, but a crash could still lose them.
    AfterCommit,
    /// After the parent directory has been synced.
    AfterDirSync,
}

/// A place where a caller can inject a failure at a named [`Stage`].
///
/// The default implementation does nothing, which is what production uses. A
/// test implements [`KeyFileHooks::check`] and returns an error at one stage.
pub trait KeyFileHooks {
    /// Called at every stage. Returning an error aborts the operation there.
    fn check(&self, stage: Stage) -> Result<(), KeyError> {
        let _ = stage;
        Ok(())
    }
}

/// The production hook: nothing ever fails early.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoFailures;

impl KeyFileHooks for NoFailures {}

/// The directory that holds every protected key file.
///
/// The root is the trust anchor for ownership: it is created `0700` and must be
/// owner-only, so nothing another account can plant inside it is reachable in
/// the first place. Files are then required to belong to the same account as
/// the root.
#[derive(Debug, Clone)]
pub struct KeyRoot {
    dir: PathBuf,
    owner: u32,
}

impl KeyRoot {
    /// Open an existing owner-only key root, creating the final component if it
    /// is absent. Parent directories are never created implicitly: a store that
    /// invents its own path hierarchy can be pointed somewhere unexpected by a
    /// changed `HOME`.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, KeyError> {
        let dir = dir.into();
        file::ensure_dir(&dir)?;
        let metadata = std::fs::symlink_metadata(&dir).map_err(|_| KeyError::RootUnavailable)?;
        Ok(Self {
            dir,
            owner: metadata.uid(),
        })
    }

    /// The root directory.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// The account that owns the root. Every file inside must match it.
    pub fn owner(&self) -> u32 {
        self.owner
    }
}

/// Where a completed rotation put the retained and the new bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    /// The archived copy of the bundle that was replaced.
    pub archived: PathBuf,
    /// The protected key file that now holds the new identity.
    pub current: PathBuf,
}

/// The result of generating and storing a fresh agent identity.
///
/// The caller needs the unsigned enrolment, because the admin signs it. It also
/// needs the bundle, because the agent signs its own tokens with it. Neither
/// can be rebuilt from the other, and neither is recoverable from the file
/// without the pin that only exists once the record is signed.
pub struct EnrolledAgent {
    /// The typed authority for the new identity.
    pub bundle: AgentKeyBundle,
    /// The record the admin still has to sign.
    pub enrolment: UnsignedEnrolment,
    /// Where the protected key file was written.
    pub path: PathBuf,
}

impl std::fmt::Debug for EnrolledAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately not the bundle: a `Debug` that prints a private half
        // ends up in a panic message and then in a log.
        f.debug_struct("EnrolledAgent")
            .field("identity", &self.bundle.identity().to_string())
            .field("fingerprint", &self.bundle.fingerprint().to_hex())
            .field("path", &self.path)
            .finish()
    }
}

/// The typed persistence and reload surface for protected key files.
///
/// All methods are filesystem operations scoped to one [`KeyRoot`]; nothing
/// here caches key material between calls.
pub struct KeyStore<H: KeyFileHooks = NoFailures> {
    root: KeyRoot,
    hooks: H,
}

impl KeyStore<NoFailures> {
    /// A store that talks to the real filesystem and never injects a failure.
    pub fn new(root: KeyRoot) -> Self {
        Self {
            root,
            hooks: NoFailures,
        }
    }
}

impl<H: KeyFileHooks> KeyStore<H> {
    /// A store whose write and read stages run through `hooks`.
    pub fn with_hooks(root: KeyRoot, hooks: H) -> Self {
        Self { root, hooks }
    }

    /// The key root this store writes into.
    pub fn root(&self) -> &KeyRoot {
        &self.root
    }

    /// The protected file an agent identity reloads from, without touching it.
    ///
    /// The identity is validated as a path segment even though an `AgentId` is
    /// already a canonical UUID: this is the seam where a value becomes a file
    /// name, and a check that trusts its caller is not a check.
    pub fn agent_path(&self, identity: &AgentId) -> Result<PathBuf, KeyError> {
        let identity = identity.to_string();
        Ok(self
            .agent_dir_path()
            .join(format!("{}{KEY_SUFFIX}", file::safe_segment(&identity)?)))
    }

    /// The protected file an admin signing key reloads from.
    pub fn admin_path(&self, key_id: &KeyId) -> Result<PathBuf, KeyError> {
        Ok(self.admin_dir_path().join(format!(
            "{}{KEY_SUFFIX}",
            file::safe_segment(key_id.as_str())?
        )))
    }

    /// Generate a fresh agent identity and store it under `root/agent/`.
    ///
    /// Refuses to replace an existing file: a silent new key would make every
    /// artifact already sealed to the old one unopenable while every command
    /// still reported success.
    pub fn generate_agent(
        &self,
        identity: AgentId,
        signing_key_id: KeyId,
        recipient_key_id: KeyId,
    ) -> Result<EnrolledAgent, KeyError> {
        let keys = AgentKeys::generate();
        let enrolment = keys
            .enrol(identity, signing_key_id.clone(), recipient_key_id.clone())
            .map_err(|_| KeyError::Enrolment)?;
        let bundle = AgentKeyBundle::from_keys(&keys, identity, signing_key_id, recipient_key_id)?;
        let path = self.save_agent_new(&bundle)?;
        Ok(EnrolledAgent {
            bundle,
            enrolment,
            path,
        })
    }

    /// Store a freshly generated agent bundle, refusing to replace one.
    pub fn save_agent_new(&self, bundle: &AgentKeyBundle) -> Result<PathBuf, KeyError> {
        let target = self.agent_path(bundle.identity())?;
        let bytes = bundle.to_bytes()?;
        file::write_protected(
            &self.agent_dir_path(),
            &target,
            &bytes,
            Install::New,
            &self.hooks,
        )?;
        Ok(target)
    }

    /// Reload an agent identity and verify it against the caller's pin.
    ///
    /// Returns authority only after S2 has confirmed the file's role, identity,
    /// key IDs, public halves and fingerprint against values that did not come
    /// from the file.
    pub fn load_agent(&self, pin: &AgentIdentityPin) -> Result<AgentKeyBundle, KeyError> {
        let target = self.agent_path(&pin.identity)?;
        // The role directory is re-validated on the read path too: a symlinked
        // `agent/` would let the reload leave the key root entirely. Validated,
        // not created -- reading a key must not need permission to write one.
        file::validate_dir(&self.agent_dir_path())?;
        let bytes = file::read_protected(&target, self.root.owner(), &self.hooks)?;
        Ok(AgentKeyBundle::from_bytes(&bytes, pin)?)
    }

    /// Replace an agent identity, retaining the previous bundle beside it.
    pub fn rotate_agent(
        &self,
        current: &AgentIdentityPin,
        replacement: &AgentKeyBundle,
    ) -> Result<Rotation, KeyError> {
        // A rotation renames one identity's keys. Writing a different identity
        // into this file would leave the caller's pin pointing at a record the
        // file no longer matches, with no way to tell which agent is running.
        if replacement.identity() != &current.identity {
            return Err(KeyError::IdentityMismatch);
        }

        let dir = self.agent_dir_path();
        file::ensure_dir(&dir)?;
        let current_path = self.agent_path(&current.identity)?;
        let retained = file::read_protected(&current_path, self.root.owner(), &self.hooks)?;

        // Only archive bytes that still verify against the caller's pin. A file
        // that fails here is not the identity being rotated, and copying it
        // aside would preserve an attacker's bundle under our archive name.
        AgentKeyBundle::from_bytes(&retained, current)?;

        let archive_dir = dir.join("archive");
        file::ensure_dir(&archive_dir)?;
        let archived = archive_dir.join(format!(
            "{}-{}{KEY_SUFFIX}",
            file::safe_segment(&current.identity.to_string())?,
            current.confirmed_fingerprint.to_hex()
        ));
        // A rotation that failed at the replacement step has already archived
        // this identity. Refusing the identical archive on the retry would turn
        // one transient failure into a permanent inability to rotate, so an
        // archive that already holds exactly these bytes is success. A
        // *different* archive under the same name is still a conflict.
        match file::write_protected(
            &archive_dir,
            &archived,
            &retained,
            Install::New,
            &self.hooks,
        ) {
            Ok(()) => {}
            Err(KeyError::AlreadyExists) if self.archive_holds(&archived, &retained)? => {}
            Err(err) => return Err(err),
        }

        let replacement_bytes = replacement.to_bytes()?;
        file::write_protected(
            &dir,
            &current_path,
            &replacement_bytes,
            Install::Replace,
            &self.hooks,
        )?;

        Ok(Rotation {
            archived,
            current: current_path,
        })
    }

    /// Store a freshly generated admin signing bundle, refusing to replace one.
    pub fn save_admin_new(&self, bundle: &AdminKeyBundle) -> Result<PathBuf, KeyError> {
        let target = self.admin_path(bundle.key_id())?;
        let bytes = bundle.to_bytes()?;
        file::write_protected(
            &self.admin_dir_path(),
            &target,
            &bytes,
            Install::New,
            &self.hooks,
        )?;
        Ok(target)
    }

    /// Reload the admin signing authority and verify it against the trust anchor.
    pub fn load_admin(&self, pin: &AdminSigningPin) -> Result<AdminSigningKey, KeyError> {
        let target = self.admin_path(&pin.key_id)?;
        file::validate_dir(&self.admin_dir_path())?;
        let bytes = file::read_protected(&target, self.root.owner(), &self.hooks)?;
        Ok(AdminKeyBundle::from_bytes(&bytes, pin)?.into_key())
    }

    /// Whether the archive at `path` already contains exactly `expected`.
    fn archive_holds(&self, path: &Path, expected: &[u8]) -> Result<bool, KeyError> {
        match file::read_protected(path, self.root.owner(), &self.hooks) {
            Ok(found) => Ok(found.as_slice() == expected),
            Err(KeyError::Missing) => Ok(false),
            Err(err) => Err(err),
        }
    }

    fn agent_dir_path(&self) -> PathBuf {
        self.root.path().join("agent")
    }

    fn admin_dir_path(&self) -> PathBuf {
        self.root.path().join("admin")
    }
}
