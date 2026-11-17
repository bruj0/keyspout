//! Where a grant's sealed record is published, and the modes it is written with.
//!
//! # One artifact per `(secret, version)`
//!
//! `p/<vault>/<admin>/granted/<secret>/<version>` (FR-016). The path names no
//! target because two grants of one secret version share the artifact: the blob is
//! sealed once, and the content key is sealed **once per referencing policy** into
//! that policy's own entry (FR-015, CF-017). `RecordEnvelope` seals to exactly one
//! recipient and stays that way — the publication is the thing that holds several.
//!
//! # A second accepted shape is a second place to widen
//!
//! Misfit E is not that the publication is readable; it is that the widening
//! reached something else under the admin's principal. So the path is *derived*
//! and [`PublicationPath::parse`] refuses every near miss, and [`apply_modes`]
//! writes exactly two modes: `0750` on the directories it owns and `0740` on the
//! artifact. Both go through `set_permissions`, because `open(2)`'s mode is masked
//! by the caller's `umask` (misfit B of feature 002, relearned).
//!
//! The principal root and the store root keep the modes the layout gave them, and
//! nothing here writes to an entry it does not own: a sibling is not repaired to a
//! default, because guessing a mode for a record this module did not create is how
//! a widening acquires a second author.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use ksp_types::{
    BoundMetadata, ContentKey, Level, OpaqueSecretId, PrincipalId, RecordVersion, VaultId,
};

use crate::config::Layout;

/// The directory modes: readable and traversable by every principal.
pub const PUBLICATION_DIR_MODE: u32 = 0o750;

/// The artifact mode: readable by every principal, writable by the admin alone.
pub const PUBLICATION_FILE_MODE: u32 = 0o740;

/// The principal-root mode, restated where the sibling assertion reads it.
pub const PRINCIPAL_ROOT_MODE: u32 = crate::layout::PRINCIPAL_ROOT_MODE;

/// The accepted path shape, in the words a refusal prints.
const ACCEPTED: &str = "p/<vault>/<admin>/granted/<secret>/<version>";

/// One publication's location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationPath {
    vault: VaultId,
    admin: PrincipalId,
    secret: OpaqueSecretId,
    version: RecordVersion,
}

impl PublicationPath {
    /// Derive the one accepted path.
    pub fn derive(
        vault: VaultId,
        admin: PrincipalId,
        secret: OpaqueSecretId,
        version: RecordVersion,
    ) -> Self {
        Self {
            vault,
            admin,
            secret,
            version,
        }
    }

    /// Parse the path a token or an operator named.
    ///
    /// Exactly `p/<vault>/<admin>/granted/<secret>/<version>`: six segments, the
    /// fourth the word `granted`, the third a canonical principal UUID and the last
    /// a version number. A path that is not that is refused **naming the accepted
    /// shape**, so an operator can derive one instead of guessing which segment was
    /// wrong.
    pub fn parse(text: &str) -> Result<Self, PublicationPathError> {
        let refuse = || PublicationPathError::NotAPublication {
            path: text.to_string(),
            accepted: ACCEPTED.to_string(),
        };
        let parts: Vec<&str> = text.split('/').collect();
        if parts.len() != 6 || parts[0] != "p" || parts[3] != "granted" {
            return Err(refuse());
        }
        if parts
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == "..")
        {
            return Err(refuse());
        }
        let version: u32 = parts[5].parse().map_err(|_| refuse())?;
        Ok(Self {
            vault: VaultId::new(parts[1]),
            admin: PrincipalId::parse(parts[2]).map_err(|_| refuse())?,
            secret: OpaqueSecretId::new(parts[4]),
            version: RecordVersion(version),
        })
    }

    /// The vault the publication belongs to.
    pub fn vault(&self) -> &VaultId {
        &self.vault
    }

    /// The admin principal that owns it.
    pub fn admin(&self) -> PrincipalId {
        self.admin
    }

    /// The secret it publishes.
    pub fn secret(&self) -> &OpaqueSecretId {
        &self.secret
    }

    /// The version it publishes.
    pub fn version(&self) -> RecordVersion {
        self.version
    }

    /// `p/<vault>/<admin>/granted/<secret>/` — the directory `apply_modes` owns.
    pub fn dir(&self, layout: &Layout) -> PathBuf {
        layout
            .store_root()
            .join("p")
            .join(self.vault.as_str())
            .join(self.admin.to_string())
            .join("granted")
            .join(self.secret.as_str())
    }

    /// `p/<vault>/<admin>/granted/<secret>/<version>` — the artifact.
    pub fn file(&self, layout: &Layout) -> PathBuf {
        self.dir(layout).join(self.version.get().to_string())
    }

    /// The canonical `p/...` form, which is what a token carries.
    pub fn canonical(&self) -> String {
        format!(
            "p/{}/{}/granted/{}/{}",
            self.vault.as_str(),
            self.admin,
            self.secret.as_str(),
            self.version.get()
        )
    }

    /// The bound metadata every entry in this publication authenticates.
    ///
    /// The level is [`Level::Granted`] and the principal is the admin: the artifact
    /// lives under her principal and she signed the grants that point at it. This
    /// exact value is the AEAD associated data of the blob, so a publication whose
    /// metadata named another level, principal, secret or version opens for nobody
    /// — misfit C, refused at publication time by the writer rather than at the
    /// agent's open (FR-034).
    pub fn metadata(&self) -> BoundMetadata {
        BoundMetadata {
            vault_id: self.vault.clone(),
            user_id: self.admin,
            level: Level::Granted,
            secret_id: self.secret.clone(),
            version: self.version.get(),
        }
    }
}

/// Apply the two publication modes, and nothing else.
///
/// The directories are created when they are absent, with the final mode set
/// explicitly rather than through `DirBuilder::mode`, which the `umask` masks. The
/// artifact must already exist: this function decides modes, not contents, so a
/// publication that has no bytes is not a publication this can widen.
///
/// A missing ancestor is an error rather than something to create: `granted/` is
/// created through the principal root, and a helper that built `p/<vault>/<admin>/`
/// itself would create a principal directory with the wrong mode.
pub fn apply_modes(path: &PublicationPath, layout: &Layout) -> Result<(), PublicationError> {
    use std::os::unix::fs::PermissionsExt;

    let file = path.file(layout);
    let (granted_dir, _) = ensure_directories(path, layout)?;

    if !file.is_file() {
        return Err(PublicationError::Absent {
            path: file.display().to_string(),
        });
    }
    std::fs::set_permissions(
        &file,
        std::fs::Permissions::from_mode(PUBLICATION_FILE_MODE),
    )
    .map_err(|cause| PublicationError::NotWritable {
        path: file.display().to_string(),
        cause: cause.to_string(),
    })?;

    // The two ancestors the widening must not have touched. Checked, not repaired:
    // a principal root with the wrong mode was made wrong by something else, and
    // fixing it here would hide that.
    let principal_root = granted_dir.parent().map(Path::to_path_buf);
    if let Some(principal_root) = principal_root {
        let mode = mode_of(&principal_root)?;
        if mode != PRINCIPAL_ROOT_MODE {
            return Err(PublicationError::PrincipalRootWidened {
                path: principal_root.display().to_string(),
                mode: format!("{mode:04o}"),
                expected: format!("{PRINCIPAL_ROOT_MODE:04o}"),
            });
        }
    }
    Ok(())
}

/// Create `granted/` and the secret's directory, and give both the publication mode.
///
/// Returned rather than merely created because the caller checks the principal root
/// above them, which is the one directory this module must not have widened.
pub fn ensure_directories(
    path: &PublicationPath,
    layout: &Layout,
) -> Result<(PathBuf, PathBuf), PublicationError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let file = path.file(layout);
    let Some(secret_dir) = file.parent().map(Path::to_path_buf) else {
        return Err(PublicationError::NotWritable {
            path: file.display().to_string(),
            cause: "the artifact has no parent directory".to_string(),
        });
    };
    let Some(granted_dir) = secret_dir.parent().map(Path::to_path_buf) else {
        return Err(PublicationError::NotWritable {
            path: secret_dir.display().to_string(),
            cause: "the secret directory has no parent".to_string(),
        });
    };

    for directory in [&granted_dir, &secret_dir] {
        if !directory.is_dir() {
            std::fs::DirBuilder::new()
                .mode(PUBLICATION_DIR_MODE)
                .create(directory)
                .map_err(|cause| PublicationError::NotWritable {
                    path: directory.display().to_string(),
                    cause: cause.to_string(),
                })?;
        }
        std::fs::set_permissions(
            directory,
            std::fs::Permissions::from_mode(PUBLICATION_DIR_MODE),
        )
        .map_err(|cause| PublicationError::NotWritable {
            path: directory.display().to_string(),
            cause: cause.to_string(),
        })?;
    }
    Ok((granted_dir, secret_dir))
}

/// The permission bits of one path.
fn mode_of(path: &Path) -> Result<u32, PublicationError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o777)
        .map_err(|cause| PublicationError::NotWritable {
            path: path.display().to_string(),
            cause: cause.to_string(),
        })
}

/// Why a publication path was refused or its modes could not be applied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublicationPathError {
    /// The text is not the derived publication path.
    #[error("the path {path} is not a publication: the accepted shape is {accepted}")]
    NotAPublication {
        /// The path that was named.
        path: String,
        /// The shape that is accepted.
        accepted: String,
    },
}

/// Why a publication could not be written or read.
#[derive(Debug, thiserror::Error)]
pub enum PublicationError {
    /// The path itself is wrong.
    #[error(transparent)]
    Path(#[from] PublicationPathError),
    /// A directory or file mode could not be applied.
    #[error("the publication at {path} could not be written: {cause}")]
    NotWritable {
        /// The path that was written.
        path: String,
        /// The operating system's own words.
        cause: String,
    },
    /// No artifact exists at the path.
    #[error("this deployment holds no publication at {path}")]
    Absent {
        /// The path that was read.
        path: String,
    },
    /// The artifact exists and could not be read.
    #[error("the publication at {path} could not be read: {cause}")]
    NotReadable {
        /// The path that was read.
        path: String,
        /// The operating system's own words.
        cause: String,
    },
    /// The admin seal does not open, so the key an entry needs is not recoverable.
    #[error(
        "the publication at {path} cannot be extended: its admin seal does not open, so the content key is not recoverable and a re-seal would break every entry already made"
    )]
    SealUnreadable {
        /// The artifact's path.
        path: String,
    },
    /// The principal root is not the mode the layout gives it.
    ///
    /// A publication is the one readable artifact under the admin's principal, so a
    /// principal root that is readable by others means the widening reached a
    /// sibling — misfit E. Refused rather than repaired, because this module did not
    /// change that mode and cannot know what else the change touched.
    #[error(
        "the principal root at {path} has mode {mode}, and the layout gives it {expected}: only the granted/ subtree widens, so this is refused rather than repaired"
    )]
    PrincipalRootWidened {
        /// The principal root.
        path: String,
        /// The mode it has.
        mode: String,
        /// The mode the layout gives it.
        expected: String,
    },

    /// The blob is not one this build wrote.
    #[error("the publication's blob is not readable: {cause}")]
    Blob {
        /// The record crate's own words.
        cause: String,
    },
    /// An envelope is not one this build wrote.
    #[error("a sealed key in the publication is not readable: {cause}")]
    Envelope {
        /// The record crate's own words.
        cause: String,
    },
    /// The artifact cannot be encoded or decoded.
    #[error("the publication could not be encoded or decoded: {cause}")]
    Encoding {
        /// The codec's own words.
        cause: String,
    },
    /// The artifact names a format version this build does not write.
    #[error("the publication names format version {version}, which this build does not know")]
    UnknownVersion {
        /// The version in the artifact.
        version: u16,
    },
    /// Two entries name one policy.
    #[error(
        "the publication holds two entries for policy {policy}: one policy references one entry, and two would let a release remove one and leave the policy still referencing the other"
    )]
    DuplicateEntry {
        /// The policy that appeared twice.
        policy: String,
    },
    /// The artifact's metadata is not the path's.
    #[error(
        "the publication at {path} authenticates metadata that is not its own: the artifact is bound to another level, principal, secret or version, so no agent can open it and it is refused before a read surface trusts it"
    )]
    BindingMismatch {
        /// The path that was read.
        path: String,
    },
}

/// The wire version of a publication artifact.
pub const PUBLICATION_VERSION: u16 = 1;

/// One policy's sealed content key, as it is stored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct EntryWire {
    policy: String,
    cooperative: bool,
    envelope: Vec<u8>,
}

/// The artifact as it is stored.
///
/// A fixed-order struct, so the bytes are a function of the contents and not of an
/// encoder's map ordering. `admin_seal` is the content key sealed to the admin's own
/// recipient key: adding an entry later needs that key, and re-sealing the blob
/// would leave every earlier entry sealing a key the blob no longer uses.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct PublicationWire {
    version: u16,
    metadata: BoundMetadata,
    blob: Vec<u8>,
    admin_seal: Vec<u8>,
    entries: Vec<EntryWire>,
}

/// One policy's entry, as a read surface sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationEntry {
    /// The policy that references this entry.
    pub policy: String,
    /// Whether the grant is cooperative (`AnyEnrolled`), which the read surface
    /// must print rather than describing the target as an enforced restriction
    /// (FR-035).
    pub cooperative: bool,
}

/// The policy ids that reference one publication, each with the entry that
/// reference seals.
///
/// One collection rather than a list of ids beside a map of keys: a reference with
/// no key would be a policy the read surface promises and the agent cannot open, and
/// the two collections could disagree after any interrupted update. The reference
/// set is therefore the key projection of this set, and cannot drift from it.
#[derive(Debug, Clone, Default)]
pub struct ReferenceSet {
    entries: Vec<(String, bool, ksp_record::envelope::RecordEnvelope)>,
}

impl ReferenceSet {
    /// A set with no references.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many policies reference the publication.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing references the publication any more.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a policy already has a reference.
    pub fn holds(&self, policy: &str) -> bool {
        self.entries
            .iter()
            .any(|(existing, _, _)| existing == policy)
    }

    /// The policies that still reference the publication, in artifact order.
    pub fn survivors(&self) -> Vec<&str> {
        self.entries
            .iter()
            .map(|(policy, _, _)| policy.as_str())
            .collect()
    }

    /// Every reference, in artifact order.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&str, bool, &ksp_record::envelope::RecordEnvelope)> {
        self.entries
            .iter()
            .map(|(policy, cooperative, envelope)| (policy.as_str(), *cooperative, envelope))
    }

    /// One policy's cooperative flag and sealed entry.
    pub fn seal_for(&self, policy: &str) -> Option<(bool, &ksp_record::envelope::RecordEnvelope)> {
        self.entries
            .iter()
            .find(|(existing, _, _)| existing == policy)
            .map(|(_, cooperative, envelope)| (*cooperative, envelope))
    }

    /// Add a reference, or report that the policy already had one.
    ///
    /// Idempotent for the same policy: a retried publish returns `false` and leaves
    /// the first entry untouched, so what the agent opens cannot move under it.
    pub fn insert(
        &mut self,
        policy: &str,
        cooperative: bool,
        envelope: ksp_record::envelope::RecordEnvelope,
    ) -> bool {
        if self.holds(policy) {
            return false;
        }
        self.entries
            .push((policy.to_string(), cooperative, envelope));
        true
    }

    /// Remove one policy's reference and its entry.
    pub fn remove(&mut self, policy: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|(existing, _, _)| existing != policy);
        self.entries.len() != before
    }
}

/// A decoded publication: one blob, one admin seal, one reference per policy.
#[derive(Debug, Clone)]
pub struct Publication {
    metadata: BoundMetadata,
    blob: ksp_record::blob::ContentBlob,
    admin_seal: ksp_record::envelope::RecordEnvelope,
    references: ReferenceSet,
}

impl Publication {
    /// A publication with no entries yet: the blob, and the content key sealed to
    /// the admin so a later policy can be added without re-sealing the blob.
    pub fn new(
        metadata: BoundMetadata,
        blob: ksp_record::blob::ContentBlob,
        admin_seal: ksp_record::envelope::RecordEnvelope,
    ) -> Self {
        Self {
            metadata,
            blob,
            admin_seal,
            references: ReferenceSet::new(),
        }
    }

    /// Recover the content key through the admin seal.
    ///
    /// This is how a second policy's entry is added: the blob is not re-sealed, so
    /// every earlier entry keeps opening exactly what it opened before. `None`
    /// means this key is not the one the publication was sealed for.
    pub fn open_with_admin(&self, recipient_x25519_sk: &[u8; 32]) -> Option<ContentKey> {
        self.admin_seal
            .open(recipient_x25519_sk, &self.metadata)
            .ok()
    }

    /// The metadata every entry authenticates.
    pub fn metadata(&self) -> &BoundMetadata {
        &self.metadata
    }

    /// Every entry, in artifact order.
    ///
    /// One traversal of the set rather than a list of ids re-looked-up: a `filter_map`
    /// over two views can drop an entry if they ever disagree, and an entry that
    /// silently disappears from a read surface is a grant an operator cannot see.
    pub fn entries(&self) -> Vec<PublicationEntry> {
        self.references
            .iter()
            .map(|(policy, cooperative, _)| PublicationEntry {
                policy: policy.to_string(),
                cooperative,
            })
            .collect()
    }

    /// The policics that reference this publication.
    pub fn references(&self) -> &ReferenceSet {
        &self.references
    }

    /// How many policies reference this publication.
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }

    /// Whether something still references this publication.
    pub fn is_empty(&self) -> bool {
        self.references.is_empty()
    }

    /// Whether a policy already has an entry.
    pub fn holds(&self, policy: &str) -> bool {
        self.references.holds(policy)
    }

    /// Add a policy's entry, or report that it already had one.
    ///
    /// Idempotent for the same policy: a second publish of one grant returns
    /// `false` and leaves the artifact's first entry untouched, so a retried
    /// publish cannot change what the agent opens.
    pub fn add_entry(
        &mut self,
        policy: &str,
        cooperative: bool,
        envelope: ksp_record::envelope::RecordEnvelope,
    ) -> bool {
        self.references.insert(policy, cooperative, envelope)
    }

    /// Remove one policy's entry and its reference.
    ///
    /// Returns whether it was there. The last release leaves a publication with no
    /// entries, and the caller decides whether to remove the artifact — this type
    /// does not delete anything, because the decision belongs to the lifecycle
    /// transaction (WP04).
    pub fn release(&mut self, policy: &str) -> bool {
        self.references.remove(policy)
    }

    /// Refuse an artifact whose metadata is not the one its path names.
    ///
    /// The AAD is the metadata, so a publication bound to another level, principal,
    /// secret or version opens for nobody (misfit C). It is refused at read time as
    /// well as at publication time, because an artifact can arrive from a backup.
    pub fn verify_binding(&self, path: &PublicationPath) -> Result<(), PublicationError> {
        if self.metadata != path.metadata() {
            return Err(PublicationError::BindingMismatch {
                path: path.canonical(),
            });
        }
        Ok(())
    }

    /// Encode the artifact.
    pub fn encode(&self) -> Result<Vec<u8>, PublicationError> {
        let wire = PublicationWire {
            version: PUBLICATION_VERSION,
            metadata: self.metadata.clone(),
            blob: self.blob.to_bytes(),
            admin_seal: self.admin_seal.to_bytes(),
            entries: self
                .references
                .iter()
                .map(|(policy, cooperative, envelope)| EntryWire {
                    policy: policy.to_string(),
                    cooperative,
                    envelope: envelope.to_bytes(),
                })
                .collect(),
        };
        ksp_types::cbor::encode(&wire).map_err(|cause| PublicationError::Encoding {
            cause: cause.to_string(),
        })
    }

    /// Decode an artifact, refusing a version this build does not know and a
    /// duplicate policy entry.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublicationError> {
        let wire: PublicationWire =
            ksp_types::cbor::decode(bytes).map_err(|cause| PublicationError::Encoding {
                cause: cause.to_string(),
            })?;
        if wire.version != PUBLICATION_VERSION {
            return Err(PublicationError::UnknownVersion {
                version: wire.version,
            });
        }
        let blob = ksp_record::blob::ContentBlob::from_bytes(&wire.blob).map_err(|error| {
            PublicationError::Blob {
                cause: error.to_string(),
            }
        })?;
        let admin_seal = ksp_record::envelope::RecordEnvelope::from_bytes(&wire.admin_seal)
            .map_err(|error| PublicationError::Envelope {
                cause: error.to_string(),
            })?;
        let mut references = ReferenceSet::new();
        for entry in wire.entries {
            let envelope = ksp_record::envelope::RecordEnvelope::from_bytes(&entry.envelope)
                .map_err(|error| PublicationError::Envelope {
                    cause: error.to_string(),
                })?;
            // One entry per policy: two entries for one id would leave a release able
            // to remove one and leave the policy still referencing the other.
            if !references.insert(&entry.policy, entry.cooperative, envelope) {
                return Err(PublicationError::DuplicateEntry {
                    policy: entry.policy,
                });
            }
        }
        Ok(Self {
            metadata: wire.metadata,
            blob,
            admin_seal,
            references,
        })
    }
}

impl Publication {
    /// A publication with no entries: the blob, sealed under the publication's own
    /// metadata, and the content key sealed to the admin.
    ///
    /// The content key is returned because the publisher needs it to seal the first
    /// policy's entry before it lets go of it; the artifact keeps only the admin's
    /// copy. A caller that drops the key without sealing an entry has written a
    /// publication nobody can open, which is why this is one call rather than three.
    pub fn fresh(
        metadata: BoundMetadata,
        name: &[u8],
        value: &[u8],
        admin_recipient: &[u8; 32],
    ) -> Result<(Self, ContentKey), PublicationError> {
        let aad = metadata
            .bound_aad()
            .map_err(|cause| PublicationError::Blob {
                cause: cause.to_string(),
            })?;
        let content_key = ContentKey::generate();
        let blob = ksp_record::blob::ContentBlob::seal(&content_key, name, value, &aad).map_err(
            |cause| PublicationError::Blob {
                cause: cause.to_string(),
            },
        )?;
        let admin_seal =
            ksp_record::envelope::RecordEnvelope::seal(&content_key, admin_recipient, &metadata)
                .map_err(|cause| PublicationError::Envelope {
                    cause: cause.to_string(),
                })?;
        Ok((Publication::new(metadata, blob, admin_seal), content_key))
    }

    /// Seal one policy's entry onto this publication.
    ///
    /// The blob is not touched: every earlier entry keeps opening exactly what it
    /// opened before, which is the whole point of one artifact per secret version
    /// (misfit B).
    pub fn seal_entry(
        &mut self,
        policy: &str,
        cooperative: bool,
        content_key: &ContentKey,
        target: &[u8; 32],
    ) -> Result<bool, PublicationError> {
        if self.holds(policy) {
            return Ok(false);
        }
        let envelope =
            ksp_record::envelope::RecordEnvelope::seal(content_key, target, &self.metadata)
                .map_err(|cause| PublicationError::Envelope {
                    cause: cause.to_string(),
                })?;
        Ok(self.add_entry(policy, cooperative, envelope))
    }

    /// Open the blob with a policy's own key.
    ///
    /// `None` covers every refusal a reader can tell apart only by asking: no entry
    /// for this policy, an entry sealed to another key, or a blob whose metadata is
    /// not the one the entry was sealed under.
    pub fn open_for(
        &self,
        policy: &str,
        recipient_x25519_sk: &[u8; 32],
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        let (_, envelope) = self.references.seal_for(policy)?;
        let content_key = envelope.open(recipient_x25519_sk, &self.metadata).ok()?;
        let aad = self.metadata.bound_aad().ok()?;
        self.blob.open(&content_key, &aad).ok()
    }
}

/// Read one publication from its path.
pub fn load(layout: &Layout, path: &PublicationPath) -> Result<Publication, PublicationError> {
    let file = path.file(layout);
    let bytes = std::fs::read(&file).map_err(|cause| PublicationError::NotReadable {
        path: file.display().to_string(),
        cause: cause.to_string(),
    })?;
    let publication = Publication::decode(&bytes)?;
    // An artifact bound to another level, principal, secret or version opens for
    // nobody, and it can arrive from a backup as easily as from here.
    publication.verify_binding(path)?;
    Ok(publication)
}

/// Write a publication at its path, atomically, with the publication modes.
///
/// Written beside the artifact and renamed over it: `load` refuses an artifact it
/// cannot decode, so one half-written body would fail every policy that references
/// it (CF-015).
pub fn write(
    layout: &Layout,
    path: &PublicationPath,
    publication: &Publication,
) -> Result<(), PublicationError> {
    let bytes = publication.encode()?;
    ensure_directories(path, layout)?;
    let file = path.file(layout);
    let mut temporary = file.clone();
    temporary.set_file_name(format!(".{}.tmp", path.version().get()));

    let written = (|| {
        let mut handle = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(PUBLICATION_FILE_MODE)
            .open(&temporary)?;
        handle.write_all(&bytes)?;
        handle.sync_all()?;
        std::fs::rename(&temporary, &file)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
        return Err(PublicationError::NotWritable {
            path: file.display().to_string(),
            cause: "the artifact could not be written".to_string(),
        });
    }
    apply_modes(path, layout).map_err(|error| {
        PublicationError::Path(PublicationPathError::NotAPublication {
            path: file.display().to_string(),
            accepted: error.to_string(),
        })
    })
}

/// What one publish names: the policy, and the two keys that must not be swapped.
///
/// A bundle rather than positional arguments, because `target` and
/// `admin_recipient` are both 32 bytes: two adjacent arrays swapped at a call site
/// compile, and the artifact would then seal the entry to the admin and the admin's
/// copy to the agent — a publication the agent cannot open and the admin can.
pub struct PublishRequest<'a> {
    /// The policy that references this entry.
    pub policy: &'a str,
    /// Whether the grant is cooperative (`AnyEnrolled`).
    pub cooperative: bool,
    /// The X25519 key the policy's target holds.
    pub target: [u8; 32],
    /// The X25519 key the admin's own vault holds.
    pub admin_recipient: [u8; 32],
}

/// Publish one policy's entry, creating the artifact when it is the first.
///
/// `source` supplies the plaintext only when the artifact does not exist yet, and
/// `open_admin` supplies the content key only when it does: a fresh publication
/// generates its own, and an existing one must recover the key from its admin seal
/// because re-sealing the blob would break every entry already made.
pub fn publish(
    layout: &Layout,
    path: &PublicationPath,
    request: PublishRequest<'_>,
    source: impl FnOnce() -> Result<(Vec<u8>, Vec<u8>), PublicationError>,
    open_admin: impl FnOnce(&Publication) -> Option<ContentKey>,
) -> Result<Publication, PublicationError> {
    let PublishRequest {
        policy,
        cooperative,
        target,
        admin_recipient,
    } = request;
    if path.file(layout).is_file() {
        let mut publication = load(layout, path)?;
        if publication.holds(policy) {
            // Idempotent: a retried publish changes nothing, so what the agent
            // opens cannot move under it.
            return Ok(publication);
        }
        let content_key =
            open_admin(&publication).ok_or_else(|| PublicationError::SealUnreadable {
                path: path.canonical(),
            })?;
        publication.seal_entry(policy, cooperative, &content_key, &target)?;
        write(layout, path, &publication)?;
        return Ok(publication);
    }

    let (name, value) = source()?;
    let (mut publication, content_key) =
        Publication::fresh(path.metadata(), &name, &value, &admin_recipient)?;
    publication.seal_entry(policy, cooperative, &content_key, &target)?;
    write(layout, path, &publication)?;
    Ok(publication)
}

/// Remove one policy's entry, leaving the artifact and every other entry.
///
/// Returns the policies that still reference the publication, so a caller can
/// report them rather than a bare count: "one reference left" does not say which
/// grant still holds the secret. Removing the artifact when the last reference goes
/// is the lifecycle transaction's decision, not this function's (WP04): a
/// publication that disappears before its ledger entry is written is a change
/// nobody can account for.
pub fn release(
    layout: &Layout,
    path: &PublicationPath,
    policy: &str,
) -> Result<Vec<String>, PublicationError> {
    let mut publication = load(layout, path)?;
    if publication.release(policy) {
        write(layout, path, &publication)?;
    }
    // A release that removed nothing writes nothing: a retried release is a no-op, not
    // a second durability event, and rewriting identical bytes would move the mtime a
    // reader may be using to tell when the artifact last changed.
    Ok(publication
        .references()
        .survivors()
        .into_iter()
        .map(str::to_string)
        .collect())
}
