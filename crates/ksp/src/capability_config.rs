//! Reading `config.toml`: the mode guard, the parser and the refusals.
//!
//! # The file is the downgrade path
//!
//! A capability configuration says which mechanisms a deployment is allowed to
//! establish and whether it refuses without them. That makes the **file** the
//! thing worth attacking: a principal who can rewrite it can demote a required
//! capability to an optional one, or replace `landlock` with the adapter that
//! establishes nothing, and every command keeps working afterwards (Misfit D).
//!
//! So the file is guarded before its content is trusted. The guard reads the
//! mode and owner from the **open file descriptor**, not from the path, because
//! the path can be repointed between the check and the read.
//!
//! # Three mistakes, three refusals
//!
//! A malformed document and an adapter name this build does not contain have
//! different fixes, and one sentence covering both would send the operator to
//! the wrong one. The same is true of a file that cannot be read at all.
//!
//! The reader **reports**; it does not resolve. The resolver (WP04) runs on the
//! validated [`CapabilityConfiguration`], so a host that cannot confine can
//! still say why (NFR-005).
//!
//! This module holds no secret and no vault state: the validated type carries
//! capability names and requirement levels only, and the file format is closed,
//! so there is no field a passphrase could be written into (FR-016).

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use ksp_posture::permissions::effective_uid;
use ksp_posture::{PERMISSION_BITS, capability_of};
use ksp_types::capability_config::{
    AdapterName, CapabilityConfiguration, CapabilitySetting, HostCapability, RequirementLevel,
};
use serde::{Deserialize, Serialize};

use crate::config::Layout;

/// The file name, relative to the home.
pub const FILE_NAME: &str = "config.toml";

/// The mode bits that let a principal other than the owner write the file.
///
/// The file holds no secret (FR-016), so permission to **read** it is not the
/// hazard — permission to **change** what the deployment is allowed to
/// establish is. FR-009 refuses exactly this.
const WRITE_BY_OTHERS: u32 = 0o022;

/// Whether a file with `mode` is safe for any principal to trust.
///
/// One condition: no principal other than the owner can write it, so the content
/// cannot change underneath the read. FR-009 refuses exactly that, and SC-007 is
/// the same statement.
///
/// **Reading is deliberately unrestricted.** The file holds no secret (FR-016),
/// and a deployment has more than one principal that has to read it: the admin
/// writes the configuration that decides whether an agent's delivery is confined,
/// and the agent's own process is the one that reads it to confine her child. An
/// earlier version of this guard also required the reader to be the owner. That is
/// unreachable in the two-account deployment the layout is built for, because the
/// home belongs to the admin (`0711`) and no other account can put a file in it —
/// `principals.rs` provisions it and the principal's `secret set` then refused.
/// Being another principal's file is not a hazard here: the deployment's owner *is*
/// the trust anchor, and the directory that decides whether the file can be
/// replaced is the home, whose mode only the admin can write.
pub fn is_private(mode: u32) -> bool {
    (mode & WRITE_BY_OTHERS) == 0
}

/// The on-disk shape of `config.toml`.
///
/// It is deliberately **not** [`CapabilityConfiguration`]. The on-disk shape is
/// this subsystem's definition and may change with the file format; the
/// validated type is the contract the resolver reads and must stay stable. The
/// split is also what lets an unknown adapter name be reported with the key it
/// appeared under: the stored shape keeps the raw strings, and validation is the
/// step that turns them into the closed type.
///
/// The schema is closed. `deny_unknown_fields` is what makes "the configuration
/// holds capability names and requirement levels only" structural rather than a
/// convention (FR-016, FR-003).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredConfiguration {
    /// The path confinement table.
    pub confinement: StoredSetting,
    /// The memory barrier table.
    pub memory_barrier: StoredSetting,
}

/// One capability's table as the file spells it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSetting {
    /// The adapters to try, in the operator's order of preference.
    ///
    /// Held as written rather than as a parsed [`AdapterName`] so that a name
    /// outside the closed set can be reported with its table and index. A
    /// derived `Deserialize` into `AdapterName` would refuse the document with
    /// the offending value and no key, which is the message T031 exists to
    /// avoid.
    pub adapters: Vec<String>,
    /// Whether the run refuses when the capability cannot be established.
    pub requirement: RequirementLevel,
}

impl From<&CapabilityConfiguration> for StoredConfiguration {
    fn from(configuration: &CapabilityConfiguration) -> Self {
        Self {
            confinement: StoredSetting::from(&configuration.confinement),
            memory_barrier: StoredSetting::from(&configuration.memory_barrier),
        }
    }
}

impl From<&CapabilitySetting> for StoredSetting {
    fn from(setting: &CapabilitySetting) -> Self {
        Self {
            adapters: setting
                .adapters
                .iter()
                .map(|adapter| adapter.as_str().to_string())
                .collect(),
            requirement: setting.requirement,
        }
    }
}

impl StoredConfiguration {
    /// Validates every key and value, producing the contract the resolver reads.
    ///
    /// `path` is only used to name the file in a refusal. It is a parameter
    /// rather than part of the value because the host probe builds this document
    /// in memory and validates it **before** writing, so the probe cannot write
    /// a file the reader would reject.
    ///
    /// # Errors
    ///
    /// [`ConfigurationRefusal::UnknownAdapter`] when a name is outside the
    /// closed set, and [`ConfigurationRefusal::WrongCapability`] when it is in
    /// the set but belongs to the other capability.
    pub fn validated(&self, path: &Path) -> Result<CapabilityConfiguration, ConfigurationRefusal> {
        Ok(CapabilityConfiguration {
            confinement: validate_setting(
                &self.confinement,
                HostCapability::PathConfinement,
                path,
            )?,
            memory_barrier: validate_setting(
                &self.memory_barrier,
                HostCapability::MemoryBarrier,
                path,
            )?,
        })
    }
}

/// Validates one capability's table against the closed set and its registry.
fn validate_setting(
    setting: &StoredSetting,
    capability: HostCapability,
    path: &Path,
) -> Result<CapabilitySetting, ConfigurationRefusal> {
    let mut adapters = Vec::with_capacity(setting.adapters.len());
    for (index, value) in setting.adapters.iter().enumerate() {
        let key = format!("{}.adapters[{index}]", capability.config_key());
        let name = AdapterName::parse(value).map_err(|_| ConfigurationRefusal::UnknownAdapter {
            path: path.to_path_buf(),
            key: key.clone(),
            value: value.clone(),
        })?;
        // A name in the closed set that establishes the *other* capability is a
        // value error, not a host fact. Accepting it would make the reader
        // answer "the host cannot establish this" for a document the operator
        // could fix in one word — a false statement about the host.
        let establishes = capability_of(name.kind());
        if establishes != capability {
            return Err(ConfigurationRefusal::WrongCapability {
                path: path.to_path_buf(),
                key,
                value: value.clone(),
                capability,
            });
        }
        adapters.push(name);
    }

    Ok(CapabilitySetting {
        adapters,
        requirement: setting.requirement,
    })
}

/// Reads and validates the capability configuration.
///
/// Returns `Ok(None)` when the file is **absent**: that is the unconfigured
/// state rather than a failure (FR-004). It is `None` and not an empty document
/// because an empty document is one the operator wrote, and a caller that had to
/// distinguish the two from a value full of empty lists would eventually treat
/// one of them as the other.
///
/// # Order
///
/// The file is opened without blocking, measured through its own descriptor,
/// guarded, and only then read. Reading content before deciding whether to
/// trust its mode would mean the content had already been parsed from a file
/// another principal can rewrite (Misfit D, criterion 6).
///
/// The non-blocking open comes first because the alternative ordering cannot
/// work: `open(2)` on a FIFO waits for a writer, so a check placed after a
/// blocking open is a check that never runs. A hung command reports nothing and
/// an operator learns nothing from it.
///
/// # Errors
///
/// One of the five [`ConfigurationRefusal`] variants, each naming the file and
/// what to fix.
pub fn read(layout: &Layout) -> Result<Option<CapabilityConfiguration>, ConfigurationRefusal> {
    let path = layout.capability_config_file();

    // `O_NONBLOCK` is not a tuning detail: `open(2)` on a FIFO with no writer
    // **blocks** until one appears, so a plain open would hang the command
    // before any check could run. The flag has no effect on a regular file,
    // which is why it is safe to pass unconditionally.
    //
    // An absent file is the unconfigured state. Opening reads no content, so
    // this does not trust anything.
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(ConfigurationRefusal::Unreadable {
                path,
                reason: err.to_string(),
            });
        }
    };

    // Measure the descriptor, not the path: the path can be repointed between a
    // check and a later open, and the descriptor is the object that will be
    // read. This also means a symlink is resolved before it is measured, which
    // is right here — the guard is about the bytes the reader will trust.
    let metadata = file
        .metadata()
        .map_err(|err| ConfigurationRefusal::Unreadable {
            path: path.clone(),
            reason: err.to_string(),
        })?;

    if !metadata.is_file() {
        // A directory opens without complaint and fails only when read, and a
        // FIFO or a device is not a document at all. None of them is something
        // the operator wrote down, so none is a configuration.
        return Err(ConfigurationRefusal::Unreadable {
            path,
            reason: "it is not a regular file".to_string(),
        });
    }

    let mode = metadata.mode() & PERMISSION_BITS;
    let owner = metadata.uid();
    let reader = effective_uid();
    if !is_private(mode) {
        return Err(ConfigurationRefusal::NotPrivate {
            path,
            mode,
            owner,
            reader,
        });
    }

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|err| ConfigurationRefusal::Unreadable {
            path: path.clone(),
            reason: err.to_string(),
        })?;

    let text = String::from_utf8(bytes).map_err(|err| ConfigurationRefusal::Malformed {
        path: path.clone(),
        reason: format!(
            "the file is not valid UTF-8 at byte {}",
            err.utf8_error().valid_up_to()
        ),
    })?;

    let stored: StoredConfiguration =
        toml::from_str(&text).map_err(|err| ConfigurationRefusal::Malformed {
            path: path.clone(),
            reason: parser_reason(&err, &text),
        })?;

    stored.validated(&path).map(Some)
}

/// The parser's reason and position, with the document itself removed.
///
/// `toml::de::Error`'s `Display` is not used: for a syntax error it renders the
/// offending **source line**, and its own message quotes the offending token. An
/// operator who pastes a passphrase into `config.toml` by mistake therefore gets
/// that passphrase printed back, and a refusal is written to stderr on its way
/// to a log (FR-016).
///
/// So the refusal keeps the two things an operator can act on — the line and
/// column, and the parser's own reason — and never quotes the document. The
/// offending token is replaced wherever the parser echoed it, and the position
/// tells the operator where to look.
fn parser_reason(err: &toml::de::Error, text: &str) -> String {
    let message = err.message().to_string();
    let Some(span) = err.span() else {
        // Without a span there is no position to give, and no token identified
        // to redact. The message is still the parser's reason.
        return message;
    };

    let (line, column) = line_and_column(text, span.start);
    let offending = text.get(span.clone()).unwrap_or_default().trim();
    // The parser quotes the token with its delimiters in some messages and
    // without them in others, so both spellings are removed.
    let bare = offending.trim_matches('"').trim_matches('\'').trim();

    let mut redacted = message;
    for token in [offending, bare] {
        if !token.is_empty() {
            redacted = redacted.replace(token, "\u{2026}");
        }
    }
    format!("{redacted} (line {line}, column {column})")
}

/// The 1-based line and column of a byte offset, as a parser would report them.
fn line_and_column(text: &str, offset: usize) -> (usize, usize) {
    let upto = text.get(..offset).unwrap_or(text);
    let line = upto.matches('\n').count() + 1;
    let column = upto
        .rsplit('\n')
        .next()
        .map_or(1, |tail| tail.chars().count() + 1);
    (line, column)
}

/// Why the capability configuration could not be read or validated.
///
/// Each variant names the file and the thing to fix. One generic message would
/// serve none of them, because the fixes differ: change the mode, change the
/// name, fix the syntax, or make the path a file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigurationRefusal {
    /// The file exists but could not be read.
    #[error("the capability configuration {path} could not be read: {reason}")]
    Unreadable {
        /// The file that was read.
        path: PathBuf,
        /// The host's reason.
        reason: String,
    },
    /// Another principal can write the file, so its content cannot be trusted.
    ///
    /// FR-009 refuses with the mode it found: the mode *is* the finding, and an
    /// operator told only "not private" has to guess which write bit is set.
    #[error(
        "the capability configuration {path} is not private: mode {mode:04o}, owner {owner}, \
         reader {reader}; it must be writable by its owner only, because a file another \
         principal can write decides what this host may establish"
    )]
    NotPrivate {
        /// The file that failed the guard.
        path: PathBuf,
        /// The mode found, masked to the permission bits.
        mode: u32,
        /// The owner found.
        owner: u32,
        /// The effective uid that would have read it.
        reader: u32,
    },
    /// The document is not the shape the schema describes.
    #[error("the capability configuration {path} is not a valid document: {reason}")]
    Malformed {
        /// The file that was parsed.
        path: PathBuf,
        /// The parser's own reason, including its line and column.
        reason: String,
    },
    /// The document names an adapter this build does not contain.
    ///
    /// FR-010 asks for the adapters the build could have offered, so the
    /// rendered refusal names them: the operator's fix is to pick one of them.
    #[error(
        "the capability configuration {path} names an adapter this build does not contain: \
         {key} = \"{value}\"; this build contains {}",
        AdapterName::ALL.join(", ")
    )]
    UnknownAdapter {
        /// The file that named it.
        path: PathBuf,
        /// The key it appeared under, for example `confinement.adapters[1]`.
        key: String,
        /// The value that was named.
        value: String,
    },
    /// The document names an adapter that cannot establish this capability.
    ///
    /// The name is in the closed set, so it is not an unknown adapter; it simply
    /// belongs to another capability. Reporting it as a host limitation would be
    /// a false claim about the host, which is what Misfit L is about.
    ///
    /// The message states what the name *cannot* do rather than which capability
    /// it belongs to: with a third capability the phrase "the other capability"
    /// would become a lie, and the operator's fix is the same either way — use
    /// one of the names this capability accepts.
    #[error(
        "the capability configuration {path} names {key} = \"{value}\", which cannot establish \
         {}; {} accepts {}",
        capability.label(),
        capability.label(),
        capability_adapters(*capability)
    )]
    WrongCapability {
        /// The file that named it.
        path: PathBuf,
        /// The key it appeared under.
        key: String,
        /// The value that was named.
        value: String,
        /// The capability whose table it appeared under.
        capability: HostCapability,
    },
}

impl ConfigurationRefusal {
    /// The file the refusal is about.
    pub fn path(&self) -> &Path {
        match self {
            Self::Unreadable { path, .. }
            | Self::NotPrivate { path, .. }
            | Self::Malformed { path, .. }
            | Self::UnknownAdapter { path, .. }
            | Self::WrongCapability { path, .. } => path,
        }
    }

    /// Whether this refusal is about the host rather than about the document.
    ///
    /// The mode refusal is the boundary itself (FR-009), so it exits as a
    /// capability refusal; the rest are mistakes in the configuration, which is
    /// a policy denial. A caller that could not tell them apart would report a
    /// widened file as a typo.
    pub fn is_boundary_refusal(&self) -> bool {
        matches!(self, Self::NotPrivate { .. })
    }
}

/// The adapters of one capability, comma-separated.
///
/// Used by the [`ConfigurationRefusal::WrongCapability`] message. It filters the
/// closed set through the same [`capability_of`] the registries use, so the
/// guidance cannot name an adapter the capability does not accept.
fn capability_adapters(capability: HostCapability) -> String {
    AdapterName::ALL
        .into_iter()
        .filter(|name| {
            AdapterName::parse(name).is_ok_and(|parsed| capability_of(parsed.kind()) == capability)
        })
        .collect::<Vec<_>>()
        .join(", ")
}
