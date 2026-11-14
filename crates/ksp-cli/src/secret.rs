//! The `ksp secret` group: store a value at the user's level, read it back.
//!
//! # Two secrets on one stdin
//!
//! `set` reads the *value* from stdin, because a value in argv is in the process
//! table and in shell history (FR-044). The vault password therefore cannot also
//! come from stdin, and it must not come from argv or the environment either. It
//! is read from a file descriptor the caller names (`--passphrase-fd`) or from
//! the terminal, which is a channel that holds no value of its own.
//!
//! # What is sealed to whom
//!
//! A `user`-level record is sealed to the *user's* recipient key, so only her
//! vault opens it. The admin holds a signing key and no recipient key at all,
//! which is why a full copy of storage plus the admin key still yields nothing
//! (SC-001).

use std::io::Read;

use ksp_identity::{UserVault, VaultBinding};
use ksp_record::RecordPath;
use ksp_record::{ContentBlob, Record, RecordEnvelope, commit_version};
use ksp_types::{BoundMetadata, Level, OpaqueSecretId};

use crate::config::{self, Layout};
use crate::deployment::{self, Deployment};
use crate::exit::{self, Outcome};
use crate::output::{Emitter, RecordMetadata, Report};

/// Why a secret operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretError {
    /// The deployment is not initialised.
    #[error("this host has no deployment")]
    NotInitialised,
    /// The vault could not be opened, for the reason `ksp vault` would give.
    ///
    /// The reason travels: "the vault could not be opened" told an operator
    /// nothing about a file owned by another account, and FR-024's whole point is
    /// that the refusal names what is wrong.
    #[error("{0}")]
    Vault(crate::vault::VaultError),
    /// The value could not be read from stdin.
    ///
    /// The message names the accepted form, because the common cause is a
    /// pipeline that fed the password and the value to one stream: the password
    /// reader consumes all of it, so the value arrives empty. `--passphrase-file`
    /// is the way to supply the password separately, and a refusal that did not
    /// say so left the caller retrying the same broken pipeline.
    #[error(
        "the value could not be read from the input: the value comes from stdin, \
         and the password comes from --passphrase-file when stdin carries a value"
    )]
    Value,
    /// The record could not be read back.
    #[error("the stored record is not readable")]
    Record,
    /// The record could not be written.
    #[error("the record could not be written")]
    Write,
}

impl SecretError {
    /// The exit code this failure maps to.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::NotInitialised | Self::Record => exit::MISSING_KEY,
            Self::Vault(error) => error.exit_code(),
            // An empty value is the caller's pipeline, not a bug in this tool.
            // A write that failed is not: the caller did nothing wrong and the
            // record may still be absent, so it keeps `INTERNAL`.
            Self::Value => exit::USAGE,
            Self::Write => exit::INTERNAL,
        }
    }
}

/// The user's unsealed vault, with the binding it was sealed under.
pub struct Unsealed {
    /// The vault itself: both keypairs and the UVK.
    pub vault: UserVault,
    /// The vault's level, which every `user`-level record names.
    pub user: ksp_types::PrincipalId,
    /// The vault the records live in.
    pub vault_id: ksp_types::VaultId,
}

/// Open the user's vault with `password`.
///
/// The unsealing itself is [`crate::vault::unseal`], which establishes the
/// memory barrier through the adapter the configuration selected. It used to
/// call `SealedVault::unseal` here instead, and that second path allocated no
/// region at all: the password and the UVK it produces were held in ordinary
/// memory on every `ksp secret` command. One unseal path is what stops that
/// from being reintroduced (FR-011, T041).
pub fn unseal(layout: &Layout, password: &[u8]) -> Result<Unsealed, SecretError> {
    let (recorded, _anchor) =
        deployment::require(layout).map_err(|_| SecretError::NotInitialised)?;
    let home = crate::vault::VaultHome::new(layout.root().to_path_buf());
    let binding = VaultBinding {
        identity: ksp_types::ActorId::User(recorded.user),
        signing_key_id: recorded
            .user_signing_key_id
            .clone()
            .ok_or(SecretError::NotInitialised)?,
        recipient_key_id: recorded
            .user_recipient_key_id
            .clone()
            .ok_or(SecretError::NotInitialised)?,
    };
    let vault = crate::vault::unseal(&home, &binding, password).map_err(SecretError::Vault)?;
    Ok(Unsealed {
        vault,
        user: recorded.user,
        vault_id: recorded.vault,
    })
}

/// The metadata a record at `level` and `version` carries.
///
/// The level is the record's **provenance**: `admin` means the admin wrote and
/// delegated the value, `user` means the user owns it. A delivery reads that
/// level to decide whether a policy is required, so the two writers must not
/// both write `user`.
pub fn metadata_at(
    deployment: &Deployment,
    level: Level,
    secret: &OpaqueSecretId,
    version: u32,
) -> BoundMetadata {
    BoundMetadata {
        vault_id: deployment.vault.clone(),
        user_id: deployment.user,
        level,
        secret_id: secret.clone(),
        version,
    }
}

/// The metadata a `user`-level record at `version` carries.
pub fn user_metadata(
    deployment: &Deployment,
    secret: &OpaqueSecretId,
    version: u32,
) -> BoundMetadata {
    metadata_at(deployment, Level::User, secret, version)
}

/// Store `value` as a new version of `secret` at the user's level.
///
/// The version advances past whatever is already there: a `user`-level chain is
/// append-only, and reusing a version number would overwrite the bytes an older
/// delivery names.
pub fn set(
    layout: &Layout,
    password: &[u8],
    secret: &OpaqueSecretId,
    name: &[u8],
    value: &[u8],
) -> Result<u32, SecretError> {
    let unsealed = unseal(layout, password)?;
    set_with(layout, &unsealed, secret, name, value)
}

/// Store a new version with a vault that is already open.
///
/// Split from [`set`] so a caller that holds the unsealed vault can append its
/// audit record with the tenant's own key without unsealing a second time: a
/// second KDF run is a second chance to ask for a password, and NFR-008 says
/// appending asks for none.
pub fn set_with(
    layout: &Layout,
    unsealed: &Unsealed,
    secret: &OpaqueSecretId,
    name: &[u8],
    value: &[u8],
) -> Result<u32, SecretError> {
    let recorded = deployment::require(layout)
        .map_err(|_| SecretError::NotInitialised)?
        .0;
    // The level is created by the table, not by the store's `create_dir_all`:
    // a level that took the caller's umask would be another principal's write
    // access to these records (misfit B).
    crate::layout::ensure_level(layout.root(), &recorded.vault, recorded.user, &Level::User)
        .map_err(|_| SecretError::Write)?;
    let store = config::open_file_store(layout).map_err(|_| SecretError::Write)?;
    seal_user_record(
        &store,
        &recorded,
        secret,
        name,
        value,
        unsealed.vault.recipient_public().to_bytes(),
    )
}

/// Seal one version of a `user`-level record to a recipient public key.
///
/// The recipient is a parameter because there are two callers that legitimately
/// hold it differently: `secret set` unseals the vault and uses its key, and
/// `admin put` uses the public half the deployment recorded. Both must produce
/// the same record, so the sealing lives here once — a second copy would be a
/// second answer to which AAD a stored record authenticates.
pub fn seal_user_record(
    store: &dyn ksp_record::version::BlobStore,
    recorded: &Deployment,
    secret: &OpaqueSecretId,
    name: &[u8],
    value: &[u8],
    recipient: [u8; 32],
) -> Result<u32, SecretError> {
    seal_record_at(store, recorded, Level::User, secret, name, value, recipient)
}

/// Store `value` as a new version of `secret` at `level`.
///
/// The level decides the path and the provenance. `admin` is what `admin put`
/// writes; `user` is what `secret set` writes. Everything else about the record
/// is identical, so the two share one implementation and cannot drift.
pub fn seal_record_at(
    store: &dyn ksp_record::version::BlobStore,
    recorded: &Deployment,
    level: Level,
    secret: &OpaqueSecretId,
    name: &[u8],
    value: &[u8],
    recipient: [u8; 32],
) -> Result<u32, SecretError> {
    let version = next_version_at(
        store,
        &recorded.vault,
        &recorded.user,
        level.clone(),
        secret,
    )?;
    let metadata = metadata_at(recorded, level, secret, version);
    let aad = metadata.bound_aad().map_err(|_| SecretError::Record)?;

    let content_key = ksp_types::ContentKey::generate();
    let blob =
        ContentBlob::seal(&content_key, name, value, &aad).map_err(|_| SecretError::Write)?;

    // Sealed to the user's own recipient key. The envelope's AAD is the same
    // bound metadata the blob authenticates, so the two cannot describe
    // different records.
    let envelope = RecordEnvelope::seal(&content_key, &recipient, &metadata)
        .map_err(|_| SecretError::Write)?;

    let record = Record {
        metadata: metadata.clone(),
        blob,
        envelope,
    };
    commit_version(store, &metadata, &record).map_err(|_| SecretError::Write)?;
    Ok(version)
}

/// The level `secret` is stored at, and its latest version there.
///
/// The level is the record's provenance, and a mint has to know it: an
/// `admin`-level value is a delegation and needs a policy, a `user`-level value
/// is the user's own and does not. Both levels are checked because the same
/// secret identifier may exist at either, and the highest version wins so a
/// later `admin put` supersedes an earlier `secret set`.
pub fn source_level(
    store: &dyn ksp_record::version::BlobStore,
    vault_id: &ksp_types::VaultId,
    user: &ksp_types::PrincipalId,
    secret: &OpaqueSecretId,
) -> Result<Option<(Level, u32)>, SecretError> {
    let mut best: Option<(Level, u32)> = None;
    for level in [Level::Admin, Level::User] {
        let mut version = 1;
        loop {
            let metadata = BoundMetadata {
                vault_id: vault_id.clone(),
                user_id: *user,
                level: level.clone(),
                secret_id: secret.clone(),
                version,
            };
            match store.get(ksp_record::RecordPath::of(&metadata).as_str()) {
                Ok(None) => break,
                Ok(Some(_)) => {
                    let supersedes = best.as_ref().is_none_or(|(_, highest)| version > *highest);
                    if supersedes {
                        best = Some((level.clone(), version));
                    }
                    version += 1;
                }
                Err(_) => return Err(SecretError::Write),
            }
        }
    }
    Ok(best)
}

/// The next free version for `secret` at the user's level.
pub fn next_version(
    store: &dyn ksp_record::version::BlobStore,
    vault_id: &ksp_types::VaultId,
    user: &ksp_types::PrincipalId,
    secret: &OpaqueSecretId,
) -> Result<u32, SecretError> {
    next_version_at(store, vault_id, user, Level::User, secret)
}

/// The next free version for `secret` at `level`.
pub fn next_version_at(
    store: &dyn ksp_record::version::BlobStore,
    vault_id: &ksp_types::VaultId,
    user: &ksp_types::PrincipalId,
    level: Level,
    secret: &OpaqueSecretId,
) -> Result<u32, SecretError> {
    let mut version = 1;
    loop {
        let metadata = BoundMetadata {
            vault_id: vault_id.clone(),
            user_id: *user,
            level: level.clone(),
            secret_id: secret.clone(),
            version,
        };
        match store.get(ksp_record::RecordPath::of(&metadata).as_str()) {
            Ok(None) => return Ok(version),
            Ok(Some(_)) => version += 1,
            Err(_) => return Err(SecretError::Write),
        }
    }
}

/// Read one stored version back: its name and its value.
///
/// The record is opened with the user's borrowed recipient bytes, and the blob
/// with the content key that yields. Neither half is copied out of the vault.
pub fn get(
    layout: &Layout,
    password: &[u8],
    secret: &OpaqueSecretId,
    version: u32,
) -> Result<(Vec<u8>, Vec<u8>), SecretError> {
    // A record lives at whichever level it was written at, and `get` is not told
    // which: an `admin put` value is at `admin`, a `secret set` value at `user`.
    // Resolving it here is what lets the user read a value the admin wrote for
    // her, which is the whole point of `admin put`.
    let unsealed = unseal(layout, password)?;
    let store = config::open_file_store(layout).map_err(|_| SecretError::Record)?;
    let level = source_level(&store, &unsealed.vault_id, &unsealed.user, secret)
        .map_err(|_| SecretError::Record)?
        .map(|(level, _)| level)
        .ok_or(SecretError::Record)?;
    get_at(layout, password, level, secret, version)
}

/// Read one stored version back from `level`: its name and its value.
///
/// The level is the record's provenance, so a reader that does not know it cannot
/// find the record. `admin` is what `admin put` wrote; `user` is the user's own.
pub fn get_at(
    layout: &Layout,
    password: &[u8],
    level: Level,
    secret: &OpaqueSecretId,
    version: u32,
) -> Result<(Vec<u8>, Vec<u8>), SecretError> {
    let unsealed = unseal(layout, password)?;
    let recorded = deployment::require(layout)
        .map_err(|_| SecretError::NotInitialised)?
        .0;
    let store = config::open_file_store(layout).map_err(|_| SecretError::Record)?;

    let metadata = metadata_at(&recorded, level, secret, version);
    let bytes =
        ksp_record::version::BlobStore::get(&store, ksp_record::RecordPath::of(&metadata).as_str())
            .map_err(|_| SecretError::Record)?
            .ok_or(SecretError::Record)?;
    let record = ksp_record::decode_record(&bytes).map_err(|_| SecretError::Record)?;

    // The private half is lent to one call and never owned: the closure returns
    // the content key, not the bytes.
    let content_key = unsealed
        .vault
        .with_recipient_secret(|sk| RecordEnvelope::open(&record.envelope, sk, &metadata))
        .map_err(|_| SecretError::Record)?;

    let aad = metadata.bound_aad().map_err(|_| SecretError::Record)?;
    record
        .blob
        .open(&content_key, &aad)
        .map_err(|_| SecretError::Record)
}

/// Read the value a `set` should store, from `reader`.
///
/// One trailing newline is stripped, the way `printf '…\n' | ksp secret set`
/// is written. Nothing else is trimmed: a value may legitimately start or end
/// with a space.
pub fn read_value<R: Read>(reader: &mut R) -> Result<Vec<u8>, SecretError> {
    let mut buffer = Vec::new();
    reader
        .read_to_end(&mut buffer)
        .map_err(|_| SecretError::Value)?;
    if buffer.last() == Some(&b'\n') {
        buffer.pop();
    }
    if buffer.is_empty() {
        return Err(SecretError::Value);
    }
    Ok(buffer)
}

/// What `get` prints when `--reveal` was not asked for.
///
/// Four bullets, the same width as a masked password field: enough to show that
/// a value exists and nothing about what it is.
pub const REDACTED: &[u8] = "••••".as_bytes();

/// Every version stored at the user's level, in record then version order.
///
/// No key is involved: a record path carries the store's own naming and opaque
/// identifiers, which is what the store can see anyway. What the listing cannot
/// see is a value, and it never asks for one.
pub fn ls(layout: &Layout) -> Result<Vec<(OpaqueSecretId, u32)>, SecretError> {
    let (recorded, _anchor) =
        deployment::require(layout).map_err(|_| SecretError::NotInitialised)?;
    let store = config::open_file_store(layout).map_err(|_| SecretError::Record)?;

    // Only this user's `user` level: an agent level is a different owner's copy,
    // and listing it here would report records this command cannot open.
    let prefix = RecordPath::directory(&recorded.vault, recorded.user, Some(&Level::User));
    let paths =
        ksp_record::version::BlobStore::list(&store, &prefix).map_err(|_| SecretError::Record)?;

    let mut found = Vec::new();
    for path in paths {
        // A path this crate did not write is not a record, so it is skipped
        // rather than guessed at: `p/<vault>/<user>/<level>/<id>/<version>`.
        let mut parts = path.split('/');
        let (Some("p"), Some(_vault), Some(_user), Some("user"), Some(id), Some(version), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            continue;
        };
        let Ok(version) = version.parse::<u32>() else {
            continue;
        };
        found.push((OpaqueSecretId::new(id), version));
    }
    found.sort_by(|left, right| {
        left.0
            .as_str()
            .cmp(right.0.as_str())
            .then(left.1.cmp(&right.1))
    });
    Ok(found)
}

/// Remove one exact version of a `user`-level record.
///
/// The password is what authorises it: the vault is the only thing that proves
/// the caller is the owner, and this host has no other way to know. Removal is
/// best effort — a copy someone saved earlier still decrypts.
pub fn rm(
    layout: &Layout,
    password: &[u8],
    secret: &OpaqueSecretId,
    version: u32,
) -> Result<(), SecretError> {
    let unsealed = unseal(layout, password)?;
    let store = config::open_file_store(layout).map_err(|_| SecretError::Record)?;
    let metadata = BoundMetadata {
        vault_id: unsealed.vault_id,
        user_id: unsealed.user,
        level: Level::User,
        secret_id: secret.clone(),
        version,
    };
    let path = ksp_record::RecordPath::of(&metadata).to_string();
    // Absence is not an error here: the caller asked for the version to be gone,
    // and a second attempt against a version that is already gone has achieved
    // what it asked for.
    ksp_backend::BlobStore::delete(&store, &path)
        .or_else(|error| {
            if path_exists(&store, &path) {
                Err(error)
            } else {
                Ok(())
            }
        })
        .map_err(|_| SecretError::Write)
}

/// Whether the store still holds the bytes at `path`.
fn path_exists(store: &ksp_backend::file::FileStore, path: &str) -> bool {
    ksp_record::version::BlobStore::get(store, path)
        .ok()
        .flatten()
        .is_some()
}

/// Run one `secret` subcommand that needs no private half.
pub fn run<W: std::io::Write>(
    command: &crate::commands::SecretCommand,
    layout: &Layout,
    emitter: &mut Emitter<W>,
) -> Outcome {
    match command {
        crate::commands::SecretCommand::Ls => match ls(layout) {
            Ok(found) => {
                let records = found
                    .iter()
                    .map(|(secret, version)| RecordMetadata {
                        record: secret.as_str().to_string(),
                        level: "user".to_string(),
                        version: *version,
                    })
                    .collect();
                match emitter.report(&Report::Records { records }) {
                    Ok(()) => Outcome::Success,
                    Err(_) => Outcome::Failed(exit::INTERNAL),
                }
            }
            Err(error) => Outcome::Failed(error.exit_code()),
        },
        other => {
            let _ = other;
            Outcome::Failed(exit::INTERNAL)
        }
    }
}

/// The report a listing prints for one record.
pub fn metadata_report(secret: &OpaqueSecretId, version: u32) -> Report {
    Report::Record(RecordMetadata {
        record: secret.as_str().to_string(),
        level: "user".to_string(),
        version,
    })
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use ksp_identity::KeyId;
    use ksp_types::VaultId;

    /// Give this home the capability configuration a real host has.
    ///
    /// The probe is the production path: it writes the strongest configuration
    /// this host can satisfy, and it never overwrites one that exists. Without a
    /// configuration the memory barrier has no adapter, and every unseal refuses
    /// — which is the product's intended first-run behaviour, and therefore
    /// something a fixture that means to exercise an *unseal* has to provide.
    fn configure(layout: &Layout) {
        crate::probe::configure(layout, crate::probe::OverwritePolicy::Replace)
            .expect("the host probe writes a configuration");
    }
    fn deployment() -> (tempfile::TempDir, Layout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        crate::admin::init(
            &layout,
            VaultId::new("vault-1"),
            "alice".to_string(),
            KeyId::new("admin-2026"),
        )
        .unwrap();
        crate::admin::user_add(
            &layout,
            b"a long enough password",
            KeyId::new("alice-ed25519-1"),
            KeyId::new("alice-x25519-1"),
            None,
        )
        .unwrap();
        configure(&layout);
        (dir, layout)
    }

    #[test]
    fn a_value_round_trips_at_the_users_level() {
        let (_dir, layout) = deployment();
        let secret = OpaqueSecretId::new("s3cr3t-id-1");

        let version = set(
            &layout,
            b"a long enough password",
            &secret,
            b"db_password",
            b"correct-horse",
        )
        .unwrap();
        assert_eq!(version, 1);

        let (name, value) = get(&layout, b"a long enough password", &secret, version).unwrap();
        assert_eq!(name, b"db_password");
        assert_eq!(value, b"correct-horse");
    }

    #[test]
    fn a_second_set_advances_the_version_rather_than_overwriting() {
        // A reused version number would rewrite the bytes an older delivery
        // names, so the older token would open the newer value.
        let (_dir, layout) = deployment();
        let secret = OpaqueSecretId::new("s3cr3t-id-1");

        let first = set(&layout, b"a long enough password", &secret, b"n", b"one").unwrap();
        let second = set(&layout, b"a long enough password", &secret, b"n", b"two").unwrap();
        assert_eq!((first, second), (1, 2));

        let (_, one) = get(&layout, b"a long enough password", &secret, 1).unwrap();
        let (_, two) = get(&layout, b"a long enough password", &secret, 2).unwrap();
        assert_eq!(one, b"one");
        assert_eq!(two, b"two");
    }

    #[test]
    fn the_wrong_password_reads_nothing_and_writes_nothing() {
        let (_dir, layout) = deployment();
        let secret = OpaqueSecretId::new("s3cr3t-id-1");
        set(&layout, b"a long enough password", &secret, b"n", b"value").unwrap();

        assert_eq!(
            get(&layout, b"the wrong password", &secret, 1).unwrap_err(),
            SecretError::Vault(crate::vault::VaultError::Refused)
        );
        assert_eq!(
            set(&layout, b"the wrong password", &secret, b"n", b"other").unwrap_err(),
            SecretError::Vault(crate::vault::VaultError::Refused)
        );

        // The stored version is unchanged: a refused write left nothing behind.
        let (_, value) = get(&layout, b"a long enough password", &secret, 1).unwrap();
        assert_eq!(value, b"value");
    }

    #[test]
    fn an_empty_value_is_refused_rather_than_stored() {
        let mut empty = &b""[..];
        assert_eq!(read_value(&mut empty).unwrap_err(), SecretError::Value);
        let mut newline = &b"\n"[..];
        assert_eq!(read_value(&mut newline).unwrap_err(), SecretError::Value);
    }

    #[test]
    fn a_value_keeps_its_inner_and_trailing_spaces() {
        // Only the one trailing newline is stripped: a value may be whitespace.
        let mut input = &b" leading and trailing \n"[..];
        assert_eq!(read_value(&mut input).unwrap(), b" leading and trailing ");
    }
}
