//! The `ksp vault` group, wired to S2's vault.
//!
//! # Nothing here is new cryptography
//!
//! `UserVault::seal` and `SealedVault::unseal` already do the work, and
//! `SealedVault` already implements the canonical encoding. This module chooses a
//! path, applies a permission, and returns an outcome.
//!
//! # The password never travels in argv
//!
//! FR-044: plaintext secret input is read from stdin, never from a command-line
//! argument, because argv is world-readable in the process table and lands in
//! shell history. Every entry point here takes the password as bytes from a
//! reader the caller chose.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ksp_identity::{SealedVault, UserVault, VaultBinding};
use ksp_types::ActorId;

use crate::exit::{self, Outcome};

/// Why a vault operation failed.
///
/// `Clone` and `PartialEq` because a caller may carry the reason into its own
/// error type (a `secret` refusal is the vault's refusal, and FR-024 wants the
/// sentence, not a code), and a test asserts the reason it got.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    /// The vault file could not be read or written.
    #[error("the vault file could not be {operation}")]
    Io {
        /// What was attempted.
        operation: &'static str,
    },
    /// The stored bytes were not a sealed vault.
    #[error("the stored vault is not readable")]
    Decode,
    /// The vault refused the password.
    #[error("the vault could not be opened with that password")]
    Refused,
    /// There is no vault here.
    #[error("no vault exists at this location")]
    Absent,
    /// The password could not be read.
    #[error("the password could not be read from the supplied input")]
    NoPassword,
    /// The password is shorter than the minimum this host accepts.
    ///
    /// A length is a policy the operator can act on; "the vault could not be
    /// opened with that password" sends them looking for a typo in a password
    /// that was typed correctly. The minimum is carried so the sentence can name
    /// it rather than describe the class.
    #[error(
        "the password is {length} bytes and this host accepts at least {minimum}, so the vault \
         was not sealed"
    )]
    PasswordTooShort {
        /// The minimum accepted length, in bytes.
        minimum: usize,
        /// The length the caller supplied, in bytes.
        length: usize,
    },
    /// No barriered region could be allocated for the password.
    #[error("no protected memory is available for the password on this host")]
    Barrier,
    /// The memory barrier capability could not be established.
    ///
    /// Distinct from [`Barrier`](Self::Barrier): that one is the selected
    /// adapter refusing, and this one is there being no adapter to ask. The
    /// sentences differ because the fixes do — one is a host that cannot lock a
    /// page, the other is a host with no configuration.
    #[error("{0}")]
    Capability(crate::establish::CapabilityError),
    /// The re-share was refused.
    #[error("the recovery phrase could not be produced: {0}")]
    Recovery(String),
    /// The vault belongs to another account, so it is not this one's to open.
    ///
    /// A vault sealed to a principal is handed to that principal's account and
    /// recorded there (FR-037). Reading it from a different account is not a
    /// weaker attempt at the password — it is the wrong principal, and a refusal
    /// that said "no vault exists" would send an operator looking for a file that
    /// is right there.
    #[error(
        "this vault is owned by uid {owner} and this invocation runs as uid {caller}, so it is \
         not this account's vault"
    )]
    NotThisAccountsVault {
        /// The on-disk owner, as measured.
        owner: u32,
        /// The effective uid of the process asking.
        caller: u32,
    },
}

impl VaultError {
    /// Keep the cause of a seal failure that the operator can act on.
    ///
    /// Every other seal failure is a wrong password from the caller's point of
    /// view, and `Refused` is the honest answer for those. A length is not: the
    /// enrolment layer already knows the minimum, and discarding it made a
    /// correctable input error look like a typo.
    fn from_seal(error: ksp_identity::EnrolmentError, length: usize) -> Self {
        match error {
            ksp_identity::EnrolmentError::PasswordTooShort { minimum } => {
                Self::PasswordTooShort { minimum, length }
            }
            _ => Self::Refused,
        }
    }

    /// The exit code this failure maps to.
    pub fn exit_code(&self) -> i32 {
        match self {
            // A vault that will not open is, from the caller's point of view,
            // missing usable key material.
            Self::Refused | Self::Absent | Self::NoPassword => exit::MISSING_KEY,
            // A length is not missing material: the operator supplied a
            // password and it was refused for a reason they can fix by typing
            // more. `MISSING_KEY` is `6`, which is the code this refusal has
            // always carried, so no published code moves.
            Self::PasswordTooShort { .. } => exit::MISSING_KEY,
            Self::Io { .. } | Self::Decode | Self::Recovery(_) => exit::INTERNAL,
            // A host that cannot lock a page refuses the operation rather than
            // handling the password in ordinary memory.
            Self::Barrier => exit::POLICY_DENIAL,
            // A capability the configuration cannot establish carries its own
            // class: a broken file is a policy denial, a missing configuration
            // or a host that cannot provide the mechanism is a capability
            // refusal.
            Self::Capability(error) => error.exit_code(),
            // The host layout cannot admit this, which is the capability refusal
            // rather than a missing key: the material is there and it is not
            // this account's.
            Self::NotThisAccountsVault { .. } => exit::CAPABILITY_REFUSAL,
        }
    }
}

/// Where this host keeps its vault.
#[derive(Debug, Clone)]
pub struct VaultHome {
    root: PathBuf,
}

impl VaultHome {
    /// A vault home under `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The vault file.
    pub fn vault_file(&self) -> PathBuf {
        self.root.join("vault.cbor")
    }

    /// The home this vault lives under.
    ///
    /// The capability configuration sits beside the vault file, so a caller that
    /// only holds a `VaultHome` needs the root to read it.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether a vault exists here.
    pub fn exists(&self) -> bool {
        self.vault_file().is_file()
    }
}

/// Read a sealed vault from `home`, and only as the account that owns it.
///
/// # Why the owner is checked here
///
/// The vault is the user principal's key material, and `admin user add` gives the
/// file to her account and records it (FR-037). Mode `0600` keeps another account
/// out by `EACCES`, which is a kernel refusal but a confusing one: it is reported
/// as "no vault exists" while the file sits there. And it is not sufficient on its
/// own — an account that has been *given* the file, or a drifted owner, would read
/// it happily. So the measured owner is compared with the asking account before a
/// byte is read, and a mismatch is the typed refusal rather than a missing file.
///
/// `stat` needs only traversal on the parents, so the check can run for a caller
/// that could not read the bytes: that is exactly the case it has to name.
pub fn read_sealed(home: &VaultHome) -> Result<SealedVault, VaultError> {
    use std::os::unix::fs::MetadataExt;

    let path = home.vault_file();
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| VaultError::Absent)?;
    let caller = ksp_posture::permissions::effective_uid();
    if metadata.uid() != caller {
        return Err(VaultError::NotThisAccountsVault {
            owner: metadata.uid(),
            caller,
        });
    }
    let bytes = std::fs::read(&path).map_err(|_| VaultError::Absent)?;
    ksp_types::cbor::decode(&bytes).map_err(|_| VaultError::Decode)
}

/// Write a sealed vault to `home`.
///
/// The file is created with owner-only permissions before the bytes are written,
/// so a sealed vault is never briefly world-readable. The bytes are ciphertext,
/// but the salt and nonce narrow an offline attack and there is no reason to
/// expose them.
pub(crate) fn write_sealed(home: &VaultHome, sealed: &SealedVault) -> Result<(), VaultError> {
    let bytes = ksp_types::cbor::encode(sealed).map_err(|_| VaultError::Decode)?;
    // A home created here gets the whole layout, at the table's modes: the
    // vault's own mode is applied below, and the roots around it must not be
    // left to the process's `umask` (misfit B).
    crate::layout::ensure(&home.root).map_err(|_| VaultError::Io {
        operation: "created",
    })?;
    let path = home.vault_file();
    write_private(&path, &bytes).map_err(|_| VaultError::Io {
        operation: "written",
    })
}

/// Write a file owner-only, atomically.
///
/// The vault is the only copy of the user's key material, and `truncate` on the
/// live path would destroy it if the write, the sync or the power failed: the
/// recovery phrase for a torn file was never printed, because it is printed only
/// after this returns. So the bytes go to a sibling first, are synced, and are
/// renamed over the live path — a rename is atomic, and a crash before it leaves
/// the previous file whole.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let staged = path.with_extension("new");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&staged)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&staged, path)?;

    // The rename is durable only once the directory entry is synced.
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Re-seal the vault and re-share it, returning the phrase that recovers it.
///
/// # Why the phrase is printed only after the file is written
///
/// The shares are cut from the bytes the file will hold, so the phrase and the
/// stored vault have to be the same bytes. `reshare_vault_bundle` splits and
/// validates *before* it persists, and hands the bundle to a closure here that
/// writes the file; if that write fails the phrase is never returned, so an
/// operator cannot be left holding a phrase that opens nothing. The previous
/// phrase is retired at the same moment, which is the point of a rekey.
///
/// # Why the password does not change
///
/// A phrase recovers a *sealed* bundle: the same ciphertext the password also
/// opens. Rotating the password would need the new one asked for twice and would
/// not change what the phrase is for. This command rotates the sharing only.
pub fn rekey(
    home: &VaultHome,
    password: &[u8],
    threshold: u8,
    shares: u8,
) -> Result<ksp_identity::RecoveryPhrase, VaultError> {
    let sealed = read_sealed(home)?;
    // The binding is the AEAD's associated data, and it comes from the
    // deployment file rather than a naming convention.
    let binding = binding_for(home, &sealed)?;
    // The barriered unseal, not a direct `SealedVault::unseal`: a rekey holds the
    // same key material as any other unseal, so it establishes the configured
    // memory barrier through the same adapter and refuses when there is none.
    let vault = unseal(home, &binding, password)?;

    // A fresh salt, so the new file is not byte-identical to the old one and an
    // old phrase cannot be mistaken for a phrase over this one.
    let resealed = vault
        .seal(password, &binding)
        .map_err(|error| VaultError::from_seal(error, password.len()))?;
    let bundle = ksp_types::SealedBundle::new(
        ksp_types::cbor::encode(&resealed).map_err(|_| VaultError::Decode)?,
    );

    ksp_identity::reshare_vault_bundle(
        &bundle,
        ksp_types::Threshold(usize::from(threshold)),
        ksp_types::ShareCount(usize::from(shares)),
        |bundle| {
            // The closure persists the *bundle's* bytes, so what the phrase
            // restores and what the file holds are one artifact.
            let stored: SealedVault = ksp_types::cbor::decode(bundle.as_bytes())
                .map_err(|_| "the re-sealed vault could not be encoded".to_string())?;
            write_sealed(home, &stored).map_err(|error| error.to_string())
        },
    )
    .map_err(|error| VaultError::Recovery(error.to_string()))
}

/// The binding this host's vault was sealed under.
fn binding_for(home: &VaultHome, sealed: &SealedVault) -> Result<VaultBinding, VaultError> {
    let _ = sealed;
    // The deployment file is the only place the key IDs live; a binding
    // reconstructed from a naming convention would open the vault only for as
    // long as the convention held.
    let layout = crate::config::Layout::new(home_root(home)?);
    let deployment = crate::deployment::require(&layout)
        .map_err(|_| VaultError::Absent)?
        .0;
    Ok(VaultBinding {
        identity: ActorId::User(deployment.user),
        signing_key_id: deployment.user_signing_key_id.ok_or(VaultError::Absent)?,
        recipient_key_id: deployment.user_recipient_key_id.ok_or(VaultError::Absent)?,
    })
}

/// The root a `VaultHome` was built over.
fn home_root(home: &VaultHome) -> Result<PathBuf, VaultError> {
    Ok(home.root.clone())
}

/// Create a vault and seal it under `password`.
///
/// Returns the binding that was used, which the caller needs in order to unseal
/// it later: the binding is the AEAD's associated data, so a vault opened with a
/// different one simply fails.
pub fn init(
    home: &VaultHome,
    identity: ActorId,
    signing_key_id: &str,
    recipient_key_id: &str,
    password: &[u8],
) -> Result<(VaultBinding, UserVault), VaultError> {
    let vault = UserVault::generate();
    let binding = VaultBinding {
        identity,
        signing_key_id: ksp_identity::KeyId::new(signing_key_id),
        recipient_key_id: ksp_identity::KeyId::new(recipient_key_id),
    };
    let sealed = vault
        .seal(password, &binding)
        .map_err(|error| VaultError::from_seal(error, password.len()))?;
    write_sealed(home, &sealed)?;
    Ok((binding, vault))
}

/// Open the vault at `home`.
///
/// This is **the** barriered unseal: the password is copied into a region the
/// selected adapter allocated, the vault is opened against that region, and the
/// region is wiped before this function returns. There is one such function, so
/// a second unseal path cannot quietly do it without the barrier.
///
/// # The adapter is the configured one
///
/// T041, FR-011: the barrier is established by the adapter the operator named,
/// not by whichever mechanism this build happens to prefer. A host with no
/// configuration has no adapter and refuses — naming `ksp init`, because the
/// host is not the problem — rather than falling back to ordinary memory.
///
/// # What this does not cover
///
/// The caller still holds the password in an ordinary `Vec`, and this function
/// cannot wipe a buffer it was lent. The window is the copy, not the whole
/// lifetime of the secret, and the code that reads a password is the place that
/// would have to narrow it further.
pub fn unseal(
    home: &VaultHome,
    binding: &VaultBinding,
    password: &[u8],
) -> Result<UserVault, VaultError> {
    let layout = crate::config::Layout::new(home.root().to_path_buf());
    let configuration = crate::establish::load(&layout).map_err(VaultError::Capability)?;
    let grant = crate::establish::granted(
        configuration.as_ref(),
        ksp_types::HostCapability::MemoryBarrier,
    )
    .map_err(VaultError::Capability)?;
    // A barrier with no adapter is not a weaker barrier: it is no barrier, and
    // the password would be held in ordinary memory. `granted` already refused
    // the required case; an `optional` capability with nothing available gets
    // this far and refuses here, because there is nothing to allocate from.
    let adapter = crate::establish::barrier(&grant).ok_or(VaultError::Barrier)?;

    let sealed = read_sealed(home)?;
    // `.max(1)`: a zero-length region is not a region, and an empty password
    // must read as a wrong password rather than as a host without protected
    // memory.
    let mut region = adapter
        .allocate(password.len().max(1))
        .map_err(|_| VaultError::Barrier)?;
    region.as_bytes_mut().copy_from_slice(password);
    let unsealed = sealed
        .unseal(region.as_bytes(), binding)
        .map_err(|_| VaultError::Refused);
    region.wipe();
    unsealed
}

/// Read a password from `reader`, with the trailing newline removed.
pub fn read_password<R: Read>(reader: &mut R) -> Result<Vec<u8>, VaultError> {
    let mut buffer = Vec::new();
    reader
        .read_to_end(&mut buffer)
        .map_err(|_| VaultError::NoPassword)?;
    while matches!(buffer.last(), Some(b'\n') | Some(b'\r')) {
        buffer.pop();
    }
    if buffer.is_empty() {
        return Err(VaultError::NoPassword);
    }
    Ok(buffer)
}

/// Run one `vault` subcommand.
pub fn run<W: Write>(
    command: &crate::commands::VaultCommand,
    home: &VaultHome,
    emitter: &mut crate::output::Emitter<W>,
) -> Outcome {
    match command {
        crate::commands::VaultCommand::Status => {
            if home.exists() {
                // Present and sealed. The version is the only thing the file
                // states without a password, so it is all this reports — and it
                // reports it: a successful command that printed nothing left the
                // caller unable to tell a sealed vault from a silent failure.
                match read_sealed(home) {
                    Ok(sealed) => {
                        let report =
                            crate::output::Report::SealedVault(crate::output::SealedVaultView {
                                version: sealed.version(),
                            });
                        match emitter.report(&report) {
                            Ok(()) => Outcome::Success,
                            Err(_) => Outcome::Failed(exit::INTERNAL),
                        }
                    }
                    Err(error) => Outcome::Failed(error.exit_code()),
                }
            } else {
                Outcome::Failed(VaultError::Absent.exit_code())
            }
        }
        // A vault is created by `admin user add`, not here: sealing one needs the
        // binding the deployment records (identity and both key IDs), and a vault
        // this command created would have no deployment to open it. Refused with
        // the reason rather than left failing as an internal error.
        crate::commands::VaultCommand::Init => {
            let mut stderr = crate::output::Emitter::new(false, std::io::stderr());
            let _ = stderr.refusal(
                "a vault is created by `admin user add`, which records the binding that opens \
                 it; `vault init` has no deployment to seal to",
            );
            Outcome::Failed(exit::CAPABILITY_REFUSAL)
        }
        // `rekey` needs a password from stdin, which the caller supplies; it is
        // handled by the command wiring. `seal` and `unseal` are not commands at
        // all: see `VaultCommand::Status` for why.
        _ => Outcome::Failed(exit::INTERNAL),
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn alice() -> ksp_types::PrincipalId {
        ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap()
    }

    fn binding() -> VaultBinding {
        VaultBinding {
            identity: ActorId::User(alice()),
            signing_key_id: ksp_identity::KeyId::new("alice-ed25519-1"),
            recipient_key_id: ksp_identity::KeyId::new("alice-x25519-1"),
        }
    }

    /// Give this home the capability configuration a real host has.
    ///
    /// The probe is the production path: it writes the strongest configuration
    /// this host can satisfy, and it never overwrites one that exists. Without a
    /// configuration the memory barrier has no adapter, and every unseal refuses
    /// — which is the product's intended first-run behaviour, so a fixture that
    /// means to exercise an *unseal* has to provide one.
    fn configure(layout: &crate::config::Layout) {
        crate::probe::configure(layout, crate::probe::OverwritePolicy::Replace)
            .expect("the host probe writes a configuration");
    }

    #[test]
    fn a_vault_is_written_and_reopened_with_its_own_binding() {
        let dir = tempfile::tempdir().unwrap();
        let home = VaultHome::new(dir.path());
        configure(&crate::config::Layout::new(dir.path()));

        let (used, _vault) = init(
            &home,
            ActorId::User(alice()),
            "alice-ed25519-1",
            "alice-x25519-1",
            b"a long enough password",
        )
        .unwrap();
        assert!(home.exists());
        assert_eq!(used, binding());

        let reopened = unseal(&home, &used, b"a long enough password").unwrap();
        let _ = reopened.vault_key();
    }

    /// A short password is a length, and the refusal has to say so.
    ///
    /// The enrolment layer already returns a structured error with the minimum
    /// in it. Before this test existed, `init` replaced every seal failure with
    /// `Refused`, so a seven-byte password reached the operator as "the vault
    /// could not be opened with that password" and the minimum was lost.
    #[test]
    fn a_short_password_names_the_minimum_instead_of_refusing_generically() {
        let dir = tempfile::tempdir().unwrap();
        let home = VaultHome::new(dir.path());
        configure(&crate::config::Layout::new(dir.path()));

        let error = init(&home, ActorId::User(alice()), "k1", "k2", b"1234567")
            .expect_err("seven bytes is below the minimum this host accepts");

        match error {
            VaultError::PasswordTooShort { minimum, length } => {
                assert_eq!(minimum, ksp_identity::MIN_PASSWORD_LEN);
                assert_eq!(length, 7);
                let rendered = VaultError::PasswordTooShort { minimum, length }.to_string();
                assert!(
                    rendered.contains(&minimum.to_string()),
                    "the refusal must name the minimum, got {rendered:?}"
                );
            }
            other => panic!("a short password is a length, not a wrong password: {other:?}"),
        }
    }

    #[test]
    fn the_wrong_password_does_not_open_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let home = VaultHome::new(dir.path());
        configure(&crate::config::Layout::new(dir.path()));
        let (used, _) = init(
            &home,
            ActorId::User(alice()),
            "k1",
            "k2",
            b"a long enough password",
        )
        .unwrap();

        let error = unseal(&home, &used, b"a different password").unwrap_err();
        assert!(matches!(error, VaultError::Refused));
        assert_eq!(error.exit_code(), exit::MISSING_KEY);
    }

    #[test]
    fn a_vault_cannot_be_moved_onto_another_identity() {
        // The binding is the AEAD's associated data, so a stolen vault file is
        // inert without the binding it was sealed under.
        let dir = tempfile::tempdir().unwrap();
        let home = VaultHome::new(dir.path());
        configure(&crate::config::Layout::new(dir.path()));
        let (used, _) = init(
            &home,
            ActorId::User(alice()),
            "k1",
            "k2",
            b"a long enough password",
        )
        .unwrap();

        let mut other = used.clone();
        other.identity = ActorId::User(
            ksp_types::PrincipalId::parse("bad00000-0000-4000-8000-000000000003").unwrap(),
        );
        assert!(matches!(
            unseal(&home, &other, b"a long enough password"),
            Err(VaultError::Refused)
        ));
    }

    #[test]
    fn the_vault_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let home = VaultHome::new(dir.path());
        configure(&crate::config::Layout::new(dir.path()));
        init(
            &home,
            ActorId::User(alice()),
            "k1",
            "k2",
            b"a long enough password",
        )
        .unwrap();

        let mode = std::fs::metadata(home.vault_file())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "a sealed vault must be owner-only");
    }

    #[test]
    fn a_password_is_read_from_the_reader_and_its_newline_stripped() {
        let mut input = &b"a long enough password\n"[..];
        assert_eq!(
            read_password(&mut input).unwrap(),
            b"a long enough password"
        );

        let mut empty = &b"\n"[..];
        assert!(matches!(
            read_password(&mut empty),
            Err(VaultError::NoPassword)
        ));
    }

    #[test]
    fn status_reports_absence_rather_than_inventing_a_vault() {
        let dir = tempfile::tempdir().unwrap();
        let home = VaultHome::new(dir.path());
        configure(&crate::config::Layout::new(dir.path()));
        let mut sink = Vec::new();
        let outcome = run(
            &crate::commands::VaultCommand::Status,
            &home,
            &mut crate::output::Emitter::new(false, &mut sink),
        );
        assert_eq!(outcome.code(), exit::MISSING_KEY);
        assert!(
            sink.is_empty(),
            "a command that found nothing says nothing on stdout: {}",
            String::from_utf8_lossy(&sink)
        );
    }

    /// A sealed vault states its version: an empty success is indistinguishable
    /// from a command that did nothing.
    #[test]
    fn status_names_the_sealed_version_instead_of_printing_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let home = VaultHome::new(dir.path());
        configure(&crate::config::Layout::new(dir.path()));
        init(
            &home,
            ActorId::User(alice()),
            "alice-ed25519-1",
            "alice-x25519-1",
            b"a long enough password",
        )
        .unwrap();

        let mut sink = Vec::new();
        let outcome = run(
            &crate::commands::VaultCommand::Status,
            &home,
            &mut crate::output::Emitter::new(false, &mut sink),
        );
        assert_eq!(outcome.code(), exit::SUCCESS);
        let text = String::from_utf8_lossy(&sink).to_string();
        assert!(text.contains("vault:       sealed, version "), "{text}");
        assert!(
            !text.contains("a long enough password"),
            "the password never reaches a report: {text}"
        );
    }
}
