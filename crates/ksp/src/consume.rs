//! `ksp run --consume`: deliver in another process, then remove and report here.
//!
//! # Why the delivery is a separate process
//!
//! S4's order is retrieve, deliver, delete, journal, report. Landlock restricts
//! the process that installs a ruleset, one way and irreversibly, and every
//! process it forks inherits the restriction — so the process that confines
//! itself to launch the child could no longer delete the record, write the
//! acknowledgement or write the report. Delivering there and deleting here is
//! the arrangement in which both halves are true: the child is confined for reads
//! *and* writes (WP18), and the delete still has somewhere to go.
//!
//! The second process is this same binary. The plaintext crosses one pipe into
//! it and reaches the user's child through the declared `--env` exception, which
//! is how a non-consume run delivers.
//!
//! # The AAD comes from the target, never from the record
//!
//! A stored record carries its own metadata, and building the associated data
//! from it would authenticate the record against itself: a record moved from a
//! sibling level would open. Every element of the AAD comes from the intent and
//! the version it names, so a record that describes a different level or version
//! fails to open (WP13's review finding).
//!
//! # What a removal does not mean
//!
//! `Removed` says a later fresh fetch from an honest store fails. It does not
//! recall a copy, and the report is one actor's claim rather than proof that
//! anything was destroyed.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ksp_deletion::{
    AcknowledgementJournal, AuthorizedIntent, Child, ChildFailureReason, ConsumeError,
    ConsumeOutcome, ConsumeRequest, Decryptor, EvidenceSigningKey, JournalError, JournalStore,
    ReportSink, SignedIntent, VersionStore, VersionTarget, consume,
};
use ksp_types::{ActorId, BoundMetadata, ContentKey, Level};

use crate::commands::RunArgs;
use crate::config::Layout;
use crate::exit::{self, Outcome};
use crate::run;

/// Why a consume could not reach S4's sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConsumeFailure {
    /// The signed delete authorisation is missing or unreadable.
    #[error("no usable signed delete authorisation sits beside the token")]
    NoIntent,
    /// The authorisation was not signed by the pinned key, or does not cover this version.
    #[error("the delete authorisation is not valid for this delivery")]
    Unauthorized,
    /// The intent names a level a delivery is never minted at.
    #[error("the delete authorisation names a level this command cannot act at")]
    Level,
}

impl ConsumeFailure {
    /// The exit code this failure maps to.
    ///
    /// An authorisation this host cannot verify is an authority it does not
    /// grant, and a missing one authorises nothing.
    pub fn exit_code(&self) -> i32 {
        exit::POLICY_DENIAL
    }
}

/// Read the authorisation beside the token and verify it against the pinned key.
///
/// The intent is a file the caller supplied, so it proves nothing by itself: it
/// is verified against the anchor this host pinned, exactly as the token is.
fn authorize(token_path: &Path, layout: &Layout) -> Result<AuthorizedIntent, ConsumeFailure> {
    // The owner's key, pinned from this host's deployment record: the intent is
    // her authorisation for this copy to be removed (spec §3.7 step 2).
    let signer =
        crate::deployment::user_verifying_key(layout).map_err(|_| ConsumeFailure::Unauthorized)?;
    let intent_path = token_path.with_extension("intent");
    let bytes = std::fs::read(intent_path).map_err(|_| ConsumeFailure::NoIntent)?;
    let signed: SignedIntent =
        ksp_types::cbor::decode(&bytes).map_err(|_| ConsumeFailure::NoIntent)?;

    // A public half needs its bytes and nothing scoped: this is the same key the
    // token was verified against, in the shape `ed25519-dalek` verifies with.
    let issuer = ed25519_dalek::VerifyingKey::from_bytes(&signer.to_bytes())
        .map_err(|_| ConsumeFailure::Unauthorized)?;
    signed
        .verify_as(&issuer)
        .map_err(|_| ConsumeFailure::Unauthorized)
}

/// One exact version in the local store.
struct StoredVersions<'a> {
    store: &'a ksp_backend::file::FileStore,
    vault: ksp_types::VaultId,
    user: ksp_types::PrincipalId,
}

impl StoredVersions<'_> {
    /// The record path this target names, from the intent's own identity.
    fn metadata(&self, target: &VersionTarget) -> BoundMetadata {
        BoundMetadata {
            vault_id: self.vault.clone(),
            user_id: self.user,
            level: target.level.clone(),
            secret_id: target.secret_id.clone(),
            version: target.version,
        }
    }
}

impl VersionStore for StoredVersions<'_> {
    fn fetch(&self, target: &VersionTarget) -> Option<Vec<u8>> {
        ksp_record::version::BlobStore::get(
            self.store,
            ksp_record::RecordPath::of(&self.metadata(target)).as_str(),
        )
        .ok()
        .flatten()
    }

    fn delete_exact(&self, target: &VersionTarget) -> Result<String, ConsumeError> {
        // "Exactly this version": the path names the level, the record and the
        // version, so no other record can be removed by this call.
        let path = ksp_record::RecordPath::of(&self.metadata(target)).to_string();
        ksp_backend::BlobStore::delete(self.store, &path).map_err(|error| {
            ConsumeError::DeleteFailed {
                reason: error.to_string(),
            }
        })?;
        // The path is the acknowledgement: it names what was removed, and the
        // report claims nothing beyond it.
        Ok(path)
    }
}

/// Opens the stored version this delivery names.
struct RecordDecryptor<'a> {
    content_key: &'a ContentKey,
    vault_id: ksp_types::VaultId,
    user_id: ksp_types::PrincipalId,
}

impl Decryptor for RecordDecryptor<'_> {
    fn decrypt(&self, target: &VersionTarget, ciphertext: &[u8]) -> Result<Vec<u8>, ConsumeError> {
        let record = ksp_record::decode_record(ciphertext).map_err(|_| ConsumeError::Decryption)?;

        // Every element comes from the request, not from the record. A record
        // that describes another level or version therefore fails to open rather
        // than opening under its own description.
        let metadata = BoundMetadata {
            vault_id: self.vault_id.clone(),
            user_id: self.user_id,
            level: target.level.clone(),
            secret_id: target.secret_id.clone(),
            version: target.version,
        };
        let aad = metadata.bound_aad().map_err(|_| ConsumeError::Decryption)?;
        let (_name, value) = record
            .blob
            .open(self.content_key, &aad)
            .map_err(|_| ConsumeError::Decryption)?;
        Ok(value)
    }
}

/// The child, delivered to by another process that confines itself first.
struct DeliveringChild<'a> {
    variable: &'a str,
    argv: &'a [String],
    /// The level directory the record was read from. Passed explicitly because
    /// the delivery process has only the plaintext and the child's argv, and a
    /// ruleset it derived itself could grant a subtree this run never read.
    level: &'a std::path::Path,
}

impl Child for DeliveringChild<'_> {
    fn deliver(&self, plaintext: &[u8]) -> Result<(), ChildFailureReason> {
        let binary = std::env::current_exe()
            .map_err(|_| ChildFailureReason::new("this executable could not be located"))?;
        let mut command = Command::new(binary);
        command
            .arg("__deliver")
            .arg("--env")
            .arg(self.variable)
            .arg("--level")
            .arg(self.level)
            .arg("--")
            .args(self.argv)
            .stdin(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|_| ChildFailureReason::new("the delivery process could not be started"))?;

        // The plaintext is written to the pipe and nothing else is done with it:
        // no argument of any process, no environment, no file.
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(plaintext).map_err(|_| {
                ChildFailureReason::new("the delivery process did not accept the value")
            })?;
        }
        let status = child
            .wait()
            .map_err(|_| ChildFailureReason::new("the delivery process could not be awaited"))?;
        match status.code() {
            Some(0) => Ok(()),
            Some(code) => Err(ChildFailureReason::new(format!("the child exited {code}"))),
            None => Err(ChildFailureReason::new("the child was signalled")),
        }
    }
}

/// A journal on the local disk.
pub struct FileJournal {
    root: PathBuf,
}

impl FileJournal {
    /// A journal under `root`.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// The file a key names, or `None` when the key would escape the directory.
    fn path(&self, key: &str) -> Option<PathBuf> {
        // A key is a file name here, and an intent id is text that arrived from
        // outside: a key that could traverse would write outside the journal.
        if key.is_empty() || key.contains('/') || key.contains('\\') || key.contains("..") {
            return None;
        }
        Some(self.root.join(key))
    }
}

impl JournalStore for FileJournal {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, JournalError> {
        let path = self.path(key).ok_or_else(|| JournalError::Store {
            operation: "read",
            reason: "the acknowledgement key is not a usable file name".to_string(),
        })?;
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(JournalError::Store {
                operation: "read",
                reason: "the journal could not be read".to_string(),
            }),
        }
    }

    fn put(&self, key: &str, bytes: &[u8]) -> Result<(), JournalError> {
        let path = self.path(key).ok_or_else(|| JournalError::Store {
            operation: "write",
            reason: "the acknowledgement key is not a usable file name".to_string(),
        })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| JournalError::Store {
                operation: "create",
                reason: "the journal directory could not be created".to_string(),
            })?;
        }
        // An existing key is compared, never overwritten: the journal decides
        // whether a second write is the same acknowledgement or a collision, and
        // it can only decide that if the bytes that were there survive.
        if let Ok(existing) = std::fs::read(&path) {
            if existing != bytes {
                return Err(JournalError::Corrupt);
            }
            return Ok(());
        }
        crate::keys::write_owner_only(&path, bytes).map_err(|_| JournalError::Store {
            operation: "write",
            reason: "the acknowledgement could not be written".to_string(),
        })
    }
}

/// Reports written as files.
pub struct FileReports {
    root: PathBuf,
}

impl FileReports {
    /// Reports under `root`.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl ReportSink for FileReports {
    fn write(&self, report: &[u8]) -> Result<(), JournalError> {
        std::fs::create_dir_all(&self.root).map_err(|_| JournalError::Store {
            operation: "create",
            reason: "the report directory is not writable".to_string(),
        })?;
        // One file per report. Overwriting would let a later report replace an
        // earlier actor's claim, which is the one thing a report must never do.
        let mut index = 0usize;
        loop {
            let path = self.root.join(format!("report-{index}.cbor"));
            if !path.exists() {
                return crate::keys::write_owner_only(&path, report).map_err(|_| {
                    JournalError::Store {
                        operation: "write",
                        reason: "the report could not be written".to_string(),
                    }
                });
            }
            index += 1;
        }
    }
}

/// Whether the intent names a level a delivery is minted at.
///
/// A delivery exists only at an agent level, because that is the only level with
/// its own recipient key. An intent naming another level would authorise a delete
/// this command has no key to open, so it is refused rather than attempted.
pub fn is_agent_level(level: &Level) -> bool {
    matches!(level, Level::Agent(_))
}

/// Run one `ksp run --consume` invocation.
pub fn run(
    args: &RunArgs,
    layout: &Layout,
    configuration: Option<&ksp_types::capability_config::CapabilityConfiguration>,
) -> Outcome {
    let loaded = match run::load(args, layout) {
        Ok(loaded) => loaded,
        // Same refusal, same disclosure: the consume path reads the same
        // protected roots as a plain run.
        Err(error) => return run::refuse(&error),
    };
    if let Some(note) = &loaded.standing_note {
        let _ = crate::output::Emitter::new(false, std::io::stderr()).refusal(note);
    }

    // What this host establishes for path confinement. The child that actually
    // confines is a second process, and it resolves the same file with the same
    // function — so the two agree by construction rather than by an argument one
    // passes to the other. This call is what refuses a required capability
    // **before** the parent touches the record: a consume that removed a version
    // and then discovered it could not confine would have deleted the only copy
    // for nothing.
    let grant = match crate::establish::granted(
        configuration,
        ksp_types::HostCapability::PathConfinement,
    ) {
        Ok(grant) => grant,
        Err(refusal) => {
            let _ =
                crate::output::Emitter::new(false, std::io::stderr()).refusal(&refusal.to_string());
            return Outcome::Failed(refusal.exit_code());
        }
    };

    // The acceptance is recorded before the child exists, for the same reason a
    // plain run records it there: the durable record has to precede the effect
    // (FR-044), and an accepted absence nobody recorded is Misfit N.
    //
    // It is signed by the agent, with the key this run already holds. The admin's
    // key is not readable from the principal's account and must not be: an
    // acceptance that could only be written by the admin would be an acceptance
    // nothing records.
    if let Some(acceptance) = grant.acceptance() {
        let record = crate::audit::AgentRecord {
            actor: loaded.user,
            signer_key_id: loaded.signing_key_id.as_str(),
            operation: ksp_types::evidence::AuditOperation::Capability,
            target: Some(ksp_types::evidence::AuditTarget::Deployment),
            outcome: ksp_types::evidence::Outcome::Success,
            exit_code: exit::SUCCESS,
            acceptance: Some(acceptance),
        };
        if let Err(refusal) = crate::audit::record_agent(layout, &loaded.bundle, &record) {
            let _ =
                crate::output::Emitter::new(false, std::io::stderr()).refusal(&refusal.to_string());
            return Outcome::Failed(refusal.exit_code());
        }
    }
    if !grant.established() {
        // NFR-010: no child is launched by a command that establishes a
        // confinement without saying that nothing was confined.
        let _ = crate::output::Emitter::new(false, std::io::stderr()).refusal(&format!(
            "no path confinement is enforced on this host: the {} capability is \
             `{}` and nothing could be established, so the child runs unconfined",
            ksp_types::HostCapability::PathConfinement.label(),
            // From the grant rather than a literal: the level is the
            // operator's, and a word spelled here would keep saying `optional`
            // after the configuration said otherwise.
            grant.requirement().label(),
        ));
    }

    let token_path = match args.token.as_deref() {
        Some(path) => PathBuf::from(path),
        None => return Outcome::Failed(exit::MISSING_KEY),
    };
    let authorized = match authorize(&token_path, layout) {
        Ok(authorized) => authorized,
        Err(failure) => return Outcome::Failed(failure.exit_code()),
    };

    let intent = authorized.intent();
    if !is_agent_level(&intent.level) {
        return Outcome::Failed(ConsumeFailure::Level.exit_code());
    }
    let target = VersionTarget {
        level: intent.level.clone(),
        secret_id: intent.secret_id.clone(),
        version: intent.version,
    };

    let backend = match crate::config::open_file_store(layout) {
        Ok(backend) => backend,
        Err(_) => return Outcome::Failed(exit::MISSING_KEY),
    };
    let versions = StoredVersions {
        store: &backend,
        vault: intent.vault_id.clone(),
        user: intent.user_id,
    };

    // Spend one permitted delivery **before** the child runs, so a crash after
    // delivery loses a use rather than restoring one. A bound that can be spent
    // twice is not a bound, and the safe direction is the one that ends the copy
    // early rather than the one that extends it.
    //
    // An arm with no bound has no counter, and spending it is a no-op: the
    // consume is time-bounded instead, which the sweep already handles.
    if let Err(_spend) =
        ksp_backend::usebound::spend(backend.root(), authorized.intent().intent_id.as_str())
    {
        // The counter could not be written. Refusing is the safe direction: a
        // delivery that cannot be counted would spend a use the user never
        // authorised, or leave the bound unenforced.
        return Outcome::Failed(exit::DELETE_FAILED);
    }

    let variable = args.env.clone().unwrap_or_else(|| "KSP_SECRET".to_string());
    let child = DeliveringChild {
        variable: &variable,
        argv: &args.child,
        level: &loaded.level_directory,
    };

    // Creation goes through the layout table for the same reason every other
    // protected root does: an inherited `umask` must not decide its mode.
    if crate::layout::ensure_row(layout.root(), &layout.journal_root()).is_err() {
        return Outcome::Failed(exit::DELETE_FAILED);
    }
    let journal = FileJournal::new(layout.journal_root());
    let acknowledgement = AcknowledgementJournal::new(journal);
    let reports = FileReports::new(layout.journal_root().join("reports"));

    // The report is signed by the actor. The seed is lent for one call so the
    // bundle keeps its own: the key built here is the only copy that outlives the
    // borrow, and it wipes itself on drop.
    let signer: EvidenceSigningKey = loaded
        .bundle
        .with_signing_secret(|seed| EvidenceSigningKey::from_seed(*seed));

    let request = ConsumeRequest {
        target,
        actor: ActorId::Agent(loaded.agent),
        signer_key_id: loaded.signing_key_id.as_str().to_string(),
        reason: "ksp run --consume".to_string(),
        acknowledged_at: i64::try_from(run::now_seconds()).unwrap_or(i64::MAX),
    };

    let decryptor = RecordDecryptor {
        // A policy-bound delivery never reaches here: `load` refuses its consume
        // before this runs (FR-019) and it holds no content key to decrypt with. The
        // arm states that rather than unwrapping, so a future caller that skipped the
        // refusal fails here instead of panicking in a delivery path.
        content_key: match loaded.content_key.as_ref() {
            Some(content_key) => content_key,
            None => {
                let _ = crate::output::Emitter::new(false, std::io::stderr()).refusal(
                    "this delivery is governed by a policy and holds no content key, so there \
                     is nothing to consume: withdraw the policy instead",
                );
                return Outcome::Failed(exit::POLICY_DENIAL);
            }
        },
        vault_id: intent.vault_id.clone(),
        user_id: intent.user_id,
    };

    match consume(
        &versions,
        &decryptor,
        &child,
        &acknowledgement,
        &signer,
        &reports,
        &authorized,
        &request,
    ) {
        Ok(ConsumeOutcome::Removed) => Outcome::Success,
        // The version is gone and the child failed. The caller must ask for a new
        // delivery rather than retry: nothing is reminted automatically.
        Ok(ConsumeOutcome::LostFreshFetch { .. }) => Outcome::Failed(exit::LOST_FRESH_FETCH),
        Err(error) => Outcome::Failed(exit::from_consume(&error)),
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says why.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_journal_key_cannot_escape_its_directory() {
        let journal = FileJournal::new(PathBuf::from("/tmp/journal"));
        assert!(journal.path("../escape").is_none());
        assert!(journal.path("a/b").is_none());
        assert!(journal.path("").is_none());
        assert_eq!(
            journal.path("s-1-a-1-2"),
            Some(PathBuf::from("/tmp/journal/s-1-a-1-2"))
        );
    }

    #[test]
    fn a_user_level_intent_is_not_a_delivery_level() {
        assert!(is_agent_level(&Level::Agent(
            ksp_types::AgentId::parse("00000000-0000-4000-8000-0000000000a1").unwrap()
        )));
        assert!(!is_agent_level(&Level::User));
    }

    #[test]
    fn the_journal_keeps_the_first_acknowledgement_and_refuses_a_different_one() {
        let root = std::env::temp_dir().join(format!("ksp-journal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let journal = FileJournal::new(root.clone());

        assert!(journal.get("k-1").unwrap().is_none());
        journal.put("k-1", b"first").unwrap();
        // The same acknowledgement again is not a second entry.
        journal.put("k-1", b"first").unwrap();
        assert_eq!(journal.get("k-1").unwrap().unwrap(), b"first");
        // A different value under the same key is a collision, not an overwrite.
        assert!(matches!(
            journal.put("k-1", b"second"),
            Err(JournalError::Corrupt)
        ));
        assert_eq!(journal.get("k-1").unwrap().unwrap(), b"first");

        let _ = std::fs::remove_dir_all(&root);
    }
}
