//! Behaviour of the durable key lifecycle across separate invocations.
//!
//! Every test here is written as "a second foreground process", because that is
//! the only thing the feature has to be true for: a process that saved a key
//! has exited before the one that reloads it starts. Nothing is carried over in
//! memory, so a test that passes because it reused an in-process bundle would
//! prove nothing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::Cell;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use ksp_identity::{AdminKeyBundle, AdminSigningKey, BundleError, KeyId};
use ksp_key_lifecycle::file::verify_protected;
use ksp_key_lifecycle::{
    KeyError, KeyFailure, KeyFileHooks, KeyRoot, KeyStore, MAX_KEY_FILE_BYTES, NoFailures, Stage,
};
use ksp_types::AgentId;

/// Fails at a chosen stage, optionally skipping the first N occurrences.
struct FailAt {
    stage: Stage,
    skip: Cell<u32>,
}

impl FailAt {
    fn at(stage: Stage) -> Self {
        Self {
            stage,
            skip: Cell::new(0),
        }
    }

    fn after(stage: Stage, occurrences: u32) -> Self {
        Self {
            stage,
            skip: Cell::new(occurrences),
        }
    }
}

impl KeyFileHooks for FailAt {
    fn check(&self, stage: Stage) -> Result<(), KeyError> {
        if stage != self.stage {
            return Ok(());
        }
        if self.skip.get() > 0 {
            self.skip.set(self.skip.get() - 1);
            return Ok(());
        }
        Err(match stage {
            Stage::BeforeRead | Stage::AfterRead => KeyError::ReadFailed,
            _ => KeyError::WriteFailed,
        })
    }
}

/// One fixed principal UUID per test name.
///
/// A name is a test label here, not an identity: the value handed to the key
/// store is the UUID the enrolment would have issued.
fn agent_id(name: &str) -> AgentId {
    let uuid = match name {
        "agent-1" => "00000000-0000-4000-8000-0000000000a1",
        "agent-2" => "00000000-0000-4000-8000-0000000000a2",
        "agent-7" => "00000000-0000-4000-8000-000000000007",
        other => panic!("no fixture UUID for {other}"),
    };
    AgentId::parse(uuid).expect("the fixture is a canonical UUID")
}

fn key_id(name: &str) -> KeyId {
    KeyId::new(name)
}

fn store_at(root: &Path) -> KeyStore<NoFailures> {
    KeyStore::new(KeyRoot::open(root).expect("the key root opens"))
}

/// The pin a caller would build from a signed enrolment record.
///
/// The bundle is used here only because a test has no admin to sign for it; the
/// point of every assertion below is that the value is supplied *from outside*
/// the file being read.
fn pin_for(bundle: &ksp_identity::AgentKeyBundle) -> ksp_identity::AgentIdentityPin {
    ksp_identity::AgentIdentityPin {
        identity: *bundle.identity(),
        signing_key_id: bundle.signing_key_id().clone(),
        recipient_key_id: bundle.recipient_key_id().clone(),
        signing_key: bundle.signing_public(),
        recipient_key: bundle.recipient_public(),
        confirmed_fingerprint: *bundle.fingerprint(),
    }
}

/// A scratch key root.
///
/// `tempfile` inherits the process umask, which on a CI runner can leave the
/// directory group-writable; the store refuses that, so the test creates the
/// owner-only root a real caller would have (`~/.config/ksp`).
fn root() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod");
    dir
}

/// A bundle belonging to another key root, for the cases where the replacement
/// has to be a *different* identity than the one already stored.
fn bundle_for(
    identity: &str,
    signing: &str,
    recipient: &str,
) -> (ksp_identity::AgentKeyBundle, ksp_identity::AgentIdentityPin) {
    let scratch = root();
    let enrolled = store_at(scratch.path())
        .generate_agent(agent_id(identity), key_id(signing), key_id(recipient))
        .expect("generation succeeds");
    let pin = pin_for(&enrolled.bundle);
    (enrolled.bundle, pin)
}

// --- criterion 2: a second process reloads the same halves -----------------

#[test]
fn agent_keys_survive_a_separate_invocation() {
    let dir = root();
    let store = store_at(dir.path());
    let generated = store
        .generate_agent(
            agent_id("agent-7"),
            key_id("signing-1"),
            key_id("recipient-1"),
        )
        .expect("generation succeeds");

    let pin = pin_for(&generated.bundle);
    let expected_signing = generated.bundle.signing_public();
    let expected_recipient = generated.bundle.recipient_public();
    let expected_fingerprint = *generated.bundle.fingerprint();
    drop(store);
    drop(generated);

    // A second process: a new store, a new root handle, nothing cached.
    let reopened = store_at(dir.path());
    let reloaded = reopened.load_agent(&pin).expect("the identity reloads");

    assert_eq!(reloaded.identity(), &agent_id("agent-7"));
    assert_eq!(reloaded.signing_public(), expected_signing);
    assert_eq!(reloaded.recipient_public(), expected_recipient);
    assert_eq!(reloaded.fingerprint(), &expected_fingerprint);

    // The reloaded authority is usable: the private half still matches the
    // public half the pin names.
    let message = b"agent-7 proves possession";
    let signature = reloaded.signing_secret().sign_bytes(message);
    assert!(expected_signing.verify(message, &signature.to_bytes()));
}

#[test]
fn admin_signing_authority_survives_a_separate_invocation() {
    let dir = root();
    let store = store_at(dir.path());
    let admin = AdminSigningKey::generate();
    let pin = ksp_identity::AdminSigningPin {
        key_id: key_id("admin-2026"),
        signing_key: admin.verifying_public(),
    };
    let bundle = AdminKeyBundle::from_key(&admin, key_id("admin-2026"));
    store.save_admin_new(&bundle).expect("the admin key saves");
    drop(store);

    let reopened = store_at(dir.path());
    let reloaded = reopened
        .load_admin(&pin)
        .expect("the admin identity reloads");
    assert_eq!(reloaded.verifying_public(), pin.signing_key);

    // The reloaded private half still matches the pinned anchor: a record it
    // signs verifies against the public key the caller pinned, not against the
    // file's own claim about itself.
    let agent = ksp_identity::AgentKeys::generate();
    let unsigned = agent
        .enrol(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("the enrolment binds");
    let record = reloaded
        .sign_enrolment(unsigned, key_id("admin-2026"))
        .expect("the admin signs");
    assert!(record.verify_issuer(&pin.signing_key).is_ok());
}

#[test]
fn only_the_admin_signing_key_is_stored_for_an_admin_identity() {
    // FR-001: the admin holds a signing key that cannot decrypt anything. The
    // stored bundle has no recipient half to leak, and an agent file cannot
    // stand in for it.
    let dir = root();
    let store = store_at(dir.path());
    let admin = AdminSigningKey::generate();
    let bundle = AdminKeyBundle::from_key(&admin, key_id("admin-2026"));
    let path = store.save_admin_new(&bundle).expect("the admin key saves");

    let bytes = fs::read(&path).expect("the file is readable");
    let pin = ksp_identity::AdminSigningPin {
        key_id: key_id("admin-2026"),
        signing_key: admin.verifying_public(),
    };
    assert!(AdminKeyBundle::from_bytes(&bytes, &pin).is_ok());
    // An agent bundle is a different role and cannot be read as an admin one.
    let store2 = store_at(dir.path());
    let agent = store2
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let agent_bytes = fs::read(&agent.path).expect("the agent file is readable");
    assert_eq!(
        AdminKeyBundle::from_bytes(&agent_bytes, &pin).unwrap_err(),
        BundleError::Malformed
    );
}

// --- criterion 1: generation never replaces --------------------------------

#[test]
fn generation_refuses_to_replace_an_existing_identity() {
    let dir = root();
    let store = store_at(dir.path());
    let first = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("the first generation succeeds");
    let first_pin = pin_for(&first.bundle);
    let first_signing = first.bundle.signing_public();
    drop(first);

    let refused = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .unwrap_err();
    assert_eq!(refused, KeyError::AlreadyExists);
    assert_eq!(refused.failure(), KeyFailure::UnusableHost);

    // The refused generation must not have touched the stored identity.
    let reloaded = store.load_agent(&first_pin).expect("the first identity");
    assert_eq!(reloaded.signing_public(), first_signing);
}

#[test]
fn an_admin_key_also_refuses_to_replace_an_existing_identity() {
    let dir = root();
    let store = store_at(dir.path());
    let admin = AdminSigningKey::generate();
    let bundle = AdminKeyBundle::from_key(&admin, key_id("admin-2026"));
    store
        .save_admin_new(&bundle)
        .expect("the first save succeeds");
    assert_eq!(
        store.save_admin_new(&bundle).unwrap_err(),
        KeyError::AlreadyExists
    );
}

// --- criterion 3: the refusal cases ---------------------------------------

#[test]
fn a_missing_file_is_missing_key_material_and_never_regenerates() {
    let dir = root();
    let store = store_at(dir.path());
    let generated = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("the first generation succeeds");
    let pin = pin_for(&generated.bundle);
    let path = generated.path.clone();
    drop(generated);
    fs::remove_file(&path).expect("the file is removed");

    let error = store.load_agent(&pin).unwrap_err();
    assert_eq!(error, KeyError::Missing);
    assert!(error.failure().is_missing_key_material());
    // Nothing was generated in its place: the slot is free, and only an
    // explicit generation fills it again.
    assert!(!path.exists());
    let regenerated = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("an explicit generation is still allowed");
    assert_eq!(regenerated.path, path);
}

#[test]
fn a_symlinked_key_file_is_refused() {
    let dir = root();
    let store = store_at(dir.path());
    let generated = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let pin = pin_for(&generated.bundle);
    let path = generated.path.clone();
    drop(generated);

    let real = dir.path().join("moved.key");
    fs::rename(&path, &real).expect("the file moves");
    std::os::unix::fs::symlink(&real, &path).expect("the symlink is created");

    let error = store.load_agent(&pin).unwrap_err();
    assert_eq!(error, KeyError::Symlink);
    assert!(error.failure().is_missing_key_material());
}

#[test]
fn a_key_file_readable_by_others_is_refused() {
    let dir = root();
    let store = store_at(dir.path());
    let generated = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let pin = pin_for(&generated.bundle);
    let path = generated.path.clone();
    drop(generated);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
    assert_eq!(
        store.load_agent(&pin).unwrap_err(),
        KeyError::WrongMode { found: 0o644 }
    );

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod back");
    assert!(store.load_agent(&pin).is_ok());
}

#[test]
fn an_overlarge_key_file_is_refused_before_it_is_read() {
    let dir = root();
    let store = store_at(dir.path());
    let generated = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let pin = pin_for(&generated.bundle);
    let path = generated.path.clone();
    drop(generated);

    fs::write(&path, vec![0u8; (MAX_KEY_FILE_BYTES + 1) as usize]).expect("write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
    assert_eq!(
        store.load_agent(&pin).unwrap_err(),
        KeyError::TooLarge {
            limit: MAX_KEY_FILE_BYTES
        }
    );
}

#[test]
fn a_truncated_key_file_is_refused() {
    let dir = root();
    let store = store_at(dir.path());
    let generated = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let pin = pin_for(&generated.bundle);
    let path = generated.path.clone();
    drop(generated);

    let bytes = fs::read(&path).expect("read");
    fs::write(&path, &bytes[..bytes.len() / 2]).expect("write half");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");

    let error = store.load_agent(&pin).unwrap_err();
    assert!(
        matches!(error, KeyError::Bundle(_)),
        "a half-written bundle must not decode, got {error:?}"
    );
    assert!(error.failure().is_missing_key_material());
}

#[test]
fn a_directory_where_a_key_file_belongs_is_refused() {
    let dir = root();
    let store = store_at(dir.path());
    let generated = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let pin = pin_for(&generated.bundle);
    let path = generated.path.clone();
    drop(generated);

    fs::remove_file(&path).expect("remove");
    fs::create_dir(&path).expect("mkdir");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
    assert_eq!(
        store.load_agent(&pin).unwrap_err(),
        KeyError::NotRegularFile
    );
}

#[test]
fn an_identity_named_by_a_substituted_file_is_refused() {
    let dir = root();
    let store = store_at(dir.path());
    let mine = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let pin = pin_for(&mine.bundle);
    let path = mine.path.clone();
    drop(mine);

    let other_root = root();
    let other = store_at(other_root.path())
        .generate_agent(agent_id("agent-2"), key_id("s-2"), key_id("r-2"))
        .expect("generation succeeds");
    let foreign = fs::read(&other.path).expect("read");
    drop(other);

    fs::write(&path, &foreign).expect("substitute");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");

    let error = store.load_agent(&pin).unwrap_err();
    assert_eq!(
        error,
        KeyError::Bundle(BundleError::IdentityMismatch),
        "the file is not its own pin"
    );
    assert!(error.failure().is_missing_key_material());
}

#[test]
fn a_bundle_that_does_not_reproduce_the_pinned_fingerprint_is_refused() {
    let dir = root();
    let store = store_at(dir.path());
    let mine = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let mut pin = pin_for(&mine.bundle);
    drop(mine);

    let other_root = root();
    let other = store_at(other_root.path())
        .generate_agent(agent_id("agent-2"), key_id("s-2"), key_id("r-2"))
        .expect("generation succeeds");
    pin.confirmed_fingerprint = *other.bundle.fingerprint();
    drop(other);

    assert_eq!(
        store.load_agent(&pin).unwrap_err(),
        KeyError::Bundle(BundleError::FingerprintMismatch)
    );
}

#[test]
fn a_wrong_pinned_public_key_is_refused() {
    let dir = root();
    let store = store_at(dir.path());
    let mine = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let mut pin = pin_for(&mine.bundle);
    drop(mine);

    let other_root = root();
    let other = store_at(other_root.path())
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    pin.signing_key = other.bundle.signing_public();
    drop(other);

    let error = store.load_agent(&pin).unwrap_err();
    assert!(
        matches!(
            error,
            KeyError::Bundle(BundleError::PublicKeyMismatch)
                | KeyError::Bundle(BundleError::FingerprintMismatch)
        ),
        "a different pinned key must not authenticate the file, got {error:?}"
    );
}

#[test]
fn an_admin_file_is_not_accepted_as_an_agent_identity() {
    let dir = root();
    let store = store_at(dir.path());
    let generated = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let pin = pin_for(&generated.bundle);
    let path = generated.path.clone();
    drop(generated);

    let admin = AdminSigningKey::generate();
    let admin_bundle = AdminKeyBundle::from_key(&admin, key_id("admin-2026"));
    let admin_store = store_at(dir.path());
    let admin_path = admin_store
        .save_admin_new(&admin_bundle)
        .expect("the admin key saves");
    let admin_bytes = fs::read(&admin_path).expect("read");

    fs::write(&path, &admin_bytes).expect("substitute");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");

    assert_eq!(
        store.load_agent(&pin).unwrap_err(),
        KeyError::Bundle(BundleError::Malformed)
    );
}

#[test]
fn a_key_root_another_account_could_write_to_is_refused() {
    let dir = root();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("chmod");
    assert_eq!(
        KeyRoot::open(dir.path()).unwrap_err(),
        KeyError::RootUnavailable
    );

    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod back");
    assert!(KeyRoot::open(dir.path()).is_ok());
}

#[test]
fn a_symlinked_key_root_is_refused() {
    let dir = root();
    let real = dir.path().join("real");
    fs::create_dir(&real).expect("mkdir");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).expect("chmod");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    assert_eq!(KeyRoot::open(&link).unwrap_err(), KeyError::Symlink);
}

#[test]
fn identity_names_that_would_escape_the_key_root_are_refused() {
    let dir = root();
    let store = store_at(dir.path());

    // An agent identity is a canonical UUID, so none of these can even be
    // constructed as one. The refusal happens where the value is parsed, before
    // any caller can hand it to a path.
    for name in [
        "../escape",
        "..",
        ".",
        "nested/name",
        "back\\slash",
        ".hidden",
        "with space",
        "nul\0byte",
        "",
    ] {
        assert!(
            AgentId::parse(name).is_err(),
            "agent name {name:?} was accepted as an identity"
        );
    }

    // The admin key ID is still free-form text, so the path-segment check is
    // still the boundary that stops it becoming a path.
    let error = store.admin_path(&key_id("../admin")).unwrap_err();
    assert_eq!(error, KeyError::InvalidName);
}

#[test]
fn a_file_owned_by_another_account_is_refused() {
    // A suite cannot create a foreign-owned file without privileges, but the
    // comparison is the part that has to be right, so it is exercised against
    // real metadata with a deliberately wrong expected owner.
    let dir = root();
    let store = store_at(dir.path());
    let generated = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let path = generated.path.clone();
    drop(generated);

    let actual = fs::metadata(&path).expect("metadata").uid();
    assert!(verify_protected(&path, actual).is_ok());
    assert_eq!(
        verify_protected(&path, actual.wrapping_add(1)).unwrap_err(),
        KeyError::WrongOwner
    );
    assert!(KeyError::WrongOwner.failure().is_missing_key_material());
}

#[test]
fn the_metadata_check_a_reload_performs_refuses_every_substitution() {
    // The same function the reload runs on its descriptor, exercised directly
    // so a change that stops calling it is visible here.
    let dir = root();
    let store = store_at(dir.path());
    let generated = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let path = generated.path.clone();
    drop(generated);
    let owner = fs::metadata(&path).expect("metadata").uid();

    assert!(verify_protected(&path, owner).is_ok());

    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("chmod");
    assert_eq!(
        verify_protected(&path, owner).unwrap_err(),
        KeyError::WrongMode { found: 0o640 }
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");

    let link = dir.path().join("agent/link.key");
    std::os::unix::fs::symlink(&path, &link).expect("symlink");
    assert_eq!(
        verify_protected(&link, owner).unwrap_err(),
        KeyError::Symlink
    );
}

#[test]
fn a_rotation_refuses_to_archive_a_substituted_file() {
    // A local attacker who swaps the stored bundle must not get it preserved
    // under an archive name the caller will later treat as retained authority.
    let dir = root();
    let store = store_at(dir.path());
    let mine = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let pin = pin_for(&mine.bundle);
    let path = mine.path.clone();
    drop(mine);

    let (foreign, _) = bundle_for("agent-1", "s-9", "r-9");
    fs::write(&path, foreign.to_bytes().expect("encode")).expect("substitute");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");

    let (replacement, _) = bundle_for("agent-1", "s-2", "r-2");
    let error = store.rotate_agent(&pin, &replacement).unwrap_err();
    assert!(error.failure().is_missing_key_material(), "got {error:?}");
    assert!(!dir.path().join("agent/archive").exists());
}

// --- criterion 4: failure injection at every stage -------------------------

#[test]
fn a_failure_before_commit_preserves_the_previous_bundle() {
    let dir = root();
    let store = store_at(dir.path());
    let first = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let first_pin = pin_for(&first.bundle);
    let first_signing = first.bundle.signing_public();
    drop(first);

    let (second_bundle, _) = bundle_for("agent-1", "s-2", "r-2");

    // The first `BeforeCommit` belongs to the archived copy; the second is the
    // replacement of the live file, which is the one that must not happen.
    let failing = KeyStore::with_hooks(
        KeyRoot::open(dir.path()).expect("root"),
        FailAt::after(Stage::BeforeCommit, 1),
    );
    assert_eq!(
        failing
            .rotate_agent(&first_pin, &second_bundle)
            .unwrap_err(),
        KeyError::WriteFailed
    );

    // The previous identity is still the one that loads.
    let reloaded = store.load_agent(&first_pin).expect("the previous identity");
    assert_eq!(reloaded.signing_public(), first_signing);
}

#[test]
fn a_failure_after_commit_is_reported_as_uncertain_not_as_success() {
    let dir = root();
    let store = store_at(dir.path());
    let first = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let first_pin = pin_for(&first.bundle);
    drop(first);

    let (second_bundle, second_pin) = bundle_for("agent-1", "s-2", "r-2");

    // The archive was installed durably; the replacement was renamed into place
    // but its directory entry was never synced. That is exactly the case where
    // claiming success would be a lie.
    let failing = KeyStore::with_hooks(
        KeyRoot::open(dir.path()).expect("root"),
        FailAt::after(Stage::AfterCommit, 1),
    );
    assert_eq!(
        failing
            .rotate_agent(&first_pin, &second_bundle)
            .unwrap_err(),
        KeyError::CommitUncertain
    );
    assert_eq!(
        KeyError::CommitUncertain.failure(),
        KeyFailure::UnusableHost
    );

    // The bytes did reach the target, so the honest report is "uncertain": the
    // new identity is what a reload now finds.
    assert!(store.load_agent(&second_pin).is_ok());
}

#[test]
fn a_failure_while_reloading_is_refused() {
    let dir = root();
    let store = store_at(dir.path());
    let generated = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let pin = pin_for(&generated.bundle);
    drop(generated);

    for stage in [Stage::BeforeRead, Stage::AfterRead] {
        let failing =
            KeyStore::with_hooks(KeyRoot::open(dir.path()).expect("root"), FailAt::at(stage));
        let error = failing.load_agent(&pin).unwrap_err();
        assert!(error.failure().is_missing_key_material(), "at {stage:?}");
    }
}

#[test]
fn every_write_stage_can_fail_without_leaving_a_partial_identity() {
    for stage in [Stage::AfterWrite, Stage::AfterFileSync, Stage::BeforeCommit] {
        a_write_failure_never_publishes_a_partial_identity(stage);
    }
}

/// One stage of the write path, in its own key root.
///
/// The root is per stage because archiving the same old identity twice is
/// refused (an archive name is written once, never overwritten), so reusing a
/// root would make the second iteration fail for the wrong reason.
fn a_write_failure_never_publishes_a_partial_identity(stage: Stage) {
    let dir = root();
    let store = store_at(dir.path());
    let first = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let first_pin = pin_for(&first.bundle);
    let first_signing = first.bundle.signing_public();
    drop(first);

    let (replacement, _) = bundle_for("agent-1", "s-2", "r-2");
    let failing = KeyStore::with_hooks(
        KeyRoot::open(dir.path()).expect("root"),
        FailAt::after(stage, 1),
    );
    let error = failing.rotate_agent(&first_pin, &replacement).unwrap_err();
    assert_eq!(error, KeyError::WriteFailed, "at {stage:?}");

    // Whatever happened, the file that loads is a complete identity and no
    // half-written temporary file has been left in the key directory.
    assert_eq!(
        store
            .load_agent(&first_pin)
            .expect("a complete identity")
            .signing_public(),
        first_signing
    );
    assert_no_temp_files(&dir.path().join("agent"));
}

fn assert_no_temp_files(dir: &Path) {
    if !dir.exists() {
        return;
    }
    let leftovers: Vec<_> = fs::read_dir(dir)
        .expect("read_dir")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");
}

// --- criterion 5: rotation and the retained old bundle --------------------

#[test]
fn rotation_retains_the_old_bundle_and_installs_the_new_one() {
    let dir = root();
    let store = store_at(dir.path());
    let first = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let first_pin = pin_for(&first.bundle);
    let first_signing = first.bundle.signing_public();
    drop(first);

    let (second_bundle, second_pin) = bundle_for("agent-1", "s-2", "r-2");

    let rotation = store
        .rotate_agent(&first_pin, &second_bundle)
        .expect("rotation succeeds");

    // The new identity is what future minting uses.
    let current = store.load_agent(&second_pin).expect("the new identity");
    assert_eq!(current.signing_public(), second_pin.signing_key);

    // The old identity is retained, not revoked: an artifact sealed before the
    // rotation still opens with the archived bundle (SC-018).
    assert!(rotation.archived.exists());
    assert_ne!(rotation.archived, rotation.current);
    let archived_bytes = fs::read(&rotation.archived).expect("the archive is readable");
    assert_eq!(
        fs::metadata(&rotation.archived)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let restored = ksp_identity::AgentKeyBundle::from_bytes(&archived_bytes, &first_pin)
        .expect("the retained bundle still verifies against the old pin");
    assert_eq!(restored.signing_public(), first_signing);

    // The old pin no longer describes the live file, which is the whole point.
    assert!(store.load_agent(&first_pin).is_err());
}

#[test]
fn rotating_a_missing_identity_is_refused() {
    let dir = root();
    let store = store_at(dir.path());
    let first = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let first_pin = pin_for(&first.bundle);
    drop(first);

    let (replacement_bundle, _) = bundle_for("agent-1", "s-2", "r-2");

    // Generating the replacement refused nothing because it has a different
    // identity name; deleting the original leaves nothing to rotate against.
    let path = store.agent_path(&agent_id("agent-1")).expect("path");
    fs::remove_file(&path).expect("remove");

    assert_eq!(
        store
            .rotate_agent(&first_pin, &replacement_bundle)
            .unwrap_err(),
        KeyError::Missing
    );
}

#[test]
fn a_failed_rotation_can_be_retried() {
    // Issue 1: a pre-commit failure leaves the archive behind. If the retry
    // refuses that archive, one transient host fault blocks rotation forever.
    let dir = root();
    let store = store_at(dir.path());
    let first = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let first_pin = pin_for(&first.bundle);
    drop(first);

    let (replacement, replacement_pin) = bundle_for("agent-1", "s-2", "r-2");

    let failing = KeyStore::with_hooks(
        KeyRoot::open(dir.path()).expect("root"),
        FailAt::after(Stage::BeforeCommit, 1),
    );
    assert_eq!(
        failing.rotate_agent(&first_pin, &replacement).unwrap_err(),
        KeyError::WriteFailed
    );

    // The same rotation, second time, on a healthy host.
    let rotation = store
        .rotate_agent(&first_pin, &replacement)
        .expect("the retry succeeds");
    assert!(rotation.archived.exists());
    assert!(store.load_agent(&replacement_pin).is_ok());
}

#[test]
fn an_archive_holding_different_bytes_is_still_a_conflict() {
    let dir = root();
    let store = store_at(dir.path());
    let first = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let first_pin = pin_for(&first.bundle);
    drop(first);

    let (replacement, _) = bundle_for("agent-1", "s-2", "r-2");
    let failing = KeyStore::with_hooks(
        KeyRoot::open(dir.path()).expect("root"),
        FailAt::after(Stage::BeforeCommit, 1),
    );
    failing.rotate_agent(&first_pin, &replacement).unwrap_err();

    // Corruption of the retained copy must not be papered over: the archive is
    // the only thing that keeps old artifacts open.
    let archive = dir.path().join("agent/archive").join(format!(
        "{}-{}.key",
        agent_id("agent-1"),
        first_pin.confirmed_fingerprint.to_hex()
    ));
    let mut bytes = fs::read(&archive).expect("read");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(&archive, &bytes).expect("write");
    fs::set_permissions(&archive, fs::Permissions::from_mode(0o600)).expect("chmod");

    assert_eq!(
        store.rotate_agent(&first_pin, &replacement).unwrap_err(),
        KeyError::AlreadyExists
    );
    // The differing archive was not overwritten with the good copy: a conflict
    // is reported, never resolved by discarding what is already there.
    assert_eq!(fs::read(&archive).expect("read"), bytes);
}

#[test]
fn a_read_only_key_root_can_still_be_reloaded() {
    // Issue 2: reading a key must not require the permission to create one.
    let dir = root();
    let store = store_at(dir.path());
    let generated = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let pin = pin_for(&generated.bundle);
    let expected = generated.bundle.signing_public();
    drop(generated);

    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).expect("chmod");
    let loaded = store.load_agent(&pin).expect("the identity reloads");
    assert_eq!(loaded.signing_public(), expected);
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod back");
}

#[test]
fn an_absent_role_directory_is_missing_key_material_not_a_host_fault() {
    // The reload path validates the role directory instead of creating it, so
    // an absent directory means "no key stored" rather than "the host refused
    // to create a directory". A read must also not have the side effect of
    // creating state it then reports as missing.
    let dir = root();
    let store = store_at(dir.path());
    let generated = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let pin = pin_for(&generated.bundle);
    drop(generated);

    fs::remove_dir_all(dir.path().join("agent")).expect("remove the role directory");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).expect("chmod");

    let error = store.load_agent(&pin).unwrap_err();
    assert_eq!(error, KeyError::Missing);
    assert!(error.failure().is_missing_key_material());
    assert!(!dir.path().join("agent").exists(), "the read created state");

    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod back");
}

#[test]
fn a_rotation_cannot_install_a_different_identity_name() {
    let dir = root();
    let store = store_at(dir.path());
    let first = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let first_pin = pin_for(&first.bundle);
    drop(first);

    let (foreign_bundle, _) = bundle_for("agent-2", "s-2", "r-2");

    assert_eq!(
        store.rotate_agent(&first_pin, &foreign_bundle).unwrap_err(),
        KeyError::IdentityMismatch
    );
}

// --- diagnostics -----------------------------------------------------------

#[test]
fn no_error_message_carries_key_material() {
    let dir = root();
    let store = store_at(dir.path());
    let generated = store
        .generate_agent(agent_id("agent-1"), key_id("s-1"), key_id("r-1"))
        .expect("generation succeeds");
    let path = generated.path.clone();
    let pin = pin_for(&generated.bundle);
    drop(generated);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
    let rendered = store.load_agent(&pin).unwrap_err().to_string();

    // The mode is safe to print; a key byte would not be.
    assert!(rendered.contains("0644"), "unexpected message: {rendered}");
    assert!(
        !rendered.contains(
            &pin.signing_key.to_bytes()[..4]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    );
    assert!(
        rendered.len() < 200,
        "the message is suspiciously long: {rendered}"
    );
}
