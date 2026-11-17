//! The policy lifecycle: the ledger entry before the write, and the order of a withdrawal.
//!
//! # What these tests are for
//!
//! `policy_edges.rs` pins what a policy *says*; this suite pins what happens *around*
//! it. Two facts are not visible in an artifact and are the whole point of the work
//! package:
//!
//! - the ledger entry exists **before** anything is written, so an unwritable ledger
//!   leaves no artifact and no publication;
//! - a withdrawal is ledger, artifact, release — in that order, retryable, and
//!   idempotent on the decision rather than on the clock.
//!
//! A test reports a failure by panicking, and the panic message is what says why.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use ksp::edges::EdgeStore;
use ksp::keys::Anchor;
use ksp::ledgers::LedgerPaths;
use ksp::lifecycle::Withdrawal;
use ksp::publication::PublicationPath;
use ksp::registry::{PrincipalRegistry, RegistryRole};
use ksp_identity::policy_edge::{EdgeRequest, PolicyEdge, PolicyTarget};
use ksp_identity::{AdminSigningKey, IssuanceLedger, KeyId};
use ksp_types::{AgentId, OpaqueSecretId, PrincipalId, RecordVersion};
use support::{Deployment, admin_and_two_users};

const NOT_BEFORE: u64 = 1_000;
const NOT_AFTER: u64 = 2_000;

fn first_user(fixture: &Deployment) -> PrincipalId {
    let layout = fixture.layout(&fixture.admin_home);
    let registry = PrincipalRegistry::load(&layout).expect("the registry reads");
    registry
        .entries
        .iter()
        .find(|entry| entry.role == RegistryRole::User)
        .expect("a user is enrolled")
        .principal
}

fn request(user: PrincipalId, version: u32, target: PolicyTarget) -> EdgeRequest {
    EdgeRequest {
        user,
        secret: OpaqueSecretId::new("s1"),
        record_version: RecordVersion(version),
        target,
        publication: None,
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
    }
}

fn store_version(fixture: &Deployment, user: PrincipalId, version: u32) {
    use ksp_record::version::BlobStore;
    use ksp_types::{BoundMetadata, Level, VaultId};

    let store = ksp_backend::file::FileStore::new(fixture.store.clone()).expect("the store opens");
    let metadata = BoundMetadata {
        vault_id: VaultId::new("vault-1"),
        user_id: user,
        level: Level::User,
        secret_id: OpaqueSecretId::new("s1"),
        version,
    };
    let path = ksp_record::RecordPath::of(&metadata).as_str().to_string();
    store
        .put_if_absent(&path, b"ciphertext")
        .expect("the record is written");
}

fn admin_key(fixture: &Deployment) -> (AdminSigningKey, KeyId) {
    let layout = fixture.layout(&fixture.admin_home);
    let anchor = Anchor::load(&layout.admin_anchor_file()).expect("the anchor reads");
    let key_id = anchor.key_id.clone();
    let admin = ksp::admin::load_admin(&layout, &anchor).expect("the admin key reads");
    (admin, key_id)
}

fn agent(fixture: &Deployment) -> AgentId {
    AgentId::parse(&fixture.agent).expect("the fixture printed a canonical agent id")
}

/// A ledger whose decisions land in this suite's own directory.
fn writable_ledger(fixture: &Deployment) -> (IssuanceLedger, PathBuf) {
    let dir = fixture.root.path().join("ledgers");
    std::fs::create_dir_all(&dir).expect("the ledger directory is created");
    (
        IssuanceLedger::with_paths(dir.join("issuance.jsonl"), dir.join("policy-events.jsonl")),
        dir,
    )
}

/// A ledger whose admin file lives in a directory nothing may write to.
///
/// The issuance file stays writable: the refusal has to come from the *decision*
/// file, not from a ledger that cannot record anything at all.
fn unwritable_ledger(fixture: &Deployment) -> (IssuanceLedger, PathBuf) {
    let open = fixture.root.path().join("ledgers");
    let sealed = fixture.root.path().join("sealed-ledger");
    std::fs::create_dir_all(&open).expect("the ledger directory is created");
    std::fs::create_dir_all(&sealed).expect("the sealed directory is created");
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o555))
        .expect("the sealed directory takes a read-only mode");
    (
        IssuanceLedger::with_paths(
            open.join("issuance.jsonl"),
            sealed.join("policy-events.jsonl"),
        ),
        sealed,
    )
}

fn store<'a>(
    layout: &'a ksp::config::Layout,
    deployment: &ksp::deployment::Deployment,
) -> EdgeStore<'a> {
    EdgeStore::new(layout, deployment)
}

#[test]
fn a_create_with_an_unwritable_ledger_writes_no_artifact() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let store = store(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);
    let (ledger, sealed) = unwritable_ledger(&fixture);

    let refused = store
        .create(
            &admin,
            key_id,
            request(user, 1, PolicyTarget::Agent(agent(&fixture))),
            &ledger,
        )
        .expect_err("an unwritable ledger refuses the decision");

    // The refusal names the ledger, not the policy: the policy is fine.
    let message = refused.to_string();
    assert!(
        message.contains("policy ledger") && message.contains("policy-events.jsonl"),
        "the refusal names the ledger: {message}"
    );
    assert!(
        !message.contains("not later than the recorded revision"),
        "the refusal is about the ledger, not the revision: {message}"
    );

    // Nothing was written. The assertion names `policies/` rather than "any `.cbor`":
    // enrolment leaves an agent artifact and the registry under the same vault, so a
    // broader question would fail on files this test never touched — and an
    // `ends_with(".cbor")` form is worse still, because `Path::ends_with` compares whole
    // components and is therefore false for every artifact that exists.
    let listed: Vec<_> = walk(&layout.store_root().join("p/vault-1"));
    let policies: Vec<_> = listed
        .iter()
        .filter(|path| path.to_string_lossy().contains("/policies/"))
        .collect();
    assert!(
        policies.is_empty(),
        "no policy artifact exists after a refused decision: {policies:?}"
    );
    assert!(
        ledger.policy_entries().is_err() || ledger.policy_entries().unwrap().is_empty(),
        "no decision was recorded"
    );

    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o755)).ok();
}

/// Every file under `root`, so a listing cannot hide a write in a subdirectory.
fn walk(root: &std::path::Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else {
            found.push(path);
        }
    }
    found
}

#[test]
fn the_same_decision_recorded_twice_is_one_line() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let edge_store = store(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);
    let (ledger, _dir) = writable_ledger(&fixture);

    let edge = edge_store
        .create(
            &admin,
            key_id,
            request(user, 1, PolicyTarget::Agent(agent(&fixture))),
            &ledger,
        )
        .expect("the edge is admitted");
    let recorded = ledger.policy_entries().expect("the ledger reads");
    assert_eq!(recorded.len(), 1, "the create recorded one decision");

    // A retry carries a later timestamp; the decision is the same one.
    let retried = ksp_identity::policy_edge::PolicyLedgerEntry::for_edge(
        &edge,
        ksp_identity::policy_edge::PolicyAction::Created,
        deployment.admin,
        recorded[0].at + 60,
    )
    .expect("the entry is built from the signed edge");
    let returned = ledger.record_policy(&retried).expect("the retry lands");
    assert_eq!(
        returned.at, recorded[0].at,
        "the recorded entry is returned"
    );
    assert_eq!(
        ledger.policy_entries().expect("the ledger reads").len(),
        1,
        "a retry is not a second line"
    );
}

#[test]
fn an_update_that_regresses_is_refused_with_the_recorded_revision() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let edge_store = store(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);
    let (ledger, _dir) = writable_ledger(&fixture);

    let edge = edge_store
        .create(
            &admin,
            key_id.clone(),
            request(user, 1, PolicyTarget::Agent(agent(&fixture))),
            &ledger,
        )
        .expect("the edge is admitted");
    let updated = edge_store
        .update(
            &admin,
            key_id.clone(),
            edge.id(),
            request(user, 1, PolicyTarget::AnyEnrolled),
            &ledger,
        )
        .expect("revision 2 is admitted");
    assert_eq!(updated.revision(), 2);

    // Put the ledger ahead of the artifact, which is the state a crash between the
    // append and the publish leaves. The next write must not go backwards.
    let ahead = ksp_identity::policy_edge::PolicyLedgerEntry::for_edge(
        &updated,
        ksp_identity::policy_edge::PolicyAction::Updated,
        deployment.admin,
        updated.revision() as i64,
    )
    .expect("the entry is built");
    let mut ahead = ahead;
    ahead.revision = 5;
    ahead.digest = [7u8; 32];
    ledger
        .record_policy(&ahead)
        .expect("the ahead revision records");

    let refused = edge_store
        .update(
            &admin,
            key_id,
            edge.id(),
            request(user, 1, PolicyTarget::Agent(agent(&fixture))),
            &ledger,
        )
        .expect_err("a regression is refused");
    let message = refused.to_string();
    assert!(
        message.contains("not later than the recorded revision 5"),
        "the refusal names the recorded revision: {message}"
    );

    // The artifact still says revision 2: a refused write changed nothing.
    let on_disk = edge_store.load(edge.id()).expect("the artifact reads");
    assert_eq!(on_disk.revision(), 2, "the refused write left the artifact");
}

#[test]
fn a_withdrawal_that_cannot_append_removes_nothing() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let edge_store = store(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);
    let (ledger, _dir) = writable_ledger(&fixture);

    let edge = edge_store
        .create(
            &admin,
            key_id,
            request(user, 1, PolicyTarget::Agent(agent(&fixture))),
            &ledger,
        )
        .expect("the edge is admitted");
    let artifact = edge_store.path(edge.id());
    assert!(
        artifact.is_file(),
        "the artifact exists before the withdrawal"
    );

    // Swap in a ledger that cannot record the decision.
    let (sealed_ledger, sealed) = unwritable_ledger(&fixture);
    let refusal = Withdrawal::new(&layout, &edge_store, &sealed_ledger)
        .complete(&edge, deployment.admin, 1_500)
        .expect_err("the withdrawal cannot record");
    assert!(
        refusal.to_string().contains("policy-events.jsonl"),
        "the refusal names the ledger: {refusal}"
    );
    assert!(
        artifact.is_file(),
        "the artifact survives a withdrawal whose decision was not recorded"
    );
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o755)).ok();
}

#[test]
fn a_withdrawal_retry_completes_without_a_duplicate_entry() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let edge_store = store(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);
    let (ledger, _dir) = writable_ledger(&fixture);

    let edge = edge_store
        .create(
            &admin,
            key_id,
            request(user, 1, PolicyTarget::Agent(agent(&fixture))),
            &ledger,
        )
        .expect("the edge is admitted");

    // The crash: the decision is recorded, then the run stops before the artifact goes.
    let withdrawal = Withdrawal::new(&layout, &edge_store, &ledger);
    let first = withdrawal
        .record(&edge, deployment.admin, 1_500)
        .expect("the decision records");
    assert_eq!(
        ledger.policy_entries().expect("the ledger reads").len(),
        2,
        "one create and one withdrawal"
    );

    // The retry completes: it removes the artifact and releases what the decision named,
    // without a second entry for a decision already in force.
    let second = withdrawal
        .complete(&edge, deployment.admin, 1_600)
        .expect("the retry completes");
    assert!(second.artifact_removed, "the retry removed the artifact");
    assert_eq!(
        second.entry.at, first.at,
        "the recorded decision is returned"
    );
    assert_eq!(
        ledger.policy_entries().expect("the ledger reads").len(),
        2,
        "the retry did not append a second withdrawal"
    );
    assert!(
        !edge_store.path(edge.id()).exists(),
        "the artifact is gone once the retry completes"
    );
}

#[test]
fn a_withdrawal_of_an_absent_artifact_reports_the_recorded_decision() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let edge_store = store(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);
    let (ledger, _dir) = writable_ledger(&fixture);

    let edge = edge_store
        .create(
            &admin,
            key_id,
            request(user, 1, PolicyTarget::Agent(agent(&fixture))),
            &ledger,
        )
        .expect("the edge is admitted");
    std::fs::remove_file(edge_store.path(edge.id())).expect("the artifact is removed by hand");

    let outcome = Withdrawal::new(&layout, &edge_store, &ledger)
        .complete(&edge, deployment.admin, 1_500)
        .expect("a withdrawal of a gone artifact still records and reports");
    assert!(
        !outcome.artifact_removed,
        "the artifact was already gone, and the outcome says so"
    );
    assert!(
        outcome.survivors.is_empty(),
        "a policy that names no publication leaves no survivor"
    );
    assert_eq!(
        outcome.entry.action,
        ksp_identity::policy_edge::PolicyAction::Withdrawn
    );
}

/// The three actions are three strings, and a report that printed one of the others
/// would describe a different decision.
#[test]
fn the_actions_are_named_once() {
    use ksp_identity::policy_edge::PolicyAction;
    assert_eq!(PolicyAction::Created.as_str(), "created");
    assert_eq!(PolicyAction::Updated.as_str(), "updated");
    assert_eq!(PolicyAction::Withdrawn.as_str(), "withdrawn");
}

/// An edge is only ever recorded through a signed artifact: the entry built from a
/// loaded edge names the same digest the ledger holds.
#[test]
fn the_entry_names_the_digest_of_the_signed_bytes() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let edge_store = store(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);
    let (ledger, _dir) = writable_ledger(&fixture);

    let edge: PolicyEdge = edge_store
        .create(
            &admin,
            key_id,
            request(user, 1, PolicyTarget::Agent(agent(&fixture))),
            &ledger,
        )
        .expect("the edge is admitted");
    let recorded = ledger.policy_entries().expect("the ledger reads");
    assert_eq!(
        recorded[0].digest,
        edge.digest().expect("the edge digests"),
        "the ledger holds the digest of the signed bytes"
    );
    assert_eq!(recorded[0].revision, edge.revision());
    assert_eq!(recorded[0].actor, deployment.admin);
}

/// Both ledgers live under the principal that writes each one, in the store.
///
/// The cross-account half of T001 — the user writes and the admin reads but cannot
/// write — needs two UNIX accounts and belongs to a `principals`-class suite; what this
/// asserts is the pair of facts such a suite depends on: the two files are in different
/// principals' directories, and each is `0640` in the store's group with a `0711` parent
/// rather than the caller's `umask`.
#[test]
fn both_ledgers_live_under_the_principals_that_write_them() {
    use std::os::unix::fs::MetadataExt;

    let fixture = admin_and_two_users();
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let paths = LedgerPaths::for_deployment(&layout, &deployment);

    assert_eq!(
        paths.issuance(),
        layout
            .store_root()
            .join("p")
            .join(deployment.vault.as_str())
            .join(deployment.user.to_string())
            .join("issuance.jsonl"),
        "the issuance ledger is under the user who appends to it"
    );
    assert_eq!(
        paths.policy_events(),
        layout
            .store_root()
            .join("p")
            .join(deployment.vault.as_str())
            .join(deployment.admin.to_string())
            .join("policy-events.jsonl"),
        "the admin's file is under the admin who appends to it"
    );
    assert_ne!(
        paths.issuance().parent(),
        paths.policy_events().parent(),
        "one writer per file means one directory each"
    );

    // Discovery agrees with the record. It has to: `run` resolves through the registry
    // and every other command through the record, and two answers would be two ledgers.
    assert_eq!(
        LedgerPaths::discover(
            &layout,
            &deployment.vault,
            deployment.user,
            &Anchor::load(&layout.admin_anchor_file()).expect("the anchor reads"),
        )
        .expect("the registry reads"),
        paths
    );

    let me = ksp_posture::permissions::effective_uid();
    let store_gid = std::fs::metadata(layout.store_root())
        .expect("the store root")
        .gid();
    paths
        .prepare(
            &layout,
            &deployment.vault,
            deployment.user,
            (me, store_gid),
            deployment.admin,
            (me, store_gid),
        )
        .expect("both ledgers are created");

    for path in [paths.issuance(), paths.policy_events()] {
        let metadata = std::fs::metadata(path).expect("the ledger exists");
        assert_eq!(
            metadata.mode() & 0o777,
            0o640,
            "{} is 0640, not the caller's umask",
            path.display()
        );
        assert_eq!(
            metadata.gid(),
            store_gid,
            "the file is in the store's group"
        );
        let parent = path
            .parent()
            .expect("a parent")
            .metadata()
            .expect("the parent");
        assert_eq!(
            parent.mode() & 0o777,
            0o711,
            "{} is 0711: the sibling traverses and does not list",
            path.parent().unwrap().display()
        );
    }
}

/// A publication with two entries: one per policy, one shared blob.
///
/// Built directly rather than through `publication::publish`, because publishing needs
/// the admin's own vault password and this test is about the *release* order, not about
/// sealing. The two entries and the blob are real; only the source of the plaintext is
/// short-circuited.
fn shared_publication(
    layout: &ksp::config::Layout,
    path: &PublicationPath,
    policies: &[&str],
) -> ksp::publication::Publication {
    use ksp_record::blob::ContentBlob;
    use ksp_record::envelope::RecordEnvelope;
    use ksp_record::kem;

    /// A derived, valid X25519 public key: never random bytes that may be low order.
    fn public_key(seed: u8) -> [u8; 32] {
        let derived = kem::public_key_for(&[seed; 32]).expect("a valid secret key");
        let mut key = [0u8; 32];
        key.copy_from_slice(&derived);
        key
    }

    let metadata = path.metadata();
    let aad = metadata.bound_aad().expect("the metadata binds");
    let content_key = ksp_types::ContentKey::generate();
    let blob = ContentBlob::seal(&content_key, b"KSP_TEST_SECRET", b"correct-horse", &aad)
        .expect("the blob seals");
    let admin_seal =
        RecordEnvelope::seal(&content_key, &public_key(7), &metadata).expect("the admin seal");
    let mut publication = ksp::publication::Publication::new(metadata, blob, admin_seal);

    for (seed, policy) in [11u8, 12].into_iter().zip(policies) {
        let envelope = RecordEnvelope::seal(&content_key, &public_key(seed), &path.metadata())
            .expect("the entry seals");
        assert!(publication.add_entry(policy, false, envelope));
    }
    ksp::publication::write(layout, path, &publication).expect("the publication is written");
    publication
}

/// Withdrawing one of two policies that share a publication keeps the other working.
///
/// The release step must remove **one reference**, not the artifact: the other agent's
/// entry still points at the same blob, and deleting it would break a grant nobody
/// withdrew. This is the acceptance criterion the withdrawal order exists for.
#[test]
fn withdrawing_one_of_two_policies_sharing_a_publication_keeps_the_other() {
    use ksp::publication::{PublicationPath, load};
    use ksp_types::{OpaqueSecretId, RecordVersion};

    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let edge_store = store(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);
    let (ledger, _dir) = writable_ledger(&fixture);

    let path = PublicationPath::derive(
        deployment.vault.clone(),
        deployment.admin,
        OpaqueSecretId::new("s1"),
        RecordVersion(1),
    );
    // Two edges, two targets, one publication: the tuple differs by target, so both are
    // admitted, and both name the same derived path.
    let withdrawn = edge_store
        .create(
            &admin,
            key_id.clone(),
            EdgeRequest {
                publication: Some(path.canonical()),
                ..request(user, 1, PolicyTarget::Agent(agent(&fixture)))
            },
            &ledger,
        )
        .expect("the first edge is admitted");
    let survivor = edge_store
        .create(
            &admin,
            key_id,
            EdgeRequest {
                publication: Some(path.canonical()),
                ..request(user, 1, PolicyTarget::AnyEnrolled)
            },
            &ledger,
        )
        .expect("the second edge is admitted");

    // The entries are keyed by the real policy ids: a publication keyed by anything
    // else is an entry no agent's token will ever find, and a release would then remove
    // nothing and report the wrong survivors.
    let _publication = shared_publication(
        &layout,
        &path,
        &[withdrawn.id().as_str(), survivor.id().as_str()],
    );

    let outcome = Withdrawal::new(&layout, &edge_store, &ledger)
        .complete(&withdrawn, deployment.admin, 1_500)
        .expect("the withdrawal completes");

    assert_eq!(
        outcome.survivors,
        vec![survivor.id().to_string()],
        "the surviving policy still references the publication"
    );
    assert!(
        !edge_store.path(withdrawn.id()).exists(),
        "the withdrawn policy's artifact is gone"
    );
    assert!(
        edge_store.path(survivor.id()).is_file(),
        "the surviving policy's artifact is untouched"
    );

    let publication = load(&layout, &path).expect("the publication is still there");
    assert!(
        publication.holds(survivor.id().as_str()),
        "the surviving agent can still open the blob"
    );
    assert!(
        !publication.holds(withdrawn.id().as_str()),
        "the withdrawn policy's entry is gone"
    );
}

/// A registry a principal planted must not decide where the admin's ledger is.
///
/// A `principals.cbor` is an ordinary file in a directory one principal owns, so reading
/// the first one found lets her name an admin of her choosing — and `run` would then read
/// a ledger nobody wrote and report a withdrawn token as live. Each case below is one way
/// of placing that file where it does not belong.
#[test]
fn a_planted_registry_does_not_decide_where_the_admin_ledger_is() {
    let fixture = admin_and_two_users();
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let anchor = Anchor::load(&layout.admin_anchor_file()).expect("the anchor reads");

    // The real registry is accepted, so the refusals below are about the forgeries and
    // not about discovery refusing everything.
    assert!(
        LedgerPaths::discover(&layout, &deployment.vault, deployment.user, &anchor).is_ok(),
        "the deployment's own registry is accepted"
    );

    // A copy in another principal's directory. It names the real admin, so only the
    // location distinguishes it — and the location is the thing a principal controls.
    //
    // It is placed under its **own** vault directory so it is the only registry the scan
    // can find: `read_dir` order is a filesystem fact, and a test that depended on which
    // of two registries came first would pass or fail by luck.
    let forged_vault = ksp_types::VaultId::new("vault-forged");
    let real = layout
        .store_root()
        .join("p")
        .join(deployment.vault.as_str())
        .join(deployment.admin.to_string())
        .join("principals.cbor");
    let planted_dir = layout
        .store_root()
        .join("p")
        .join(forged_vault.as_str())
        .join(deployment.user.to_string());
    std::fs::create_dir_all(&planted_dir).expect("the forged vault directory exists");
    std::fs::copy(&real, planted_dir.join("principals.cbor"))
        .expect("the registry is copied into the user's directory");

    let refusal = LedgerPaths::discover(&layout, &forged_vault, deployment.user, &anchor)
        .expect_err("a registry outside the admin's directory is refused");
    assert!(
        matches!(refusal, ksp::ledgers::LedgerPathsError::Planted { .. }),
        "the refusal names the location, not the content: {refusal}"
    );
    assert!(
        refusal
            .to_string()
            .contains("p/<vault>/<admin>/principals.cbor"),
        "the refusal names the accepted shape: {refusal}"
    );
    std::fs::remove_dir_all(layout.store_root().join("p").join(forged_vault.as_str())).ok();

    // The caller's own principal named as admin. Even from the right place this collapses
    // the two writers into one, so there is no separate admin ledger to read.
    assert!(
        LedgerPaths::discover(&layout, &deployment.vault, deployment.admin, &anchor).is_err(),
        "a user who is her own admin cannot be used to locate the admin's ledger"
    );
}

/// A staging write that fails records nothing.
///
/// The transaction is stage, record, commit. This pins the first seam: when the staging
/// write itself fails, the ledger is untouched and the partial file the failed write
/// created is removed, so the decision and the tree cannot disagree. A process that dies
/// *between* the two steps is a different state: it leaves the invisible staging file,
/// and `EdgeStore::stage` says so rather than this test implying otherwise. The second
/// seam — a **commit** failure, which happens after
/// the append — keeps the staged bytes and names their path in `RecordedNotPublished`;
/// it cannot be reached black-box here, because `rename` is the only step left and no
/// filesystem operation available to a single-account test makes that one call fail
/// without also failing `load`, which runs first. That limitation is recorded in the
/// work package, not hidden.
#[test]
fn a_staging_failure_records_nothing_and_a_finished_create_leaves_no_staging_file() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let edge_store = store(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);
    let (ledger, _dir) = writable_ledger(&fixture);

    let edge = edge_store
        .create(
            &admin,
            key_id.clone(),
            request(user, 1, PolicyTarget::Agent(agent(&fixture))),
            &ledger,
        )
        .expect("the edge is admitted");
    assert!(
        !edge_store
            .dir()
            .join(format!(".{}.tmp", edge.id()))
            .exists(),
        "a completed create leaves no staging file"
    );

    // A directory at the staging path makes the write fail, and it happens before the
    // append. `request` differs by target, so the candidate is a new revision.
    let staged = edge_store.dir().join(format!(".{}.tmp", edge.id()));
    std::fs::create_dir(&staged).expect("the staging path is occupied");

    let refused = edge_store
        .update(
            &admin,
            key_id,
            edge.id(),
            request(user, 1, PolicyTarget::AnyEnrolled),
            &ledger,
        )
        .expect_err("the artifact cannot be staged");
    assert!(
        !refused.to_string().contains("was recorded"),
        "a staging failure is not a recorded decision: {refused}"
    );

    assert_eq!(
        ledger.policy_entries().expect("the ledger reads").len(),
        1,
        "the ledger holds the create and nothing else"
    );
    assert_eq!(
        edge_store
            .load(edge.id())
            .expect("the artifact reads")
            .revision(),
        1,
        "the artifact did not move"
    );

    std::fs::remove_dir(&staged).ok();
}
