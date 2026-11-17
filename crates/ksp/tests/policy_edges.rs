//! The policy edge as a deployment artifact: where it lives, who signs it, and
//! what it refuses to exist without.
//!
//! # What this covers
//!
//! The model's invariants are in `crates/ksp-identity/tests/policy_edge.rs`. This
//! suite is about the **store**: one artifact per edge under the admin principal, a
//! readable mode, uniqueness over the set of active edges, and the links that have
//! to resolve before a signature exists at all.
//!
//! # Why the fixture is the shared one
//!
//! An edge names a user and an agent, so the deployment has to hold both. The WP01
//! fixture builds an admin, two users and an enrolled agent over one store, which
//! is exactly the shape an edge needs; building it again here would be a second
//! statement of the topology.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use ksp::edges::EdgeStore;
use ksp::keys::Anchor;
use ksp::registry::PrincipalRegistry;
use ksp_identity::policy_edge::{EdgeRefusal, EdgeRequest, PolicyTarget};
use ksp_identity::{AdminSigningKey, KeyId};
use ksp_types::{AgentId, Level, OpaqueSecretId, PrincipalId, RecordVersion, VaultId};
use support::{Deployment, admin_and_two_users};

const NOT_BEFORE: u64 = 1_000;
const NOT_AFTER: u64 = 2_000;

/// A ledger beside the home for this suite's policy decisions.
///
/// Every `create`/`update` takes one because a publish without a ledger is the
/// defect the lifecycle work package removes: the file that witnesses the change is
/// required by the call, not remembered by the caller.
fn edge_ledger(fixture: &Deployment) -> ksp_identity::IssuanceLedger {
    let layout = fixture.layout(&fixture.admin_home);
    ksp_identity::IssuanceLedger::at(layout.issuance_ledger())
}

/// The user the edges in this suite name: the first enrolled one.
fn first_user(fixture: &Deployment) -> PrincipalId {
    let layout = fixture.layout(&fixture.admin_home);
    let registry = PrincipalRegistry::load(&layout).expect("the registry reads");
    registry
        .entries
        .iter()
        .find(|entry| entry.role == ksp::registry::RegistryRole::User)
        .expect("a user is enrolled")
        .principal
}

/// A request for one secret version and target.
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

/// Put a `user`-level record so the secret-version link resolves.
fn store_version(fixture: &Deployment, user: PrincipalId, version: u32) {
    use ksp_record::version::BlobStore;
    use ksp_types::BoundMetadata;

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

/// The admin key and its id, as a real deployment pins them.
fn admin_key(fixture: &Deployment) -> (AdminSigningKey, KeyId) {
    let layout = fixture.layout(&fixture.admin_home);
    let anchor = Anchor::load(&layout.admin_anchor_file()).expect("the anchor reads");
    let key_id = anchor.key_id.clone();
    let admin = ksp::admin::load_admin(&layout, &anchor).expect("the admin key reads");
    (admin, key_id)
}

/// The agent the fixture enrolled.
fn agent(fixture: &Deployment) -> AgentId {
    AgentId::parse(&fixture.agent).expect("the fixture printed a canonical agent id")
}

#[test]
fn creating_an_edge_writes_one_readable_artifact_under_the_admin_principal() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let store = EdgeStore::new(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);

    let edge = store
        .create(
            &admin,
            key_id.clone(),
            request(user, 1, PolicyTarget::Agent(agent(&fixture))),
            &edge_ledger(&fixture),
        )
        .expect("the edge is admitted");

    let path = store.path(edge.id());
    assert!(path.is_file(), "the artifact is at {}", path.display());
    assert!(
        path.to_str()
            .unwrap()
            .contains(&format!("/p/vault-1/{}/policies/", deployment.admin)),
        "it lives under the admin principal: {}",
        path.display()
    );
    assert_eq!(edge.revision(), 1);
    assert!(
        edge.verify_issuer(&anchor_key(&fixture)),
        "the admin's pinned key verifies it"
    );

    use std::os::unix::fs::PermissionsExt;
    let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o644, "the artifact is public material");
    let dir_mode = std::fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        dir_mode, 0o755,
        "a read surface can enumerate the directory"
    );

    // Reading it back gives the same edge, and every principal can list it.
    assert_eq!(store.load(edge.id()).unwrap(), edge);
    assert_eq!(store.list().unwrap(), vec![edge]);
}

fn anchor_key(fixture: &Deployment) -> ksp_identity::VerifyingPublicKey {
    let layout = fixture.layout(&fixture.admin_home);
    Anchor::load(&layout.admin_anchor_file())
        .expect("the anchor reads")
        .key
}

#[test]
fn a_second_active_edge_for_one_tuple_is_refused_and_a_regrant_is_a_new_id() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let store = EdgeStore::new(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);
    let target = PolicyTarget::Agent(agent(&fixture));

    let first = store
        .create(
            &admin,
            key_id.clone(),
            request(user, 1, target),
            &edge_ledger(&fixture),
        )
        .unwrap();

    let refused = store
        .create(
            &admin,
            key_id.clone(),
            request(user, 1, target),
            &edge_ledger(&fixture),
        )
        .unwrap_err();
    let message = refused.to_string();
    assert!(
        message.contains(first.id().as_str()),
        "the refusal names the edge that already holds the tuple: {message}"
    );

    // Withdrawal removes the artifact; a re-grant is then allowed, and it is a new
    // authority rather than a reuse of the old identifier.
    std::fs::remove_file(store.path(first.id())).unwrap();
    let again = store
        .create(
            &admin,
            key_id,
            request(user, 1, target),
            &edge_ledger(&fixture),
        )
        .expect("a re-grant after withdrawal is admitted");
    assert_ne!(
        again.id(),
        first.id(),
        "a re-grant mints a new id, so an old token cannot come back into force"
    );
}

#[test]
fn each_dangling_link_is_refused_by_its_own_sentence_and_writes_nothing() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let store = EdgeStore::new(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);
    let target = PolicyTarget::Agent(agent(&fixture));

    // The secret version is stored for the version under test, so each case fails
    // only on the link it is about.
    store_version(&fixture, user, 1);

    let unknown_user = PrincipalId::parse("00000000-0000-4000-8000-00000000dead").unwrap();
    let unknown_agent = AgentId::parse("00000000-0000-4000-8000-00000000beef").unwrap();

    let cases = [
        (
            request(unknown_user, 1, target),
            "does not hold",
            "the user link",
        ),
        (
            request(user, 1, PolicyTarget::Agent(unknown_agent)),
            "not enrolled on this host",
            "the agent link",
        ),
        (
            request(user, 9, target),
            "that version is not stored",
            "the secret-version link",
        ),
    ];
    for (request, expected, which) in cases {
        let error = store
            .create(&admin, key_id.clone(), request, &edge_ledger(&fixture))
            .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains(expected),
            "{which} names itself: {message}"
        );
        assert!(
            matches!(error, ksp::edges::EdgeStoreError::Refused(_)),
            "{which} is a model refusal"
        );
    }
    assert!(
        store.list().unwrap().is_empty(),
        "a refused edge writes no artifact"
    );

    // The same request with every link resolved is admitted, which is what makes the
    // three refusals above about the links rather than about the request.
    store
        .create(
            &admin,
            key_id,
            request(user, 1, target),
            &edge_ledger(&fixture),
        )
        .expect("the edge with resolved links is admitted");
}

#[test]
fn any_enrolled_does_not_need_an_enrolled_agent() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let store = EdgeStore::new(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);

    let edge = store
        .create(
            &admin,
            key_id,
            request(user, 1, PolicyTarget::AnyEnrolled),
            &edge_ledger(&fixture),
        )
        .expect("a cooperative edge needs no named agent");
    assert_eq!(edge.target(), PolicyTarget::AnyEnrolled);
    assert_eq!(edge.target().mode(), "cooperative");
    assert_eq!(
        PolicyTarget::Agent(agent(&fixture)).mode(),
        "cryptographic",
        "a named agent is the cryptographic mode"
    );
}

#[test]
fn an_update_keeps_the_id_and_advances_one_revision() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    store_version(&fixture, user, 2);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let store = EdgeStore::new(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);

    let created = store
        .create(
            &admin,
            key_id.clone(),
            request(user, 1, PolicyTarget::AnyEnrolled),
            &edge_ledger(&fixture),
        )
        .unwrap();
    let updated = store
        .update(
            &admin,
            key_id,
            created.id(),
            request(user, 2, PolicyTarget::AnyEnrolled),
            &edge_ledger(&fixture),
        )
        .expect("the update is admitted");

    assert_eq!(updated.id(), created.id());
    assert_eq!(updated.revision(), 2);
    assert_eq!(updated.record_version(), RecordVersion(2));
    // The file was replaced, not appended: one artifact per edge.
    assert_eq!(store.list().unwrap(), vec![updated.clone()]);
    assert_eq!(store.load(created.id()).unwrap(), updated);
}

/// The agent's public identity is published where the admin can read it, and a
/// rotation replaces it rather than leaving the old key behind.
#[test]
fn an_agent_enrolment_publishes_a_readable_identity_and_rotation_replaces_it() {
    let fixture = admin_and_two_users();
    let owner = first_user(&fixture);
    let layout = fixture.layout(&fixture.admin_home);
    let agent = agent(&fixture);

    let index = ksp::agent_index::path(&layout, &VaultId::new("vault-1"), owner, &agent);
    assert!(index.is_file(), "the index is at {}", index.display());
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&index).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644, "the identity is public material");
    let dir_mode = std::fs::metadata(ksp::agent_index::dir(
        &layout,
        &VaultId::new("vault-1"),
        owner,
    ))
    .unwrap()
    .permissions()
    .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o755, "a principal can enumerate her agents");

    let published = ksp::agent_index::load(&layout, &VaultId::new("vault-1"), owner, &agent)
        .expect("the index reads");
    assert_eq!(published.identity, agent);
    assert_eq!(published.display_name.as_deref(), Some("alice-agent"));

    // Rotation, run in the agent's own home, rewrites the index in the same step.
    let (code, output) = fixture.run(
        &fixture.alice_home,
        &[
            "agent",
            "rotate",
            "--agent",
            &fixture.agent,
            "--signing-key-id",
            "rotated-ed25519-1",
            "--recipient-key-id",
            "rotated-x25519-1",
        ],
        None,
    );
    assert_eq!(code, 0, "the rotation failed: {output}");
    let rotated = ksp::agent_index::load(&layout, &VaultId::new("vault-1"), owner, &agent)
        .expect("the index reads after rotation");
    assert_ne!(
        rotated.signing_key, published.signing_key,
        "the index names the new key, not the one the agent replaced"
    );
    assert_eq!(
        ksp::agent_index::list(&layout, &VaultId::new("vault-1"), owner)
            .unwrap()
            .len(),
        1,
        "one agent, published once"
    );
}

#[test]
fn a_refusal_shaped_like_a_pattern_never_reaches_the_store() {
    // The boundary of the model, reached through the store's own admission path.
    let error = PolicyTarget::parse("agent-*").unwrap_err();
    assert!(matches!(error, EdgeRefusal::TargetPattern { .. }));
    assert!(PolicyTarget::parse("*").is_err());
    // The accepted spelling of the cooperative target, and the one display name a
    // read surface prints for it.
    assert_eq!(
        PolicyTarget::parse("any-enrolled").unwrap().to_string(),
        "any-enrolled"
    );
}

/// A reader of the store has only the pinned anchor to go on.
///
/// `policies/` is `0755`, so the artifact is readable by every principal — the
/// mode the plan chooses on purpose. What makes it *authority* is the signature
/// under the admin's pinned key, and a store that hands back a decoded body
/// without checking that has authenticated nothing: it has read a file. The two
/// cases are the two shapes a forged artifact can take.
#[test]
fn an_artifact_the_pinned_admin_did_not_sign_is_refused_on_read() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let store = EdgeStore::new(&layout, &deployment);
    // The directory is created by `publish`, and these artifacts are written by
    // hand: a forged one is exactly the artifact no command would write.
    std::fs::create_dir_all(store.dir()).unwrap();

    // Case 1: another key, and it says so. Authority is not "a signature exists".
    let stranger = AdminSigningKey::generate();
    let foreign = ksp_identity::policy_edge::PolicyEdge::create(
        &stranger,
        KeyId::new("a-stranger-ed25519"),
        VaultId::new("vault-1"),
        request(user, 1, PolicyTarget::AnyEnrolled),
    )
    .expect("the stranger can sign its own edge");
    std::fs::write(store.path(foreign.id()), foreign.encode().unwrap()).unwrap();
    let refused = store.load(foreign.id()).unwrap_err().to_string();
    assert!(
        refused.contains("admin key") || refused.contains("not sign"),
        "the refusal says who was expected: {refused}"
    );

    // Case 2: the pinned key id with a body it did not sign. A key id is a claim;
    // the signature is the fact.
    let impostor = ksp_identity::policy_edge::PolicyEdge::create(
        &stranger,
        deployment.admin_key_id.clone(),
        VaultId::new("vault-1"),
        request(user, 1, PolicyTarget::AnyEnrolled),
    )
    .expect("the stranger can sign under any claim");
    std::fs::write(store.path(impostor.id()), impostor.encode().unwrap()).unwrap();
    let refused = store.load(impostor.id()).unwrap_err().to_string();
    assert!(
        refused.contains("does not verify") || refused.contains("anchor"),
        "the refusal says what disagreed: {refused}"
    );
    assert!(
        store.list().is_err(),
        "a list surface must not hand a forged edge to a caller either"
    );
}

/// `PolicyId::parse` refuses a string that is not 32 lowercase hex characters,
/// because the identifier is a path segment. Decoding an artifact has to make the
/// same refusal: `policy_edge::PolicyEdge` deserialises its identifiers without
/// running their parsers, and the write path builds a file name from the id.
#[test]
fn an_identifier_that_is_not_canonical_is_not_an_edge() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let store = EdgeStore::new(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);

    let edge = store
        .create(
            &admin,
            key_id,
            request(user, 1, PolicyTarget::AnyEnrolled),
            &edge_ledger(&fixture),
        )
        .expect("the edge is admitted");
    let bytes = std::fs::read(store.path(edge.id())).unwrap();

    let id = edge.id().as_str().to_string();
    let offset = bytes
        .windows(id.len())
        .position(|window| window == id.as_bytes())
        .expect("the identifier is in the artifact");
    let mut patched = bytes.clone();
    patched[offset..offset + id.len()].make_ascii_uppercase();
    assert_ne!(
        patched[offset..offset + id.len()],
        bytes[offset..offset + id.len()],
        "the identifier had a letter in it, so the patch landed"
    );

    let refused = ksp_identity::policy_edge::PolicyEdge::decode(&patched).unwrap_err();
    assert!(
        matches!(refused, EdgeRefusal::IdNotCanonical { .. }),
        "a decoded identifier is validated like a parsed one: {refused}"
    );
    // The unpatched bytes are the control, so the refusal is about the spelling.
    assert!(ksp_identity::policy_edge::PolicyEdge::decode(&bytes).is_ok());
}

/// One identifier names one authority. An artifact whose body names a different id
/// than the file it sits in would be re-signed under the body's name and written
/// over an artifact that was never loaded.
#[test]
fn an_artifact_that_names_another_identifier_is_refused() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let store = EdgeStore::new(&layout, &deployment);
    let (admin, key_id) = admin_key(&fixture);

    let first = store
        .create(
            &admin,
            key_id.clone(),
            request(user, 1, PolicyTarget::Agent(agent(&fixture))),
            &edge_ledger(&fixture),
        )
        .unwrap();
    let second = store
        .create(
            &admin,
            key_id,
            request(user, 1, PolicyTarget::AnyEnrolled),
            &edge_ledger(&fixture),
        )
        .unwrap();

    // The first artifact, filed under the second identifier.
    std::fs::copy(store.path(first.id()), store.path(second.id())).unwrap();
    let refused = store.load(second.id()).unwrap_err().to_string();
    assert!(
        refused.contains(first.id().as_str()),
        "the refusal names the identifier the body carries: {refused}"
    );
}

/// An empty directory and an unreadable one are different facts, and only one of
/// them means "this deployment grants nothing". A `list` that answers `Ok(vec![])`
/// to `EACCES` makes the uniqueness check unable to see a duplicate, so a second
/// active edge for one tuple would be admitted on a store it could not read.
#[test]
fn an_unreadable_directory_is_not_an_empty_one() {
    let fixture = admin_and_two_users();
    let user = first_user(&fixture);
    store_version(&fixture, user, 1);
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let store = EdgeStore::new(&layout, &deployment);

    // A deployment that has never granted anything: no directory, and that reads
    // as an empty set rather than as a failure.
    assert!(store.list().unwrap().is_empty());

    let (admin, key_id) = admin_key(&fixture);
    store
        .create(
            &admin,
            key_id,
            request(user, 1, PolicyTarget::AnyEnrolled),
            &edge_ledger(&fixture),
        )
        .unwrap();

    use std::os::unix::fs::PermissionsExt;
    let directory = store.dir();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o000)).unwrap();
    let denied = std::fs::read_dir(&directory).is_err();
    let listed = store.list();
    // Restore before asserting, so a failure does not leave an unreadable path for
    // the fixture's cleanup to trip over.
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();

    // The suite runs unprivileged by design; root bypasses the mode, so a run as
    // root has to say it could not express the case rather than pass as if it had.
    assert!(
        denied,
        "this test needs an account the directory mode applies to; run it unprivileged"
    );
    assert!(
        listed.is_err(),
        "a directory that cannot be read is not a directory with no grants"
    );
}
