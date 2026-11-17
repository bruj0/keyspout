//! The joined read surfaces: what an admin and a user see of the policy graph.
//!
//! # What these tests are for
//!
//! Every other suite pins what a policy *does*. This one pins what a person can
//! *find out* about one, which is a different question with its own ways to be
//! wrong: a row that disappears when a link is broken, a label decided in a format
//! string, a filter that silently matches nothing, a bounded listing that does not
//! say what it left out.
//!
//! The tests assert the positive claim (`state=dangling`, `mode=cooperative`)
//! rather than the absence of a forbidden word: "not excluded" is true of the
//! sentence that negates it, so a negative assertion is not a guard.
//!
//! A test reports a failure by panicking, and the panic message is what says why.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use ksp::edges::EdgeStore;
use ksp::keys::Anchor;
use ksp::ledgers::LedgerPaths;
use ksp::lifecycle::Withdrawal;
use ksp::policy_view::{PolicyFilter, PolicyReader, PolicyState};
use ksp::registry::{PrincipalRegistry, RegistryRole};
use ksp_identity::policy_edge::{EdgeRequest, PolicyTarget};
use ksp_identity::{AdminSigningKey, IssuanceLedger, KeyId};
use ksp_types::{AgentId, OpaqueSecretId, PrincipalId, RecordVersion};
use support::{Deployment, admin_and_two_users};

const NOT_BEFORE: u64 = 1_000;
const NOT_AFTER: u64 = 2_000;

/// The instant these tests judge "expired" against: inside the window.
const NOW: i64 = 1_500;

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

/// The deployment's own ledger, created the way `admin init` creates it.
///
/// The reader reads `p/<vault>/<admin>/policy-events.jsonl` — the deployment's file
/// — so a test that recorded its decisions anywhere else would be asserting against
/// a view of a tree nothing wrote.
fn deployment_ledger(fixture: &Deployment) -> (IssuanceLedger, ksp::config::Layout) {
    use std::os::unix::fs::MetadataExt;
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    let owner = std::fs::metadata(layout.root()).map(|meta| (meta.uid(), meta.gid()));
    let owner = owner.expect("the home has an owner");
    LedgerPaths::for_deployment(&layout, &deployment)
        .prepare(
            &layout,
            &deployment.vault,
            deployment.user,
            owner,
            deployment.admin,
            owner,
        )
        .expect("the ledgers are created");
    (
        LedgerPaths::for_deployment(&layout, &deployment).as_ledger(),
        layout,
    )
}

/// A reader over the deployment, and the store a test writes edges through.
struct Scene {
    layout: ksp::config::Layout,
    store: EdgeStore<'static>,
    ledger: IssuanceLedger,
    admin: AdminSigningKey,
    key_id: KeyId,
    user: PrincipalId,
}

fn scene(fixture: &Deployment) -> Scene {
    let (ledger, layout) = deployment_ledger(fixture);
    let (admin, key_id) = admin_key(fixture);
    let user = first_user(fixture);
    // Admission refuses a dangling secret version, so the version every request
    // names exists before any edge is created.
    store_version(fixture, user, 1);
    // The store borrows the layout, so the layout is leaked: a test process is
    // short-lived and this keeps the borrow honest rather than cloning a Layout
    // whose paths would then be a second statement of the same fact.
    let layout: &'static ksp::config::Layout = Box::leak(Box::new(layout));
    let deployment = ksp::deployment::Deployment::load(layout).expect("a deployment record");
    let store = EdgeStore::new(layout, &deployment);
    Scene {
        layout: layout.clone(),
        store,
        ledger,
        admin,
        key_id,
        user,
    }
}

fn create(scene: &Scene, target: PolicyTarget) -> ksp_identity::policy_edge::PolicyEdge {
    scene
        .store
        .create(
            &scene.admin,
            scene.key_id.clone(),
            request(scene.user, 1, target),
            &scene.ledger,
        )
        .expect("the edge is admitted")
}

#[test]
fn a_listing_prints_the_mode_the_state_and_an_empty_set_honestly() {
    let fixture = admin_and_two_users();
    let scene = scene(&fixture);

    // An empty set is a valid answer, and it is asserted before the non-empty one so
    // a listing that never worked cannot pass by printing nothing.
    let reader = PolicyReader::open(&scene.layout, NOW).expect("the reader opens");
    let empty = reader
        .list(&PolicyFilter {
            limit: 10,
            ..Default::default()
        })
        .expect("an empty deployment lists");
    assert_eq!(empty.total, 0, "no policy exists yet");
    assert!(empty.records.is_empty(), "and none is printed");

    let cryptographic = create(&scene, PolicyTarget::Agent(agent(&fixture)));
    let cooperative = create(&scene, PolicyTarget::AnyEnrolled);

    let reader = PolicyReader::open(&scene.layout, NOW).expect("the reader opens");
    let listing = reader
        .list(&PolicyFilter {
            limit: 10,
            ..Default::default()
        })
        .expect("the listing reads");
    assert_eq!(listing.total, 2, "both policies are listed");
    let by_id = |id: &str| {
        listing
            .records
            .iter()
            .find(|record| record.id == id)
            .unwrap_or_else(|| panic!("{id} is in the listing"))
            .clone()
    };
    let first = by_id(cryptographic.id().as_str());
    let second = by_id(cooperative.id().as_str());
    assert_eq!(
        first.mode, "cryptographic",
        "a specific-agent grant is cryptographic"
    );
    assert_eq!(
        second.mode, "cooperative",
        "any-enrolled is cooperative, and the label comes from the model"
    );
    assert_eq!(first.state, PolicyState::Active.as_str());
    assert_eq!(first.target, format!("agent:{}", agent(&fixture)));
    assert_eq!(second.target, "any-enrolled");
}

#[test]
fn the_user_and_secret_and_state_filters_select_and_the_total_survives_the_limit() {
    let fixture = admin_and_two_users();
    let scene = scene(&fixture);
    let user = scene.user;
    let cryptographic = create(&scene, PolicyTarget::Agent(agent(&fixture)));
    let _cooperative = create(&scene, PolicyTarget::AnyEnrolled);
    // A third policy for the *other* principal, so a user filter has something to
    // exclude rather than matching everything by accident.
    let other = {
        let layout = fixture.layout(&fixture.admin_home);
        let registry = PrincipalRegistry::load(&layout).expect("the registry reads");
        registry
            .entries
            .iter()
            .filter(|entry| entry.role == RegistryRole::User)
            .map(|entry| entry.principal)
            .find(|principal| *principal != user)
            .expect("a second user is enrolled")
    };
    store_version(&fixture, other, 1);
    let _other_edge = scene
        .store
        .create(
            &scene.admin,
            scene.key_id.clone(),
            request(other, 1, PolicyTarget::AnyEnrolled),
            &scene.ledger,
        )
        .expect("the second user's edge is admitted");

    let reader = PolicyReader::open(&scene.layout, NOW).expect("the reader opens");

    let mine = reader
        .list(&PolicyFilter {
            user: Some(user),
            limit: 10,
            ..Default::default()
        })
        .expect("the user filter reads");
    assert_eq!(mine.total, 2, "exactly this user's two policies");
    assert!(
        mine.records
            .iter()
            .all(|record| record.user == user.to_string()),
        "no other principal's policy is in the answer"
    );

    let by_secret = reader
        .list(&PolicyFilter {
            secret: Some(OpaqueSecretId::new("s1")),
            limit: 10,
            ..Default::default()
        })
        .expect("the secret filter reads");
    assert_eq!(by_secret.total, 3, "every edge names s1");

    // Withdraw the cryptographic one, then ask for withdrawn.
    let withdrawal = Withdrawal::new(&scene.layout, &scene.store, &scene.ledger);
    withdrawal
        .complete(&cryptographic, withdrawal_actor(&fixture), NOW)
        .expect("the withdrawal completes");

    let withdrawn = reader
        .list(&PolicyFilter {
            state: Some(PolicyState::Withdrawn),
            limit: 10,
            ..Default::default()
        })
        .expect("the state filter reads");
    assert_eq!(withdrawn.total, 1, "exactly one policy is withdrawn");
    assert_eq!(withdrawn.records[0].id, cryptographic.id().as_str());

    let bounded = reader
        .list(&PolicyFilter {
            user: Some(user),
            limit: 1,
            ..Default::default()
        })
        .expect("the bounded listing reads");
    assert_eq!(bounded.records.len(), 1, "one record is printed");
    assert_eq!(
        bounded.total, 2,
        "and the total it did not print is still reported"
    );
    assert_eq!(bounded.limit, 1);
}

fn withdrawal_actor(fixture: &Deployment) -> PrincipalId {
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    deployment.admin
}

#[test]
fn show_joins_verification_the_agent_fingerprint_and_the_withdrawal() {
    let fixture = admin_and_two_users();
    let scene = scene(&fixture);
    let edge = create(&scene, PolicyTarget::Agent(agent(&fixture)));

    let reader = PolicyReader::open(&scene.layout, NOW).expect("the reader opens");
    let view = reader
        .show(edge.id().as_str(), None)
        .expect("the policy shows");
    assert!(
        view.verified,
        "the issuer verified against the pinned anchor"
    );
    assert_eq!(view.state, "active");
    assert_eq!(view.agents.len(), 1, "the target names one agent");
    let published = &view.agents[0];
    assert_eq!(
        published.identity,
        agent(&fixture).to_string(),
        "the identity is the UUID, and it is what the row joins on"
    );
    assert!(
        !published.fingerprint.is_empty(),
        "the fingerprint is what an operator confirms out of band, so it is part of the join"
    );
    assert!(
        !published.signing_key_id.is_empty() && !published.recipient_key_id.is_empty(),
        "both key ids are present"
    );

    // A cooperative grant has no publication and no agent: the row says both, and
    // it says them as facts rather than as a failed lookup.
    let cooperative = create(&scene, PolicyTarget::AnyEnrolled);
    let cooperative_view = reader
        .show(cooperative.id().as_str(), None)
        .expect("the cooperative policy shows");
    assert!(cooperative_view.publication.is_none(), "no publication");
    assert!(
        cooperative_view.agents.is_empty(),
        "no agent is named, which is the target's statement"
    );

    // Withdraw, then read again: the artifact is removed, and the decision is still
    // the answer.
    let withdrawal = Withdrawal::new(&scene.layout, &scene.store, &scene.ledger);
    withdrawal
        .complete(&edge, withdrawal_actor(&fixture), NOW)
        .expect("the withdrawal completes");
    let after = reader
        .show(edge.id().as_str(), None)
        .expect("a withdrawn policy still shows");
    assert_eq!(after.state, "withdrawn");
    let recorded = after
        .withdrawal
        .expect("the withdrawal is part of the answer");
    assert_eq!(recorded.actor, withdrawal_actor(&fixture).to_string());
    assert_eq!(
        after.publication, view.publication,
        "the ledger's copy of the publication survives the artifact it named"
    );
}

#[test]
fn a_user_scope_never_returns_another_principles_policy() {
    let fixture = admin_and_two_users();
    let scene = scene(&fixture);
    let mine = create(&scene, PolicyTarget::AnyEnrolled);
    let other = {
        let layout = fixture.layout(&fixture.admin_home);
        let registry = PrincipalRegistry::load(&layout).expect("the registry reads");
        registry
            .entries
            .iter()
            .filter(|entry| entry.role == RegistryRole::User)
            .map(|entry| entry.principal)
            .find(|principal| *principal != scene.user)
            .expect("a second user is enrolled")
    };
    store_version(&fixture, other, 1);
    let theirs = scene
        .store
        .create(
            &scene.admin,
            scene.key_id.clone(),
            request(other, 1, PolicyTarget::AnyEnrolled),
            &scene.ledger,
        )
        .expect("the second user's edge is admitted");

    let reader = PolicyReader::open(&scene.layout, NOW).expect("the reader opens");
    let scoped = reader
        .list(&PolicyFilter {
            scope: Some(scene.user),
            limit: 10,
            ..Default::default()
        })
        .expect("the scoped listing reads");
    assert_eq!(scoped.total, 1, "only her policy is in scope");
    assert_eq!(scoped.records[0].id, mine.id().as_str());

    let refusal = reader
        .show(theirs.id().as_str(), Some(scene.user))
        .expect_err("another principal's policy is not shown");
    assert!(
        refusal.to_string().contains("holds no policy"),
        "the answer denies holding it rather than denying permission, so it cannot confirm the edge exists: {refusal}"
    );
}

#[test]
fn a_policy_whose_publication_is_missing_is_dangling_and_names_it() {
    let fixture = admin_and_two_users();
    let scene = scene(&fixture);
    let deployment = ksp::deployment::Deployment::load(&scene.layout).expect("a deployment record");
    // An edge that names a publication nobody wrote. This is the state a `create`
    // leaves when its publication step fails: the ledger and the artifact are
    // written, the artifact names the publication, and no file is there. The read
    // surface must say so — a grant that cannot deliver is not a healthy grant.
    let path = ksp::publication::PublicationPath::derive(
        deployment.vault.clone(),
        deployment.admin,
        OpaqueSecretId::new("s1"),
        RecordVersion(1),
    );
    let mut request = request(scene.user, 1, PolicyTarget::Agent(agent(&fixture)));
    request.publication = Some(path.canonical());
    let edge = scene
        .store
        .create(&scene.admin, scene.key_id.clone(), request, &scene.ledger)
        .expect("the edge is admitted: no precondition checks the publication");
    assert!(
        !path.file(&scene.layout).exists(),
        "the fixture must not write the publication, or the test proves nothing"
    );

    let reader = PolicyReader::open(&scene.layout, NOW).expect("the reader opens");
    let record = reader
        .show(edge.id().as_str(), None)
        .expect("the policy is shown");
    assert_eq!(
        record.state, "dangling",
        "a grant whose publication is absent cannot deliver, and `active` would say it can"
    );
    let reason = record.state_reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains("publication") && reason.contains(path.canonical().as_str()),
        "the reason names the missing publication: {reason}"
    );
}

#[test]
fn a_policy_naming_an_agent_that_was_never_published_is_dangling_not_absent() {
    let fixture = admin_and_two_users();
    let scene = scene(&fixture);
    store_version(&fixture, scene.user, 1);
    // A UUID no `agent enroll` ever published. The edge is admitted because the
    // check runs at create time; the test removes the publication afterwards.
    let edge = create(&scene, PolicyTarget::Agent(agent(&fixture)));
    let index = {
        let layout = fixture.layout(&fixture.alice_home);
        ksp::agent_index::path(
            &layout,
            &edge.vault().clone(),
            *edge.user(),
            &agent(&fixture),
        )
    };
    assert!(index.exists(), "the fixture published this agent");
    std::fs::remove_file(&index).expect("the publication is removed");

    let reader = PolicyReader::open(&scene.layout, NOW).expect("the reader opens");
    let listing = reader
        .list(&PolicyFilter {
            limit: 10,
            ..Default::default()
        })
        .expect("the listing still answers");
    let record = listing
        .records
        .iter()
        .find(|record| record.id == edge.id().as_str())
        .expect("the policy is printed, not omitted");
    assert_eq!(record.state, "dangling");
    let reason = record.state_reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains("is not published by this user"),
        "the reason names the missing link: {reason}"
    );
    assert!(
        record.agents.is_empty(),
        "an agent that cannot be resolved has no row"
    );
}

#[test]
fn a_policy_past_its_validity_window_is_expired_and_still_listed() {
    let fixture = admin_and_two_users();
    let scene = scene(&fixture);
    let edge = create(&scene, PolicyTarget::AnyEnrolled);

    // The reader takes "now" as an argument, so the window that ended at NOT_AFTER
    // is judged by a clock just past it. The state is derived, not stored: nothing
    // rewrites an artifact when its window closes.
    let reader = PolicyReader::open(&scene.layout, NOT_AFTER as i64 + 1).expect("the reader opens");
    let view = reader
        .show(edge.id().as_str(), None)
        .expect("the policy shows");
    assert_eq!(view.state, "expired");
    let reason = view.state_reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains("validity window ended"),
        "the reason names the window and its end: {reason}"
    );
    // A window that has passed is not a link that is missing: the edge still names
    // everything it named, and the state says which of the two facts stopped it.
    assert_eq!(
        view.agents.len(),
        0,
        "a cooperative target names no agent, expired or not"
    );

    // And the same instant, on the cryptographic edge, keeps its agent row: the
    // window is what ended, not the publication of the keys.
    let cryptographic = create(&scene, PolicyTarget::Agent(agent(&fixture)));
    let view = reader
        .show(cryptographic.id().as_str(), None)
        .expect("the cryptographic policy shows");
    assert_eq!(view.state, "expired");
    assert_eq!(
        view.agents.len(),
        1,
        "the agent is still resolvable, so its row is still printed"
    );
}

#[test]
fn an_artifact_whose_digest_is_not_the_ledgers_is_unverified() {
    let fixture = admin_and_two_users();
    let scene = scene(&fixture);
    let edge = create(&scene, PolicyTarget::AnyEnrolled);

    // A restored backup, or a ledger swapped for another line: the artifact decodes
    // and even verifies, and the decision it claims is not the one recorded.
    let path = scene.ledger.policy_events_path().to_path_buf();
    let text = std::fs::read_to_string(&path).expect("the ledger reads");
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let entry: serde_json::Value = serde_json::from_str(&lines[0]).expect("one decision");
    let mut forged = entry.clone();
    let entry_object = forged["entry"]
        .as_object_mut()
        .expect("the decision is an object");
    entry_object.insert("digest".to_string(), serde_json::json!(vec![0u8; 32]));
    lines[0] = serde_json::to_string(&forged).expect("the forged line encodes");
    std::fs::write(&path, lines.join("\n") + "\n").expect("the ledger is rewritten");

    let reader = PolicyReader::open(&scene.layout, NOW).expect("the reader opens");
    let view = reader
        .show(edge.id().as_str(), None)
        .expect("the policy still shows");
    assert_eq!(view.state, "unverified");
    let reason = view.state_reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains("digest is not the one the ledger recorded"),
        "the reason names the disagreement: {reason}"
    );
    assert!(
        view.withdrawal.is_none(),
        "a forged line is not a withdrawal it can report"
    );
}

#[test]
fn text_and_json_carry_the_same_records() {
    let fixture = admin_and_two_users();
    let scene = scene(&fixture);
    let first = create(&scene, PolicyTarget::Agent(agent(&fixture)));
    let second = create(&scene, PolicyTarget::AnyEnrolled);

    let (code, text) = fixture.run(&fixture.admin_home, &["admin", "policy", "list"], None);
    assert_eq!(code, 0, "the text listing succeeds: {text}");
    let (json_code, json) = fixture.run(
        &fixture.admin_home,
        &["admin", "policy", "list", "--json"],
        None,
    );
    assert_eq!(json_code, 0, "the JSON listing succeeds: {json}");

    let value: serde_json::Value = serde_json::from_str(&json).expect("one JSON object");
    assert_eq!(
        value["kind"], "policies",
        "the object carries its kind tag: {json}"
    );
    let records = value["records"].as_array().expect("a records array");
    assert_eq!(records.len(), 2, "one record per policy");
    assert_eq!(value["total"], 2);
    for id in [first.id().as_str(), second.id().as_str()] {
        assert!(
            text.contains(id),
            "the text view prints {id} as the JSON view does"
        );
        assert!(
            records
                .iter()
                .any(|record| record["id"].as_str() == Some(id)),
            "the JSON view prints {id}"
        );
    }
    let modes: Vec<&str> = records
        .iter()
        .map(|record| record["mode"].as_str().expect("a mode"))
        .collect();
    assert!(
        modes.contains(&"cryptographic") && modes.contains(&"cooperative"),
        "both labels are on the JSON surface too: {modes:?}"
    );
}

#[test]
fn the_user_surface_answers_only_for_the_calling_account() {
    let fixture = admin_and_two_users();
    let scene = scene(&fixture);
    let mine = create(&scene, PolicyTarget::AnyEnrolled);
    let other = {
        let layout = fixture.layout(&fixture.admin_home);
        let registry = PrincipalRegistry::load(&layout).expect("the registry reads");
        registry
            .entries
            .iter()
            .filter(|entry| entry.role == RegistryRole::User)
            .map(|entry| entry.principal)
            .find(|principal| *principal != scene.user)
            .expect("a second user is enrolled")
    };
    store_version(&fixture, other, 1);
    let theirs = scene
        .store
        .create(
            &scene.admin,
            scene.key_id.clone(),
            request(other, 1, PolicyTarget::AnyEnrolled),
            &scene.ledger,
        )
        .expect("the second user's edge is admitted");

    // This suite runs as one account, and the fixture binds every principal to it.
    // Binding only this user leaves the resolver one answer, which is the state a
    // real deployment is in when one account owns one principal's home.
    let registry_path = fixture.registry();
    let mut registry = PrincipalRegistry::load_at(&registry_path).expect("the registry reads");
    let account = String::from_utf8(
        std::process::Command::new("/usr/bin/id")
            .arg("-un")
            .output()
            .expect("the account name reads")
            .stdout,
    )
    .expect("the account name is UTF-8")
    .trim()
    .to_string();
    for entry in registry.entries.iter_mut() {
        entry.account = if entry.principal == scene.user {
            Some(account.clone())
        } else {
            None
        };
    }
    registry
        .save_at(&registry_path, &fixture.layout(&fixture.admin_home))
        .expect("the registry is rewritten");

    let (code, listing) = fixture.run(&fixture.alice_home, &["policy", "list"], None);
    assert_eq!(code, 0, "the user's listing succeeds: {listing}");
    assert!(
        listing.contains(mine.id().as_str()),
        "her policy is listed: {listing}"
    );
    assert!(
        !listing.contains(theirs.id().as_str()),
        "the other principal's policy is not: {listing}"
    );

    let (refused, message) = fixture.run(
        &fixture.alice_home,
        &["policy", "show", theirs.id().as_str()],
        None,
    );
    assert_ne!(refused, 0, "another principal's policy is not shown");
    assert!(
        message.contains("holds no policy"),
        "and the answer does not confirm it exists: {message}"
    );
}
