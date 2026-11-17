//! The delivery token one specific-agent policy authorises.
//!
//! # What changed and why it is here
//!
//! The token used to be minted by the user, which required her password twice: once
//! to sign the artifact and once to sign the ledger entry. A policy-bound delivery
//! has no key of hers in it, so the signature moved to the moment the authority
//! already exists — policy creation, under the admin's enrolled key (FR-018,
//! CF-020). The user's export is a copy, and this suite is where "a copy" has to
//! mean "reads no password and signs nothing".
//!
//! # Why the fixture is the shared one
//!
//! An edge names a user and an agent and its publication lives under the admin, so
//! the deployment has to hold all three. The WP01 fixture does, and rebuilding it
//! here would be a second statement of the topology.
//!
//! # Why there is no verb
//!
//! The design spec's command surface is pinned by a test in `commands.rs` and only
//! WP07 changes it, so this suite calls the operations the surface will reach
//! (CF-019).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use ksp::config::Layout;
use ksp::deployment::Deployment;
use ksp::edges::EdgeStore;
use ksp::keys::Anchor;
use ksp::publication::{self, PublicationPath};
use ksp::registry::PrincipalRegistry;
use ksp::token::{export_policy_token, issue_policy_token};
use ksp_identity::policy_edge::{EdgeRequest, PolicyEdge, PolicyTarget};
use ksp_identity::{AdminSigningKey, DeliveredKey, DeliveryArtifact, KeyId};
use ksp_types::{AgentId, Level, OpaqueSecretId, PrincipalId, RecordVersion, VaultId};
use support::{Deployment as Fixture, admin_and_two_users};

/// The password the fixture's admin sealed her vault with. The issuance no longer
/// reads it — that is the point of CF-020 — so it is used only to seal.
const PASSWORD: &[u8] = b"correct horse battery";
/// The grant is live now, because `run` refuses an expired one and a fixture dated in
/// 1970 would test the refusal rather than the delivery.
fn not_before() -> u64 {
    now() - 60
}

fn not_after() -> u64 {
    now() + 3_600
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs()
}
const SECRET: &str = "s1";

fn vault() -> VaultId {
    VaultId::new("vault-1")
}

/// The user the grant names: the first enrolled one.
fn first_user(fixture: &Fixture) -> PrincipalId {
    let layout = fixture.layout(&fixture.admin_home);
    let registry = PrincipalRegistry::load(&layout).expect("the registry reads");
    registry
        .entries
        .iter()
        .find(|entry| entry.role == ksp::registry::RegistryRole::User)
        .expect("a user is enrolled")
        .principal
}

fn agent(fixture: &Fixture) -> AgentId {
    AgentId::parse(&fixture.agent).expect("the fixture printed a canonical agent id")
}

/// Put a `user`-level record so the secret-version link resolves.
fn store_version(fixture: &Fixture, user: PrincipalId, version: u32) {
    use ksp_record::version::BlobStore;
    use ksp_types::BoundMetadata;

    let store = ksp_backend::file::FileStore::new(fixture.store.clone()).expect("the store opens");
    let metadata = BoundMetadata {
        vault_id: vault(),
        user_id: user,
        level: Level::User,
        secret_id: OpaqueSecretId::new(SECRET),
        version,
    };
    let path = ksp_record::RecordPath::of(&metadata).as_str().to_string();
    store
        .put_if_absent(&path, b"ciphertext")
        .expect("the record is written");

    // `put_if_absent` creates the level directory with the process `umask`, which a
    // real write never does: the layout owns that mode, and the run path refuses a
    // protected root that has drifted. Applied here so the fixture describes a
    // deployment rather than a directory tree that merely contains the files.
    let level_directory = fixture
        .store
        .join("p")
        .join(vault().as_str())
        .join(user.to_string())
        .join("user");
    std::fs::set_permissions(
        &level_directory,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .expect("the level directory takes the layout's mode");
}

/// The admin key and its id, as a real deployment pins them.
fn admin_key(fixture: &Fixture) -> (AdminSigningKey, KeyId) {
    let layout = fixture.layout(&fixture.admin_home);
    let anchor = Anchor::load(&layout.admin_anchor_file()).expect("the anchor reads");
    let key_id = anchor.key_id.clone();
    let admin = ksp::admin::load_admin(&layout, &anchor).expect("the admin key reads");
    (admin, key_id)
}

/// Everything a policy-bound delivery needs to exist before its edge does.
///
/// The order is the real one: the user publishes her agent, the admin seals her own
/// vault, and the publication is written before the edge that names it. An edge whose
/// publication does not exist yet is refused, which is the subject of one test below.
/// A ledger beside the home for this suite's policy decisions.
fn edge_ledger(prepared: &Prepared) -> ksp_identity::IssuanceLedger {
    ksp_identity::IssuanceLedger::at(prepared.layout.issuance_ledger())
}

struct Prepared {
    layout: Layout,
    recorded: Deployment,
    user: PrincipalId,
    agent: AgentId,
    publication: PublicationPath,
    admin: AdminSigningKey,
    key_id: KeyId,
    /// The agent's X25519 public key, which its publication entry is sealed to.
    agent_recipient: [u8; 32],
    /// The admin's own X25519 public key, which the content key is sealed to.
    admin_recipient: [u8; 32],
}

fn prepared(fixture: &Fixture) -> Prepared {
    let layout = fixture.layout(&fixture.admin_home);
    let user = first_user(fixture);
    let agent = agent(fixture);
    store_version(fixture, user, 1);

    // The admin's own X25519 key, which the publication's content key is sealed to.
    ksp::admin::seal_vault(&layout, PASSWORD).expect("the admin vault is sealed");
    let recorded = Deployment::load(&layout).expect("a deployment record");
    let admin_recipient = recorded
        .admin_vault_recipient_key
        .expect("sealing records the admin's recipient key");

    // The agent's published keys: the admin cannot enter the user's `0700` home, so
    // the index entry is the only material she can read (CF-011). The enrolment is
    // written in the *user's* home, which is where the agent enrolled.
    let user_layout = fixture.layout(&fixture.alice_home);
    let stored = ksp::keys::StoredEnrolment::load(&user_layout.enrolment_file(&agent.to_string()))
        .expect("the agent is enrolled");
    ksp::agent_index::publish(&layout, &vault(), user, &stored).expect("the agent is published");

    let publication = PublicationPath::derive(
        vault(),
        recorded.admin,
        OpaqueSecretId::new(SECRET),
        RecordVersion(1),
    );
    let (admin, key_id) = admin_key(fixture);
    Prepared {
        layout,
        recorded,
        user,
        agent,
        publication,
        admin,
        key_id,
        agent_recipient: stored.recipient_key.to_bytes(),
        admin_recipient: admin_recipient.to_bytes(),
    }
}

fn request(prepared: &Prepared, target: PolicyTarget) -> EdgeRequest {
    EdgeRequest {
        user: prepared.user,
        secret: OpaqueSecretId::new(SECRET),
        record_version: RecordVersion(1),
        target,
        publication: Some(prepared.publication.canonical()),
        not_before: not_before(),
        not_after: not_after(),
    }
}

/// The edge a policy-bound delivery is issued under, and its publication.
///
/// The order is the real one: the grant is signed first, and the publication carries
/// **its** id as the entry key. A publication written before the grant cannot know
/// that id, and an entry keyed by anything else is an entry the agent's token will
/// never find.
fn edge(prepared: &Prepared) -> PolicyEdge {
    let store = EdgeStore::new(&prepared.layout, &prepared.recorded);
    let edge = store
        .create(
            &prepared.admin,
            prepared.key_id.clone(),
            request(prepared, PolicyTarget::Agent(prepared.agent)),
            &edge_ledger(prepared),
        )
        .expect("the edge is created");
    publication::publish(
        &prepared.layout,
        &prepared.publication,
        publication::PublishRequest {
            policy: edge.id().as_str(),
            cooperative: false,
            target: prepared.agent_recipient,
            admin_recipient: prepared.admin_recipient,
        },
        || Ok((b"name".to_vec(), b"value".to_vec())),
        |_| None,
    )
    .expect("the publication is written");
    edge
}

#[test]
fn the_issued_token_names_the_policy_and_the_publication_and_carries_no_key() {
    let fixture = admin_and_two_users();
    let prepared = prepared(&fixture);
    let edge = edge(&prepared);

    let issued = issue_policy_token(
        &prepared.layout,
        &prepared.admin,
        &edge,
        "jti-1".to_string(),
    )
    .expect("issued");
    let bytes = std::fs::read(&issued.path).expect("the token is on disk");
    let artifact = DeliveryArtifact::from_bytes(&bytes).expect("the token parses");
    let header = artifact.header();

    assert_eq!(header.records().len(), 1);
    let record = &header.records()[0];
    assert_eq!(
        record.policy.as_ref(),
        Some(edge.id()),
        "the record names the policy that authorises it"
    );
    assert!(
        record.is_policy_bound(),
        "a policy-bound record says so through its own id"
    );
    assert_eq!(
        header.issuer_key_id(),
        &prepared.key_id,
        "the admin's enrolled key signs the delivery, not the user's"
    );
    assert_eq!(
        header.user(),
        &prepared.recorded.admin,
        "the publication's owning principal is the one the agent reads under"
    );
    assert_eq!(header.level(), &Level::Granted);
    assert_eq!(
        header.expires_at(),
        edge.body().not_after(),
        "the policy's validity window is the only lease a policy-bound delivery has"
    );

    // The sealed entry is a reference, never a key: the user who exports this token
    // cannot open the publication, so a key here would be one she never held (C1).
    let verified =
        ksp_identity::delivery::verify(&artifact, &anchor_key(&prepared)).expect("it verifies");
    // The private half is lent to the call, never extracted: this is the same
    // closure `run` uses, so the test cannot become a second route to the bytes.
    let opened = agent_bundle(&fixture)
        .with_recipient_secret(|secret| ksp_identity::delivery::open(&verified, secret))
        .expect("the agent opens its own entry");
    let delivered = opened
        .delivered(&record.secret, record.version)
        .expect("the entry is there");
    assert!(
        delivered.content().is_none(),
        "a policy-bound entry carries no content key"
    );
    assert_eq!(
        delivered
            .policy()
            .map(|reference| reference.publication.as_str()),
        Some(prepared.publication.canonical().as_str()),
        "the entry names the publication the agent will read"
    );
    assert!(matches!(delivered, DeliveredKey::Policy(_)));
}

#[test]
fn the_user_exports_the_admin_issued_token_without_a_password() {
    let fixture = admin_and_two_users();
    let prepared = prepared(&fixture);
    let edge = edge(&prepared);
    let issued = issue_policy_token(
        &prepared.layout,
        &prepared.admin,
        &edge,
        "jti-2".to_string(),
    )
    .expect("issued");

    let out = fixture.admin_home.join("exported.token");
    // No password is passed and none is read: the export is a copy of an artifact
    // that was signed at policy creation (FR-018).
    export_policy_token(&prepared.layout, &edge, &prepared.agent, &out)
        .expect("the export succeeds");
    assert_eq!(
        std::fs::read(&out).expect("the export is on disk"),
        std::fs::read(&issued.path).expect("the issued token is on disk"),
        "the export is the issued bytes, not a second signature"
    );
}

#[test]
fn exporting_to_an_agent_the_policy_does_not_name_is_refused() {
    let fixture = admin_and_two_users();
    let prepared = prepared(&fixture);
    let edge = edge(&prepared);

    let out = fixture.admin_home.join("wrong-agent.token");
    let refusal = export_policy_token(
        &prepared.layout,
        &edge,
        &AgentId::parse("00000000-0000-4000-8000-00000000dead").expect("a canonical id"),
        &out,
    )
    .expect_err("another agent is refused");

    let sentence = refusal.to_string();
    assert!(
        sentence.contains(&prepared.agent.to_string()),
        "the refusal names the agent the policy does name: {sentence}"
    );
    assert!(
        !out.exists(),
        "a refused export writes nothing for the agent to run by mistake"
    );
}

#[test]
fn a_cooperative_policy_issues_no_token() {
    let fixture = admin_and_two_users();
    let prepared = prepared(&fixture);
    let store = EdgeStore::new(&prepared.layout, &prepared.recorded);
    let cooperative = store
        .create(
            &prepared.admin,
            prepared.key_id.clone(),
            request(&prepared, PolicyTarget::AnyEnrolled),
            &edge_ledger(&prepared),
        )
        .expect("the cooperative edge is created");

    let refusal = issue_policy_token(
        &prepared.layout,
        &prepared.admin,
        &cooperative,
        "jti-3".to_string(),
    )
    .expect_err("a cooperative grant issues no delivery");
    let sentence = refusal.to_string();
    assert!(
        sentence.contains("cooperative"),
        "the refusal says the grant is cooperative rather than enforced: {sentence}"
    );
    assert!(
        !store.token_path(cooperative.id()).exists(),
        "no token is written for a grant that restricts no agent"
    );
}

#[test]
fn an_edge_whose_publication_is_not_the_derived_path_is_refused() {
    let fixture = admin_and_two_users();
    let prepared = prepared(&fixture);
    let store = EdgeStore::new(&prepared.layout, &prepared.recorded);
    let elsewhere = format!("{}9", prepared.publication.canonical());
    let mut request = request(&prepared, PolicyTarget::Agent(prepared.agent));
    request.publication = Some(elsewhere.clone());
    let edge = store
        .create(
            &prepared.admin,
            prepared.key_id.clone(),
            request,
            &edge_ledger(&prepared),
        )
        .expect("the edge is created");

    let refusal = issue_policy_token(
        &prepared.layout,
        &prepared.admin,
        &edge,
        "jti-4".to_string(),
    )
    .expect_err("a path that is not the derived one is refused");
    let sentence = refusal.to_string();
    assert!(
        sentence.contains(&prepared.publication.canonical()),
        "the refusal names the path this build accepts: {sentence}"
    );
    assert!(
        sentence.contains(&elsewhere),
        "and it names what the grant actually records, so an operator can see the \
         difference: {sentence}"
    );
}

fn anchor_key(prepared: &Prepared) -> ksp_identity::VerifyingPublicKey {
    let anchor = Anchor::load(&prepared.layout.admin_anchor_file()).expect("the anchor reads");
    anchor.key
}

/// The agent's key bundle, from the key file the fixture wrote.
fn agent_bundle(fixture: &Fixture) -> ksp_identity::AgentKeyBundle {
    // The agent enrolled in the user's home, which is the account whose records it
    // reads.
    let layout = fixture.layout(&fixture.alice_home);
    let agent = agent(fixture);
    let stored = ksp::keys::StoredEnrolment::load(&layout.enrolment_file(&agent.to_string()))
        .expect("the agent is enrolled");
    let store = ksp_key_lifecycle::KeyStore::new(
        ksp_key_lifecycle::KeyRoot::open(layout.agent_key_root()).expect("the key root opens"),
    );
    store.load_agent(&stored.pin()).expect("the bundle loads")
}

#[test]
fn the_named_agent_receives_the_value_and_consume_is_refused() {
    let fixture = admin_and_two_users();
    let prepared = prepared(&fixture);
    let edge = edge(&prepared);
    issue_policy_token(
        &prepared.layout,
        &prepared.admin,
        &edge,
        "jti-run".to_string(),
    )
    .expect("issued");

    // The user exports it and hands the file to the agent; nothing in either step
    // reads a password or a key that opens the publication.
    // The run path is gated on the host's confinement and on a proven sweep, which a
    // provisioning fixture has never run: `init` writes the configuration this host can
    // satisfy, and `secret gc` is what proves a sweep, the same two steps a real
    // deployment takes before its first delivery.
    let (code, output) = fixture.run(&fixture.alice_home, &["init"], None);
    assert_eq!(code, 0, "init failed: {output}");
    // The sweep proof is written by the principal that holds the admin key, which is
    // the admin's home; the agent's home reads the proof the store carries.
    let (code, output) = fixture.run(&fixture.admin_home, &["init"], None);
    assert_eq!(code, 0, "the admin init failed: {output}");
    let (code, output) = fixture.run(&fixture.admin_home, &["secret", "gc"], None);
    assert_eq!(code, 0, "the sweep run failed: {output}");

    let token = fixture.alice_home.join("policy.token");
    export_policy_token(&prepared.layout, &edge, &prepared.agent, &token).expect("exported");
    let path = token.to_str().expect("a UTF-8 temporary path");

    let (code, output) = fixture.run(
        &fixture.alice_home,
        &[
            "run",
            "--token",
            path,
            "--env",
            "DB",
            "--",
            "/bin/sh",
            "-c",
            "printf '%s' \"$DB\"",
        ],
        None,
    );
    assert_eq!(code, 0, "the policy-bound run was refused: {output}");
    assert!(
        output.contains("value"),
        "the agent received the published value: {output}"
    );

    // FR-019: there is no agent-level copy to consume, so the refusal has to happen
    // before the child starts and name the control that does end access.
    let marker = fixture.alice_home.join("child-ran");
    let (code, output) = fixture.run(
        &fixture.alice_home,
        &[
            "run",
            "--token",
            path,
            "--consume",
            "--env",
            "DB",
            "--",
            "/bin/sh",
            "-c",
            &format!("touch {}", marker.display()),
        ],
        None,
    );
    assert_ne!(code, 0, "a policy-bound consume must fail: {output}");
    assert!(
        output.contains("withdraw the policy"),
        "the refusal names withdrawal as the accepted control: {output}"
    );
    assert!(
        !marker.exists(),
        "the child must not have started: {output}"
    );
}

/// The child that prints the delivered variable, so a run's effect is observable.
fn print_db(fixture: &Fixture, token: &std::path::Path) -> (i32, String) {
    fixture.run(
        &fixture.alice_home,
        &[
            "run",
            "--token",
            token.to_str().expect("a UTF-8 temporary path"),
            "--env",
            "DB",
            "--",
            "/bin/sh",
            "-c",
            "printf '%s' \"$DB\"",
        ],
        None,
    )
}

/// Provision both homes and export the policy's token for the fixture's agent.
fn exportable(fixture: &Fixture, prepared: &Prepared, edge: &PolicyEdge) -> std::path::PathBuf {
    let (code, output) = fixture.run(&fixture.alice_home, &["init"], None);
    assert_eq!(code, 0, "init failed: {output}");
    let (code, output) = fixture.run(&fixture.admin_home, &["init"], None);
    assert_eq!(code, 0, "the admin init failed: {output}");
    let (code, output) = fixture.run(&fixture.admin_home, &["secret", "gc"], None);
    assert_eq!(code, 0, "the sweep run failed: {output}");
    issue_policy_token(
        &prepared.layout,
        &prepared.admin,
        edge,
        "jti-case".to_string(),
    )
    .expect("issued");
    let token = fixture.alice_home.join("case.token");
    export_policy_token(&prepared.layout, edge, &prepared.agent, &token).expect("exported");
    token
}

#[test]
fn an_expired_grant_fails_before_decryption_and_names_the_window() {
    let fixture = admin_and_two_users();
    let mut prepared = prepared(&fixture);
    // A grant that expired an hour ago. It is still signed and still published: nothing
    // at issuance reads the window, which is why `run` has to.
    prepared.publication = PublicationPath::derive(
        vault(),
        prepared.recorded.admin,
        OpaqueSecretId::new(SECRET),
        RecordVersion(1),
    );
    let store = EdgeStore::new(&prepared.layout, &prepared.recorded);
    let expired = store
        .create(
            &prepared.admin,
            prepared.key_id.clone(),
            EdgeRequest {
                user: prepared.user,
                secret: OpaqueSecretId::new(SECRET),
                record_version: RecordVersion(1),
                target: PolicyTarget::Agent(prepared.agent),
                publication: Some(prepared.publication.canonical()),
                not_before: now() - 7_200,
                not_after: now() - 3_600,
            },
            &edge_ledger(&prepared),
        )
        .expect("the expired grant is created");
    publication::publish(
        &prepared.layout,
        &prepared.publication,
        publication::PublishRequest {
            policy: expired.id().as_str(),
            cooperative: false,
            target: prepared.agent_recipient,
            admin_recipient: prepared.admin_recipient,
        },
        || Ok((b"name".to_vec(), b"value".to_vec())),
        |_| None,
    )
    .expect("the publication is written");
    let token = exportable(&fixture, &prepared, &expired);

    let (code, output) = print_db(&fixture, &token);
    assert_eq!(code, 2, "an expired grant is a policy denial: {output}");
    assert!(
        output.contains(&expired.body().not_after().to_string()),
        "the refusal names the instant it expired: {output}"
    );
    assert!(!output.contains("value"), "nothing was delivered: {output}");
}

#[test]
fn a_grant_that_now_names_another_agent_refuses_the_live_token() {
    let fixture = admin_and_two_users();
    let prepared = prepared(&fixture);
    let edge = edge(&prepared);
    let token = exportable(&fixture, &prepared, &edge);

    // A second agent of the same user, so the re-grant names somebody who is really
    // enrolled: the store refuses a dangling target, which is the right invariant and
    // would hide the run-side check if the test used a fictional id.
    let (code, output) = fixture.run(
        &fixture.alice_home,
        &["agent", "enroll", "--agent", "second-agent"],
        None,
    );
    assert_eq!(code, 0, "the second agent enrols: {output}");
    let user_layout = fixture.layout(&fixture.alice_home);
    let other = std::fs::read_dir(user_layout.enrolments_dir())
        .expect("the enrolment directory reads")
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            entry
                .path()
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| AgentId::parse(stem).ok())
        })
        .find(|id| *id != prepared.agent)
        .expect("a second agent is enrolled");
    let stored = ksp::keys::StoredEnrolment::load(&user_layout.enrolment_file(&other.to_string()))
        .expect("the second agent is enrolled");
    ksp::agent_index::publish(&prepared.layout, &vault(), prepared.user, &stored)
        .expect("the second agent is published");

    // The admin re-grants the same policy to that agent: the token still names the id,
    // and the grant no longer names the agent holding it.
    let store = EdgeStore::new(&prepared.layout, &prepared.recorded);
    store
        .update(
            &prepared.admin,
            prepared.key_id.clone(),
            edge.id(),
            EdgeRequest {
                user: prepared.user,
                secret: OpaqueSecretId::new(SECRET),
                record_version: RecordVersion(1),
                target: PolicyTarget::Agent(other),
                publication: Some(prepared.publication.canonical()),
                not_before: not_before(),
                not_after: not_after(),
            },
            &edge_ledger(&prepared),
        )
        .expect("the grant is re-issued to the other agent");

    let (code, output) = print_db(&fixture, &token);
    assert_eq!(
        code, 2,
        "a grant naming another agent is a policy denial: {output}"
    );
    assert!(
        output.contains(&prepared.agent.to_string()),
        "the refusal names the agent the delivery is for: {output}"
    );
    assert!(!output.contains("value"), "nothing was delivered: {output}");
}

#[test]
fn a_deleted_grant_refuses_and_names_withdrawal() {
    let fixture = admin_and_two_users();
    let prepared = prepared(&fixture);
    let edge = edge(&prepared);
    let token = exportable(&fixture, &prepared, &edge);

    // Withdrawal deletes the artifact; the run has to refuse once it is gone, before
    // anything is decrypted, and say which of the two reasons it is.
    let store = EdgeStore::new(&prepared.layout, &prepared.recorded);
    std::fs::remove_file(store.path(edge.id())).expect("the grant is removed");

    let (code, output) = print_db(&fixture, &token);
    assert_eq!(code, 2, "a withdrawn grant is a policy denial: {output}");
    assert!(
        output.contains("withdrawn"),
        "the refusal names withdrawal as the reason a grant is absent: {output}"
    );
    assert!(!output.contains("value"), "nothing was delivered: {output}");
}

#[test]
fn a_token_that_does_not_verify_is_not_exported() {
    let fixture = admin_and_two_users();
    let prepared = prepared(&fixture);
    let edge = edge(&prepared);
    let issued = issue_policy_token(
        &prepared.layout,
        &prepared.admin,
        &edge,
        "jti-tamper".to_string(),
    )
    .expect("issued");

    // One bit of the signature, so the file still parses and still names the right key
    // id: parsing and identity are not authenticity, and an export that checked only
    // those would ship a token the agent refuses.
    let mut bytes = std::fs::read(&issued.path).expect("the token is on disk");
    match bytes.last_mut() {
        Some(last) => *last ^= 0x01,
        None => panic!("the artifact is not empty"),
    }
    std::fs::write(&issued.path, &bytes).expect("the tampered token is written back");

    let out = fixture.alice_home.join("never.token");
    let refusal = export_policy_token(&prepared.layout, &edge, &prepared.agent, &out)
        .expect_err("a token that does not verify is refused");
    assert!(
        refusal.to_string().contains("does not verify"),
        "the refusal says the token failed verification: {refusal}"
    );
    assert!(
        !out.exists(),
        "a refused export writes nothing for an agent to run by mistake"
    );
}
