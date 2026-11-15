//! SC-019: a separate foreground process reloads the agent's protected key.
//!
//! # What this proves that a unit test cannot
//!
//! The agent's private halves are generated in one process and used in another.
//! Both processes are real `ksp` invocations, so the only thing that can carry
//! the key between them is the protected file WP15 writes — and the reload is
//! checked against a pin that was written from the public halves alone.
//!
//! The admin side (anchor, record, artifact) is built here with the libraries,
//! because `ksp admin` and `ksp token` are wired elsewhere; the subject of this
//! test is the *agent* process, which is the one that must never see a second
//! copy of a private half.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

use ksp::config::Layout;
use ksp::exit;
use ksp::keys::{Anchor, StoredEnrolment};
use ksp_identity::delivery::{self, VerifiedRecipientKey};
use ksp_identity::{AdminSigningKey, KeyId, UnsignedEnrolment};
use ksp_record::{ContentBlob, Record, RecordEnvelope, commit_version};
use ksp_types::{
    ActorId, AgentId, BoundMetadata, ContentKey, Level, OpaqueSecretId, RecordVersion, VaultId,
};

/// A secret with a value nobody could guess by accident.
const VALUE: &str = "correct-horse-battery-staple";

fn ksp() -> &'static str {
    env!("CARGO_BIN_EXE_ksp")
}

/// Run `ksp` with this home and return (exit code, stdout).
/// Give this home the capability configuration a real host has.
///
/// `ksp init` is the production probe: it writes the strongest configuration
/// this host can satisfy and never overwrites one that exists, so calling it on
/// every invocation is safe. A host with no configuration has no adapter for
/// either capability, and every unseal and every delivery refuses — the
/// product's intended first-run behaviour, and therefore a precondition of every
/// test below that reaches one.
fn configure(home: &std::path::Path) {
    let _ = Command::new(ksp())
        .env("KSP_HOME", home)
        .arg("init")
        .output();
}

fn ksp_in(home: &std::path::Path, args: &[&str]) -> (i32, String) {
    configure(home);
    let output = Command::new(ksp())
        .env("KSP_HOME", home)
        .args(args)
        .output()
        .expect("the binary runs");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.code().unwrap_or(-1), stdout)
}

/// Enrol one agent and return the principal UUID the enrolment issued.
fn enrol(home: &std::path::Path, name: &str) -> AgentId {
    let (code, stdout) = ksp_in(home, &["agent", "enroll", "--agent", name]);
    assert_eq!(code, exit::SUCCESS, "enrol {name} failed: {stdout}");
    let start = stdout
        .find("agent:")
        .unwrap_or_else(|| panic!("no agent identity in {stdout}"));
    let uuid: String = stdout[start + "agent:".len()..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit() || *c == '-')
        .collect();
    AgentId::parse(&uuid).unwrap_or_else(|_| panic!("not a canonical UUID: {uuid}"))
}

fn metadata(version: u32, agent: AgentId) -> BoundMetadata {
    BoundMetadata {
        vault_id: VaultId::new("vault-1"),
        user_id: ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        level: Level::Agent(agent),
        secret_id: OpaqueSecretId::new("s3cr3t-id-1"),
        version,
    }
}

/// Act as Alice on her own machine: pin the anchor, record the enrolment, seal
/// one record and one delivery to the agent's recipient key.
fn provision(
    home: &std::path::Path,
    agent: AgentId,
) -> (std::path::PathBuf, AdminSigningKey, String) {
    let layout = Layout::new(home);
    let admin = AdminSigningKey::generate();
    Anchor {
        key_id: KeyId::new("admin-2026"),
        key: admin.verifying_public(),
    }
    .save(&layout.admin_anchor_file())
    .unwrap();

    // The public halves come from the pin the agent printed, not from its key
    // file: Alice never reads the agent's private material.
    let stored = StoredEnrolment::load(&layout.enrolment_file(&agent.to_string())).unwrap();
    let unsigned = UnsignedEnrolment::bind(
        ActorId::Agent(agent),
        stored.signing_key,
        stored.recipient_key,
        stored.signing_key_id.clone(),
        stored.recipient_key_id.clone(),
    )
    .unwrap();
    let record = admin
        .sign_enrolment(unsigned, KeyId::new("admin-2026"))
        .unwrap();
    let confirmed = *record.fingerprint();
    let recipient = VerifiedRecipientKey::confirm(&record, &confirmed).unwrap();

    let meta = metadata(1, agent);
    let content_key = ContentKey::generate();
    let aad = meta.bound_aad().unwrap();
    let blob = ContentBlob::seal(&content_key, b"db_password", VALUE.as_bytes(), &aad).unwrap();
    let envelope =
        RecordEnvelope::seal(&content_key, &stored.recipient_key.to_bytes(), &meta).unwrap();
    let sealed_record = Record {
        metadata: meta.clone(),
        blob,
        envelope,
    };
    ksp::layout::ensure_level(layout.root(), &meta.vault_id, meta.user_id, &meta.level).unwrap();
    let store = ksp_backend::file::FileStore::new(layout.store_root()).unwrap();
    commit_version(&store, &meta, &sealed_record).unwrap();

    let selected = ksp_identity::SelectedRecord {
        secret: meta.secret_id.clone(),
        version: RecordVersion(1),
    };
    let header = ksp_identity::DeliveryHeader::new(
        meta.vault_id.clone(),
        meta.user_id,
        KeyId::new("admin-2026"),
        agent,
        stored.signing_key,
        stored.recipient_key,
        stored.signing_key_id.clone(),
        stored.recipient_key_id.clone(),
        meta.level.clone(),
        Level::User,
        Level::Agent(agent).path_segment(),
        vec![selected.clone()],
        u64::MAX,
        "jti-sc019-1".to_string(),
    )
    .unwrap();
    let keys =
        ksp_identity::SelectedContentKeys::new(&header, vec![(selected, content_key)]).unwrap();
    // The lease is Alice's, so the host pins *her* enrolled public key: the run
    // path verifies a delivery against it and never against the admin's key.
    let user_signer = ksp_identity::SigningSecretKey::generate();
    ksp::deployment::Deployment {
        vault: meta.vault_id.clone(),
        // Two principals, because a deployment always has two: the admin who
        // signed the policy and the user who owns the record.
        admin: ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        user: meta.user_id,
        user_name: Some("alice".to_string()),
        user_account: None,
        admin_key_id: KeyId::new("admin-2026"),
        user_signing_key_id: Some(KeyId::new("alice-ed25519-1")),
        user_signing_key: Some(user_signer.verifying_public()),
        user_recipient_key_id: None,
        user_recipient_key: None,
    }
    .save(&layout)
    .unwrap();

    let artifact = delivery::seal(&user_signer, &header, &keys, &recipient).unwrap();

    let token_path = home.join(format!("{agent}.token"));
    std::fs::write(&token_path, artifact.to_bytes().unwrap()).unwrap();
    (token_path, admin, confirmed.to_hex())
}

#[test]
fn a_second_process_reloads_the_key_and_delivers_only_the_scoped_secret() {
    let home = tempfile::tempdir().unwrap();

    // Process 1: the agent host enrols and prints its fingerprint.
    let agent = enrol(home.path(), "agent-7");
    let (token, _admin, _fingerprint) = provision(home.path(), agent);

    // Process 2: a different foreground invocation, which has only the protected
    // file and the token.
    let (code, stdout) = ksp_in(
        home.path(),
        &[
            "run",
            "--token",
            token.to_str().unwrap(),
            "--env",
            "KSP_TEST_SECRET",
            "--",
            "printenv",
            "KSP_TEST_SECRET",
        ],
    );
    assert_eq!(code, exit::SUCCESS, "run failed: {stdout}");
    assert!(
        stdout.contains(VALUE),
        "the child did not receive the scoped value: {stdout}"
    );
}

#[test]
fn a_missing_key_file_refuses_with_six_and_delivers_nothing() {
    let home = tempfile::tempdir().unwrap();
    let agent = enrol(home.path(), "agent-7");
    let (token, _admin, _) = provision(home.path(), agent);

    let layout = Layout::new(home.path());
    std::fs::remove_file(
        layout
            .agent_key_root()
            .join("agent")
            .join(format!("{agent}.key")),
    )
    .unwrap();

    let (code, stdout) = ksp_in(
        home.path(),
        &[
            "run",
            "--token",
            token.to_str().unwrap(),
            "--env",
            "KSP_TEST_SECRET",
            "--",
            "printenv",
            "KSP_TEST_SECRET",
        ],
    );
    assert_eq!(code, exit::MISSING_KEY, "a missing key must exit 6");
    assert!(
        !stdout.contains(VALUE),
        "a refused run delivered the value: {stdout}"
    );
}

#[test]
fn a_key_file_swapped_for_another_agents_refuses_with_six() {
    // The failure this exists for: two agents on one host. Agent 8's file in
    // agent 7's slot still opens *something*, so only the pin can refuse it.
    let home = tempfile::tempdir().unwrap();
    let agent = enrol(home.path(), "agent-7");
    let stranger = enrol(home.path(), "agent-8");
    assert_ne!(agent, stranger, "two enrolments are two identities");
    let (token, _admin, _) = provision(home.path(), agent);

    let layout = Layout::new(home.path());
    let agent_dir = layout.agent_key_root().join("agent");
    std::fs::copy(
        agent_dir.join(format!("{stranger}.key")),
        agent_dir.join(format!("{agent}.key")),
    )
    .unwrap();

    let (code, stdout) = ksp_in(
        home.path(),
        &[
            "run",
            "--token",
            token.to_str().unwrap(),
            "--env",
            "KSP_TEST_SECRET",
            "--",
            "printenv",
            "KSP_TEST_SECRET",
        ],
    );
    assert_eq!(code, exit::MISSING_KEY, "a substituted key must exit 6");
    assert!(!stdout.contains(VALUE));
}
