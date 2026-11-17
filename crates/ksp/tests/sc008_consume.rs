//! SC-008, end to end through the binary: consume delivers, then removes.
//!
//! # What this proves
//!
//! `ksp run --consume` performs S4's whole sequence in the real process model:
//! retrieve the exact version, deliver it from a second `ksp` process that
//! confines *itself*, then delete, journal and report in the parent — which never
//! confined anything and therefore still holds the filesystem rights the delete
//! needs. Splitting it any other way either loses the delete or confines nothing.
//!
//! # Why the token is built here
//!
//! `ksp token mint` refuses on the `file` backend with exit `7`, correctly: the
//! backend has no cleanup mechanism, so a lease cannot be classified. A token is
//! therefore constructed with the libraries the way a remote backend would have
//! produced one, and that is the only double in this file — it is the admission
//! decision, not the delivery, the consumption or the reporting.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ksp::config::Layout;
use ksp::exit;
use ksp::keys::{Anchor, StoredEnrolment};
use ksp_deletion::{EvidenceSigningKey, SignedIntent};
use ksp_identity::delivery::{self, VerifiedRecipientKey};
use ksp_identity::{AdminSigningKey, KeyId, SelectedRecord, UnsignedEnrolment};
use ksp_record::{ContentBlob, Record, RecordEnvelope, commit_version};
use ksp_types::evidence::DeletionIntent;
use ksp_types::{
    ActorId, AgentId, BoundMetadata, ContentKey, Level, OpaqueSecretId, RecordVersion, VaultId,
};

/// A secret with a value nobody could guess by accident.
const VALUE: &str = "correct-horse-battery-staple";

fn ksp() -> &'static str {
    env!("CARGO_BIN_EXE_ksp")
}

/// Run `ksp` with this home and return (exit code, stdout and stderr).
/// Give this home the capability configuration a real host has.
///
/// `ksp init` is the production probe: it writes the strongest configuration
/// this host can satisfy and never overwrites one that exists, so calling it on
/// every invocation is safe. A host with no configuration has no adapter for
/// either capability, and every unseal and every delivery refuses — the
/// product's intended first-run behaviour, and therefore a precondition of every
/// test below that reaches one.
fn configure(home: &Path) {
    let _ = Command::new(ksp())
        .env("KSP_HOME", home)
        .arg("init")
        .output();
}

fn ksp_in(home: &Path, args: &[&str]) -> (i32, String) {
    configure(home);
    let output = Command::new(ksp())
        .env("KSP_HOME", home)
        .args(args)
        .output()
        .expect("the binary runs");
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.code().unwrap_or(-1), combined)
}

/// Enrol one agent and return the principal UUID the enrolment issued.
fn enrol(home: &Path) -> AgentId {
    let (code, output) = ksp_in(home, &["agent", "enroll", "--agent", "agent-7"]);
    assert_eq!(code, exit::SUCCESS, "enrol failed: {output}");
    let start = output
        .find("agent:")
        .unwrap_or_else(|| panic!("no agent identity in {output}"));
    let uuid: String = output[start + "agent:".len()..]
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

/// A provisioned host: anchor, record, delivery, and the intent beside it.
fn provision(home: &Path, intent_version: Option<u32>, agent: AgentId) -> PathBuf {
    let layout = Layout::new(home);
    let admin = AdminSigningKey::generate();
    Anchor {
        key_id: KeyId::new("admin-2026"),
        key: admin.verifying_public(),
    }
    .save(&layout.admin_anchor_file())
    .unwrap();

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
    ksp::layout::ensure_level(layout.root(), &meta.vault_id, meta.user_id, &meta.level).unwrap();
    commit_version(
        &ksp_backend::file::FileStore::new(layout.store_root()).unwrap(),
        &meta,
        &Record {
            metadata: meta.clone(),
            blob,
            envelope,
        },
    )
    .unwrap();

    let selected = SelectedRecord {
        secret: meta.secret_id.clone(),
        version: RecordVersion(1),
        policy: None,
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
        "jti-sc008-1".to_string(),
    )
    .unwrap();
    let keys = ksp_identity::SelectedContentKeys::new(
        &header,
        vec![(selected, ksp_identity::DeliveredKey::Content(content_key))],
    )
    .unwrap();
    // The lease is Alice's, so the host pins *her* enrolled public key: the run
    // path verifies a delivery against it and never against the admin's key.
    let user_signer = ksp_identity::SigningSecretKey::generate();
    ksp::deployment::Deployment {
        vault: meta.vault_id.clone(),
        admin: ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        user: meta.user_id,
        user_name: Some("alice".to_string()),
        user_account: None,
        admin_key_id: KeyId::new("admin-2026"),
        admin_vault_signing_key_id: None,
        admin_vault_recipient_key_id: None,
        admin_vault_recipient_key: None,
        user_signing_key_id: Some(KeyId::new("alice-ed25519-1")),
        user_signing_key: Some(user_signer.verifying_public()),
        user_recipient_key_id: None,
        user_recipient_key: None,
    }
    .save(&layout)
    .unwrap();

    let artifact = delivery::seal(&user_signer, &header, &keys, &recipient).unwrap();

    let token = home.join("agent-7.token");
    std::fs::write(&token, artifact.to_bytes().unwrap()).unwrap();

    if let Some(version) = intent_version {
        // The admin authorises the removal, in the same scoped-use shape the CLI
        // uses: the seed is lent to one call and no copy is kept.
        let intent = DeletionIntent {
            intent_id: format!("s3cr3t-id-1-agent-7-{version}"),
            vault_id: meta.vault_id.clone(),
            user_id: meta.user_id,
            level: meta.level.clone(),
            secret_id: meta.secret_id.clone(),
            version,
            deadline: 4_102_444_800,
            authorized_deleters: vec![ActorId::Agent(agent)],
        };
        // Hers, like the artifact: the host pins her enrolled key and verifies
        // both with it, so an intent the admin signed is authority the verifier
        // does not grant (spec §3.7 step 2).
        let signed = user_signer
            .with_secret(|seed| {
                SignedIntent::sign(
                    &EvidenceSigningKey::from_seed(*seed),
                    "alice-ed25519-1",
                    intent,
                )
            })
            .unwrap();
        std::fs::write(
            token.with_extension("intent"),
            ksp_types::cbor::encode(&signed).unwrap(),
        )
        .unwrap();
    }

    token
}

/// Whether the record the delivery names is still in the store.
fn record_present(home: &Path, agent: AgentId) -> bool {
    Layout::new(home)
        .store_root()
        .join(ksp_record::RecordPath::of(&metadata(1, agent)).as_str())
        .exists()
}

#[test]
fn a_consume_delivers_the_value_and_removes_the_exact_version() {
    let home = tempfile::tempdir().unwrap();
    let agent = enrol(home.path());
    let token = provision(home.path(), Some(1), agent);
    assert!(
        record_present(home.path(), agent),
        "the fixture record is stored"
    );

    let (code, output) = ksp_in(
        home.path(),
        &[
            "run",
            "--consume",
            "--token",
            token.to_str().unwrap(),
            "--env",
            "KSP_TEST_SECRET",
            "--",
            "printenv",
            "KSP_TEST_SECRET",
        ],
    );

    assert_eq!(code, exit::SUCCESS, "consume failed: {output}");
    assert!(
        output.contains(VALUE),
        "the child did not receive the value: {output}"
    );
    assert!(
        !record_present(home.path(), agent),
        "the version this delivery was bound to is still in the store"
    );

    // The acknowledgement and the report are the record of what happened, and
    // neither is optional: a delete with no report is a claim nobody signed.
    let journal = Layout::new(home.path()).journal_root();
    assert!(
        std::fs::read_dir(&journal)
            .map(|entries| entries.count())
            .unwrap_or(0)
            > 0,
        "no acknowledgement was journalled"
    );
    assert!(
        journal.join("reports").join("report-0.cbor").exists(),
        "no report was written"
    );
}

#[test]
fn a_child_that_fails_after_the_removal_reports_the_lost_fresh_fetch_code() {
    let home = tempfile::tempdir().unwrap();
    let agent = enrol(home.path());
    let token = provision(home.path(), Some(1), agent);

    let (code, output) = ksp_in(
        home.path(),
        &[
            "run",
            "--consume",
            "--token",
            token.to_str().unwrap(),
            "--env",
            "KSP_TEST_SECRET",
            "--",
            "sh",
            "-c",
            "exit 3",
        ],
    );

    // Distinct from a plain child failure: the version is gone, so a retry with
    // this token cannot work and the caller must ask for a new delivery.
    assert_eq!(
        code,
        exit::LOST_FRESH_FETCH,
        "a failed child after a removal must exit 10: {output}"
    );
    assert!(
        !record_present(home.path(), agent),
        "the version must be removed even when the child failed"
    );
}

#[test]
fn a_consume_without_an_authorisation_is_refused_and_removes_nothing() {
    let home = tempfile::tempdir().unwrap();
    let agent = enrol(home.path());
    let token = provision(home.path(), None, agent);

    let (code, output) = ksp_in(
        home.path(),
        &[
            "run",
            "--consume",
            "--token",
            token.to_str().unwrap(),
            "--env",
            "KSP_TEST_SECRET",
            "--",
            "printenv",
            "KSP_TEST_SECRET",
        ],
    );

    assert_eq!(code, exit::POLICY_DENIAL, "no intent must exit 2: {output}");
    assert!(
        !output.contains(VALUE),
        "a refused consume delivered the value"
    );
    assert!(
        record_present(home.path(), agent),
        "a refused consume removed the record"
    );
}

#[test]
fn an_authorisation_for_another_version_is_refused_and_removes_nothing() {
    let home = tempfile::tempdir().unwrap();
    let agent = enrol(home.path());
    // A genuine admin signature over a *different* version: the signature
    // verifies, so only the coverage check can refuse this.
    let token = provision(home.path(), Some(2), agent);

    let (code, output) = ksp_in(
        home.path(),
        &[
            "run",
            "--consume",
            "--token",
            token.to_str().unwrap(),
            "--env",
            "KSP_TEST_SECRET",
            "--",
            "printenv",
            "KSP_TEST_SECRET",
        ],
    );

    assert_eq!(
        code,
        exit::UNCONSUMED_REFUSED,
        "an intent for another version must be refused: {output}"
    );
    assert!(
        !output.contains(VALUE),
        "a refused consume delivered the value"
    );
    assert!(
        record_present(home.path(), agent),
        "a refused consume removed the record"
    );
}

#[test]
fn a_delivered_child_cannot_write_outside_the_ruleset() {
    // The delivery happens in the process that confines itself, so the child it
    // launches inherits the ruleset. A write next to the store — inside this
    // test's own temporary directory, outside every rule — must be refused by the
    // kernel, not by a check the child could skip (WP18, and WP12's answer to
    // what a run's child may do: nothing outside the rules).
    let home = tempfile::tempdir().unwrap();
    let agent = enrol(home.path());
    let token = provision(home.path(), Some(1), agent);

    let escape = home.path().join("escape.txt");
    // The marker goes to stdout, which is an inherited descriptor and therefore
    // still writable. Without it a missing shell would look exactly like a
    // refusal, and this test would pass for the wrong reason.
    let command = format!("printf before; printf escaped > {}", escape.display());
    let (code, output) = ksp_in(
        home.path(),
        &[
            "run",
            "--consume",
            "--token",
            token.to_str().unwrap(),
            "--env",
            "KSP_TEST_SECRET",
            "--",
            "sh",
            "-c",
            &command,
        ],
    );

    assert_eq!(
        code,
        exit::LOST_FRESH_FETCH,
        "a child refused by the ruleset exits non-zero after the removal: {output}"
    );
    assert!(
        output.contains("before"),
        "the child never ran, so the denial below proves nothing: {output}"
    );
    assert!(
        !escape.exists(),
        "the confined child wrote outside the ruleset"
    );
}
