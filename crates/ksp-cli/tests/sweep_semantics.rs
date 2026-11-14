//! Sweep semantics, end to end through the binary.
//!
//! # What these prove that the backend unit tests cannot
//!
//! The backend tests decide what a sweep *should* do with a deadline. These
//! prove the command wires that decision to the store on this host: the version
//! that is due disappears, the live one stays, a second run reports an absence
//! rather than a second removal, a bounded run names its backlog, and the proof
//! the run signs carries the same counts. Nothing here needs a vault password:
//! the sweep reads paths and metadata only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ksp_backend::ArmingStore as _;
use ksp_backend::arming::ArmRecord;
use ksp_backend::proof::SignedSweepProof;
use ksp_cli::config::Layout;
use ksp_cli::exit;
use ksp_record::version::BlobStore as _;
use ksp_types::evidence::DeletionIntent;
use ksp_types::{ActorId, AgentId, BoundMetadata, Level, OpaqueSecretId, PrincipalId, VaultId};

/// The vault password every provisioning step in this file uses.
const PASSWORD: &str = "a long enough password";
/// The agent whose level the sweep removes from.
const AGENT: &str = "00000000-0000-4000-8000-000000000007";
/// The cadence the arming declares.
const INTERVAL_SECS: u64 = 300;

fn ksp() -> &'static str {
    env!("CARGO_BIN_EXE_ksp")
}

fn ksp_in(home: &Path, args: &[&str], stdin: Option<&str>) -> (i32, String) {
    let mut command = Command::new(ksp());
    command
        .env("KSP_HOME", home)
        .env("LC_ALL", "C")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = command.spawn().expect("the binary runs");
    if let Some(text) = stdin
        && let Err(error) = child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(text.as_bytes())
    {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe,
            "the input is written: {error}"
        );
    }
    let output = child.wait_with_output().expect("the binary finishes");
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.code().unwrap_or(-1), combined)
}

/// Initialise the deployment and enrol the user, through the binary.
fn provision(home: &Path) -> PrincipalId {
    let (code, output) = ksp_in(
        home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin init failed: {output}");
    let (code, output) = ksp_in(home, &["admin", "user", "add"], Some(PASSWORD));
    assert_eq!(code, exit::SUCCESS, "admin user add failed: {output}");
    ksp_cli::deployment::require(&Layout::new(home.to_path_buf()))
        .expect("the deployment is recorded")
        .0
        .user
}

/// The canonical scope for this deployment.
fn scope(owner: PrincipalId) -> String {
    format!("p/vault-1/{owner}/agent-*")
}

/// Record one schedule for this deployment, through the binary.
fn arm(home: &Path, scope: &str) {
    let delete = format!("delete:{scope}");
    let list = format!("list:{scope}");
    let (code, output) = ksp_in(
        home,
        &[
            "backend",
            "arm-sweep",
            "--interval",
            &format!("{INTERVAL_SECS}s"),
            "--scope",
            scope,
            "--credential",
            "unix:ksp-sweeper",
            "--grant",
            delete.as_str(),
            "--grant",
            list.as_str(),
            "--grant",
            "write:journal",
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "arm-sweep failed: {output}");
}

/// Seconds since the epoch, as the binary reads its own clock.
fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// One agent level's bound metadata for `version`.
fn metadata(owner: PrincipalId, agent: AgentId, version: u32) -> BoundMetadata {
    BoundMetadata {
        vault_id: VaultId::new("vault-1"),
        user_id: owner,
        level: Level::Agent(agent),
        secret_id: OpaqueSecretId::new("secret-1"),
        version,
    }
}

/// Arm one exact version, and optionally write the blob the arm names.
///
/// The intent authorises the admin collector, which is the actor the sweep
/// reports as (FR-018); the agent is not running at the deadline.
fn arm_version(
    layout: &Layout,
    owner: PrincipalId,
    agent: AgentId,
    version: u32,
    deadline: i64,
    with_record: bool,
) {
    let (deployment, anchor) = ksp_cli::deployment::require(layout).expect("a deployment");
    assert_eq!(deployment.user, owner);
    let metadata = metadata(owner, agent, version);
    let intent = DeletionIntent {
        intent_id: format!("intent-{version}"),
        vault_id: metadata.vault_id.clone(),
        user_id: owner,
        level: metadata.level.clone(),
        secret_id: metadata.secret_id.clone(),
        version,
        deadline,
        authorized_deleters: vec![ActorId::Admin(deployment.admin)],
    };
    let admin = ksp_cli::admin::load_admin(layout, &anchor).expect("the admin key loads");
    let signed = admin.with_secret(|seed| {
        ArmRecord::sign(
            format!("op-{version}"),
            intent,
            anchor.key_id.as_str().to_string(),
            None,
            &ed25519_dalek::SigningKey::from_bytes(seed),
        )
        .expect("the intent signs")
    });
    let store = ksp_cli::config::open_file_store(layout).expect("the store opens");
    store
        .arm_once(
            &format!("op-{version}"),
            &signed.to_bytes().expect("the arm record encodes"),
            deadline,
        )
        .expect("the arm is durable");
    if with_record {
        store
            .put_if_absent(
                ksp_record::RecordPath::of(&metadata).as_str(),
                b"the sealed record",
            )
            .expect("the record is written");
    }
}

/// The record path, for the test process to check existence.
fn record_path(layout: &Layout, owner: PrincipalId, agent: AgentId, version: u32) -> PathBuf {
    layout
        .store_root()
        .join(ksp_record::RecordPath::of(&metadata(owner, agent, version)).as_str())
}

/// The newest proof on disk, as the bytes that were signed.
fn newest_proof_file(layout: &Layout) -> PathBuf {
    let mut names: Vec<PathBuf> = std::fs::read_dir(layout.sweeper_proofs_dir())
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "cbor"))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names.pop().expect("the run wrote a proof")
}

/// The newest proof, decoded.
fn newest_proof(layout: &Layout) -> ksp_backend::proof::SweepProof {
    SignedSweepProof::from_bytes(&std::fs::read(newest_proof_file(layout)).unwrap())
        .expect("the proof decodes")
        .proof
}

/// Acceptance 6: the sweep removes a path, not every copy. A reader that already
/// held the record keeps what it read; a fresh fetch of the same version is gone
/// afterwards, and the live lease still reads. That is consume-is-not-exactly-
/// once, stated as the test it needs.
#[test]
fn a_copy_taken_before_the_sweep_survives_and_a_later_fetch_is_gone() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner));
    let layout = Layout::new(home.path().to_path_buf());
    let agent = AgentId::parse(AGENT).unwrap();
    let now = now_seconds();

    arm_version(&layout, owner, agent, 1, now - 10, true);
    arm_version(&layout, owner, agent, 2, now + 10_000, true);

    let store = ksp_cli::config::open_file_store(&layout).expect("the store opens");
    let due = ksp_record::RecordPath::of(&metadata(owner, agent, 1));
    let held = store
        .get(due.as_str())
        .expect("the store answers")
        .expect("the due version is there before the sweep");
    assert_eq!(held, b"the sealed record");

    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the sweep failed: {output}");

    assert_eq!(
        held, b"the sealed record",
        "a copy the reader already holds is not recalled by removing the path"
    );
    assert_eq!(
        store.get(due.as_str()).expect("the store answers"),
        None,
        "a fetch after the removal finds nothing at the version's path"
    );
    let live = ksp_record::RecordPath::of(&metadata(owner, agent, 2));
    assert!(
        store
            .get(live.as_str())
            .expect("the store answers")
            .is_some(),
        "the live lease still reads"
    );
}

/// TDD target Y: one removal out of three, and the proof says only what the run
/// did. It names no version, so a reader cannot use it to claim which copy is
/// gone — the per-version evidence is the signed actor report.
#[test]
fn the_proof_counts_one_removal_and_two_live_leases_without_naming_a_version() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner));
    let layout = Layout::new(home.path().to_path_buf());
    let agent = AgentId::parse(AGENT).unwrap();
    let now = now_seconds();

    arm_version(&layout, owner, agent, 1, now - 10, true);
    arm_version(&layout, owner, agent, 2, now + 10_000, true);
    arm_version(&layout, owner, agent, 3, now + 20_000, true);

    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the sweep failed: {output}");

    let proof = newest_proof(&layout);
    assert_eq!(proof.removed, 1, "one version was due");
    assert_eq!(proof.not_yet_due, 2, "two leases are still live");
    assert_eq!(proof.already_absent, 0, "nothing was missing");

    let signed = std::fs::read(newest_proof_file(&layout)).unwrap();
    let text = String::from_utf8_lossy(&signed);
    assert!(
        !text.contains("secret-1"),
        "the proof must not name the secret whose version went: {text}"
    );
}

/// Acceptance 1, 2 and 4: the due version goes, the live one stays, the second
/// run reports an absence, and the proof carries the same counts.
#[test]
fn a_gc_removes_only_the_due_version_and_the_proof_says_what_it_did() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner));
    let layout = Layout::new(home.path().to_path_buf());
    let agent = AgentId::parse(AGENT).unwrap();
    let now = now_seconds();

    // One past its deadline with a record, one live with a record. The live one
    // is written too: a sweep that deleted by looking at the set rather than the
    // deadline would take it.
    arm_version(&layout, owner, agent, 1, now - 10, true);
    arm_version(&layout, owner, agent, 2, now + 10_000, true);
    assert!(record_path(&layout, owner, agent, 1).exists());
    assert!(record_path(&layout, owner, agent, 2).exists());

    // No password, no stdin: the sweep reads paths and metadata only (T046).
    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the sweep failed: {output}");
    assert!(
        output.contains("removed=1") && output.contains("already_absent=0"),
        "one due version, and nothing was already gone: {output}"
    );
    assert!(
        output.contains("not_yet_due=1"),
        "the live lease is reported, not swept: {output}"
    );
    assert!(
        !record_path(&layout, owner, agent, 1).exists(),
        "the due version is gone"
    );
    assert!(
        record_path(&layout, owner, agent, 2).exists(),
        "a lease that has not expired stays"
    );

    let proof = newest_proof(&layout);
    assert!(proof.success, "the run completed");
    assert_eq!(proof.removed, 1);
    assert_eq!(proof.not_yet_due, 1);
    let deployment = ksp_cli::deployment::require(&layout)
        .expect("the deployment is recorded")
        .0;
    assert_eq!(
        proof.admin, deployment.admin,
        "the signed proof names the collector that wrote it"
    );
    assert_ne!(
        proof.admin, deployment.user,
        "the signed proof never attributes the run to the user whose records it swept"
    );
    assert!(
        proof.error_codes.is_empty(),
        "a clean sweep reports no error class"
    );

    // Acceptance 2: the arm record is still there, so a second run finds the same
    // due version absent and says so instead of counting a second removal.
    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the second sweep failed: {output}");
    assert!(
        output.contains("removed=0") && output.contains("already_absent=1"),
        "the second run observes an absence, not a removal: {output}"
    );
}

/// Acceptance 3 and misfit H: a bounded run names the backlog it left, so
/// "swept some" cannot read as "swept all".
#[test]
fn a_bounded_run_reports_the_backlog_it_left() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner));
    let layout = Layout::new(home.path().to_path_buf());
    let agent = AgentId::parse(AGENT).unwrap();
    let now = now_seconds();

    arm_version(&layout, owner, agent, 1, now - 300, true);
    arm_version(&layout, owner, agent, 2, now - 200, true);
    arm_version(&layout, owner, agent, 3, now - 100, true);

    let (code, output) = ksp_in(
        home.path(),
        &["secret", "purge-expired", "--limit", "1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the bounded run failed: {output}");
    assert!(
        output.contains("removed=1"),
        "the limit is one deletion: {output}"
    );
    assert!(
        output.contains("bound_reached=true"),
        "the bound stopped the run: {output}"
    );
    assert!(
        output.contains("backlog=2"),
        "two due versions remain, and the output says so: {output}"
    );
    assert!(
        output.contains("not a cleared backlog"),
        "the sentence says what the count means: {output}"
    );
    let remaining = (1..=3)
        .filter(|version| record_path(&layout, owner, agent, *version).exists())
        .count();
    assert_eq!(
        remaining, 2,
        "the earliest deadline went and the other two stayed"
    );
}

/// T046: the sweep asks for no vault password, and a closed stdin is not a
/// refusal. This is the shape the systemd unit runs with.
#[test]
fn a_sweep_needs_no_vault_password() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner));

    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);

    assert_eq!(code, exit::SUCCESS, "the keyless sweep failed: {output}");
    assert!(
        !output.to_lowercase().contains("password"),
        "the sweep must not ask for a secret it does not use: {output}"
    );
}
