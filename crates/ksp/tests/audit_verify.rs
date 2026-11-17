//! `ksp audit verify`, end to end through the real binary.
//!
//! # What these prove that the unit tests cannot
//!
//! The library decides what a finding *is* from pins it is handed. These prove the
//! wiring: the pins come from the anchor, the policy and the enrolments rather
//! than from the log, a tampered record is named at its index, a head digest kept
//! outside the log is what turns a silent truncation into a mismatch, and the
//! command needs no vault and no password.
//!
//! A verifier that trusted the record would pass the forgery test below, because
//! that record is internally consistent — which is exactly Misfit W.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ksp::config::Layout;
use ksp::exit;
use ksp_deletion::{AuditChain, EvidenceSigningKey, SignedAuditRecord};
use ksp_key_lifecycle::{KeyRoot, KeyStore};
use ksp_types::PrincipalId;
use ksp_types::evidence::{AuditComponent, AuditOperation, AuditRecord, Outcome};

/// The vault password every provisioning step in this file uses.
const PASSWORD: &str = "a long enough password";
/// The value stored where a test needs a record.
const VALUE: &str = "correct-horse-battery-staple";
/// The agent whose records one test signs.
const AGENT: &str = "agent-7";

fn ksp() -> &'static str {
    env!("CARGO_BIN_EXE_ksp")
}

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

fn ksp_in(home: &Path, args: &[&str], stdin: Option<&str>) -> (i32, String) {
    configure(home);
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
    if let Some(text) = stdin {
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(text.as_bytes())
            .expect("the input is written");
    }
    let output = child.wait_with_output().expect("the binary finishes");
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.code().unwrap_or(-1), combined)
}

fn password_file(home: &Path) -> PathBuf {
    let path = home.join("passphrase");
    std::fs::write(&path, PASSWORD).unwrap();
    path
}

/// A deployment with a user, an enrolled agent and one shared secret.
fn provision(home: &Path) {
    let (code, output) = ksp_in(
        home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin init failed: {output}");
    let (code, output) = ksp_in(home, &["admin", "user", "add"], Some(PASSWORD));
    assert_eq!(code, exit::SUCCESS, "admin user add failed: {output}");
    let (code, output) = ksp_in(home, &["agent", "enroll", "--agent", AGENT], None);
    assert_eq!(code, exit::SUCCESS, "agent enroll failed: {output}");
    let agent = agent_identity(home);
    let (code, output) = ksp_in(
        home,
        &[
            "admin",
            "policy",
            "--agent",
            agent.as_str(),
            "--secret",
            "secret-id-1",
        ],
        Some(PASSWORD),
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");
}

/// Store one secret as the user, which appends a user-signed record.
fn set_secret(home: &Path, id: &str) {
    let passphrase = password_file(home);
    let (code, output) = ksp_in(
        home,
        &[
            "secret",
            "set",
            id,
            "--name",
            "db_password",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "secret set failed: {output}");
}

fn layout(home: &Path) -> Layout {
    Layout::new(home.to_path_buf())
}

/// The UUID `agent enroll` minted, which is what the policy and the withdrawal name.
fn agent_identity(home: &Path) -> String {
    let mut identities = std::fs::read_dir(layout(home).enrolments_dir())
        .expect("the enrolments directory exists")
        .flatten()
        .filter_map(|entry| {
            entry
                .path()
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    identities.sort();
    identities.pop().expect("one agent was enrolled")
}

fn user(home: &Path) -> PrincipalId {
    ksp::deployment::require(&layout(home))
        .expect("the deployment is recorded")
        .0
        .user
}

fn admin_key_id(home: &Path) -> String {
    ksp::deployment::require(&layout(home))
        .expect("the deployment is recorded")
        .1
        .key_id
        .as_str()
        .to_string()
}

/// The segment the user's own key writes.
fn user_segment(home: &Path) -> PathBuf {
    let key_id = ksp::deployment::require(&layout(home))
        .expect("the deployment is recorded")
        .0
        .user_signing_key_id
        .expect("the deployment pins the user's signing key");
    AuditChain::new(layout(home).audit_root()).segment(user(home), key_id.as_str())
}

/// Sign one record as the enrolled agent and append it to the user's chain.
fn append_agent_record(home: &Path, operation: AuditOperation) {
    let layout = layout(home);
    let stored = ksp::keys::StoredEnrolment::load(&layout.enrolment_file(&agent_identity(home)))
        .expect("the pin reads");
    let store = KeyStore::new(KeyRoot::open(layout.agent_key_root()).expect("the key root opens"));
    let bundle = store
        .load_agent(&stored.pin())
        .expect("the agent key loads");
    let writer = EvidenceSigningKey::from_seed(bundle.with_signing_secret(|seed| *seed));
    let record = AuditRecord {
        actor: user(home),
        signer_key_id: stored.signing_key_id.as_str().to_string(),
        component: AuditComponent::Agent,
        operation,
        target: None,
        outcome: Outcome::Success,
        exit_code: 0,
        observed_at: 1_700_000_000,
        prev_digest: None,
        acceptance: None,
    };
    AuditChain::new(layout.audit_root())
        .append(&writer, user(home), stored.signing_key_id.as_str(), record)
        .expect("the agent record appends");
}

/// Re-write a segment's frames, which is the shape a tampering test edits.
fn write_frames(path: &Path, records: &[SignedAuditRecord]) {
    let mut bytes = Vec::new();
    for record in records {
        let body = record.to_bytes().unwrap();
        bytes.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&body);
    }
    std::fs::write(path, bytes).unwrap();
}

/// The head digest a clean run prints, which is what an operator writes down.
fn head(home: &Path) -> String {
    let (code, output) = ksp_in(home, &["audit", "verify", "--json"], None);
    assert_eq!(code, exit::SUCCESS, "verify failed: {output}");
    let document: serde_json::Value = serde_json::from_str(&output).expect("verify is JSON");
    document["heads"][0]["digest"]
        .as_str()
        .expect("the run prints a head")
        .to_string()
}

/// Acceptance 1 and Misfit V: an untouched log verifies, and the run still says
/// completeness is unknown. It never claims the log is whole.
#[test]
fn an_untouched_log_verifies_and_completeness_is_unknown() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    set_secret(home.path(), "secret-id-1");

    let (code, output) = ksp_in(home.path(), &["audit", "verify"], None);
    assert_eq!(code, exit::SUCCESS, "an untouched log verifies: {output}");
    assert!(
        output.contains("unpinned=0")
            && output.contains("invalid=0")
            && output.contains("mismatch=0"),
        "nothing is reported against a clean log: {output}"
    );
    assert!(
        output.contains("completeness unknown: no head digest was supplied from outside the log"),
        "the run must say completeness is unknown: {output}"
    );
    assert!(
        !output.contains("log valid") && !output.contains("log complete"),
        "verification must not claim coverage: {output}"
    );
}

/// Acceptance 2: editing one record's outcome is reported as an invalid signature
/// at its index, and the link the next record wrote stops resolving.
#[test]
fn an_edited_record_is_reported_at_its_index() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    set_secret(home.path(), "secret-id-1");
    set_secret(home.path(), "secret-id-2");

    let path = user_segment(home.path());
    let key_id = ksp::deployment::require(&layout(home.path()))
        .unwrap()
        .0
        .user_signing_key_id
        .unwrap();
    let mut records = AuditChain::new(layout(home.path()).audit_root())
        .read(user(home.path()), key_id.as_str())
        .expect("the segment reads");
    assert_eq!(records.len(), 2, "two user writes, two records");
    records[0].record.outcome = match records[0].record.outcome {
        Outcome::Success => Outcome::Failure,
        Outcome::Failure => Outcome::Success,
    };
    write_frames(&path, &records);

    let (code, output) = ksp_in(home.path(), &["audit", "verify"], None);
    assert_eq!(
        code,
        exit::AUDIT_UNVERIFIED,
        "a tampered log is a nonzero class of its own: {output}"
    );
    assert!(
        output.contains("invalid=1"),
        "exactly the edited record is invalid: {output}"
    );
    assert!(
        output.contains("chain=broken"),
        "the link after the edit stops resolving: {output}"
    );
}

/// Acceptance 3 and Misfit W: a record signed by an unpinned key is reported
/// unpinned, even in a file named after the admin's key.
#[test]
fn a_record_signed_by_an_unpinned_key_is_unpinned_not_invalid() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    set_secret(home.path(), "secret-id-1");

    let attacker = EvidenceSigningKey::generate();
    let forged = SignedAuditRecord::sign(
        &attacker,
        AuditRecord {
            actor: user(home.path()),
            signer_key_id: "attacker-2026".to_string(),
            component: AuditComponent::CommandLine,
            operation: AuditOperation::Put,
            target: None,
            outcome: Outcome::Success,
            exit_code: 0,
            observed_at: 1_700_000_000,
            prev_digest: None,
            acceptance: None,
        },
    )
    .unwrap();
    // The file name claims the admin's key. The verifier must not read it.
    let decoy = layout(home.path())
        .audit_root()
        .join(user(home.path()).to_string())
        .join(format!("segment-{}.cbor", admin_key_id(home.path())));
    write_frames(&decoy, &[forged]);

    let (code, output) = ksp_in(home.path(), &["audit", "verify"], None);
    assert_eq!(
        code,
        exit::AUDIT_UNVERIFIED,
        "the finding is nonzero: {output}"
    );
    assert!(
        output.contains("unpinned=1"),
        "the stranger is reported unpinned: {output}"
    );
    assert!(
        !output.contains("invalid=1"),
        "an unknown signer is not the same finding as a bad signature: {output}"
    );
}

/// Acceptance 4 and FR-052: a record signed by a key whose grant was withdrawn
/// still verifies, and the report carries the policy revision that revoked it.
#[test]
fn a_revoked_signer_is_reported_with_the_policy_revision() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    set_secret(home.path(), "secret-id-1");
    append_agent_record(home.path(), AuditOperation::Deliver);

    let (code, output) = ksp_in(home.path(), &["audit", "verify"], None);
    assert_eq!(code, exit::SUCCESS, "the agent record verifies: {output}");
    assert!(
        output.contains("revoked=0"),
        "no grant is withdrawn yet: {output}"
    );

    let (code, output) = ksp_in(
        home.path(),
        &[
            "admin",
            "revoke",
            "--agent",
            agent_identity(home.path()).as_str(),
        ],
        Some(PASSWORD),
    );
    assert_eq!(code, exit::SUCCESS, "admin revoke failed: {output}");

    let (code, output) = ksp_in(home.path(), &["audit", "verify"], None);
    assert_eq!(
        code,
        exit::SUCCESS,
        "a revoked signature still verifies cryptographically: {output}"
    );
    assert!(
        output.contains("revoked=1"),
        "the withdrawn grant is counted: {output}"
    );
    assert!(
        output.contains("withdrawn (revision "),
        "the note names the policy revision that withdrew the grant: {output}"
    );
}

/// Misfit X: two writers produce two segments, and neither is a fork.
#[test]
fn two_writers_do_not_produce_a_fork() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    set_secret(home.path(), "secret-id-1");
    append_agent_record(home.path(), AuditOperation::Deliver);

    let (code, output) = ksp_in(home.path(), &["audit", "verify"], None);
    assert_eq!(code, exit::SUCCESS, "both segments verify: {output}");
    assert!(
        output.contains("segments=3") || output.contains("segments=2"),
        "the admin, the user and the agent write separate segments: {output}"
    );
    assert!(
        !output.contains("fork"),
        "two writers must not be reported as a fork: {output}"
    );
}

/// Acceptance 6 and Misfit V: removing the tail leaves no finding until a head
/// digest from outside the log is supplied, and then it is a mismatch.
#[test]
fn a_truncated_tail_is_only_reported_against_a_supplied_head() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    set_secret(home.path(), "secret-id-1");
    set_secret(home.path(), "secret-id-2");
    let recorded = head(home.path());

    // Drop the last frame the user wrote: a shorter chain, still internally valid.
    let path = user_segment(home.path());
    let key_id = ksp::deployment::require(&layout(home.path()))
        .unwrap()
        .0
        .user_signing_key_id
        .unwrap();
    let mut records = AuditChain::new(layout(home.path()).audit_root())
        .read(user(home.path()), key_id.as_str())
        .expect("the segment reads");
    records.pop().expect("the segment has a tail");
    write_frames(&path, &records);

    let (code, output) = ksp_in(home.path(), &["audit", "verify"], None);
    assert_eq!(
        code,
        exit::SUCCESS,
        "without a head, a short chain is indistinguishable from a whole one: {output}"
    );
    assert!(
        !output.contains("truncat"),
        "the run must not invent a truncation finding it cannot support: {output}"
    );

    let (code, output) = ksp_in(
        home.path(),
        &["audit", "verify", "--head", recorded.as_str()],
        None,
    );
    assert_eq!(
        code,
        exit::AUDIT_UNVERIFIED,
        "the supplied head no longer matches: {output}"
    );
    assert!(
        output.contains("head mismatch") && output.contains("completeness cannot be established"),
        "the mismatch is named and completeness is refused: {output}"
    );
}

/// Acceptance 7 and NFR-010: verification works from public material only, and
/// does not read a password file even when one is named in the environment.
#[test]
fn verification_needs_only_public_material() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    set_secret(home.path(), "secret-id-1");

    // A home holding the pins and the log, and nothing secret.
    let public = tempfile::tempdir().unwrap();
    for file in ["deployment.cbor", "admin-anchor.cbor", "policy.cbor"] {
        std::fs::copy(home.path().join(file), public.path().join(file))
            .unwrap_or_else(|error| panic!("{file} copies: {error}"));
    }
    for directory in ["enrolments", "audit"] {
        copy_tree(&home.path().join(directory), &public.path().join(directory));
    }
    // The principal registry is public material too: a current deployment's
    // verifier reads it from the store, and a home without one is the pre-014
    // layout the gate refuses. Copying it keeps this test about what verification
    // needs, not about which layout the fixture happened to build.
    copy_tree(&home.path().join("store"), &public.path().join("store"));
    assert!(
        !public.path().join("vault.cbor").exists(),
        "the third-party home must hold no vault"
    );

    let mut command = Command::new(ksp());
    let output = command
        .env("KSP_HOME", public.path())
        // A path that cannot be opened as a password file: a verifier that reads
        // it fails, which is the point.
        .env("KSP_PASSPHRASE_FILE", public.path().join("not-a-file"))
        .args(["audit", "verify"])
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code().unwrap_or(-1),
        exit::SUCCESS,
        "verification must need no vault and no password: {combined}"
    );
    assert!(
        !combined.contains("password") && !combined.contains("vault"),
        "the run must not ask for a secret: {combined}"
    );
}

/// T053: verification is read-only. The bytes and modes under `audit/` are the
/// same before and after.
#[test]
fn verification_does_not_change_the_log() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    set_secret(home.path(), "secret-id-1");
    let before = snapshot(&layout(home.path()).audit_root());

    let (code, output) = ksp_in(home.path(), &["audit", "verify"], None);
    assert_eq!(code, exit::SUCCESS, "verify failed: {output}");

    assert_eq!(
        before,
        snapshot(&layout(home.path()).audit_root()),
        "verification must not write, repair, re-sign or reorder the log"
    );
}

/// Every file's relative path, bytes and mode, in a stable order.
fn snapshot(root: &Path) -> Vec<(String, Vec<u8>, u32)> {
    use std::os::unix::fs::PermissionsExt;

    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
            files.push((relative, std::fs::read(&path).unwrap(), mode));
        }
    }
    files.sort();
    files
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let path = entry.path();
        let target = to.join(entry.file_name());
        if path.is_dir() {
            copy_tree(&path, &target);
        } else {
            std::fs::copy(&path, &target).unwrap();
        }
    }
}

/// T051: the first record of each finding class is named, not just counted.
#[test]
fn each_finding_names_the_first_record_it_was_seen_at() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    set_secret(home.path(), "secret-id-1");
    set_secret(home.path(), "secret-id-2");

    // Edit the first record: invalid at index 0, and the chain breaks there.
    let path = user_segment(home.path());
    let key_id = ksp::deployment::require(&layout(home.path()))
        .unwrap()
        .0
        .user_signing_key_id
        .unwrap();
    let mut records = AuditChain::new(layout(home.path()).audit_root())
        .read(user(home.path()), key_id.as_str())
        .expect("the segment reads");
    records[0].record.exit_code = 1;
    write_frames(&path, &records);

    let (code, output) = ksp_in(home.path(), &["audit", "verify"], None);
    assert_eq!(
        code,
        exit::AUDIT_UNVERIFIED,
        "the finding is nonzero: {output}"
    );
    assert!(
        output.contains("first invalid: ") && output.contains("at index 0"),
        "the report names where the first invalid record is: {output}"
    );
    assert!(
        output.contains("chain=broken") && output.contains("signature at index 0"),
        "the break names the edited record: {output}"
    );
}

/// A log copied without a policy cannot pin the user's key, and the run says so
/// instead of leaving an unpinned count unexplained.
#[test]
fn a_missing_policy_is_disclosed_when_the_users_key_cannot_be_pinned() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    set_secret(home.path(), "secret-id-1");

    let public = tempfile::tempdir().unwrap();
    for file in ["deployment.cbor", "admin-anchor.cbor"] {
        std::fs::copy(home.path().join(file), public.path().join(file)).unwrap();
    }
    for directory in ["enrolments", "audit"] {
        copy_tree(&home.path().join(directory), &public.path().join(directory));
    }

    let (code, output) = ksp_in(public.path(), &["audit", "verify"], None);
    assert_eq!(
        code,
        exit::AUDIT_UNVERIFIED,
        "the user's records cannot be pinned without a policy: {output}"
    );
    assert!(
        output.contains("unpinned=1"),
        "the user's record is unpinned, not invalid: {output}"
    );
    assert!(
        output.contains("no policy signed by the admin is present"),
        "the report explains the missing pin: {output}"
    );
}

/// The issuance ledger `audit verify` actually reads: the store path.
///
/// Resolved through `LedgerPaths` rather than assembled by hand, because the point of
/// the test is the file the verifier opens, and a fixture that built its own path would
/// pass while the verifier read somewhere else.
fn deployment_ledger(home: &std::path::Path) -> std::path::PathBuf {
    let layout = layout(home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    ksp::ledgers::LedgerPaths::for_deployment(&layout, &deployment)
        .issuance()
        .to_path_buf()
}

/// A ledger this run cannot parse must not make every agent look current: the
/// verifier refuses rather than claiming a status it cannot establish.
#[test]
fn an_unreadable_ledger_refuses_rather_than_calling_agents_current() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    set_secret(home.path(), "secret-id-1");
    std::fs::write(deployment_ledger(home.path()), b"this is not a ledger").unwrap();

    let (code, output) = ksp_in(home.path(), &["audit", "verify"], None);
    assert_eq!(
        code,
        exit::MISSING_KEY,
        "pins that cannot be established are missing key material: {output}"
    );
    assert!(
        output.contains("issuance ledger could not be read"),
        "the refusal names the file it could not read: {output}"
    );
}

/// One entry the walk cannot name does not hide the records it can read, and it
/// does not pass as a clean run.
#[test]
fn an_unnamed_entry_is_counted_without_hiding_the_rest() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    set_secret(home.path(), "secret-id-1");
    std::fs::create_dir_all(layout(home.path()).audit_root().join("not-a-principal")).unwrap();

    let (code, output) = ksp_in(home.path(), &["audit", "verify"], None);
    assert_eq!(
        code,
        exit::AUDIT_UNVERIFIED,
        "an entry the run cannot name is not a clean run: {output}"
    );
    assert!(
        output.contains("unreadable=1") && output.contains("valid=1"),
        "the records it could read still verify: {output}"
    );
    assert!(
        output.contains("could not read") && output.contains("not-a-principal"),
        "the entry is named: {output}"
    );
}

/// Misfit W in the output: the chain is named for the signer that verified, not
/// for the file it happens to live in.
#[test]
fn a_chain_is_named_for_its_verified_signer_not_its_file() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    set_secret(home.path(), "secret-id-1");

    let from = user_segment(home.path());
    let decoy = from
        .parent()
        .unwrap()
        .join(format!("segment-{}.cbor", admin_key_id(home.path())));
    std::fs::rename(&from, &decoy).unwrap();

    let (code, output) = ksp_in(home.path(), &["audit", "verify"], None);
    assert_eq!(
        code,
        exit::SUCCESS,
        "the moved segment still verifies: {output}"
    );
    assert!(
        output.contains("/alice-ed25519-1="),
        "the head names the key that verified, not the file: {output}"
    );
    assert!(
        !output.contains(&format!("/{}=", admin_key_id(home.path()))),
        "the decoy file name does not become the chain identity: {output}"
    );
}

/// A head that is not a digest is a usage error, not a finding about the log.
#[test]
fn a_malformed_head_digest_is_refused_before_the_log_is_read() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    set_secret(home.path(), "secret-id-1");

    let (code, output) = ksp_in(
        home.path(),
        &["audit", "verify", "--head", "not-a-digest"],
        None,
    );
    assert_eq!(code, 2, "a usage error exits 2: {output}");
    assert!(
        output.contains("a head digest is 64 hex characters"),
        "the parser says what a head looks like: {output}"
    );
    assert!(
        !output.contains("head mismatch"),
        "a typo must not read as a deleted tail: {output}"
    );
}

/// A supplied head that matches a pre-break record is not a completeness claim:
/// the chain stopped before the log did, and the run says so.
#[test]
fn a_matched_head_on_a_broken_chain_still_refuses_completeness() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    set_secret(home.path(), "secret-id-1");
    set_secret(home.path(), "secret-id-2");

    let key_id = ksp::deployment::require(&layout(home.path()))
        .unwrap()
        .0
        .user_signing_key_id
        .unwrap();
    let chain = AuditChain::new(layout(home.path()).audit_root());
    let mut records = chain
        .read(user(home.path()), key_id.as_str())
        .expect("the segment reads");
    let first = hex(&records[0].digest());

    // Edit the tail: the walk reaches record 0 and stops at the edited record.
    records[1].record.exit_code = 1;
    write_frames(&user_segment(home.path()), &records);

    let (code, output) = ksp_in(
        home.path(),
        &["audit", "verify", "--head", first.as_str()],
        None,
    );
    assert_eq!(
        code,
        exit::AUDIT_UNVERIFIED,
        "the chain is broken: {output}"
    );
    assert!(
        output.contains("matches the last record this run could reach")
            && output.contains("completeness cannot be established"),
        "a matched head on a broken chain is not coverage: {output}"
    );
}

/// Lowercase hex, so a test can write down a digest the way the command prints it.
fn hex(bytes: &[u8]) -> String {
    let mut text = String::new();
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}
