//! `ksp status` as one document, end to end through the binary.
//!
//! # What these prove that a unit test cannot
//!
//! The document is the only place an operator learns what the host can and cannot
//! observe. These tests drive three homes (nothing recorded, armed but never run,
//! proven), one disagreement between the declaration and the proof, and the three
//! unobservable facts the design requires to print `unknown` rather than a default.
//!
//! The forbidden-phrasing test is deliberately about *claims*: a disclosure that says
//! a schedule is not a timing promise contains neither a guarantee nor a lag, and the
//! list of words it greps for is the list of things a status line may not assert.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ksp_backend::proof::{SignedSweepProof, SweepProof};
use ksp_cli::config::Layout;
use ksp_cli::exit;
use ksp_types::evidence::{AuditComponent, AuditOperation, Outcome};
use ksp_types::{AgentId, OpaqueSecretId, PrincipalId};

/// The vault password every invocation in this file uses.
const PASSWORD: &str = "a long enough password";
/// The record the delivery copies.
const SECRET: &str = "s3cr3t-id-1";
/// The cadence the arming declares and the run is expected to prove.
const INTERVAL_SECS: u64 = 300;

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
fn arm(home: &Path, scope: &str, interval: &str, replace: bool) {
    let delete = format!("delete:{scope}");
    let list = format!("list:{scope}");
    let mut args = vec![
        "backend",
        "arm-sweep",
        "--interval",
        interval,
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
    ];
    if replace {
        args.push("--replace");
    }
    let (code, output) = ksp_in(home, &args, None);
    assert_eq!(code, exit::SUCCESS, "arm-sweep failed: {output}");
}

/// Grant the agent the record, write the record, and return the agent's UUID.
fn enrol_and_grant(home: &Path) -> AgentId {
    let layout = Layout::new(home.to_path_buf());
    let agent = ksp_cli::agent::enroll("deploy-bot", &layout)
        .expect("the agent enrols")
        .enrolment
        .identity;
    ksp_cli::admin::policy(&layout, vec![agent], vec![OpaqueSecretId::new(SECRET)])
        .expect("the policy grants the agent the record");
    ksp_cli::secret::set(
        &layout,
        PASSWORD.as_bytes(),
        &OpaqueSecretId::new(SECRET),
        b"db_password",
        b"correct-horse",
    )
    .expect("the user writes the record");
    agent
}

/// Ask for a lease of `ttl` seconds through the binary.
fn lease(home: &Path, agent: AgentId, ttl: u64, out: &Path) -> (i32, String) {
    ksp_in(
        home,
        &[
            "token",
            "mint",
            "--agent",
            &agent.to_string(),
            "--secret",
            SECRET,
            "--name",
            "db_password",
            "--ttl",
            &ttl.to_string(),
            "--out",
            out.to_str().expect("a utf-8 path"),
        ],
        Some(PASSWORD),
    )
}

/// Seconds since the epoch, as the binary reads its own clock.
fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Build and write one proof, signed by whichever key the caller holds.
fn write_proof(layout: &Layout, run_end: i64, signer: &ed25519_dalek::SigningKey, key_id: &str) {
    let (deployment, _) = ksp_cli::deployment::require(layout).expect("the deployment exists");
    let proof = SweepProof {
        scope: ksp_cli::admission::deployment_scope(&deployment),
        arming_id: Some("systemd:file".to_string()),
        admin: deployment.admin,
        run_start: run_end - 4,
        run_end,
        declared_interval_secs: Some(INTERVAL_SECS),
        realised_interval_secs: None,
        success: true,
        removed: 0,
        already_absent: 0,
        not_yet_due: 0,
        bound_reached: false,
        error_codes: Vec::new(),
        signer_key_id: key_id.to_string(),
        prev_digest: None,
    };
    let signed = SignedSweepProof::sign(proof, signer).expect("the proof signs");
    ksp_backend::proof::write(&layout.sweeper_proofs_dir(), &signed).expect("the proof is written");
}

/// The mode of one path, for a test that changes it and puts it back.
fn mode_of(path: &Path) -> u32 {
    metadata(path).permissions().mode()
}

fn set_mode(path: &Path, mode: u32) {
    let mut permissions = metadata(path).permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(path, permissions).expect("the mode is set");
}

fn metadata(path: &Path) -> std::fs::Metadata {
    std::fs::metadata(path).expect("the path exists")
}

/// Acceptance 1: the three homes are three distinguishable documents.
#[test]
fn three_homes_produce_three_distinguishable_documents() {
    // A home that was never provisioned: every absence is named with its own reason.
    let bare = tempfile::tempdir().unwrap();
    let (code, no_home) = ksp_in(bare.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {no_home}");
    assert!(
        no_home.contains("arming:      none (this host has no deployment"),
        "an unprovisioned home records no schedule: {no_home}"
    );
    assert!(
        no_home.contains("proof:       none (this host has no deployment"),
        "and it holds no proof: {no_home}"
    );
    assert!(
        no_home.contains("audit:       unknown (this host has no deployment"),
        "with nothing to verify against, the head is unknown rather than absent: {no_home}"
    );

    // Armed, never run: the declaration is disclosed and the proof is absent.
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner), "300s", false);
    let (code, armed) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {armed}");
    // The default kind follows the host, so the recorded schedule a bare arm
    // produces is named differently on each platform. Both are the local store's
    // own scheduler: a Mac has no systemd, and a systemd unit on one is a job
    // nobody can install.
    let expected = if cfg!(target_os = "macos") {
        "launchd com.keyspout.sweep"
    } else {
        "systemd ksp-sweep.service"
    };
    assert!(
        armed.contains(&format!("arming:      {expected}, declared 300s")),
        "the recorded schedule is named as the host's own kind ({expected}): {armed}"
    );
    assert!(
        armed.contains("proof:       none (no sweep proof exists"),
        "an arming is not evidence, and status says so: {armed}"
    );
    assert!(
        !armed.contains("proven:      300s"),
        "a declaration must never print as a proven cadence: {armed}"
    );

    // Proven: one run supplies the window, the age and the fresh state.
    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the sweep run failed: {output}");
    let (code, proven) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {proven}");
    assert!(
        proven.contains("proven:      300s"),
        "the run's cadence is the proven one: {proven}"
    );
    assert!(
        proven.contains("run window:  "),
        "the run window is printed beside the age: {proven}"
    );
    assert!(
        proven.contains("proof state: fresh"),
        "a fresh proof says it is fresh: {proven}"
    );

    for (left, right) in [(&no_home, &armed), (&armed, &proven), (&no_home, &proven)] {
        assert_ne!(left, right, "the three homes are three documents");
    }
}

/// Acceptance 2 and FR-057: a disagreement names both intervals, and the decision
/// uses the proven one.
#[test]
fn a_disagreement_names_both_intervals_and_admission_uses_the_proven_one() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    // A run under a 60s declaration proves 60s.
    arm(home.path(), &scope(owner), "60s", false);
    let agent = enrol_and_grant(home.path());
    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the sweep run failed: {output}");
    // The operator re-arms for 300s; the proof still establishes 60s.
    arm(home.path(), &scope(owner), "300s", true);

    let (code, output) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    assert!(
        output.contains("cadence:     300s (declared)"),
        "the declaration is named: {output}"
    );
    assert!(
        output.contains("proven:      60s"),
        "the proof's interval is named beside it: {output}"
    );
    assert!(
        output.contains(
            "disagreement: the arming declares 300s and the newest proof establishes 60s, so \
             admission uses 60s"
        ),
        "the disagreement is stated, not averaged: {output}"
    );

    // The decision, not just the text: 120s is 2 x 60 and far below 2 x 300.
    let token = home.path().join("deploy-bot.token");
    let (code, output) = lease(home.path(), agent, 120, &token);
    assert_eq!(
        code,
        exit::SUCCESS,
        "admission must use the proven 60s, not the declared 300s: {output}"
    );
    let below = home.path().join("below.token");
    let (code, output) = lease(home.path(), agent, 119, &below);
    assert_eq!(
        code,
        exit::CAPABILITY_REFUSAL,
        "119s is below 2 x 60s: {output}"
    );
    assert!(!below.exists(), "a refused mint leaves no token");
}

/// Acceptance 3 and T056: an unreadable proof directory and an unreadable log each
/// print `unknown` with a reason, and the reasons are different.
#[test]
fn an_unreadable_proof_directory_and_an_unreadable_log_print_unknown_with_reasons() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner), "300s", false);
    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the sweep run failed: {output}");
    let layout = Layout::new(home.path().to_path_buf());

    // An unreadable proof directory is not an absent proof.
    let proofs = layout.sweeper_proofs_dir();
    let original = mode_of(&proofs);
    set_mode(&proofs, 0o000);
    let (code, output) = ksp_in(home.path(), &["status"], None);
    set_mode(&proofs, original);
    assert_eq!(
        code,
        exit::SUCCESS,
        "status discloses rather than fails: {output}"
    );
    assert!(
        output.contains(
            "proof:       none (the sweep proof directory could not be read, so no proof can be \
             verified)"
        ),
        "the reason names the directory, not a missing run: {output}"
    );
    // The line below it must not claim there was no failure: the directory that
    // could hide one is the directory that could not be read.
    assert!(
        output.contains("newest failure: unknown (the sweep proof directory could not be read"),
        "an unreadable directory cannot rule a failure out: {output}"
    );
    assert!(
        !output.contains("newest failure: none ("),
        "and it must not say none: {output}"
    );
    assert!(
        !output.contains("no sweep proof exists"),
        "an unreadable directory must not read as 'nothing was ever written': {output}"
    );

    // One audit record so the root exists, then make it unreadable.
    ksp_cli::audit::record_admin(
        &layout,
        AuditComponent::CommandLine,
        AuditOperation::Init,
        None,
        Outcome::Success,
        exit::SUCCESS,
    )
    .expect("the record is written");
    let audit = layout.audit_root();
    let original = mode_of(&audit);
    set_mode(&audit, 0o000);
    let (code, output) = ksp_in(home.path(), &["status"], None);
    set_mode(&audit, original);
    assert_eq!(
        code,
        exit::SUCCESS,
        "status discloses rather than fails: {output}"
    );
    assert!(
        output.contains("audit:       unknown (the audit log could not be read"),
        "an unreadable log has no head, and says why: {output}"
    );

    // With the mode restored the same log does have a head.
    let (code, output) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    assert!(
        output.contains("records in 1 segment(s), 1 chain(s)"),
        "a readable log names its head: {output}"
    );
    assert!(
        output.contains("head ") && output.contains("a head is not an external checkpoint"),
        "a head is printed with what it does not prove: {output}"
    );
}

/// Acceptance 4 and misfit I: the passphrase line is the deliverable.
#[test]
fn the_passphrase_line_is_present_verbatim_and_claims_only_the_file_at_rest() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());

    let (code, output) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    assert!(
        output.contains(
            "passphrase:  protects the key file at rest; does not protect a process that already \
             holds the key, a captured ciphertext pair, or a same-UID process that is not confined"
        ),
        "the claim names what it protects and what it does not: {output}"
    );
    for overclaim in [
        "cannot read",
        "cannot open",
        "the agent cannot",
        "protects the vault",
    ] {
        assert!(
            !output.contains(overclaim),
            "the passphrase claim must not imply {overclaim:?}: {output}"
        );
    }
}

/// Acceptance 5 and FR-056: the newest failure is visible and changes nothing.
#[test]
fn a_failed_run_is_shown_and_does_not_change_the_admitted_interval() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner), "300s", false);
    let agent = enrol_and_grant(home.path());
    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the first run failed: {output}");
    let layout = Layout::new(home.path().to_path_buf());

    // A run that cannot arm its intent fails, which is a second proof.
    let intents = layout.store_root().join("intents");
    std::fs::create_dir_all(&intents).unwrap();
    std::fs::write(intents.join("not-cbor"), b"\xff\xff not an arm record").unwrap();
    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::DELETE_FAILED, "the run must fail: {output}");

    let (code, output) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    assert!(
        output.contains("newest failure: run ") && output.contains("codes ["),
        "the newest failed run and its codes are shown: {output}"
    );
    assert!(
        output.contains("a failed run does not change the admitted interval"),
        "and status says what the failure did not do: {output}"
    );
    assert!(
        output.contains("proven:      300s") && output.contains("capability:  Scheduled"),
        "the success before the failure still decides: {output}"
    );

    // The decision agrees with the text: the interval did not move.
    let token = home.path().join("deploy-bot.token");
    let (code, output) = lease(home.path(), agent, INTERVAL_SECS * 2, &token);
    assert_eq!(
        code,
        exit::SUCCESS,
        "a failed run must not extend or shorten the clock: {output}"
    );
}

/// Acceptance 6, FR-009 and FR-035: no line claims erasure, a lag or a guarantee.
#[test]
fn no_status_line_claims_erasure_a_lag_or_a_guarantee() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner), "300s", false);
    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the sweep run failed: {output}");

    let (code, output) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    let lowered = output.to_lowercase();
    for forbidden in [
        "guarantee",
        "guaranteed",
        "erasure",
        "erased",
        "max lag",
        "maximum lag",
        "worst case",
        "worst-case",
        "upper bound",
        "no later than",
        "ensures",
        "will be deleted",
    ] {
        assert!(
            !lowered.contains(forbidden),
            "status must not claim {forbidden:?}: {output}"
        );
    }

    // The disclaimers are presence, not absence: an empty document would pass above.
    assert!(
        output.contains("not a timing promise"),
        "the floor is stated as policy: {output}"
    );
    assert!(
        output.contains("not evidence that a sweep completed"),
        "a trigger is not a sweep: {output}"
    );
    assert!(
        output.contains("a head is not an external checkpoint"),
        "a head is not completeness: {output}"
    );
    assert!(
        output.contains("cleanup lag: unknown"),
        "the lag is present and unknown: {output}"
    );
}

/// Misfits D and N: a stale proof prints its age and window, and the capability drops
/// rather than looking healthy.
#[test]
fn a_stale_proof_shows_its_age_and_run_window_and_downgrades_the_capability() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner), "300s", false);
    let layout = Layout::new(home.path().to_path_buf());
    let (_, anchor) = ksp_cli::deployment::require(&layout).unwrap();
    let admin = ksp_cli::admin::load_admin(&layout, &anchor).unwrap();

    // A proof from an hour ago: `I + grace` for 300s is 450s, so it is stale.
    let now = now_seconds();
    admin.with_secret(|seed| {
        let signer = ed25519_dalek::SigningKey::from_bytes(seed);
        write_proof(&layout, now - 3_600, &signer, anchor.key_id.as_str());
    });

    let (code, output) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    assert!(
        output.contains("run window:  "),
        "the window is printed, not just the age: {output}"
    );
    assert!(
        output.contains("proof state: stale (age 36"),
        "the stale state carries its age: {output}"
    );
    assert!(
        output.contains("which is lateness and not a copy that lasted longer"),
        "lateness is not obsolescence: {output}"
    );
    assert!(
        output.contains("capability:  None"),
        "a stale proof admits nothing: {output}"
    );
}

/// Misfit M: a proof whose signature is not the pinned admin's is unverifiable.
#[test]
fn a_proof_that_does_not_verify_is_unknown_and_never_scheduled() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner), "300s", false);
    let layout = Layout::new(home.path().to_path_buf());

    write_proof(
        &layout,
        now_seconds(),
        &ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]),
        "not-the-admin",
    );

    let (code, output) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    assert!(
        output.contains("does not verify against any pinned key"),
        "the proof is unverifiable, not absent: {output}"
    );
    assert!(
        output.contains("proven:      none"),
        "an unverifiable proof proves no cadence: {output}"
    );
    assert!(
        output.contains("capability:  None"),
        "and it admits nothing: {output}"
    );
}

/// FR-005 and FR-006: the next elapse and the last trigger are `unknown` with a
/// reason when this build does not interrogate the host.
#[test]
fn the_next_elapse_and_last_trigger_are_unknown_with_a_reason() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner), "300s", false);

    let (code, output) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    assert!(
        output.contains("unit:        unknown (this build records the query"),
        "the unit state says it was not interrogated: {output}"
    );
    assert!(
        output.contains("next elapse: unknown (this build records the query"),
        "and so does the elapse: {output}"
    );
    assert!(
        output.contains("last trigger: unknown (this build records the query"),
        "and the trigger: {output}"
    );
    assert!(
        output.contains("trigger note: a last trigger is when the manager started the job"),
        "the trigger is not evidence of a sweep: {output}"
    );
}

/// The proof files a status run cannot decode are counted, not hidden.
#[test]
fn a_proof_file_that_cannot_be_decoded_is_counted() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner), "300s", false);
    let layout = Layout::new(home.path().to_path_buf());
    std::fs::create_dir_all(layout.sweeper_proofs_dir()).unwrap();
    // `<run_end:010>-<hex>.cbor` is the name the scan reads.
    let path: PathBuf = layout.sweeper_proofs_dir().join("0000000001-deadbeef.cbor");
    std::fs::write(&path, b"\xff\xff not a proof").unwrap();

    let (code, output) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    assert!(
        output.contains("proof files:  1 could not be decoded and were skipped"),
        "a skipped proof is counted: {output}"
    );
}

/// The JSON document carries the same facts: a scripted reader is a reader, and a
/// fact that only the text branch knows would be a second source of truth.
#[test]
fn the_json_document_carries_the_same_facts() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner), "300s", false);
    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the sweep run failed: {output}");

    let (code, output) = ksp_in(home.path(), &["status", "--json"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    let document: serde_json::Value =
        serde_json::from_str(output.trim()).expect("status --json is one object");

    assert!(document["arming"]["Recorded"].is_object(), "{document}");
    assert_eq!(
        document["proof"]["newest_success"]["declared_interval_secs"], 300,
        "the run's own interval is in the document: {document}"
    );
    assert!(
        document["proof"]["freshness"].is_string(),
        "the freshness is named, not implied: {document}"
    );
    assert!(
        document["audit"]["chains"][0]["digest"].is_string(),
        "the head is in the document: {document}"
    );
    assert_eq!(
        document["passphrase"],
        ksp_backend::status::PASSPHRASE_SENTENCE,
        "the claim is the same sentence in both branches"
    );
}

/// A deployment record that exists and cannot be read is not an absent one.
#[test]
fn a_deployment_record_that_cannot_be_read_is_not_reported_as_absent() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    let layout = Layout::new(home.path().to_path_buf());
    std::fs::write(layout.deployment_file(), b"\xff\xff not a deployment").unwrap();

    let (code, output) = ksp_in(home.path(), &["status"], None);
    assert_eq!(
        code,
        exit::SUCCESS,
        "status discloses rather than fails: {output}"
    );
    assert!(
        output
            .contains("arming:      none (the deployment record could not be read as this host's"),
        "the schedule says the record could not be read: {output}"
    );
    assert!(
        output
            .contains("proof:       none (the deployment record could not be read as this host's"),
        "and so does the proof: {output}"
    );
    assert!(
        output.contains(
            "audit:       unknown (the deployment record could not be read as this host's"
        ),
        "and the head: {output}"
    );
    assert!(
        !output.contains("this host has no deployment"),
        "a corrupt record is not an absent one: {output}"
    );
}

/// A head over records no pin holds is printed with the count it cannot attribute.
#[test]
fn an_unpinned_audit_record_is_counted_beside_the_head() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    let layout = Layout::new(home.path().to_path_buf());
    let (deployment, _) = ksp_cli::deployment::require(&layout).unwrap();
    ksp_cli::audit::record_admin(
        &layout,
        AuditComponent::CommandLine,
        AuditOperation::Init,
        None,
        Outcome::Success,
        exit::SUCCESS,
    )
    .expect("the pinned record is written");
    // A second segment in the same actor directory, signed by a key no pin holds.
    let writer = ksp_deletion::EvidenceSigningKey::from_seed([7u8; 32]);
    ksp_cli::audit::append(
        &layout,
        &writer,
        deployment.admin,
        &ksp_cli::audit::Event {
            actor: deployment.admin,
            signer_key_id: "not-pinned",
            component: AuditComponent::CommandLine,
            operation: AuditOperation::Init,
            target: None,
            outcome: Outcome::Success,
            exit_code: exit::SUCCESS,

            acceptance: None,
        },
    )
    .expect("the unpinned record is written");

    let (code, output) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    assert!(
        output.contains("records in 2 segment(s), 2 chain(s)"),
        "both chains reach a head: {output}"
    );
    assert!(
        output.contains(
            "unattributed: 1 record(s) verified against no pinned key, so the head ends a chain \
             this host cannot fully attribute"
        ),
        "a head over an unattributable record says so: {output}"
    );
}

/// `backend test` answers with the capability admission reads, so on one host it
/// cannot disagree with `status` and with a mint about the same lease.
///
/// The classification a backend carries by configuration alone is `None` for
/// `file` — a declaration is not evidence. A probe that stops there refuses every
/// lease on a host whose proof is fresh and whose mint succeeds, and it reports
/// `mechanism` and `cadence` from a source the mint never consults.
#[test]
fn the_lease_probe_agrees_with_status_once_a_proof_exists() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner), "300s", false);
    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the sweep run failed: {output}");

    // 600s is exactly 2 x the proven 300s, which admission admits.
    let (code, output) = ksp_in(home.path(), &["backend", "test", "--ttl", "600"], None);
    assert_eq!(
        code,
        exit::SUCCESS,
        "a proven cadence must admit its own 2x lease: {output}"
    );
    assert!(
        output.contains("capability=Scheduled { interval: 300s }"),
        "the probe reports the proven capability, not the configuration-only None: {output}"
    );
    assert!(
        output.contains("admitted=true"),
        "the lease the mint would accept is accepted here: {output}"
    );
    assert!(
        output.contains("cadence=300s"),
        "the cadence is the proven one: {output}"
    );

    // The boundary is admission's, not this probe's: one second below 2x refuses.
    let (code, output) = ksp_in(home.path(), &["backend", "test", "--ttl", "599"], None);
    assert_eq!(
        code,
        exit::CAPABILITY_REFUSAL,
        "599s is below 2 x 300s: {output}"
    );
    assert!(output.contains("admitted=false"), "{output}");

    // And the same verdict from `status`, which reads the same classification.
    let (_, status) = ksp_in(home.path(), &["status"], None);
    assert!(
        status.contains("capability:  Scheduled { interval: 300s }"),
        "status and the probe name one capability: {status}"
    );
}
