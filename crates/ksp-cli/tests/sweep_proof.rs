//! The sweep proof, end to end through the binary.
//!
//! # What these prove that a unit test cannot
//!
//! The gate's arithmetic is proved in `ksp-backend`. These tests prove the two
//! connections that make the arithmetic matter: a sweep run writes the proof it is
//! supposed to write, and a lease request reads that proof instead of the arming
//! record. A declaration admits nothing; one completed run does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ksp_backend::proof::{SignedSweepProof, SweepProof};
use ksp_cli::config::Layout;
use ksp_cli::exit;
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
        // A command that refuses before reading closes the pipe first; that is
        // this test's own write failing, not the refusal under test.
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
fn arm(home: &Path, scope: &str, interval: &str) {
    let delete = format!("delete:{scope}");
    let list = format!("list:{scope}");
    let (code, output) = ksp_in(
        home,
        &[
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
        ],
        None,
    );
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

/// The proof files, sorted by name.
fn proofs(layout: &Layout) -> Vec<PathBuf> {
    let mut names = std::fs::read_dir(layout.sweeper_proofs_dir())
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "cbor"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// Acceptance 1, 2 and misfit C: a recorded schedule admits nothing until a run
/// proves it, and the proof a run writes is what changes the answer.
#[test]
fn an_armed_sweeper_admits_nothing_until_a_run_writes_a_proof() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner), "300s");
    let agent = enrol_and_grant(home.path());
    let layout = Layout::new(home.path().to_path_buf());
    let token = home.path().join("deploy-bot.token");

    // The arming exists and is readable; it is not evidence, so the lease is
    // refused and the refusal names the absent proof.
    let (code, output) = lease(home.path(), agent, 600, &token);
    assert_eq!(
        code,
        exit::CAPABILITY_REFUSAL,
        "a declaration alone must not admit a lease: {output}"
    );
    assert!(
        output.contains("no sweep proof"),
        "the refusal names what was observed, not just a number: {output}"
    );
    assert!(!token.exists(), "a refused mint wrote a token file");

    // One completed run writes exactly one proof, world-readable and not
    // writable by any principal that can only read it.
    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the sweep run failed: {output}");
    let written = proofs(&layout);
    assert_eq!(written.len(), 1, "one run writes one proof: {written:?}");
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(&written[0]).unwrap().permissions(),
    ) & 0o777;
    assert_eq!(mode, 0o644, "a proof is readable by every principal");

    // Acceptance 2: `2 x proven` is the floor, and it is applied in seconds.
    let (code, output) = lease(home.path(), agent, INTERVAL_SECS * 2, &token);
    assert_eq!(
        code,
        exit::SUCCESS,
        "600s at a proven 300s cadence is the floor: {output}"
    );

    let below = home.path().join("below.token");
    let (code, output) = lease(home.path(), agent, INTERVAL_SECS * 2 - 1, &below);
    assert_eq!(
        code,
        exit::CAPABILITY_REFUSAL,
        "599s at a proven 300s cadence is below the floor: {output}"
    );
    assert!(
        !below.exists(),
        "a refused mint must not leave a token behind"
    );
}

/// T036: a run that failed still leaves a proof, and the proof says the run
/// failed rather than that the backlog was empty.
#[test]
fn a_failed_run_writes_a_proof_that_records_the_failure() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner), "300s");
    let layout = Layout::new(home.path().to_path_buf());

    // One clean run first, so the failure has a proof to link to.
    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the first run failed: {output}");

    // An arm record this host cannot decode. The run read the schedule, so this
    // is not "nothing is due" — it is a failure, and a failure is evidence too.
    let intents = layout.store_root().join("intents");
    std::fs::create_dir_all(&intents).unwrap();
    std::fs::write(intents.join("not-cbor"), b"\xff\xff not an arm record").unwrap();

    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(
        code,
        exit::DELETE_FAILED,
        "a run that could not arm is not a success: {output}"
    );

    let written = proofs(&layout);
    assert_eq!(
        written.len(),
        2,
        "a failed run writes a proof too: {written:?}"
    );
    let decoded: Vec<SweepProof> = written
        .iter()
        .map(|path| {
            SignedSweepProof::from_bytes(&std::fs::read(path).unwrap())
                .expect("every written proof decodes")
                .proof
        })
        .collect();
    let failed = decoded
        .iter()
        .find(|proof| !proof.success)
        .expect("a proof records the failed run");
    assert_eq!(
        failed.error_codes,
        vec![exit::POLICY_DENIAL],
        "an arm record this host cannot use is an authorisation it could not establish"
    );
    assert!(
        failed.prev_digest.is_some(),
        "the failed run still links the success before it"
    );
    assert_eq!(
        (failed.removed, failed.already_absent, failed.not_yet_due),
        (0, 0, 0),
        "a run that produced no counts says zero, not a backlog"
    );
    assert!(
        decoded.iter().any(|proof| proof.success),
        "the clean run's proof is not overwritten by the failure"
    );
}

/// The integer between `prefix` and `suffix` in `text`.
///
/// Ages are read as numbers rather than matched as strings: the child process can
/// cross a clock second between writing the proof and printing it, and a test that
/// insists on `0s` fails for a reason that is not the behaviour under test.
fn number_between(text: &str, prefix: &str, suffix: &str) -> i64 {
    let start = text
        .find(prefix)
        .unwrap_or_else(|| panic!("'{prefix}' is in the output: {text}"))
        + prefix.len();
    let rest = &text[start..];
    let end = rest
        .find(suffix)
        .unwrap_or_else(|| panic!("'{suffix}' follows '{prefix}' in the output: {text}"));
    rest[..end]
        .parse()
        .unwrap_or_else(|_| panic!("'{prefix}<n>{suffix}' holds a number: {text}"))
}

/// Acceptance 5 and 6: status separates the declared cadence from the proven one,
/// and a host with only a declaration reports no proven cadence.
#[test]
fn status_names_the_declared_and_the_proven_cadence_separately() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner), "300s");

    let (code, output) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    assert!(
        output.contains("cadence:     300s (declared)"),
        "the declaration is disclosed as a declaration: {output}"
    );
    assert!(
        output.contains("proven:      none"),
        "no run has proven the cadence yet: {output}"
    );

    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the sweep run failed: {output}");

    let (code, output) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    assert!(
        output.contains("proven:      300s"),
        "after a run the proven cadence is named: {output}"
    );
    let age = number_between(&output, "(proof age ", "s)");
    assert!(
        (0..=2).contains(&age),
        "the proof was written by the run just made: {output}"
    );
    assert!(
        output.contains("capability:  Scheduled"),
        "a fresh proof is what makes the backend Scheduled: {output}"
    );
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

/// Misfit D: a stale proof's refusal names its age and the bound it exceeded, so a
/// reader cannot mistake the bound for a maximum lag.
#[test]
fn a_stale_proof_is_refused_with_its_age_and_its_bound() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner), "300s");
    let agent = enrol_and_grant(home.path());
    let layout = Layout::new(home.path().to_path_buf());
    let (_, anchor) = ksp_cli::deployment::require(&layout).unwrap();
    let admin = ksp_cli::admin::load_admin(&layout, &anchor).unwrap();

    // A proof from long enough ago that `I + grace` has passed.
    let now = now_seconds();
    admin.with_secret(|seed| {
        let signer = ed25519_dalek::SigningKey::from_bytes(seed);
        write_proof(&layout, now - 1_000, &signer, anchor.key_id.as_str());
    });

    let token = home.path().join("deploy-bot.token");
    let (code, output) = lease(home.path(), agent, INTERVAL_SECS * 2, &token);
    assert_eq!(code, exit::CAPABILITY_REFUSAL, "{output}");
    let age = number_between(&output, " is ", "s old");
    assert!(
        (1_000..=1_002).contains(&age),
        "the age tracks the proof written a thousand seconds ago: {output}"
    );
    assert!(
        output.contains("bound is 450s"),
        "the refusal names the bound: {output}"
    );
    assert!(
        output.contains("late, which is not a deletion deadline"),
        "lateness is not obsolescence: {output}"
    );
    assert!(!token.exists());
}

/// Misfit M: a valid arming and a fresh timestamp do not rescue a proof whose
/// signature is not the pinned admin's.
#[test]
fn a_proof_signed_by_another_key_is_unverified() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm(home.path(), &scope(owner), "300s");
    let agent = enrol_and_grant(home.path());
    let layout = Layout::new(home.path().to_path_buf());
    // A fresh proof, dated now, signed by a key the anchor does not pin.
    let now = now_seconds();
    write_proof(
        &layout,
        now,
        &ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]),
        "not-the-admin",
    );

    let token = home.path().join("deploy-bot.token");
    let (code, output) = lease(home.path(), agent, INTERVAL_SECS * 2, &token);
    assert_eq!(code, exit::CAPABILITY_REFUSAL, "{output}");
    assert!(
        output.contains("does not verify against any pinned key"),
        "the refusal says the proof is unverifiable, not absent: {output}"
    );
    assert!(!token.exists());
}
