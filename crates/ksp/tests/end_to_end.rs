//! The feature end to end, through the binary.
//!
//! # What this proves that the work packages could not
//!
//! Each work package was verified in isolation. This runs the one user-visible
//! path the feature exists for: arm a scope, install the job, read the state,
//! then let a proof move it. The steps cross process boundaries, so a wiring gap
//! between two subsystems shows here and nowhere else.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use ksp::config::Layout;
use ksp::exit;
use ksp_backend::proof::{SignedSweepProof, SweepProof, write as write_proof_file};
use ksp_types::PrincipalId;

const PASSWORD: &str = "a long enough password";
const INTERVAL_SECS: u64 = 3_600;

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

/// Provision a deployment and return the **user** id.
///
/// `admin init` prints both a principal id and a user id, and the sweep scope
/// names the user. Taking the principal is refused as outside the deployment.
fn provision(home: &Path) -> PrincipalId {
    let (code, output) = ksp_in(
        home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin init failed: {output}");
    let (code, output) = ksp_in(home, &["admin", "user", "add"], Some(PASSWORD));
    assert_eq!(code, exit::SUCCESS, "admin user add failed: {output}");
    ksp::deployment::require(&Layout::new(home.to_path_buf()))
        .expect("the deployment exists")
        .0
        .user
}

fn scope(owner: PrincipalId) -> String {
    format!("p/vault-1/{owner}/agent-*")
}

/// One complete `arm-sweep` invocation with `--install`, under a throwaway home.
fn install_in(home: &Path, fake_home: &Path, scope: &str) -> (i32, String) {
    let delete = format!("delete:{scope}");
    let mut command = Command::new(ksp());
    command
        .env("KSP_HOME", home)
        .env("HOME", fake_home)
        .env("LC_ALL", "C")
        .args([
            "backend",
            "arm-sweep",
            "--kind",
            "launchd",
            "--interval",
            &INTERVAL_SECS.to_string(),
            "--scope",
            scope,
            "--credential",
            "unix:ksp-sweeper",
            "--grant",
            &delete,
            "--install",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let output = command.output().expect("the binary runs");
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.code().unwrap_or(-1), combined)
}

/// Write one fresh, verified proof for this deployment.
fn write_fresh_proof(home: &Path) {
    let layout = Layout::new(home.to_path_buf());
    let (deployment, anchor) = ksp::deployment::require(&layout).expect("the deployment exists");
    let admin = ksp::admin::load_admin(&layout, &anchor).expect("the admin key loads");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let proof = SweepProof {
        scope: ksp::admission::deployment_scope(&deployment),
        arming_id: Some("launchd:file".to_string()),
        admin: deployment.admin,
        run_start: now - 4,
        run_end: now,
        declared_interval_secs: Some(INTERVAL_SECS),
        realised_interval_secs: None,
        success: true,
        removed: 0,
        already_absent: 0,
        not_yet_due: 0,
        bound_reached: false,
        error_codes: Vec::new(),
        signer_key_id: anchor.key_id.as_str().to_string(),
        prev_digest: None,
    };
    let signed = admin
        .with_secret(|seed| {
            SignedSweepProof::sign(proof, &ed25519_dalek::SigningKey::from_bytes(seed))
        })
        .expect("the proof signs");
    write_proof_file(&layout.sweeper_proofs_dir(), &signed).expect("the proof is written");
}

/// The whole path: bad scope refused, canonical scope installed, capability not
/// `Scheduled`, then a proof makes it `Scheduled` with no `next:` line.
#[test]
fn the_feature_runs_end_to_end() {
    let home = tempfile::tempdir().unwrap();
    let fake_home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let canonical = scope(owner);

    // Step 1: a bad scope is refused before any install.
    let one = format!("p/vault-1/{owner}/agent-1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f");
    let (code, output) = install_in(home.path(), fake_home.path(), &one);
    assert_eq!(code, exit::POLICY_DENIAL, "a bad scope exits 2: {output}");
    assert!(
        output.contains(&canonical),
        "the refusal names the accepted shape: {output}"
    );
    let agents = fake_home.path().join("Library/LaunchAgents");
    assert!(
        !agents.exists() || std::fs::read_dir(&agents).unwrap().next().is_none(),
        "a refused scope installs nothing"
    );

    // Step 2: the canonical scope installs, and the plist is written at 0600.
    let (_code, output) = install_in(home.path(), fake_home.path(), &canonical);
    let plist = std::fs::read_dir(&agents)
        .unwrap_or_else(|error| panic!("the LaunchAgents directory exists: {error}; {output}"))
        .filter_map(Result::ok)
        .next()
        .expect("one plist was written")
        .path();
    let mode =
        std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&plist).unwrap().permissions());
    assert_eq!(mode & 0o777, 0o600, "the plist is private to its owner");

    // Step 3: the capability is not Scheduled, and the next: line says a proof
    // is needed. This is misfit E: an install is a declaration, not evidence.
    let (code, status) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status runs: {status}");
    assert!(
        !status.contains("capability:  Scheduled"),
        "an install does not make the capability Scheduled: {status}"
    );
    assert!(
        status.contains("next:"),
        "the state names the next step: {status}"
    );
    assert!(
        status.contains("proof"),
        "the next step names a proof: {status}"
    );

    // Step 4: a fresh verified proof is the only thing that produces Scheduled,
    // and a proven schedule prints no next: line.
    write_fresh_proof(home.path());
    let (code, status) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status runs: {status}");
    assert!(
        status.contains("capability:  Scheduled"),
        "a fresh verified proof makes the capability Scheduled: {status}"
    );
    assert!(
        !status.contains("next:"),
        "a proven schedule needs no next step: {status}"
    );
}

/// `--install` is listed by the parser, so the walkthrough's flag is real.
#[test]
fn the_install_flag_is_listed() {
    let home = tempfile::tempdir().unwrap();
    let (code, help) = ksp_in(home.path(), &["backend", "arm-sweep", "--help"], None);
    assert_eq!(code, 0, "arm-sweep --help runs: {help}");
    assert!(help.contains("--install"), "the flag is listed: {help}");
}

/// `admin user add` reads the password from `--passphrase-file`.
///
/// Every later command that needs the password accepts the flag, and this step
/// did not: a scripted setup had to pipe the password to this one command and
/// read it from a file for the rest. The test supplies the password *only*
/// through the file and closes stdin, so a command that still read stdin would
/// fail here rather than succeed by accident.
#[test]
fn admin_user_add_reads_the_password_from_a_file() {
    let home = tempfile::tempdir().unwrap();
    let (code, output) = ksp_in(
        home.path(),
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin init failed: {output}");

    let password_file = home.path().join("password");
    std::fs::write(&password_file, PASSWORD).expect("the password file is written");

    // No stdin at all: the flag is the only source, so this proves the flag is
    // read rather than accepted and ignored.
    let (code, output) = ksp_in(
        home.path(),
        &[
            "admin",
            "user",
            "add",
            "--passphrase-file",
            password_file.to_str().expect("a UTF-8 path"),
        ],
        None,
    );
    assert_eq!(
        code,
        exit::SUCCESS,
        "admin user add reads the password from the file: {output}"
    );
    assert!(
        output.contains("principal="),
        "the command reports the principal it issued: {output}"
    );
}

/// The flag is listed, so an operator can find it.
#[test]
fn admin_user_add_lists_the_passphrase_file_flag() {
    let home = tempfile::tempdir().unwrap();
    let (code, help) = ksp_in(home.path(), &["admin", "user", "add", "--help"], None);
    assert_eq!(code, 0, "admin user add --help runs: {help}");
    assert!(
        help.contains("--passphrase-file"),
        "the flag is listed: {help}"
    );
}

/// A bad scope with `--install` exits 2 with the scope message, not an install
/// error: the scope check runs first.
#[test]
fn the_scope_check_runs_before_the_install() {
    let home = tempfile::tempdir().unwrap();
    let fake_home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let one = format!("p/vault-1/{owner}/agent-1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f");

    let (code, output) = install_in(home.path(), fake_home.path(), &one);
    assert_eq!(code, exit::POLICY_DENIAL, "{output}");
    // The positive assertion: the refusal is the scope message and it names the
    // accepted shape. A negative-only check would pass on any other failure.
    assert!(
        output.contains(&scope(owner)),
        "the refusal names the accepted shape: {output}"
    );
    assert!(
        output.contains("is not the shape admission reads"),
        "the refusal is the scope message: {output}"
    );
    assert!(
        !output.contains("could not be loaded") && !output.contains("outside this account"),
        "the refusal is not an install error: {output}"
    );
}

/// The installer never reads the capability state.
///
/// A source-level assertion, because the property is an absence: no test can
/// observe an import that was never written.
#[test]
fn the_installer_does_not_import_the_admission_module() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/install.rs");
    let source = std::fs::read_to_string(&path).expect("install.rs is readable");
    assert!(
        !source.contains("use crate::admission"),
        "install.rs must not import admission.rs: the installer cannot read the capability state"
    );
}

/// The freshness bound is interval plus grace, and a proof inside it is fresh.
///
/// Misfit D: the bound is what a sleeping machine wakes past, and it is the only
/// freshness guarantee the host has.
#[test]
fn the_bound_is_the_interval_plus_the_measured_grace() {
    let interval = Duration::from_secs(INTERVAL_SECS);
    let grace = 5;
    let fresh = ksp_backend::proof::ProofObservation {
        interval,
        age: i64::try_from(interval.as_secs()).unwrap_or(i64::MAX) + grace - 1,
        grace,
    };
    assert_eq!(
        fresh.freshness(),
        ksp_backend::proof::ProofFreshness::Fresh,
        "one second inside the bound is fresh"
    );
    let stale = ksp_backend::proof::ProofObservation {
        interval,
        age: i64::try_from(interval.as_secs()).unwrap_or(i64::MAX) + grace,
        grace,
    };
    assert_eq!(
        stale.freshness(),
        ksp_backend::proof::ProofFreshness::Stale,
        "the bound itself is stale"
    );
}
