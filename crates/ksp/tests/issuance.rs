//! The issuance ledger, end to end through the binary.
//!
//! # What these prove that a unit test cannot
//!
//! `ksp-identity` proves `publish_recorded` seals before it appends and returns
//! no artifact when the append fails. These prove the command asks it: a minted
//! lease appears in `token list`, can be revoked, and stops a later `ksp run`
//! with the revocation message instead of a warning that the host keeps no
//! ledger.
//!
//! Before this work package `publish_recorded` had no production caller, so the
//! ledger was always empty and every one of those commands reported that it knew
//! nothing — on both platforms.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use ksp::config::Layout;
use ksp::exit;
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

/// Give this home the capability configuration a real host has.
fn configure(home: &Path) {
    let (code, output) = ksp_in(home, &["init"], None);
    assert_eq!(code, exit::SUCCESS, "ksp init failed: {output}");
}

/// Initialise the deployment and enrol the user, through the binary.
fn provision(home: &Path) -> PrincipalId {
    configure(home);
    let (code, output) = ksp_in(
        home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin init failed: {output}");
    let (code, output) = ksp_in(home, &["admin", "user", "add"], Some(PASSWORD));
    assert_eq!(code, exit::SUCCESS, "admin user add failed: {output}");
    let (deployment, _anchor) = ksp::deployment::require(&Layout::new(home.to_path_buf())).unwrap();
    deployment.user
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
    let agent = ksp::agent::enroll("deploy-bot", &layout)
        .expect("the agent enrols")
        .enrolment
        .identity;
    ksp::admin::policy(
        &layout,
        vec![agent],
        vec![OpaqueSecretId::new(SECRET)],
        false,
    )
    .expect("the policy grants the agent the record");
    ksp::secret::set(
        &layout,
        PASSWORD.as_bytes(),
        &OpaqueSecretId::new(SECRET),
        b"db_password",
        b"correct-horse",
    )
    .expect("the user writes the record");
    agent
}

/// A deployment with an armed, proven schedule and a record the agent may read.
///
/// A lease needs all of it: the proof is what admits the TTL, and the policy is
/// what names the agent. `secret gc` is the run that writes the proof.
fn proven_deployment(home: &Path) -> AgentId {
    let owner = provision(home);
    arm(home, &scope(owner), &format!("{INTERVAL_SECS}s"));
    let agent = enrol_and_grant(home);
    let (code, output) = ksp_in(home, &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the sweep run failed: {output}");
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

/// The `jti` the token file carries.
/// The issuance ledger the mint writes: the store path, resolved the way production
/// resolves it.
///
/// A fixture that used the home path would be testing a file no command touches, and
/// every one of these tests is about what happens to the file the mint appends to.
fn deployment_ledger(home: &std::path::Path) -> std::path::PathBuf {
    let layout = Layout::new(home.to_path_buf());
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
    ksp::ledgers::LedgerPaths::for_deployment(&layout, &deployment)
        .issuance()
        .to_path_buf()
}

fn jti_of(home: &Path, token: &Path) -> String {
    let (code, output) = ksp_in(
        home,
        &["token", "inspect", "--token", token.to_str().unwrap()],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "inspect failed: {output}");
    output
        .lines()
        .find_map(|line| {
            line.split_once("jti=")
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .map(str::to_string)
        })
        .unwrap_or_else(|| panic!("the inspection names the jti: {output}"))
}

/// FR-008 and misfit C: a minted lease is in the ledger, so it can be revoked
/// and a later run refuses with the revocation.
#[test]
fn a_minted_lease_appears_in_the_ledger_and_can_be_revoked() {
    let home = tempfile::tempdir().unwrap();
    let agent = proven_deployment(home.path());
    let token = home.path().join("deploy-bot.token");

    let (code, output) = lease(home.path(), agent, INTERVAL_SECS * 2, &token);
    assert_eq!(code, exit::SUCCESS, "the lease was refused: {output}");
    let jti = jti_of(home.path(), &token);

    // Before this work package the ledger was empty, so the list had no row and
    // the revoke below refused every identifier.
    let (code, output) = ksp_in(home.path(), &["token", "list"], None);
    assert_eq!(code, exit::SUCCESS, "list failed: {output}");
    assert!(
        output.contains(&jti),
        "the ledger names the lease this host minted ({jti}): {output}"
    );

    let (code, output) = ksp_in(home.path(), &["token", "revoke", &jti], None);
    assert_eq!(code, exit::SUCCESS, "the revoke was refused: {output}");

    let (code, output) = ksp_in(home.path(), &["token", "list"], None);
    assert_eq!(code, exit::SUCCESS, "list failed: {output}");
    assert!(
        output.contains(&jti) && output.contains("revoked"),
        "the row says the lease no longer stands: {output}"
    );

    // The refusal names the revocation and not an absent ledger.
    let (code, output) = ksp_in(
        home.path(),
        &[
            "run",
            "--token",
            token.to_str().unwrap(),
            "--env",
            "DB_PASSWORD",
            "--",
            "/bin/true",
        ],
        None,
    );
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "a revoked token must stop the run: {output}"
    );
    assert!(
        output.contains("revoked"),
        "the refusal names the revocation: {output}"
    );
    assert!(
        !output.contains("cannot tell whether it was revoked"),
        "a host that keeps a ledger must not say it cannot tell: {output}"
    );
}

/// A second mint for the same version, naming different bytes, is refused.
///
/// The operation identity is the intent's own id, which is also the `jti`. The
/// arm compares the signed record byte for byte, and the second mint below
/// carries a longer `--ttl`, so its intent's `deadline` differs and the bytes
/// differ by construction. That refusal is what keeps the ledger honest for the
/// case it covers: the same lease cannot be recorded twice under a changed
/// intent.
///
/// The identical-bytes case is **not** covered here, because the code does not
/// refuse it. Two mints for one version inside the same second produce the same
/// `deadline` and therefore the same bytes; the arm accepts that as the same
/// intent, and `IssuanceLedger::append` writes the row without comparing
/// identities, so `token list` shows the lease twice. An earlier version of this
/// test minted both leases with the same `--ttl` and failed about one run in
/// eight, whenever the two mints straddled a second boundary. The gap is
/// recorded as CF-026 in feature 006's carry-forward ledger, which is internal
/// and does not ship.
#[test]
fn a_second_mint_for_one_version_is_refused_and_records_nothing() {
    let home = tempfile::tempdir().unwrap();
    let agent = proven_deployment(home.path());
    let first = home.path().join("first.token");

    let (code, output) = lease(home.path(), agent, INTERVAL_SECS * 2, &first);
    assert_eq!(code, exit::SUCCESS, "the first lease was refused: {output}");
    let jti = jti_of(home.path(), &first);
    let ledger = deployment_ledger(home.path());
    let before = std::fs::read(&ledger).expect("the first mint wrote the ledger");

    // A different `--ttl`, so the second intent's deadline differs and the bytes
    // differ whatever the clock says. See the note above.
    let again = home.path().join("again.token");
    let (code, output) = lease(home.path(), agent, INTERVAL_SECS * 3, &again);
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "a second mint for the same version is refused: {output}"
    );
    assert!(
        output.contains("operation identity"),
        "the refusal names the identity it collided with: {output}"
    );
    assert!(!again.exists(), "a refused mint wrote a token file");
    assert_eq!(
        std::fs::read(&ledger).expect("the ledger is still readable"),
        before,
        "a refused second mint must not append a row"
    );

    let (code, output) = ksp_in(home.path(), &["token", "list"], None);
    assert_eq!(code, exit::SUCCESS, "list failed: {output}");
    let rows = output.lines().filter(|line| line.contains(&jti)).count();
    assert_eq!(rows, 1, "one lease is one row: {output}");
}

/// FR-010: a refused mint writes no row.
#[test]
fn a_refused_mint_leaves_the_ledger_byte_identical() {
    let home = tempfile::tempdir().unwrap();
    let agent = proven_deployment(home.path());
    let ledger = deployment_ledger(home.path());

    // One successful mint, so the file exists and has content to compare.
    let first = home.path().join("first.token");
    let (code, output) = lease(home.path(), agent, INTERVAL_SECS * 2, &first);
    assert_eq!(code, exit::SUCCESS, "{output}");
    let before = std::fs::read(&ledger).expect("the first mint wrote the ledger");

    // 599s at a proven 300s cadence is below the floor, so the mint is refused
    // before any publication.
    let below = home.path().join("below.token");
    let (code, output) = lease(home.path(), agent, INTERVAL_SECS * 2 - 1, &below);
    assert_eq!(
        code,
        exit::CAPABILITY_REFUSAL,
        "a lease below the floor is refused: {output}"
    );
    assert!(!below.exists(), "a refused mint wrote a token file");
    assert_eq!(
        std::fs::read(&ledger).expect("the ledger is still readable"),
        before,
        "a refused mint must not append to the ledger"
    );
}

/// A ledger that cannot be written returns a refusal and no artifact.
///
/// The order matters: `publish_recorded` seals first, so the seal succeeds in
/// memory and the append fails. A token on disk with no ledger row would be a
/// live credential nothing can revoke.
///
/// The ledger is replaced by a directory, so the append fails with `EISDIR` and
/// nothing else in the home is affected. Chmod on the home would block the token
/// write as well, which is a different finding.
///
/// `admin init` creates the ledger now, so the path is occupied by removing the
/// file first: `create_dir_all` on a path that is already a file fails with
/// `AlreadyExists`, which would fail the fixture rather than the behaviour under
/// test.
#[test]
fn a_ledger_that_cannot_be_written_returns_no_token() {
    let home = tempfile::tempdir().unwrap();
    let agent = proven_deployment(home.path());
    let ledger = deployment_ledger(home.path());
    std::fs::remove_file(&ledger).expect("provisioning created the ledger");
    std::fs::create_dir_all(&ledger).expect("the ledger path is occupied by a directory");

    let token = home.path().join("unwritable.token");
    let (code, output) = lease(home.path(), agent, INTERVAL_SECS * 2, &token);

    assert_ne!(
        code,
        exit::SUCCESS,
        "a mint that could not be recorded must not report success: {output}"
    );
    assert!(
        output.contains("recorded") || output.contains("ledger"),
        "the refusal names the ledger: {output}"
    );
    assert!(
        !token.exists(),
        "a mint with no ledger row must leave no token file"
    );
}
