//! Provenance and the run-time policy check, end to end through the binary.
//!
//! # What this covers
//!
//! Two sharing paths and the authority each relies on:
//!
//! 1. **admin → user → agent.** The admin wrote the value with `admin put`, so a
//!    delivery of it is a *delegation*. It needs a policy that is present,
//!    issuer-verified, currently valid, and grants the exact secret and agent.
//! 2. **user → agent.** The user wrote the value with `secret set`, so the value
//!    is theirs and the delivery is signed to the agent's key directly. No policy
//!    exists for it and none is needed.
//!
//! # Why the level is the marker
//!
//! A record does not carry a provenance field. The level it is stored at *is* the
//! marker: `admin` means the admin wrote and delegated it, `user` means the user
//! owns it. That is why `admin put` must write at `Level::Admin` — without it, a
//! blanket "every delivery needs a policy" rule would refuse the user's own
//! secrets, which have no policy and need none.
//!
//! # The measured defect these tests pin
//!
//! Before this work, deleting `policy.cbor` and running an already-minted token
//! still delivered the value with exit `0`. The policy was a mint-time gate and
//! nothing more.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ksp::config::Layout;
use ksp::exit;
use ksp_types::{Level, PrincipalId};

/// The vault password every invocation in this file uses.
const PASSWORD: &str = "a long enough password";
/// A value nobody could guess by accident.
const VALUE: &str = "correct-horse-battery-staple";

fn ksp() -> &'static str {
    env!("CARGO_BIN_EXE_ksp")
}

/// Give this home the capability configuration a real host has.
fn configure(home: &Path) {
    let _ = Command::new(ksp())
        .env("KSP_HOME", home)
        .arg("init")
        .output();
}

/// Run `ksp` with this home, optionally writing `stdin`, and return (code, output).
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
    ksp::deployment::require(&Layout::new(home.to_path_buf()))
        .expect("the deployment is recorded")
        .0
        .user
}

/// The canonical sweep scope for this deployment.
fn scope(owner: PrincipalId) -> String {
    format!("p/vault-1/{owner}/agent-*")
}

/// Record one schedule and run the sweep, so a lease is admissible.
fn arm_and_sweep(home: &Path, owner: PrincipalId) {
    let scope = scope(owner);
    let delete = format!("delete:{scope}");
    let (code, output) = ksp_in(
        home,
        &[
            "backend",
            "arm-sweep",
            "--interval",
            "3600",
            "--scope",
            &scope,
            "--credential",
            "unix:ksp-sweeper",
            "--grant",
            &delete,
            "--identifier",
            "ksp-sweep.service",
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "arm-sweep failed: {output}");
    let (code, output) = ksp_in(home, &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the sweep failed: {output}");
}

/// Enrol an agent and return its identity.
fn enrol_agent(home: &Path, name: &str) -> String {
    let (code, output) = ksp_in(home, &["agent", "enroll", "--agent", name], None);
    assert_eq!(code, exit::SUCCESS, "agent enroll failed: {output}");
    output
        .lines()
        .find_map(|line| line.strip_prefix("agent:"))
        .and_then(|rest| rest.split_whitespace().next())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("the enrolment prints the UUID: {output}"))
}

/// Grant `secret` to `agent` in the policy.
fn grant(home: &Path, agent: &str, secret: &str) {
    let (code, output) = ksp_in(
        home,
        &["admin", "policy", "--agent", agent, "--secret", secret],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");
}

/// Mint a token for `secret` to `agent`, returning the token path.
fn share(home: &Path, agent: &str, secret: &str) -> PathBuf {
    let token = home.join("token.ksp");
    let (code, output) = ksp_in(
        home,
        &[
            "secret",
            "share",
            secret,
            "--agent",
            agent,
            "--name",
            "db_password",
            "--out",
            token.to_str().expect("a utf-8 path"),
            "--ttl",
            "7200",
            "--passphrase-file",
            home.join("pw").to_str().expect("a utf-8 path"),
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "secret share failed: {output}");
    token
}

/// Write the vault password to a file the invocations read.
fn write_password(home: &Path) {
    std::fs::write(home.join("pw"), PASSWORD).expect("the password file is written");
}

// ---------------------------------------------------------------------------
// T001 — the level is the provenance marker
// ---------------------------------------------------------------------------

/// `admin put` writes at the `admin` level, and `secret set` at `user`.
///
/// The level is the only provenance marker a record carries, so the two writers
/// must not both write `user`. Asserted by the store path, not by output text: a
/// renderer that printed the right word while the record landed elsewhere would
/// pass a text assertion.
#[test]
fn an_admin_put_record_is_stored_at_the_admin_level() {
    let home = tempfile::tempdir().unwrap();
    provision(home.path());
    write_password(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "put", "s-admin", "--name", "delegated"],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "admin put failed: {output}");

    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "set",
            "s-user",
            "--name",
            "owned",
            "--passphrase-file",
            home.path().join("pw").to_str().expect("a utf-8 path"),
        ],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "secret set failed: {output}");

    let store = home.path().join("store");
    let admin_path = find_record(&store, "s-admin");
    let user_path = find_record(&store, "s-user");

    assert!(
        admin_path.contains(&format!("/{}/", Level::Admin.path_segment())),
        "an admin-written record lives at the admin level: {admin_path}"
    );
    assert!(
        user_path.contains(&format!("/{}/", Level::User.path_segment())),
        "a user-written record lives at the user level: {user_path}"
    );
}

/// Every record path under `store` whose secret component is `secret`.
fn find_record(store: &Path, secret: &str) -> String {
    fn walk(dir: &Path, found: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else {
                found.push(path.to_string_lossy().to_string());
            }
        }
    }
    let mut found = Vec::new();
    walk(store, &mut found);
    found
        .into_iter()
        .find(|path| path.contains(secret))
        .unwrap_or_else(|| panic!("no record for {secret} under {}", store.display()))
}

// ---------------------------------------------------------------------------
// T007–T009 — an admin-sourced delivery needs a policy
// ---------------------------------------------------------------------------

/// The measured defect: an already-minted token delivered after the policy was
/// deleted.
#[test]
fn an_admin_sourced_run_is_refused_when_the_policy_is_absent() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    write_password(home.path());
    arm_and_sweep(home.path(), owner);
    let agent = enrol_agent(home.path(), "laptop");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "put", "s1", "--name", "db_password"],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "admin put failed: {output}");
    grant(home.path(), &agent, "s1");
    let token = share(home.path(), &agent, "s1");

    // The control: with the policy present, the run delivers.
    let (code, output) = ksp_in(
        home.path(),
        &[
            "run",
            "--token",
            token.to_str().expect("a utf-8 path"),
            "--env",
            "X",
            "--",
            "/usr/bin/printenv",
            "X",
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "a granted run delivers: {output}");
    assert!(
        output.contains(VALUE),
        "the value reaches the child: {output}"
    );

    // The defect: remove the policy and run the same token again.
    std::fs::remove_file(home.path().join("policy.cbor")).expect("the policy is removed");
    let (code, output) = ksp_in(
        home.path(),
        &[
            "run",
            "--token",
            token.to_str().expect("a utf-8 path"),
            "--env",
            "X",
            "--",
            "/usr/bin/printenv",
            "X",
        ],
        None,
    );

    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "an admin-sourced delivery with no policy is refused: {output}"
    );
    assert!(
        output.contains("policy"),
        "the refusal names the policy: {output}"
    );
    assert!(
        !output.contains(VALUE),
        "a refused run never reaches the value: {output}"
    );
}

/// An expired policy authorises nothing, even for a token that has not expired.
#[test]
fn an_admin_sourced_run_is_refused_when_the_policy_has_expired() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    write_password(home.path());
    arm_and_sweep(home.path(), owner);
    let agent = enrol_agent(home.path(), "laptop");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "put", "s1", "--name", "db_password"],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "admin put failed: {output}");
    grant(home.path(), &agent, "s1");
    let token = share(home.path(), &agent, "s1");

    expire_policy(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &[
            "run",
            "--token",
            token.to_str().expect("a utf-8 path"),
            "--env",
            "X",
            "--",
            "/usr/bin/printenv",
            "X",
        ],
        None,
    );
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "an expired policy refuses the run: {output}"
    );
    assert!(
        output.contains("expired") || output.contains("not_after"),
        "the refusal names the expiry: {output}"
    );
    assert!(!output.contains(VALUE), "no value on a refusal: {output}");
}

/// Rewrite the policy with `not_after` in the past, keeping the admin signature.
fn expire_policy(home: &Path) {
    rewrite_policy_validity(home, 0, 1);
}

/// Rewrite the policy's validity window, keeping the admin signature.
fn rewrite_policy_validity(home: &Path, not_before: u64, not_after: u64) {
    let layout = Layout::new(home.to_path_buf());
    let anchor = ksp::keys::Anchor::load(&layout.admin_anchor_file()).expect("the anchor loads");
    let admin = ksp::admin::load_admin(&layout, &anchor).expect("the admin key loads");
    let deployment = ksp::deployment::require(&layout)
        .expect("the deployment is recorded")
        .0;
    let existing = ksp::admin::read_policy(&layout).expect("the policy reads");

    let trusted = ksp_identity::TrustedEnrolmentKeys {
        signing_key: deployment.user_signing_key.expect("the user signing key"),
        recipient_key: deployment
            .user_recipient_key
            .expect("the user recipient key"),
        signing_key_id: deployment.user_signing_key_id.clone().expect("the key id"),
        recipient_key_id: deployment
            .user_recipient_key_id
            .clone()
            .expect("the key id"),
    };
    let body = ksp_identity::PolicyBody::new(
        existing.revision() + 1,
        deployment.vault.clone(),
        deployment.user,
        trusted,
        existing.shareable_secrets().to_vec(),
        existing.shareable_agents().to_vec(),
        3_600,
        86_400,
        not_before,
        not_after,
    );
    let policy = ksp_identity::Policy::new(&admin, deployment.admin_key_id.clone(), body)
        .expect("the policy is signed");
    let bytes = ksp_identity::encode_policy(&policy).expect("the policy encodes");
    std::fs::write(layout.policy_file(), bytes).expect("the policy is written");
}

/// A policy dated in the future authorises nothing yet, and says so.
///
/// The distinction matters: a not-yet-valid policy is a valid file, so the remedy
/// is to wait or to correct a clock. Reporting it as "could not be decoded" would
/// send the operator to replace a file that is not the problem.
#[test]
fn an_admin_sourced_run_is_refused_when_the_policy_is_not_yet_valid() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    write_password(home.path());
    arm_and_sweep(home.path(), owner);
    let agent = enrol_agent(home.path(), "laptop");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "put", "s1", "--name", "db_password"],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "admin put failed: {output}");
    grant(home.path(), &agent, "s1");
    let token = share(home.path(), &agent, "s1");

    // A window that starts well after any run can happen, and is still a
    // well-formed interval (not_before < not_after).
    let future = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs()
        + 86_400;
    rewrite_policy_validity(home.path(), future, future + 3_600);

    let (code, output) = ksp_in(
        home.path(),
        &[
            "run",
            "--token",
            token.to_str().expect("a utf-8 path"),
            "--env",
            "X",
            "--",
            "/usr/bin/printenv",
            "X",
        ],
        None,
    );
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "a policy that is not yet valid refuses the run: {output}"
    );
    assert!(
        output.contains("not valid until"),
        "the refusal names the start of the window, not a decode failure: {output}"
    );
    assert!(!output.contains(VALUE), "no value on a refusal: {output}");
}

/// A policy that does not grant the agent refuses the run and names it.
#[test]
fn an_admin_sourced_run_is_refused_when_the_grant_is_absent() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    write_password(home.path());
    arm_and_sweep(home.path(), owner);
    let agent = enrol_agent(home.path(), "laptop");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "put", "s1", "--name", "db_password"],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "admin put failed: {output}");
    grant(home.path(), &agent, "s1");
    let token = share(home.path(), &agent, "s1");

    // Withdraw the grant, then run the token minted while it existed.
    let (code, output) = ksp_in(home.path(), &["admin", "revoke", "--agent", &agent], None);
    assert_eq!(code, exit::SUCCESS, "admin revoke failed: {output}");

    let (code, output) = ksp_in(
        home.path(),
        &[
            "run",
            "--token",
            token.to_str().expect("a utf-8 path"),
            "--env",
            "X",
            "--",
            "/usr/bin/printenv",
            "X",
        ],
        None,
    );
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "a withdrawn grant refuses the run: {output}"
    );
    assert!(
        !output.contains(VALUE),
        "a refused run never reaches the value: {output}"
    );
}

// ---------------------------------------------------------------------------
// T011 — a user-sourced delivery needs no policy
// ---------------------------------------------------------------------------

/// The user's own secret delivers with no policy on disk.
///
/// This is the requirement that makes the whole design work: a blanket
/// "policy required" rule would refuse this, which is why provenance had to come
/// first.
#[test]
fn a_user_sourced_run_delivers_with_no_policy_present() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    write_password(home.path());
    arm_and_sweep(home.path(), owner);
    let agent = enrol_agent(home.path(), "laptop");

    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "set",
            "s1",
            "--name",
            "personal",
            "--passphrase-file",
            home.path().join("pw").to_str().expect("a utf-8 path"),
        ],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "secret set failed: {output}");
    grant(home.path(), &agent, "s1");
    let token = share(home.path(), &agent, "s1");

    std::fs::remove_file(home.path().join("policy.cbor")).expect("the policy is removed");

    let (code, output) = ksp_in(
        home.path(),
        &[
            "run",
            "--token",
            token.to_str().expect("a utf-8 path"),
            "--env",
            "X",
            "--",
            "/usr/bin/printenv",
            "X",
        ],
        None,
    );
    assert_eq!(
        code,
        exit::SUCCESS,
        "a user-sourced delivery needs no policy: {output}"
    );
    assert!(
        output.contains(VALUE),
        "the user's own value still reaches the child: {output}"
    );
}
