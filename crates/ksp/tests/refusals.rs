//! A refusal names what to do.
//!
//! # Why this file exists
//!
//! Two defects with one shape. **D7**: five command arms read the password, got
//! `Err(2)` back, and returned it without printing anything. The code `2` is
//! "policy denied the operation", so a caller could not tell a missing credential
//! from a policy decision. **D1**: `secret share` sealed the delivery first and
//! appended to the issuance ledger second, so an account that could not append
//! wasted the crypto work and dropped the artifact with a raw `Permission denied`.
//!
//! These tests drive the real binary. Each pins one acceptance criterion, and the
//! password cases assert on **both** the exit code and the sentence: a code alone
//! is what the defect already produced.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Stdio};

use ksp::exit;

/// The vault password these tests use where a password is meant to succeed.
const PASSWORD: &str = "a long enough password";

fn ksp() -> &'static str {
    env!("CARGO_BIN_EXE_ksp")
}

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
        use std::io::Write as _;
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(text.as_bytes())
            .expect("the password is written");
    }
    let output = child.wait_with_output().expect("the binary finishes");
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.code().unwrap_or(-1), combined)
}

fn provision_vault(home: &Path) {
    let (code, output) = ksp_in(
        home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin init failed: {output}");
    let (code, output) = ksp_in(home, &["admin", "user", "add"], Some(PASSWORD));
    assert_eq!(code, exit::SUCCESS, "admin user add failed: {output}");
}

/// Enrol an agent and return the principal UUID it issued.
fn enrol(home: &Path, name: &str) -> String {
    let (code, output) = ksp_in(home, &["agent", "enroll", "--agent", name], None);
    assert_eq!(code, exit::SUCCESS, "enrol {name} failed: {output}");
    output
        .split("agent:")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no agent identity in {output}"))
        .to_string()
}

/// Write a password to a file and return its path, so a command can read it.
fn password_file(home: &Path) -> std::path::PathBuf {
    let path = home.join("passphrase");
    std::fs::write(&path, format!("{PASSWORD}\n")).expect("the passphrase file is written");
    path
}

/// Store one secret so `get`, `rm`, `share` and `mint` have something to act on.
fn store_secret(home: &Path, id: &str) {
    let pass = password_file(home);
    let (code, output) = ksp_in(
        home,
        &[
            "secret",
            "set",
            id,
            "--name",
            "db_password",
            "--passphrase-file",
            pass.to_str().expect("a utf-8 path"),
        ],
        Some("correct-horse\n"),
    );
    assert_eq!(code, exit::SUCCESS, "secret set failed: {output}");
}

/// Every command that reads a password, with the arguments that reach the read.
///
/// `secret set` is excluded: it keeps its own code and message, and it is asserted
/// separately. The four here are the arms D7 names.
fn password_reading_commands(home: &Path) -> Vec<(&'static str, Vec<String>)> {
    let agent = enrol(home, "laptop");
    let out = home.join("laptop.token");
    let out = out.to_str().expect("a utf-8 path").to_string();
    vec![
        (
            "secret get",
            vec!["secret".into(), "get".into(), "s1".into()],
        ),
        ("secret rm", vec!["secret".into(), "rm".into(), "s1".into()]),
        (
            "secret share",
            vec![
                "secret".into(),
                "share".into(),
                "s1".into(),
                "--agent".into(),
                agent.clone(),
                "--name".into(),
                "db_password".into(),
                "--out".into(),
                out,
                "--ttl".into(),
                "600".into(),
            ],
        ),
        (
            "token mint",
            vec![
                "token".into(),
                "mint".into(),
                "--agent".into(),
                agent,
                "--secret".into(),
                "s1".into(),
                "--name".into(),
                "db_password".into(),
                "--out".into(),
                home.join("mint.token")
                    .to_str()
                    .expect("a utf-8 path")
                    .to_string(),
                "--ttl".into(),
                "600".into(),
            ],
        ),
    ]
}

/// A missing password exits `6` and names `--passphrase-file`.
///
/// Both halves matter. The code alone is what the defect already returned, and a
/// sentence that does not name the flag leaves the caller with no next step.
#[test]
fn every_password_reading_command_refuses_with_six_and_names_the_flag() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    store_secret(home.path(), "s1");

    for (name, args) in password_reading_commands(home.path()) {
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let (code, output) = ksp_in(home.path(), &borrowed, None);
        assert_eq!(
            code,
            exit::MISSING_KEY,
            "{name} must exit {} for a missing password, not {code}: {output}",
            exit::MISSING_KEY
        );
        assert!(
            output.contains("--passphrase-file"),
            "{name} must name --passphrase-file: {output}"
        );
        assert!(
            !output.contains("policy denied"),
            "{name} must not report a policy denial for a missing password: {output}"
        );
    }
}

/// `secret set` keeps exit `13` and its own message.
///
/// The value comes from stdin, so the password cannot, and the refusal says so.
/// This is the precedent the other four adopt, and it must not be flattened into
/// the same code as the rest.
#[test]
fn secret_set_keeps_thirteen_and_its_own_message() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &["secret", "set", "s1", "--name", "db_password"],
        Some("correct-horse\n"),
    );
    assert_eq!(
        code,
        exit::USAGE,
        "secret set must keep its usage code: {output}"
    );
    assert!(
        output.contains("--passphrase-file"),
        "secret set must name --passphrase-file: {output}"
    );
    assert!(
        output.contains("stdin"),
        "secret set must say why stdin cannot carry the password: {output}"
    );
}

/// A correct password still succeeds on the password-reading path.
///
/// The refusal must not have been bought by breaking the success path. `secret
/// get` without `--reveal` masks the value, so this asserts on the record's name
/// rather than on the value: the point is that the read succeeded, not that the
/// value is printable.
#[test]
fn a_correct_password_still_succeeds() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    store_secret(home.path(), "s1");
    let pass = password_file(home.path());
    let pass = pass.to_str().expect("a utf-8 path");

    let (code, output) = ksp_in(
        home.path(),
        &["secret", "get", "s1", "--passphrase-file", pass],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "secret get failed: {output}");
    assert!(
        output.contains("db_password"),
        "the record must be named: {output}"
    );

    // `--reveal` prints the value, which is what a caller that needs the secret
    // does. The password read is the same one, so it must succeed too.
    let (code, output) = ksp_in(
        home.path(),
        &["secret", "get", "s1", "--reveal", "--passphrase-file", pass],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "secret get --reveal failed: {output}");
    assert!(
        output.contains("correct-horse"),
        "the revealed value must be returned: {output}"
    );
}

/// A real policy denial still returns `2`.
///
/// The fix must not have removed the code a genuine policy refusal uses. A
/// `secret get` for a record that does not exist returns `6` — a missing record
/// is missing material, not a policy decision — so this uses a refusal that is
/// genuinely a policy denial: `admin revoke` with neither a secret nor an agent
/// names nothing to withdraw.
#[test]
fn a_real_policy_denial_still_returns_two() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());

    let (code, output) = ksp_in(home.path(), &["admin", "revoke"], None);
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "a withdrawal that names nothing is a policy denial: {output}"
    );
    assert!(
        output.contains("--secret") && output.contains("--agent"),
        "the refusal must name the accepted form: {output}"
    );
}

/// Both reader branches agree on the code and the sentence.
///
/// A closed pipe delivers nothing and returns at once; an open pipe never
/// delivers. Both are a missing password, and a caller that branches on the code
/// must not see two different answers for the same condition.
#[test]
fn the_closed_pipe_and_the_open_pipe_agree() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    store_secret(home.path(), "s1");

    // Closed pipe: `/dev/null`. This is the branch `ksp_in` with no stdin uses.
    let (closed_code, closed_output) = ksp_in(home.path(), &["secret", "get", "s1"], None);

    // Open pipe that never delivers: a pipe whose write end stays open while the
    // process runs. `sh -c` keeps it open for the duration of the read.
    let child = Command::new("sh")
        .env("KSP_HOME", home.path())
        .env("LC_ALL", "C")
        .args(["-c", "sleep 5 | \"$0\" secret get s1"])
        .arg(ksp())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the shell runs");
    let output = child.wait_with_output().expect("the shell finishes");
    let open_code = output.status.code().unwrap_or(-1);
    let open_output = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        closed_code, open_code,
        "the two branches must agree on the code: closed={closed_code} open={open_code}\n\
         closed: {closed_output}\nopen: {open_output}"
    );
    assert_eq!(
        closed_code,
        exit::MISSING_KEY,
        "both branches must report a missing key: {closed_output}"
    );
    assert!(
        open_output.contains("--passphrase-file"),
        "the open-pipe branch must name --passphrase-file: {open_output}"
    );
}

/// A deployment with no account binding shares as before.
///
/// The D1 pre-check compares the caller against the bound account. With no
/// binding there is no other account to compare against, so the check must not
/// fire — a single-account host is the ordinary case.
#[test]
fn a_deployment_with_no_binding_is_unaffected() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    store_secret(home.path(), "s1");
    let agent = enrol(home.path(), "laptop");
    let pass = password_file(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "share",
            "s1",
            "--agent",
            &agent,
            "--ttl",
            "600",
            "--passphrase-file",
            pass.to_str().expect("a utf-8 path"),
        ],
        None,
    );
    // On `file` the share is refused by admission with `7` until a sweep proof
    // exists. What matters here is that the D1 pre-check did not fire: no refusal
    // may name `admin user add --unix-user` on an unbound host.
    assert!(
        !output.contains("admin user add --unix-user"),
        "an unbound deployment must not be told to bind an account: {output}"
    );
    assert_ne!(
        code,
        exit::SUCCESS,
        "a `file` backend refuses a lease until a proof exists: {output}"
    );
}
