//! A use bound on a shared copy, end to end through the binary.
//!
//! # What this covers
//!
//! `ksp secret share --uses N` bounds a copy by a number of deliveries. A plain
//! run spends one and leaves the version; `--consume` spends one and deletes; the
//! sweep removes a copy whose counter reached zero.
//!
//! # Why both paths spend
//!
//! `--consume` deletes the version as part of its own sequence, so a bound that
//! only a consume could spend would be spent exactly once — `--uses 3` could
//! never reach three. A plain run is therefore the counter's main consumer, and
//! `--consume` keeps its meaning ("delete now") while also spending.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ksp::config::Layout;
use ksp::exit;
use ksp_types::PrincipalId;

const PASSWORD: &str = "a long enough password";
const VALUE: &str = "correct-horse-battery-staple";

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

fn provision(home: &Path) -> PrincipalId {
    let (code, output) = ksp_in(
        home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin init failed: {output}");
    let (code, output) = ksp_in(home, &["admin", "user", "add"], Some(PASSWORD));
    assert_eq!(code, exit::SUCCESS, "admin user add failed: {output}");
    std::fs::write(home.join("pw"), PASSWORD).expect("the password file is written");
    ksp::deployment::require(&Layout::new(home.to_path_buf()))
        .expect("the deployment is recorded")
        .0
        .user
}

fn arm_and_sweep(home: &Path, owner: PrincipalId) {
    let scope = format!("p/vault-1/{owner}/agent-*");
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

fn enrol_agent(home: &Path) -> String {
    let (code, output) = ksp_in(home, &["agent", "enroll", "--agent", "laptop"], None);
    assert_eq!(code, exit::SUCCESS, "agent enroll failed: {output}");
    output
        .lines()
        .find_map(|line| line.strip_prefix("agent:"))
        .and_then(|rest| rest.split_whitespace().next())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("the enrolment prints the UUID: {output}"))
}

/// The counter file for the only arm this deployment has.
fn counter(home: &Path) -> Option<u32> {
    fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.file_name().is_some_and(|name| name == "uses") {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(&home.join("store").join("intents"), &mut found);
    found
        .first()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| text.trim().parse().ok())
}

/// Share `s1` with the agent, bounded by `uses`.
fn share_with_uses(home: &Path, agent: &str, uses: u32) -> PathBuf {
    let token = home.join("token.ksp");
    let (code, output) = ksp_in(
        home,
        &[
            "secret",
            "share",
            "s1",
            "--agent",
            agent,
            "--name",
            "db_password",
            "--out",
            token.to_str().expect("a utf-8 path"),
            "--ttl",
            "7200",
            "--uses",
            &uses.to_string(),
            "--passphrase-file",
            home.join("pw").to_str().expect("a utf-8 path"),
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "secret share failed: {output}");
    token
}

/// A deployment with one user-written secret granted to one agent.
fn deployment_with_secret(home: &Path) -> (String, PathBuf) {
    let owner = provision(home);
    arm_and_sweep(home, owner);
    let agent = enrol_agent(home);
    let (code, output) = ksp_in(
        home,
        &[
            "secret",
            "set",
            "s1",
            "--name",
            "db_password",
            "--passphrase-file",
            home.join("pw").to_str().expect("a utf-8 path"),
        ],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "secret set failed: {output}");
    let (code, output) = ksp_in(
        home,
        &["admin", "policy", "--agent", &agent, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");
    let token = share_with_uses(home, &agent, 3);
    (agent, token)
}

fn run_token(home: &Path, token: &Path, consume: bool) -> (i32, String) {
    let mut args = vec!["run"];
    if consume {
        args.push("--consume");
    }
    args.extend_from_slice(&[
        "--token",
        token.to_str().expect("a utf-8 path"),
        "--env",
        "X",
        "--",
        "/usr/bin/printenv",
        "X",
    ]);
    ksp_in(home, &args, None)
}

/// Three plain runs spend the bound, and the sweep then removes the copy.
#[test]
fn three_plain_runs_spend_the_bound_and_the_sweep_removes_it() {
    let home = tempfile::tempdir().unwrap();
    let (_agent, token) = deployment_with_secret(home.path());

    assert_eq!(counter(home.path()), Some(3), "the bound is armed");

    for expected in [2, 1, 0] {
        let (code, output) = run_token(home.path(), &token, false);
        assert_eq!(code, exit::SUCCESS, "a bounded run delivers: {output}");
        assert!(
            output.contains(VALUE),
            "the value reaches the child: {output}"
        );
        assert_eq!(
            counter(home.path()),
            Some(expected),
            "a plain run spends one permitted delivery"
        );
    }

    // The copy is still present: a plain run leaves it, and only the sweep
    // removes it.
    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);
    assert_eq!(code, exit::SUCCESS, "the sweep runs: {output}");
    assert!(
        output.contains("removed 1"),
        "an exhausted counter is what the sweep removes: {output}"
    );

    let (code, output) = run_token(home.path(), &token, false);
    assert_eq!(
        code,
        exit::MISSING_KEY,
        "the copy is gone after the sweep: {output}"
    );
}

/// `--consume` spends one and deletes, whatever the count.
///
/// The use bound does not change what `--consume` means: it still removes the
/// version on the first run, so a bound of three is spent once.
#[test]
fn consume_spends_one_and_deletes_immediately() {
    let home = tempfile::tempdir().unwrap();
    let (_agent, token) = deployment_with_secret(home.path());

    let (code, output) = run_token(home.path(), &token, true);
    assert_eq!(code, exit::SUCCESS, "the consume delivers: {output}");
    assert!(
        output.contains(VALUE),
        "the value reaches the child: {output}"
    );
    assert_eq!(
        counter(home.path()),
        Some(2),
        "the consume spends one permitted delivery"
    );

    let (code, output) = run_token(home.path(), &token, false);
    assert_eq!(
        code,
        exit::MISSING_KEY,
        "the version is gone after a consume, whatever the count: {output}"
    );
}

/// An unbounded share behaves exactly as it did before.
#[test]
fn an_unbounded_share_has_no_counter_and_runs_repeatedly() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    arm_and_sweep(home.path(), owner);
    let agent = enrol_agent(home.path());
    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "set",
            "s1",
            "--name",
            "db_password",
            "--passphrase-file",
            home.path().join("pw").to_str().expect("a utf-8 path"),
        ],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "secret set failed: {output}");
    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &agent, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");

    let token = home.path().join("token.ksp");
    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "share",
            "s1",
            "--agent",
            &agent,
            "--name",
            "db_password",
            "--out",
            token.to_str().expect("a utf-8 path"),
            "--ttl",
            "7200",
            "--passphrase-file",
            home.path().join("pw").to_str().expect("a utf-8 path"),
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "secret share failed: {output}");
    assert_eq!(
        counter(home.path()),
        None,
        "a time-bounded share arms no counter"
    );

    for _ in 0..3 {
        let (code, output) = run_token(home.path(), &token, false);
        assert_eq!(
            code,
            exit::SUCCESS,
            "an unbounded copy delivers repeatedly: {output}"
        );
    }
}

/// A user arming and a user sweep are enough on their own.
///
/// This is the whole point of the feature: the user bounds her own copy and
/// enforces it herself, with no admin arming and no admin proof. Before this,
/// the mint gate refused every lease until the admin had armed and swept.
#[test]
fn a_user_arming_and_sweep_admit_a_copy_with_no_admin_involvement() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let agent = enrol_agent(home.path());
    let scope = format!("p/vault-1/{owner}/agent-*");
    let delete = format!("delete:{scope}");
    let pw = home.path().join("pw");
    let pw = pw.to_str().expect("a utf-8 path");

    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "set",
            "s1",
            "--name",
            "personal",
            "--passphrase-file",
            pw,
        ],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "secret set failed: {output}");
    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &agent, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");

    // The user arms her own schedule, signed by her key.
    let (code, output) = ksp_in(
        home.path(),
        &[
            "backend",
            "arm-sweep",
            "--interval",
            "3600",
            "--scope",
            &scope,
            "--credential",
            "unix:ksp-user",
            "--grant",
            &delete,
            "--identifier",
            "my-gc",
            "--user-arming",
            "--passphrase-file",
            pw,
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the user arming failed: {output}");

    // Her own sweep proves the cadence.
    let (code, output) = ksp_in(
        home.path(),
        &["secret", "gc", "--user-arming", "--passphrase-file", pw],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the user sweep failed: {output}");
    assert!(
        output.contains("capability=Scheduled"),
        "her own arming is what her sweep serves: {output}"
    );

    // And the share mints, with no admin arming anywhere.
    let token = home.path().join("token.ksp");
    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "share",
            "s1",
            "--agent",
            &agent,
            "--name",
            "personal",
            "--out",
            token.to_str().expect("a utf-8 path"),
            "--ttl",
            "7200",
            "--uses",
            "1",
            "--passphrase-file",
            pw,
        ],
        None,
    );
    assert_eq!(
        code,
        exit::SUCCESS,
        "a user-bounded copy mints without an admin proof: {output}"
    );
}

/// The user's sweep is attributed to her, not to the admin.
///
/// The audit log exists to say who did what. A user's deletion signed by the
/// admin key would be a false claim in the one record whose purpose is
/// attribution.
#[test]
fn a_user_sweep_is_signed_by_the_user() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let scope = format!("p/vault-1/{owner}/agent-*");
    let delete = format!("delete:{scope}");
    let pw = home.path().join("pw");
    let pw = pw.to_str().expect("a utf-8 path");

    let (code, output) = ksp_in(
        home.path(),
        &[
            "backend",
            "arm-sweep",
            "--interval",
            "3600",
            "--scope",
            &scope,
            "--credential",
            "unix:ksp-user",
            "--grant",
            &delete,
            "--identifier",
            "my-gc",
            "--user-arming",
            "--passphrase-file",
            pw,
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the user arming failed: {output}");
    let (code, output) = ksp_in(
        home.path(),
        &["secret", "gc", "--user-arming", "--passphrase-file", pw],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the user sweep failed: {output}");

    let (code, output) = ksp_in(
        home.path(),
        &["audit", "--admin", "--passphrase-file", pw],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "audit failed: {output}");
    let sweep = output
        .lines()
        .find(|line| line.contains("operation=sweep"))
        .unwrap_or_else(|| panic!("the sweep is recorded: {output}"));
    assert!(
        !sweep.contains("signer=admin-"),
        "a user sweep must not be signed by the admin: {sweep}"
    );
    assert!(
        sweep.contains("signer=alice-ed25519-1"),
        "the user's own key signs her sweep: {sweep}"
    );
}
