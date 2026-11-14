//! `ksp backend arm-sweep --install` through the real binary.
//!
//! # What these prove that a unit test cannot
//!
//! `ksp_cli::install` proves the installer writes at `0600`, refuses a
//! system-wide target and records what it did. These prove the command reaches
//! it, that a refusal runs no process, and — the point of misfit E — that a
//! successful install never becomes evidence.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use ksp_cli::exit;
use ksp_types::PrincipalId;

const PASSWORD: &str = "a long enough password";

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

fn provision(home: &Path) -> PrincipalId {
    let (code, output) = ksp_in(
        home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin init failed: {output}");
    let (code, output) = ksp_in(home, &["admin", "user", "add"], Some(PASSWORD));
    assert_eq!(code, exit::SUCCESS, "admin user add failed: {output}");
    let (deployment, _anchor) =
        ksp_cli::deployment::require(&ksp_cli::config::Layout::new(home.to_path_buf())).unwrap();
    deployment.user
}

/// One complete install invocation, with `HOME` pointed at a throwaway tree.
///
/// `ksp` writes a LaunchAgent under the operator's home, so the test gives it
/// a home it owns rather than touching the real one.
fn install_in(home: &Path, fake_home: &Path, scope: &str, extra: &[&str]) -> (i32, String) {
    let delete = format!("delete:{scope}");
    let list = format!("list:{scope}");
    let mut args = vec![
        "backend",
        "arm-sweep",
        "--kind",
        "launchd",
        "--interval",
        "1h",
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
        "--install",
    ];
    args.extend_from_slice(extra);
    let mut command = Command::new(ksp());
    command
        .env("KSP_HOME", home)
        .env("HOME", fake_home)
        .env("LC_ALL", "C")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let output = command.output().expect("the binary runs");
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.code().unwrap_or(-1), combined)
}

fn scope(owner: PrincipalId) -> String {
    format!("p/vault-1/{owner}/agent-*")
}

/// The install writes a `0600` property list under the operator's own home.
///
/// The file is written before the load is attempted, so this asserts the file
/// rather than the exit code: whether `launchd` can load it is environmental,
/// and the write is what this test is about.
#[test]
fn an_install_writes_a_private_plist_under_the_operators_home() {
    let home = tempfile::tempdir().unwrap();
    let fake_home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());

    let (_code, output) = install_in(home.path(), fake_home.path(), &scope(owner), &[]);

    let agents = fake_home.path().join("Library/LaunchAgents");
    let entries: Vec<_> = std::fs::read_dir(&agents)
        .unwrap_or_else(|error| panic!("the LaunchAgents directory exists: {error}; {output}"))
        .filter_map(Result::ok)
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "exactly one plist is written: {entries:?}"
    );

    let path = entries[0].path();
    let mode =
        std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&path).unwrap().permissions());
    assert_eq!(mode & 0o777, 0o600, "the plist is private to its owner");

    let body = std::fs::read_to_string(&path).unwrap();
    assert!(body.contains("Label"), "{body}");
    assert!(body.contains("StartInterval"), "{body}");
}

/// The plist carries the resolved `KSP_HOME`, not an empty string.
///
/// The job runs outside this invocation and inherits no environment, so the
/// home it must read has to be written into the file. This runs with `KSP_HOME`
/// **unset**, which is the only case that tells the two implementations apart:
/// `layout.root()` falls back to `.ksp` under the working directory, while a
/// second read of the variable yields an empty string. A job with no home
/// sweeps nothing.
#[test]
fn the_plist_carries_the_resolved_home() {
    let fake_home = tempfile::tempdir().unwrap();
    // The deployment lives at `<cwd>/.ksp`, which is where the binary looks when
    // `KSP_HOME` is unset. Provisioning writes it there.
    let cwd = tempfile::tempdir().unwrap();
    let deployment = cwd.path().join(".ksp");
    let owner = provision(&deployment);

    let scope = scope(owner);
    let delete = format!("delete:{scope}");
    let list = format!("list:{scope}");
    let mut command = Command::new(ksp());
    command
        .env("HOME", fake_home.path())
        .env("LC_ALL", "C")
        // The point of the test: the operator relied on the default.
        .env_remove("KSP_HOME")
        .current_dir(cwd.path())
        .args([
            "backend",
            "arm-sweep",
            "--kind",
            "launchd",
            "--interval",
            "1h",
            "--scope",
            &scope,
            "--credential",
            "unix:ksp-sweeper",
            "--grant",
            &delete,
            "--grant",
            &list,
            "--grant",
            "write:journal",
            "--install",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let output = command.output().expect("the binary runs");
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);

    let agents = fake_home.path().join("Library/LaunchAgents");
    let path = std::fs::read_dir(&agents)
        .unwrap_or_else(|error| panic!("the LaunchAgents directory exists: {error}; {combined}"))
        .filter_map(Result::ok)
        .next()
        .expect("one plist was written")
        .path();
    let body = std::fs::read_to_string(&path).unwrap();

    // With no `KSP_HOME`, the resolved root is `.ksp` under the working
    // directory. The plist must name that, not an empty string.
    assert!(
        !body.contains("<key>KSP_HOME</key>\n    <string></string>"),
        "the plist must not carry an empty home: {body}"
    );
    assert!(
        body.contains(".ksp"),
        "the plist names the resolved default home: {body}"
    );
}

/// A successful install is a declaration, not evidence.
///
/// Misfit E: the capability stays `None` until a fresh verified proof exists.
/// If an install made the capability `Scheduled`, a lease would be admitted on
/// a schedule nothing has proven.
///
/// The load itself is not asserted here: whether this machine has a usable
/// `launchd` GUI domain is environmental, and the property under test holds
/// whether the load succeeds or fails. The unit tests in `ksp_cli::install`
/// cover the load through a recording runner, so the seam is exercised without
/// depending on the host.
#[test]
fn a_successful_install_does_not_make_the_capability_scheduled() {
    let home = tempfile::tempdir().unwrap();
    let fake_home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());

    // The install may fail to load on a host with no GUI domain; either way the
    // plist is written and the capability must not move.
    let (_code, output) = install_in(home.path(), fake_home.path(), &scope(owner), &[]);
    assert!(
        !output.contains("Try re-running the command as root"),
        "a load failure must not suggest escalation: {output}"
    );

    let (code, output) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    assert!(
        !output.contains("capability:  Scheduled"),
        "an install is a declaration, not evidence: {output}"
    );
}

/// A kind that is not `launchd` is refused, and no file is written.
#[test]
fn a_non_launchd_install_is_refused_and_writes_nothing() {
    let home = tempfile::tempdir().unwrap();
    let fake_home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let scope = scope(owner);
    let delete = format!("delete:{scope}");
    let list = format!("list:{scope}");

    let mut command = Command::new(ksp());
    command
        .env("KSP_HOME", home.path())
        .env("HOME", fake_home.path())
        .env("LC_ALL", "C")
        .args([
            "backend",
            "arm-sweep",
            "--kind",
            "crontab",
            "--interval",
            "1h",
            "--scope",
            &scope,
            "--credential",
            "unix:ksp-sweeper",
            "--grant",
            &delete,
            "--grant",
            &list,
            "--grant",
            "write:journal",
            "--install",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let output = command.output().expect("the binary runs");
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    let code = output.status.code().unwrap_or(-1);

    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "a crontab install is refused: {combined}"
    );
    let agents = fake_home.path().join("Library/LaunchAgents");
    assert!(
        !agents.exists() || std::fs::read_dir(&agents).unwrap().next().is_none(),
        "a refused install writes nothing"
    );
}

/// The refusal names no privileged command.
///
/// Misfit C: the easiest way to reach a schedule is to escalate, and the
/// refusal must not suggest it.
#[test]
fn an_install_refusal_names_no_privileged_command() {
    let home = tempfile::tempdir().unwrap();
    let fake_home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let scope = scope(owner);
    let delete = format!("delete:{scope}");
    let list = format!("list:{scope}");

    let mut command = Command::new(ksp());
    command
        .env("KSP_HOME", home.path())
        .env("HOME", fake_home.path())
        .env("LC_ALL", "C")
        .args([
            "backend",
            "arm-sweep",
            "--kind",
            "crontab",
            "--interval",
            "1h",
            "--scope",
            &scope,
            "--credential",
            "unix:ksp-sweeper",
            "--grant",
            &delete,
            "--grant",
            &list,
            "--grant",
            "write:journal",
            "--install",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let output = command.output().expect("the binary runs");
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);

    assert!(
        !combined.contains("sudo"),
        "the refusal suggests no escalation: {combined}"
    );
    assert!(
        !combined.contains("/Library/LaunchDaemons"),
        "the refusal names no system-wide target: {combined}"
    );
}

/// A bad scope is refused before any install is attempted.
///
/// WP01's refusal must fire first: installing a job for a scope admission
/// never reads would install a schedule that reaches no lease.
#[test]
fn a_bad_scope_is_refused_before_the_install_runs() {
    let home = tempfile::tempdir().unwrap();
    let fake_home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let one = format!("p/vault-1/{owner}/agent-1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f");

    let (code, output) = install_in(home.path(), fake_home.path(), &one, &[]);
    assert_eq!(code, exit::POLICY_DENIAL, "the scope is refused: {output}");
    assert!(
        output.contains(&scope(owner)),
        "the refusal names the accepted shape: {output}"
    );
    let agents = fake_home.path().join("Library/LaunchAgents");
    assert!(
        !agents.exists() || std::fs::read_dir(&agents).unwrap().next().is_none(),
        "a refused scope installs nothing"
    );
}
