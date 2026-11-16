//! `ksp backend arm-sweep` through the real binary.
//!
//! # What these prove that a unit test cannot
//!
//! `ksp_backend::sweeper` proves the guards decide correctly. These prove the command
//! asks them and then behaves: one arming per backend and scope, a replacement that
//! reports what it replaced, a unit template printed rather than installed, and a
//! query that says it decides nothing.
//!
//! The last test reads the command's own source, because acceptance 4 is a negative:
//! no privileged helper may be spawned. A runtime assertion cannot see a call that was
//! never made, and a comment cannot enforce one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use ksp::config::Layout;
use ksp::exit;
use ksp_types::PrincipalId;

/// The vault password every invocation in this file uses.
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
        // A command that refuses before reading input closes the pipe first; the
        // broken pipe is this test's own write, not the refusal under test.
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
    let (deployment, _anchor) = ksp::deployment::require(&Layout::new(home.to_path_buf())).unwrap();
    deployment.user
}

/// The canonical scope for this deployment.
fn scope(owner: PrincipalId) -> String {
    format!("p/vault-1/{owner}/agent-*")
}

/// One complete arming invocation.
fn arm(home: &Path, scope: &str, extra: &[&str]) -> (i32, String) {
    arm_with(home, scope, "1h", extra)
}

/// The same invocation at another interval.
fn arm_with(home: &Path, scope: &str, interval: &str, extra: &[&str]) -> (i32, String) {
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
    args.extend_from_slice(extra);
    ksp_in(home, &args, None)
}

/// Acceptance 1 and misfit P: one arming per backend and scope, and a replace that
/// says what it replaced.
#[test]
fn a_second_arming_is_refused_and_replace_reports_the_previous_record() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let scope = scope(owner);

    let (code, output) = arm(home.path(), &scope, &[]);
    assert_eq!(code, exit::SUCCESS, "the first arming failed: {output}");
    assert!(output.contains("id="), "{output}");

    let (code, output) = arm(home.path(), &scope, &[]);
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "a second arming must be refused: {output}"
    );
    assert!(
        output.contains("already armed") && output.contains("--replace"),
        "the refusal names the collision and the flag: {output}"
    );

    let (code, output) = arm_with(home.path(), &scope, "30m", &["--replace"]);
    assert_eq!(code, exit::SUCCESS, "the replacement failed: {output}");
    assert!(
        output.contains("replaced:"),
        "a replacement must report what it replaced: {output}"
    );
    assert!(output.contains("interval=3600s"), "{output}");
    assert!(output.contains("interval=1800s"), "{output}");
}

/// Acceptance 2 and misfit O: the width is checked, and the refusal names it.
///
/// The third case used to assert that `{scope}/db-password` armed successfully.
/// That was the defect written as a requirement: the trailing segment was dropped
/// and the command reported success for a sweep that could never run. A scope is a
/// level, so a scope naming a record is refused — see
/// `a_scope_deeper_than_the_level_is_refused_at_the_command` for the full case.
#[test]
fn a_broader_scope_is_refused_and_a_deeper_one_is_refused_too() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());

    let (code, output) = arm(home.path(), "p/vault-1", &[]);
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "a vault-wide scope must be refused: {output}"
    );
    assert!(output.contains("broader"), "{output}");

    let (code, output) = arm(home.path(), &format!("p/vault-1/{owner}"), &[]);
    assert_eq!(code, exit::POLICY_DENIAL, "{output}");
    assert!(
        output.contains("user and admin levels"),
        "the refusal says which levels it would have reached: {output}"
    );

    let deeper = format!("{}/db-password", scope(owner));
    let (code, output) = arm(home.path(), &deeper, &[]);
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "a scope naming a record must be refused: {output}"
    );
    assert!(
        output.contains(&scope(owner)),
        "the refusal names the accepted level: {output}"
    );
}

/// Misfit A: an operator who arms `agent-<uuid>` is told the accepted shape.
///
/// The scope parses as one agent level, which reaches no lease admission reads.
/// Before this refusal the operator was told about a missing sweep proof, which
/// is true and useless.
#[test]
fn an_agent_uuid_scope_is_refused_and_names_the_accepted_shape() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let one = format!("p/vault-1/{owner}/agent-1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f");

    let (code, output) = arm(home.path(), &one, &[]);
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "an agent-uuid scope must be refused: {output}"
    );
    assert!(
        output.contains(&scope(owner)),
        "the refusal names the accepted shape: {output}"
    );
    assert!(
        output.contains("--scope"),
        "the admin refusal says what to re-run: {output}"
    );
}

/// Misfit B: the refusal never normalises the scope into an accepted one.
#[test]
fn a_refused_scope_does_not_record_an_arming() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let one = format!("p/vault-1/{owner}/agent-1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f");

    let (code, _) = arm(home.path(), &one, &[]);
    assert_eq!(code, exit::POLICY_DENIAL);
    // Nothing was recorded, so the canonical scope is still free to arm.
    let (code, output) = arm(home.path(), &scope(owner), &[]);
    assert_eq!(
        code,
        exit::SUCCESS,
        "a refused scope must not leave a record behind: {output}"
    );
    assert!(
        !output.contains("replaced:"),
        "the canonical scope replaced nothing: {output}"
    );
}

/// The same refusal, rendered for a user arming, names what she can run.
///
/// The accepted shape is one definition, but the next step is not: an admin
/// arms `agent-*`, while a user's own cleanup is `ksp secret gc`. One variant
/// carries the shape; the caller supplies the step, because only the caller
/// knows which authority is acting.
#[test]
fn a_user_armings_scope_refusal_names_the_user_command() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let one = format!("p/vault-1/{owner}/agent-1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f");
    let passphrase = home.path().join("pw");
    std::fs::write(&passphrase, PASSWORD).unwrap();
    let passphrase = passphrase.to_str().expect("a utf-8 path");

    let delete = format!("delete:{one}");
    let list = format!("list:{one}");
    let (code, output) = ksp_in(
        home.path(),
        &[
            "backend",
            "arm-sweep",
            "--interval",
            "1h",
            "--scope",
            &one,
            "--credential",
            "unix:ksp-user",
            "--grant",
            &delete,
            "--grant",
            &list,
            "--user-arming",
            "--passphrase-file",
            passphrase,
        ],
        None,
    );
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "a user arming with an agent-uuid scope is refused: {output}"
    );
    assert!(
        output.contains("ksp secret gc"),
        "the user refusal names the command she can run: {output}"
    );
    assert!(
        !output.contains("--scope"),
        "the user refusal does not tell her to re-run the admin command: {output}"
    );
    assert!(
        output.contains(&scope(owner)),
        "the refusal still names the accepted shape: {output}"
    );
}

/// Acceptance 3 and misfit Q: the credential's width is checked.
#[test]
fn a_root_credential_is_refused_and_delete_list_is_accepted() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let scope = scope(owner);

    let delete = format!("delete:{scope}");
    let read = format!("read:{scope}");
    let mut args = vec![
        "backend",
        "arm-sweep",
        "--interval",
        "1h",
        "--scope",
        scope.as_str(),
        "--credential",
        "root",
        "--grant",
        delete.as_str(),
    ];
    let (code, output) = ksp_in(home.path(), &args, None);
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "a root credential must be refused: {output}"
    );
    assert!(
        output.contains("owns the store") && output.contains("every right"),
        "the excess is named: {output}"
    );

    // A read grant is refused even under a bare identity.
    args[7] = "unix:ksp-sweeper";
    args.push("--grant");
    args.push(read.as_str());
    let (code, output) = ksp_in(home.path(), &args, None);
    assert_eq!(code, exit::POLICY_DENIAL, "{output}");
    assert!(
        output.contains("'read'"),
        "the excess names the right: {output}"
    );

    let (code, output) = arm(home.path(), &scope, &[]);
    assert_eq!(
        code,
        exit::SUCCESS,
        "delete+list+journal is enough: {output}"
    );
}

/// Acceptance 5 and misfit C: the template is printed with the accuracy pin, and
/// nothing is installed.
#[test]
fn the_unit_template_is_printed_and_nothing_is_installed() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());

    let (code, output) = arm(home.path(), &scope(owner), &["--kind", "systemd"]);
    assert_eq!(code, exit::SUCCESS, "{output}");
    assert!(output.contains("AccuracySec=1s"), "{output}");
    assert!(output.contains("User=ksp-admin"), "{output}");
    assert!(output.contains("Type=oneshot"), "{output}");
    assert!(
        output.contains("nothing was installed"),
        "a declaration must not read as an installation: {output}"
    );
    assert!(
        output.contains("configuration until a signed sweep proof"),
        "the record says what it is not: {output}"
    );
    assert!(
        !Path::new("/etc/systemd/system/ksp-sweep.service").exists(),
        "the command must not write a unit"
    );
}

/// The local store follows the host's scheduler, and the artifact follows the kind.
#[test]
fn a_launchd_arming_records_the_kind_and_prints_a_plist() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());

    let (code, output) = arm(home.path(), &scope(owner), &["--kind", "launchd"]);
    assert_eq!(code, exit::SUCCESS, "{output}");
    assert!(output.contains("kind=launchd"), "{output}");
    assert!(
        output.contains("identifier=com.keyspout.sweep"),
        "the default label is what launchctl unload names: {output}"
    );
    assert!(output.contains("<key>StartInterval</key>"), "{output}");
    assert!(output.contains("<integer>3600</integer>"), "{output}");
    assert!(output.contains("<key>KSP_HOME</key>"), "{output}");
    assert!(
        output.contains(&home.path().display().to_string()),
        "the job carries the operator's own home, not a guessed one: {output}"
    );
    assert!(
        output.contains("no property list"),
        "a declaration must not read as an installation: {output}"
    );
    assert!(
        !Path::new("/Library/LaunchDaemons/com.keyspout.sweep.plist").exists(),
        "the command must not write a plist"
    );
}

/// FR-005: both local schedulers stay accepted; a crontab on a local store does not.
#[test]
fn both_local_schedulers_are_accepted_and_a_local_crontab_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let scope = scope(owner);

    let (code, output) = arm(home.path(), &scope, &["--kind", "systemd", "--replace"]);
    assert_eq!(
        code,
        exit::SUCCESS,
        "systemd must stay accepted on a local store on every platform: {output}"
    );
    assert!(output.contains("AccuracySec=1s"), "{output}");

    let (code, output) = arm(home.path(), &scope, &["--kind", "launchd", "--replace"]);
    assert_eq!(code, exit::SUCCESS, "{output}");
    assert!(output.contains("<key>StartInterval</key>"), "{output}");

    let (code, output) = arm(home.path(), &scope, &["--kind", "crontab", "--replace"]);
    assert_ne!(
        code,
        exit::SUCCESS,
        "a crontab is not a local scheduler: {output}"
    );
    assert!(
        output.contains("crontab") && output.contains("file"),
        "the refusal names the kind and the backend: {output}"
    );
}

/// FR-006: a launchd query reports what the manager says, and names no command
/// this host could run.
///
/// # This test used to assert `unknown:`
///
/// It pinned the behaviour that `ArmingQuery::for_kind` returned `Unknown` for
/// `launchd`, with the note that this build records the query and the operator
/// runs it. That was true of the *query* and false of the *fact*: `launchctl
/// print` reports the job's state, and the build now reads it. A status line that
/// said `unknown` while the answer was one command away told an operator their
/// schedule was unverifiable when it was not.
///
/// What still holds, and is what this test is for: the query names no `systemctl`
/// command on a Mac, and it decides nothing.
#[test]
fn a_launchd_query_measures_the_job_and_names_no_systemctl_command() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());

    let (code, output) = arm(
        home.path(),
        &scope(owner),
        &["--kind", "launchd", "--query"],
    );
    assert_eq!(code, exit::SUCCESS, "{output}");
    // The job is not installed in this fixture, so the manager cannot report it.
    // Both `reported` and `unknown` are correct answers here; what must not
    // appear is a `systemctl` command, which a Mac cannot run.
    assert!(
        output.contains("unknown:") || output.contains("reported"),
        "the query must say what the manager answered, or why it could not: {output}"
    );
    assert!(output.contains("decides nothing"), "{output}");
    assert!(
        !output.contains("systemctl show"),
        "a Mac has no systemctl to show: {output}"
    );
}

/// Acceptance 6 and T034: the query describes and decides nothing.
#[test]
fn the_query_says_it_decides_nothing() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());

    // The kind is named here because the default now follows the host: on macOS a
    // bare `arm-sweep` records a launchd job, and this test is about the systemd
    // query.
    let (code, output) = arm(
        home.path(),
        &scope(owner),
        &["--kind", "systemd", "--query"],
    );
    assert_eq!(code, exit::SUCCESS, "{output}");
    assert!(output.contains("decides nothing"), "{output}");
    assert!(
        output.contains("systemctl show"),
        "the query an operator would run is named: {output}"
    );
}

/// Acceptance 4, as a source assertion: no privileged helper is spawned from here.
#[test]
fn the_arming_command_spawns_no_privileged_helper() {
    let source = include_str!("../src/arm.rs");
    // The prose is allowed to name what the code must not do; the code is not.
    let code = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    // Names are fine — the kinds and the query's argv mention them. What must not
    // appear is a way to *run* something, or a path a service manager reads.
    for forbidden in [
        "Command::new",
        "std::process",
        "sudo",
        "/etc/systemd",
        "crontab -",
    ] {
        assert!(
            !code.contains(forbidden),
            "the arming command must not reference '{forbidden}'"
        );
    }
}

/// Misfit K: a binding that names nothing is refused, and no record is written.
#[test]
fn a_blank_credential_is_refused_and_writes_nothing() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let scope = scope(owner);

    let delete = format!("delete:{scope}");
    let (code, output) = ksp_in(
        home.path(),
        &[
            "backend",
            "arm-sweep",
            "--interval",
            "1h",
            "--scope",
            scope.as_str(),
            "--credential",
            " ",
            "--grant",
            delete.as_str(),
        ],
        None,
    );
    assert_eq!(code, exit::POLICY_DENIAL, "{output}");
    assert!(
        output.contains("names no identity"),
        "the refusal names the hole: {output}"
    );
    let armings = Layout::new(home.path().to_path_buf()).sweeper_armings_dir();
    let written = std::fs::read_dir(&armings)
        .map(|entries| entries.flatten().count())
        .unwrap_or(0);
    assert_eq!(written, 0, "a refused arming writes no record");
}

/// A scope deeper than the level is refused, and the refusal names the level.
///
/// Before this guard `SweepScope::parse` inspected the level segment and never
/// checked the arity, so `agent-*/db-password` armed, exited `0`, and the
/// capability never moved: `gc` then reported that no armed record was read while
/// one existed. The operator saw success and a sweep that did nothing.
#[test]
fn a_scope_deeper_than_the_level_is_refused_at_the_command() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let accepted = scope(owner);
    let deeper = format!("{accepted}/db-password");

    let (code, output) = arm(home.path(), &deeper, &[]);
    assert_ne!(
        code,
        exit::SUCCESS,
        "a scope naming a record must not arm: {output}"
    );
    assert!(
        output.contains(&accepted),
        "the refusal must name the accepted scope ({accepted}): {output}"
    );
    assert!(
        output.contains("level"),
        "the refusal must say a scope is a level: {output}"
    );

    // Nothing was recorded: the next arming of the accepted shape is the first,
    // not a collision with the refused one.
    let (code, output) = arm(home.path(), &accepted, &[]);
    assert_eq!(
        code,
        exit::SUCCESS,
        "the accepted scope must still arm after a refusal: {output}"
    );
}

/// A grant naming a record is refused, the same way the scope is.
///
/// The grant's scope goes through the same rule: `within` consumed every armed
/// segment and returned `true` whatever the grant had left over, so a grant of
/// `agent-*/db-password` was accepted as "within" `agent-*`.
#[test]
fn a_grant_deeper_than_the_level_is_refused_at_the_command() {
    let home = tempfile::tempdir().unwrap();
    let owner = provision(home.path());
    let accepted = scope(owner);
    let deeper = format!("{accepted}/db-password");

    let delete = format!("delete:{deeper}");
    let list = format!("list:{deeper}");
    let (code, output) = ksp_in(
        home.path(),
        &[
            "backend",
            "arm-sweep",
            "--interval",
            "1h",
            "--scope",
            &accepted,
            "--credential",
            "unix:ksp-sweeper",
            "--grant",
            &delete,
            "--grant",
            &list,
            "--grant",
            "write:journal",
        ],
        None,
    );
    assert_ne!(
        code,
        exit::SUCCESS,
        "a grant naming a record must not arm: {output}"
    );
    assert!(
        output.contains("wider than") || output.contains("grant"),
        "the refusal must name the grant: {output}"
    );
}
