//! The provisioning handover: what `admin user add --home` must leave behind.
//!
//! # What this covers
//!
//! D1 and D2 in `docs/known-defects.md`, in the half that needs **no** root: the
//! per-account-home topology without a `--unix-user` chown. Adding `--unix-user`
//! binds a file to another account and needs privilege, so the ownership half
//! lives in `principals.rs`; the *handover of the capability configuration* is the
//! same code either way and is observable here.
//!
//! # Why the outcome is three-way and not two
//!
//! `capability_config::read` returns `Ok(None)` for an absent file, documented as
//! *"the unconfigured state rather than a failure"*. So the handover has three
//! outcomes, and collapsing them is a defect:
//!
//! | `read` | Handover |
//! |---|---|
//! | `Ok(Some(config))` | copy it into the target home at `0644` |
//! | `Ok(None)` | write nothing, and do **not** refuse |
//! | `Err(refusal)` | refuse, naming the configuration |
//!
//! `None` is the operator's omission, not the handover's, and `admin user add` is
//! not the command that probes a host. A fixture that never configured its admin
//! home keeps working, which is the property CF-001 recorded.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::os::unix::fs::PermissionsExt;

use support::PASSWORD;

/// The strongest configuration this host offers, written the way `ksp init` writes
/// it: the admin runs it, so the file is the admin's and nobody else's.
fn configure(home: &std::path::Path) {
    let mut command = std::process::Command::new(support::ksp());
    command
        .env("KSP_HOME", home)
        .arg("init")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let output = command.output().expect("the binary runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "`ksp init` must succeed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn mode_of(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

/// A configured admin hands the configuration to the second home.
///
/// This is D1: the target home used to receive the vault, the record, the anchor
/// and the policy, and no configuration at all, so every `ksp run` from it refused
/// at exit 7 — the code for "this host cannot admit the lease", naming a file the
/// principal cannot create.
#[test]
fn a_configured_admin_hands_the_capability_configuration_to_the_second_home() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let admin_home = root.path().join("admin-home");
    let alice_home = root.path().join("alice-home");
    let store = root.path().join("store");
    std::fs::create_dir_all(&store).unwrap();

    let run = |home: &std::path::Path, args: &[&str], stdin: Option<&str>| {
        let mut command = std::process::Command::new(support::ksp());
        command
            .env("KSP_HOME", home)
            .env("KSP_STORE", &store)
            .args(args)
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().expect("the binary runs");
        if let Some(text) = stdin {
            use std::io::Write;
            child
                .stdin
                .take()
                .expect("stdin is piped")
                .write_all(text.as_bytes())
                .unwrap();
        }
        let output = child.wait_with_output().unwrap();
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr),
        )
    };

    let (code, output) = run(
        &admin_home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, 0, "admin init failed: {output}");

    // The admin configures the deployment, which is the precondition D1 describes.
    configure(&admin_home);
    let admin_config = admin_home.join("config.toml");
    assert!(admin_config.is_file(), "`ksp init` wrote the configuration");

    let (code, output) = run(
        &admin_home,
        &[
            "admin",
            "user",
            "add",
            "--home",
            alice_home.to_str().unwrap(),
        ],
        Some(PASSWORD),
    );
    assert_eq!(code, 0, "admin user add failed: {output}");

    let alice_config = alice_home.join("config.toml");
    assert!(
        alice_config.is_file(),
        "the handover writes the configuration into the target home, or every \
         `ksp run` there refuses at exit 7 with no file to fix; left in {}: {:?}",
        alice_home.display(),
        std::fs::read_dir(&alice_home)
            .map(|d| d
                .filter_map(Result::ok)
                .map(|e| e.file_name())
                .collect::<Vec<_>>())
            .unwrap_or_default()
    );

    // `0644`: the second principal must be able to read it and must not be able to
    // write it. The guard refuses a file another principal can write (`0o022`),
    // and read is what the second principal's `ksp run` needs.
    assert_eq!(
        mode_of(&alice_config),
        0o644,
        "the handed-over configuration is readable, not writable, by the other \
         principal"
    );

    // The bytes are the admin's: a handover that re-rendered the document could
    // disagree with the configuration the deployment actually runs under.
    assert_eq!(
        std::fs::read(&alice_config).unwrap(),
        std::fs::read(&admin_config).unwrap(),
        "the handover copies the configuration rather than inventing one"
    );
}

/// An unconfigured admin does not make enrolment refuse.
///
/// `None` is the unconfigured state, not a failure. Refusing here would break the
/// per-account-home topology's own fixture — `support::admin_and_two_users` never
/// runs `ksp init` — and with it 65 call sites across 9 suites.
#[test]
fn an_unconfigured_admin_still_enrols_and_writes_no_configuration() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let admin_home = root.path().join("admin-home");
    let alice_home = root.path().join("alice-home");
    let store = root.path().join("store");
    std::fs::create_dir_all(&store).unwrap();

    let run = |home: &std::path::Path, args: &[&str], stdin: Option<&str>| {
        let mut command = std::process::Command::new(support::ksp());
        command
            .env("KSP_HOME", home)
            .env("KSP_STORE", &store)
            .args(args)
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().expect("the binary runs");
        if let Some(text) = stdin {
            use std::io::Write;
            child
                .stdin
                .take()
                .expect("stdin is piped")
                .write_all(text.as_bytes())
                .unwrap();
        }
        let output = child.wait_with_output().unwrap();
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr),
        )
    };

    let (code, output) = run(
        &admin_home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, 0, "admin init failed: {output}");

    // Deliberately no `ksp init`: the admin home has no configuration.
    assert!(
        !admin_home.join("config.toml").exists(),
        "the fixture for this test must not configure the admin home"
    );

    let (code, output) = run(
        &admin_home,
        &[
            "admin",
            "user",
            "add",
            "--home",
            alice_home.to_str().unwrap(),
        ],
        Some(PASSWORD),
    );
    assert_eq!(
        code, 0,
        "an unconfigured admin is not a reason to refuse the enrolment: {output}"
    );

    assert!(
        !alice_home.join("config.toml").exists(),
        "there is nothing to copy, so the handover invents nothing"
    );
}

/// An existing configuration in the target home is left exactly as it was.
///
/// The second home may hold a configuration the operator wrote for that host. A
/// handover that overwrote it would silently change what the principal's deliveries
/// are allowed to establish.
#[test]
fn an_existing_target_configuration_is_left_alone() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let admin_home = root.path().join("admin-home");
    let alice_home = root.path().join("alice-home");
    let store = root.path().join("store");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::create_dir_all(&alice_home).unwrap();

    let run = |home: &std::path::Path, args: &[&str], stdin: Option<&str>| {
        let mut command = std::process::Command::new(support::ksp());
        command
            .env("KSP_HOME", home)
            .env("KSP_STORE", &store)
            .args(args)
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().expect("the binary runs");
        if let Some(text) = stdin {
            use std::io::Write;
            child
                .stdin
                .take()
                .expect("stdin is piped")
                .write_all(text.as_bytes())
                .unwrap();
        }
        let output = child.wait_with_output().unwrap();
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr),
        )
    };

    let (code, output) = run(
        &admin_home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, 0, "admin init failed: {output}");
    configure(&admin_home);

    // A configuration the operator wrote for *this* host, distinguishable from the
    // admin's by its bytes.
    let target_config = alice_home.join("config.toml");
    let operator_written = "confinement = { adapters = [\"none\"], requirement = \"optional\" }\n\
                            memory_barrier = { adapters = [\"mlock\"], requirement = \"optional\" }\n";
    std::fs::write(&target_config, operator_written).unwrap();
    std::fs::set_permissions(&target_config, std::fs::Permissions::from_mode(0o600)).unwrap();

    let (code, output) = run(
        &admin_home,
        &[
            "admin",
            "user",
            "add",
            "--home",
            alice_home.to_str().unwrap(),
        ],
        Some(PASSWORD),
    );
    assert_eq!(code, 0, "admin user add failed: {output}");

    assert_eq!(
        std::fs::read_to_string(&target_config).unwrap(),
        operator_written,
        "the operator's own configuration in the target home is not replaced"
    );
    assert_eq!(
        mode_of(&target_config),
        0o600,
        "and its mode is not changed either"
    );
}

/// The handed-over configuration is readable by the principal and not writable.
///
/// TE-003. `0644` is the whole point: the Mode and Owner Guard refuses a file
/// another principal can *write* (`0o022`), because that is the path that lowers a
/// requirement level, and reading is what the principal's `ksp run` needs. A
/// handover at `0600` — what `ksp init` writes in the admin's own home — would
/// defeat itself.
///
/// Asserted by the kernel rather than by reading the mode back: a mode a test
/// believes is a mode the code claims, and the property is what the kernel does
/// with it.
#[test]
fn the_handed_over_configuration_is_readable_and_not_writable_by_the_principal() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let admin_home = root.path().join("admin-home");
    let alice_home = root.path().join("alice-home");
    let store = root.path().join("store");
    std::fs::create_dir_all(&store).unwrap();

    let run = |home: &std::path::Path, args: &[&str], stdin: Option<&str>| {
        let mut command = std::process::Command::new(support::ksp());
        command
            .env("KSP_HOME", home)
            .env("KSP_STORE", &store)
            .args(args)
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().expect("the binary runs");
        if let Some(text) = stdin {
            use std::io::Write;
            child
                .stdin
                .take()
                .expect("stdin is piped")
                .write_all(text.as_bytes())
                .unwrap();
        }
        let output = child.wait_with_output().unwrap();
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr),
        )
    };

    let (code, output) = run(
        &admin_home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, 0, "admin init failed: {output}");
    configure(&admin_home);

    let (code, output) = run(
        &admin_home,
        &[
            "admin",
            "user",
            "add",
            "--home",
            alice_home.to_str().unwrap(),
        ],
        Some(PASSWORD),
    );
    assert_eq!(code, 0, "admin user add failed: {output}");

    let config = alice_home.join("config.toml");
    assert!(config.is_file(), "the handover wrote the configuration");

    // The guard's own condition, evaluated the way the reader evaluates it: no
    // write bit for group or other. Stated as an assertion on the mode *and* on
    // the guard, because a mode the guard rejects is a deployment that cannot run.
    let mode = mode_of(&config);
    assert_eq!(
        mode & 0o022,
        0,
        "no principal other than the owner may write the configuration: mode {mode:04o}"
    );
    assert!(
        ksp::capability_config::is_private(mode),
        "the handed-over mode must satisfy the Mode and Owner Guard: mode {mode:04o}"
    );
    // And it is readable, which `0600` would not be for anyone but the admin.
    assert_eq!(
        mode & 0o444,
        0o444,
        "the configuration is world-readable, so the principal can open it: mode {mode:04o}"
    );
}

/// An unconfigured admin still enrols, writes nothing, and **says so**.
///
/// Issue 4: the outcome stays successful (CF-001), but a silent skip leaves the
/// principal's later `ksp run` failing at exit 7 with a sentence about
/// confinement, and nothing connects it to this step.
#[test]
fn an_unconfigured_handover_reports_the_omission_without_failing() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let admin_home = root.path().join("admin-home");
    let alice_home = root.path().join("alice-home");
    let store = root.path().join("store");
    std::fs::create_dir_all(&store).unwrap();

    let mut command = std::process::Command::new(support::ksp());
    command
        .env("KSP_HOME", &admin_home)
        .env("KSP_STORE", &store)
        .args(["admin", "init", "--vault", "vault-1", "--user", "alice"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let output = command.output().expect("the binary runs");
    assert_eq!(output.status.code(), Some(0), "admin init failed");

    assert!(
        !admin_home.join("config.toml").exists(),
        "this test needs an unconfigured admin home"
    );

    let mut command = std::process::Command::new(support::ksp());
    command
        .env("KSP_HOME", &admin_home)
        .env("KSP_STORE", &store)
        .args([
            "admin",
            "user",
            "add",
            "--home",
            alice_home.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().expect("the binary runs");
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(PASSWORD.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(0),
        "the outcome does not change: an unconfigured admin is not a refusal"
    );
    assert!(
        stderr.contains("no capability configuration"),
        "the omission is reported rather than left to a later exit 7: {stderr}"
    );
    assert!(
        stderr.contains("ksp init"),
        "the notice names the command that fixes it: {stderr}"
    );
}

/// A delivery from a second home succeeds, which D1 made impossible.
///
/// TE-001. The whole point of the configuration handover: `ksp run` reads the
/// Capability Configuration from the invoking home before it does anything else,
/// so before this feature every command that establishes a capability from a
/// second principal's home refused at **exit 7** — *"the backend or the host layout
/// cannot admit this lease"* — naming a file she could not create.
///
/// # Why the earliest capability-establishing command is the assertion
///
/// The first such command in the sequence is `secret set`, and it fails at exit 7
/// on the unmodified tree. Asserting there is stronger than asserting on `run`:
/// it is the first point the defect reaches, so a passing assertion cannot be
/// satisfied by a later step that happens to work. `run` is exercised too, because
/// the defect entry names it, but the exit-7 check on `secret set` is the one that
/// cannot be true by accident.
///
/// # Why this is unprivileged and still proves the case
///
/// `--home` without `--unix-user` performs no `chown`, so the handover runs on
/// directories the invoking account owns. The *configuration* half of the handover
/// is identical either way, and that is the half D1 is about. The ownership half is
/// `principals.rs`'s business, behind `require_root()`.
#[test]
fn a_delivery_from_a_second_home_succeeds() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let admin_home = root.path().join("admin-home");
    let alice_home = root.path().join("alice-home");
    let store = root.path().join("store");
    std::fs::create_dir_all(&store).unwrap();

    let run = |home: &std::path::Path, args: &[&str], stdin: Option<&str>| {
        let mut command = std::process::Command::new(support::ksp());
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("KSP_HOME", home)
            .env("KSP_STORE", &store)
            .args(args)
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().expect("the binary runs");
        if let Some(text) = stdin {
            use std::io::Write;
            child
                .stdin
                .take()
                .expect("stdin is piped")
                .write_all(text.as_bytes())
                .unwrap();
        }
        let output = child.wait_with_output().unwrap();
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr),
        )
    };

    // 1. The admin provisions and configures this deployment.
    let (code, output) = run(
        &admin_home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, 0, "admin init failed: {output}");
    configure(&admin_home);

    // 2. The second home is enrolled, and receives the configuration.
    let (code, output) = run(
        &admin_home,
        &[
            "admin",
            "user",
            "add",
            "--home",
            alice_home.to_str().unwrap(),
        ],
        Some(PASSWORD),
    );
    assert_eq!(code, 0, "admin user add failed: {output}");
    assert!(
        alice_home.join("config.toml").is_file(),
        "the handover writes the configuration into this home"
    );

    let pass = root.path().join("pw");
    std::fs::write(&pass, PASSWORD).unwrap();

    // 3. The first capability-establishing command from the second home. On the
    //    unmodified tree this is exit 7, which is D1.
    let (code, output) = run(
        &alice_home,
        &[
            "secret",
            "set",
            "s1",
            "--name",
            "db_password",
            "--passphrase-file",
            pass.to_str().unwrap(),
        ],
        Some("correct-horse"),
    );
    assert_ne!(
        code, 7,
        "a command from the second home must not refuse for a capability the home \
         lacks; D1 was exactly this exit code: {output}"
    );
    assert_eq!(code, 0, "secret set from the second home failed: {output}");

    // 4. And the run path reads the same configuration. A token that names nothing
    //    is enough: `run` establishes its capability before it looks at the token,
    //    so a configuration failure appears here as the same exit 7.
    let bogus = alice_home.join("bogus.ksp");
    std::fs::write(&bogus, b"not a token").unwrap();
    let (code, output) = run(
        &alice_home,
        &[
            "run",
            "--token",
            bogus.to_str().unwrap(),
            "--env",
            "DB",
            "--",
            "/bin/sh",
            "-c",
            "printf %s \"$DB\"",
        ],
        None,
    );
    assert_ne!(
        code, 7,
        "the run path must not refuse for a capability this home lacks: {output}"
    );
}
