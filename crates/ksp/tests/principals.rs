//! The admin ↔ user boundary, with two real UNIX users.
//!
//! # What this file is for
//!
//! Misfit B says the boundary is mode bits and ownership. Misfit F says the admin
//! can destroy records it cannot read. Both are claims about the *kernel*, and a
//! test that asserts a Keyspout-side check proves neither: a client-side refusal
//! would pass while the file stayed readable to anyone who skipped the client.
//! So this file runs as `root`, creates two accounts, and asks the kernel.
//!
//! # Why it is not `#[ignore]`d
//!
//! A skipped security test reads like a pass. This one runs in the VM as `root`
//! and **fails** anywhere else, naming the command that runs it. The cost is that
//! `cargo test --workspace` must run as `root` inside the VM for this crate;
//! that is the price of a test that cannot be silently absent.
//!
//! # What it does not claim
//!
//! Nothing here bounds two processes that share one uid. The agent runs as its
//! user, and that boundary is Landlock plus the lease (misfit A), not a mode.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(unsafe_code)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use ksp::exit;
use ksp::layout;
use ksp_types::{Level, PrincipalId, VaultId};

/// A principal UUID for the level paths. Version 4, RFC 4122 variant, so the
/// strict parser accepts it.
const PRINCIPAL: &str = "6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f";
/// The agent whose level the admin will try to delete inside.
const AGENT: &str = "00000000-0000-4000-8000-000000000007";

fn ksp() -> &'static str {
    env!("CARGO_BIN_EXE_ksp")
}

/// The command that runs this file where it can mean something.
///
/// Built from the manifest directory so it is copy-pasteable from the host: the
/// worktree path is the one this test binary was compiled in.
fn vm_command() -> String {
    let worktree = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate lives inside the worktree")
        .display()
        .to_string();
    format!(
        "run in the VM: scripts/ksp-vm.sh sudo -n bash -c \
         'cd {worktree} && CARGO_TARGET_DIR=/tmp/ksp-root-target \
         cargo test -p ksp --test principals'"
    )
}

/// Refuse to run anywhere the boundary cannot be exercised.
fn require_root() {
    // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
    let euid = unsafe { libc::geteuid() };
    assert_eq!(euid, 0, "{}", vm_command());
}

#[test]
fn the_guard_names_the_command_instead_of_skipping() {
    // The failure has to be actionable, and it has to be a failure: a skip here
    // would read as a pass in every CI log that ever shows it.
    let message = vm_command();
    assert!(message.starts_with("run in the VM:"), "{message}");
    assert!(message.contains("--test principals"), "{message}");
    assert!(
        Path::new(env!("CARGO_MANIFEST_DIR")).is_absolute(),
        "the exact command must be usable from the host"
    );
}

/// The global lock `/etc/passwd` takes, held by both `useradd` and `userdel`.
///
/// These tests run in parallel threads, and two account changes racing for that
/// lock fail with "cannot lock /etc/passwd" — a flake that reads like a broken
/// fixture. One mutex here is cheaper and more honest than serialising the file.
static ACCOUNTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn accounts() -> std::sync::MutexGuard<'static, ()> {
    // A panic in another test must not turn every later account into a failure:
    // the guard protects a global lock, not data, so a poisoned mutex is still
    // the right mutual exclusion.
    ACCOUNTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Remove an account, taking the same lock `useradd` does.
fn remove_user(name: &str) {
    let _guard = accounts();
    let _ = Command::new("userdel").args(["-r", name]).output();
}

/// A throwaway account, removed even when an assertion panics.
struct TestUser {
    name: String,
    uid: u32,
    gid: u32,
}

impl Drop for TestUser {
    fn drop(&mut self) {
        // Best effort: a failed cleanup must not replace the assertion that was
        // already panicking, and the name carries a per-run suffix so a leftover
        // account cannot poison the next run.
        remove_user(&self.name);
    }
}

fn unique_suffix() -> String {
    // A counter, not only the clock: the sub-second nanoseconds wrap every ~17ms
    // once truncated to six hex digits, and two tests starting within one window
    // asked `useradd` for the same name.
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.subsec_nanos())
        .unwrap_or_default();
    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) & 0xfff;
    format!(
        "{:06x}{:04x}{:03x}",
        nanos,
        std::process::id() & 0xffff,
        sequence
    )
}

fn id_of(user: &str, flag: &str) -> u32 {
    let output = Command::new("id")
        .args([flag, user])
        .output()
        .expect("`id` runs");
    assert!(output.status.success(), "`id {flag} {user}` failed");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("`id` prints a number")
}

fn create_user(prefix: &str, suffix: &str) -> TestUser {
    let name = format!("{prefix}-{suffix}");
    let guard = accounts();
    // No subordinate ID ranges: these accounts open files and run the binary, and
    // a range is drawn from a shared pool this host may not have room in — the
    // failure is `useradd: Can't get unique subordinate UID range`, which has
    // nothing to do with what the test is measuring.
    let created = Command::new("useradd")
        .args([
            "-M",
            "-N",
            "-s",
            "/bin/sh",
            "-K",
            "SUB_UID_COUNT=0",
            "-K",
            "SUB_GID_COUNT=0",
            &name,
        ])
        .output()
        .expect("`useradd` runs");
    assert!(
        created.status.success(),
        "useradd failed for {name}: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    let uid = id_of(&name, "-u");
    let gid = id_of(&name, "-g");
    drop(guard);
    TestUser { name, uid, gid }
}

/// Run `program` as `user`, with the user's supplementary groups.
///
/// `.uid()`/`.gid()` alone leave root's supplementary groups attached, and a
/// probe that is supposed to be in `ksp-sweep` would then be denied by a mode it
/// really does satisfy. `initgroups` reads the account's groups, so the probe is
/// the process the deployment would have.
fn run_as(user: &TestUser, program: &str, args: &[&str]) -> Output {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    as_user(&mut command, user);
    command.output().expect("the probe runs")
}

/// Attach the child-side credential switch: groups, then gid, then uid.
fn as_user(command: &mut Command, user: &TestUser) {
    use std::os::unix::process::CommandExt;

    let name = std::ffi::CString::new(user.name.clone()).expect("a user name has no NUL");
    let (uid, gid) = (user.uid, user.gid);
    // `initgroups` takes the base group id as a `gid_t` on Linux and as a
    // `c_int` on Darwin. The two differ in width, so the argument is converted
    // per target rather than passed as the `u32` the record holds.
    #[cfg(target_os = "linux")]
    let base_group = gid;
    #[cfg(not(target_os = "linux"))]
    let base_group = gid as libc::c_int;
    // SAFETY: the closure runs in the child between fork and exec. Each call
    // either fails the spawn or changes only this process's credentials, and no
    // pointer outlives the call.
    unsafe {
        command.pre_exec(move || {
            if libc::initgroups(name.as_ptr(), base_group) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(gid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// The kernel said no, and it said so with `EACCES`.
fn assert_denied(user: &TestUser, program: &str, args: &[&str]) {
    let output = run_as(user, program, args);
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert!(
        !output.status.success(),
        "`{program} {args:?}` as {} must fail",
        user.name
    );
    assert!(
        stderr.contains("permission denied"),
        "`{program} {args:?}` as {} must be denied by the kernel, got: {stderr}",
        user.name
    );
}

/// The control: the same command against something the principal does own.
///
/// Without this, a test whose fixtures were never readable at all would pass
/// every denial assertion and prove nothing.
fn assert_allowed(user: &TestUser, program: &str, args: &[&str]) {
    let output = run_as(user, program, args);
    assert!(
        output.status.success(),
        "`{program} {args:?}` as {} must succeed, got: {}",
        user.name,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("the fixture paths are UTF-8")
}

#[test]
fn the_two_principal_boundary_is_a_mode_and_not_an_intention() {
    require_root();

    let suffix = unique_suffix();
    let admin = create_user("ksp-admin", &suffix);
    let user = create_user("ksp-user", &suffix);

    // A home whose roots carry the table's modes. `ensure` creates them owned by
    // this process; the two principals are then given the ones they own, which is
    // what a two-account deployment looks like after provisioning.
    let temp = tempfile::tempdir().unwrap();
    // The temporary root is created owner-only, and the second account has to
    // reach the home below it. Without this the run fails with `EACCES` on the
    // issuance ledger, which reads as a product bug and is not one: the test
    // never gave the account a way in.
    //
    // This is the same step the other two-account test does, and it was missing
    // here. It passed on a machine whose `TMPDIR` happened to be traversable and
    // failed on a clean CI runner, which is the worst kind of test bug: green
    // where it was written, red where it is trusted.
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let home = temp.path().join("ksp");
    layout::ensure(&home).unwrap();
    std::os::unix::fs::chown(&home, Some(admin.uid), Some(admin.gid)).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(layout::HOME_MODE)).unwrap();

    // FR-015's delete path on agent levels is the store's group. The store is a
    // deployment root, so it belongs to the admin that provisioned it, and a
    // level created below it takes that group.
    std::os::unix::fs::chown(home.join("store"), Some(admin.uid), Some(admin.gid)).unwrap();

    let admin_root = home.join("admin");
    std::os::unix::fs::chown(&admin_root, Some(admin.uid), Some(admin.gid)).unwrap();
    let admin_key = admin_root.join("admin-ed25519-1.key");
    std::fs::write(&admin_key, b"admin key material").unwrap();
    std::fs::set_permissions(&admin_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::chown(&admin_key, Some(admin.uid), Some(admin.gid)).unwrap();

    // The user's level and one agent level, both owned by the user principal —
    // an agent process runs as that user, not as a third account.
    let vault = VaultId::new("v-1");
    let principal = PrincipalId::parse(PRINCIPAL).unwrap();
    let user_level = layout::ensure_level(&home, &vault, principal, &Level::User).unwrap();
    let agent_level = layout::ensure_level(
        &home,
        &vault,
        principal,
        &Level::Agent(ksp_types::AgentId::parse(AGENT).unwrap()),
    )
    .unwrap();
    for level in [&user_level, &agent_level] {
        // Uid only: the agent level's group is the sweep group, and passing the
        // user's primary gid here would quietly replace the delete path.
        std::os::unix::fs::chown(level, Some(user.uid), None).unwrap();
        let record = level.join("secret-1");
        std::fs::write(&record, b"record").unwrap();
        // The mode the store writes a record with: owner-only, so the widened
        // agent level grants delete and never read.
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::chown(&record, Some(user.uid), Some(user.gid)).unwrap();
    }
    assert_eq!(
        mode_of(&agent_level),
        layout::AGENT_LEVEL_MODE,
        "an agent level is writable by the sweep group and not readable by it"
    );
    assert_eq!(
        std::fs::metadata(&agent_level).unwrap().gid(),
        admin.gid,
        "the agent level belongs to the store's group, which the admin is in"
    );
    assert_eq!(
        mode_of(&user_level),
        layout::LEVEL_MODE,
        "a user level is never widened to another principal"
    );

    // Controls first: both principals can read what they own, so the denials
    // below are about the boundary and not about a fixture nobody could open.
    assert_allowed(&admin, "cat", &[path_text(&admin_key)]);
    assert_allowed(&user, "cat", &[path_text(&user_level.join("secret-1"))]);

    // The user cannot read the admin's key root, even knowing the path.
    assert_denied(&user, "cat", &[path_text(&admin_key)]);
    // The admin cannot read the user's level, nor list it.
    assert_denied(&admin, "cat", &[path_text(&user_level.join("secret-1"))]);
    assert_denied(&admin, "ls", &[path_text(&user_level)]);

    // Misfit F, the write half: the admin owns the deployment root and still
    // cannot write inside the user's level. The boundary is the mode, not the
    // intention.
    assert_denied(&admin, "touch", &[path_text(&user_level.join("planted"))]);
    // ... nor delete a record there.
    assert_denied(&admin, "rm", &[path_text(&user_level.join("secret-1"))]);

    // FR-015 and C2: the admin *can* delete inside the agent level it sweeps,
    // and still cannot read or list it. The group gives `-wx`, never `r`.
    assert_denied(&admin, "cat", &[path_text(&agent_level.join("secret-1"))]);
    assert_denied(&admin, "ls", &[path_text(&agent_level)]);
    assert_allowed(&admin, "rm", &[path_text(&agent_level.join("secret-1"))]);
    // The level directory itself sits under a `0711` parent, so a principal that
    // can traverse to it still cannot remove it.
    assert_denied(&admin, "rmdir", &[path_text(&agent_level)]);

    // The real binary runs across the boundary: `ksp status` as each principal
    // reads the same layout and reports the same measurement. A path confinement
    // applied by Keyspout would not let a *different* uid do this.
    for (who, principal) in [("admin", &admin), ("user", &user)] {
        let mut command = Command::new(ksp());
        command
            .args(["status"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("KSP_HOME", &home);
        as_user(&mut command, principal);
        let output = command.output().expect("the binary runs");
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        assert!(
            output.status.success(),
            "ksp status as {who} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains("protected roots match the layout"),
            "ksp status as {who} must disclose the layout: {stdout}"
        );
    }
}

/// T065 and FR-037: the vault the admin writes is bound to the account that will
/// read it, and the binding is recorded so a later owner is judged rather than
/// assumed.
///
/// The step runs as root because changing a file's owner is privileged: an
/// account gives a file away only as root. Everything after it runs as the
/// principal the step names.
#[test]
fn user_add_binds_the_vault_to_the_named_account() {
    require_root();

    let suffix = unique_suffix();
    let admin = create_user("ksp-admin", &suffix);
    let user = create_user("ksp-user", &suffix);

    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("ksp");
    std::fs::create_dir(&home).unwrap();
    std::os::unix::fs::chown(&home, Some(admin.uid), Some(admin.gid)).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(layout::HOME_MODE)).unwrap();

    // Provision as the admin account, which is the one that holds the key.
    let mut init = std::process::Command::new(ksp());
    init.args(["admin", "init", "--vault", "vault-1", "--user", "alice"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("KSP_HOME", &home);
    as_user(&mut init, &admin);
    let output = init.output().expect("the binary runs");
    assert!(
        output.status.success(),
        "admin init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        mode_of(&home.join("admin-anchor.cbor")),
        layout::PUBLIC_FILE_MODE,
        "the anchor is a public key every principal verifies against"
    );
    assert_eq!(
        mode_of(&home.join("deployment.cbor")),
        layout::PUBLIC_FILE_MODE,
        "the user reads her own identifiers and public keys"
    );

    // The binding step needs root for the chown, so it runs as root here — and as
    // root it can read the admin key the pin names.
    let password = temp.path().join("pw");
    std::fs::write(&password, "correct horse battery staple").unwrap();
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut command = std::process::Command::new(ksp());
    command
        .args(["admin", "user", "add", "--unix-user", &user.name])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("KSP_HOME", &home)
        .stdin(std::fs::File::open(&password).unwrap());
    let output = command.output().expect("the binary runs");
    assert!(
        output.status.success(),
        "admin user add failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let vault = home.join("vault.cbor");
    assert_eq!(
        std::fs::metadata(&vault).unwrap().uid(),
        user.uid,
        "the vault belongs to the principal who opens it"
    );
    assert_eq!(mode_of(&vault), layout::VAULT_MODE, "and to nobody else");

    // A second enrolment is refused before the vault is touched: a replacement
    // would lock the principal out of everything already sealed to her, so the
    // refusal names the principal and `ksp vault rekey` as the command that is
    // meant to replace a vault. The record-conflict rule itself (FR-024) is
    // asserted by `a_file_owner_is_recorded_once_and_a_conflicting_claim_is_refused`.
    let mut second = std::process::Command::new(ksp());
    second
        .args(["admin", "user", "add", "--unix-user", &admin.name])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("KSP_HOME", &home)
        .stdin(std::fs::File::open(&password).unwrap());
    let output = second.output().expect("the binary runs");
    let said = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a second owner must not be recorded: {said}"
    );
    assert!(
        said.contains("already holds a sealed vault") && said.contains("vault rekey"),
        "the refusal says what it would have replaced and what to use instead: {said}"
    );
    assert_eq!(
        std::fs::metadata(&vault).unwrap().uid(),
        user.uid,
        "and the first binding still stands"
    );
}

/// The password both accounts use for the vault, written into alice's own home.
const VAULT_PASSWORD: &str = "correct horse battery staple";

/// Run `ksp` as `user` in `home`, with an optional file on stdin.
///
/// `KSP_HOME` is passed in the environment rather than argv: it is a non-secret
/// runtime value, and the binary takes every path from it.
fn ksp_as(user: &TestUser, home: &Path, args: &[&str], stdin: Option<&Path>) -> Output {
    let mut command = std::process::Command::new(ksp());
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("KSP_HOME", home);
    match stdin {
        Some(path) => {
            command.stdin(std::fs::File::open(path).expect("the stdin file is readable"));
        }
        None => {
            command.stdin(std::process::Stdio::null());
        }
    }
    as_user(&mut command, user);
    command.output().expect("the binary runs")
}

/// Run `ksp` as one account with a `umask` of its own.
///
/// The umask is set in the child between fork and exec, the way a login session
/// would: a mode the implementation takes from the caller's umask is a mode it
/// does not control, and this harness is how that shows up as a failure.
fn ksp_as_umask(
    user: &TestUser,
    home: &Path,
    umask: u32,
    args: &[&str],
    stdin: Option<&Path>,
) -> Output {
    use std::os::unix::process::CommandExt;

    let mut command = std::process::Command::new(ksp());
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("KSP_HOME", home);
    match stdin {
        Some(path) => {
            command.stdin(std::fs::File::open(path).expect("the stdin file is readable"));
        }
        None => {
            command.stdin(std::process::Stdio::null());
        }
    }
    // SAFETY: the closure runs in the child between fork and exec and calls only
    // `umask`, which takes an integer and cannot fail.
    unsafe {
        command.pre_exec(move || {
            libc::umask(umask as libc::mode_t);
            Ok(())
        });
    }
    as_user(&mut command, user);
    command.output().expect("the binary runs")
}

/// Run `ksp` as root: the one privileged step, and nothing else.
fn ksp_as_root(home: &Path, args: &[&str], stdin: Option<&Path>) -> Output {
    let mut command = std::process::Command::new(ksp());
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("KSP_HOME", home);
    match stdin {
        Some(path) => {
            command.stdin(std::fs::File::open(path).expect("the stdin file is readable"));
        }
        None => {
            command.stdin(std::process::Stdio::null());
        }
    }
    command.output().expect("the binary runs")
}

/// The two streams together, because a refusal may be printed to either.
fn text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string() + &String::from_utf8_lossy(&output.stderr)
}

/// The step succeeded, and here is what it said.
fn proceeds(output: &Output, what: &str) -> String {
    let said = text(output);
    assert_eq!(
        output.status.code(),
        Some(exit::SUCCESS),
        "`{what}` must succeed, said: {said}"
    );
    said
}

/// The session WP12 documented, run by two accounts, each doing its own step.
///
/// # What makes this a proof rather than a demonstration
///
/// Every successful step runs as the principal that is supposed to run it: the
/// admin provisions and writes the policy, alice stores the record, enrols her
/// agent, shares and runs. Neither step is run as root except the one privileged
/// handover, which is the only step that needs it. The denials afterwards are
/// asserted with `EACCES` in both directions, so a client-side check passing
/// here could not stand in for the kernel's.
#[test]
fn two_accounts_complete_the_session_and_the_kernel_keeps_them_apart() {
    require_root();

    let suffix = unique_suffix();
    let admin = create_user("ksp-admin", &suffix);
    let alice = create_user("ksp-user", &suffix);

    // The admin's home, at the layout's own mode: `0711`, so alice traverses to
    // the files that are hers and cannot list what is not.
    let temp = tempfile::tempdir().unwrap();
    // The temporary root is created owner-only, and the second account has to
    // reach the home and her own directory below it.
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let home = temp.path().join("ksp");
    std::fs::create_dir(&home).unwrap();
    std::os::unix::fs::chown(&home, Some(admin.uid), Some(admin.gid)).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(layout::HOME_MODE)).unwrap();

    // Alice's own directory: the password file she opens and the token she holds.
    // The home belongs to the admin, so neither can live there.
    let alice_dir = temp.path().join("alice");
    std::fs::create_dir(&alice_dir).unwrap();
    std::os::unix::fs::chown(&alice_dir, Some(alice.uid), Some(alice.gid)).unwrap();
    std::fs::set_permissions(&alice_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let password = alice_dir.join("vault.pw");
    std::fs::write(&password, VAULT_PASSWORD).unwrap();
    std::os::unix::fs::chown(&password, Some(alice.uid), Some(alice.gid)).unwrap();
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
    let value = alice_dir.join("value");
    std::fs::write(&value, b"correct-horse").unwrap();

    // 1. The admin provisions the deployment as herself.
    let out = ksp_as(
        &admin,
        &home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    proceeds(&out, "admin init");

    // 1b. The capability configuration, which every command that establishes a
    //     capability reads before it does anything. The admin writes it — `ksp
    //     init` records the strongest adapter this host offers — and root widens
    //     the file so the second account can read it.
    //
    //     Reading is what the guard permits: what it refuses is a file another
    //     principal can *write* (FR-009, SC-007), because that is the path that
    //     lowers the requirement level. Who may replace the file is decided by the
    //     home's mode, and only the admin can write that.
    let out = ksp_as(&admin, &home, &["init"], None);
    proceeds(&out, "init");
    let config = home.join("config.toml");
    assert_eq!(
        mode_of(&config),
        0o600,
        "`ksp init` writes an owner-only file (SC-008)"
    );
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_ne!(
        std::fs::metadata(&config).unwrap().uid(),
        alice.uid,
        "the file is the admin's, and alice reads it anyway: a deployment has one \
         configuration and two principals"
    );

    // 2. Root hands the vault and the roots to alice. This is the only privileged
    //    step in the session, and it records the binding it just created.
    let out = ksp_as_root(
        &home,
        &["admin", "user", "add", "--unix-user", &alice.name],
        Some(&password),
    );
    proceeds(&out, "admin user add");

    // 3. The binding resolves to a name, not a bare uid the operator has to look
    //    up (FR-023's disclosure).
    let out = ksp_as(&admin, &home, &["status"], None);
    let said = proceeds(&out, "status");
    assert!(
        said.contains(&format!("binding:     {} (uid {})", alice.name, alice.uid)),
        "the report names the bound account: {said}"
    );

    // 4. Alice stores the record as herself. The vault is hers, so this is the
    //    first step that proves the handover was real rather than recorded.
    let out = ksp_as(
        &alice,
        &home,
        &[
            "secret",
            "set",
            "s3cr3t-id-1",
            "--name",
            "db_password",
            "--passphrase-file",
            path_text(&password),
        ],
        Some(&value),
    );
    proceeds(&out, "secret set");

    // 5. Alice enrols her agent: `agent/` and `enrolments/` are hers to write.
    let out = ksp_as(
        &alice,
        &home,
        &["agent", "enroll", "--agent", "deploy-bot"],
        None,
    );
    let said = proceeds(&out, "agent enroll");
    let agent = said
        .split_whitespace()
        .next()
        .and_then(|first| first.strip_prefix("agent:"))
        .expect("the enrolment prints the agent's UUID")
        .to_string();

    // The principal UUIDs come from the deployment record rather than a guess:
    // they are what the level and chain directories are named.
    let layout_home = ksp::config::Layout::new(home.clone());
    let (deployment, _anchor) =
        ksp::deployment::require(&layout_home).expect("the deployment is provisioned");
    let user = deployment.user.to_string();
    let admin_principal = deployment.admin.to_string();

    // 6. The admin writes the policy without a password: the public halves are in
    //    the deployment record, so administration does not depend on a secret only
    //    alice has (FR-020).
    let out = ksp_as(
        &admin,
        &home,
        &[
            "admin",
            "policy",
            "--agent",
            &agent,
            "--secret",
            "s3cr3t-id-1",
        ],
        None,
    );
    proceeds(&out, "admin policy");

    // 7. The admin arms the schedule that authorises a lease, naming a sweep
    //    identity that is not the store's owner.
    let scope = format!("p/vault-1/{user}/agent-*");
    let grant = format!("delete:{scope}");
    let out = ksp_as(
        &admin,
        &home,
        &[
            "backend",
            "arm-sweep",
            "--kind",
            "systemd",
            "--interval",
            "3600",
            "--scope",
            &scope,
            "--credential",
            "ksp-sweep",
            "--grant",
            &grant,
            "--identifier",
            "ksp-sweep.service",
        ],
        None,
    );
    proceeds(&out, "backend arm-sweep");

    // 8. The admin sweeps. Nothing is due yet — the point is the signed proof,
    //    which is what admission reads.
    let out = ksp_as(&admin, &home, &["secret", "gc"], None);
    let said = proceeds(&out, "secret gc");
    assert!(
        said.contains("capability=Scheduled"),
        "the sweep recorded the armed capability: {said}"
    );

    // 9. Alice shares at the floor the proof establishes. The lease is *hers*: the
    //    intent and the artifact are signed with her enrolled key, and the admin's
    //    key takes no part (spec §3.7), which is the whole reason this works from
    //    her account.
    let token = alice_dir.join("token.ksp");
    // Under `umask 077`, so every file this step creates is one the *code* has to
    // give a mode to. The arm record is shared with the sweep and the token is
    // hers alone; a mint that inherited either mode from a login session would
    // pass with `022` and fail in the field.
    let out = ksp_as_umask(
        &alice,
        &home,
        0o077,
        &[
            "secret",
            "share",
            "s3cr3t-id-1",
            "--agent",
            &agent,
            "--name",
            "db_password",
            "--ttl",
            "7200",
            "--out",
            path_text(&token),
            "--passphrase-file",
            path_text(&password),
        ],
        None,
    );
    proceeds(&out, "secret share");

    // 9b. The artifact names the key that signed it: hers, not the admin's. The
    //     signature already verified against her pin, so a header naming the admin
    //     would be a signed claim the signature contradicts — and the first thing
    //     an operator reads is this line.
    let user_key = deployment
        .user_signing_key_id
        .as_ref()
        .expect("the binding recorded her signing key id")
        .as_str()
        .to_string();
    let out = ksp_as(
        &alice,
        &home,
        &["token", "inspect", "--token", path_text(&token)],
        None,
    );
    let said = proceeds(&out, "token inspect");
    assert!(
        said.contains(&format!("issuer={user_key}")),
        "the artifact names her key as the issuer: {said}"
    );
    assert!(
        !said.contains("issuer=admin-"),
        "the admin key signs no lease: {said}"
    );

    // 10. The delivered value reaches the child and nothing else does.
    let out = ksp_as(
        &alice,
        &home,
        &[
            "run",
            "--token",
            path_text(&token),
            "--env",
            "DB_PASSWORD",
            "--",
            "sh",
            "-c",
            "echo len=${#DB_PASSWORD}",
        ],
        None,
    );
    let said = proceeds(&out, "run");
    assert!(said.contains("len=13"), "the child saw the value: {said}");
    assert!(
        !said.contains("correct-horse"),
        "the value itself never reaches the terminal: {said}"
    );

    // 10b. The admin's sweep reads the record *she* did not write. The journal is
    //      shared, so this is where a mode taken from Alice's umask would show:
    //      the lease would be unreadable and reported as a failure instead of a
    //      deadline the sweep is waiting on.
    let out = ksp_as(&admin, &home, &["secret", "gc"], None);
    let said = proceeds(&out, "secret gc after the share");
    assert!(
        said.contains("not_yet_due=1"),
        "the sweep reads the lease Alice armed: {said}"
    );
    assert!(
        said.contains("removed=0"),
        "nothing is due yet, so nothing is removed: {said}"
    );

    // 11. The log is one chain per writer. Alice verifies her own completely; the
    //     admin's walk cannot read Alice's chain, and says so with the code that
    //     means "this verification is partial" rather than reporting a green log
    //     over a third of it (misfit S).
    let out = ksp_as(&alice, &home, &["audit", "verify"], None);
    let said = proceeds(&out, "audit verify as the principal");
    assert!(said.contains("chain=unbroken"), "{said}");
    assert!(said.contains("unreadable=0"), "{said}");
    assert!(
        said.contains("valid=2"),
        "both of her records verified: {said}"
    );

    let out = ksp_as(&admin, &home, &["audit", "verify"], None);
    let said = text(&out);
    assert_eq!(
        out.status.code(),
        Some(exit::AUDIT_UNVERIFIED),
        "a partial verification is not a pass: {said}"
    );
    assert!(said.contains("chain=unbroken"), "{said}");
    assert!(
        said.contains("unreadable=1"),
        "the admin's walk names what it could not read: {said}"
    );

    let out = ksp_as(&admin, &home, &["audit", "--admin"], None);
    let said = proceeds(&out, "audit --admin");
    let user_chain = format!("audit/{user}");
    assert!(
        said.contains(&format!("note: could not read {user_chain}")),
        "the admin's view names the chain it may not read: {said}"
    );
    assert!(
        !said.contains("unreadable=0"),
        "a chain it could not read is counted, not dropped: {said}"
    );

    // 12. The boundary itself, in both directions.
    let admin_keys = home.join("admin");
    // The key lives one level down, under the level directory the table names, so
    // the fixture descends rather than assuming a flat root.
    let key = std::fs::read_dir(&admin_keys)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .find_map(|path| {
            if path.is_file() {
                return Some(path);
            }
            std::fs::read_dir(path)
                .ok()?
                .flatten()
                .map(|inner| inner.path())
                .find(|inner| inner.is_file())
        })
        .expect("`admin init` wrote the protected key");
    assert_denied(&alice, "/usr/bin/ls", &[path_text(&admin_keys)]);
    assert_denied(&alice, "/usr/bin/cat", &[path_text(&key)]);
    assert_denied(
        &alice,
        "/usr/bin/ls",
        &[path_text(&home.join("audit").join(&admin_principal))],
    );
    assert_denied(
        &admin,
        "/usr/bin/ls",
        &[path_text(&home.join("audit").join(&user))],
    );

    // The user level is the principal's own: `0700`, hers, and the admin may not
    // read or list it (misfit B, misfit F's read half). The agent level is the drop
    // box misfit F needs: the sweep group may delete a copy it cannot read.
    let user_level = home
        .join("store/p")
        .join("vault-1")
        .join(&user)
        .join("user");
    let agent_level = home
        .join("store/p")
        .join("vault-1")
        .join(&user)
        .join(format!("agent-{agent}"));
    assert_eq!(
        std::fs::metadata(&user_level).unwrap().uid(),
        alice.uid,
        "the level belongs to the principal whose records it holds"
    );
    assert_eq!(mode_of(&user_level), 0o700, "and to nobody else");
    assert_denied(&admin, "/usr/bin/ls", &[path_text(&user_level)]);
    assert!(agent_level.is_dir(), "the share wrote the agent level");
    assert_denied(&admin, "/usr/bin/ls", &[path_text(&agent_level)]);

    // The control half: each principal reaches its own material, so the denials
    // above cannot be a fixture nobody could read.
    assert_allowed(&admin, "/usr/bin/ls", &[path_text(&admin_keys)]);
    assert_allowed(
        &admin,
        "/usr/bin/ls",
        &[path_text(&home.join("audit").join(&admin_principal))],
    );
    assert_allowed(&alice, "/usr/bin/ls", &[path_text(&home.join("agent"))]);
    assert_allowed(
        &alice,
        "/usr/bin/ls",
        &[path_text(&home.join("audit").join(&user))],
    );
}

/// FR-024: an owner that no longer matches the binding is reported, and refused.
///
/// Two findings from one edit: the *record* is measured and named with its path,
/// its mode and the owner the layout recorded, and the vault is no longer this
/// account's, so opening it is the typed capability refusal rather than "the
/// vault does not exist".
#[test]
fn a_vault_given_to_another_account_is_reported_and_refused() {
    require_root();

    let suffix = unique_suffix();
    let admin = create_user("ksp-admin", &suffix);
    let alice = create_user("ksp-user", &suffix);

    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let home = temp.path().join("ksp");
    std::fs::create_dir(&home).unwrap();
    std::os::unix::fs::chown(&home, Some(admin.uid), Some(admin.gid)).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(layout::HOME_MODE)).unwrap();
    // Alice's own directory holds the password file, for the same reason as in the
    // session test: the temporary root is not a path she may traverse.
    let alice_dir = temp.path().join("alice");
    std::fs::create_dir(&alice_dir).unwrap();
    std::os::unix::fs::chown(&alice_dir, Some(alice.uid), Some(alice.gid)).unwrap();
    std::fs::set_permissions(&alice_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let password = alice_dir.join("vault.pw");
    std::fs::write(&password, VAULT_PASSWORD).unwrap();
    std::os::unix::fs::chown(&password, Some(alice.uid), Some(alice.gid)).unwrap();
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();

    let out = ksp_as(
        &admin,
        &home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    proceeds(&out, "admin init");

    // 1b. The capability configuration, which every command that establishes a
    //     capability reads before it does anything. The admin writes it — `ksp
    //     init` records the strongest adapter this host offers — and root widens
    //     the file so the second account can read it.
    //
    //     Reading is what the guard permits: what it refuses is a file another
    //     principal can *write* (FR-009, SC-007), because that is the path that
    //     lowers the requirement level. Who may replace the file is decided by the
    //     home's mode, and only the admin can write that.
    let out = ksp_as(&admin, &home, &["init"], None);
    proceeds(&out, "init");
    let config = home.join("config.toml");
    assert_eq!(
        mode_of(&config),
        0o600,
        "`ksp init` writes an owner-only file (SC-008)"
    );
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_ne!(
        std::fs::metadata(&config).unwrap().uid(),
        alice.uid,
        "the file is the admin's, and alice reads it anyway: a deployment has one \
         configuration and two principals"
    );
    let out = ksp_as_root(
        &home,
        &["admin", "user", "add", "--unix-user", &alice.name],
        Some(&password),
    );
    proceeds(&out, "admin user add");

    // The drift an `rsync` or a restore produces: the file is still alice's
    // record, and the kernel would let root read it. The measurement is what says
    // whose it is supposed to be.
    let vault = home.join("vault.cbor");
    std::os::unix::fs::chown(&vault, Some(0), Some(0)).unwrap();

    let out = ksp_as(&admin, &home, &["status"], None);
    let said = proceeds(&out, "status");
    assert!(said.contains("vault.cbor"), "{said}");
    assert!(said.contains("drifted"), "{said}");
    assert!(
        said.contains(&format!("owned by uid {}", alice.uid)),
        "the finding names the owner the layout recorded: {said}"
    );

    // And the vault no longer belongs to the account that asks for it: the refusal
    // is the layout's capability, exit 7, with both uids in the sentence.
    let out = ksp_as(
        &alice,
        &home,
        &[
            "secret",
            "get",
            "s3cr3t-id-1",
            "--passphrase-file",
            path_text(&password),
        ],
        None,
    );
    assert_eq!(
        out.status.code(),
        Some(exit::CAPABILITY_REFUSAL),
        "a vault owned by another account is a capability refusal: {}",
        text(&out)
    );
    let said = text(&out);
    assert!(
        said.contains("owned by uid 0") && said.contains(&format!("runs as uid {}", alice.uid)),
        "the refusal names both accounts: {said}"
    );
    assert!(
        !said.contains("no vault exists"),
        "the file is right there, so 'absent' would send the operator looking: {said}"
    );

    // A binding whose account is gone is reported as unverified, not assumed.
    let removed = {
        let _guard = accounts();
        std::process::Command::new("userdel")
            .args(["-r", &alice.name])
            .status()
            .expect("`userdel` runs")
    };
    assert!(removed.success(), "the account is removed for the finding");
    let out = ksp_as(&admin, &home, &["status"], None);
    let said = proceeds(&out, "status after the account was removed");
    assert!(
        said.contains(&format!("binding:     {} — unverified: ", alice.name)),
        "the report says the binding no longer resolves: {said}"
    );

    // And the request for a lease fails for that reason, not by accident: the
    // record and the vault are still on disk under a uid that no longer names
    // anyone, and a host that minted from them would be trusting a binding it has
    // just reported as unverified (FR-023, acceptance 2).
    let out = ksp_as(
        &admin,
        &home,
        &[
            "secret",
            "share",
            "s3cr3t-id-1",
            "--agent",
            "00000000-0000-4000-8000-000000000000",
            "--name",
            "db_password",
            "--ttl",
            "7200",
            "--out",
            path_text(&home.join("never.ksp")),
        ],
        // The password arrives on stdin, opened by the test rather than by the
        // child: a `--passphrase-file` here is a file the admin cannot read, and
        // the refusal has to come from the binding, not from that.
        Some(&password),
    );
    assert_eq!(
        out.status.code(),
        Some(exit::CAPABILITY_REFUSAL),
        "a lease requested through a gone binding is a capability refusal: {}",
        text(&out)
    );
    let said = text(&out);
    assert!(
        said.contains(&format!(
            "the principal binding is unverified: {}",
            alice.name
        )),
        "the refusal names the binding, not the bytes: {said}"
    );
}
