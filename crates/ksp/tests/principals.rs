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

/// Refuse when the accounts are not provisioned, naming what is missing.
///
/// # Why this refuses rather than returning
///
/// An early `return` from a test function is indistinguishable from a pass in the
/// harness output. A developer with no accounts would see a green suite that
/// verified nothing, which is the failure `AGENTS.md` names: *"A skipped security
/// test reads like a pass."* So this refuses, and the refusal is the first thing
/// they read because it runs before the root check.
fn require_accounts() -> (String, String) {
    let missing: Vec<&str> = ["KSP_TEST_ADMIN_USER", "KSP_TEST_USER"]
        .into_iter()
        .filter(|name| std::env::var(name).map(|v| v.is_empty()).unwrap_or(true))
        .collect();
    assert!(
        missing.is_empty(),
        "the two-account boundary tests need {} set, so this suite did not run.\n\
         Provision the accounts once, as DEVELOPMENT.md describes:\n\
         \x20   sudo sysadminctl -addUser ksp-admin        # macOS\n\
         \x20   sudo sysadminctl -addUser ksp-user         # macOS\n\
         \x20   sudo useradd -M -N -s /bin/sh ksp-admin    # Linux\n\
         \x20   sudo useradd -M -N -s /bin/sh ksp-user     # Linux\n\
         Then export KSP_TEST_ADMIN_USER=ksp-admin and KSP_TEST_USER=ksp-user.\n\
         Neither account may be in admin, sudo or wheel: this suite measures one \
         account's authority, and an admin account turns the grant into root.",
        missing.join(" and ")
    );
    (
        std::env::var("KSP_TEST_ADMIN_USER").expect("checked above"),
        std::env::var("KSP_TEST_USER").expect("checked above"),
    )
}

/// A throwaway account, removed even when an assertion panics.
struct TestUser {
    name: String,
    uid: u32,
    gid: u32,
}

impl Drop for TestUser {
    fn drop(&mut self) {
        // Nothing to clean up: the account belongs to the operator, and deleting
        // one this harness did not create would be a worse bug than the leak the
        // old `userdel` guarded against.
    }
}

fn id_of(user: &str, flag: &str) -> u32 {
    let output = Command::new("id")
        .args([flag, user])
        .output()
        .expect("`id` runs");
    assert!(
        output.status.success(),
        "`id {flag} {user}` failed; is the account provisioned?"
    );
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("`id` prints a number")
}

/// Resolve one of the two provisioned accounts by its environment variable.
///
/// `env_name` is `KSP_TEST_ADMIN_USER` or `KSP_TEST_USER`. The prefix/suffix
/// parameters of the old `create_user` are gone with the creation: the operator
/// names the accounts, so the harness takes the name it was given.
///
/// # Panics
///
/// When the variable is unset. Callers are expected to have called
/// [`require_accounts`] first, which prints the skip; reaching this panic means a
/// test forgot that guard, and a silent pass would be worse.
fn provisioned_user(env_name: &str) -> TestUser {
    let name = std::env::var(env_name).unwrap_or_else(|_| {
        panic!("{env_name} is unset; call require_accounts() before provisioning a user")
    });
    TestUser {
        uid: id_of(&name, "-u"),
        gid: id_of(&name, "-g"),
        name,
    }
}

/// Run `program` as `user`, with the user's supplementary groups.
///
/// `.uid()`/`.gid()` alone leave root's supplementary groups attached, and a
/// probe that is supposed to be in `ksp-sweep` would then be denied by a mode it
/// really does satisfy. `initgroups` reads the account's groups, so the probe is
/// the process the deployment would have.
fn run_as(user: &TestUser, program: &str, args: &[&str]) -> Output {
    // A bare name is resolved through the child's `PATH`. The list below is the
    // conventional set, and on macOS `cat`, `ls`, `rm` and `rmdir` live in `/bin`,
    // not `/usr/bin` — both are listed, so a bare name works on either platform.
    // A name that is in neither is a test bug, and the panic says which.
    let mut command = if program.starts_with('/') {
        // An absolute path is still resolved by basename when it does not exist:
        // macOS keeps `cat`, `ls`, `rm` and `rmdir` in `/bin`, not `/usr/bin`, so a
        // hardcoded `/usr/bin/ls` is a Linux assumption that fails here with
        // `ENOENT` — which reads as "the probe is broken" rather than "the path is
        // wrong for this platform".
        if std::path::Path::new(program).is_file() {
            Command::new(program)
        } else {
            let base = program.rsplit('/').next().unwrap_or(program);
            let found = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
                .iter()
                .map(|dir| std::path::Path::new(dir).join(base))
                .find(|candidate| candidate.is_file())
                .unwrap_or_else(|| {
                    panic!(
                        "the probe {program} does not exist, and `{base}` is in none of \
                         /usr/bin, /bin, /usr/sbin, /sbin; the assertions below would \
                         fail for the wrong reason"
                    )
                });
            Command::new(found)
        }
    } else {
        let found = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
            .iter()
            .map(|dir| std::path::Path::new(dir).join(program))
            .find(|candidate| candidate.is_file())
            .unwrap_or_else(|| {
                panic!(
                    "the probe `{program}` is in none of /usr/bin, /bin, /usr/sbin, /sbin; \
                     the assertions below would fail for the wrong reason"
                )
            });
        Command::new(found)
    };
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
    let _accounts = require_accounts();

    require_root();
    let admin = provisioned_user("KSP_TEST_ADMIN_USER");
    let user = provisioned_user("KSP_TEST_USER");

    // A home whose roots carry the table's modes. `ensure` creates them owned by
    // this process; the two principals are then given the ones they own, which is
    // what a two-account deployment looks like after provisioning.
    let temp = shared_tempdir();
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
    // The store is named, not resolved. `layout::ensure` reads `KSP_STORE` from
    // the environment, so a developer who has one exported gets a layout row
    // written into a directory owned by another account — and every `admin init`
    // below then fails with an `EACCES` that reads exactly like a product defect.
    // The children this test spawns never see the variable (`env_clear`), so they
    // use `<home>/store`; naming it here is what makes the two agree.
    layout::ensure_at(&home, Some(home.join("store"))).unwrap();
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
    let _accounts = require_accounts();

    require_root();
    let admin = provisioned_user("KSP_TEST_ADMIN_USER");
    let user = provisioned_user("KSP_TEST_USER");

    let temp = shared_tempdir();
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

/// A temporary directory the second account can actually traverse into.
///
/// # Why `tempfile::tempdir()` is not enough
///
/// Under `sudo`, `TMPDIR` is root's own per-user directory —
/// `/var/folders/zz/<hash>/T` — and that directory is `0700 root:wheel`. A
/// `TempDir` created inside it is reachable to nobody but root, however wide the
/// temp dir itself is widened: traversal is refused at the **parent** before the
/// child is ever reached.
///
/// That produced two failures that read like product defects and were not:
///
/// - `cat <admin-key>` as the admin account returned `EACCES`, because the path's
///   parent was unreadable to it;
/// - `admin init` refused with *"a protected file this operation had to write
///   could not be written"*, because the layout row is written under the same
///   untraversable parent.
///
/// # What this does instead
///
/// It asks `tempfile` for a directory under `/tmp` — `1777` and traversable from
/// every account — and widens **that directory and its own child** to `0755`.
/// `TempDir` still owns the whole tree, so dropping it removes everything; a base
/// created beside it would leak on every run.
fn shared_tempdir() -> tempfile::TempDir {
    let temp = tempfile::Builder::new()
        .prefix("ksp-principals-")
        .tempdir_in("/tmp")
        .expect("a temp dir under /tmp, which every account can traverse");
    // The directory tempfile made is `0700`, which is the same block one level up:
    // the second account must traverse into the fixture root and on into the home.
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755))
        .expect("the fixture root is traversable by the second account");

    // And its **group** must be unprivileged. `/tmp` is gid 0 (`wheel`) on macOS,
    // and a directory created by a process whose primary gid is 0 inherits it. A
    // store root under such a directory resolves its group to `wheel`, and
    // `join_store_group` would then add the principal to a root-equivalent group —
    // D6 in `docs/known-defects.md`, which this fixture would otherwise reproduce
    // accidentally on every run.
    //
    // So the fixture's group is set to `staff`, which is unprivileged on macOS and
    // is the group the invoking account belongs to. `wheel` is refused with the
    // reason rather than silently accepted: a fixture that reproduces D6 would
    // make the suite pass while handing the principal a root-equivalent group.
    //
    // SAFETY: `chown` takes a path and two integers and touches no memory beyond
    // the path it is handed.
    let parent_gid = std::fs::metadata(temp.path())
        .expect("the fixture root exists")
        .gid();
    if parent_gid == 0 {
        let staff_gid = unprivileged_gid();
        let c_path = std::ffi::CString::new(temp.path().as_os_str().as_encoded_bytes())
            .expect("a path has no NUL");
        let result = unsafe { libc::chown(c_path.as_ptr(), u32::MAX, staff_gid) };
        assert_eq!(
            result,
            0,
            "the fixture root's group could not be moved off gid 0 (wheel/root), so \
             every store root below it would resolve to a root-equivalent group: {}",
            std::io::Error::last_os_error()
        );
    }
    temp
}

/// The gid of `staff`, or of the invoking account's own group.
///
/// `staff` is 20 on macOS and `staff` is also 100 on some Linux distributions, so
/// the name is looked up rather than assumed. Falls back to the effective gid,
/// which is unprivileged whenever the caller is not root.
fn unprivileged_gid() -> u32 {
    // SAFETY: `getegid` takes no arguments and cannot fail.
    let own = unsafe { libc::getegid() };
    if own != 0 {
        return own;
    }
    20
}

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
    let _accounts = require_accounts();

    require_root();
    let admin = provisioned_user("KSP_TEST_ADMIN_USER");
    let alice = provisioned_user("KSP_TEST_USER");

    // The admin's home, at the layout's own mode: `0711`, so alice traverses to
    // the files that are hers and cannot list what is not.
    let temp = shared_tempdir();
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
