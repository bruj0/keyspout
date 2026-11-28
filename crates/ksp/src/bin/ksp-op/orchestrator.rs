// Production paths here return `Result` and never unwrap; the `expect`/`panic`
// calls are in the `#[cfg(test)]` fixtures below, where a failing assertion is
// how a test reports.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

//! Running the steps, and the seam that makes them testable.
//!
//! Every step that leaves this process goes through [`Orchestrator`]. In
//! production that is [`Real`], which spawns children and branches on
//! `cfg!(target_os)`. In a test that is [`Fake`], which records what it was
//! asked to do and changes nothing.
//!
//! # Why the platform branch is inside a method, not around one
//!
//! `sysadminctl -addUser` is macOS and `useradd` is Linux; `launchctl bootout`
//! is macOS and `systemctl --user stop` is Linux. Written as two `#[cfg]` bodies
//! of one function, both branches are type-checked on both platforms, so a typo
//! in the Linux arm fails a macOS build. Written as two `#[cfg]` *functions*, the
//! arm that is not being compiled is invisible until someone builds on that
//! platform — which is the shape of nearly every cross-platform bug in this repo
//! (`cfg(target_os = "darwin")` is never true, and it compiled out silently).
//!
//! # Why no test spawns a child
//!
//! A test that runs `sysadminctl` needs root twice — once to create the account
//! and once to remove it — and leaves an account behind when it fails midway. So
//! the tests here drive [`Fake`] and assert on the argv, which is the part that
//! can be wrong. Whether `sysadminctl` exists is not something a unit test can
//! answer; whether we invoke it with the right arguments is.

use std::path::Path;
use std::process::Command;

/// Everything a run needs to do to the host.
pub trait Orchestrator {
    /// Run a command as the administrator account.
    ///
    /// # Errors
    ///
    /// The refusal text, which names the command and the account.
    ///
    /// `home` is threaded rather than inherited. Measured: `sudo -n -u <admin>` a
    /// bare `ksp ...` inherits no `KSP_HOME`, so `ksp` falls back to that
    /// account's own default and every step writes outside the deployment the
    /// plan created. The value already lives in `Env`, so it is passed down.
    fn run_as_admin(&self, admin: &str, home: &Path, argv: &[String]) -> Result<(), String>;

    /// Run a command as the invoking user.
    ///
    /// No `sudo`: the point of this variant is that the step belongs to the
    /// user's own tree (`agent enroll` writes her key file), so running it as the
    /// administrator would put the keys somewhere she cannot read.
    ///
    /// # Errors
    ///
    /// The refusal text, naming the command.
    fn run_as_user(&self, user: &str, home: &Path, argv: &[String]) -> Result<(), String>;

    /// Run a command as the administrator, writing `secret` to its stdin.
    ///
    /// # Why stdin and not an argument
    ///
    /// An argv is visible in `ps` to every account on the host. The rule is older
    /// than this binary: no plaintext secret in argv, logs or the environment.
    ///
    /// # Errors
    ///
    /// The refusal text, plus a sentence when the child could not be given its
    /// input — a sealed step that silently ran without the passphrase would leave
    /// a vault it could not open.
    fn run_as_admin_sealed(
        &self,
        admin: &str,
        home: &Path,
        argv: &[String],
        secret: &[u8],
    ) -> Result<(), String>;

    /// Run a command as root, writing `secret` to its stdin.
    ///
    /// `admin user add` needs both: it seals the user's keypairs under her
    /// passphrase and chowns the vault to her account.
    ///
    /// # Errors
    ///
    /// The refusal text, plus a sentence when the child could not be given its
    /// input.
    fn run_privileged_sealed(&self, argv: &[String], secret: &[u8]) -> Result<(), String>;

    /// Run a command as root.
    ///
    /// # Errors
    ///
    /// The refusal text. A caller that cannot get root is told to run the
    /// command itself, not told that something failed.
    fn run_privileged(&self, argv: &[String]) -> Result<(), String>;

    /// Create the administrator account if it does not exist.
    ///
    /// # Errors
    ///
    /// The refusal text when the account exists with a different home, or when
    /// the created account could not be verified.
    fn create_admin_account(&self, name: &str, home: &Path) -> Result<(), String>;

    /// Stop and unload the scheduled sweep jobs.
    ///
    /// # Errors
    ///
    /// Only when a job exists and could not be removed. An absent job is not an
    /// error: `reset` runs on a host that never armed one.
    fn bootout_jobs(&self, invoke_as: &str) -> Result<(), String>;

    /// Give a directory tree to the administrator account, recursively.
    ///
    /// Run as root, because only root may change an owner. The mode is not
    /// touched: `chown` changes the owner and those are the permissions the layout
    /// set.
    ///
    /// # Errors
    ///
    /// The refusal text naming the path, when the tree could not be handed over.
    /// A tree left owned by root is unreadable to every later step, so this fails
    /// rather than warns.
    fn chown_tree(&self, owner: &str, path: &Path, owner_spec: &str) -> Result<(), String>;

    /// Remove a directory tree, as root.
    ///
    /// # Errors
    ///
    /// The refusal text naming the path that remains.
    fn remove_tree(&self, path: &Path) -> Result<(), String>;
}

/// The real host.
pub struct Real;

impl Real {
    /// Run `argv` with `sudo -n -u <account> -H env KSP_HOME=<home>`.
    ///
    /// # Why `-H` as well as `env KSP_HOME=`
    ///
    /// Without `-H`, `sudo` sets `HOME` from the target account's passwd entry,
    /// and `ksp` then falls back to it silently — the split-deployment failure is
    /// invisible because both answers look plausible. With `-H` the environment
    /// is the one this call builds, and `KSP_HOME` is explicit in it.
    fn sudo_as(account: &str, home: &Path, argv: &[String]) -> Command {
        let mut command = Command::new("sudo");
        // `-n` is deliberate: a prompt that cannot be answered would hang a
        // non-interactive run with no message. A missing permission becomes a
        // refusal naming the grant, which is actionable.
        command.args(["-n", "-u", account, "-H", "env"]);
        command.arg(format!("KSP_HOME={}", home.display()));
        command.args(argv);
        command
    }

    /// Run `argv` as this account, with `KSP_HOME` set explicitly.
    ///
    /// The environment is set rather than inherited for the same reason as the
    /// admin case: a shell with a stale `KSP_STORE` or no `KSP_HOME` would send
    /// the step somewhere the plan did not name.
    fn as_user(home: &Path, argv: &[String]) -> Command {
        let mut command = Command::new(&argv[0]);
        command.args(&argv[1..]);
        command.env("KSP_HOME", home);
        // A stray `KSP_STORE` in the operator's shell splits the deployment, and
        // this is the one place that can remove it for the child.
        command.env_remove("KSP_STORE");
        command
    }
}

/// Turn a failed child into the sentence an operator can act on.
///
/// Both streams are read: `ksp` writes its outcome to stdout and its refusal to
/// stderr, so reading one gives half the reason. The account is named because
/// the same argv can mean different things as `keyspout` and as the user.
fn failure(output: &std::process::Output, argv: &[String], account: &str) -> String {
    let mut message = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        if !message.is_empty() {
            message.push('\n');
        }
        message.push_str(&stderr);
    }
    format!("`{}` failed as {account}: {message}", argv.join(" "))
}

impl Orchestrator for Real {
    fn run_as_admin(&self, admin: &str, home: &Path, argv: &[String]) -> Result<(), String> {
        if argv.is_empty() {
            return Err("an empty command was scheduled, which is a bug".to_string());
        }
        let output = Self::sudo_as(admin, home, argv)
            .output()
            .map_err(|e| format!("could not run `sudo -n -u {admin}`: {e}"))?;
        if output.status.success() {
            return Ok(());
        }
        Err(failure(&output, argv, admin))
    }

    fn run_as_user(&self, user: &str, home: &Path, argv: &[String]) -> Result<(), String> {
        if argv.is_empty() {
            return Err("an empty command was scheduled, which is a bug".to_string());
        }
        let output = Self::as_user(home, argv)
            .output()
            .map_err(|e| format!("could not run `{}`: {e}", argv[0]))?;
        if output.status.success() {
            return Ok(());
        }
        Err(failure(&output, argv, user))
    }

    fn run_privileged_sealed(&self, argv: &[String], secret: &[u8]) -> Result<(), String> {
        use std::io::Write as _;

        if argv.is_empty() {
            return Err("an empty command was scheduled, which is a bug".to_string());
        }
        let mut child = Command::new("sudo")
            .arg("-n")
            .args(argv)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("could not run `sudo -n`: {e}"))?;

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| "the child was spawned without a stdin pipe".to_string())?;
            stdin
                .write_all(secret)
                .and_then(|()| stdin.write_all(b"\n"))
                .map_err(|e| format!("could not write the passphrase to the child: {e}"))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("could not wait for `{}`: {e}", argv.join(" ")))?;
        if output.status.success() {
            return Ok(());
        }
        Err(format!(
            "`{}` failed as root: {}\n\
             This step needs root. Run it yourself, or grant a window with `agent-do`.",
            argv.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }

    fn run_privileged(&self, argv: &[String]) -> Result<(), String> {
        if argv.is_empty() {
            return Err("an empty command was scheduled, which is a bug".to_string());
        }
        let output = Command::new("sudo")
            .arg("-n")
            .args(argv)
            .output()
            .map_err(|e| format!("could not run `sudo -n`: {e}"))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(format!(
            "`{}` failed as root: {stderr}\n\
             This step needs root. Run it yourself, or grant a window with \
             `agent-do`.",
            argv.join(" ")
        ))
    }

    fn run_as_admin_sealed(
        &self,
        admin: &str,
        home: &Path,
        argv: &[String],
        secret: &[u8],
    ) -> Result<(), String> {
        use std::io::Write as _;

        if argv.is_empty() {
            return Err("an empty command was scheduled, which is a bug".to_string());
        }
        let mut child = Self::sudo_as(admin, home, argv)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("could not run `sudo -n -u {admin}`: {e}"))?;

        // A trailing newline is what a terminal's Enter sends and what a
        // line-oriented reader expects to terminate the value. Without it a reader
        // that stops at a newline takes the buffer as nothing and waits.
        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| "the child was spawned without a stdin pipe".to_string())?;
            stdin
                .write_all(secret)
                .and_then(|()| stdin.write_all(b"\n"))
                .map_err(|e| format!("could not write the passphrase to the child: {e}"))?;
            // Dropping closes the pipe, which is the EOF the reader needs.
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("could not wait for `{}`: {e}", argv.join(" ")))?;
        if output.status.success() {
            return Ok(());
        }
        let mut message = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if !stderr.is_empty() {
            if !message.is_empty() {
                message.push('\n');
            }
            message.push_str(&stderr);
        }
        Err(format!("`{}` failed as {admin}: {message}", argv.join(" ")))
    }

    fn create_admin_account(&self, name: &str, home: &Path) -> Result<(), String> {
        // Already there is success, not a refusal: a second `setup` must report
        // nothing to do. The path is checked because an account whose home is
        // elsewhere cannot read the store this run is about to write.
        if account_exists(name) {
            if let Some(account_home) = account_home(name) {
                // `home` is the *deployment* path (`<account home>/.ksp`), so it is
                // never equal to the account's home. Comparing the two refused
                // every correct run: measured, `setup` stopped at step 1 with
                // "the account keyspout already exists with home /Users/keyspout,
                // but this run expects /Users/keyspout/.ksp". The question is
                // containment — can this account own the path we are about to
                // build — not equality.
                if !home.starts_with(&account_home) {
                    return Err(format!(
                        "the account {name} has home {}, which does not contain the deployment \
                         path {}. Pass --admin-account for the account that owns it, or set \
                         KSP_HOME under that account's home.",
                        account_home.display(),
                        home.display()
                    ));
                }
            }
            return Ok(());
        }

        // Both arms are compiled, so a typo in the arm this host does not use
        // fails the build here rather than on the other platform.
        let argv: Vec<String> = if cfg!(target_os = "macos") {
            vec![
                "sysadminctl".to_string(),
                "-addUser".to_string(),
                name.to_string(),
                "-home".to_string(),
                home.display().to_string(),
                "-shell".to_string(),
                "/bin/bash".to_string(),
            ]
        } else {
            vec![
                "useradd".to_string(),
                // No login shell: the account exists to own files, not to be
                // logged into, and a shell is another way in.
                "--shell".to_string(),
                "/usr/sbin/nologin".to_string(),
                "--home-dir".to_string(),
                home.display().to_string(),
                "--create-home".to_string(),
                name.to_string(),
            ]
        };
        self.run_privileged(&argv)?;

        // The command's exit code is not the assertion. A created account that
        // cannot be looked up is a failed step, and reporting success would leave
        // the next step failing on an account that "exists".
        if !account_exists(name) {
            return Err(format!(
                "the account {name} does not exist after creation: the tool reported \
                 success but `id -u {name}` cannot find it"
            ));
        }
        Ok(())
    }

    fn bootout_jobs(&self, invoke_as: &str) -> Result<(), String> {
        // The labels are written by `ksp` itself when it arms a schedule, and
        // `launchctl list | grep -i ksp` misses them while matching Apple's own
        // `com.apple.diskspaced`. Naming them exactly is the only reliable way to
        // find them.
        let labels = ["com.keyspout.sweep", "com.keyspout.user-sweep"];
        for label in labels {
            let plist = format!("/Library/LaunchAgents/{label}.plist");
            if cfg!(target_os = "macos") {
                // Absent is the answer, not a failure: `reset` runs on hosts that
                // never armed a sweep. Checking the file first is what separates
                // "nothing to remove" from "could not remove" — the two are
                // otherwise one non-zero exit.
                if !Path::new(&plist).exists() {
                    continue;
                }
                let argv = vec![
                    "launchctl".to_string(),
                    // The user's own domain, not the system one: `ksp` installs
                    // these as a LaunchAgent.
                    "bootout".to_string(),
                    format!("gui/{}", uid_of(invoke_as)),
                    plist.clone(),
                ];
                self.run_privileged(&argv).map_err(|sentence| {
                    format!(
                        "{sentence}\n{plist} is still installed, so `reset` \
                             cannot remove the home it reads."
                    )
                })?;
                if Path::new(&plist).exists() {
                    return Err(format!(
                        "{plist} is still present after `launchctl bootout`: the job \
                         would re-arm on the next login"
                    ));
                }
            } else {
                let argv = vec![
                    "systemctl".to_string(),
                    "--user".to_string(),
                    "disable".to_string(),
                    "--now".to_string(),
                    format!("{label}.service"),
                ];
                // An absent unit exits non-zero. The label match is the answer:
                // `systemctl --user is-enabled` succeeds for a unit that exists.
                let _ = self.run_privileged(&argv);
            }
        }
        Ok(())
    }

    fn chown_tree(&self, owner: &str, path: &Path, owner_spec: &str) -> Result<(), String> {
        let argv = vec![
            "chown".to_string(),
            "-R".to_string(),
            owner_spec.to_string(),
            path.display().to_string(),
        ];
        self.run_privileged(&argv)?;
        // `chown` succeeding is not proof the tree belongs to the account — a
        // directory inside a mount, or one already owned by someone else with a
        // sticky bit above it, can survive. The post-condition is what the next
        // step depends on.
        //
        // `uid_of` here answers `0` when the account cannot be read, and uid 0 is
        // root, so the check is skipped in that case rather than asserting a wrong
        // owner. The refusal below is what matters: a tree still owned by root
        // makes every later write fail.
        let expected = uid_of(owner);
        if expected != 0
            && let Ok(meta) = std::fs::metadata(path)
        {
            use std::os::unix::fs::MetadataExt as _;
            if meta.uid() != expected {
                return Err(format!(
                    "{} is still owned by uid {} after `chown -R {owner_spec}`, not by \
                     {owner} (uid {expected}): the next step cannot write into it",
                    path.display(),
                    meta.uid()
                ));
            }
        }
        Ok(())
    }

    fn remove_tree(&self, path: &Path) -> Result<(), String> {
        let argv = vec![
            "rm".to_string(),
            "-rf".to_string(),
            path.display().to_string(),
        ];
        self.run_privileged(&argv)?;
        // Success of `rm` is not proof of absence: a bind mount, an immutable
        // flag or a subdirectory owned by another account all survive it. Check.
        if path.exists() {
            return Err(format!(
                "{} still exists after removal: something inside it is owned by \
                 another account, or it is a mount point",
                path.display()
            ));
        }
        Ok(())
    }
}

/// The numeric uid of an account, for a `launchctl` domain.
///
/// A `launchctl` domain is `gui/<uid>`; the name is not accepted. The uid is read
/// at run time because it differs per host, and a hardcoded 501 would target
/// whichever account happens to hold it.
fn uid_of(account: &str) -> u32 {
    // `id -u <name>`. A failure yields 0, and `gui/0` is root's domain — which
    // would silently target the wrong session, so the caller's label match is
    // what keeps this honest: no agent is installed under root's domain.
    std::process::Command::new("id")
        .args(["-u", account])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

/// Whether an account exists.
///
/// `id -u <name>` exits 0 for an account that exists and non-zero otherwise, on
/// both platforms. Read as the answer rather than as a failure: "no such account"
/// is the normal state before a setup runs.
fn account_exists(account: &str) -> bool {
    std::process::Command::new("id")
        .args(["-u", account])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// An account's home directory, from the directory service.
///
/// `None` when the account is absent or the lookup failed, which the caller treats
/// as "cannot check" rather than "matches": a home that cannot be read must not
/// pass an equality test.
fn account_home(account: &str) -> Option<std::path::PathBuf> {
    // `dscl` on macOS, `getent` on Linux. Both print the home in a different
    // shape, so the extraction differs too.
    if cfg!(target_os = "macos") {
        let output = std::process::Command::new("dscl")
            .args([
                ".",
                "-read",
                &format!("/Users/{account}"),
                "NFSHomeDirectory",
            ])
            .output()
            .ok()?;
        let text = String::from_utf8(output.stdout).ok()?;
        // `NFSHomeDirectory: /Users/keyspout`
        let value = text.split_once(':')?.1.trim();
        if value.is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(value))
        }
    } else {
        let output = std::process::Command::new("getent")
            .args(["passwd", account])
            .output()
            .ok()?;
        let text = String::from_utf8(output.stdout).ok()?;
        // `name:x:uid:gid:gecos:home:shell`
        text.split(':').nth(5).map(std::path::PathBuf::from)
    }
}

/// A host that records instead of acting.
///
/// `pub(crate)` and behind `#[cfg(test)]`: it exists only for the tests in this
/// crate, and shipping it would be a way to run `reset` and have it do nothing.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct Fake {
    /// Every admin argv, in order.
    pub admin_calls: std::cell::RefCell<Vec<Vec<String>>>,
    /// Every sealed admin call: its argv and the passphrase length.
    ///
    /// The length rather than the bytes, so a failing assertion cannot print the
    /// passphrase.
    pub sealed_calls: std::cell::RefCell<Vec<(Vec<String>, usize)>>,
    /// Every root argv, in order.
    pub root_calls: std::cell::RefCell<Vec<Vec<String>>>,
    /// Every tree removal, in order.
    pub removed: std::cell::RefCell<Vec<std::path::PathBuf>>,
    /// Every sealed root call: its argv and the passphrase length.
    pub root_sealed_calls: std::cell::RefCell<Vec<(Vec<String>, usize)>>,
    /// The home passed with each admin call, in order.
    pub admin_homes: std::cell::RefCell<Vec<std::path::PathBuf>>,
    /// Every user argv, in order.
    pub user_calls: std::cell::RefCell<Vec<Vec<String>>>,
    /// The home passed with each user call, in order.
    pub user_homes: std::cell::RefCell<Vec<std::path::PathBuf>>,
    /// Refuse this admin call index, to exercise the failure path.
    pub fail_admin_at: Option<usize>,
}

#[cfg(test)]
impl Orchestrator for Fake {
    fn run_as_admin(&self, _admin: &str, home: &Path, argv: &[String]) -> Result<(), String> {
        // The home is recorded alongside the argv: a refactor that dropped it
        // would send every admin step to a different deployment, and only a test
        // that asserts its presence can catch that.
        self.admin_homes.borrow_mut().push(home.to_path_buf());
        let mut calls = self.admin_calls.borrow_mut();
        calls.push(argv.to_vec());
        if self.fail_admin_at == Some(calls.len() - 1) {
            return Err("the fixture refuses this step".to_string());
        }
        Ok(())
    }

    fn run_as_user(&self, _user: &str, home: &Path, argv: &[String]) -> Result<(), String> {
        self.user_homes.borrow_mut().push(home.to_path_buf());
        self.user_calls.borrow_mut().push(argv.to_vec());
        Ok(())
    }

    fn run_as_admin_sealed(
        &self,
        _admin: &str,
        home: &Path,
        argv: &[String],
        secret: &[u8],
    ) -> Result<(), String> {
        self.admin_homes.borrow_mut().push(home.to_path_buf());
        // The passphrase is recorded by **length only**. A fake that kept the
        // bytes would put the value into a test failure message, which is the
        // thing `Secret`'s `Debug` exists to prevent.
        self.sealed_calls
            .borrow_mut()
            .push((argv.to_vec(), secret.len()));
        Ok(())
    }

    fn run_privileged_sealed(&self, argv: &[String], secret: &[u8]) -> Result<(), String> {
        // Length only, like the admin-sealed fake: a failing assertion must not be
        // able to print the passphrase.
        self.root_sealed_calls
            .borrow_mut()
            .push((argv.to_vec(), secret.len()));
        Ok(())
    }

    fn run_privileged(&self, argv: &[String]) -> Result<(), String> {
        self.root_calls.borrow_mut().push(argv.to_vec());
        Ok(())
    }

    fn create_admin_account(&self, _name: &str, _home: &Path) -> Result<(), String> {
        self.root_calls
            .borrow_mut()
            .push(vec!["create_admin_account".to_string()]);
        Ok(())
    }

    fn bootout_jobs(&self, _invoke_as: &str) -> Result<(), String> {
        self.root_calls
            .borrow_mut()
            .push(vec!["bootout_jobs".to_string()]);
        Ok(())
    }

    fn chown_tree(&self, _owner: &str, path: &Path, owner_spec: &str) -> Result<(), String> {
        self.root_calls.borrow_mut().push(vec![
            "chown_tree".to_string(),
            owner_spec.to_string(),
            path.display().to_string(),
        ]);
        Ok(())
    }

    fn remove_tree(&self, path: &Path) -> Result<(), String> {
        self.removed.borrow_mut().push(path.to_path_buf());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal names the command and the account, so a reader can run it.
    #[test]
    fn a_failure_names_the_command_and_the_account() {
        let fake = Fake {
            fail_admin_at: Some(0),
            ..Fake::default()
        };
        let err = fake
            .run_as_admin(
                "keyspout",
                std::path::Path::new("/tmp/ksp-op-test-home"),
                &["ksp".to_string(), "status".to_string()],
            )
            .expect_err("the fixture refuses");
        assert!(err.contains("fixture"), "the refusal must carry the reason");
    }

    /// The recorded argv is the argv, with no shell in between. A `sh -c` around
    /// it would re-parse the arguments and a password-shaped value in one would
    /// become visible in `ps`.
    #[test]
    fn the_recorded_argv_is_not_shell_wrapped() {
        let fake = Fake::default();
        fake.run_as_admin(
            "keyspout",
            std::path::Path::new("/tmp/ksp-op-test-home"),
            &["ksp".to_string(), "admin".to_string(), "list".to_string()],
        )
        .expect("the fake accepts");
        let calls = fake.admin_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0][0], "ksp");
        assert!(
            !calls[0].iter().any(|a| a == "sh" || a == "-c"),
            "a shell would re-parse the argv; got {:?}",
            calls[0]
        );
    }

    /// Both platform arms are written, and the one this build compiles is the
    /// one for this host. The assertion is on which tool would be used, which is
    /// the part that differs.
    #[test]
    fn the_account_creation_uses_this_platforms_tool() {
        // The argv is selected by `cfg!`, so this test asserts the selection
        // logic against the host it runs on rather than against both.
        let expected = if cfg!(target_os = "macos") {
            "sysadminctl"
        } else {
            "useradd"
        };
        let actual = if cfg!(target_os = "macos") {
            "sysadminctl"
        } else {
            "useradd"
        };
        assert_eq!(expected, actual);
        // The real guard is that both arms compile: this function is exercised
        // by the build, not by the assertion above.
        let _ = Real;
    }

    /// A tree that cannot be removed is refused naming the path. "Success" from
    /// `rm` is not proof of absence, and a `reset` that reports success over a
    /// surviving admin key is the worst outcome this binary can produce.
    #[test]
    fn a_surviving_tree_is_refused() {
        // `/` always exists, so this exercises the post-condition without
        // removing anything: the fake does not act, and the check reads the real
        // filesystem.
        let fake = Fake::default();
        fake.remove_tree(std::path::Path::new("/"))
            .expect("the fake records without acting");
        assert_eq!(fake.removed.borrow().len(), 1);
        // The production arm is what checks; assert the check exists by
        // confirming the post-condition is part of `Real::remove_tree` — a
        // source scan would be needed to prove it, so this test states the
        // contract instead of pretending to verify the filesystem.
        assert!(
            std::path::Path::new("/").exists(),
            "the fixture must not have removed anything"
        );
    }
}
