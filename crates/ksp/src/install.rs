//! Installing a sweep job without escalating.
//!
//! # What this module owns
//!
//! Where a job may be written, how it is written, and what the operator is told.
//! It decides nothing about authorization: the caller supplies an
//! [`InstallAuthority`], because only the caller knows whether an admin or the
//! user is acting.
//!
//! # What it must not do
//!
//! It must never read the capability state. If the installer could ask "is the
//! capability already `Scheduled`?", the shortcut "install only when it is
//! `None`" becomes expressible, and that shortcut invites the reverse inference:
//! that a successful install means the capability is no longer `None`. That
//! inference is misfit E, and the module boundary is what prevents it.

use std::path::{Path, PathBuf};

/// Who is asking for the install.
///
/// The installer reads this to choose the [`Loaded`] value; it never reads it to
/// decide whether to proceed. A refusal is the caller's decision, made before it
/// calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallAuthority {
    /// The admin armed the schedule. A load is verified.
    Admin,
    /// The user armed her own schedule. A load is declared, not verified.
    User,
}

/// What the load actually established.
///
/// Two variants, not a bool: a bool lets `true` be read as "running", which is
/// misfit E in one line. `Declared` says a job was written and its load was
/// requested; `Verified` says the load command succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Loaded {
    /// The load command succeeded.
    Verified,
    /// The job was written and its load was requested, but nothing proves it
    /// runs. An install is a declaration, never evidence.
    Declared,
}

/// What an install produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOutcome {
    /// The file that was written.
    pub path: PathBuf,
    /// What the load established.
    pub loaded: Loaded,
}

/// The unit content and where it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitSpec {
    /// The file body.
    pub content: String,
    /// The absolute path to write.
    pub path: PathBuf,
}

/// Why an install did not happen.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstallRefusal {
    /// The requested kind is not one this host can install.
    #[error(
        "this host installs a launchd property list only; '{kind}' is not installed by ksp, so \
         nothing was written and no privileged command was run"
    )]
    UnsupportedKind {
        /// The kind the operator asked for.
        kind: String,
    },
    /// The destination is outside the operator's own home.
    #[error(
        "the destination '{path}' is outside this account's own home; ksp installs a job for the \
         account that runs it and never escalates, so nothing was written"
    )]
    OutsideHome {
        /// The destination that was refused.
        path: String,
    },
    /// The file could not be written.
    #[error("the job could not be written to '{path}': {reason}")]
    Write {
        /// The destination.
        path: String,
        /// Why it failed, in the reader's words.
        reason: String,
    },
    /// The load command was attempted and failed.
    ///
    /// The reason is `launchctl`'s own text with any escalation hint removed: a
    /// tool that suggests `sudo` invites the operator to escalate for a job
    /// that is meant to run as them, which is misfit C.
    #[error("the job was written to '{path}' but could not be loaded: {reason}")]
    Load {
        /// The file that was written.
        path: String,
        /// Why the load failed, with any escalation hint removed.
        reason: String,
    },
}

/// Runs one external command.
///
/// A trait so a test can assert that a refusal ran nothing, which a runtime
/// check cannot see: a call that was never made leaves no trace.
pub trait CommandRunner {
    /// Run `program` with `args`, returning `Ok(())` on success.
    fn run(&self, program: &str, args: &[&str]) -> Result<(), String>;
}

/// The real runner.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<(), String> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|error| error.to_string())?;
        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    }
}

/// Installs a `launchd` property list under the operator's own home.
pub struct LaunchdInstaller<R: CommandRunner> {
    runner: R,
    /// The operator's home, so a test can point it at a throwaway tree.
    home: PathBuf,
}

impl<R: CommandRunner> LaunchdInstaller<R> {
    /// Build an installer that writes under `home`.
    pub fn new(runner: R, home: impl Into<PathBuf>) -> Self {
        Self {
            runner,
            home: home.into(),
        }
    }

    /// Write the unit and load it.
    ///
    /// The mode is set with `set_permissions`, never through `open(2)`'s mode:
    /// that mode is masked by the caller's `umask`, and a principal on `umask
    /// 077` would produce a file the loader cannot read.
    pub fn install(
        &self,
        unit: &UnitSpec,
        authority: InstallAuthority,
    ) -> Result<InstallOutcome, InstallRefusal> {
        self.check_destination(&unit.path)?;
        if let Some(parent) = unit.path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| InstallRefusal::Write {
                path: parent.display().to_string(),
                reason: error.to_string(),
            })?;
        }
        std::fs::write(&unit.path, &unit.content).map_err(|error| InstallRefusal::Write {
            path: unit.path.display().to_string(),
            reason: error.to_string(),
        })?;
        // Crosses an account boundary, so the mode is set explicitly rather than
        // requested at creation.
        std::fs::set_permissions(
            &unit.path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .map_err(|error| InstallRefusal::Write {
            path: unit.path.display().to_string(),
            reason: error.to_string(),
        })?;

        let path_text = unit.path.display().to_string();
        // `ksp-posture` owns the uid lookup, so this crate keeps its
        // `unsafe_code = "deny"` and does not reach for libc directly.
        let uid = ksp_posture::permissions::effective_uid();
        let domain = format!("gui/{uid}");
        self.runner
            .run("launchctl", &["bootstrap", &domain, &path_text])
            .map_err(|reason| InstallRefusal::Load {
                path: path_text.clone(),
                reason: strip_escalation_hint(&reason),
            })?;

        Ok(InstallOutcome {
            path: unit.path.clone(),
            loaded: match authority {
                InstallAuthority::Admin => Loaded::Verified,
                InstallAuthority::User => Loaded::Declared,
            },
        })
    }

    /// Refuse a destination outside the operator's own home.
    fn check_destination(&self, path: &Path) -> Result<(), InstallRefusal> {
        if path.starts_with(&self.home) {
            Ok(())
        } else {
            Err(InstallRefusal::OutsideHome {
                path: path.display().to_string(),
            })
        }
    }
}

/// Remove any escalation hint from a tool's error text.
///
/// `launchctl` appends "Try re-running the command as root for richer errors."
/// Passing that through tells an operator to escalate for a job that is meant
/// to run as them. Misfit C: the refusal must never suggest escalation.
fn strip_escalation_hint(reason: &str) -> String {
    reason
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            !(lower.contains("as root") || lower.contains("sudo") || lower.contains("privilege"))
        })
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string()
}

/// Refuses every install, naming why.
///
/// What a build without `launchd` support returns. It runs no process.
pub struct RefusingInstaller {
    reason: &'static str,
}

impl RefusingInstaller {
    /// Build a refusing installer with the given reason.
    pub fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// Refuse, naming the reason.
    pub fn install(&self, unit: &UnitSpec) -> Result<InstallOutcome, InstallRefusal> {
        Err(InstallRefusal::Write {
            path: unit.path.display().to_string(),
            reason: self.reason.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::cell::RefCell;

    /// Records every call so a test can assert none was made.
    #[derive(Default)]
    struct RecordingRunner {
        calls: RefCell<Vec<(String, Vec<String>)>>,
        fail: bool,
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<(), String> {
            self.calls.borrow_mut().push((
                program.to_string(),
                args.iter().map(|a| a.to_string()).collect(),
            ));
            if self.fail {
                Err("the domain is not available".to_string())
            } else {
                Ok(())
            }
        }
    }

    fn unit_in(home: &Path) -> UnitSpec {
        UnitSpec {
            content: "<plist/>".to_string(),
            path: home.join("Library/LaunchAgents/com.keyspout.sweep.plist"),
        }
    }

    #[test]
    fn an_install_writes_the_unit_at_0600_and_loads_it() {
        let home = tempfile::tempdir().unwrap();
        let runner = RecordingRunner::default();
        let installer = LaunchdInstaller::new(runner, home.path());
        let unit = unit_in(home.path());

        let outcome = installer.install(&unit, InstallAuthority::Admin).unwrap();
        assert_eq!(outcome.loaded, Loaded::Verified);
        assert_eq!(outcome.path, unit.path);

        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&unit.path).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600, "the unit is private to its owner");

        let calls = installer.runner.calls.borrow();
        assert_eq!(calls.len(), 1, "one load command");
        assert_eq!(calls[0].0, "launchctl");
        assert_eq!(calls[0].1[0], "bootstrap");
    }

    /// A user arming's install is declared, not verified.
    #[test]
    fn a_user_install_is_declared_and_an_admin_install_is_verified() {
        let home = tempfile::tempdir().unwrap();
        let user = LaunchdInstaller::new(RecordingRunner::default(), home.path());
        let outcome = user
            .install(&unit_in(home.path()), InstallAuthority::User)
            .unwrap();
        assert_eq!(outcome.loaded, Loaded::Declared);

        let admin = LaunchdInstaller::new(RecordingRunner::default(), home.path());
        let outcome = admin
            .install(&unit_in(home.path()), InstallAuthority::Admin)
            .unwrap();
        assert_eq!(outcome.loaded, Loaded::Verified);
    }

    /// A destination outside the operator's home is refused before any write.
    #[test]
    fn a_destination_outside_the_home_is_refused_and_writes_nothing() {
        let home = tempfile::tempdir().unwrap();
        let runner = RecordingRunner::default();
        let installer = LaunchdInstaller::new(runner, home.path());
        let unit = UnitSpec {
            content: "<plist/>".to_string(),
            path: PathBuf::from("/Library/LaunchDaemons/com.keyspout.sweep.plist"),
        };

        let refusal = installer
            .install(&unit, InstallAuthority::Admin)
            .unwrap_err();
        assert!(
            matches!(refusal, InstallRefusal::OutsideHome { .. }),
            "{refusal:?}"
        );
        assert!(!unit.path.exists(), "nothing is written outside the home");
        assert!(
            installer.runner.calls.borrow().is_empty(),
            "a refusal runs no process"
        );
    }

    /// A failed load reports the file that was written.
    #[test]
    fn a_failed_load_names_the_file_it_wrote() {
        let home = tempfile::tempdir().unwrap();
        let runner = RecordingRunner {
            fail: true,
            ..RecordingRunner::default()
        };
        let installer = LaunchdInstaller::new(runner, home.path());
        let unit = unit_in(home.path());

        let refusal = installer
            .install(&unit, InstallAuthority::Admin)
            .unwrap_err();
        let InstallRefusal::Load { path, .. } = &refusal else {
            panic!("expected Load, got {refusal:?}");
        };
        assert_eq!(path, &unit.path.display().to_string());
        assert!(
            unit.path.exists(),
            "the file stays, so the operator can inspect it"
        );
    }

    /// The refusing installer runs nothing.
    #[test]
    fn the_refusing_installer_runs_no_process() {
        let home = tempfile::tempdir().unwrap();
        let installer = RefusingInstaller::new("launchd is not available on this host");
        let unit = unit_in(home.path());
        assert!(installer.install(&unit).is_err());
        assert!(!unit.path.exists());
    }
}
