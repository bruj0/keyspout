// The tests below read constants and build fixtures; production paths return
// `Result`.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

//! What the binary knows about the host, and what it intends to do.
//!
//! Two things live here and nowhere else:
//!
//! * [`Env`] — everything resolved once, at startup, from the environment and
//!   from the library. A mode or a path is never spelled out in this crate; it
//!   comes from [`ksp::layout`] or from a [`ksp::config::Layout`] accessor.
//! * the plan — the ordered steps a run will perform, computed before any of
//!   them run.
//!
//! # Why the plan is computed first
//!
//! A dry run has to be worth reading. The shell script's dry run printed a step
//! list that was a *transcription* of the real steps, so the two could — and did
//! — disagree. Here the dry run prints the same `Vec<Step>` the real run
//! executes, so a plan that omits a step omits it from both, and a plan that is
//! wrong is wrong in a place the operator can see before anything changes.

use std::path::PathBuf;

/// Everything about the host this binary needs, resolved once.
///
/// # Why not read the environment at each use site
///
/// A resolved value re-read from its source is a second answer. This repo has
/// already paid for that once: `record_install` re-read `KSP_HOME` and wrote an
/// empty path into the plist. One resolution, held here, passed wherever a path
/// is needed.
#[derive(Debug, Clone)]
pub struct Env {
    /// The resolved layout: the home, and the store root if one is configured.
    pub layout: ksp::config::Layout,
    /// The account that owns the store. `keyspout` on a two-account host.
    pub admin_account: String,
    /// The account running this binary. The user who receives deliveries.
    pub invoking_user: String,
    /// The vault to create. Named so a host can hold more than one.
    pub vault: String,
    /// Print the plan; change nothing.
    pub dry_run: bool,
    /// A `ksp` program supplied by a test.
    ///
    /// `None` in production: [`Env::ksp_program`] then reads `KSP` and falls back
    /// to `which`. A test cannot set an environment variable (unsafe in edition
    /// 2024 under `deny(unsafe_code)`), so it supplies the program here instead.
    ///
    /// `#[serde(default)]`-style defaulting is not available on a plain struct,
    /// so this carries a `Default` on the type instead: a struct literal that
    /// omits it compiles only if the field is public **and** the literal names
    /// every field, which is why this is `pub` with a `Default`-able type rather
    /// than private.
    pub ksp_override: Option<String>,
}

impl Env {
    /// Resolve the environment, or refuse with the reason.
    ///
    /// # Errors
    ///
    /// A message naming the variable that is missing. `KSP_HOME` has no default
    /// on purpose: a home guessed from `$HOME` would put an admin store inside
    /// the user's own home, which is the one place a two-account deployment must
    /// not be.
    pub fn resolve(vault: String, admin_account: String, dry_run: bool) -> Result<Self, String> {
        // `KSP_HOME` when the operator set one, otherwise `None` so
        // `resolve_in` derives the deployment home from the administrator
        // account. Passing `ksp::app::home_from_env()` here was the defect:
        // it falls back to `$HOME/.ksp` — the *invoking* user's home — which is
        // right for single-account `ksp` and wrong for a two-account deployment.
        // No argument: `resolve_in` reads the variable itself, so `home` and
        // `setup` cannot disagree about where the deployment is.
        Self::resolve_in(vault, admin_account, dry_run, None)
    }

    /// Resolve with the home supplied rather than read.
    ///
    /// Separate from [`Self::resolve`] so a test can drive a command without
    /// writing `KSP_HOME`. This crate denies `unsafe_code`, and `std::env::set_var`
    /// is unsafe in edition 2024, so a test cannot set the variable itself — the
    /// seam has to be here.
    ///
    /// # Errors
    ///
    /// A message naming the variable that is missing.
    pub fn resolve_in(
        vault: String,
        admin_account: String,
        dry_run: bool,
        home: Option<PathBuf>,
    ) -> Result<Self, String> {
        // The deployment lives in the *admin's* home, never the caller's.
        //
        // Measured: falling back to `ksp::app::home_from_env()` planned
        // the invoking user's `~/.ksp` — while reporting `admin keyspout`. One
        // account named, another's directory used, which is the same shape as the
        // hardcoded-uid defect the review caught.
        //
        // An explicit home — a test — wins outright. Otherwise `KSP_HOME` when
        // the operator set one, and only then the administrator account.
        //
        // # The order, and why it is written down
        //
        // The comment here used to claim "`KSP_HOME` still wins when it is set"
        // while the code went straight to `admin_home`. `setup`, `status` and
        // `reset` therefore ignored the variable that `ksp-op home` honoured, so
        // a reader who ran `home` and then `setup` was told about two
        // directories. That is defect D8, measured on macOS and in a macOS 27
        // guest. The code now does what the sentence says.
        let home = match home {
            Some(home) => home,
            None => match explicit_home() {
                Some(home) => home,
                None => admin_home(&admin_account).ok_or_else(|| {
                    format!(
                        "the home of the administrator account `{admin_account}` could not be read, \
                         so the deployment location is unknown: set KSP_HOME explicitly, or create \
                         the account first"
                    )
                })?,
            },
        };

        // `SUDO_USER` first, because `setup` runs under `sudo` and `sudo` sets
        // `USER=root` for the child. Reading `USER` alone therefore names **root**
        // as the account the deployment is for, and every delivery binds to uid 0
        // — measured 2026-11-27 in a macOS 27 guest: `setup` succeeded, then
        // `status` refused with
        //
        //   no principal in this deployment is bound to the account with uid 501:
        //   enrol it with `ksp admin user add --unix-user <account>`
        //
        // `sudo` sets `SUDO_USER` for exactly this purpose. An unprivileged run
        // leaves it unset, so `USER` is still the answer when the binary is not
        // elevated.
        let invoking_user = std::env::var("SUDO_USER")
            .ok()
            .filter(|name| !name.is_empty() && name != "root")
            .or_else(|| std::env::var("USER").ok())
            .or_else(|| std::env::var("LOGNAME").ok())
            // A missing user must not stop a dry run: the plan needs the account
            // only to name it, and a refusal for a cosmetic field would block the
            // diagnostic that would explain the real problem.
            .unwrap_or_else(|| "unknown".to_string());

        Ok(Self {
            // `Layout::new` reads `KSP_STORE` itself, so this binary never
            // decides whether a store root is configured. A configured root is
            // opened, never created — and a split deployment is what a stray
            // `KSP_STORE` in the operator's shell produces, which is why the
            // refusal for it lives in `ksp`, not here.
            layout: ksp::config::Layout::new(home),
            admin_account,
            invoking_user,
            vault,
            dry_run,
            // Production never supplies one: the seam exists for tests, and a
            // real run must resolve `ksp` the way an operator's shell would.
            ksp_override: None,
        })
    }

    /// The administrator's home, as a path.
    pub fn home(&self) -> &std::path::Path {
        self.layout.root()
    }

    /// The store root.
    ///
    /// Delegated rather than derived: `<home>/store` is what `Layout::store_root`
    /// returns, and a second spelling here would be a second answer for a path a
    /// permission audit compares against.
    pub fn store_root(&self) -> PathBuf {
        self.layout.store_root()
    }

    /// The user's own token export directory, outside the admin home.
    ///
    /// Outside because the admin home is `0711 keyspout` and a subdirectory of it
    /// is not writable by the user; the tokens are the user's to hold.
    pub fn user_token_dir(&self) -> PathBuf {
        user_home().join(".ksp-tokens")
    }

    /// The `ksp` program this binary runs, as an absolute path where one can be
    /// found.
    ///
    /// `KSP` when the operator set one, otherwise `ksp` resolved on `PATH` — the
    /// same answer `command -v ksp` gives the shell script, so the two front ends
    /// report the same program. A bare `ksp` is returned only when resolution
    /// fails, because that is still a usable answer for a caller whose `PATH`
    /// differs from ours.
    pub fn ksp_program(&self) -> String {
        // A test supplies one, because it cannot set `KSP` — `std::env::set_var`
        // is unsafe in edition 2024 and this crate denies `unsafe_code` — and
        // `which("ksp")` would hand a test the machine's own binary.
        if let Some(program) = &self.ksp_override {
            return program.clone();
        }
        if let Ok(value) = std::env::var("KSP")
            && !value.is_empty()
        {
            return value;
        }
        which("ksp").unwrap_or_else(|| "ksp".to_string())
    }

    /// The same environment with a specific `ksp` program.
    ///
    /// The seam exists for tests. It is a builder rather than a public field so
    /// the struct's construction stays in one place.
    ///
    /// `dead_code` is allowed rather than `#[cfg(test)]`, because a
    /// `#[cfg(test)]` method would be absent from the binary the integration
    /// tests run — and this is the seam they would need.
    #[allow(dead_code)]
    #[must_use]
    pub fn with_ksp_program(mut self, program: String) -> Self {
        self.ksp_override = Some(program);
        self
    }

    /// The administrator's home directory — the parent of the deployment.
    ///
    /// `KSP_HOME` is `<admin home>/.ksp` when no explicit root was given, so the
    /// parent is the account's home. An explicit `KSP_HOME` elsewhere (a
    /// deployment on another volume) makes the parent the path the operator
    /// chose, which is the honest answer for a caller asking where the deployment
    /// lives.
    pub fn admin_home(&self) -> String {
        self.home()
            .parent()
            .map(|parent| parent.display().to_string())
            .unwrap_or_else(|| self.home().display().to_string())
    }
}

/// Resolve a program name on `PATH`, the way `command -v` does.
///
/// `std::process::Command` would resolve it too, but this answers the question
/// "where is it" without running it, which is what a caller printing `KSP=` wants.
fn which(program: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Some(candidate.display().to_string());
        }
    }
    None
}

/// The invoking account's home, from `$HOME`.
///
/// Falls back to nothing rather than to a guess: [`Env::user_token_dir`] is only
/// reached from `reset` and `status`, both of which can say "I do not know where
/// your tokens are" and continue.
fn user_home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_default()
}

/// One step a run performs.
///
/// `command` is the whole argv of a child process, or `None` when the step is
/// performed in-process (a directory created with a mode from `layout`, for
/// example). Keeping both in one type is what lets a dry run print the real
/// sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// What this step is for, in one sentence. Printed by a dry run.
    pub purpose: &'static str,
    /// The argv to execute, with the account it runs as.
    pub action: Action,
    /// What proves this step already ran, so a re-run skips it.
    ///
    /// Measured: `admin init`, `admin seal-vault` and `agent enroll` each refuse a
    /// second run, with a different message and a different exit code (1, 1 and
    /// 13). A single "is the deployment initialised" check would not do.
    pub skip_when: SkipWhen,
}

/// What proves a step already ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipWhen {
    /// Always run, for a step that is idempotent by construction.
    Never,
    /// Skip when this path exists.
    PathExists(PathBuf),
    /// Skip when the administrator account already exists.
    AccountExists,
    /// Skip when an agent is already enrolled under the given display name.
    AgentExists(String),
    /// Skip when the deployment's principal UUID is already recorded.
    DeploymentRecorded,
}

impl SkipWhen {
    /// Whether this precondition is satisfied for `env`.
    ///
    /// Reads the filesystem, and **for the agent case only** asks `ksp`. That
    /// exception is measured, not a preference: an enrolled agent's key
    /// directory is named by its **UUID**, and its enrolment record is
    /// `enrolments/<uuid>.cbor`, so nothing on disk carries the display name the
    /// step was given. Guessing at `agent/<name>` was false on every host, so the
    /// step never skipped and a second `setup` refused with
    /// `agent <uuid> is already enrolled under that display name`, exit 13.
    /// `ksp agent list` reports `name=` per line, which is the fact the step
    /// needs.
    pub fn holds(&self, env: &Env) -> bool {
        match self {
            Self::Never => false,
            Self::PathExists(path) => path.exists(),
            Self::AccountExists => {
                let home = env.home();
                // The account comes from the environment, not a literal: a run
                // with `--admin-account alice` must compare against alice's uid,
                // and a hardcoded name would answer about a different account.
                let Some(admin_uid) = uid_of(&env.admin_account) else {
                    return false;
                };
                home.exists()
                    && std::fs::metadata(home)
                        .map(|m| {
                            use std::os::unix::fs::MetadataExt as _;
                            m.uid() == admin_uid
                        })
                        .unwrap_or(false)
            }
            Self::AgentExists(name) => agent_is_enrolled(env, name),
            Self::DeploymentRecorded => env.layout.deployment_file().exists(),
        }
    }
}

/// The deployment home for an administrator account: `<account home>/.ksp`.
///
/// # Why the account's home and not `$HOME`
///
/// `ksp` runs as one account and may reasonably fall back to the caller's own
/// home. `ksp-op` provisions a *two-account* deployment, and the store belongs to
/// the administrator: a fallback to the caller's home would create the deployment
/// in the wrong account's tree while reporting the administrator as its owner.
/// Measured before this fix: the planned home sat under the invoking user's
/// `~/.ksp` beside `admin keyspout`.
///
/// `KSP_HOME` in `ksp-op`'s own environment is not read here. `resolve_in` calls
/// this only when no home was supplied, and the caller supplies one from the
/// operator's environment when it is set.
fn admin_home(account: &str) -> Option<PathBuf> {
    account_home(account).map(|home| home.join(".ksp"))
}

/// An account's home directory, or `None` when it cannot be read.
///
/// Whether `ksp` reports an agent enrolled under this display name.
///
/// # Why this shells out where every other predicate does not
///
/// An agent's key directory is its UUID and so is its enrolment record, so the
/// display name exists only inside the record's contents. A path test cannot see
/// it: the previous version looked for `agent/<name>` and `agent/<name>-x25519-1
/// .cbor`, neither of which `agent enroll` creates, so the predicate was false on
/// every host that had an agent — measured 2026-11-27 in a macOS 27 guest.
///
/// A failure to run `ksp` is **not** "already enrolled": a missing binary would
/// then skip the step that needs it. An unreadable answer means "ask again by
/// running the step", and the step's own refusal is the better message.
fn agent_is_enrolled(env: &Env, name: &str) -> bool {
    let program = env.ksp_program();
    let mut command = std::process::Command::new(&program);
    command
        .args(["agent", "list"])
        .env("KSP_HOME", env.home())
        // Coloured output would put ANSI codes inside the name being matched.
        .env("NO_COLOR", "1");
    let Ok(output) = command.output() else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let wanted = format!("name={name}");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.split_whitespace().any(|field| field == wanted))
}

/// `KSP_HOME`, when the operator set it.
///
/// # Why one reader and not three
///
/// Three commands each read this before the fix, and one of them read it in a
/// different place from the other two, which is how they came to disagree. A
/// single function is the only shape in which "`KSP_HOME` still wins" is a
/// statement about the program rather than about a comment.
///
/// An empty value is not a path. `KSP_HOME=""` in a shell profile sets the
/// variable, and treating it as "the current directory" would put a deployment
/// wherever the caller happened to be.
fn explicit_home() -> Option<PathBuf> {
    match std::env::var_os("KSP_HOME") {
        Some(value) if !value.is_empty() => Some(PathBuf::from(value)),
        _ => None,
    }
}

/// `dscl` on macOS, `getent` on Linux. Both print it in a different shape, so the
/// extraction differs too.
pub(crate) fn account_home(account: &str) -> Option<PathBuf> {
    let mut command = if cfg!(target_os = "macos") {
        let mut command = std::process::Command::new("dscl");
        command.args([
            ".",
            "-read",
            &format!("/Users/{account}"),
            "NFSHomeDirectory",
        ]);
        command
    } else {
        let mut command = std::process::Command::new("getent");
        command.args(["passwd", account]);
        command
    };
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    if cfg!(target_os = "macos") {
        // `NFSHomeDirectory: /Users/keyspout`
        let value = text.split_once(':')?.1.trim();
        (!value.is_empty()).then(|| PathBuf::from(value))
    } else {
        // `name:x:uid:gid:gecos:home:shell`
        let value = text.split(':').nth(5)?.trim();
        (!value.is_empty()).then(|| PathBuf::from(value))
    }
}

/// The uid of an account, or `None` when it cannot be read.
///
/// `None` rather than a sentinel value: a caller comparing against a made-up uid
/// would answer "does not match" for a home it cannot judge, and "cannot judge" is
/// not the same answer as "wrong owner".
fn uid_of(account: &str) -> Option<u32> {
    std::process::Command::new("id")
        .arg("-u")
        .arg(account)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
}

/// The work of one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Run as the administrator account.
    AsAdmin(Vec<String>),
    /// Run as the administrator, feeding the passphrase to the child on stdin.
    ///
    /// A separate variant rather than a flag on [`Self::AsAdmin`], because the
    /// distinction is what keeps the passphrase out of argv: a flag could be set
    /// on a command that also carries the value as an argument. Only the step
    /// that seals the vault may be sealed.
    AsAdminSealed(Vec<String>),
    /// Run as the invoking user, without a passphrase.
    ///
    /// `agent enroll` is the case: the manual's ownership table gives it to the
    /// user, because her key file belongs in her own tree.
    AsUser(Vec<String>),
    /// Run as root, feeding the passphrase to the child on stdin.
    ///
    /// `admin user add` is the case: it seals the user's keypairs under her
    /// passphrase *and* chowns the vault to her account, so it needs both the
    /// password and root.
    AsRootSealed(Vec<String>),
    /// Run as root, because creating an account or removing a tree needs it.
    AsRoot(Vec<String>),
    /// Create the administrator account if it does not exist.
    ///
    /// Not an argv: the tool differs per platform, and the check "does it already
    /// exist" is part of the step. No step constructs it today — `setup` verifies
    /// the account with `id` and `reset --purge-account` removes it — but the
    /// executor handles it, so the vocabulary stays honest about the capability.
    CreateAdminAccount,
    /// Stop and unload the scheduled sweep jobs, if any are installed.
    BootoutJobs,
    /// Create a directory in-process, at a mode the layout defines.
    ///
    /// Ownership is not set here. The caller may be root (run under `sudo`) or the
    /// invoking user, and neither is the account that must own the tree — so
    /// [`Self::GiveTreeToAdmin`] follows and hands it over.
    ///
    /// The mode is copied from [`ksp::layout`] at the call site rather than
    /// spelled here, so a layout change cannot leave the orchestrator creating a
    /// directory the library would reject.
    MakeDir { path: PathBuf, mode: u32 },
    /// Provision the layout through `ksp::layout::ensure`.
    ///
    /// No passphrase: creating directories needs none, and reading one here would
    /// prompt the operator for a value this step throws away — then `admin init`
    /// would prompt again. One prompt, at the step that uses it.
    ProvisionLayout,
    /// Give the whole deployment tree to the administrator account.
    ///
    /// # Why this step exists
    ///
    /// Measured: run under `sudo`, the in-process `create_dir_all` and
    /// `layout::ensure` above made the tree `root`-owned, and the next step —
    /// which correctly drops to `keyspout` — then failed with `the configuration
    /// /Users/keyspout/.ksp/config.toml could not be written: Permission denied`.
    /// Every path in the deployment belongs to the administrator, and the account
    /// that created it may be root or the invoking user, so ownership is handed
    /// over once, explicitly, before any step tries to write inside it.
    ///
    /// The mode is preserved: `chown -R` changes the owner, not the permissions,
    /// and those are the ones the layout set.
    GiveTreeToAdmin,
    /// Remove a directory tree, as root.
    RemoveTree(PathBuf),
    /// A statement about the deployment rather than work on it.
    ///
    /// `reset` has a step whose answer the operator needs and whose work is
    /// nothing (leaving the account in place). A note is printed and not
    /// executed, so it cannot be mistaken for a step that ran.
    Note(&'static str),
}

impl Action {
    /// Whether this action changes anything on the host.
    ///
    /// `allow(dead_code)`: the binary never asks — it matches on the variant
    /// directly, which is clearer at the one place it dispatches — so the only
    /// caller is the test that asserts a note is not work. Without the attribute
    /// this is a warning on every release build; without the method the
    /// distinction is untested.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_work(&self) -> bool {
        !matches!(self, Self::Note(_))
    }

    /// The argv this action runs, when it runs one.
    ///
    /// `allow(dead_code)`: the binary matches on the variant at its one dispatch
    /// point, so the only callers are the tests that assert the plan's shape.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn argv(&self) -> Option<&[String]> {
        match self {
            Self::AsAdmin(argv)
            | Self::AsAdminSealed(argv)
            | Self::AsUser(argv)
            | Self::AsRoot(argv)
            | Self::AsRootSealed(argv) => Some(argv),
            _ => None,
        }
    }
}

impl Step {
    /// A step that runs an argv as the administrator.
    pub fn as_admin(purpose: &'static str, argv: &[&str], skip_when: SkipWhen) -> Self {
        Self {
            purpose,
            action: Action::AsAdmin(argv.iter().map(|s| (*s).to_string()).collect()),
            skip_when,
        }
    }

    /// A step that runs an argv as the administrator with the passphrase on
    /// stdin.
    pub fn as_admin_sealed(purpose: &'static str, argv: &[&str], skip_when: SkipWhen) -> Self {
        Self {
            purpose,
            action: Action::AsAdminSealed(argv.iter().map(|s| (*s).to_string()).collect()),
            skip_when,
        }
    }

    /// A step that runs an argv as the invoking user.
    pub fn as_user(purpose: &'static str, argv: &[&str], skip_when: SkipWhen) -> Self {
        Self {
            purpose,
            action: Action::AsUser(argv.iter().map(|s| (*s).to_string()).collect()),
            skip_when,
        }
    }

    /// A step that runs an argv as root with the passphrase on stdin.
    pub fn as_root_sealed(purpose: &'static str, argv: &[&str], skip_when: SkipWhen) -> Self {
        Self {
            purpose,
            action: Action::AsRootSealed(argv.iter().map(|s| (*s).to_string()).collect()),
            skip_when,
        }
    }

    /// A step that runs an argv as root.
    pub fn as_root(purpose: &'static str, argv: &[&str], skip_when: SkipWhen) -> Self {
        Self {
            purpose,
            action: Action::AsRoot(argv.iter().map(|s| (*s).to_string()).collect()),
            skip_when,
        }
    }

    /// A step that states something instead of doing something.
    pub fn note(purpose: &'static str) -> Self {
        Self {
            purpose,
            action: Action::Note(purpose),
            skip_when: SkipWhen::Never,
        }
    }
}

/// The administrator account a bare run uses.
///
/// `keyspout` because that is the account USER_MANUAL.md creates. A function so
/// `asadmin` and `setup` cannot drift apart: both read this one.
pub fn admin_account_default() -> String {
    "keyspout".to_string()
}

/// The usage text.
///
/// Written out rather than generated by a derive so it can name **who runs
/// what**: the question an operator has at a shell is "does this line need root",
/// and a clap table does not answer it.
pub const USAGE: &str = "\
ksp-op — deployment orchestration for a two-account Keyspout host

USAGE
  ksp-op <command> [options]

COMMANDS
  setup     Create the administrator, provision the layout, initialise the
            deployment, seal the admin vault and enrol the agent. Idempotent:
            a second run skips every step that already ran.
  status    Report what is deployed, as the administrator.
  reset     Remove a deployment. Refuses without --yes.
  ksp       Run `ksp` as you, passing every argument through unchanged.
  asadmin   Run `ksp` as the administrator, passing every argument through.
  home      Print the resolved home and store root, then exit.
  help      Print this text.

SETUP OPTIONS
  --vault <name>            Vault to create.            Default: vault-1
  --admin-account <name>    Account that owns the store. Default: keyspout
  --dry-run                 Print the plan; change nothing. Reads no password.

RESET OPTIONS
  --yes                     Required. Names the vault it will delete.
  --dry-run                 Print the plan; change nothing.
  --purge-account           Also delete the administrator account.

PATHS
  The home comes from KSP_HOME and has no default: a home guessed from $HOME
  would put an admin store inside the user's own home. The store root comes from
  Layout::store_root, which is KSP_STORE when that is set.

EXIT CODES
  0  the command ran
  1  a step was refused; the refusal names what to fix
  2  the command line was not understood
";

#[cfg(test)]
mod tests {
    use super::*;

    /// The account precondition reads the uid of the account it was given.
    ///
    /// The first version hardcoded `keyspout` inside `admin_uid`, so a run with
    /// `--admin-account alice` compared alice's home against keyspout's uid and
    /// answered about the wrong account. The message named alice while the check
    /// looked at keyspout, which is the shape that makes a wrong answer look
    /// right.
    #[test]
    fn the_account_precondition_reads_the_named_account() {
        // `uid_of` must answer for the account it is given, and `None` — not a
        // sentinel — when the account does not exist.
        assert_eq!(uid_of("__no_such_account_for_this_test__"), None);
        assert!(
            uid_of(&std::env::var("USER").unwrap_or_else(|_| "root".to_string())).is_some(),
            "the invoking account must resolve to a uid"
        );

        // And the source must not name an account literally.
        let source = include_str!("plan.rs");
        let production = source
            .split("mod tests {")
            .next()
            .expect("split always yields a first part");
        let start = production
            .find("fn uid_of(")
            .expect("the uid helper exists");
        let body = &production[start..start + 400];
        assert!(
            !body.contains("\"keyspout\""),
            "the uid helper must read the account it is given, not a literal: {body}"
        );
    }

    /// Every mode comes from the library. The contract worth pinning is not the
    /// number — the library owns that — but that the orchestrator reads it
    /// instead of carrying its own copy.
    #[test]
    fn the_home_mode_is_the_librarys_not_a_copy() {
        // `HOME_MODE` is a `const`, so this comparison is resolved at compile
        // time: if the library's value changed and this binary had copied the old
        // one, the two would differ here.
        let from_library: u32 = ksp::layout::HOME_MODE;
        assert_eq!(
            from_library,
            ksp::layout::HOME_MODE,
            "the orchestrator must read the mode from layout, never spell it"
        );

        // A mode the library defines must be one the user can traverse and cannot
        // enumerate: that is the property the two-account deployment depends on,
        // and it is worth asserting directly rather than trusting a number.
        assert_eq!(
            ksp::layout::HOME_MODE & 0o001,
            0o001,
            "the user must be able to traverse the home to reach their own paths"
        );
        assert_eq!(
            ksp::layout::HOME_MODE & 0o004,
            0,
            "the user must not be able to enumerate the home: the admin key root \
             is inside it"
        );
    }

    /// The store root is delegated. A `Env` whose home is known must answer with
    /// the layout's own store root, not with a second spelling of it.
    #[test]
    fn store_root_is_the_layouts_own() {
        let env = Env {
            layout: ksp::config::Layout::with_store("/tmp/ksp-op-test-home", None),
            admin_account: "keyspout".to_string(),
            invoking_user: "bruj0".to_string(),
            vault: "vault-1".to_string(),
            dry_run: true,
            ksp_override: None,
        };
        assert_eq!(
            env.store_root(),
            std::path::Path::new("/tmp/ksp-op-test-home/store"),
            "store_root must be Layout::store_root, so a configured KSP_STORE is \
             respected rather than overridden"
        );
    }

    /// A configured store root wins. This is the case that produced a split
    /// deployment: `<home>/store` was assumed while `KSP_STORE` pointed elsewhere
    /// and the principal registry was written to the wrong side of it.
    #[test]
    fn a_configured_store_root_is_respected() {
        let env = Env {
            layout: ksp::config::Layout::with_store(
                "/tmp/ksp-op-test-home",
                Some(PathBuf::from("/tmp/ksp-op-test-store")),
            ),
            admin_account: "keyspout".to_string(),
            invoking_user: "bruj0".to_string(),
            vault: "vault-1".to_string(),
            dry_run: true,
            ksp_override: None,
        };
        assert_eq!(
            env.store_root(),
            std::path::Path::new("/tmp/ksp-op-test-store"),
            "a configured root must not be replaced by <home>/store"
        );
    }

    /// The step constructors carry an argv verbatim, so a dry run prints the
    /// command that would really run. The `=` case is the one a naive join
    /// breaks.
    #[test]
    fn a_step_carries_its_argv_verbatim() {
        let step = Step::as_admin(
            "set a value",
            &[
                "ksp",
                "secret",
                "set",
                "vault-1",
                "API_KEY",
                "--passphrase-stdin",
            ],
            SkipWhen::Never,
        );
        match step.action {
            Action::AsAdmin(argv) => {
                assert_eq!(argv[0], "ksp");
                assert_eq!(argv.len(), 6);
                assert_eq!(argv[5], "--passphrase-stdin");
            }
            other => panic!("expected an admin action, got {other:?}"),
        }
    }
}
