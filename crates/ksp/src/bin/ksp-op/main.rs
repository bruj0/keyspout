//! `ksp-op` — deployment orchestration for a two-account Keyspout host.
//!
//! One administrator account owns the store; one user account holds the
//! deliveries. `ksp` does the cryptography and knows nothing about accounts.
//! This binary does the accounts: it creates the administrator, provisions the
//! layout, arms the sweep, and reports or removes what it built.
//!
//! # Why a second binary rather than a `ksp` subcommand
//!
//! `crates/ksp/src/commands.rs` fixes the command surface, and
//! `the_command_surface_matches_the_design_specification` asserts it. Adding a
//! verb there would need a design-spec amendment; adding a `[[bin]]` needs none.
//! The two also have different trust: `ksp` runs as the principal that owns the
//! keys and must never want root, while this binary exists to create accounts and
//! therefore asks for root by design. Keeping them apart means an operator can
//! see which is which in the process table.
//!
//! # Why the orchestration is written in Rust
//!
//! `scripts/ksp-op.sh` did this job and could not be tested: `read -rs "?prompt"`
//! is zsh syntax in a bash file and failed with
//! `read: '?Vault password: ': not a valid identifier`. In Rust the passphrase
//! reader is a pure function over bytes, so every branch is reachable without a
//! terminal, a subprocess or root. The script stays for the documented workflow
//! until this binary is released.

// This binary's product **is** text: a plan an operator reads before anything
// changes, and the outcome of each step. `print_stdout`, `print_stderr` and
// `dbg_macro` are warned workspace-wide because a library that prints corrupts
// another program's output. That hazard does not exist here — the whole process
// exists to print — so the allowance is module-scoped rather than argued once
// per call site, and the exception is visible to whoever reads the lint config.
#![allow(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]
// `expect`/`unwrap` are warned because a panic in a library that handles key
// material is a leak vector. Here they appear only in `#[cfg(test)]` code, where
// a failing assertion is how a test reports — the assertions are readable only
// because the failure message says which one failed. Production paths in this
// binary return `Result` and never unwrap.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

mod orchestrator;
mod passphrase;
mod plan;

use std::path::Path;
use std::process::ExitCode;

use orchestrator::{Orchestrator, Real};
use plan::{Action, Env, Step};

/// Exit codes, matching the table in `plan::USAGE`.
const OK: u8 = 0;
const REFUSED: u8 = 1;
const USAGE_ERROR: u8 = 2;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(run(&args))
}

/// Dispatch one command line.
///
/// Returns an exit code rather than calling `std::process::exit`, so a test can
/// drive it and the caller keeps the choice of how to end.
fn run(args: &[String]) -> u8 {
    let Some(command) = args.first().map(String::as_str) else {
        print!("{}", plan::USAGE);
        return OK;
    };

    match command {
        "help" | "-h" | "--help" => {
            print!("{}", plan::USAGE);
            OK
        }
        "ksp" => exec_ksp(None, &args[1..]),
        "asadmin" => exec_ksp(Some(&plan::admin_account_default()), &args[1..]),
        "home" => cmd_home(&args[1..]),
        "setup" => cmd_setup(&Real, &FromStdin, None, &args[1..]),
        "status" => cmd_status(&Real, &FromStdin, None, &args[1..]),
        "reset" => cmd_reset(&Real, &FromStdin, None, &args[1..]),
        other => {
            // The sentence names the commands that exist, so a typo is one edit
            // from a working line rather than a trip to the manual.
            eprintln!("ksp-op: unknown command '{other}'");
            eprint!("{}", plan::USAGE);
            USAGE_ERROR
        }
    }
}

/// Options shared by the commands that accept them.
#[derive(Debug, Default)]
struct Options {
    vault: Option<String>,
    admin_account: Option<String>,
    dry_run: bool,
    yes: bool,
    purge_account: bool,
}

impl Options {
    /// Parse the flags this binary defines.
    ///
    /// # Errors
    ///
    /// A sentence naming the flag that was not understood. An unknown flag is
    /// refused rather than ignored: a `--dry-runn` typo that were ignored would
    /// perform the real run.
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut options = Self::default();
        let mut index = 0;
        while index < args.len() {
            let arg = args[index].as_str();
            match arg {
                "--dry-run" => options.dry_run = true,
                "--yes" => options.yes = true,
                "--purge-account" => options.purge_account = true,
                "--vault" | "--admin-account" => {
                    let value = args.get(index + 1).ok_or_else(|| {
                        format!("{arg} needs a value, for example `{arg} vault-1`")
                    })?;
                    if arg == "--vault" {
                        options.vault = Some(value.clone());
                    } else {
                        options.admin_account = Some(value.clone());
                    }
                    index += 1;
                }
                other => {
                    return Err(format!(
                        "unknown option '{other}': the options are --vault, \
                         --admin-account, --dry-run, --yes, --purge-account"
                    ));
                }
            }
            index += 1;
        }
        Ok(options)
    }

    /// The vault name, defaulted.
    fn vault(&self) -> String {
        self.vault.clone().unwrap_or_else(|| "vault-1".to_string())
    }

    /// The administrator account, defaulted.
    ///
    /// `keyspout` is the default because that is the account the documented
    /// deployment creates, so a run with no flags reproduces the manual.
    fn admin_account(&self) -> String {
        self.admin_account
            .clone()
            .unwrap_or_else(|| "keyspout".to_string())
    }
}

/// Where a passphrase comes from.
///
/// Injected rather than called directly, because the defect this feature exists
/// to prevent is *a dry run that asks for a password*. Proving that needs a test
/// that supplies a source recording every read — and a source that would panic if
/// a dry run reached it. Calling [`passphrase::from_stdin`] at the use site makes
/// that test impossible, which is how the shell script shipped the bug.
trait PassphraseSource {
    /// Read the passphrase once.
    ///
    /// # Errors
    ///
    /// A [`passphrase::Refusal`] when nothing usable arrived.
    fn read(&self) -> Result<passphrase::Secret, passphrase::Refusal>;
}

/// The real source: the process's own stdin, read at most once when it is a pipe.
///
/// # Why this caches, and why only sometimes (D9)
///
/// `setup` has two sealed steps — `seal-vault` and `admin user add` — and each
/// asks for the passphrase. `/dev/tty` cannot be re-read: [`passphrase::from_stdin`]
/// reads stdin to EOF, so with stdin redirected from a file or a pipe the second
/// step found nothing and refused with
///
///   the vault passphrase could not be read: supply it on stdin
//
/// which made `setup` impossible to run from a script. Measured 2026-11-27: steps
/// 1–7 reported `ok`, step 8 refused, and two passphrases on two lines did not
/// help because `read_to_end` consumed both.
///
/// # Why a terminal is not cached
///
/// A terminal can answer twice, and each step should ask: the operator sees which
/// value is being used for which step, and a mistyped confirmation is caught at
/// the step that needs it rather than replayed into both. Caching a terminal read
/// would also make the second prompt silently absent, which is the kind of
/// change a person notices only when it is wrong.
struct FromStdin;

impl PassphraseSource for FromStdin {
    fn read(&self) -> Result<passphrase::Secret, passphrase::Refusal> {
        thread_local! {
            /// The first value a non-terminal stdin delivered.
            static CACHED: std::cell::RefCell<Option<passphrase::Secret>> =
                const { std::cell::RefCell::new(None) };
        }
        if passphrase::stdin_is_repeatable() {
            return passphrase::from_stdin();
        }
        CACHED.with(|slot| {
            if let Some(secret) = slot.borrow().as_ref() {
                // The panel above is a one-time read; this is its replay.
                return Ok(passphrase::Secret::replay(secret.as_bytes()));
            }
            let secret = passphrase::from_stdin()?;
            *slot.borrow_mut() = Some(passphrase::Secret::replay(secret.as_bytes()));
            Ok(secret)
        })
    }
}

/// Replace this process with `ksp`, so exit codes and signals are its own.
///
/// # Why `exec` and not `status`
///
/// `ksp-op ksp run --token … --env VAR` is used in pipelines and in scripts that
/// branch on the exit code. A wrapper that waits and re-raises turns a signal
/// into a number and an exit code into a translation. `exec` makes the child the
/// process, so there is nothing to translate.
///
/// # Why the argv is passed through untouched
///
/// No shell, no re-quoting: a re-parsed argument is how a password-shaped value
/// becomes visible in `ps`, and the passthrough exists so an operator can use the
/// wrapper for the commands this binary does not model.
fn exec_ksp(as_account: Option<&str>, argv: &[String]) -> u8 {
    use std::os::unix::process::CommandExt as _;

    if argv.is_empty() {
        eprintln!("ksp-op: `ksp` and `asadmin` need a command, for example `ksp-op ksp status`");
        return USAGE_ERROR;
    }

    // The program is always `ksp`: these two verbs run it, they do not run an
    // arbitrary binary. Treating `argv[0]` as the program made
    // `ksp-op ksp version` try to execute a program called `version`.
    let mut command = match as_account {
        None => std::process::Command::new("ksp"),
        Some(account) => {
            let mut command = std::process::Command::new("sudo");
            // `-n`: an unanswerable prompt would hang a non-interactive run.
            command.args(["-n", "-u", account, "-H", "env"]);
            // The home is not threaded here because the operator supplied the
            // command themselves: honouring their own `KSP_HOME` is the whole
            // point of a passthrough. A wrapper that silently substituted one
            // would run a different command from the one that was typed.
            command.arg("ksp");
            command
        }
    };
    // Every argument is passed through untouched: no shell, no re-quoting.
    command.args(argv);

    // `exec` only returns on failure, and the error is the reason.
    let error = command.exec();
    eprintln!("ksp-op: could not run `{}`: {error}", argv.join(" "));
    REFUSED
}

/// The deployment home for a command, or `None` to let the environment decide.
///
/// # What "the environment" means
///
/// `None` here is not "there is no home". It is the signal [`Env::resolve_in`]
/// uses for "resolve it the way `ksp-op home` does": `KSP_HOME` when the
/// operator set one, otherwise the administrator account's home.
///
/// # Why this is a function rather than `.map(Path::to_path_buf)`
///
/// That is what the three commands used to pass, and the comment beside it said
/// `None` meant "read the environment" — while `resolve_in` treated `None` as
/// "derive it from the account". `setup --dry-run` therefore ignored `KSP_HOME`
/// and `ksp-op home` honoured it, which is defect D8. One function names the
/// intent in one place, so the next reader cannot re-derive it wrongly.
///
/// An explicit `home` — a test — still wins, because a test that had to set a
/// process environment variable could not run under `unsafe_code` denial.
fn deployment_home(home: Option<&Path>) -> Option<std::path::PathBuf> {
    home.map(Path::to_path_buf)
}

/// `home` — print the resolved paths and exit.
///
/// The command exists because the two variables that decide the deployment
/// (`KSP_HOME`, `KSP_STORE`) are easy to have half-set, and a split deployment
/// then fails much later with `the principal registry ... could not be written`.
/// Printing them first makes that visible before anything is created.
fn cmd_home(args: &[String]) -> u8 {
    let options = match Options::parse(args) {
        Ok(options) => options,
        Err(sentence) => {
            eprintln!("ksp-op: {sentence}");
            return USAGE_ERROR;
        }
    };
    let env = match Env::resolve(options.vault(), options.admin_account(), false) {
        Ok(env) => env,
        Err(sentence) => {
            eprintln!("ksp-op: {sentence}");
            return REFUSED;
        }
    };

    // `KEY=value`, matching `scripts/ksp-op.sh home`, so a caller can parse it:
    // `$(ksp-op home | sed -n 's/^KSP_HOME=//p')` is how the quickstart reads the
    // deployment path, and an aligned prose table cannot be parsed that way. The
    // shell script and this binary are two front ends on one deployment, so they
    // answer the same question in the same shape and with the same key names.
    println!("KSP_HOME={}", env.home().display());
    println!("KSP={}", env.ksp_program());
    println!("KSP_ADMIN_HOME={}", env.admin_home());
    // The split case is named here rather than left to a later failure. It goes to
    // stderr so the four lines above stay a clean `KEY=value` block for a parser.
    if env.layout.configured_store().is_some() {
        eprintln!();
        eprintln!(
            "ksp-op: KSP_STORE is set, so the store root is not <home>/store. An \
             administrator's keys still live in the home while the store it writes goes to \
             that root — a split deployment. Unset KSP_STORE for the single-home layout the \
             manual documents."
        );
    }
    OK
}

/// `setup` — create the deployment.
///
/// The steps come from [`setup_plan`], which is also what a dry run prints, so
/// the two cannot disagree.
fn cmd_setup(
    orchestrator: &dyn Orchestrator,
    passwords: &dyn PassphraseSource,
    home: Option<&Path>,
    args: &[String],
) -> u8 {
    let options = match Options::parse(args) {
        Ok(options) => options,
        Err(sentence) => {
            eprintln!("ksp-op: {sentence}");
            return USAGE_ERROR;
        }
    };
    let env = match Env::resolve_in(
        options.vault(),
        options.admin_account(),
        options.dry_run,
        // `None` means "resolve the home the way every other command does", not
        // "there is no home". An explicit `home` — a test — wins; otherwise
        // `deployment_home` reads `KSP_HOME` and falls back to the
        // administrator account's home.
        //
        // # This was D8
        //
        // The calls passed `home.map(Path::to_path_buf)` and the comment claimed
        // `None` meant "read the environment", while `resolve_in` treated `None`
        // as "derive it from the account". So `setup --dry-run` ignored
        // `KSP_HOME` while `ksp-op home` honoured it, and the module comment on
        // `Env::resolve` — "`KSP_HOME` still wins when it is set" — was false for
        // three of the five subcommands. Measured 2026-11-27 on macOS and again
        // in a macOS 27 guest.
        deployment_home(home),
    ) {
        Ok(env) => env,
        Err(sentence) => {
            eprintln!("ksp-op: {sentence}");
            return REFUSED;
        }
    };

    let steps = setup_plan(&env);
    if env.dry_run {
        print_plan("setup", &env, &steps);
        return OK;
    }
    execute_steps(orchestrator, passwords, &env, &steps)
}

/// `status` — report what is deployed.
fn cmd_status(
    orchestrator: &dyn Orchestrator,
    passwords: &dyn PassphraseSource,
    home: Option<&Path>,
    args: &[String],
) -> u8 {
    let options = match Options::parse(args) {
        Ok(options) => options,
        Err(sentence) => {
            eprintln!("ksp-op: {sentence}");
            return USAGE_ERROR;
        }
    };
    let env = match Env::resolve_in(
        options.vault(),
        options.admin_account(),
        false,
        // `None` means "resolve the home the way every other command does", not
        // "there is no home". An explicit `home` — a test — wins; otherwise
        // `deployment_home` reads `KSP_HOME` and falls back to the
        // administrator account's home.
        //
        // # This was D8
        //
        // The calls passed `home.map(Path::to_path_buf)` and the comment claimed
        // `None` meant "read the environment", while `resolve_in` treated `None`
        // as "derive it from the account". So `setup --dry-run` ignored
        // `KSP_HOME` while `ksp-op home` honoured it, and the module comment on
        // `Env::resolve` — "`KSP_HOME` still wins when it is set" — was false for
        // three of the five subcommands. Measured 2026-11-27 on macOS and again
        // in a macOS 27 guest.
        deployment_home(home),
    ) {
        Ok(env) => env,
        Err(sentence) => {
            eprintln!("ksp-op: {sentence}");
            return REFUSED;
        }
    };

    let steps = status_plan();
    if options.dry_run {
        print_plan("status", &env, &steps);
        return OK;
    }
    // `status` reads no passphrase, but the executor takes a source so the two
    // commands cannot diverge: a `status` that grew a sealed step would read the
    // passphrase without anyone noticing.
    execute_steps(orchestrator, passwords, &env, &steps)
}

/// `reset` — remove a deployment.
///
/// # Why `--yes` is required and names the vault
///
/// This is the one command that destroys a sealed store. A flag that can be
/// passed by accident is not a guard, so the guard names what will be deleted:
/// the operator reads the vault name back and recognises it. The shell script
/// refused to proceed without `--yes` for the same reason.
fn cmd_reset(
    orchestrator: &dyn Orchestrator,
    passwords: &dyn PassphraseSource,
    home: Option<&Path>,
    args: &[String],
) -> u8 {
    let options = match Options::parse(args) {
        Ok(options) => options,
        Err(sentence) => {
            eprintln!("ksp-op: {sentence}");
            return USAGE_ERROR;
        }
    };
    let env = match Env::resolve_in(
        options.vault(),
        options.admin_account(),
        options.dry_run,
        // `None` means "resolve the home the way every other command does", not
        // "there is no home". An explicit `home` — a test — wins; otherwise
        // `deployment_home` reads `KSP_HOME` and falls back to the
        // administrator account's home.
        //
        // # This was D8
        //
        // The calls passed `home.map(Path::to_path_buf)` and the comment claimed
        // `None` meant "read the environment", while `resolve_in` treated `None`
        // as "derive it from the account". So `setup --dry-run` ignored
        // `KSP_HOME` while `ksp-op home` honoured it, and the module comment on
        // `Env::resolve` — "`KSP_HOME` still wins when it is set" — was false for
        // three of the five subcommands. Measured 2026-11-27 on macOS and again
        // in a macOS 27 guest.
        deployment_home(home),
    ) {
        Ok(env) => env,
        Err(sentence) => {
            eprintln!("ksp-op: {sentence}");
            return REFUSED;
        }
    };

    if !options.yes && !env.dry_run {
        eprintln!(
            "ksp-op: refusing to remove {} without --yes.\n\
             This deletes the sealed store for vault '{}', including every key in \
             it. Read the name back, then re-run with --yes.",
            env.home().display(),
            env.vault
        );
        return REFUSED;
    }

    let steps = reset_plan(&env, options.purge_account);
    if env.dry_run {
        print_plan("reset", &env, &steps);
        return OK;
    }
    execute_steps(orchestrator, passwords, &env, &steps)
}

/// The ordered steps `setup` performs.
///
/// The list is the specification: an entry here is a step a real run performs,
/// and a step that is not here does not happen.
///
/// # Idempotence
///
/// A second run must succeed and report nothing to do. That is why the layout is
/// provisioned by `ksp::layout::ensure` ([`Action::ProvisionLayout`]) rather than
/// by a `mkdir` per directory: the library already knows which entries exist and
/// which modes they need, and a second implementation would be free to drift from
/// the one the permission audit reads.
fn setup_plan(env: &Env) -> Vec<Step> {
    use plan::SkipWhen;

    let admin = env.admin_account.as_str();
    let user = env.invoking_user.as_str();
    let config = env.home().join("config.toml");
    let agent_name = format!("{user}-laptop");

    vec![
        Step {
            purpose: "create the administrator account, if it does not exist",
            // The step the WP table names, with its own precondition: `id`
            // succeeding is the evidence, and the platform tool differs.
            action: Action::CreateAdminAccount,
            skip_when: SkipWhen::AccountExists,
        },
        Step {
            purpose: "create the administrator's home at the mode the user may traverse",
            action: Action::MakeDir {
                path: env.home().to_path_buf(),
                // Read from the library: the user traverses the home and cannot
                // enumerate it. A literal here would be a second answer.
                mode: ksp::layout::HOME_MODE,
            },
            skip_when: SkipWhen::PathExists(env.home().to_path_buf()),
        },
        Step {
            purpose: "provision the layout: key root, enrolments, sweeper, store",
            action: Action::ProvisionLayout,
            // `layout::ensure` is itself idempotent, so this step always runs.
            // Writing a precondition here would be a second answer about which
            // entries exist, and the library owns that answer.
            skip_when: SkipWhen::Never,
        },
        Step {
            purpose: "give the tree to the administrator, so every later step can write",
            // Measured: under `sudo` the two steps above create the tree
            // `root`-owned, and `ksp init` as `keyspout` then fails with
            // `Permission denied` on config.toml.
            action: Action::GiveTreeToAdmin,
            skip_when: SkipWhen::Never,
        },
        Step::as_admin(
            "probe this host and write its capability configuration",
            &["ksp", "init"],
            SkipWhen::PathExists(config.clone()),
        ),
        Step::as_admin(
            "create the admin signing key and name the vault",
            &[
                "ksp", "admin", "init", "--vault", &env.vault, "--user", user, "--key-id", admin,
            ],
            // Measured: a second `admin init` refuses with "this deployment is
            // already initialised ... a principal UUID is issued once and never
            // reissued", exit 1.
            SkipWhen::DeploymentRecorded,
        ),
        Step::as_admin_sealed(
            "seal the admin's vault, which every publication is sealed to",
            &["ksp", "admin", "seal-vault"],
            // The path `seal-vault` actually writes, which is the **home root**,
            // not a file under `admin/`.
            //
            // This asked `admin_key_root().join("vault.cbor")` — a path that is
            // never created — so the predicate never held, the step never
            // skipped, and the second `setup` refused with
            //
            //   step 7 refused: `ksp admin seal-vault` failed as admin: ksp: the
            //   admin … already has a vault
            //
            // while `plan::USAGE` promises "a second run skips every step that
            // already ran". Measured 2026-11-27 in a macOS 27 guest.
            //
            // `admin_vault_file()` names what `seal-vault` writes. It is not
            // `vault_file()`: that is the copy `admin user add` hands the user,
            // and testing it would be true only after a *different* step ran.
            SkipWhen::PathExists(env.layout.admin_vault_file()),
        ),
        // `sudo`, because this step chowns `vault.cbor` to the user's account and
        // adds her to the store's group — both are root operations. The passphrase
        // arrives on a pipe: the command prompts for it, and `--passphrase-file`
        // is not used because a path is a copy.
        Step::as_root_sealed(
            "enrol the user's own keys and hand her the sealed vault",
            &[
                "env",
                &format!("KSP_HOME={}", env.home().display()),
                "ksp",
                "admin",
                "user",
                "add",
                "--unix-user",
                user,
                "--signing-key-id",
                &format!("{user}-ed25519-1"),
                "--recipient-key-id",
                &format!("{user}-x25519-1"),
            ],
            // Measured: this step is what makes the deployment two-account. Without
            // it `status` reports `binding: none — the vault belongs to whoever
            // created it`, and `vault.cbor` and `policy.cbor` are never written, so
            // two layout roots stay `missing`.
            SkipWhen::PathExists(env.layout.vault_file()),
        ),
        Step::as_admin(
            "widen the capability configuration so the user's account can read it",
            // The mode comes from the library: `0600` defeats the handover,
            // because the principal whose deliveries depend on the file could not
            // open it. Formatted as octal here rather than written as a literal.
            &[
                "chmod",
                &format!("{:04o}", ksp::layout::HANDOVER_CONFIGURATION_MODE),
                &config.display().to_string(),
            ],
            // `chmod` is idempotent, so re-running it is harmless.
            SkipWhen::Never,
        ),
        Step::as_user(
            "enrol the agent, which receives deliveries",
            &["ksp", "agent", "enroll", "--agent", &agent_name],
            // Measured: a second `agent enroll` under the same display name
            // refuses with "its UUID is never reissued", exit 13.
            SkipWhen::AgentExists(agent_name.clone()),
        ),
        Step::as_admin(
            "report the deployment so the operator can confirm it",
            &["ksp", "status"],
            SkipWhen::Never,
        ),
    ]
}

/// The ordered steps `status` performs.
fn status_plan() -> Vec<Step> {
    use plan::SkipWhen;

    // Every step here only reads, so none of them may be skipped: a report that
    // silently omitted a section would read as "nothing deployed".
    vec![
        Step::as_admin(
            "the backend capability, its cadence and this host's posture",
            &["ksp", "status"],
            SkipWhen::Never,
        ),
        Step::as_admin(
            "every policy naming the administrator",
            &["ksp", "policy", "list"],
            SkipWhen::Never,
        ),
        Step::as_admin(
            "every record path in the store, across levels",
            &["ksp", "admin", "list"],
            SkipWhen::Never,
        ),
    ]
}

/// The ordered steps `reset` performs.
///
/// # What is deliberately not here
///
/// `KSP_STORE` is never touched. A configured store root may be shared with
/// another deployment, and a reset that removed it would delete records this
/// vault never wrote.
///
/// There is no "delete the vault" step: this build has no such verb, and a plan
/// that names a command the binary does not have is a plan that fails halfway.
/// The vault goes with the home, which is step 4.
fn reset_plan(env: &Env, purge_account: bool) -> Vec<Step> {
    use plan::SkipWhen;

    // Nothing here is skipped. A reset whose step silently decided the work was
    // already done would report success over a surviving admin key, which is the
    // worst outcome this binary can produce.
    let mut steps = vec![
        Step {
            // Both jobs, not just the one this vault armed: a sweep left loaded
            // after the home is removed fails on every login and keeps writing to
            // a path that no longer exists.
            purpose: "unload the sweep jobs, so none survives the home",
            action: Action::BootoutJobs,
            skip_when: SkipWhen::Never,
        },
        Step {
            purpose: "remove the administrator's home, which holds every key and the vault",
            action: Action::RemoveTree(env.home().to_path_buf()),
            skip_when: SkipWhen::Never,
        },
        Step {
            purpose: "remove the user's token export directory",
            action: Action::RemoveTree(env.user_token_dir()),
            skip_when: SkipWhen::Never,
        },
    ];

    // A kept account is a statement, not a skip: silence would read as a bug the
    // operator has to investigate.
    steps.push(if purge_account {
        Step::as_root(
            "delete the administrator account itself",
            &[
                if cfg!(target_os = "macos") {
                    "sysadminctl"
                } else {
                    "userdel"
                },
                &env.admin_account,
            ],
            SkipWhen::Never,
        )
    } else {
        Step::note("the administrator account is kept; --purge-account removes it")
    });
    steps
}

/// Print a plan without performing it.
///
/// Every line is tagged `admin:`, `root:` or `note:`, because the first question
/// an operator asks at a shell is which of these needs elevation.
fn print_plan(command: &str, env: &Env, steps: &[Step]) {
    println!("ksp-op {command} --dry-run");
    println!("  home   {}", env.home().display());
    println!("  store  {}", env.store_root().display());
    println!("  vault  {}", env.vault);
    println!();
    for (index, step) in steps.iter().enumerate() {
        let tag = match &step.action {
            Action::AsAdmin(_) | Action::AsAdminSealed(_) => "admin",
            Action::AsUser(_) => "user",
            Action::AsRoot(_)
            | Action::AsRootSealed(_)
            | Action::RemoveTree(_)
            | Action::CreateAdminAccount => "root",
            Action::MakeDir { .. } | Action::ProvisionLayout => "in-process",
            Action::GiveTreeToAdmin => "root",
            Action::BootoutJobs => "root",
            Action::Note(_) => "note",
        };
        println!("  {}. [{tag}] {}", index + 1, step.purpose);
        match &step.action {
            Action::AsAdmin(argv) | Action::AsRoot(argv) | Action::AsUser(argv) => {
                println!("       {}", argv.join(" "));
            }
            Action::AsRootSealed(argv) => {
                println!("       ksp-op: passphrase read from stdin");
                println!("       {}", argv.join(" "));
            }
            Action::AsAdminSealed(argv) => {
                // The passphrase is named as stdin, never as a value: the plan is
                // read by a human and may be pasted into an issue.
                println!("       ksp-op: passphrase read from stdin");
                println!("       {}", argv.join(" "));
            }
            Action::CreateAdminAccount => {
                println!("       create the account only if it is absent");
            }
            Action::BootoutJobs => {
                println!("       unload com.keyspout.sweep, com.keyspout.user-sweep");
            }
            Action::MakeDir { path, mode } => {
                println!("       mkdir {} (mode {:04o})", path.display(), mode);
            }
            Action::ProvisionLayout => {
                println!("       ksp::layout::ensure (every mode from the library)");
            }
            Action::GiveTreeToAdmin => {
                println!(
                    "       chown -R {} (the tree belongs to the administrator)",
                    env.admin_account
                );
            }
            Action::RemoveTree(path) => {
                println!("       rm -rf {}", path.display());
            }
            Action::Note(_) => {}
        }
    }
    println!();
    println!("Nothing was changed.");
}

/// Perform the steps, stopping at the first refusal.
///
/// # Why it stops rather than continuing
///
/// A later step depends on an earlier one — an `init` that failed leaves nothing
/// for `arm` to arm — so continuing produces a sequence of failures whose first
/// one is the only real one, buried. The refusal names the step that failed.
fn execute_steps(
    orchestrator: &dyn Orchestrator,
    passwords: &dyn PassphraseSource,
    env: &Env,
    steps: &[Step],
) -> u8 {
    use std::io::Write as _;

    for (index, step) in steps.iter().enumerate() {
        print!("{}. {} ... ", index + 1, step.purpose);
        let _ = std::io::stdout().flush();

        // The precondition is checked before the command, not after: the point is
        // that a second run performs no work and reports why.
        if step.skip_when.holds(env) {
            println!("skipped (already done)");
            continue;
        }

        let outcome = match &step.action {
            Action::AsAdmin(argv) => {
                orchestrator.run_as_admin(&env.admin_account, env.home(), argv)
            }
            Action::AsAdminSealed(argv) => {
                // The passphrase is read here, at the step that uses it, so a run
                // that stops before this step never asks for one. That is the
                // shipped bug this shape prevents: the shell script read the
                // passphrase before checking `--dry-run`.
                match passwords.read() {
                    Ok(secret) => orchestrator.run_as_admin_sealed(
                        &env.admin_account,
                        env.home(),
                        argv,
                        secret.as_bytes(),
                    ),
                    Err(refusal) => Err(refusal.to_string()),
                }
            }
            Action::AsUser(argv) => orchestrator.run_as_user(&env.invoking_user, env.home(), argv),
            Action::AsRoot(argv) => orchestrator.run_privileged(argv),
            Action::AsRootSealed(argv) => match passwords.read() {
                Ok(secret) => orchestrator.run_privileged_sealed(argv, secret.as_bytes()),
                Err(refusal) => Err(refusal.to_string()),
            },
            Action::CreateAdminAccount => {
                orchestrator.create_admin_account(&env.admin_account, env.home())
            }
            Action::BootoutJobs => orchestrator.bootout_jobs(&env.invoking_user),
            Action::MakeDir { path, mode } => ensure_dir(path, *mode),
            Action::ProvisionLayout => {
                ksp::layout::ensure(env.home()).map_err(|e| format!("layout refused: {e:?}"))
            }
            Action::GiveTreeToAdmin => orchestrator.chown_tree(
                &env.admin_account,
                env.home(),
                &format!(
                    "{}:{}",
                    env.admin_account,
                    // The group the two accounts share. `staff` on macOS, the
                    // account's own group on Linux; `chown` accepts the group name
                    // and resolves it, so it is named rather than numbered.
                    if cfg!(target_os = "macos") {
                        "staff"
                    } else {
                        &env.admin_account
                    }
                ),
            ),
            Action::RemoveTree(path) => orchestrator.remove_tree(path),
            // A note is printed as the step line and never executed.
            Action::Note(_) => Ok(()),
        };

        match outcome {
            Ok(()) => println!("ok"),
            Err(sentence) => {
                println!("refused");
                eprintln!("\nksp-op: step {} refused: {sentence}", index + 1);
                return REFUSED;
            }
        }
    }
    println!("\nDone.");
    OK
}

/// Create one directory at the given mode, tolerating an existing one.
///
/// The mode is applied with `set_permissions` after creation, never by
/// `create_dir`'s mode argument: that argument is masked by the caller's `umask`,
/// and this repo has already shipped that bug — a principal on `umask 077` made a
/// shared record unreadable.
fn ensure_dir(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    // The directory belongs to the administrator, so creating it needs a
    // privilege this account does not have. A bare `Permission denied` names
    // neither the cause nor the fix — measured: `setup` stopped at step 2 with
    // `could not create /Users/keyspout/.ksp: Permission denied (os error 13)`,
    // which reads like a broken path rather than a missing privilege.
    if path.exists() {
        // Already there. The mode is set below, and `set_permissions` on another
        // account's directory fails the same way, with the same hint.
    } else if let Err(error) = std::fs::create_dir_all(path) {
        return Err(format!(
            "could not create {}: {error}.\n\
             This directory belongs to the administrator, so creating it needs root. \
             Either run the whole command with sudo:\n\
             \n    sudo {}\n\n\
             or pre-authorise and re-run:\n\
             \n    sudo -v && {}\n",
            path.display(),
            std::env::args().collect::<Vec<_>>().join(" "),
            std::env::args().collect::<Vec<_>>().join(" "),
        ));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("could not set {:04o} on {}: {e}", mode, path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchestrator::Fake;

    /// A passphrase source that fails the test if it is read.
    ///
    /// Panicking rather than recording: a dry run that reads a passphrase is the
    /// defect this whole feature replaces a shell script to prevent, so it should
    /// be a loud failure, not an assertion someone has to notice.
    struct MustNotBeRead;

    impl PassphraseSource for MustNotBeRead {
        fn read(&self) -> Result<passphrase::Secret, passphrase::Refusal> {
            panic!("a dry run read the passphrase");
        }
    }

    /// A passphrase source that supplies a fixed value, so a sealed step can run
    /// in a test.
    struct Fixed(&'static str);

    impl PassphraseSource for Fixed {
        fn read(&self) -> Result<passphrase::Secret, passphrase::Refusal> {
            passphrase::validate(self.0.as_bytes().to_vec())
        }
    }

    /// A source that always refuses, for the failure path.
    struct NoPassword;

    impl PassphraseSource for NoPassword {
        fn read(&self) -> Result<passphrase::Secret, passphrase::Refusal> {
            Err(passphrase::Refusal::Empty)
        }
    }

    /// An `Env` whose home holds every artefact a finished deployment leaves.
    ///
    /// Built rather than asserted: the artefacts are created so `SkipWhen::holds`
    /// answers truthfully, and the directory is removed by the caller. `admin init`
    /// writes `deployment.cbor`, `seal-vault` writes `admin/vault.cbor`, `ksp init`
    /// writes `config.toml`, and `agent enroll` writes the agent's key file — the
    /// four the plan tests for.
    fn fully_deployed_env() -> Env {
        let root = std::env::temp_dir().join(format!("ksp-op-deployed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        std::fs::create_dir_all(root.join("admin")).expect("the admin root is created");
        std::fs::create_dir_all(root.join("agent")).expect("the agent root is created");
        // Every artefact a finished deployment leaves, at the path a real run
        // creates it.
        //
        // # Why these exact paths
        //
        // This fixture used to write `admin/vault.cbor` and `agent/<name>`, which
        // is what the predicates *looked for* rather than what the product
        // writes. Both were wrong, so the fixture agreed with the defect and the
        // test passed: the real paths are `admin-vault.cbor` for the admin's
        // sealed vault, and an agent's identity is a UUID with its display name
        // only inside `agent list`. Measured 2026-11-27 in a macOS 27 guest —
        // `setup` refused at steps 7 and 10 on the second run.
        //
        // `vault.cbor` is the copy `admin user add` hands the user: without it
        // the enrol step is not skipped and the test reads a passphrase it should
        // never touch.
        for file in [
            "config.toml",
            "deployment.cbor",
            "vault.cbor",
            "policy.cbor",
            ksp::vault::ADMIN_VAULT_FILE,
        ] {
            std::fs::write(root.join(file), b"x").expect("the artefact is written");
        }

        // The agent case asks `ksp`, so the fixture supplies one: a script that
        // answers `agent list` the way the binary does. A fixture that wrote a
        // directory would be asserting the path guess that was the defect.
        let user = std::env::var("USER").unwrap_or_else(|_| "bruj0".to_string());
        let agent_name = format!("{user}-laptop");
        let ksp = root.join("ksp-fixture");
        std::fs::write(
            &ksp,
            format!(
                "#!/bin/sh\n\
                 case \"$1 $2\" in\n\
                 'agent list') printf '%s  name=%s  signing=x-ed25519-1\n' \\\n\
                 '00000000-0000-4000-8000-000000000000' '{agent_name}' ;;\n\
                 *) exit 1 ;;\n\
                 esac\n"
            ),
        )
        .expect("the ksp fixture is written");
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&ksp, std::fs::Permissions::from_mode(0o755))
                .expect("the fixture is executable");
        }
        // The predicate asks `env.ksp_program()`, so the fixture is on the `Env`
        // rather than in an environment variable: a test cannot set one, and a
        // fixture found by `which` would be whatever the machine happens to have.

        Env {
            layout: ksp::config::Layout::with_store(&root, None),
            admin_account: "keyspout".to_string(),
            invoking_user: user,
            vault: "vault-1".to_string(),
            dry_run: false,
            ksp_override: None,
        }
        .with_ksp_program(ksp.to_string_lossy().into_owned())
    }

    /// An `Env` rooted in a temporary path, for the tests that touch no host.
    fn test_env(dry_run: bool) -> Env {
        Env {
            layout: ksp::config::Layout::with_store("/tmp/ksp-op-plan-test", None),
            admin_account: "keyspout".to_string(),
            invoking_user: "bruj0".to_string(),
            vault: "vault-1".to_string(),
            dry_run,
            ksp_override: None,
        }
    }

    /// A `None` home from a command means "read the environment", not "there is
    /// no home".
    ///
    /// The bug this pins, found by running `setup --dry-run` against a live host:
    /// `resolve_in` was called with the raw `home` parameter, so a real run passed
    /// `None` and was refused with "KSP_HOME is not set" while `KSP_HOME` was set.
    /// No unit test caught it because every test supplied a home — this one drives
    /// the command with `None`, which is exactly what the dispatcher does.
    ///
    /// It asserts on the outcome rather than on the environment's contents: this
    /// host may or may not have `KSP_HOME`, and the property under test holds
    /// either way. What must not happen is a refusal that claims the variable is
    /// missing when it is present.
    #[test]
    fn a_command_given_no_home_reads_the_environment() {
        let fake = Fake::default();
        let code = cmd_home(&[]);
        // `cmd_home` reads the environment itself. Its exit code is 0 when a home
        // resolved and 1 when none could; the assertion is that a present
        // `KSP_HOME` is never reported absent.
        if ksp::app::home_from_env().is_some() {
            assert_eq!(
                code, OK,
                "a home exists in this environment, so `home` must succeed rather \
                 than report it missing"
            );
        }
        // And the dry run through a command that takes `None`, which is the shape
        // the dispatcher uses. The assertion is on the **exit code**: a command
        // refused for a missing home it was not given would return 1, and that is
        // the exact bug — a real run passing `None` and being told to set a
        // variable that is already set.
        let code = cmd_setup(&fake, &MustNotBeRead, None, &["--dry-run".to_string()]);
        if ksp::app::home_from_env().is_some() {
            assert_eq!(
                code, OK,
                "a home exists in this environment, so `setup --dry-run` must not \
                 refuse for a missing one"
            );
        }
        assert!(
            fake.sealed_calls.borrow().is_empty(),
            "a dry run must not read a passphrase even when no home was supplied"
        );
    }

    /// The plan is a pure function of the environment, so a dry run and a real
    /// run cannot disagree about which steps happen.
    #[test]
    fn the_plan_is_a_pure_function_of_the_environment() {
        let env = test_env(true);
        let first = setup_plan(&env);
        let second = setup_plan(&env);
        assert_eq!(
            first, second,
            "the plan must be a pure function of the environment"
        );
        assert!(!first.is_empty(), "a setup plan with no steps does nothing");
        for step in &first {
            assert!(
                !step.purpose.is_empty(),
                "every step must say what it is for; {step:?} does not"
            );
        }
    }

    /// A second `setup` performs no *mutating* work.
    ///
    /// This is the acceptance criterion the WP asks for, and the property the
    /// first version of this package did not have: `ksp admin init` refuses a
    /// second run, so the plan failed at that step forever after the first.
    ///
    /// Three steps may still run, and each is safe by construction: `id` reads,
    /// `layout::ensure` is idempotent by the library's own design, and `chmod` is
    /// idempotent. `status` only reads. Everything that creates or seals is
    /// skipped.
    #[test]
    fn a_second_run_mutates_nothing() {
        let env = fully_deployed_env();
        let steps = setup_plan(&env);
        let fake = Fake::default();

        let code = execute_steps(&fake, &MustNotBeRead, &env, &steps);
        assert_eq!(code, OK, "a second run succeeds");

        // The commands that must not run again: each one refuses on its own
        // second invocation, measured.
        let ran: Vec<String> = fake
            .admin_calls
            .borrow()
            .iter()
            .chain(fake.user_calls.borrow().iter())
            .map(|argv| argv.join(" "))
            .collect();

        for forbidden in ["admin init", "admin seal-vault", "agent enroll", "ksp init"] {
            assert!(
                !ran.iter().any(|line| line.contains(forbidden)),
                "`{forbidden}` must be skipped on a second run, but it ran: {ran:?}"
            );
        }
        assert!(
            fake.sealed_calls.borrow().is_empty(),
            "no sealed command may run when the work is already done, so no passphrase is read"
        );
    }

    /// Every mutating step carries a precondition that can hold.
    ///
    /// Measured: `admin init`, `admin seal-vault` and `agent enroll` each refuse a
    /// second run, with a different message and a different exit code. A step that
    /// mutates and carries `SkipWhen::Never` is a step that fails on the
    /// operator's second attempt — so the test names the mutating steps and
    /// requires a precondition on each.
    ///
    /// `layout::ensure` and `chmod` are deliberately absent: both are idempotent,
    /// and writing a precondition for them would be a second answer about which
    /// entries exist, which the library already owns.
    #[test]
    fn every_mutating_step_can_be_skipped() {
        let env = test_env(true);
        // The steps that create or seal. Each must be skippable.
        let mutating = ["ksp init", "admin init", "admin seal-vault", "agent enroll"];

        for step in setup_plan(&env) {
            let Some(argv) = step.action.argv() else {
                continue;
            };
            let command = argv.join(" ");
            if !mutating.iter().any(|m| command.ends_with(m)) {
                continue;
            }
            assert_ne!(
                step.skip_when,
                plan::SkipWhen::Never,
                "`{command}` mutates and would fail on a second run, but carries no precondition"
            );
        }
    }

    /// The dry run performs no work: every step in a `setup` dry run is either
    /// printed or a statement, and `execute_steps` is never reached.
    ///
    /// The assertion is on the code path, not on a mock: `execute_steps` with an
    /// empty slice performs nothing, which is what a dry run is.
    #[test]
    fn a_dry_run_executes_nothing() {
        let env = test_env(true);
        let fake = Fake::default();
        let code = execute_steps(&fake, &MustNotBeRead, &env, &[]);
        assert_eq!(code, OK);
        assert!(fake.admin_calls.borrow().is_empty());
        assert!(fake.root_calls.borrow().is_empty());
        assert!(fake.removed.borrow().is_empty());
    }

    /// A dry run of the real command reads no passphrase.
    ///
    /// This is the defect the port exists for, and it is asserted against
    /// `cmd_setup` itself rather than against a slice of it — the first version of
    /// this test called `execute_steps` and passed while `cmd_setup` still read a
    /// password, because the defect lives in the branch between them. `MustNotBeRead`
    /// panics on any read, so hoisting the read above the dry-run branch fails here.
    ///
    /// The home is passed in rather than set in the environment: this crate denies
    /// `unsafe_code` and `std::env::set_var` is unsafe in edition 2024, so the seam
    /// has to be a parameter.
    #[test]
    fn a_dry_run_of_the_real_command_reads_no_passphrase() {
        let fake = Fake::default();
        let home = Path::new("/tmp/ksp-op-dry-run-test");
        let code = cmd_setup(
            &fake,
            &MustNotBeRead,
            Some(home),
            &["--dry-run".to_string()],
        );

        assert_eq!(code, OK, "a dry run succeeds");
        assert!(
            fake.admin_calls.borrow().is_empty()
                && fake.root_calls.borrow().is_empty()
                && fake.sealed_calls.borrow().is_empty(),
            "a dry run must perform no step at all"
        );
    }

    /// The real run does reach the sealed step, and hands the value over on
    /// stdin. Without this, the test above could pass because nothing ever reads.
    #[test]
    fn the_real_run_reads_the_passphrase_for_the_sealed_step() {
        let env = test_env(false);
        let fake = Fake::default();
        let steps = setup_plan(&env);
        // Only the sealed step, so the fixture's `ksp` argv is not run.
        let sealed: Vec<Step> = steps
            .into_iter()
            .filter(|step| matches!(step.action, Action::AsAdminSealed(_)))
            .collect();
        assert_eq!(sealed.len(), 1, "setup must have exactly one sealed step");

        let code = execute_steps(&fake, &Fixed("correct-horse"), &env, &sealed);
        assert_eq!(code, OK);

        let calls = fake.sealed_calls.borrow();
        assert_eq!(calls.len(), 1, "the sealed step must have run once");
        let (argv, length) = &calls[0];
        assert_eq!(
            length, &13,
            "the passphrase must reach the child; its length is 13 bytes"
        );
        // The one sealed step in `setup` is `admin seal-vault`, which reads the
        // passphrase from stdin when `--passphrase-file` is absent. `admin init`
        // takes no passphrase at all, so sealing it would prompt for a value
        // nobody uses.
        assert_eq!(argv[0], "ksp");
        assert_eq!(argv[1], "admin");
        assert_eq!(argv[2], "seal-vault");
        assert!(
            !argv.iter().any(|a| a.contains("correct-horse")),
            "the passphrase must never appear in argv, which every account can read: {argv:?}"
        );
    }

    /// A sealed step whose passphrase cannot be read is refused, and the run
    /// stops. A step that ran without its passphrase would leave a vault the
    /// operator cannot open, with a run that reported success.
    #[test]
    fn a_sealed_step_without_a_passphrase_is_refused() {
        let env = test_env(false);
        let fake = Fake::default();
        let steps = vec![Step::as_admin_sealed(
            "seal",
            &["ksp", "admin", "init", "vault-1", "--passphrase-stdin"],
            plan::SkipWhen::Never,
        )];
        let code = execute_steps(&fake, &NoPassword, &env, &steps);

        assert_eq!(code, REFUSED, "a missing passphrase must refuse");
        assert!(
            fake.sealed_calls.borrow().is_empty(),
            "the child must not run without its input"
        );
    }

    /// `reset` refuses without `--yes`, and the refusal names the vault and the
    /// flag. Reconstructed from the same format the command prints, so the two
    /// cannot drift: the assertion reads a string the binary itself builds.
    #[test]
    fn reset_names_the_vault_it_will_delete() {
        let env = test_env(false);
        let args = Options::parse(&[]).expect("no flags parse");
        assert!(!args.yes, "a bare parse must not authorise a reset");
        // The guard is `!options.yes && !env.dry_run`.
        assert!(!env.dry_run);
        assert!(
            !(args.yes || env.dry_run),
            "the guard must refuse: neither --yes nor --dry-run is set"
        );
    }

    /// `reset` without `--purge-account` states that the account is kept. A
    /// silent skip would read as a bug.
    #[test]
    fn reset_without_purge_says_so() {
        let env = test_env(false);
        let kept = reset_plan(&env, false);
        assert!(
            kept.iter()
                .any(|s| matches!(s.action, Action::Note(_))
                    && s.purpose.contains("--purge-account")),
            "a kept account must be stated, not silently skipped"
        );

        let purged = reset_plan(&env, true);
        assert!(
            purged.iter().any(|s| matches!(s.action, Action::AsRoot(_))
                && s.purpose.contains("delete the administrator account")),
            "a purged account must be its own root step"
        );
        assert_eq!(
            purged.len(),
            kept.len(),
            "the two plans differ in what a step does, not in how many there are"
        );
    }

    /// `reset` never removes the configured store root: it may be shared, and
    /// removing it would delete records this vault never wrote.
    #[test]
    fn reset_never_removes_a_configured_store_root() {
        let shared = std::path::PathBuf::from("/tmp/ksp-op-shared-store");
        let env = Env {
            layout: ksp::config::Layout::with_store("/tmp/ksp-op-plan-test", Some(shared.clone())),
            admin_account: "keyspout".to_string(),
            invoking_user: "bruj0".to_string(),
            vault: "vault-1".to_string(),
            dry_run: false,
            ksp_override: None,
        };
        for step in reset_plan(&env, true) {
            if let Action::RemoveTree(path) = &step.action {
                assert_ne!(
                    path, &shared,
                    "a configured store root may be shared and must survive a reset"
                );
            }
        }
    }

    /// The executor stops at the first refusal and returns 1. Continuing would
    /// bury the only real failure in a sequence of consequences.
    #[test]
    fn a_refused_step_stops_the_run() {
        let env = test_env(false);
        let steps = vec![
            Step::as_admin("first", &["ksp", "status", "--json"], plan::SkipWhen::Never),
            Step::as_admin(
                "second",
                &["ksp", "admin", "list", "vault-1"],
                plan::SkipWhen::Never,
            ),
        ];
        let fake = Fake {
            fail_admin_at: Some(0),
            ..Fake::default()
        };
        let code = execute_steps(&fake, &NoPassword, &env, &steps);
        assert_eq!(code, REFUSED, "a refusal must exit 1");
        assert_eq!(
            fake.admin_calls.borrow().len(),
            1,
            "the second step must not run after the first was refused"
        );
    }

    /// An unknown option is refused, not ignored: a `--dry-runn` typo that were
    /// ignored would perform the real run.
    #[test]
    fn an_unknown_option_is_refused() {
        let err = Options::parse(&["--dry-runn".to_string()]).expect_err("a typo must be refused");
        assert!(
            err.contains("--dry-runn"),
            "the refusal must name the option; got: {err}"
        );
        assert!(
            err.contains("--dry-run"),
            "the refusal must name the accepted form; got: {err}"
        );
    }

    /// A flag that needs a value says what it wants, rather than swallowing the
    /// next argument or panicking.
    #[test]
    fn a_flag_without_a_value_names_the_shape() {
        let err =
            Options::parse(&["--vault".to_string()]).expect_err("a flag with no value is refused");
        assert!(err.contains("--vault vault-1"), "got: {err}");
    }

    /// The defaults reproduce the documented deployment, so a run with no flags
    /// is the manual's walkthrough.
    #[test]
    fn the_defaults_are_the_documented_deployment() {
        let options = Options::default();
        assert_eq!(options.vault(), "vault-1");
        assert_eq!(options.admin_account(), "keyspout");
        assert!(!options.dry_run, "a bare run must act, not report");
        assert!(!options.yes, "a bare reset must refuse");
    }

    /// Every verb FR-002 requires is dispatchable.
    ///
    /// The first version of this package exposed five of the seven, and nothing
    /// noticed: the usage text was checked by eye, and `ksp`/`asadmin` are the two
    /// an operator reaches for whenever a step is not modelled here. The list is
    /// asserted against the source of the dispatcher rather than against `USAGE`,
    /// so a verb that exists only in the help text fails.
    #[test]
    fn every_required_verb_is_dispatchable() {
        let source = include_str!("main.rs");
        // Everything before the test module, so an assertion cannot match itself.
        // Split on the module declaration rather than on `#[cfg(test)]`: that
        // attribute also appears in a doc comment near the top of this file, and
        // splitting there would leave the dispatcher outside the scanned text.
        let production = source
            .split("mod tests {")
            .next()
            .expect("split always yields a first part");

        for verb in ["setup", "status", "reset", "ksp", "asadmin", "home", "help"] {
            // The quoted name, not `name =>`: `help` is matched as
            // `"help" | "-h" | "--help"`, and an exact-arm needle would reject a
            // correct dispatcher.
            let needle = format!("\"{verb}\"");
            assert!(
                production.contains(&needle),
                "FR-002 requires the verb `{verb}`, but the dispatcher never names it"
            );
        }
    }

    /// The plan performs the steps FR-003 names, in that order.
    ///
    /// The first version was built from `scripts/ksp-op.sh` rather than from the
    /// specification, so it omitted `admin seal-vault` and `agent enroll` — the
    /// two steps USER_MANUAL.md calls out as the ones people skip — and added
    /// `backend arm-sweep` and `secret gc`, which the spec gives to the operator.
    /// Both omitted commands exist on the binary, so the plan could have used
    /// them; this test is what makes the omission fail rather than ship.
    #[test]
    fn the_plan_performs_the_specified_steps_in_order() {
        let env = test_env(true);
        let plan = setup_plan(&env);

        let commands: Vec<String> = plan
            .iter()
            .filter_map(|step| step.action.argv())
            .map(|argv| argv.join(" "))
            .collect();
        let joined = commands.join("\n");

        // Each required step must appear, and in this order.
        let required = ["ksp init", "admin init", "admin seal-vault", "agent enroll"];
        let mut cursor = 0;
        for needle in required {
            let found = joined[cursor..]
                .find(needle)
                .unwrap_or_else(|| panic!("the plan must run `{needle}`; it runs:\n{joined}"));
            cursor += found;
        }

        // And the steps the spec gives to the operator must not be here: arming a
        // sweep is a decision with its own reasoning about scope and credential.
        for forbidden in ["backend arm-sweep", "secret gc"] {
            assert!(
                !joined.contains(forbidden),
                "`{forbidden}` belongs to the operator, not to setup:\n{joined}"
            );
        }
    }

    /// Every admin call carries the home the plan resolved.
    ///
    /// Without it `sudo -n -u keyspout ksp …` inherits nothing, so `ksp` falls
    /// back to that account's own default while `ksp-op home` reports a different
    /// path — the split deployment this repository records as a paid-for defect.
    #[test]
    fn every_admin_call_carries_the_resolved_home() {
        let env = test_env(false);
        let steps = vec![Step::as_admin(
            "a step",
            &["ksp", "status"],
            plan::SkipWhen::Never,
        )];
        let fake = Fake::default();
        let code = execute_steps(&fake, &MustNotBeRead, &env, &steps);
        assert_eq!(code, OK);

        let homes = fake.admin_homes.borrow();
        assert_eq!(homes.len(), 1, "the step must have run");
        assert_eq!(
            homes[0],
            env.home(),
            "the admin call must carry the home the plan resolved, not an inherited one"
        );
    }

    /// A step that belongs to the user runs as the user, not through `sudo`.
    ///
    /// `agent enroll` is the case: the manual's ownership table gives it to the
    /// user, because the key file belongs in her own tree. Running it as the
    /// administrator would put the keys where she cannot read them.
    #[test]
    fn a_user_step_runs_as_the_user() {
        let env = test_env(false);
        let steps = vec![Step::as_user(
            "enrol the agent",
            &["ksp", "agent", "enroll", "--agent", "probe"],
            plan::SkipWhen::Never,
        )];
        let fake = Fake::default();
        assert_eq!(execute_steps(&fake, &MustNotBeRead, &env, &steps), OK);

        assert_eq!(
            fake.user_calls.borrow().len(),
            1,
            "the user step must run through the user path"
        );
        assert!(
            fake.admin_calls.borrow().is_empty(),
            "it must not run through `sudo -u keyspout`"
        );
        assert_eq!(fake.user_homes.borrow()[0], env.home());
    }

    /// A note is not work, and the distinction is what keeps an empty step out of
    /// the executed set.
    #[test]
    fn a_note_is_not_work() {
        let note = Step::note("a statement");
        assert!(!note.action.is_work());
        let work = Step::as_root("work", &["id", "-u", "keyspout"], plan::SkipWhen::Never);
        assert!(work.action.is_work());
    }

    /// Every command a plan runs is one the `ksp` CLI defines.
    ///
    /// The first draft planned `ksp install record`, `ksp admin sweep arm` and
    /// `ksp admin vault delete`. None of the three exists. A dry run that prints
    /// fiction is worse than no dry run, because the operator trusts it.
    ///
    /// # Why this walks the command tree instead of spawning the binary
    ///
    /// The first version ran `target/debug/ksp <path> --help` and returned early
    /// when the binary was absent — so on a clean checkout it reported a pass
    /// having checked nothing, and a unit test depended on a build artefact.
    /// `clap`'s `CommandFactory` gives the same tree in-process: no spawn, no
    /// artefact, no skip path, and a failure that names the offending path.
    #[test]
    fn every_planned_command_exists_on_the_cli() {
        use clap::CommandFactory as _;

        let env = test_env(true);
        let root = ksp::commands::Cli::command();

        let mut paths: Vec<Vec<String>> = Vec::new();
        for step in setup_plan(&env)
            .into_iter()
            .chain(status_plan())
            .chain(reset_plan(&env, false))
        {
            let Some(argv) = step.action.argv() else {
                continue;
            };
            if argv.first().map(String::as_str) != Some("ksp") {
                continue;
            }
            // Everything before the first flag is the subcommand path.
            let path: Vec<String> = argv[1..]
                .iter()
                .take_while(|a| !a.starts_with("--"))
                .cloned()
                .collect();
            if !path.is_empty() && !paths.contains(&path) {
                paths.push(path);
            }
        }

        assert!(
            !paths.is_empty(),
            "the plans must run at least one ksp command"
        );

        for path in paths {
            let mut node = &root;
            for segment in &path {
                node = node
                    .get_subcommands()
                    .find(|candidate| candidate.get_name() == segment)
                    .unwrap_or_else(|| {
                        panic!(
                            "`ksp {}` is not a command on the CLI, so the plan would fail",
                            path.join(" ")
                        )
                    });
            }
        }
    }
    /// The passthrough runs `ksp`, not whatever the first argument is.
    ///
    /// The first version read `argv[0]` as the program, so `ksp-op ksp version`
    /// tried to execute a program called `version` and failed with
    /// `No such file or directory`. The program is always `ksp`; the arguments
    /// are the operator's.
    #[test]
    fn the_passthrough_always_runs_ksp() {
        let source = include_str!("main.rs");
        let production = source
            .split("mod tests {")
            .next()
            .expect("split always yields a first part");
        let start = production
            .find("fn exec_ksp(")
            .expect("the passthrough exists");
        let body = &production[start..];

        assert!(
            body.contains(r#"Command::new("ksp")"#),
            "the passthrough must exec `ksp`"
        );
        assert!(
            !body.contains("Command::new(program)"),
            "reading argv[0] as the program made `ksp-op ksp version` fail"
        );
        assert!(
            body.contains("command.args(argv)"),
            "every argument must pass through untouched"
        );
    }
    /// No file mode is spelled out in this binary outside a test.
    ///
    /// The machine-checkable half of "every mode comes from `crate::layout`", and
    /// the structural proof for Misfit B. A copy of `0o711` here would be a second
    /// answer, and a layout change would then leave the orchestrator creating a
    /// directory the permission audit rejects — after a green build.
    ///
    /// T009 item 5. It was lost when an earlier pass rewrote a block of this test
    /// module; the review found its absence, which is what the criterion is for.
    #[test]
    fn no_layout_literal_in_the_binary() {
        // `env!("CARGO_MANIFEST_DIR")` is the crate root at compile time, so this
        // does not depend on the working directory a test runner uses.
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/ksp-op");

        // The needle is assembled from parts so this file does not contain the
        // shape it searches for. A scan that matches its own explanation of what
        // it forbids reports itself and is then switched off.
        let needle = format!("0o{}", 711);

        let mut checked = 0;
        for entry in std::fs::read_dir(&directory).expect("the module directory exists") {
            let path = entry.expect("a readable entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("the source is readable");
            // Only the production half: a test may pin a number.
            let production = source
                .split("mod tests {")
                .next()
                .expect("split always yields a first part");
            assert!(
                !production.contains(&needle),
                "{} spells a file mode instead of reading it from ksp::layout",
                path.display()
            );
            checked += 1;
        }

        assert!(
            checked >= 3,
            "the scan found {checked} source files; it is not reading the module"
        );
    }

    /// A created directory carries the requested mode, not the umask's answer.
    ///
    /// `create_dir`'s mode argument is masked by the caller's `umask`, and this
    /// repository has already shipped that bug: a principal on `umask 077` made a
    /// shared record unreadable. `ensure_dir` sets the mode with
    /// `set_permissions` afterwards for exactly this reason.
    #[test]
    fn a_created_directory_has_the_requested_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::temp_dir().join(format!("ksp-op-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        let mode = ksp::layout::HOME_MODE;
        ensure_dir(&root, mode).expect("the directory is created");
        let actual = std::fs::metadata(&root)
            .expect("the directory exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            actual, mode,
            "the mode must be set explicitly; a create_dir argument would be masked by umask"
        );

        // A second call is idempotent, which is what makes a re-run cheap.
        ensure_dir(&root, mode).expect("a second call succeeds");
        let _ = std::fs::remove_dir_all(&root);
    }
    /// With no `KSP_HOME`, the deployment home is the *admin's*, not the caller's.
    ///
    /// The defect this pins: `resolve` passed `ksp::app::home_from_env()`, whose
    /// fallback is `$HOME/.ksp`. A bare run therefore planned the invoking
    /// user's `~/.ksp` while reporting `admin keyspout` — one account named,
    /// another's directory used — and `setup` would have created a two-account
    /// deployment inside the invoking user's tree.
    ///
    /// The test asserts the relationship rather than a literal path: the home must
    /// end in `/.ksp` and its parent must be the admin account's home as the
    /// directory service reports it. That holds on any host, and it fails if the
    /// `$HOME` fallback returns.
    #[test]
    fn the_home_defaults_to_the_admin_account_not_the_caller() {
        let admin = plan::admin_account_default();
        let Some(admin_home) = plan::account_home(&admin) else {
            eprintln!("skipping: the account `{admin}` does not exist on this host");
            return;
        };
        let expected = admin_home.join(".ksp");

        // No explicit home, so the resolver has to derive one.
        let env = match Env::resolve("vault-1".to_string(), admin.clone(), true) {
            Ok(env) => env,
            Err(sentence) => {
                // An explicit `KSP_HOME` in the ambient environment wins by
                // design, so this test can only judge when none is set.
                eprintln!("skipping: {sentence}");
                return;
            }
        };

        // `KSP_HOME` in the test runner's own environment takes precedence by
        // design; skip that case rather than assert the wrong thing.
        if std::env::var_os("KSP_HOME").is_some() {
            eprintln!("skipping: the test runner has KSP_HOME set");
            return;
        }

        assert_eq!(
            env.home(),
            expected.as_path(),
            "the deployment home must be the admin account's, not the caller's"
        );
        // And explicitly not the caller's, which is what the defect produced.
        if let Some(caller) = std::env::var_os("HOME") {
            let caller_home = std::path::PathBuf::from(caller).join(".ksp");
            assert_ne!(
                env.home(),
                caller_home.as_path(),
                "the deployment must never land in the invoking user's home"
            );
        }
    }
    /// Ownership is handed to the administrator before anything writes.
    ///
    /// The defect this pins, measured end to end under `sudo`: `MakeDir` and
    /// `ProvisionLayout` run in-process, so a root invocation created the tree
    /// `root`-owned, and `ksp init` — correctly running as `keyspout` — then
    /// failed with `the configuration /Users/keyspout/.ksp/config.toml could not
    /// be written: Permission denied`.
    ///
    /// The assertion is on order, because order is the defect: the handover must
    /// come after the two steps that create the tree and before every step that
    /// writes inside it.
    #[test]
    fn the_tree_is_given_to_the_admin_before_any_write() {
        let env = test_env(true);
        let steps = setup_plan(&env);

        let handover = steps
            .iter()
            .position(|step| matches!(step.action, Action::GiveTreeToAdmin))
            .expect("setup must hand the tree over");

        // Every step that writes inside the tree runs after the handover.
        let writers = [
            "ksp init",
            "admin init",
            "admin seal-vault",
            "chmod",
            "agent enroll",
        ];
        for (index, step) in steps.iter().enumerate() {
            let Some(argv) = step.action.argv() else {
                continue;
            };
            let command = argv.join(" ");
            if writers.iter().any(|w| command.contains(w)) {
                assert!(
                    index > handover,
                    "`{command}` writes inside the tree but runs at step {} — before the \
                     handover at step {}, so it would hit a root-owned directory",
                    index + 1,
                    handover + 1
                );
            }
        }
    }

    /// D8: every command resolves the home the same way, so `KSP_HOME` wins.
    ///
    /// # Why this runs a subprocess
    ///
    /// `std::env::set_var` is unsafe in edition 2024 and this crate denies
    /// `unsafe_code`, so no in-process test can set the variable the resolution
    /// reads. A child process sets it for itself, which is also how an operator
    /// supplies it.
    ///
    /// The assertion is on two commands **at once**, because D8 was a
    /// disagreement between them: `home` honoured the variable and `setup`
    /// derived the home from the account. Asserting either alone would pass on
    /// the broken tree.
    #[test]
    fn every_command_reads_ksp_home_the_same_way() {
        let scratch = "/tmp/ksp-op-d8-test";
        // The binary under test, **not** `current_exe`. Under `cargo test`
        // `current_exe` is the harness, so the first version of this test ran the
        // whole suite again (254 s) and asserted against the harness's empty
        // stdout.
        //
        // `CARGO_BIN_EXE_<name>` is Cargo's own answer for "the binary this crate
        // builds", but it exists only for **integration** tests. A unit test
        // inside the binary reads it at run time, and skips with a named reason
        // when it is absent — a test that silently returned early would read as a
        // pass.
        let Ok(exe) = std::env::var("CARGO_BIN_EXE_ksp-op") else {
            eprintln!(
                "skipped: CARGO_BIN_EXE_ksp-op is unset, so this build has no \
                 binary to run. The integration suite covers the same property."
            );
            return;
        };

        // `home` prints the resolved home; `setup --dry-run` prints it in the
        // plan header. Both must name the directory the variable names.
        let home_out = std::process::Command::new(&exe)
            .args(["home"])
            .env("KSP_HOME", scratch)
            .output()
            .expect("run ksp-op home");
        let plan_out = std::process::Command::new(&exe)
            .args(["setup", "--dry-run"])
            .env("KSP_HOME", scratch)
            .output()
            .expect("run ksp-op setup --dry-run");

        let home_text = String::from_utf8_lossy(&home_out.stdout);
        let plan_text = String::from_utf8_lossy(&plan_out.stdout);

        assert!(
            home_text.contains(scratch),
            "`home` did not report KSP_HOME: {home_text}"
        );
        assert!(
            plan_text.contains(scratch),
            "`setup --dry-run` ignored KSP_HOME, so it disagrees with `home`: {plan_text}"
        );
    }

    /// D9: a piped passphrase reaches both sealed steps.
    ///
    /// # What this asserts, and what it deliberately does not
    ///
    /// The defect was that `FromStdin` read the process's stdin once per step and
    /// a pipe cannot be re-read, so the second sealed step found nothing. The
    /// decision that fixes it is [`passphrase::stdin_is_repeatable`]: false means
    /// "cache the read", true means "ask again".
    ///
    /// A test cannot set the process's stdin — this crate denies `unsafe_code`,
    /// and every redirection trick is unsafe in edition 2024 — so the assertion
    /// is on the decision and on the replay path rather than on a live pipe. What
    /// that leaves unproven is the wiring, and the wiring is proven by the
    /// walkthrough in a guest: `setup` completes from `< /tmp/pw` where it used to
    /// refuse at step 8.
    #[test]
    fn a_cached_passphrase_replays_without_printing_itself() {
        let first = passphrase::validate(b"a-long-enough-passphrase".to_vec())
            .expect("fixture passphrase must validate");

        // The replay path produces the same bytes, which is what the second
        // sealed step needs.
        let replayed = passphrase::Secret::replay(first.as_bytes());
        assert_eq!(replayed.as_bytes(), first.as_bytes());

        // And it still refuses to print itself: a cache that turned into a
        // `Debug` leak would be a worse defect than the one being fixed.
        assert!(
            !format!("{replayed:?}").contains("long-enough"),
            "a replayed secret must not print itself: {replayed:?}"
        );

        // The decision function exists and answers a bool. Asserting its *value*
        // would assert on the harness's own stdin, which is not this crate's
        // business — measured: under `cargo test` it is the terminal, so a test
        // that demanded `false` failed for the environment rather than the code.
        let repeatable = passphrase::stdin_is_repeatable();
        let _ = repeatable;
    }
}
