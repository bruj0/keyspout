//! Dispatch: one parsed invocation to one outcome.
//!
//! A command that is recognised but not yet wired returns [`exit::INTERNAL`]
//! rather than success. A silent `0` for work that did not happen is the one
//! failure a CLI must never report, because every caller treats it as proof the
//! operation occurred.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::commands::{Cli, Command};
use crate::config::{self, Layout};
use crate::exit::{self, Outcome};
use crate::output::{Emitter, Report};
use crate::probe::{self, OverwritePolicy, ProbeSummary};
use crate::vault::{VaultHome, run as run_vault};

/// Where this host keeps its state.
///
/// `KSP_HOME` when set, otherwise `.ksp` under the working directory. The
/// variable names a directory, not a secret, so reading it is not a redaction
/// concern.
pub fn home_from_env() -> PathBuf {
    match std::env::var_os("KSP_HOME") {
        Some(value) => PathBuf::from(value),
        None => PathBuf::from(".ksp"),
    }
}

/// Run one invocation.
pub fn dispatch(cli: &Cli, home: &Path) -> Outcome {
    match &cli.command {
        Command::Version => {
            // The version is not a secret and carries no state.
            let _ = writeln!(std::io::stdout(), "ksp {}", env!("CARGO_PKG_VERSION"));
            Outcome::Success
        }
        Command::Status => {
            let layout = Layout::new(home.to_path_buf());
            let mut emitter = Emitter::new(cli.json, std::io::stdout());
            run_status(&layout, &mut emitter)
        }
        Command::Init => {
            let layout = Layout::new(home.to_path_buf());
            let mut emitter = Emitter::new(cli.json, std::io::stdout());
            run_probe(&layout, &mut emitter, OverwritePolicy::IfAbsent)
        }
        Command::Config { command } => match command {
            crate::commands::ConfigCommand::Init { force } => {
                let layout = Layout::new(home.to_path_buf());
                let mut emitter = Emitter::new(cli.json, std::io::stdout());
                // The policy is chosen here and nowhere else: both verbs share
                // one probe, and the only thing that differs is this answer.
                let policy = if *force {
                    OverwritePolicy::Replace
                } else {
                    OverwritePolicy::IfAbsent
                };
                run_probe(&layout, &mut emitter, policy)
            }
        },
        Command::Vault { command } => {
            let vault_home = VaultHome::new(home.to_path_buf());
            match command {
                crate::commands::VaultCommand::Rekey { threshold, shares } => {
                    let password = match crate::admin::read_password(&mut std::io::stdin()) {
                        Ok(password) => password,
                        Err(error) => return Outcome::Failed(error.exit_code()),
                    };
                    let mut emitter = Emitter::new(cli.json, std::io::stdout());
                    match crate::vault::rekey(&vault_home, &password, *threshold, *shares) {
                        Ok(phrase) => {
                            let report = Report::RecoveryPhrase(crate::output::RecoveryView {
                                phrase: phrase.render(),
                                threshold: phrase.threshold().0,
                                shares: phrase.shares().len(),
                            });
                            match emitter.report(&report) {
                                Ok(()) => Outcome::Success,
                                Err(_) => Outcome::Failed(exit::INTERNAL),
                            }
                        }
                        Err(error) => {
                            let _ = emitter.refusal(&error.to_string());
                            Outcome::Failed(error.exit_code())
                        }
                    }
                }
                other => {
                    let mut emitter = Emitter::new(cli.json, std::io::stdout());
                    run_vault(other, &vault_home, &mut emitter)
                }
            }
        }
        Command::Agent { command } => {
            let layout = Layout::new(home.to_path_buf());
            let mut emitter = Emitter::new(cli.json, std::io::stdout());
            match command {
                crate::commands::AgentCommand::Enroll { agent } => {
                    match crate::agent::enroll(agent, &layout) {
                        Ok(enrolled) => {
                            let report = Report::Identity(crate::output::PublicIdentity {
                                identity: format!("agent:{}", enrolled.enrolment.identity),
                                signing_key: crate::agent::hex(
                                    &enrolled.enrolment.signing_key.to_bytes(),
                                ),
                                recipient_key: crate::agent::hex(
                                    &enrolled.enrolment.recipient_key.to_bytes(),
                                ),
                                signing_key_id: enrolled
                                    .enrolment
                                    .signing_key_id
                                    .as_str()
                                    .to_string(),
                                recipient_key_id: enrolled
                                    .enrolment
                                    .recipient_key_id
                                    .as_str()
                                    .to_string(),
                                fingerprint: crate::agent::hex(
                                    enrolled.enrolment.fingerprint.as_bytes(),
                                ),
                            });
                            match emitter.report(&report) {
                                Ok(()) => Outcome::Success,
                                Err(_) => Outcome::Failed(exit::INTERNAL),
                            }
                        }
                        Err(error) => {
                            let _ = emitter.refusal(&error.to_string());
                            Outcome::Failed(error.exit_code())
                        }
                    }
                }
                crate::commands::AgentCommand::Rotate {
                    agent,
                    signing_key_id,
                    recipient_key_id,
                } => {
                    let identity = ksp_types::AgentId::parse(agent)
                        .map_err(|_| crate::agent::AgentError::Identity(agent.clone()));
                    let identity = match identity {
                        Ok(identity) => identity,
                        Err(error) => return Outcome::Failed(error.exit_code()),
                    };
                    match crate::agent::rotate(
                        &identity,
                        &layout,
                        ksp_identity::KeyId::new(signing_key_id.clone()),
                        ksp_identity::KeyId::new(recipient_key_id.clone()),
                    ) {
                        Ok(rotated) => {
                            let report =
                                crate::output::Report::Identity(crate::output::PublicIdentity {
                                    identity: format!("agent:{}", agent),
                                    signing_key: crate::agent::hex(
                                        &rotated.enrolment.signing_key.to_bytes(),
                                    ),
                                    recipient_key: crate::agent::hex(
                                        &rotated.enrolment.recipient_key.to_bytes(),
                                    ),
                                    signing_key_id: rotated
                                        .enrolment
                                        .signing_key_id
                                        .as_str()
                                        .to_string(),
                                    recipient_key_id: rotated
                                        .enrolment
                                        .recipient_key_id
                                        .as_str()
                                        .to_string(),
                                    fingerprint: crate::agent::hex(
                                        rotated.enrolment.fingerprint.as_bytes(),
                                    ),
                                });
                            match emitter.report(&report) {
                                Ok(()) => Outcome::Success,
                                Err(_) => Outcome::Failed(exit::INTERNAL),
                            }
                        }
                        Err(error) => {
                            let _ = emitter.refusal(&error.to_string());
                            Outcome::Failed(error.exit_code())
                        }
                    }
                }
                other => crate::agent::run(other, &layout, &mut emitter),
            }
        }
        Command::Admin { command } => {
            let layout = Layout::new(home.to_path_buf());
            let mut emitter = Emitter::new(cli.json, std::io::stdout());
            run_admin(command, &layout, &mut emitter)
        }
        Command::Secret { command } => {
            let layout = Layout::new(home.to_path_buf());
            let mut emitter = Emitter::new(cli.json, std::io::stdout());
            run_secret(command, &layout, &mut emitter)
        }
        Command::Token { command } => {
            let layout = Layout::new(home.to_path_buf());
            let mut emitter = Emitter::new(cli.json, std::io::stdout());
            run_token(
                command,
                &layout,
                config::read_backend(&layout).ok(),
                &mut emitter,
            )
        }
        Command::Backend { command } => crate::backend::run(
            command,
            &Layout::new(home.to_path_buf()),
            &mut Emitter::new(cli.json, std::io::stdout()),
        ),
        Command::Audit {
            command,
            admin,
            principal,
            passphrase_file,
            limit,
            since,
        } => match command {
            Some(crate::commands::AuditCommand::Verify { head }) => crate::audit_verify::run(
                &Layout::new(home.to_path_buf()),
                crate::audit_verify::Verify { heads: head },
                &mut Emitter::new(cli.json, std::io::stdout()),
            ),
            None => {
                let mut emitter = Emitter::new(cli.json, std::io::stdout());
                // A window is measured from now, and a duration that will not
                // parse is the caller's mistake: it names the accepted forms
                // rather than defaulting to a window nobody asked for.
                let since = match since.as_deref().map(crate::audit_view::parse_since) {
                    None => None,
                    Some(Ok(secs)) => Some(crate::run::now_seconds() as i64 - secs as i64),
                    Some(Err(message)) => {
                        let _ = emitter.refusal(&message);
                        return Outcome::Failed(exit::USAGE);
                    }
                };
                crate::audit_view::run(
                    &Layout::new(home.to_path_buf()),
                    crate::audit_view::View {
                        as_admin: *admin,
                        principal: principal.as_deref(),
                        passphrase_file: passphrase_file.as_deref(),
                        filter: crate::audit_view::Filter {
                            limit: *limit,
                            since,
                        },
                    },
                    &mut emitter,
                )
            }
        },
        Command::Run(args) => crate::run::run(args, &Layout::new(home.to_path_buf())),
        Command::Deliver(args) => crate::deliver::run(args),
        // No catch-all: every parsed command is dispatched here, and the compiler
        // refusing an unreachable arm is what keeps a newly added command from
        // being wired to a silent success.
    }
}

/// Dispatch one `admin` subcommand.
///
/// The password is read from stdin and nowhere else: argv is world-readable in
/// the process table and lands in shell history (FR-044).
fn run_admin<W: Write>(
    command: &crate::commands::AdminCommand,
    layout: &Layout,
    emitter: &mut Emitter<W>,
) -> Outcome {
    use crate::commands::{AdminCommand, AdminUserCommand};
    match command {
        AdminCommand::Init {
            vault,
            user,
            key_id,
        } => match crate::admin::init(
            layout,
            ksp_types::VaultId::new(vault.clone()),
            user.clone(),
            ksp_identity::KeyId::new(key_id.clone()),
        ) {
            Ok(initialised) => {
                let report = Report::Anchor(crate::output::PinnedAnchor {
                    key_id: initialised.anchor.key_id.as_str().to_string(),
                    signing_key: crate::agent::hex(&initialised.anchor.key.to_bytes()),
                    principal: initialised.admin.to_string(),
                    user: initialised.user.to_string(),
                });
                report_or_internal(emitter, &report)
            }
            Err(error) => refused(emitter, error.exit_code(), &error.to_string()),
        },
        AdminCommand::User {
            command:
                AdminUserCommand::Add {
                    signing_key_id,
                    recipient_key_id,
                    unix_user,
                },
        } => {
            let password = match crate::admin::read_password(&mut std::io::stdin()) {
                Ok(password) => password,
                Err(error) => return refused(emitter, error.exit_code(), &error.to_string()),
            };
            match crate::admin::user_add(
                layout,
                &password,
                ksp_identity::KeyId::new(signing_key_id.clone()),
                ksp_identity::KeyId::new(recipient_key_id.clone()),
                unix_user.as_deref(),
            ) {
                Ok(principal) => report_or_internal(
                    emitter,
                    &Report::PrincipalIssued {
                        operation: "admin user add".to_string(),
                        principal: principal.to_string(),
                    },
                ),
                Err(error) => {
                    // The typed message, not only the class: FR-023 and FR-024
                    // refuse for reasons an operator has to read, and a code
                    // alone ("policy denied") names neither the account nor the
                    // claim that stopped it.
                    let _ = emitter.refusal(&error.to_string());
                    Outcome::Failed(error.exit_code())
                }
            }
        }
        AdminCommand::Put { id, name } => {
            let value = match crate::secret::read_value(&mut std::io::stdin()) {
                Ok(value) => value,
                Err(error) => {
                    // The typed message names the accepted form; a code alone
                    // told the caller nothing about its own pipeline.
                    let _ = emitter.refusal(&error.to_string());
                    return Outcome::Failed(error.exit_code());
                }
            };
            let secret = ksp_types::OpaqueSecretId::new(id.clone());
            match crate::admin::put(layout, &secret, name.as_bytes(), &value) {
                Ok(version) => {
                    // Administrative write, signed with the admin's key; the record
                    // is durable before the new version is named.
                    let target = match crate::deployment::require(layout) {
                        Ok((recorded, _anchor)) => Some(ksp_types::evidence::AuditTarget::Record {
                            vault: recorded.vault,
                            level: ksp_types::Level::Admin,
                            secret: secret.clone(),
                            version,
                        }),
                        Err(_) => None,
                    };
                    if let Err(refusal) = crate::audit::record_admin(
                        layout,
                        ksp_types::evidence::AuditComponent::CommandLine,
                        ksp_types::evidence::AuditOperation::Put,
                        target,
                        ksp_types::evidence::Outcome::Success,
                        exit::SUCCESS,
                    ) {
                        let _ = emitter.refusal(&refusal.to_string());
                        return Outcome::Failed(refusal.exit_code());
                    }
                    report_or_internal(
                        emitter,
                        &Report::Record(crate::output::RecordMetadata {
                            record: format!("admin/{}", secret.as_str()),
                            level: ksp_types::Level::Admin.path_segment(),
                            version,
                        }),
                    )
                }
                Err(error) => {
                    // The refusal is the entry that proves the control fired, so it
                    // is recorded before the refusal is printed.
                    let _ = crate::audit::record_admin(
                        layout,
                        ksp_types::evidence::AuditComponent::CommandLine,
                        ksp_types::evidence::AuditOperation::Put,
                        None,
                        ksp_types::evidence::Outcome::Failure,
                        error.exit_code(),
                    );
                    // "No key to seal to" and "the record could not be written"
                    // share an exit code, and a caller cannot act on the code
                    // alone.
                    let _ = emitter.refusal(&error.to_string());
                    Outcome::Failed(error.exit_code())
                }
            }
        }
        AdminCommand::List => match crate::admin::list(layout) {
            Ok(records) => report_or_internal(emitter, &Report::Records { records }),
            Err(error) => {
                let _ = emitter.refusal(&error.to_string());
                Outcome::Failed(error.exit_code())
            }
        },
        AdminCommand::Audit => match crate::admin::audit(layout) {
            Ok(view) => {
                // An entry this host cannot read or verify is a nonzero exit:
                // the command ran, and what it found is not substantiated.
                let outcome = report_or_internal(emitter, &Report::Audit(view.clone()));
                if view.unreadable > 0 && outcome.is_success() {
                    Outcome::Failed(exit::POLICY_DENIAL)
                } else {
                    outcome
                }
            }
            Err(error) => {
                let _ = emitter.refusal(&error.to_string());
                Outcome::Failed(error.exit_code())
            }
        },
        AdminCommand::Policy {
            agents,
            secrets,
            show,
        } => {
            // The read-back. It writes nothing and needs no admin key: the
            // policy is public material every principal reads, and a caller that
            // must hold the admin key to *see* what it may do cannot check a
            // grant it was told about.
            if *show {
                return match crate::admin::show_policy(layout) {
                    Ok(view) => report_or_internal(emitter, &Report::Policy(view)),
                    Err(error) => refused(emitter, error.exit_code(), &error.to_string()),
                };
            }
            // No password: the keys this policy names are public halves the
            // deployment recorded at enrolment (FR-020). Asking for the user's
            // password here made the admin depend on a secret only she has.
            let granted = match parse_agents(agents) {
                Ok(granted) => granted,
                Err(error) => {
                    let _ = emitter.refusal(&error.to_string());
                    return Outcome::Failed(error.exit_code());
                }
            };
            match crate::admin::policy(
                layout,
                granted,
                secrets.iter().map(ksp_types::OpaqueSecretId::new).collect(),
            ) {
                Ok(()) => report_or_internal(
                    emitter,
                    &Report::Confirmation {
                        operation: "admin policy".to_string(),
                    },
                ),
                Err(error) => refused(emitter, error.exit_code(), &error.to_string()),
            }
        }
        other => crate::admin::run(other, layout, emitter),
    }
}

/// Read the vault password from a file, or from stdin when none is named.
///
/// The password is never an argument and never an environment variable: argv is
/// in the process table and in shell history, and an environment variable is
/// inherited by every child, and beside the one command whose stdin carries the
/// value it cannot be stdin either. What appears is the *path* of a file the
/// operator already protects, and a path is not a secret.
///
/// # Why stdin is only read from a terminal
///
/// A read of stdin blocks until the stream closes or delivers. A terminal closes
/// when the operator presses Enter. A closed pipe delivers what it holds and then
/// ends. An **open** pipe that is never written to and never closed — which is
/// what a process supervisor hands a child by default — blocks forever, and the
/// command produces no exit code, no message and no evidence. A hang is the worst
/// failure shape available, so the guard refuses before the read rather than
/// waiting on a stream that cannot answer.
///
/// The refusal names `--passphrase-file`, because a caller that cannot type has
/// to be told the one way it can supply the password.
pub(crate) fn password(file: Option<&std::path::Path>) -> Result<Vec<u8>, i32> {
    match file {
        None => read_password_from_stdin(),
        Some(path) => {
            // A path, not a descriptor number: a descriptor is only inherited by
            // accident across the shells and wrappers a real invocation passes
            // through, and one that silently failed to arrive would read as a
            // wrong password. The password itself never appears in argv.
            let mut file = match std::fs::File::open(path) {
                Ok(file) => file,
                Err(_) => return Err(exit::MISSING_KEY),
            };
            crate::admin::read_password(&mut file).map_err(|error| error.exit_code())
        }
    }
}

/// How long a non-terminal stdin is given to deliver a password.
///
/// A pipe that already holds the password returns at once, because its writer has
/// closed. This bound only elapses for a stream that will never deliver anything,
/// so it costs a working caller nothing and caps the wait for a blocked one.
const STDIN_GRACE: std::time::Duration = std::time::Duration::from_millis(200);

/// Read the password from stdin, refusing rather than blocking forever.
///
/// # Why this is not a plain read
///
/// A read of stdin blocks until the stream closes or delivers. A terminal closes
/// when the operator presses Enter. A closed pipe delivers what it holds and then
/// ends. An **open** pipe that is never written to and never closed — which is
/// what a process supervisor hands a child by default — blocks forever, and the
/// command produces no exit code, no message and no evidence. A hang is the worst
/// failure shape available.
///
/// # Why a terminal check alone is not enough
///
/// `IsTerminal` says "is this a terminal", and a pipe carrying a password is not
/// one. Refusing every non-terminal would break the shape that worked before this
/// change: a caller that pipes the password and closes the pipe, which
/// `QUICKSTART.md` documents. The question is not "is this a terminal" but "will a
/// read return", so the read happens on a worker thread and the wait is bounded.
/// A pipe holding data returns at once; an open pipe does not return at all, and
/// the caller is told about `--passphrase-file` instead of being left waiting.
///
/// The worker thread is abandoned rather than joined when the bound elapses. It
/// holds nothing but a blocked read, and the process exits when this function's
/// caller returns, which ends it.
fn read_password_from_stdin() -> Result<Vec<u8>, i32> {
    use std::io::IsTerminal as _;
    if std::io::stdin().is_terminal() {
        // The operator types and presses Enter, so a blocking read is correct.
        return crate::admin::read_password(&mut std::io::stdin())
            .map_err(|error| error.exit_code());
    }

    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let outcome =
            std::io::Read::read_to_end(&mut std::io::stdin(), &mut buffer).map(|_| buffer);
        // A send failure means the receiver already gave up; nothing to report.
        let _ = sender.send(outcome);
    });

    match receiver.recv_timeout(STDIN_GRACE) {
        Ok(Ok(buffer)) => {
            // The same trimming and empty check a file read gets, so the two
            // sources cannot disagree about what a password is.
            crate::admin::read_password(&mut &buffer[..]).map_err(|error| error.exit_code())
        }
        // The stream did not deliver in time: an open pipe with nothing in it.
        // The caller renders `describe(MISSING_KEY)`, whose sentence names
        // `--passphrase-file`.
        Ok(Err(_)) | Err(_) => Err(exit::MISSING_KEY),
    }
}

/// Render the status disclosure: backend capability, posture, freshness.
///
/// # The posture is measured, not asserted
///
/// Applying a ruleset is the only way this build can learn what the kernel
/// enforces: S5 publishes a posture for an applied ruleset and for nothing else.
/// This process is confined from that moment and exits immediately after
/// printing, so nothing is launched under the measured ruleset.
///
/// Everything that reads the home is measured **before** the ruleset is applied.
/// The ruleset names system paths only, so a read afterwards fails with `EACCES`
/// and would be reported as an absent root or an unrecorded owner — `status`
/// reads the deployment and the layout record to name every level and its owner,
/// and it must do that while it can still open them.
///
/// # This is the *optional* posture
///
/// T013 keeps the two apart: a delivery needs confinement and refuses without it,
/// while `status` and a record write measure what they can get. Applying an
/// optional spec that this host cannot satisfy reports the shortfall; it does not
/// manufacture the delivery's refusal here.
///
/// The same host, measured by the *required* posture a delivery uses, may refuse.
/// `status` reports and exits zero; it never refuses, because an operator needs
/// the disclosure of a broken host far more than they need a second copy of the
/// refusal. The spec is therefore `optional`, and the report says
/// `SoftRequirement` — the line is a measurement of this host, not the policy a
/// delivery applies.
///
/// # The barrier is measured *before* the ruleset
///
/// FR-012 asks for exactly this order. Landlock denies by default once a right is
/// handled, so allocating afterwards could fail because of this command's own
/// confinement and be reported as "no barrier" on a host that has one — a false
/// negative about the host, produced by the measurement. The line describes a
/// region this command actually allocated, not the intent to allocate one.
/// `AllowFallback` is the preference the vault path uses, so a host demoted to the
/// sealed-memfd fallback says so here rather than looking equal to a host with
/// `memfd_secret`.
/// Probe this host, write the configuration if the policy allows, and report.
///
/// Both verbs land here; the only difference between them is the policy they
/// pass, which is chosen at the dispatch arm. Reporting an existing
/// configuration is a **success**: the host is configured, which is the state
/// the caller asked for, so a script that runs `ksp init` twice does not see a
/// failure on the second run.
///
/// A refusal is printed and exits with the code the crate uses for a file that
/// could not be written, because the failure is local to this host's filesystem
/// and is not one of the modelled refusals.
fn run_probe<W: Write>(
    layout: &Layout,
    emitter: &mut Emitter<W>,
    policy: OverwritePolicy,
) -> Outcome {
    let report = match probe::configure(layout, policy) {
        Ok(report) => report,
        Err(refusal) => {
            let _ = emitter.refusal(&refusal.to_string());
            // `INTERNAL`, not `CAPABILITY_REFUSAL`: code 7's published sentence
            // is about a lease the backend or the host layout cannot admit, and
            // a configuration that could not be written is neither. Reusing it
            // printed a true reason followed by a false one, and the false line
            // is the one a script reads.
            return Outcome::Failed(exit::INTERNAL);
        }
    };

    let summary = ProbeSummary::of(&report);
    if emitter.probe(&summary).is_err() {
        return Outcome::Failed(exit::INTERNAL);
    }
    Outcome::Success
}

fn run_status<W: Write>(layout: &Layout, emitter: &mut Emitter<W>) -> Outcome {
    // The capability configuration is read before any capability is touched
    // (T040, FR-003). A malformed or unsafe file refuses here, when nothing has
    // been established and nothing has to be undone — and the refusal names the
    // file and the key rather than surfacing later as a Landlock failure.
    //
    // Reading it does not depend on the capability it selects (NFR-005): the
    // reader parses two tables and knows nothing about Landlock, so a host that
    // cannot confine can still report why.
    let configuration = match crate::establish::load(layout) {
        Ok(configuration) => configuration,
        Err(refusal) => {
            let _ = emitter.refusal(&refusal.to_string());
            return Outcome::Failed(refusal.exit_code());
        }
    };

    let selection = match config::read_backend(layout) {
        Ok(selection) => selection,
        Err(_) => return Outcome::Failed(exit::INTERNAL),
    };
    // One clock reading for every age the document prints: two readings would let the
    // proof age and the admission decision disagree within one report.
    let now = i64::try_from(crate::run::now_seconds()).unwrap_or(i64::MAX);
    // Status reads the same classification admission reads, so the declared and the
    // proven cadence it prints cannot disagree with the answer a lease gets.
    let admission = match crate::admission::classify(layout, &selection, now) {
        Ok(admission) => admission,
        Err(_) => return Outcome::Failed(exit::CAPABILITY_REFUSAL),
    };
    let classification = &admission.classification;

    // The recorded schedule, the newest proof of each outcome and the audit head are
    // read before the probe confines this process for the same reason the layout is:
    // `audit/` is owner-only, and a read after Landlock would report an unreadable log
    // caused by this command's own ruleset.
    let (arming, proof, audit, binding) = compose_facts(layout, now);

    // The barrier is measured **before** the ruleset is applied. Landlock denies
    // by default once a right is handled, so allocating afterwards could fail
    // because of this command's own confinement and be reported as "no barrier"
    // on a host that has one.
    let (barrier, undumpable) = measure_barrier(configuration.as_ref());

    // The layout is measured before the probe confines this process: the level
    // rows and the recorded owners need the deployment and the layout record, and
    // a Landlock ruleset over the system paths denies every other read. Measuring
    // afterwards reported an ownerless, level-less table on a healthy home.
    let permissions =
        ksp_backend::status::PermissionDisclosure::new(crate::layout::audit(layout.root()));

    // The ruleset is the system paths only, not a run's full spec. `status` reads
    // no record and no key *after this point*, so naming the store and key root
    // would make the measurement depend on paths that may not exist yet — and a
    // missing path is not evidence about what the kernel enforces. What this line
    // reports is whether this host can confine a process to the system paths at
    // all.
    //
    // Through the selected adapter, so the posture names the mechanism that ran.
    // The mechanism alone leaves the ruleset unattributed, and a status line
    // reading `no adapter` on a host where Landlock is enforced is a false
    // statement about the host (FR-007).
    //
    // `optional`, not the configured level: this is the measurement posture
    // (T013). `status` reports what the host can do; the configured level is
    // applied by the command that needs the capability, and it is reported here
    // as its own line rather than folded into the measurement.
    let confinement = measure_confinement(configuration.as_ref());

    // No trusted checkpoint is held anywhere in this build, so a replayed older
    // policy would verify too. That is a fact to disclose, not a gap to paper
    // over with `Available`.
    // `permissions` was measured before the probe: a status line that named the
    // posture but not a widened key root would answer the confinement question
    // and skip the one that says whether the boundary is still there (FR-013,
    // FR-014).
    let report = ksp_backend::status::report(
        classification,
        ksp_backend::status::StatusFacts {
            arming,
            proof,
            audit,
            posture: ksp_backend::status::PostureDisclosure {
                confinement,
                barrier,
                undumpable,
            },
            capabilities: crate::establish::disclosures(configuration.as_ref()),
            freshness: ksp_backend::status::Freshness::RollbackDetectionUnavailable,
            canary: None,
            permissions,
            binding,
        },
    );
    match emitter.report(&Report::Status(Box::new(report))) {
        Ok(()) => Outcome::Success,
        Err(_) => Outcome::Failed(exit::INTERNAL),
    }
}

/// What the selected barrier adapter established, and the two dump controls it
/// applied, as `status` reports them.
///
/// The adapter is the one the configuration selected, so the line names the
/// mechanism that ran rather than one this build could have used. An
/// unconfigured capability establishes nothing and says so with no adapter
/// named — which is a different statement from a configured adapter the host
/// refused, and the capability disclosure beside it carries that difference.
///
/// The controls are read from the region the adapter produced, because that
/// region applied them. When no region was produced, this process applies them
/// itself: the answer is then about the host rather than about a barrier that
/// does not exist, and printing a control nobody applied would be the plausible
/// claim this work package exists to remove (FR-013).
fn measure_barrier(
    configuration: Option<&ksp_types::capability_config::CapabilityConfiguration>,
) -> (ksp_posture::BarrierPosture, ksp_posture::UndumpablePosture) {
    // A capability `status` cannot establish is *reported*, never fatal: the
    // command exists to say why (NFR-005), and exiting non-zero would deny the
    // operator the answer.
    let none = || {
        ksp_posture::BarrierPosture::unavailable(ksp_posture::MemlockObservation {
            soft_bytes: None,
            hard_bytes: None,
        })
    };
    let Ok(grant) =
        crate::establish::granted(configuration, ksp_types::HostCapability::MemoryBarrier)
    else {
        return (none(), ksp_posture::refuse_dumping());
    };
    let Some(adapter) = crate::establish::barrier(&grant) else {
        // Optional and nothing available: no adapter ran, so there is no
        // mechanism to name.
        return (none(), ksp_posture::refuse_dumping());
    };
    match adapter.allocate(32) {
        // `of` derives the adapter from the kind, so this names the mechanism
        // that allocated the region rather than only the kind it left behind.
        Ok(region) => (
            ksp_posture::BarrierPosture::of(region.kind(), region.observed_memlock()),
            region.undumpable().clone(),
        ),
        // The adapter ran and failed. The controls were therefore not applied by
        // it, so this process applies them and reports what the host allows.
        Err(_) => (none(), ksp_posture::refuse_dumping()),
    }
}

/// What the selected confinement adapter enforced, as `status` reports it.
fn measure_confinement(
    configuration: Option<&ksp_types::capability_config::CapabilityConfiguration>,
) -> ksp_posture::ConfinementPosture {
    let landlock = ksp_posture::LandlockObservation::of_this_host();
    let Ok(grant) =
        crate::establish::granted(configuration, ksp_types::HostCapability::PathConfinement)
    else {
        return ksp_posture::ConfinementPosture::unavailable(landlock, false);
    };
    let Some(adapter) = crate::establish::confinement(&grant) else {
        return ksp_posture::ConfinementPosture::unavailable(landlock, false);
    };

    let spec = ksp_posture::ConfinementSpec::optional(
        ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"]
            .into_iter()
            .map(std::path::Path::new)
            .filter(|path| path.is_dir())
            .map(ksp_posture::ConfinementRule::read_only),
    );
    match adapter.establish(&spec) {
        Ok(child) => child.applied().posture(),
        // The adapter ran and the kernel refused. Naming it is the difference
        // between "nothing tried" and "this tried, and this host cannot do it".
        Err(_) => ksp_posture::ConfinementPosture::declined(
            landlock,
            false,
            adapter.name(),
            adapter.guarantee(),
        ),
    }
}

/// The recorded schedule, the newest proof of each outcome and the audit head.
///
/// One composition for all three: `ksp status` is the only document, and a command
/// that built its own ad-hoc view of the same facts would be the second source of
/// truth the design bans. Nothing here decides anything — the capability comes from
/// the same admission classification a lease request reads.
fn compose_facts(
    layout: &Layout,
    now: i64,
) -> (
    ksp_backend::status::ArmingDisclosure,
    ksp_backend::status::ProofDisclosure,
    ksp_backend::status::AuditDisclosure,
    ksp_backend::status::BindingDisclosure,
) {
    use ksp_backend::status::{ArmingDisclosure, BindingDisclosure, ProofDisclosure};

    let (deployment, anchor) = match crate::deployment::require(layout) {
        Ok(found) => found,
        Err(error) => {
            // A home that was never provisioned is a known absence. A deployment file
            // that exists and cannot be read is not: the material is there and this
            // host cannot trust it, which is a different thing to look at.
            let cause = match error {
                crate::keys::PinError::Absent => "this host has no deployment",
                _ => "the deployment record could not be read as this host's",
            };
            return (
                ArmingDisclosure::None {
                    reason: format!("{cause}, so no schedule is recorded here"),
                },
                ProofDisclosure {
                    newest_success: None,
                    freshness: None,
                    absent_reason: Some(format!(
                        "{cause}, so there is no pinned key to verify a proof against"
                    )),
                    newest_failure: None,
                    malformed: 0,
                },
                audit_facts(layout),
                BindingDisclosure::None,
            );
        }
    };
    let binding = binding_facts(&deployment);
    let (deployment, anchor) = (&deployment, &anchor);

    let arming = match crate::admission::look_up_arming(layout, deployment, anchor) {
        crate::admission::ArmingLookup::Absent => ArmingDisclosure::None {
            reason: "no verified arming record names this deployment".to_string(),
        },
        crate::admission::ArmingLookup::Unknown { reason } => ArmingDisclosure::Unknown { reason },
        crate::admission::ArmingLookup::Recorded(arming) => ArmingDisclosure::Recorded {
            kind: arming.kind.label().to_string(),
            identifier: arming.identifier.clone(),
            declared_interval_secs: arming.interval_secs,
            recorded_at: arming.recorded_at,
            signer_key_id: arming.signer_key_id.clone(),
            // The query is *described*, never run and never consulted by the
            // admission path: this build records what the operator would ask.
            unit: ksp_backend::sweeper::ArmingQuery::for_kind(arming.kind),
        },
    };
    (
        arming,
        proof_facts(layout, deployment, anchor, now),
        audit_facts(layout),
        binding,
    )
}

/// Whether the recorded account still resolves on this host (FR-023).
///
/// The probe runs here rather than at enrolment because the finding is about the
/// host *now*: an account can be renamed, removed or replaced by a different uid
/// between the `user add` that recorded it and the `status` that reads it, and the
/// failure mode is a `chown` that silently lands on someone else. A home with no
/// recorded account is reported as unbound, not as verified-by-default.
fn binding_facts(
    deployment: &crate::deployment::Deployment,
) -> ksp_backend::status::BindingDisclosure {
    use ksp_backend::status::BindingDisclosure;

    let Some(account) = deployment.user_account.clone() else {
        return BindingDisclosure::None;
    };
    match crate::admin::unix_account(&account) {
        Ok((uid, _gid)) => BindingDisclosure::Verified { account, uid },
        Err(error) => BindingDisclosure::Unverified {
            account,
            reason: error.to_string(),
        },
    }
}

/// The newest successful and the newest failed run, from one gate.
fn proof_facts(
    layout: &Layout,
    deployment: &crate::deployment::Deployment,
    anchor: &crate::keys::Anchor,
    now: i64,
) -> ksp_backend::status::ProofDisclosure {
    use ksp_backend::proof::{FailedRun, ProofGate};
    use ksp_backend::status::{Observed, ProofDisclosure};

    let unknown = |reason: String| ProofDisclosure {
        newest_success: None,
        freshness: None,
        absent_reason: Some(reason),
        newest_failure: None,
        malformed: 0,
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&anchor.key.to_bytes()) else {
        return unknown(
            "the pinned admin key is not a valid key, so no proof can be verified".to_string(),
        );
    };
    let gate = ProofGate {
        directory: layout.sweeper_proofs_dir(),
        anchor: &key,
        scope: crate::admission::deployment_scope(deployment),
    };
    let malformed = gate.trouble();
    let (newest_success, freshness, absent_reason) = match gate.proved_run(now) {
        Ok(run) => {
            let age = run.observation.age;
            (
                Some(proof_record(&run.proof, age)),
                Some(run.observation.freshness()),
                None,
            )
        }
        Err(refusal) => (None, None, Some(refusal.to_string())),
    };
    let newest_failure = match gate.newest_failure() {
        Ok(Some(FailedRun::Verified(proof))) => Some(Observed::Known(proof_record(
            &proof,
            now.saturating_sub(proof.run_end),
        ))),
        // A failure that does not verify is not this deployment's report, and its
        // counts are exactly what an attacker would want an operator to read.
        Ok(Some(FailedRun::Unverified { reason })) => Some(Observed::Unknown { reason }),
        Ok(None) => None,
        // A directory this run cannot read might hold a failure: reporting "none"
        // would be the absent-versus-unreadable conflation this document exists to
        // stop, one line below the proof line that gets it right.
        Err(refusal) => Some(Observed::Unknown {
            reason: refusal.to_string(),
        }),
    };
    ProofDisclosure {
        newest_success,
        freshness,
        absent_reason,
        newest_failure,
        malformed,
    }
}

/// One signed proof, as disclosure prints it.
fn proof_record(
    proof: &ksp_backend::proof::SweepProof,
    age: i64,
) -> ksp_backend::status::ProofRecord {
    ksp_backend::status::ProofRecord {
        run_start: proof.run_start,
        run_end: proof.run_end,
        age_secs: age,
        declared_interval_secs: proof.declared_interval_secs,
        realised_interval_secs: proof.realised_interval_secs,
        removed: proof.removed,
        already_absent: proof.already_absent,
        not_yet_due: proof.not_yet_due,
        bound_reached: proof.bound_reached,
        error_codes: proof.error_codes.clone(),
        signer_key_id: proof.signer_key_id.clone(),
    }
}

/// Where the audit log ends, or why no head can be named.
fn audit_facts(layout: &Layout) -> ksp_backend::status::AuditDisclosure {
    use ksp_backend::status::{AuditChainHead, AuditDisclosure};

    let heads = crate::audit_verify::heads(layout);
    AuditDisclosure {
        chains: heads
            .chains
            .into_iter()
            .map(|head| AuditChainHead {
                chain: head.chain,
                digest: head.digest,
            })
            .collect(),
        records: heads.records,
        segments: heads.segments,
        unreadable: heads.unreadable,
        unattributed: heads.unattributed,
        broken: heads.broken,
        absent_reason: heads.reason,
    }
}

/// Run one sweep and print why it did not start when it did not.
///
/// The exit code alone cannot say whether the deployment is missing or the
/// backend could not be opened, and `main` prints only the generic sentence for
/// a code. The specific reason is printed here, before that one.
fn run_sweep<W: Write>(
    bound: ksp_backend::SweepBound,
    layout: &Layout,
    emitter: &mut Emitter<W>,
) -> Outcome {
    run_sweep_as(bound, layout, emitter, false, None)
}

/// Run a sweep as the admin, or as the user.
///
/// The two differ in who signs and who is named as the actor. A user sweep
/// writes no proof, because a proof is the admin's claim that a schedule was
/// kept.
fn run_sweep_as<W: Write>(
    bound: ksp_backend::SweepBound,
    layout: &Layout,
    emitter: &mut Emitter<W>,
    user_signed: bool,
    passphrase_file: Option<&std::path::Path>,
) -> Outcome {
    let result = crate::sweep::run_as(bound, layout, user_signed, passphrase_file);
    let code = match &result {
        // A run whose evidence did not land is a failure even when the removals
        // succeeded: no reader can see what it did.
        Ok(swept) => match &swept.proof {
            Err(error) => error.exit_code(),
            Ok(_) => crate::sweep::code(&swept.report),
        },
        Err(error) => error.exit_code(),
    };
    // A sweep run is recorded whether it removed anything, removed nothing or
    // failed: "the sweeper ran" is what the log has to be able to answer (FR-038).
    // Its own proof is the detailed statement; this is the chain entry.
    //
    // On a run that already failed the record is best effort. Refusing *again*
    // would replace the reason the sweep stopped — "this host has no deployment" —
    // with "the audit root is missing", and an operator chasing the second would
    // never find the first.
    let outcome = if code == exit::SUCCESS {
        ksp_types::evidence::Outcome::Success
    } else {
        ksp_types::evidence::Outcome::Failure
    };
    // Who signs the chain entry decides whose act the log records. A user sweep
    // is the user's act, and attributing it to the admin would be a false claim in
    // an attribution log — the same defect Misfit C names for the proof.
    let recorded = match user_signed {
        true => match password(passphrase_file)
            .map_err(|_code| crate::audit::AuditError::Keys)
            .and_then(|password| {
                crate::secret::unseal(layout, &password).map_err(|_| crate::audit::AuditError::Keys)
            }) {
            Ok(unsealed) => crate::audit::record_user(
                layout,
                &unsealed,
                ksp_types::evidence::AuditOperation::Sweep,
                None,
                outcome,
                code,
            ),
            // The vault would not open, so the entry cannot be signed by the user.
            // The sweep itself already failed for the same reason, and refusing
            // again would replace that reason.
            Err(_) => Ok(()),
        },
        false => crate::audit::record_admin(
            layout,
            ksp_types::evidence::AuditComponent::Sweeper,
            ksp_types::evidence::AuditOperation::Sweep,
            None,
            outcome,
            code,
        ),
    };
    // A sweep that failed has nothing to leave unlogged, so its own error is the one
    // to report; only a completed sweep needs its record to have landed.
    if result.is_ok()
        && let Err(refusal) = recorded
    {
        let _ = emitter.refusal(&refusal.to_string());
        return Outcome::Failed(refusal.exit_code());
    }
    match result {
        Ok(swept) => {
            let outcome = crate::sweep::outcome(&swept.report, emitter);
            match (&swept.proof, outcome) {
                (Err(error), _) => {
                    let _ = emitter.refusal(&error.to_string());
                    Outcome::Failed(error.exit_code())
                }
                (Ok(_), outcome) => outcome,
            }
        }
        Err(error) => {
            let _ = emitter.refusal(&error.to_string());
            Outcome::Failed(error.exit_code())
        }
    }
}

/// Dispatch one `secret` subcommand.
fn run_secret<W: Write>(
    command: &crate::commands::SecretCommand,
    layout: &Layout,
    emitter: &mut Emitter<W>,
) -> Outcome {
    use crate::commands::SecretCommand;
    match command {
        SecretCommand::Set {
            id,
            name,
            passphrase_file,
        } => {
            // The value comes from stdin; the password therefore cannot.
            let password = match password(passphrase_file.as_deref()) {
                Ok(password) => password,
                Err(code) => return Outcome::Failed(code),
            };
            let value = match crate::secret::read_value(&mut std::io::stdin()) {
                Ok(value) => value,
                Err(error) => {
                    // The typed message names the accepted form, and an empty
                    // value came back as "unexpected internal failure" with no
                    // reason at all.
                    let _ = emitter.refusal(&error.to_string());
                    return Outcome::Failed(error.exit_code());
                }
            };
            let secret = ksp_types::OpaqueSecretId::new(id.clone());
            // One unseal for both the write and its record: the tenant's own key
            // signs, and appending does not ask for a password the command did not
            // already hold (NFR-008).
            let unsealed = match crate::secret::unseal(layout, &password) {
                Ok(unsealed) => unsealed,
                Err(error) => return Outcome::Failed(error.exit_code()),
            };
            match crate::secret::set_with(layout, &unsealed, &secret, name.as_bytes(), &value) {
                Ok(version) => {
                    let target = Some(ksp_types::evidence::AuditTarget::Record {
                        vault: unsealed.vault_id.clone(),
                        level: ksp_types::Level::User,
                        secret: secret.clone(),
                        version,
                    });
                    // The record is durable before the success is printed: a record
                    // that cannot be written refuses the operation rather than
                    // letting an unlogged write stand (FR-044).
                    if let Err(refusal) = crate::audit::record_user(
                        layout,
                        &unsealed,
                        ksp_types::evidence::AuditOperation::Put,
                        target,
                        ksp_types::evidence::Outcome::Success,
                        exit::SUCCESS,
                    ) {
                        let _ = emitter.refusal(&refusal.to_string());
                        return Outcome::Failed(refusal.exit_code());
                    }
                    report_or_internal(emitter, &crate::secret::metadata_report(&secret, version))
                }
                Err(error) => {
                    // The refusal is recorded too: the entries that prove a control
                    // fired are the ones a successes-only log omits (Misfit U). The
                    // original failure stands — there is no effect to leave
                    // unlogged, so a second refusal would only hide the first.
                    let _ = crate::audit::record_user(
                        layout,
                        &unsealed,
                        ksp_types::evidence::AuditOperation::Put,
                        // No version: the write did not produce one, and `0` would
                        // be a record of a version that never existed.
                        None,
                        ksp_types::evidence::Outcome::Failure,
                        error.exit_code(),
                    );
                    let _ = emitter.refusal(&error.to_string());
                    Outcome::Failed(error.exit_code())
                }
            }
        }
        SecretCommand::Get {
            id,
            version,
            reveal,
            passphrase_file,
        } => {
            let password = match password(passphrase_file.as_deref()) {
                Ok(password) => password,
                Err(code) => return Outcome::Failed(code),
            };
            let secret = ksp_types::OpaqueSecretId::new(id.clone());
            match crate::secret::get(layout, &password, &secret, *version) {
                // A value has no route into `Report`, which is what keeps it out
                // of audit output. `get` writes it to stdout and nowhere else —
                // and only when `--reveal` asked for it, because stdout is a file
                // a shell redirects and a terminal scrolls back.
                //
                // The document is built here rather than as a `Report` variant
                // for that reason: a value with a route into `Report` is a value
                // in the log. `--json` still has to mean something, though — it
                // used to be accepted and ignored, so an agent that passed it and
                // parsed stdout got a tab-separated line.
                Ok((name, value)) => {
                    let shown = if *reveal {
                        value.as_slice()
                    } else {
                        crate::secret::REDACTED
                    };
                    let mut out = std::io::stdout();
                    let written = if emitter.is_json() {
                        let document = serde_json::json!({
                            "kind": "secret",
                            "record": id,
                            "name": String::from_utf8_lossy(&name),
                            "version": version,
                            "revealed": reveal,
                            "value": String::from_utf8_lossy(shown),
                        });
                        match serde_json::to_vec(&document) {
                            Ok(bytes) => out
                                .write_all(&bytes)
                                .and_then(|()| out.write_all(b"\n"))
                                .is_ok(),
                            Err(_) => false,
                        }
                    } else {
                        out.write_all(&name).is_ok()
                            && out.write_all(b"\t").is_ok()
                            && out.write_all(shown).is_ok()
                            && out.write_all(b"\n").is_ok()
                    };
                    if !written {
                        return Outcome::Failed(exit::INTERNAL);
                    }
                    let _ = emitter;
                    Outcome::Success
                }
                Err(error) => refused(emitter, error.exit_code(), &error.to_string()),
            }
        }
        SecretCommand::Rm {
            id,
            version,
            passphrase_file,
        } => {
            let password = match password(passphrase_file.as_deref()) {
                Ok(password) => password,
                Err(code) => return Outcome::Failed(code),
            };
            let secret = ksp_types::OpaqueSecretId::new(id.clone());
            match crate::secret::rm(layout, &password, &secret, *version) {
                Ok(()) => report_or_internal(
                    emitter,
                    &Report::Confirmation {
                        operation: format!("secret rm {} version {version}", secret.as_str()),
                    },
                ),
                Err(error) => refused(emitter, error.exit_code(), &error.to_string()),
            }
        }
        SecretCommand::Share {
            id,
            agent,
            name,
            ttl,
            uses,
            out,
            passphrase_file,
        } => {
            let password = match password(passphrase_file.as_deref()) {
                Ok(password) => password,
                Err(code) => return Outcome::Failed(code),
            };
            // The same gate the mint applies: a lease on a backend whose cleanup
            // this host cannot prove is refused, not written with a deadline nobody
            // enforces.
            let admission = match config::read_backend(layout)
                .map_err(|_| ())
                .and_then(|backend| {
                    crate::admission::classify(
                        layout,
                        &backend,
                        i64::try_from(crate::run::now_seconds()).unwrap_or(i64::MAX),
                    )
                    .map_err(|_| ())
                }) {
                Ok(admission) => admission,
                Err(()) => return Outcome::Failed(exit::CAPABILITY_REFUSAL),
            };
            let identity = match parse_agent(agent) {
                Ok(identity) => identity,
                Err(error) => {
                    let _ = emitter.refusal(&error.to_string());
                    return Outcome::Failed(error.exit_code());
                }
            };
            match crate::token::mint_lease(
                layout,
                &admission,
                &password,
                &identity,
                &ksp_types::OpaqueSecretId::new(id.clone()),
                name.as_bytes(),
                *ttl,
                *uses,
                out,
            ) {
                Ok(minted) => report_or_internal(
                    emitter,
                    &Report::Record(crate::output::RecordMetadata {
                        record: id.clone(),
                        level: ksp_types::Level::Agent(identity).path_segment(),
                        version: minted.version,
                    }),
                ),
                Err(error) => {
                    let _ = emitter.refusal(&error.to_string());
                    Outcome::Failed(error.exit_code())
                }
            }
        }
        SecretCommand::PurgeExpired { limit } => run_sweep(
            ksp_backend::SweepBound::Lazy { limit: *limit },
            layout,
            emitter,
        ),
        SecretCommand::Gc {
            user_arming,
            passphrase_file,
        } => run_sweep_as(
            ksp_backend::SweepBound::Batch,
            layout,
            emitter,
            *user_arming,
            passphrase_file.as_deref(),
        ),
        other => crate::secret::run(other, layout, emitter),
    }
}

/// Dispatch one `token` subcommand.
fn run_token<W: Write>(
    command: &crate::commands::TokenCommand,
    layout: &Layout,
    backend: Option<config::BackendSelection>,
    emitter: &mut Emitter<W>,
) -> Outcome {
    use crate::commands::TokenCommand;
    match command {
        TokenCommand::Mint {
            agent,
            secret,
            name,
            ttl,
            uses,
            out,
            passphrase_file,
        } => {
            let password = match password(passphrase_file.as_deref()) {
                Ok(password) => password,
                Err(code) => return Outcome::Failed(code),
            };
            // The configured backend, not one a token names. On `file` this is
            // `None` until a sweep proof proves the cadence, and the mint refuses
            // with 7 naming what it observed.
            let admission = match backend.as_ref().map(|backend| {
                crate::admission::classify(
                    layout,
                    backend,
                    i64::try_from(crate::run::now_seconds()).unwrap_or(i64::MAX),
                )
            }) {
                Some(Ok(admission)) => admission,
                _ => return Outcome::Failed(exit::CAPABILITY_REFUSAL),
            };
            let identity = match parse_agent(agent) {
                Ok(identity) => identity,
                Err(error) => {
                    let _ = emitter.refusal(&error.to_string());
                    return Outcome::Failed(error.exit_code());
                }
            };
            match crate::token::mint_lease(
                layout,
                &admission,
                &password,
                &identity,
                &ksp_types::OpaqueSecretId::new(secret.clone()),
                name.as_bytes(),
                *ttl,
                *uses,
                out,
            ) {
                Ok(minted) => report_or_internal(
                    emitter,
                    &Report::Record(crate::output::RecordMetadata {
                        record: secret.clone(),
                        level: ksp_types::Level::Agent(identity).path_segment(),
                        version: minted.version,
                    }),
                ),
                Err(error) => {
                    let _ = emitter.refusal(&error.to_string());
                    Outcome::Failed(error.exit_code())
                }
            }
        }
        other => crate::token::run(other, layout, emitter),
    }
}

/// Print a report, or report the failure to print it.
/// Parse one `--agent` flag.
///
/// The flag carries the agent's principal UUID. A display name is not an
/// identity and is refused with the canonical form named.
fn parse_agent(text: &str) -> Result<ksp_types::AgentId, crate::agent::AgentError> {
    crate::agent::parse_agent(text)
}

/// Parse every `--agent` flag of one command before any of them is acted on.
fn parse_agents(texts: &[String]) -> Result<Vec<ksp_types::AgentId>, crate::agent::AgentError> {
    texts.iter().map(|text| parse_agent(text)).collect()
}

/// Fail an operation, printing the typed reason before the class.
///
/// A code alone ("policy denied the operation") names neither the account, the
/// path nor the claim that stopped the work. Every command that has a typed
/// failure therefore prints it: the class is the contract, the sentence is the
/// instruction (FR-022, FR-023, FR-024).
fn refused<W: Write>(emitter: &mut Emitter<W>, code: i32, message: &str) -> Outcome {
    let _ = emitter.refusal(message);
    Outcome::Failed(code)
}

fn report_or_internal<W: Write>(emitter: &mut Emitter<W>, report: &Report) -> Outcome {
    match emitter.report(report) {
        Ok(()) => Outcome::Success,
        Err(_) => Outcome::Failed(exit::INTERNAL),
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use clap::Parser;

    fn parsed(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once(&"ksp").chain(args.iter())).unwrap()
    }

    #[test]
    fn version_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let outcome = dispatch(&parsed(&["version"]), dir.path());
        assert_eq!(outcome.code(), exit::SUCCESS);
    }

    #[test]
    fn vault_status_on_an_empty_home_reports_missing_key_material() {
        let dir = tempfile::tempdir().unwrap();
        let outcome = dispatch(&parsed(&["vault", "status"]), dir.path());
        assert_eq!(outcome.code(), exit::MISSING_KEY);
    }

    #[test]
    fn a_command_that_needs_provisioning_refuses_rather_than_succeeding() {
        // The failure this guards: a parsed command returning 0 tells a script
        // the operation succeeded when nothing ran. Every command is dispatched
        // now, so what has to hold is that an unprovisioned one names a refusal
        // instead of reporting success.
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            dispatch(&parsed(&["secret", "ls"]), dir.path()).code(),
            exit::MISSING_KEY,
            "an unprovisioned listing has no keys to read"
        );
        for args in [
            vec!["secret", "get", "s-1", "--reveal"],
            vec!["token", "inspect", "--token", "absent.token"],
            vec!["run", "--token", "absent.token", "--", "true"],
        ] {
            let code = dispatch(&parsed(&args), dir.path()).code();
            assert_ne!(code, exit::SUCCESS, "{args:?} reported success");
            assert_ne!(
                code,
                exit::INTERNAL,
                "{args:?} reported an unmapped failure"
            );
        }
    }

    #[test]
    fn the_home_is_taken_from_the_environment_when_set() {
        // Read-only: the test supplies the variable through the process
        // environment, which `std::env` exposes without a mutation.
        let value = std::env::var_os("KSP_HOME");
        let expected = match &value {
            Some(path) => PathBuf::from(path),
            None => PathBuf::from(".ksp"),
        };
        assert_eq!(home_from_env(), expected);
    }
}
