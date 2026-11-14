//! The command surface, fixed by the design specification.
//!
//! The tree is defined once, here, and every leaf accepts `--json` because a
//! caller that scripts `ksp` should never have to scrape text.
//!
//! The Phase 4 session-agent subcommands (`agent start`, `agent stop`,
//! `agent status`, `agent lock-timeout`) are **absent**, not hidden: they are out
//! of MVP scope, and a hidden command is one that still exists.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// The foreground `ksp` binary.
#[derive(Debug, Parser)]
#[command(
    name = "ksp",
    about = "A serverless, contract-based secret manager for agents",
    version
)]
pub struct Cli {
    /// Emit machine-readable JSON.
    #[arg(long, global = true)]
    pub json: bool,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// The top-level command groups.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Report what this host's backend can and cannot do, and its posture.
    ///
    /// Not a health check and never an erasure claim: every line is a
    /// disclosure, and a value this host cannot observe is printed as unknown.
    Status,
    /// Administer the deployment.
    Admin {
        /// The admin subcommand.
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Manage the vault.
    Vault {
        /// The vault subcommand.
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Manage agents.
    Agent {
        /// The agent subcommand.
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Manage tokens.
    Token {
        /// The token subcommand.
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Manage secrets.
    Secret {
        /// The secret subcommand.
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Run a child with a delivered secret.
    Run(RunArgs),
    /// Internal: confine this process and launch the child it is handed.
    ///
    /// Hidden rather than documented, and named so nobody types it by accident.
    /// It exists because a consume must deliver from a process that does *not*
    /// go on to delete: confinement is irreversible, so the deleter cannot be the
    /// confined one. The plaintext arrives on stdin and nothing about it appears
    /// in argv or in this process's environment.
    #[command(hide = true, name = "__deliver")]
    Deliver(DeliverArgs),
    /// Inspect the selected backend.
    Backend {
        /// The backend subcommand.
        #[command(subcommand)]
        command: BackendCommand,
    },
    /// Read the audit log, scoped to the caller's own view.
    ///
    /// The caller is whoever proves a pinned key: the tenant by opening its vault,
    /// the admin by loading the key its anchor pins. `--principal` selects a
    /// *subject* and never the caller, so it can narrow this view but never widen
    /// it.
    ///
    /// The tenant view needs the vault password. It is read from a terminal, or
    /// from the file named by `--passphrase-file`; a caller with neither is
    /// refused rather than left waiting on a stream that cannot answer.
    Audit {
        /// A subcommand. Without one, read the caller's scoped view.
        #[command(subcommand)]
        command: Option<AuditCommand>,
        /// Read the complete view, as the holder of the admin key.
        #[arg(long)]
        admin: bool,
        /// Show the records of one principal, by UUID.
        #[arg(long)]
        principal: Option<String>,
        /// Read the vault password from this file instead of stdin.
        ///
        /// The way to supply the password when there is no terminal to type at.
        /// A caller that pipes the password on stdin still works; a caller that
        /// leaves stdin open is refused, because an open pipe never delivers.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Emit at most this many record lines. `0` reads without a bound.
        ///
        /// A bound is the default because the log grows without limit, and a
        /// consumer asking "what happened recently" should not have to decode a
        /// year of records to answer. The header reports the total beside the
        /// emitted count, so a bounded view is never mistaken for a complete one.
        #[arg(long, default_value_t = crate::audit_view::DEFAULT_LIMIT)]
        limit: usize,
        /// Emit only records at or after this instant, as `<n><s|m|h|d>`.
        ///
        /// `30m`, `1h`, `7d`. The window is measured from now, and it filters by
        /// each record's own `observed_at`.
        #[arg(long)]
        since: Option<String>,
    },
    /// Print the version.
    Version,

    /// Probe this host and write its capability configuration.
    ///
    /// The first-run path. It never replaces a configuration that is already
    /// there: a host is configured once, and a second `ksp init` on the same
    /// host reports what exists and changes nothing.
    Init,

    /// Inspect and write the capability configuration.
    Config {
        /// The config subcommand.
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

/// A head digest in the form verification prints it: 64 hex characters.
///
/// Validated at the parser so a typo is a usage error, not a "head mismatch" that
/// sends an operator looking for a deleted tail.
fn head_digest(text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.len() == 64 && text.chars().all(|character| character.is_ascii_hexdigit()) {
        Ok(text.to_ascii_lowercase())
    } else {
        Err("a head digest is 64 hex characters, as `ksp audit verify` prints it".to_string())
    }
}

/// `ksp audit`.
#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Check every record against pinned public material.
    ///
    /// Read-only, no password, no private key: it works from a directory holding
    /// only the log and the pins.
    Verify {
        /// A head digest recorded outside the log, in hex; repeat for several chains.
        #[arg(long = "head", value_parser = head_digest)]
        head: Vec<String>,
    },
}

/// `ksp admin`.
#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Initialise the deployment: the admin's signing key.
    Init {
        /// The vault every record will live in.
        #[arg(long)]
        vault: String,
        /// The user whose records the vault holds.
        #[arg(long)]
        user: String,
        /// The ID to pin the admin key under.
        #[arg(long, default_value = "admin-2026")]
        key_id: String,
    },
    /// Administer users.
    User {
        /// The user subcommand.
        #[command(subcommand)]
        command: AdminUserCommand,
    },
    /// Re-sign the policy with the grants named here.
    Policy {
        /// Grant a delivery to this agent. Repeatable.
        #[arg(long = "agent")]
        agents: Vec<String>,
        /// Grant this secret. Repeatable.
        #[arg(long = "secret")]
        secrets: Vec<String>,
    },
    /// Put one version of a `user`-level secret. The value is read from stdin.
    ///
    /// No password: the record is sealed to the user's recorded recipient
    /// public key, which is enough to write and never enough to read.
    Put {
        /// The opaque record identifier.
        id: String,
        /// The record's name, encrypted with its value.
        #[arg(long)]
        name: String,
    },
    /// List every record path in this store, across levels.
    List,
    /// Read the acknowledgement journal and the signed reports beside it.
    Audit,
    /// Withdraw one grant: re-sign the policy without it, and record the decision.
    Revoke {
        /// The `user`-level secret that may no longer be shared.
        #[arg(long, conflicts_with = "agent")]
        secret: Option<String>,
        /// The agent that may no longer receive a `user`-level secret.
        #[arg(long, conflicts_with = "secret")]
        agent: Option<String>,
    },
}

/// `ksp admin user`.
#[derive(Debug, Subcommand)]
pub enum AdminUserCommand {
    /// Enrol a user: create her vault and sign a policy naming her keys.
    Add {
        /// The ID to enrol her Ed25519 key under.
        #[arg(long, default_value = "alice-ed25519-1")]
        signing_key_id: String,
        /// The ID to enrol her X25519 key under.
        #[arg(long, default_value = "alice-x25519-1")]
        recipient_key_id: String,
        /// The UNIX account the user principal runs as, when it is not the
        /// account that provisions the deployment.
        ///
        /// The vault is sealed to her keys and must then be *hers*: this names
        /// the account that will own `vault.cbor`, and the binding is recorded so
        /// a changed owner is reported rather than assumed. Omit it in the
        /// single-account layout, where the provisioning account is the user.
        #[arg(long = "unix-user")]
        unix_user: Option<String>,
    },
}

/// `ksp vault`.
#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// Create a vault.
    Init,
    /// Show the vault's state.
    ///
    /// There is no `unseal` and no `seal` here, and their absence is the
    /// decision rather than a gap. A command that unsealed a vault for a later
    /// invocation would leave a process holding the user's key on her behalf,
    /// which is the session agent NFR-001 and NFR-002 forbid: every operation on
    /// the secret path is a foreground invocation that exits. `secret get`,
    /// `secret set` and `token mint` each unseal inside their own process and
    /// let it end there.
    Status,
    /// Re-share the sealed vault: new recovery phrase, old phrase retired.
    ///
    /// The password does not change. What changes is the sharing of the sealed
    /// bundle, so a phrase written down before this command no longer
    /// reconstructs the vault that exists after it.
    Rekey {
        /// How many shares are needed to recover.
        #[arg(long, default_value_t = 2)]
        threshold: u8,
        /// How many shares the phrase states.
        #[arg(long, default_value_t = 3)]
        shares: u8,
    },
}

/// `ksp agent`, without the Phase 4 session subcommands.
#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    /// Enrol an agent: generate both keypairs and write its protected key file.
    Enroll {
        /// The agent identity.
        #[arg(long)]
        agent: String,
    },
    /// Print an agent's public keys.
    Pubkey {
        /// The agent identity.
        #[arg(long)]
        agent: String,
    },
    /// Rotate an agent's keys, retaining the previous bundle beside them.
    ///
    /// The new key IDs are named by the operator because they are how every
    /// policy and pin refers to the key: deriving them from a counter would
    /// collide on a second rotation, and reusing the old IDs would leave two
    /// different keys answering to one name. A rotation does not revoke an
    /// artifact already sealed to the old key — that copy still opens wherever
    /// the old private half is retained.
    Rotate {
        /// The agent identity.
        #[arg(long)]
        agent: String,
        /// The ID the new Ed25519 key is enrolled under.
        #[arg(long)]
        signing_key_id: String,
        /// The ID the new X25519 key is enrolled under.
        #[arg(long)]
        recipient_key_id: String,
    },
}

/// `ksp token`.
#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Mint a token: copy the record to the agent's level and seal it.
    Mint {
        /// The agent to deliver to.
        #[arg(long)]
        agent: String,
        /// The opaque record identifier to copy.
        #[arg(long)]
        secret: String,
        /// The record's name, re-encrypted into the agent-level copy.
        #[arg(long)]
        name: String,
        /// The lease, in seconds.
        #[arg(long, default_value_t = 900)]
        ttl: u64,
        /// How many deliveries the copy permits, when the sharer bounds it.
        #[arg(long)]
        uses: Option<u32>,
        /// Where to write the token.
        #[arg(long)]
        out: std::path::PathBuf,
        /// Read the vault password from this file.
        #[arg(long)]
        passphrase_file: Option<std::path::PathBuf>,
    },
    /// Lease a token over an agent-level version that already exists.
    ///
    /// Refused, with the reason: opening an existing agent-level record needs the
    /// content key that its envelope sealed to that agent, and unwrapping it here
    /// would be the key escrow the levels exist to prevent. A lease is produced
    /// from the source by `token mint` or `secret share`, which is why those take
    /// the user's password and this cannot.
    Lease,
    /// List the tokens this host minted.
    List,
    /// Inspect a token: scope, issuer and expiry, never a key or a value.
    Inspect {
        /// The token file to inspect.
        #[arg(long)]
        token: std::path::PathBuf,
    },
    /// Revoke a token identifier this host minted.
    Revoke {
        /// The token's opaque identifier, which is the `jti` its header carries.
        token_id: String,
    },
}

/// `ksp secret`.
#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// List secrets.
    Ls,
    /// Get a secret. Printed only to a terminal the user controls.
    Get {
        /// The opaque record identifier.
        id: String,
        /// The exact version to read.
        #[arg(long, default_value_t = 1)]
        version: u32,
        /// Print the value. Without this the value is redacted.
        ///
        /// The default is the redacted form because `get` writes to stdout, and
        /// stdout is a file a shell redirects, a terminal scrolls back and a
        /// paste buffer keeps. `run` is the surface that hands a value to a
        /// process without this ceremony.
        #[arg(long)]
        reveal: bool,
        /// Read the vault password from this file.
        #[arg(long)]
        passphrase_file: Option<std::path::PathBuf>,
    },
    /// Set a secret. The value is read from stdin, never from argv.
    Set {
        /// The opaque record identifier.
        id: String,
        /// The record's name, encrypted with its value.
        #[arg(long)]
        name: String,
        /// Read the vault password from this file. Required here because stdin
        /// carries the value.
        #[arg(long)]
        passphrase_file: Option<std::path::PathBuf>,
    },
    /// Remove one version of a secret.
    Rm {
        /// The opaque record identifier.
        id: String,
        /// The exact version to remove.
        #[arg(long, default_value_t = 1)]
        version: u32,
        /// Read the vault password from this file.
        #[arg(long)]
        passphrase_file: Option<std::path::PathBuf>,
    },
    /// Share a `user`-level secret with an agent: a leased copy, plus the token.
    ///
    /// The design spec names this command, and `token mint` is what performs it:
    /// a fresh content key, a separate agent-level record, and an artifact. One
    /// implementation, two names — "share this with deploy-bot" is what an
    /// operator says, and minting a lease is what the mechanism does.
    Share {
        /// The `user`-level secret to share.
        id: String,
        /// The agent that receives the copy.
        #[arg(long)]
        agent: String,
        /// The record's name, encrypted with its value.
        #[arg(long)]
        name: String,
        /// Lease length in seconds.
        #[arg(long, default_value_t = 1_200)]
        ttl: u64,
        /// How many deliveries the copy permits, when the sharer bounds it.
        ///
        /// A second bound beside the TTL: whichever is reached first removes the
        /// copy. It lives in the arm record, so it is armed before any token
        /// bytes exist and cannot be raised after signing.
        #[arg(long)]
        uses: Option<u32>,
        /// Where to write the token the agent holds.
        #[arg(long)]
        out: std::path::PathBuf,
        /// Read the vault password from this file.
        #[arg(long)]
        passphrase_file: Option<std::path::PathBuf>,
    },
    /// Remove versions whose armed deadline has passed, bounded.
    PurgeExpired {
        /// The most versions to remove in this invocation.
        ///
        /// Bounded on purpose: a foreground command on a large backlog stays
        /// predictable, and the next run continues from the same place. The
        /// limit counts removals, not records examined.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Remove every version whose armed deadline has passed.
    Gc {
        /// Sign this sweep with the user's enrolled key rather than the admin's.
        ///
        /// A user sweep removes the user's own copies and writes no proof: a
        /// proof is what admits a lease, and only the admin may make that claim.
        #[arg(long = "user-arming")]
        user_arming: bool,
        /// Read the vault password from this file, for a user sweep.
        #[arg(long)]
        passphrase_file: Option<std::path::PathBuf>,
    },
}

/// `ksp run`.
#[derive(Debug, Parser)]
pub struct RunArgs {
    /// The token file to run with.
    #[arg(long, conflicts_with = "agent")]
    pub token: Option<String>,
    /// Run as an enrolled agent.
    #[arg(long, conflicts_with = "token")]
    pub agent: Option<String>,
    /// Name the environment variable the child receives the secret in.
    ///
    /// A name, never a value: the value comes from the delivery, and passing one
    /// on the command line would put a secret in argv.
    #[arg(long, value_name = "NAME")]
    pub env: Option<String>,
    /// Deliver every secret the delivery names.
    #[arg(long)]
    pub env_all: bool,
    /// Consume the version: deliver, then delete the exact version, then report.
    #[arg(long)]
    pub consume: bool,
    /// The child command and its arguments.
    #[arg(last = true, required = true)]
    pub child: Vec<String>,
}

/// The delivery half of `ksp run --consume`.
#[derive(Debug, clap::Args)]
pub struct DeliverArgs {
    /// The environment variable the child receives the value in.
    #[arg(long, value_name = "NAME")]
    pub env: String,
    /// The level directory the record was read from: the one subtree the child
    /// may reach. Passed by the parent, which derived it from the bound metadata,
    /// so this process never has to trust a path it computed itself.
    #[arg(long, value_name = "PATH")]
    pub level: std::path::PathBuf,
    /// The child command and its arguments.
    #[arg(last = true, required = true)]
    pub child: Vec<String>,
}

/// `ksp config`.
///
/// The configuration surface. `init` is the only verb today, because the
/// probe is the only thing that writes the file: `ksp status` reads it and
/// never writes (FR-004, SC-001).
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Probe this host and write its capability configuration.
    ///
    /// Without `--force` it behaves as `ksp init` does: if a configuration
    /// already exists it is reported and left byte-for-byte unchanged.
    Init {
        /// Re-probe the host and replace an existing configuration.
        #[arg(long)]
        force: bool,
    },
}

/// `ksp backend`.
#[derive(Debug, Subcommand)]
pub enum BackendCommand {
    /// List the selectable backends.
    List,
    /// Test whether the selected backend admits a lease of this length.
    Test {
        /// The lease to test, in seconds. Defaults to a fifteen-minute delivery.
        #[arg(long)]
        ttl: Option<u64>,
    },
    /// Record one sweep schedule for the selected backend and scope.
    ///
    /// Records the schedule and prints what to install. Without `--install` it
    /// writes no unit, no property list, no crontab entry and calls no
    /// privileged helper: the operator installs. With `--install` it writes a
    /// launchd property list under this account's own home and loads it, and
    /// still runs no privileged helper: a system-wide target is refused rather
    /// than escalated to.
    ArmSweep {
        /// The kind of schedule: systemd, launchd, crontab, provider-lifecycle or
        /// external-job. Omitted, the backend's own default for this host is used:
        /// a systemd unit on Linux and a launchd property list on macOS.
        #[arg(long)]
        kind: Option<String>,
        /// How often the job is declared to run: 1h, 30m, 90s or seconds.
        #[arg(long)]
        interval: String,
        /// The store prefix the job sweeps.
        #[arg(long)]
        scope: String,
        /// The identity the armed job runs as.
        #[arg(long)]
        credential: String,
        /// One declared right and what it reaches, as <right>:<scope>. Repeatable.
        #[arg(long = "grant", required = true)]
        grants: Vec<String>,
        /// The unit or job name the operator installs under.
        #[arg(long)]
        identifier: Option<String>,
        /// Replace an existing arming for this backend and scope.
        #[arg(long)]
        replace: bool,
        /// Also describe what this host could measure about the schedule.
        #[arg(long)]
        query: bool,
        /// Sign this arming with the user's enrolled key rather than the admin's.
        ///
        /// A user arming bounds the user's own copies and needs no proof: a proof
        /// exists so a store will honour an admin-signed lease, and there is no
        /// lease here. The user is the authority for her own value.
        #[arg(long = "user-arming")]
        user_arming: bool,
        /// Read the vault password from this file, for a user-signed arming.
        #[arg(long)]
        passphrase_file: Option<std::path::PathBuf>,
        /// Write the job under this account's own home and load it.
        ///
        /// A launchd property list only, written to `~/Library/LaunchAgents`
        /// and loaded with `launchctl bootstrap`. ksp never escalates: a
        /// system-wide target is refused rather than installed as root. A
        /// successful install is a declaration, not evidence — the capability
        /// stays `None` until a run proves the schedule.
        #[arg(long)]
        install: bool,
    },
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use clap::CommandFactory;

    /// `vault unseal` and `vault seal` are absent, not unimplemented.
    ///
    /// NFR-001 and NFR-002: no process holds authority on another party's behalf
    /// and every secret-path operation is a foreground invocation that exits. A
    /// vault left unsealed for a later invocation is exactly that forbidden
    /// session, so the commands do not parse at all — a parser that accepted them
    /// and exited 1 would look like a bug waiting to be fixed.
    #[test]
    fn the_vault_group_has_no_unseal_and_no_seal() {
        for name in ["unseal", "seal"] {
            let parsed = Cli::try_parse_from(["ksp", "vault", name]);
            let error = parsed.expect_err("the command must not parse");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::InvalidSubcommand,
                "`vault {name}` must be unknown to the parser"
            );
        }
    }

    /// Every leaf path, however deep the tree nests.
    ///
    /// A command that takes subcommands **and** its own arguments is a path of its
    /// own as well: `ksp audit` reads the scoped view, and `ksp audit verify` is a
    /// second act on the same log. Reporting only the leaves would drop the first.
    fn surface() -> Vec<String> {
        fn walk(command: &clap::Command, prefix: &str, out: &mut Vec<String>) {
            for sub in command.get_subcommands() {
                let path = if prefix.is_empty() {
                    sub.get_name().to_string()
                } else {
                    format!("{prefix} {}", sub.get_name())
                };
                if sub.get_subcommands().count() == 0 {
                    out.push(path);
                } else {
                    if sub
                        .get_arguments()
                        .any(|argument| argument.get_id() != "help")
                    {
                        out.push(path.clone());
                    }
                    walk(sub, &path, out);
                }
            }
        }
        let command = Cli::command();
        let mut paths = Vec::new();
        walk(&command, "", &mut paths);
        paths.sort();
        paths
    }

    #[test]
    fn the_command_surface_matches_the_design_specification() {
        // Design-spec §6, as amended: `vault unseal` and `vault seal` are gone
        // because NFR-001/NFR-002 forbid the session they would create, and
        // `the_vault_group_has_no_unseal_and_no_seal` holds that absence. A
        // command that is missing is a capability the product does not have; one
        // that is extra is a surface nobody specified.
        //
        // `ksp audit` is specified by feature 002 and not by the design spec's
        // §6 list: FR-040 to FR-043 and US7 name the command, and the spec's
        // `admin audit` is a different report over a different store — the
        // deletion acknowledgement journal. The design spec's surface list
        // predates feature 002 and is not this build's to edit.
        //
        // `__`-prefixed names are this binary's own mechanism, not user surface:
        // they are hidden, they are named so they cannot be typed by accident,
        // and each one is asserted separately below.
        let expected = {
            let mut paths = vec![
                // Design-spec §2.3 and §9 name `ksp status` as the command that
                // discloses the effective backend and the host posture.
                "status",
                // Feature 002 FR-040: the scoped audit log view.
                "audit",
                // Feature 002 FR-047…FR-054: verification against pinned material.
                "audit verify",
                // Feature 004 FR-021…FR-025: the probe's two verbs. `init` is
                // the first-run path and `config init` is the same probe with
                // `--force` as its repair path, so the surface gains both. A
                // `config` group rather than `config show` is what the design
                // spec's §6 list has room for; it holds one verb today.
                "config init",
                "init",
                "admin audit",
                "admin init",
                "admin list",
                "admin policy",
                "admin put",
                "admin revoke",
                "admin user add",
                "vault init",
                "vault rekey",
                "vault status",
                "agent enroll",
                "agent pubkey",
                "agent rotate",
                "token inspect",
                "token lease",
                "token list",
                "token mint",
                "token revoke",
                "secret gc",
                "secret get",
                "secret ls",
                "secret purge-expired",
                "secret rm",
                "secret set",
                "secret share",
                "run",
                // FR-003: the admin records the sweep schedule here; the design spec's
                // §6 list carries `backend list | test`, and feature 002 adds the leaf.
                "backend arm-sweep",
                "backend list",
                "backend test",
                "version",
            ];
            paths.sort();
            paths
        };
        let public: Vec<String> = surface()
            .into_iter()
            .filter(|path| !path.starts_with("__"))
            .collect();
        assert_eq!(public, expected);
    }

    #[test]
    fn the_internal_delivery_command_exists_and_stays_hidden() {
        // `ksp run --consume` must deliver from a process that does not go on to
        // delete, because confinement is irreversible. That process is this
        // binary, and this is the one command that makes it possible — hidden, so
        // the user-facing surface is still exactly the design specification's.
        let deliver = Cli::command()
            .find_subcommand("__deliver")
            .cloned()
            .expect("the delivery command exists");
        assert!(deliver.is_hide_set(), "__deliver must stay hidden");
        assert_eq!(
            surface()
                .iter()
                .filter(|path| path.starts_with("__"))
                .count(),
            1
        );
    }

    #[test]
    fn the_phase_four_session_agent_subcommands_are_absent() {
        // Not hidden: absent. A hidden command still exists, and these are out of
        // MVP scope rather than discouraged.
        for excluded in ["start", "stop", "status", "lock-timeout"] {
            assert!(
                !Cli::command()
                    .find_subcommand("agent")
                    .unwrap()
                    .get_subcommands()
                    .any(|sub| sub.get_name() == excluded),
                "agent {excluded} must not exist"
            );
        }
    }

    #[test]
    fn every_command_accepts_json() {
        // `--json` is global, which means it is accepted *after* the subcommand
        // as well as before it. Asserting only the leading position would pass
        // for a non-global flag, because clap takes a top-level argument there
        // either way.
        assert!(
            Cli::try_parse_from(["ksp", "--json", "secret", "ls"])
                .unwrap()
                .json
        );
        assert!(
            Cli::try_parse_from(["ksp", "secret", "ls", "--json"])
                .unwrap()
                .json
        );
        // A leaf whose required arguments were added later still has to accept
        // `--json` in the trailing position, so the assertion names them.
        assert!(
            Cli::try_parse_from([
                "ksp", "token", "mint", "--agent", "a", "--secret", "s", "--name", "n", "--out",
                "t", "--json"
            ])
            .unwrap()
            .json
        );
        assert!(
            Cli::try_parse_from(["ksp", "admin", "user", "add", "--json"])
                .unwrap()
                .json
        );
    }

    #[test]
    fn run_reads_the_child_only_after_a_separator() {
        // `--` is required before the child: without it a mistyped flag would be
        // passed to the child as though it were ksp's own.
        assert!(Cli::try_parse_from(["ksp", "run", "--consume", "printenv"]).is_err());
        let cli = Cli::try_parse_from(["ksp", "run", "--consume", "--", "printenv"]).unwrap();
        let Command::Run(args) = cli.command else {
            panic!("expected run");
        };
        assert!(args.consume);
        assert_eq!(args.child, vec!["printenv".to_string()]);
    }

    #[test]
    fn a_token_and_an_agent_are_mutually_exclusive() {
        assert!(
            Cli::try_parse_from(["ksp", "run", "--token", "t", "--agent", "7", "--", "true"])
                .is_err()
        );
    }
}
