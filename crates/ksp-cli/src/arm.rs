//! `ksp backend arm-sweep`: record one schedule per backend and scope.
//!
//! # Recording is not installing
//!
//! This module writes one signed record under `KSP_HOME/sweeper/armings/` and prints
//! what an operator would install. It does not write into `/etc/systemd`, does not
//! touch a crontab, and does not spawn a privileged helper: `ksp` holds no root, and a
//! command that installed a unit would be a command that needed it (misfit C — a
//! declaration mistaken for an installation).
//!
//! # One record, one scope
//!
//! The record's identity is `(backend, scope)`, so arming the same pair twice collides
//! on one file instead of racing as two jobs (misfit P). Replacing is explicit
//! (`--replace`) and reports what it replaced.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::config::{self, Layout};
use crate::exit::{self, Outcome};
use crate::output::{ArmingView, Emitter, Report};
use ksp_backend::sweeper::{
    ArmingError, ArmingKind, ArmingQuery, CredentialBinding, Grant, MeasuredUnitState, Right,
    SignedArming, SweeperArming,
};

/// What the command line asked for.
pub struct ArmRequest<'a> {
    /// `--kind`, or `None` to use the kind the backend provides (FR-003).
    pub kind: Option<&'a str>,
    /// `--interval`, as `1h`, `30m`, `90s` or a bare number of seconds.
    pub interval: &'a str,
    /// `--scope`, a store prefix.
    pub scope: &'a str,
    /// `--credential`, the identity the job runs as.
    pub credential: &'a str,
    /// `--grant`, repeatable, each `right:scope`.
    pub grants: &'a [String],
    /// `--identifier`, the unit or job name the operator installs under.
    pub identifier: Option<&'a str>,
    /// `--replace`, accept an existing arming for this backend and scope.
    pub replace: bool,
    /// `--query`, also describe what this host could measure.
    pub query: bool,
    /// Sign this arming with the **user's** enrolled key rather than the admin's.
    ///
    /// A user arming bounds the user's own copies, so the user is its authority.
    /// It needs no proof: a proof exists so a store will honour an admin-signed
    /// lease, and there is no lease here to honour.
    pub user_signed: bool,
    /// Read the vault password from this file, for a user-signed arming.
    pub passphrase_file: Option<&'a std::path::Path>,
    /// Write the job under this account's own home and load it.
    ///
    /// A launchd property list only. The install is a declaration, not
    /// evidence: the capability stays `None` until a run proves the schedule.
    pub install: bool,
}

/// Why the arming was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArmError {
    /// The backend's arming record could not be read or written.
    #[error("the arming record could not be recorded under sweeper/armings")]
    Store,
    /// This host has no deployment to arm.
    #[error("this host has no deployment")]
    NotProvisioned,
    /// The admin key the anchor pins could not be loaded.
    #[error("the admin signing key could not be loaded against the pinned anchor")]
    Keys,
    /// The interval text is not a duration, or is zero.
    #[error("'{0}' is not an interval; use 1h, 30m, 90s or a whole number of seconds")]
    Interval(String),
    /// A `--grant` is not `right:scope`.
    #[error("'{0}' is not a grant; use <right>:<scope>, for example delete:{1}")]
    Grant(String, String),
    /// An arming already exists for this backend and scope.
    #[error(
        "this backend and scope are already armed ({existing}); pass --replace to replace it, so \
         that two sweeps never run against one scope"
    )]
    AlreadyArmed {
        /// What the existing record says, so the operator can decide.
        existing: String,
    },
    /// The record could not be signed.
    #[error("the arming could not be signed")]
    Sign,
    /// The scope is not the shape admission reads.
    ///
    /// Rendered from [`ArmingError::ScopeAdmissionUnreadable`] with the next
    /// step for this authority, so the operator is told what to run rather than
    /// only what was wrong.
    #[error(
        "the scope '{scope}' is not the shape admission reads; this deployment admits \
         '{accepted}'. {next}"
    )]
    ScopeRefused {
        /// The scope as written.
        scope: String,
        /// The shape this deployment admits.
        accepted: String,
        /// What to do next, for this authority.
        next: String,
    },
    /// The job could not be installed.
    #[error("{0}")]
    Install(#[from] crate::install::InstallRefusal),
    /// The record itself is invalid.
    #[error("{0}")]
    Record(#[from] ArmingError),
}

impl ArmError {
    /// The exit code this refusal maps to.
    pub fn exit_code(&self) -> i32 {
        match self {
            // Nothing that could authorise the record was present.
            Self::NotProvisioned | Self::Keys => exit::MISSING_KEY,
            // Well-formed requests the deployment does not permit.
            Self::Interval(_)
            | Self::Grant(..)
            | Self::AlreadyArmed { .. }
            | Self::ScopeRefused { .. }
            | Self::Install(_)
            | Self::Record(_) => exit::POLICY_DENIAL,
            // An arming that cannot be recorded must not be reported as recorded.
            Self::Store | Self::Sign => exit::CAPABILITY_REFUSAL,
        }
    }
}

/// Parse `1h`, `30m`, `90s` or a bare number of seconds.
pub fn parse_interval(text: &str) -> Result<u64, ArmError> {
    let trimmed = text.trim();
    let (digits, scale) = match trimmed.chars().last() {
        Some('h') | Some('H') => (&trimmed[..trimmed.len() - 1], 3600),
        Some('m') | Some('M') => (&trimmed[..trimmed.len() - 1], 60),
        Some('s') | Some('S') => (&trimmed[..trimmed.len() - 1], 1),
        _ => (trimmed, 1),
    };
    let value: u64 = digits
        .trim()
        .parse()
        .map_err(|_| ArmError::Interval(text.to_string()))?;
    let seconds = value
        .checked_mul(scale)
        .ok_or_else(|| ArmError::Interval(text.to_string()))?;
    if seconds == 0 {
        return Err(ArmError::Interval(text.to_string()));
    }
    Ok(seconds)
}

/// Parse one `right:scope` grant.
fn parse_grant(text: &str) -> Result<Grant, ArmError> {
    let (right, scope) = text
        .split_once(':')
        .ok_or_else(|| ArmError::Grant(text.to_string(), "p/".to_string()))?;
    let right = match right.trim().to_ascii_lowercase().as_str() {
        "delete" => Right::Delete,
        "list" => Right::List,
        "write" => Right::Write,
        "read" => Right::Read,
        "admin" => Right::Admin,
        "owner" => Right::Owner,
        other => {
            return Err(ArmError::Grant(other.to_string(), "p/".to_string()));
        }
    };
    Ok(Grant {
        right,
        scope: scope.trim().to_string(),
    })
}

/// Where one host's armings live.
fn arming_path(layout: &Layout, id: &str) -> PathBuf {
    layout.sweeper_armings_dir().join(format!("{id}.cbor"))
}

/// Run one `backend arm-sweep`.
pub fn run<W: Write>(
    request: ArmRequest<'_>,
    layout: &Layout,
    emitter: &mut Emitter<W>,
) -> Outcome {
    match record(&request, layout) {
        Ok(view) => match emitter.report(&Report::Arming(view)) {
            Ok(()) => Outcome::Success,
            Err(_) => Outcome::Failed(exit::INTERNAL),
        },
        Err(error) => {
            let _ = emitter.refusal(&error.to_string());
            Outcome::Failed(error.exit_code())
        }
    }
}

/// Install the arming's job under this account's own home.
///
/// The authority is decided here, because this is the only place that knows
/// whether the admin or the user signed. The installer is given the answer and
/// decides nothing about authorization.
fn record_install(
    arming: &ksp_backend::sweeper::SweeperArming,
    layout: &Layout,
    kind: ksp_backend::sweeper::ArmingKind,
    user_signed: bool,
) -> Result<crate::output::InstalledView, ArmError> {
    use crate::install::{InstallAuthority, LaunchdInstaller, Loaded, SystemRunner, UnitSpec};

    if kind != ksp_backend::sweeper::ArmingKind::Launchd {
        return Err(ArmError::Install(
            crate::install::InstallRefusal::UnsupportedKind {
                kind: kind.label().to_string(),
            },
        ));
    }
    let home = std::env::var("HOME").map_err(|_| {
        ArmError::Install(crate::install::InstallRefusal::Write {
            path: "~/Library/LaunchAgents".to_string(),
            reason: "HOME is not set, so this account's home cannot be named".to_string(),
        })
    })?;
    // The plist must carry the home the job will read, and this process already
    // resolved it: `layout.root()` is `KSP_HOME`, defaulted or explicit. Reading
    // the variable again would write an empty value whenever the operator relied
    // on the default, and a job with no home sweeps nothing.
    let content = arming
        .launchd_plist(&layout.root().display().to_string())
        .ok_or_else(|| {
            ArmError::Install(crate::install::InstallRefusal::UnsupportedKind {
                kind: kind.label().to_string(),
            })
        })?;
    let path = std::path::Path::new(&home)
        .join("Library/LaunchAgents")
        .join(format!("{}.plist", arming.identifier));

    let installer = LaunchdInstaller::new(SystemRunner, &home);
    let authority = if user_signed {
        InstallAuthority::User
    } else {
        InstallAuthority::Admin
    };
    let outcome = installer
        .install(
            &UnitSpec {
                content,
                path: path.clone(),
            },
            authority,
        )
        .map_err(ArmError::Install)?;

    let note = match outcome.loaded {
        Loaded::Verified => {
            "the job is loaded, and an install is still not evidence: the capability stays None \
             until a run writes a signed sweep proof"
        }
        Loaded::Declared => {
            "the job is written and its load was requested; a user arming is a declaration, and \
             only a run that writes a proof makes the schedule evidence"
        }
    };
    Ok(crate::output::InstalledView {
        path: outcome.path.display().to_string(),
        note: note.to_string(),
    })
}

/// Turn a scope refusal into the message its authority should read.
///
/// The error type is authority-neutral because the accepted shape is the same
/// for both. What differs is the next step: an admin arms `agent-*`, while a
/// user's own cleanup is `ksp secret gc` and needs no arming at all. Rendering
/// here — the one place that knows which authority is acting — keeps the
/// backend from having to know about either command.
fn render_scope_refusal(error: ArmingError, user_signed: bool) -> ArmError {
    let ArmingError::ScopeAdmissionUnreadable { scope, accepted } = error else {
        return ArmError::Record(error);
    };
    let next = if user_signed {
        format!(
            "a user arming reaches no lease: run 'ksp secret gc --user-arming' to sweep your \
             own copies, or arm '{accepted}' as the admin"
        )
    } else {
        format!("re-run with --scope {accepted}")
    };
    ArmError::ScopeRefused {
        scope,
        accepted,
        next,
    }
}

/// Build, validate and store one arming; return what to report.
fn record(request: &ArmRequest<'_>, layout: &Layout) -> Result<ArmingView, ArmError> {
    let (deployment, anchor) =
        crate::deployment::require(layout).map_err(|_| ArmError::NotProvisioned)?;
    let backend = config::read_backend(layout)
        .map_err(|_| ArmError::NotProvisioned)?
        .name()
        .to_string();

    let kind = match request.kind {
        Some(text) => parse_kind(text)?,
        None => ArmingKind::for_backend(&backend, ksp_backend::sweeper::HostPlatform::current())
            .ok_or(ArmError::Record(ArmingError::Incomplete(
                "the backend's arming kind",
            )))?,
    };
    let interval_secs = parse_interval(request.interval)?;
    let grants = request
        .grants
        .iter()
        .map(|text| parse_grant(text))
        .collect::<Result<Vec<_>, _>>()?;
    let identifier = request.identifier.unwrap_or(match kind {
        ArmingKind::Systemd => "ksp-sweep.service",
        ArmingKind::Launchd => "com.keyspout.sweep",
        ArmingKind::Crontab => "ksp-sweep",
        ArmingKind::ProviderLifecycle => "ksp-sweep-lifecycle",
        ArmingKind::ExternalJob => "ksp-sweep-job",
    });
    let recorded_at = now_secs();

    let arming = SweeperArming::new(ksp_backend::sweeper::ArmingSpec {
        backend: &backend,
        vault: &deployment.vault,
        kind,
        identifier,
        interval_secs,
        scope: request.scope,
        credential: CredentialBinding {
            identity: request.credential.to_string(),
            grants,
        },
        principal: deployment.user,
        recorded_at,
        signer_key_id: anchor.key_id.as_str(),
        user_signed: request.user_signed,
    })
    .map_err(|error| render_scope_refusal(error, request.user_signed))?;

    let path = arming_path(layout, &arming.arming_id);
    let replaced = match read_arming(&path)? {
        Some(existing) => {
            if !request.replace {
                return Err(ArmError::AlreadyArmed {
                    existing: summarise(&existing),
                });
            }
            Some(summarise(&existing))
        }
        None => None,
    };

    // Who signs decides whose cleanup this is. An admin arming admits a lease and
    // is signed by the admin key; a user arming bounds the user's own copies and
    // is signed by the user's enrolled key, which is the only key that speaks for
    // her. Signing hers with the admin key would attribute her deletions to the
    // admin in every report the sweep writes.
    let signed = if request.user_signed {
        let password = match request.passphrase_file {
            Some(path) => std::fs::read(path).map_err(|_| ArmError::Keys)?,
            None => {
                let mut buffer = Vec::new();
                use std::io::Read as _;
                std::io::stdin()
                    .read_to_end(&mut buffer)
                    .map_err(|_| ArmError::Keys)?;
                buffer
            }
        };
        let unsealed = crate::secret::unseal(layout, &password).map_err(|_| ArmError::Keys)?;
        unsealed
            .vault
            .with_signing_key(|signer| {
                // The seed is lent for one call, as the admin path does, so no
                // copy of the key outlives the signature.
                signer.with_secret(|seed| {
                    SignedArming::sign(arming.clone(), &ed25519_dalek::SigningKey::from_bytes(seed))
                })
            })
            .map_err(|_| ArmError::Sign)?
    } else {
        let admin = crate::admin::load_admin(layout, &anchor).map_err(|_| ArmError::Keys)?;
        admin
            .with_secret(|seed| {
                SignedArming::sign(arming.clone(), &ed25519_dalek::SigningKey::from_bytes(seed))
            })
            .map_err(|_| ArmError::Sign)?
    };
    write_arming(layout, &path, &signed)?;

    // The install runs after the arming is recorded and validated, so the scope
    // refusal fires first: installing a job for a scope admission never reads
    // would install a schedule that reaches no lease.
    let installed = if request.install {
        Some(record_install(&arming, layout, kind, request.user_signed)?)
    } else {
        None
    };

    let query = if request.query {
        let state = ArmingQuery::for_kind(kind);
        let command = match kind {
            ArmingKind::Systemd => {
                let (program, args) = ArmingQuery::systemd_command(identifier);
                Some(format!("{program} {}", args.join(" ")))
            }
            _ => None,
        };
        Some(describe_query(&state, command.as_deref()))
    } else {
        None
    };

    Ok(ArmingView {
        backend,
        kind: kind.label().to_string(),
        identifier: identifier.to_string(),
        interval_secs,
        scope: arming.scope.clone(),
        credential: arming.credential.identity.clone(),
        rights: arming
            .credential
            .grants
            .iter()
            .map(|grant| format!("{}:{}", grant.right.label(), grant.scope))
            .collect(),
        principal: arming.principal.to_string(),
        recorded_at,
        arming_id: arming.arming_id.clone(),
        replaced,
        installed,
        // Both artifacts are templates the operator installs; `ksp` installs
        // neither. The plist carries the operator's own `KSP_HOME`, because a job
        // launched outside this invocation has no environment inherited from it.
        unit_template: arming
            .systemd_unit(&layout.root().display().to_string())
            .or_else(|| arming.launchd_plist(&layout.root().display().to_string())),
        query,
    })
}

fn parse_kind(text: &str) -> Result<ArmingKind, ArmError> {
    match text.trim().to_ascii_lowercase().as_str() {
        "systemd" => Ok(ArmingKind::Systemd),
        "launchd" => Ok(ArmingKind::Launchd),
        "crontab" => Ok(ArmingKind::Crontab),
        "provider-lifecycle" => Ok(ArmingKind::ProviderLifecycle),
        "external-job" => Ok(ArmingKind::ExternalJob),
        _ => Err(ArmError::Record(ArmingError::Incomplete(
            "a kind of systemd, launchd, crontab, provider-lifecycle or external-job",
        ))),
    }
}

/// What an existing record says, for a refusal or a replacement report.
fn summarise(arming: &SweeperArming) -> String {
    format!(
        "kind={} identifier={} interval={}s recorded_at={}",
        arming.kind.label(),
        arming.identifier,
        arming.interval_secs,
        arming.recorded_at
    )
}

fn read_arming(path: &Path) -> Result<Option<SweeperArming>, ArmError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(SignedArming::from_bytes(&bytes)?.arming)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ArmError::Store),
    }
}

/// Write the record durably: a synced temporary file in the same directory, then a
/// rename, then a synced directory.
///
/// FR-003 asks for the record to be durable before any lease is admitted, and a rename
/// alone is not durable: a crash can leave the file's bytes unwritten or the directory
/// entry unrecorded while this command has already reported success. The sync on the
/// file makes the bytes real, the rename makes a reader see either the previous record
/// or the new one, and the sync on the directory makes the rename itself survive.
fn write_arming(layout: &Layout, path: &Path, signed: &SignedArming) -> Result<(), ArmError> {
    let directory = layout.sweeper_armings_dir();
    crate::layout::ensure_row(layout.root(), &directory).map_err(|_| ArmError::Store)?;
    let bytes = signed.to_bytes().map_err(|_| ArmError::Store)?;
    let temporary = directory.join(format!(
        ".{}.tmp",
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("arming")
    ));
    let written = std::fs::File::create(&temporary).and_then(|mut file| {
        std::io::Write::write_all(&mut file, &bytes)?;
        file.sync_all()
    });
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
        return Err(ArmError::Store);
    }
    if std::fs::rename(&temporary, path).is_err() {
        let _ = std::fs::remove_file(&temporary);
        return Err(ArmError::Store);
    }
    std::fs::File::open(&directory)
        .and_then(|handle| handle.sync_all())
        .map_err(|_| ArmError::Store)
}

/// The query line: the command, what it could not tell, and that it decides nothing.
fn describe_query(state: &MeasuredUnitState, command: Option<&str>) -> String {
    let measured = match state {
        MeasuredUnitState::Reported { active, detail, .. } => {
            format!("reported active={active} ({detail})")
        }
        MeasuredUnitState::Unknown { reason } => format!("unknown: {reason}"),
    };
    match command {
        Some(command) => format!("{measured}; ask with: {command}"),
        None => measured,
    }
}

/// Seconds since the epoch, for the record's own clock.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
