//! The Host Probe and the write policy behind `ksp init` and `ksp config init`.
//!
//! # One probe, two policies
//!
//! `ksp init` is the first-run path and `ksp config init --force` is a
//! deliberate repair. They are the same measurement with different answers to
//! one question — may I replace what is already there — so the question is
//! asked in one place ([`OverwritePolicy`]) rather than twice (FR-021,
//! FR-023, FR-024, FR-025).
//!
//! # The probe holds no availability logic
//!
//! It asks the registry for each adapter and the adapter for its own
//! availability (FR-026, T034). Copying an availability rule here is how a
//! probe comes to write a configuration the resolver rejects on the same host,
//! because the resolver reads the registry and the copy would drift.
//!
//! # The probe does not decide the requirement level on its own authority
//!
//! FR-031 fixes the one case where the probe deviates: when no mechanism on
//! this host enforces a capability, writing `required` would produce a
//! configuration that refuses every run on that host. The probe writes
//! `optional` **and says so** (FR-022). Writing `optional` where the host can
//! enforce the capability would be a silent downgrade, so it does not.
//!
//! # Nothing here reads a secret
//!
//! The probe reads the host's capability mechanisms and nothing else: no
//! vault, no enrolment, no key (FR-026, NFR-001).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ksp_posture::adapters::{confinement_adapter, memory_barrier_adapter};
use ksp_posture::capability_of;
use ksp_types::capability_config::{
    AdapterAvailability, AdapterName, CapabilityConfiguration, CapabilitySetting, GuaranteeLevel,
    HostCapability, RequirementLevel,
};
use serde::Serialize;

use crate::capability_config::StoredConfiguration;
use crate::config::Layout;
use crate::layout::HOME_MODE;

/// The mode the configuration file is written with (FR-009, NFR-001).
///
/// The file decides what this host may establish, so it belongs to the
/// principal that runs the probe and to nobody else.
pub const FILE_MODE: u32 = 0o600;

/// The header written above the tables.
///
/// The file is meant to be edited, and an operator who opens it should learn
/// the two rules the probe applied without reading this crate. It carries no
/// host fact, so it is a constant rather than formatted text: a file whose
/// comments change between two probes on the same host is a file whose diffs
/// cannot be read.
const HEADER: &str = "\
# Keyspout capability configuration.
#
# Each capability names an ordered preference list. The first adapter this host
# provides is the one that runs. The requirement level says whether a run
# refuses when the capability cannot be established.
";

/// What to do when a configuration already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwritePolicy {
    /// Leave an existing file alone — `ksp init`, `ksp config init`.
    IfAbsent,
    /// Replace an existing file — `ksp config init --force`.
    Replace,
}

/// What the probe learned about one adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The guarantee the adapter declares for its capability.
    pub guarantee: GuaranteeLevel,
    /// Whether this host provides the adapter's mechanism.
    pub availability: AdapterAvailability,
}

/// The registry, as the probe sees it.
///
/// A function rather than a direct call so a test can supply a host instead of
/// asserting a fact about the machine it happens to run on: a test that reads
/// the running host is a test of the host, not of the probe.
pub type Observe = fn(&AdapterName) -> Option<Observation>;

/// Asks the real registries.
///
/// The registry that answers is chosen by the name's own capability, because
/// the two registries are disjoint: a barrier name asked of the confinement
/// registry answers `None`, and the reverse.
pub fn observe_from_registry(name: &AdapterName) -> Option<Observation> {
    match capability_of(name.kind()) {
        HostCapability::PathConfinement => confinement_adapter(name).map(|adapter| Observation {
            guarantee: adapter.guarantee(),
            availability: adapter.availability(),
        }),
        HostCapability::MemoryBarrier => memory_barrier_adapter(name).map(|adapter| Observation {
            guarantee: adapter.guarantee(),
            availability: adapter.availability(),
        }),
    }
}

/// One capability as the probe decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDisclosure {
    /// Which capability this is.
    pub capability: HostCapability,
    /// The preference list written, strongest first.
    pub adapters: Vec<AdapterName>,
    /// The level written, and the reason it was written.
    pub requirement: RequirementLevel,
    /// The adapter the resolver will select on this host, if any.
    pub selected: Option<AdapterName>,
    /// The guarantee the selected adapter declares; `None` when nothing runs.
    pub guarantee: GuaranteeLevel,
    /// Every adapter this host cannot provide, with the host's reason.
    pub unavailable: Vec<(AdapterName, String)>,
}

impl CapabilityDisclosure {
    /// Whether this host will establish the capability at all.
    pub fn established(&self) -> bool {
        self.guarantee != GuaranteeLevel::None
    }
}

/// What the probe decided, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    /// The configuration to write.
    pub configuration: CapabilityConfiguration,
    /// What each capability will and will not establish, in table order.
    pub disclosure: Vec<CapabilityDisclosure>,
}

/// The result of asking for a configuration, either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeReport {
    /// The probe wrote a file.
    Written {
        /// Where it was written.
        path: PathBuf,
        /// The exact text written, so a caller prints what is on disk rather
        /// than a second rendering of it (FR-022).
        text: String,
        /// What the probe decided.
        outcome: ProbeOutcome,
    },
    /// A configuration already existed and the policy left it alone.
    LeftAlone {
        /// The file that was left alone.
        path: PathBuf,
    },
}

impl ProbeReport {
    /// The file the report is about.
    pub fn path(&self) -> &Path {
        match self {
            Self::Written { path, .. } | Self::LeftAlone { path } => path,
        }
    }
}

/// Why the probe could not produce a configuration.
///
/// Neither variant is a host limit: the probe reads hosts it cannot satisfy
/// without failing, because `optional` is a valid answer (FR-031). Both are
/// local failures — a probe that built something the reader refuses, which is
/// a defect in this module, and a file that could not be written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    /// The probe built a configuration the reader refuses.
    ///
    /// This cannot happen through correct behaviour, which is the point of
    /// validating before writing: the probe must not be able to write a file
    /// that `ksp status` would then refuse to read.
    #[error("the probe built a configuration its own reader refuses: {reason}")]
    Rejected {
        /// The reader's refusal.
        reason: String,
    },
    /// The configuration could not be written.
    #[error("the configuration {path} could not be written: {reason}")]
    Unwritable {
        /// The file that could not be written.
        path: PathBuf,
        /// The host's reason.
        reason: String,
    },
    /// The deployment root the configuration lives in could not be created.
    ///
    /// `ksp init` is the first-run command, so the host it is written for is
    /// one whose home may not exist yet. Naming the **directory** in this
    /// refusal rather than the file matters: the operator's fix is to create or
    /// permit a directory, and a message about `config.toml` would send them to
    /// the wrong path.
    #[error("the deployment root {path} could not be created: {reason}")]
    NoHome {
        /// The directory that could not be created.
        path: PathBuf,
        /// The host's reason.
        reason: String,
    },
}

/// Measures this host and decides what to write.
///
/// # Requirement levels
///
/// `required` when at least one adapter this host provides establishes the
/// capability with a guarantee better than nothing, `optional` otherwise
/// (FR-031). The probe does not raise the level the operator did not ask for;
/// a file it writes is the first one, so there is no operator yet.
///
/// # Order
///
/// The list is every adapter of the capability, strongest guarantee first, so
/// that an operator whose host later gains a stronger mechanism finds it
/// already in the list (NFR-008) and so that a weaker adapter is a *fallback*
/// rather than the only choice. The resolver selects the first entry the host
/// provides, so the ordering is what makes strength win over accident.
///
/// Ties keep the closed set's order, which is the order the registry declares.
pub fn probe() -> ProbeOutcome {
    probe_with(observe_from_registry)
}

/// Measures a host described by `observe`, for tests and for the real one.
pub fn probe_with(observe: Observe) -> ProbeOutcome {
    let mut disclosure = Vec::new();
    let confinement = decide(HostCapability::PathConfinement, observe, &mut disclosure);
    let memory_barrier = decide(HostCapability::MemoryBarrier, observe, &mut disclosure);

    ProbeOutcome {
        configuration: CapabilityConfiguration {
            confinement,
            memory_barrier,
        },
        disclosure,
    }
}

/// Decides one capability's table and records why.
fn decide(
    capability: HostCapability,
    observe: Observe,
    disclosure: &mut Vec<CapabilityDisclosure>,
) -> CapabilitySetting {
    // Every name the closed set holds for this capability, with what the host
    // says about it. A name with no observation is not in this build, which the
    // closed set forbids; dropping it rather than inventing a guarantee keeps
    // the file honest if that ever changes.
    let mut observed: Vec<(AdapterName, Observation)> = AdapterName::ALL
        .into_iter()
        .filter_map(|name| AdapterName::parse(name).ok())
        .filter(|name| capability_of(name.kind()) == capability)
        .filter_map(|name| observe(&name).map(|observation| (name, observation)))
        .collect();

    // Strongest first, and stable, so equal guarantees keep the closed set's
    // order and the written file is the same on every run.
    observed.sort_by_key(|(_, observation)| std::cmp::Reverse(observation.guarantee));

    let selected = observed
        .iter()
        .find(|(_, observation)| observation.availability.is_available());
    let guarantee = selected.map_or(GuaranteeLevel::None, |(_, observation)| {
        observation.guarantee
    });
    let requirement = if guarantee == GuaranteeLevel::None {
        RequirementLevel::Optional
    } else {
        RequirementLevel::Required
    };

    let unavailable = observed
        .iter()
        .filter_map(|(name, observation)| {
            observation
                .availability
                .reason()
                .map(|reason| (name.clone(), reason.to_string()))
        })
        .collect();

    disclosure.push(CapabilityDisclosure {
        capability,
        adapters: observed.iter().map(|(name, _)| name.clone()).collect(),
        requirement,
        selected: selected.map(|(name, _)| name.clone()),
        guarantee,
        unavailable,
    });

    CapabilitySetting {
        adapters: observed.into_iter().map(|(name, _)| name).collect(),
        requirement,
    }
}

/// Measures this host and writes the configuration if the policy allows it.
///
/// The configuration is validated **before** anything is written, through the
/// same reader that will later read it. A probe that wrote first and validated
/// afterwards could leave a file that stops every command on the host.
///
/// # Errors
///
/// [`ProbeError::Rejected`] if the built configuration is one the reader
/// refuses, and [`ProbeError::Unwritable`] if the file cannot be written.
pub fn configure(layout: &Layout, policy: OverwritePolicy) -> Result<ProbeReport, ProbeError> {
    configure_with(layout, policy, probe())
}

/// Writes `outcome` if the policy allows it.
///
/// The outcome is a parameter rather than a measurement taken here so that the
/// write path can be tested against a described host. A test that let this
/// function measure the running host would assert a fact about the machine it
/// runs on, and the two gate hosts disagree about every mechanism.
///
/// # Errors
///
/// [`ProbeError::Rejected`] if `outcome` is a configuration the reader refuses,
/// and [`ProbeError::Unwritable`] if the file cannot be written.
pub fn configure_with(
    layout: &Layout,
    policy: OverwritePolicy,
    outcome: ProbeOutcome,
) -> Result<ProbeReport, ProbeError> {
    let path = layout.capability_config_file();

    // `symlink_metadata` rather than `exists`: `exists` follows a symlink and
    // answers `false` for a dangling one, which would make `ksp init` treat a
    // host that has something at this path as unconfigured and write through
    // the link. "Something is placed here" is the question the policy asks.
    if policy == OverwritePolicy::IfAbsent && fs::symlink_metadata(&path).is_ok() {
        return Ok(ProbeReport::LeftAlone { path });
    }

    let stored = StoredConfiguration::from(&outcome.configuration);

    // Validate before writing. The probe and the reader are two halves of one
    // contract, and this is the call that keeps them from drifting.
    stored
        .validated(&path)
        .map_err(|refusal| ProbeError::Rejected {
            reason: refusal.to_string(),
        })?;

    let text = render_document(&stored).map_err(|reason| ProbeError::Rejected { reason })?;

    // The home must exist before the file can be written into it, and the host
    // this command is for is one where it may not: `ksp init` is the first-run
    // path, and `KSP_HOME` defaults to a `.ksp` directory that a fresh checkout
    // does not have.
    ensure_home(layout.root())?;
    write_private(&path, &text)?;

    Ok(ProbeReport::Written {
        path,
        text,
        outcome,
    })
}

/// The file's text: the header, then the tables.
///
/// `to_string_pretty` fails only for a value the format cannot express, and
/// this type is two tables of strings and enums, so a failure here means the
/// stored shape grew something TOML cannot write. Reporting that as a rejection
/// is right: writing the header alone would leave a document the reader refuses,
/// which is the one thing the probe must never do.
fn render_document(stored: &StoredConfiguration) -> Result<String, String> {
    toml::to_string_pretty(stored)
        .map(|body| format!("{HEADER}\n{body}"))
        .map_err(|err| format!("the configuration could not be rendered as TOML: {err}"))
}

/// Creates the deployment root when it is absent, at the layout table's mode.
///
/// The mode comes from the table rather than from a literal here, and it is set
/// on the **directory** after creation rather than asked of `create_dir`: a
/// creation mode is masked by the caller's `umask`, which is how `enrolments/`
/// once became `0775`.
///
/// This creates the one directory the configuration needs and no other. The
/// rest of the layout is `ksp admin init`'s to provision, and `ksp init` writing
/// a store or a key root would be a deployment it was never asked to make.
fn ensure_home(home: &Path) -> Result<(), ProbeError> {
    if home.is_dir() {
        return Ok(());
    }

    let refusal = |reason: String| ProbeError::NoHome {
        path: home.to_path_buf(),
        reason,
    };

    fs::create_dir_all(home).map_err(|err| refusal(err.to_string()))?;
    fs::set_permissions(home, fs::Permissions::from_mode(HOME_MODE))
        .map_err(|err| refusal(err.to_string()))?;
    Ok(())
}

/// Writes `text` at `path` with [`FILE_MODE`], replacing what is there.
///
/// The mode is set on the **descriptor**, not requested from `open(2)`: a mode
/// passed to `open` is masked by the caller's `umask`, so a principal running
/// `umask 077` and one running `umask 022` would otherwise get different files
/// from the same command. An existing file keeps its old mode through
/// `truncate`, so setting it after the write is the only way both paths agree.
fn write_private(path: &Path, text: &str) -> Result<(), ProbeError> {
    let unwritable = |reason: String| ProbeError::Unwritable {
        path: path.to_path_buf(),
        reason,
    };

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(FILE_MODE)
        .open(path)
        .map_err(|err| unwritable(err.to_string()))?;

    file.write_all(text.as_bytes())
        .map_err(|err| unwritable(err.to_string()))?;

    file.set_permissions(fs::Permissions::from_mode(FILE_MODE))
        .map_err(|err| unwritable(err.to_string()))?;

    // The file is the deployment's policy: a configuration that reached the
    // page cache and not the disk is one a crash silently reverts.
    file.sync_all().map_err(|err| unwritable(err.to_string()))?;

    Ok(())
}

/// The probe's outcome, in the shape a caller renders or serialises.
///
/// Strings rather than the domain types: this is the boundary where a value
/// becomes output, and a JSON consumer reads a name, not a Rust enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeSummary {
    /// `written` or `existing`.
    pub outcome: &'static str,
    /// The configuration file.
    pub path: String,
    /// The mode of a file the probe wrote.
    pub mode: Option<String>,
    /// The document written, when one was.
    pub configuration: Option<String>,
    /// Per capability: what will run, at what guarantee, and what will not.
    pub capabilities: Vec<CapabilitySummary>,
}

/// One capability, as output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilitySummary {
    /// The table's key, as the file spells it.
    pub capability: &'static str,
    /// The name a view prints.
    pub label: &'static str,
    /// The preference list written.
    pub adapters: Vec<String>,
    /// The level written.
    pub requirement: &'static str,
    /// The adapter the resolver will select, if any.
    pub selected: Option<String>,
    /// That adapter's guarantee.
    pub guarantee: &'static str,
    /// What this host cannot provide, and why.
    pub unavailable: Vec<String>,
}

impl ProbeSummary {
    /// The summary for a report the probe produced.
    pub fn of(report: &ProbeReport) -> Self {
        match report {
            ProbeReport::LeftAlone { path } => Self {
                outcome: "existing",
                path: path.display().to_string(),
                mode: None,
                configuration: None,
                capabilities: Vec::new(),
            },
            ProbeReport::Written {
                path,
                text,
                outcome,
            } => Self {
                outcome: "written",
                path: path.display().to_string(),
                mode: Some(format!("{FILE_MODE:04o}")),
                configuration: Some(text.clone()),
                capabilities: outcome
                    .disclosure
                    .iter()
                    .map(|entry| CapabilitySummary {
                        capability: entry.capability.config_key(),
                        label: entry.capability.label(),
                        adapters: entry
                            .adapters
                            .iter()
                            .map(|name| name.as_str().to_string())
                            .collect(),
                        requirement: entry.requirement.label(),
                        selected: entry
                            .selected
                            .as_ref()
                            .map(|name| name.as_str().to_string()),
                        guarantee: entry.guarantee.label(),
                        unavailable: entry
                            .unavailable
                            .iter()
                            .map(|(name, reason)| format!("{}: {reason}", name.as_str()))
                            .collect(),
                    })
                    .collect(),
            },
        }
    }
}

/// The text a person reads: what was written, and what it does not guarantee.
///
/// FR-022 asks for two things — the configuration, and what it does not
/// guarantee — and the second is the one a report can forget. A capability
/// written `optional` is named with the host's own reason, because "optional"
/// without a reason reads like a choice the operator made.
pub fn render(summary: &ProbeSummary) -> String {
    if summary.outcome == "existing" {
        return format!(
            "a configuration already exists at {}\n\
             nothing was changed. Run `ksp config init --force` to re-probe this \
             host and replace it.",
            summary.path
        );
    }

    let mut text = format!(
        "wrote {} with mode {}",
        summary.path,
        summary.mode.as_deref().unwrap_or("unknown")
    );
    if let Some(configuration) = &summary.configuration {
        text.push_str("\n\n");
        text.push_str(configuration.trim_end());
    }

    text.push_str("\n\nwhat this configuration does not guarantee:");
    for entry in &summary.capabilities {
        text.push('\n');
        text.push_str(&not_guaranteed(entry));
    }
    text
}

/// One capability's line in the disclosure.
fn not_guaranteed(entry: &CapabilitySummary) -> String {
    let reasons = if entry.unavailable.is_empty() {
        String::new()
    } else {
        format!(" ({})", entry.unavailable.join("; "))
    };

    match (entry.selected.as_deref(), entry.guarantee) {
        (Some(adapter), "full") => format!(
            "  {}: full, established by {adapter}. Nothing is given up here.",
            entry.label
        ),
        (Some(adapter), "weakened") => format!(
            "  {}: weakened, established by {adapter}. The run proceeds with a \
             smaller guarantee than the capability names{reasons}.",
            entry.label
        ),
        _ => format!(
            "  {}: not established on this host{reasons}. The level written is \
             {}, so a run continues without it.",
            entry.label, entry.requirement
        ),
    }
}
