//! What this host establishes for a host capability, and what the run does
//! about it.
//!
//! This module is the one place a command asks *may this capability be
//! established, and by what*. It joins the two halves that were built apart:
//! the configuration reader (S2) says which adapters the operator wants and
//! whether the run requires the capability; the resolver and the requirement
//! check (S1) say which adapter the host confirms and whether that satisfies
//! the level.
//!
//! # The order the three facts arrive in
//!
//! 1. **The configuration is read and validated first**, before any capability
//!    is touched (T040, FR-003). A malformed or unsafe file refuses the run
//!    here, when nothing has been established and nothing has to be undone.
//! 2. **The preference list is resolved against the host.** The first adapter
//!    the host confirms is the one that runs; the rest are recorded with the
//!    host's reason.
//! 3. **The requirement level decides whether the run proceeds.** A required
//!    capability needs a real mechanism; an optional one proceeds with the
//!    guarantee the selected adapter actually establishes.
//!
//! # An absent configuration is a refusal, not a default
//!
//! There is no built-in preference list (NFR-006). A host with no
//! `config.toml` has no adapter selected for either capability, and a command
//! that needs one refuses and names `ksp init`. Inferring an adapter from the
//! host would make the operator's configuration advisory, which is the
//! silent-downgrade failure the whole feature exists to close (Misfit A).
//!
//! So the absent file is the **required** case: the run refuses because there
//! is nothing to establish the capability with, and it names the missing
//! configuration (FR-015) rather than the host, because the host is not the
//! problem.
//!
//! # Reading the file is not establishing the capability
//!
//! [`load`] reads and validates; [`granted`] decides. Keeping them apart is
//! what lets `ksp status` report *why* a capability could not be established on
//! a host that cannot establish it (NFR-005), and what lets the refusal order
//! be the one the operator can act on: a broken file is fixed by editing it,
//! a missing mechanism is not.

use std::fmt;

use ksp_posture::adapters::{confinement_adapter, memory_barrier_adapter};
use ksp_posture::{
    CapabilityDisclosure, Resolution, SkippedAdapter, UnavailableCapability, capability_of,
    resolve_confinement, resolve_memory_barrier, satisfies,
};
use ksp_types::capability_config::{
    AdapterAvailability, AdapterName, CapabilityConfiguration, CapabilitySetting, GuaranteeLevel,
    HostCapability, RequirementLevel,
};
use ksp_types::evidence::CapabilityAcceptance;

use crate::capability_config::{self, ConfigurationRefusal};
use crate::config::Layout;
use crate::exit;

/// The platform the run is on, as the status line names it.
///
/// One spelling, from the compiler rather than from a `cfg!` ladder, so a
/// reader of the disclosure compares it with `uname` without translating.
pub const PLATFORM: &str = std::env::consts::OS;

/// Resolves one capability's preference list against the host.
///
/// A function pointer rather than a direct call so the decision can be tested
/// against a host the test controls. The production path supplies
/// [`resolve_registry`], which asks the **adapter** — the resolver itself never
/// decides availability.
pub type Resolve = fn(HostCapability, &[AdapterName]) -> Result<Resolution, UnavailableCapability>;

/// The resolver the production path uses: the registry's own answer.
pub fn resolve_registry(
    capability: HostCapability,
    preference: &[AdapterName],
) -> Result<Resolution, UnavailableCapability> {
    match capability {
        HostCapability::PathConfinement => resolve_confinement(preference),
        HostCapability::MemoryBarrier => resolve_memory_barrier(preference),
    }
}

/// The adapters this build contains for one capability, in the order the
/// configuration file lists them.
///
/// FR-010 asks an unconfigured capability to name the adapters that could have
/// been offered. It is derived from the same closed set the registry matches
/// on, so it cannot name an adapter the build does not hold.
pub fn adapters_for(capability: HostCapability) -> Vec<&'static str> {
    AdapterName::ALL
        .into_iter()
        .filter(|name| {
            AdapterName::parse(name).is_ok_and(|parsed| capability_of(parsed.kind()) == capability)
        })
        .collect()
}

/// Reads and validates the capability configuration.
///
/// `Ok(None)` is the unconfigured state, not a failure (FR-004). The caller
/// passes the result to [`granted`] or [`disclosure`] rather than reading the
/// file twice: two reads of a file another principal could rewrite between them
/// is two different answers to one question.
///
/// # Errors
///
/// One of the [`ConfigurationRefusal`] variants, each naming the file and the
/// thing to fix.
pub fn load(layout: &Layout) -> Result<Option<CapabilityConfiguration>, CapabilityError> {
    capability_config::read(layout).map_err(CapabilityError::Configuration)
}

/// A resolved capability: the adapter that runs, and what it establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    capability: HostCapability,
    requirement: RequirementLevel,
    adapter: Option<AdapterName>,
    guarantee: GuaranteeLevel,
    configured: Vec<AdapterName>,
    skipped: Vec<SkippedAdapter>,
}

impl Grant {
    /// The capability this grant is for.
    pub fn capability(&self) -> HostCapability {
        self.capability
    }

    /// The level the operator set for it.
    pub fn requirement(&self) -> RequirementLevel {
        self.requirement
    }

    /// The adapter the host confirmed, when one was.
    ///
    /// `None` when the capability is optional and nothing could be
    /// established — the run proceeds and the disclosure says nothing was.
    pub fn adapter(&self) -> Option<&AdapterName> {
        self.adapter.as_ref()
    }

    /// What the selected adapter establishes.
    ///
    /// `None` when no adapter ran, so an unestablished capability is never
    /// rendered as one that established something (FR-020).
    pub fn guarantee(&self) -> GuaranteeLevel {
        self.guarantee
    }

    /// The adapters the configuration named, in the operator's order.
    pub fn configured(&self) -> &[AdapterName] {
        &self.configured
    }

    /// The adapters that did not run, each with the host's reason.
    pub fn skipped(&self) -> &[SkippedAdapter] {
        &self.skipped
    }

    /// Whether an adapter established a mechanism.
    pub fn established(&self) -> bool {
        self.adapter.is_some() && self.guarantee != GuaranteeLevel::None
    }

    /// The acceptance this grant records, when it accepted an absence.
    ///
    /// `Some` exactly when an adapter ran and established nothing: that is the
    /// operator's decision travelling with the run, and recording it is what
    /// makes the absence durable rather than merely visible (Misfit N,
    /// NFR-009).
    ///
    /// A capability with no adapter at all has no acceptance to record: there
    /// is no mechanism to name, and inventing one would put a name in the log
    /// that never ran (FR-007).
    pub fn acceptance(&self) -> Option<CapabilityAcceptance> {
        let adapter = self.adapter.as_ref()?;
        if self.guarantee != GuaranteeLevel::None {
            return None;
        }
        Some(CapabilityAcceptance::new(
            self.capability,
            adapter.clone(),
            self.guarantee,
        ))
    }

    /// The disclosure `ksp status` renders for this capability.
    pub fn disclosure(&self) -> CapabilityDisclosure {
        CapabilityDisclosure {
            capability: self.capability,
            platform: PLATFORM.to_string(),
            configured_order: self.configured.clone(),
            requirement: Some(self.requirement),
            selected: self.adapter.clone(),
            guarantee: self.guarantee,
            skipped: self
                .skipped
                .iter()
                .map(|entry| (entry.adapter().clone(), entry.reason().to_string()))
                .collect(),
        }
    }
}

/// The capability as the configuration and the host leave it, with no decision.
///
/// Never refuses. `ksp status` is the caller: it reports an unconfigured or
/// unavailable capability rather than failing, because a host that cannot
/// confine still has to be able to say why (NFR-005).
pub fn disclosure(
    configuration: Option<&CapabilityConfiguration>,
    capability: HostCapability,
) -> CapabilityDisclosure {
    describe(configuration, capability, resolve_registry)
}

/// [`disclosure`], with the resolver supplied.
fn describe(
    configuration: Option<&CapabilityConfiguration>,
    capability: HostCapability,
    resolve: Resolve,
) -> CapabilityDisclosure {
    let configured: Vec<AdapterName> = configuration
        .map(|configuration| configuration.setting(capability).adapters.clone())
        .unwrap_or_default();
    // `None` only when there is no file: that is what separates "no
    // configuration" from "a configuration that names nothing this host
    // provides", which are two different fixes and used to render the same
    // sentence.
    let requirement =
        configuration.map(|configuration| configuration.setting(capability).requirement);

    let (selected, guarantee, skipped) = resolve(capability, &configured).map_or_else(
        |unavailable| {
            (
                None,
                GuaranteeLevel::None,
                unavailable
                    .reasons()
                    .iter()
                    .map(|entry| (entry.adapter().clone(), entry.reason().to_string()))
                    .collect(),
            )
        },
        |resolution| {
            (
                Some(resolution.selected().adapter().clone()),
                resolution.guarantee(),
                resolution
                    .skipped()
                    .iter()
                    .map(|entry| (entry.adapter().clone(), entry.reason().to_string()))
                    .collect(),
            )
        },
    );

    CapabilityDisclosure {
        capability,
        platform: PLATFORM.to_string(),
        configured_order: configured,
        requirement,
        selected,
        guarantee,
        skipped,
    }
}

/// Every capability's disclosure, in the closed set's order.
///
/// The status document carries all of them, so a reader compares like with
/// like: a capability that established nothing sits in the same shape as one
/// that did (FR-038).
pub fn disclosures(configuration: Option<&CapabilityConfiguration>) -> Vec<CapabilityDisclosure> {
    HostCapability::ALL
        .into_iter()
        .map(|capability| disclosure(configuration, capability))
        .collect()
}

/// The grant for `capability`, or the reason the run cannot proceed.
///
/// # Errors
///
/// - [`CapabilityError::Configuration`] when the file is malformed or unsafe.
///   The caller passes the configuration it already loaded, so this variant is
///   produced by [`load`] rather than here.
/// - [`CapabilityError::Unconfigured`] when no file exists.
/// - [`CapabilityError::NoAdapterNamed`] when the file names none for this
///   capability.
/// - [`CapabilityError::Unavailable`] when every named adapter is unavailable
///   on this host and the capability is required.
/// - [`CapabilityError::NotSatisfied`] when the selected adapter establishes
///   nothing and the capability is required (FR-035, Misfit M).
pub fn granted(
    configuration: Option<&CapabilityConfiguration>,
    capability: HostCapability,
) -> Result<Grant, CapabilityError> {
    granted_with(configuration, capability, resolve_registry)
}

/// [`granted`], with the resolver supplied.
///
/// The decision is a pure function of the configuration and the resolver's
/// answer, so a test can exercise the required/optional split and the
/// unconfigured case on any host — including the two the gate runs on, where
/// the real answer differs.
pub fn granted_with(
    configuration: Option<&CapabilityConfiguration>,
    capability: HostCapability,
    resolve: Resolve,
) -> Result<Grant, CapabilityError> {
    let Some(configuration) = configuration else {
        return Err(CapabilityError::Unconfigured { capability });
    };
    let setting: &CapabilitySetting = configuration.setting(capability);
    if setting.adapters.is_empty() {
        return Err(CapabilityError::NoAdapterNamed { capability });
    }

    let configured = setting.adapters.clone();
    match resolve(capability, &configured) {
        Err(unavailable) => {
            // An optional capability proceeds with nothing established
            // (FR-029); a required one refuses (FR-028).
            if setting.requirement == RequirementLevel::Required {
                return Err(CapabilityError::Unavailable {
                    capability,
                    reasons: unavailable.reasons().to_vec(),
                });
            }
            Ok(Grant {
                capability,
                requirement: setting.requirement,
                adapter: None,
                guarantee: GuaranteeLevel::None,
                configured,
                skipped: unavailable.reasons().to_vec(),
            })
        }
        Ok(resolution) => {
            // One check, from the resolver's own type, so no caller can
            // implement the required/optional rule differently.
            if !satisfies(resolution.guarantee(), setting.requirement) {
                return Err(CapabilityError::NotSatisfied {
                    capability,
                    requirement: setting.requirement,
                    adapter: resolution.selected().adapter().clone(),
                    guarantee: resolution.guarantee(),
                });
            }
            Ok(Grant {
                capability,
                requirement: setting.requirement,
                adapter: Some(resolution.selected().adapter().clone()),
                guarantee: resolution.guarantee(),
                configured,
                skipped: resolution.skipped().to_vec(),
            })
        }
    }
}

/// The adapter value for a grant, when one ran.
///
/// Kept here rather than at each call site so the two registries are reached
/// through one function, and a caller that receives a [`Grant`] cannot pick an
/// adapter the grant did not select.
pub fn confinement(grant: &Grant) -> Option<&'static dyn ksp_posture::ConfinementAdapter> {
    grant.adapter().and_then(confinement_adapter)
}

/// The barrier adapter a grant selected, when one ran.
pub fn barrier(grant: &Grant) -> Option<&'static dyn ksp_posture::MemoryBarrierAdapter> {
    grant.adapter().and_then(memory_barrier_adapter)
}

/// Whether this host provides the adapter's mechanism, for a disclosure.
///
/// The unreachable branch is the honest one: a name in the grant came from the
/// closed set, and the registry holds every name in it on every target. If the
/// two ever disagree the answer is "unavailable", because claiming a mechanism
/// that is not there is the failure the whole feature bans.
pub fn availability(capability: HostCapability, name: &AdapterName) -> AdapterAvailability {
    match capability {
        HostCapability::PathConfinement => {
            confinement_adapter(name).map_or_else(unavailable, |adapter| adapter.availability())
        }
        HostCapability::MemoryBarrier => {
            memory_barrier_adapter(name).map_or_else(unavailable, |adapter| adapter.availability())
        }
    }
}

/// The answer for an adapter the registry does not hold.
fn unavailable() -> AdapterAvailability {
    AdapterAvailability::Unavailable {
        reason: "this build has no adapter with that name".to_string(),
    }
}

/// Why a capability cannot be established.
///
/// Every variant names the configuration key and, where the host is the reason,
/// the host's own words. NFR-004 asks a refusal that names a capability to name
/// the adapter, the host's reason and the key that selected it. The key is
/// derived from the capability rather than restated, so the message cannot drift
/// from the table the reader parses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    /// The configuration file cannot be read, parsed or trusted.
    Configuration(ConfigurationRefusal),
    /// No configuration file exists, so no adapter is selected.
    Unconfigured {
        /// The capability the run needed.
        capability: HostCapability,
    },
    /// The configuration exists but names no adapter for the capability.
    NoAdapterNamed {
        /// The capability the run needed.
        capability: HostCapability,
    },
    /// Every adapter the configuration named is unavailable on this host.
    Unavailable {
        /// The capability the run needed.
        capability: HostCapability,
        /// Each named adapter the host refused, with the host's reason.
        reasons: Vec<SkippedAdapter>,
    },
    /// The selected adapter establishes nothing, and the capability is required.
    NotSatisfied {
        /// The capability the run needed.
        capability: HostCapability,
        /// The level the operator set.
        requirement: RequirementLevel,
        /// The adapter the host confirmed.
        adapter: AdapterName,
        /// What it establishes: always [`GuaranteeLevel::None`] here.
        guarantee: GuaranteeLevel,
    },
}

impl fmt::Display for CapabilityError {
    /// Every sentence names the capability, the configuration key and, where the
    /// host is the reason, the host's own words (NFR-004).
    ///
    /// Written out rather than derived: three of the five sentences call a
    /// helper, and a derive attribute that formatted a field through one is a
    /// footgun the next reader has to check the macro's rules to be sure about.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(refusal) => fmt::Display::fmt(refusal, f),
            Self::Unconfigured { capability } => write!(
                f,
                "the {} capability cannot be established: this host has no {} configuration, \
                 and no adapter is inferred from the host; run `ksp init` to write the \
                 strongest configuration this host can satisfy",
                capability.label(),
                capability.config_key(),
            ),
            Self::NoAdapterNamed { capability } => write!(
                f,
                "the {} capability cannot be established: {}.adapters is empty in the \
                 configuration, so nothing can establish it; name one of {} there",
                capability.label(),
                capability.config_key(),
                adapters_for(*capability).join(", "),
            ),
            Self::Unavailable {
                capability,
                reasons,
            } => write!(
                f,
                "the {} capability is required by {}.requirement and cannot be established \
                 on this host: {}",
                capability.label(),
                capability.config_key(),
                render_reasons(reasons),
            ),
            Self::NotSatisfied {
                capability,
                adapter,
                guarantee,
                ..
            } => write!(
                f,
                "the {} capability is required by {}.requirement = \"required\" and the \
                 selected adapter {} establishes nothing (guarantee {}); a required capability \
                 is never satisfied by an adapter that guarantees nothing — set the \
                 requirement to \"optional\" to accept the absence deliberately",
                capability.label(),
                capability.config_key(),
                adapter.as_str(),
                guarantee.label(),
            ),
        }
    }
}

impl std::error::Error for CapabilityError {}

impl CapabilityError {
    /// The exit class this refusal produces.
    ///
    /// A configuration the operator wrote wrong is a policy denial: the run is
    /// refused because the file says so. A file another principal can write is
    /// the boundary itself (FR-009), and a capability the host cannot establish
    /// is the host's answer — both exit as a capability refusal, which is the
    /// code whose sentence is about the host or the layout.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Configuration(refusal) => {
                if refusal.is_boundary_refusal() {
                    exit::CAPABILITY_REFUSAL
                } else {
                    exit::POLICY_DENIAL
                }
            }
            Self::Unconfigured { .. }
            | Self::NoAdapterNamed { .. }
            | Self::Unavailable { .. }
            | Self::NotSatisfied { .. } => exit::CAPABILITY_REFUSAL,
        }
    }
}

/// `adapter: reason; adapter: reason`, in the configuration's order.
fn render_reasons(reasons: &[SkippedAdapter]) -> String {
    if reasons.is_empty() {
        return "no adapter was tried".to_string();
    }
    reasons
        .iter()
        .map(|entry| format!("{}: {}", entry.name(), entry.reason()))
        .collect::<Vec<_>>()
        .join("; ")
}

impl fmt::Display for Grant {
    /// The one-line rendering a view prints for a resolved capability.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.disclosure(), f)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use ksp_types::capability_config::CapabilitySetting;

    fn name(value: &str) -> AdapterName {
        AdapterName::parse(value).expect("a name in the closed set parses")
    }

    /// A configuration with one capability's setting and the other's left
    /// harmless.
    fn configured(
        capability: HostCapability,
        adapters: &[&str],
        requirement: RequirementLevel,
    ) -> CapabilityConfiguration {
        let setting = CapabilitySetting {
            adapters: adapters.iter().map(|value| name(value)).collect(),
            requirement,
        };
        match capability {
            HostCapability::PathConfinement => CapabilityConfiguration {
                confinement: setting,
                memory_barrier: CapabilitySetting {
                    adapters: vec![name("mlock")],
                    requirement: RequirementLevel::Optional,
                },
            },
            HostCapability::MemoryBarrier => CapabilityConfiguration {
                confinement: CapabilitySetting {
                    adapters: vec![name("portable_confinement")],
                    requirement: RequirementLevel::Optional,
                },
                memory_barrier: setting,
            },
        }
    }

    /// A resolver where Landlock is the only available confinement adapter.
    ///
    /// A `fn` pointer cannot capture, so the host is fixed here rather than
    /// passed in. The decision under test is the required/optional split, which
    /// does not depend on *which* adapter is available — only on whether one is.
    fn resolve_only_landlock(
        capability: HostCapability,
        preference: &[AdapterName],
    ) -> Result<Resolution, UnavailableCapability> {
        let available = |named: &AdapterName| -> Option<AdapterAvailability> {
            if named.as_str() == "landlock" && capability == HostCapability::PathConfinement {
                Some(AdapterAvailability::Available)
            } else {
                Some(AdapterAvailability::Unavailable {
                    reason: "this host does not provide it".to_string(),
                })
            }
        };
        ksp_posture::resolve_with(capability, preference, available)
    }

    #[test]
    fn no_configuration_is_a_refusal_that_names_ksp_init() {
        let error = granted(None, HostCapability::PathConfinement)
            .expect_err("an absent configuration selects no adapter");
        assert!(matches!(error, CapabilityError::Unconfigured { .. }));
        let text = error.to_string();
        assert!(text.contains("ksp init"), "{text}");
        assert!(text.contains("confinement"), "{text}");
        assert_eq!(error.exit_code(), exit::CAPABILITY_REFUSAL);
    }

    #[test]
    fn an_empty_list_is_a_different_refusal_from_a_missing_file() {
        // CF-021: a value must not state a fact it was never told. The two
        // cases have different fixes, so they have different sentences.
        let configuration = configured(
            HostCapability::PathConfinement,
            &[],
            RequirementLevel::Required,
        );
        let error = granted(Some(&configuration), HostCapability::PathConfinement)
            .expect_err("an empty list cannot establish anything");
        assert!(matches!(error, CapabilityError::NoAdapterNamed { .. }));
        let text = error.to_string();
        assert!(text.contains("landlock, portable_confinement"), "{text}");
        assert!(!text.contains("ksp init"), "{text}");
    }

    #[test]
    fn an_unavailable_required_capability_refuses_with_the_hosts_reason() {
        let configuration = configured(
            HostCapability::PathConfinement,
            &["portable_confinement"],
            RequirementLevel::Required,
        );
        let error = granted_with(
            Some(&configuration),
            HostCapability::PathConfinement,
            resolve_only_landlock,
        )
        .expect_err("a required capability the host refuses must refuse the run");
        assert!(matches!(error, CapabilityError::Unavailable { .. }));
        let text = error.to_string();
        assert!(text.contains("portable_confinement"), "{text}");
        assert!(text.contains("this host does not provide it"), "{text}");
        assert!(text.contains("confinement.requirement"), "{text}");
    }

    #[test]
    fn an_unavailable_optional_capability_proceeds_with_nothing_established() {
        let configuration = configured(
            HostCapability::PathConfinement,
            &["portable_confinement"],
            RequirementLevel::Optional,
        );
        let grant = granted_with(
            Some(&configuration),
            HostCapability::PathConfinement,
            resolve_only_landlock,
        )
        .expect("an optional capability proceeds");
        assert_eq!(grant.adapter(), None);
        assert_eq!(grant.guarantee(), GuaranteeLevel::None);
        assert!(!grant.established());
        // No adapter ran, so there is nothing to record an acceptance
        // against: a name in the log that never ran is the failure FR-007
        // bans.
        assert_eq!(grant.acceptance(), None);
    }

    #[test]
    fn a_none_guarantee_never_satisfies_required() {
        let configuration = configured(
            HostCapability::PathConfinement,
            &["portable_confinement"],
            RequirementLevel::Required,
        );
        // The real resolver: `portable_confinement` is available everywhere and
        // guarantees nothing, which is the whole of Misfit M.
        let error = granted(Some(&configuration), HostCapability::PathConfinement)
            .expect_err("a no-op never satisfies a required capability");
        assert!(matches!(error, CapabilityError::NotSatisfied { .. }));
        let text = error.to_string();
        assert!(text.contains("portable_confinement"), "{text}");
        assert!(text.contains("guarantee none"), "{text}");
        assert!(text.contains("optional"), "{text}");
    }

    #[test]
    fn an_optional_none_guarantee_proceeds_and_records_the_acceptance() {
        let configuration = configured(
            HostCapability::PathConfinement,
            &["portable_confinement"],
            RequirementLevel::Optional,
        );
        let grant = granted(Some(&configuration), HostCapability::PathConfinement)
            .expect("an optional absence proceeds");
        assert!(grant.adapter().is_some());
        assert!(!grant.established());
        let acceptance = grant
            .acceptance()
            .expect("an accepted absence is recorded, or it is merely visible");
        assert_eq!(acceptance.capability, HostCapability::PathConfinement);
        assert_eq!(acceptance.adapter.as_str(), "portable_confinement");
        assert_eq!(acceptance.guarantee, GuaranteeLevel::None);
    }

    #[test]
    fn a_weakened_guarantee_records_no_acceptance() {
        // `mlock` is a real mechanism with a smaller guarantee, so it is not an
        // absence and does not need an acceptance recorded against it.
        let configuration = configured(
            HostCapability::MemoryBarrier,
            &["mlock"],
            RequirementLevel::Required,
        );
        let grant = granted(Some(&configuration), HostCapability::MemoryBarrier)
            .expect("the real mlock adapter is available on both gate hosts");
        assert_eq!(grant.guarantee(), GuaranteeLevel::Weakened);
        assert!(grant.established());
        assert_eq!(grant.acceptance(), None);
    }

    #[test]
    fn the_configured_order_is_carried_into_the_disclosure() {
        let configuration = configured(
            HostCapability::PathConfinement,
            &["portable_confinement", "landlock"],
            RequirementLevel::Optional,
        );
        let disclosure = self::disclosure(Some(&configuration), HostCapability::PathConfinement);
        assert_eq!(
            disclosure
                .configured_order
                .iter()
                .map(AdapterName::as_str)
                .collect::<Vec<_>>(),
            vec!["portable_confinement", "landlock"],
        );
        assert_eq!(disclosure.platform, PLATFORM);
        // The order is the preference: `portable_confinement` is available
        // everywhere, so it runs and `landlock` is never asked.
        assert_eq!(
            disclosure.selected.as_ref().map(AdapterName::as_str),
            Some("portable_confinement")
        );
    }

    #[test]
    fn an_unconfigured_disclosure_names_no_adapter() {
        let disclosure = self::disclosure(None, HostCapability::MemoryBarrier);
        assert!(!disclosure.is_configured());
        assert!(disclosure.configured_order.is_empty());
        assert_eq!(disclosure.guarantee, GuaranteeLevel::None);
    }

    #[test]
    fn the_build_contains_an_adapter_for_every_capability_on_every_target() {
        for capability in HostCapability::ALL {
            assert!(
                !adapters_for(capability).is_empty(),
                "{capability:?} must have an adapter on every target (FR-018, NFR-007)"
            );
        }
    }

    #[test]
    fn the_adapter_hint_matches_the_capability_the_registry_partitions() {
        // The hint FR-010 prints must not name an adapter the capability does
        // not accept, or the operator's fix is refused when they apply it.
        for capability in HostCapability::ALL {
            for name in adapters_for(capability) {
                let parsed = AdapterName::parse(name).expect("in the closed set");
                assert_eq!(capability_of(parsed.kind()), capability);
            }
        }
    }
}
