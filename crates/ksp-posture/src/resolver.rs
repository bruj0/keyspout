//! The resolver and the requirement check.
//!
//! Two decisions, kept apart:
//!
//! - **The resolver** answers *which adapter runs*. It walks the configured
//!   preference list in order and takes the first one the host confirms.
//! - **The requirement check** answers *whether the run may proceed*. It
//!   compares the selected adapter's guarantee against the configured
//!   requirement level.
//!
//! The split is structural rather than a convention: the resolver has no
//! parameter for the requirement level and the check has no parameter for a
//! preference list. A caller that wants "may this run proceed?" must call
//! both, and cannot get a half-decided answer out of either.
//!
//! # The order is the preference
//!
//! The configuration's order is the operator's ranking, and the resolver walks
//! it as written. It never sorts by guarantee level: doing so would silently
//! promote an adapter the operator ranked *below* another, which is the
//! downgrade path Misfit D exists to close.
//!
//! # Nothing is inferred from the host
//!
//! NFR-006: an adapter runs because the configuration named it and the host
//! confirmed it — never because the host happens to offer it. So an empty
//! preference list is a refusal, not an invitation to pick whatever the host
//! has. The first-run probe (WP07) is the one exception, and it writes its
//! selection to the configuration file, where the operator can read it and
//! change it.
//!
//! # The skipped list is part of the result
//!
//! A silent fallback is only invisible because the disclosure is missing
//! (Misfit B). The skipped list is what lets the disclosure say *why* the first
//! choice did not run, and each entry carries the **host's** reason rather
//! than a generic "not supported" — the operator decides whether to fix it
//! from the text.

use std::fmt;

use ksp_types::{
    AdapterAvailability, AdapterName, GuaranteeLevel, HostCapability, RequirementLevel,
};

use crate::adapters::{confinement_adapter, memory_barrier_adapter};

/// The adapter the resolver selected, and what it did not.
///
/// The skipped list is not a log line. It is part of the result because the
/// disclosure surface reads it and has nowhere else to get the fact: a
/// disclosure that says "ran `sealed_memfd`" without saying why `memfd_secret`
/// did not run is the silent fallback Misfit A describes.
///
/// # Why the two capabilities share one type
///
/// The plan's `Resolution` holds a `&'static dyn ConfinementAdapter`, so it
/// names one capability's trait. A shared type that held *either* trait would
/// need a supertrait, and the two traits have no method in common — they
/// establish different things. So this type holds the facts both capabilities
/// have in common: the selected adapter's **name** and its **guarantee**, plus
/// the skipped list.
///
/// The selected adapter's *behaviour* is reached through the capability's own
/// registry, by name. That keeps one type for both capabilities without
/// pretending the two traits are the same, and it keeps the resolution free
/// of a lifetime parameter — the registry hands out `&'static` adapters, so
/// the caller can always get the adapter back from the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    capability: HostCapability,
    selected: SelectedAdapter,
    skipped: Vec<SkippedAdapter>,
}

/// The adapter that was resolver selected, and what it guarantees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedAdapter {
    name: AdapterName,
    guarantee: GuaranteeLevel,
}

impl SelectedAdapter {
    /// The selected adapter's stable identifier.
    pub fn name(&self) -> &'static str {
        self.name.as_str()
    }

    /// The selected adapter's name, as the closed type.
    ///
    /// The name is an [`AdapterName`], so a caller that carries it onward
    /// carries the closure with it.
    pub fn adapter(&self) -> &AdapterName {
        &self.name
    }

    /// What the adapter establishes for its capability.
    ///
    /// The adapter's **own** level, never the level of a stronger adapter the
    /// operator preferred (FR-030). A run that fell back to `sealed_memfd`
    /// must report the fallback's guarantee, or the disclosure describes a
    /// mechanism that did not run.
    pub fn guarantee(&self) -> GuaranteeLevel {
        self.guarantee
    }
}

/// An adapter that did not run, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedAdapter {
    name: AdapterName,
    reason: String,
}

impl SkippedAdapter {
    /// An adapter that did not run, and the host's reason.
    ///
    /// Public so a caller that builds a refusal by hand — the probe (WP07)
    /// reports an unavailable capability the same way — can name the adapter
    /// and its reason without inventing a parallel type.
    ///
    /// The name is an [`AdapterName`], so it can only name an adapter in the
    /// closed set. A refusal therefore cannot quote a mechanism that does not
    /// exist.
    pub fn new(name: AdapterName, reason: impl Into<String>) -> Self {
        Self {
            name,
            reason: reason.into(),
        }
    }

    /// The adapter's stable identifier.
    pub fn name(&self) -> &'static str {
        self.name.as_str()
    }

    /// The adapter's name, as the closed type.
    pub fn adapter(&self) -> &AdapterName {
        &self.name
    }

    /// The host's reason.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl Resolution {
    /// The capability this resolution is for.
    pub fn capability(&self) -> HostCapability {
        self.capability
    }

    /// The selected adapter.
    pub fn selected(&self) -> &SelectedAdapter {
        &self.selected
    }

    /// The selected adapter's stable identifier.
    pub fn selected_name(&self) -> &'static str {
        self.selected.name()
    }

    /// What the selected adapter establishes.
    pub fn guarantee(&self) -> GuaranteeLevel {
        self.selected.guarantee()
    }

    /// The adapters that did not run, each with the host's reason.
    ///
    /// The order is the configured order, so a reader can compare this list
    /// against the configuration line by line.
    pub fn skipped(&self) -> &[SkippedAdapter] {
        &self.skipped
    }

    /// The names of the adapters that did not run.
    pub fn skipped_names(&self) -> Vec<&'static str> {
        self.skipped.iter().map(|entry| entry.name()).collect()
    }

    /// Whether the run may proceed under `requirement`.
    ///
    /// The check, applied to what the resolver selected. It lives here as well
    /// as in [`satisfies`] so a caller holding a resolution does not have to
    /// remember to make the second call.
    pub fn satisfies(&self, requirement: RequirementLevel) -> bool {
        satisfies(self.guarantee(), requirement)
    }
}

/// Why a capability could not be established.
///
/// The refusal names the capability and every adapter the resolver could not
/// use with the host's reason.
///
/// # It carries no requirement level, and that is deliberate
///
/// The resolver receives the adapter list and nothing else, so it does not know
/// whether the configuration marked the capability `required` or `optional`. A
/// refusal that carried a level would have to guess, and guessing `required`
/// produces a **false claim about the operator's own configuration** — the
/// message would say "the path confinement capability is required but cannot
/// be established" for a capability the operator marked optional, on exactly
/// the path FR-029 governs.
///
/// So the level is not here. It belongs to the caller, which read the
/// configuration and knows it. The caller decides whether an unavailable
/// capability refuses the run (FR-028) or weakens the posture and continues
/// (FR-029), and it says so in its own message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnavailableCapability {
    capability: HostCapability,
    reasons: Vec<SkippedAdapter>,
}

impl UnavailableCapability {
    /// A refusal for `capability`, with each rejected adapter and the host's
    /// reason.
    pub fn for_capability(capability: HostCapability, reasons: Vec<SkippedAdapter>) -> Self {
        Self {
            capability,
            reasons,
        }
    }

    /// The capability that could not be established.
    pub fn capability(&self) -> HostCapability {
        self.capability
    }

    /// Each adapter the resolver could not use, with the host's reason.
    pub fn reasons(&self) -> &[SkippedAdapter] {
        &self.reasons
    }
}

impl fmt::Display for UnavailableCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No requirement level: the resolver does not know it, and naming one
        // would state something about the operator's configuration that this
        // value cannot support.
        write!(
            f,
            "the {} capability cannot be established on this host",
            self.capability.label()
        )?;
        if self.reasons.is_empty() {
            // No adapter was named at all, which is a different problem from
            // an adapter the host cannot provide. The two need different
            // sentences: one is a missing configuration, the other is a
            // missing mechanism (Misfit C and Misfit E interact).
            write!(f, ": no adapter is configured for it")?;
            return Ok(());
        }
        for entry in &self.reasons {
            write!(f, "; {}: {}", entry.name(), entry.reason())?;
        }
        Ok(())
    }
}

impl std::error::Error for UnavailableCapability {}

/// Resolves the path-confinement capability against `preference`.
///
/// The list is walked in order. Each named adapter is asked for its
/// availability, and the first one the host confirms is selected. The rest are
/// recorded as skipped with the host's reason.
///
/// The resolver asks the **adapter** for availability; it never decides
/// availability itself. The probe (WP07) reads the same fact through the same
/// path, and the two must not disagree on a host.
///
/// # What it does not do
///
/// It does not reorder the list, and it does not consult an adapter the
/// configuration did not name. An empty list is a refusal: the capability is
/// unconfigured, and inferring an adapter from the host would be exactly the
/// inference NFR-006 forbids.
///
/// # The refusal carries no requirement level
///
/// The resolver receives the adapter list and nothing else, so it does not
/// know whether the configuration marked the capability `required` or
/// `optional`. The refusal it produces therefore names the capability and the
/// host's reasons and says nothing about the requirement — the caller read the
/// configuration and knows the level, and it decides whether an unavailable
/// capability refuses (FR-028) or weakens the posture and continues (FR-029).
///
/// A refusal that guessed the level would state something false about the
/// operator's own configuration.
pub fn resolve_confinement(
    preference: &[AdapterName],
) -> Result<Resolution, UnavailableCapability> {
    resolve_with(HostCapability::PathConfinement, preference, |named| {
        confinement_adapter(named).map(|adapter| adapter.availability())
    })
}

/// Resolves the memory-barrier capability against `preference`.
///
/// The same shape as [`resolve_confinement`], over the barrier registry and
/// the barrier trait. The two are separate functions rather than one generic
/// one because the two adapter traits are separate: a single generic resolver
/// would have to name both, and the result type would name the wrong one for
/// half its uses.
pub fn resolve_memory_barrier(
    preference: &[AdapterName],
) -> Result<Resolution, UnavailableCapability> {
    resolve_with(HostCapability::MemoryBarrier, preference, |named| {
        memory_barrier_adapter(named).map(|adapter| adapter.availability())
    })
}

/// The resolver's algorithm, over a supplied availability.
///
/// # Why the availability is a parameter
///
/// The algorithm — *walk the list in order, take the first the host confirms* —
/// is the thing that must be right, and it must be right on every host. A test
/// that exercises it only against the running host exercises it only on the
/// hosts that happen to be available: a host where every adapter works proves
/// nothing about the case where the first one does not, and a host where every
/// adapter is missing proves nothing about the case where one works.
///
/// So the algorithm takes the availability as a parameter, and the two public
/// functions supply the real one — the one that asks the adapter. The
/// production path is unchanged: the closure asks the **adapter**, and the
/// resolver never decides availability itself.
///
/// `None` means the build holds no adapter with that name at all, which is a
/// different fact from "the host cannot provide it" (Misfit C and Misfit E
/// interact) and gets a different sentence.
///
/// # It is public so the algorithm can be tested against every host
///
/// The test that matters is the one that says "the first entry is unavailable,
/// so the second runs" — and that has to hold on a host where the first entry
/// *is* available too. A caller can supply the availability it wants and get
/// the same algorithm the production path uses.
pub fn resolve_with<F>(
    capability: HostCapability,
    preference: &[AdapterName],
    availability: F,
) -> Result<Resolution, UnavailableCapability>
where
    F: Fn(&AdapterName) -> Option<AdapterAvailability>,
{
    let mut skipped: Vec<SkippedAdapter> = Vec::new();

    for named in preference {
        let Some(answer) = availability(named) else {
            skipped.push(SkippedAdapter {
                name: named.clone(),
                reason: format!(
                    "this build has no {} adapter named {}",
                    capability.label(),
                    named.as_str()
                ),
            });
            continue;
        };

        match answer {
            AdapterAvailability::Available => {
                return Ok(Resolution {
                    capability,
                    selected: SelectedAdapter {
                        name: named.clone(),
                        guarantee: guarantee_of(capability, named),
                    },
                    skipped,
                });
            }
            AdapterAvailability::Unavailable { reason } => {
                skipped.push(SkippedAdapter {
                    name: named.clone(),
                    reason,
                });
            }
        }
    }

    Err(UnavailableCapability::for_capability(capability, skipped))
}

/// The guarantee level the named adapter establishes for `capability`.
///
/// Read from the adapter rather than assumed, so the resolution reports the
/// adapter's **own** claim and never the level of a stronger adapter the
/// operator preferred (FR-030).
fn guarantee_of(capability: HostCapability, named: &AdapterName) -> GuaranteeLevel {
    match capability {
        HostCapability::PathConfinement => confinement_adapter(named)
            .map(|adapter| adapter.guarantee())
            .unwrap_or(GuaranteeLevel::None),
        HostCapability::MemoryBarrier => memory_barrier_adapter(named)
            .map(|adapter| adapter.guarantee())
            .unwrap_or(GuaranteeLevel::None),
    }
}

/// Whether the run may proceed with `guarantee` under `requirement`.
///
/// One function, so no caller can implement the check differently.
///
/// # What the question is
///
/// It asks *may the run proceed*, not *was the capability established*. The
/// two are different questions and the requirement level is what separates
/// them:
///
/// - `Required` and the guarantee is `None` → **false**. An adapter that
///   establishes no mechanism satisfies nothing, whatever the configuration
///   named (FR-035, Misfit M). The operator who wrote `required` never meant
///   "required, but nothing".
/// - `Optional` and the guarantee is `None` → **true**. The run proceeds and
///   the disclosure reports that the capability established nothing
///   (FR-036). The requirement level is a policy about the *run*, not about the
///   mechanism.
/// - Either level and the guarantee is `Full` or `Weakened` → **true**. A real
///   mechanism satisfies both levels.
///
/// The "established nothing" report comes from the guarantee level the
/// resolution carries, not from this boolean. A caller that only gets `false`
/// learns that the run must not proceed; a caller that also reads the
/// resolution's guarantee learns *why*.
///
/// # Why `Optional` is not "anything goes"
///
/// It changes whether the run refuses. It does not turn a `None` guarantee
/// into an enforced capability, and it does not make a `Weakened` mechanism
/// read as `Full` (FR-020, FR-030). Those are the level's job, and the level
/// travels with the resolution.
pub fn satisfies(guarantee: GuaranteeLevel, requirement: RequirementLevel) -> bool {
    match requirement {
        // A required capability needs a mechanism. `None` is not a weaker
        // mechanism; it is the absence of one.
        RequirementLevel::Required => guarantee != GuaranteeLevel::None,
        // An optional capability proceeds either way. What established nothing
        // is reported, not refused.
        RequirementLevel::Optional => true,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn name(value: &str) -> AdapterName {
        AdapterName::parse(value).expect("a name in the closed set parses")
    }

    #[test]
    fn a_none_guarantee_never_satisfies_required() {
        assert!(!satisfies(GuaranteeLevel::None, RequirementLevel::Required));
    }

    #[test]
    fn a_weakened_guarantee_satisfies_required() {
        assert!(satisfies(
            GuaranteeLevel::Weakened,
            RequirementLevel::Required
        ));
    }

    #[test]
    fn a_full_guarantee_satisfies_both_levels() {
        assert!(satisfies(GuaranteeLevel::Full, RequirementLevel::Required));
        assert!(satisfies(GuaranteeLevel::Full, RequirementLevel::Optional));
    }

    /// FR-036: an optional capability whose adapter established nothing still
    /// lets the run proceed. The disclosure says it established nothing; the
    /// run is not refused for it.
    #[test]
    fn an_optional_capability_proceeds_even_when_nothing_was_established() {
        assert!(satisfies(GuaranteeLevel::None, RequirementLevel::Optional));
    }

    /// The two levels must disagree, or the requirement level would be a
    /// constant in the code path — which is exactly what FR-027 forbids.
    #[test]
    fn the_requirement_level_changes_the_answer() {
        assert_ne!(
            satisfies(GuaranteeLevel::None, RequirementLevel::Required),
            satisfies(GuaranteeLevel::None, RequirementLevel::Optional),
            "the requirement level must decide whether a `none` guarantee is \
             refused or merely reported"
        );
    }

    #[test]
    fn the_empty_list_is_a_refusal_with_no_reasons() {
        let refusal = resolve_confinement(&[]).expect_err("an empty list must refuse");
        assert!(refusal.reasons().is_empty());
        assert_eq!(refusal.capability(), HostCapability::PathConfinement);
    }

    #[test]
    fn the_refusal_text_names_the_capability_and_the_adapter() {
        let refusal = UnavailableCapability::for_capability(
            HostCapability::MemoryBarrier,
            vec![SkippedAdapter::new(
                AdapterName::parse("memfd_secret").expect("in the closed set"),
                "no such syscall here",
            )],
        );
        let rendered = refusal.to_string();
        assert!(rendered.contains("memory barrier"), "{rendered}");
        assert!(rendered.contains("memfd_secret"), "{rendered}");
        // The resolver was never told the requirement level, so the refusal
        // must not state one: claiming "required" for a capability the
        // operator marked optional would be a false claim about their own
        // configuration.
        assert!(!rendered.contains("required"), "{rendered}");
        assert!(!rendered.contains("optional"), "{rendered}");
    }

    #[test]
    fn a_refusal_with_no_adapter_named_says_so() {
        let refusal =
            UnavailableCapability::for_capability(HostCapability::PathConfinement, Vec::new());
        assert!(
            refusal.to_string().contains("no adapter is configured"),
            "an unconfigured capability and a missing mechanism need different \
             sentences; got: {refusal}"
        );
    }

    /// The portable adapter is always available, so it is always selected when
    /// it is the only entry. Its guarantee is `None`, which is the whole of
    /// Misfit M.
    #[test]
    fn the_portable_adapter_is_selected_and_guarantees_nothing() {
        let resolution =
            resolve_confinement(&[name("portable_confinement")]).expect("it is always available");
        assert_eq!(resolution.selected_name(), "portable_confinement");
        assert_eq!(resolution.guarantee(), GuaranteeLevel::None);
        assert!(
            !resolution.satisfies(RequirementLevel::Required),
            "a portable adapter must not satisfy a required capability"
        );
        assert!(
            resolution.satisfies(RequirementLevel::Optional),
            "an optional capability proceeds, and the disclosure reports that \
             nothing was established"
        );
    }
}
