//! The resolver and the requirement check.
//!
//! Two decisions live here, and they are kept apart on purpose:
//!
//! - **The resolver** answers *which adapter runs*. It walks the configured
//!   preference list in order and takes the first one the host confirms.
//! - **The requirement check** answers *whether that is enough*. It compares
//!   the selected adapter's guarantee against the configured requirement
//!   level.
//!
//! Conflating them would put a `Required`/`Optional` decision inside the
//! walk, and a caller that reached for the resolver to answer "may this run
//! proceed?" would get a half-decided answer. The resolver resolves; the
//! requirement check judges.
//!
//! # The property that makes the order meaningful
//!
//! The configuration's order is the operator's preference. The resolver walks
//! it and never reorders it, so a host that provides the first entry never
//! reaches the second — and a host that does not provide the first entry
//! reaches the second *without* the operator's intent being changed. Sorting
//! the list by guarantee level would silently promote an adapter the operator
//! ranked below another.
//!
//! # Why the skipped list is part of the result
//!
//! A silent fallback is only invisible because the disclosure is missing
//! (Misfit B). The skipped list is what lets the disclosure say *why* the
//! first choice did not run, and it carries the **host's** reason rather than
//! a generic "not supported" — the operator decides whether to fix it from
//! the text.
//!
//! # What these tests assert against
//!
//! Every assertion is against a value the resolver produced or against an
//! independent fact about the host. A test that compared the resolver's
//! answer against another value the same expression produced could not fail
//! (CF-014).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_posture::adapters::{
    ConfinementAdapter, MemoryBarrierAdapter, confinement_adapter, memory_barrier_adapter,
};
use ksp_posture::resolver::{
    SkippedAdapter, UnavailableCapability, resolve_confinement, resolve_memory_barrier,
    resolve_with, satisfies,
};
use ksp_types::{
    AdapterAvailability, AdapterName, GuaranteeLevel, HostCapability, RequirementLevel,
};

/// The name, as the configuration file spells it.
fn name(value: &str) -> AdapterName {
    AdapterName::parse(value).expect("a name in the closed set parses")
}

/// The preference list, in the operator's order.
fn preference(values: &[&str]) -> Vec<AdapterName> {
    values.iter().map(|value| name(value)).collect()
}

/// The barrier adapter for `value`.
fn barrier(value: &str) -> &'static dyn MemoryBarrierAdapter {
    memory_barrier_adapter(&name(value))
        .unwrap_or_else(|| panic!("{value} must be in this build on every target"))
}

/// The confinement adapter for `value`.
fn confinement(value: &str) -> &'static dyn ConfinementAdapter {
    confinement_adapter(&name(value))
        .unwrap_or_else(|| panic!("{value} must be in this build on every target"))
}

// ---------------------------------------------------------------------------
// The availability of each adapter on this host
// ---------------------------------------------------------------------------

/// What this host provides, read from the adapters themselves.
///
/// The tests below compare the resolver's answers against this, so the
/// expectation is never derived from the resolver's own output.
fn host_provides(value: &str) -> bool {
    let adapter_name = name(value);
    if let Some(adapter) = confinement_adapter(&adapter_name) {
        return adapter.availability().is_available();
    }
    if let Some(adapter) = memory_barrier_adapter(&adapter_name) {
        return adapter.availability().is_available();
    }
    panic!("{value} is in no registry");
}

// ---------------------------------------------------------------------------
// The order is the preference
// ---------------------------------------------------------------------------

/// The resolver selects the **first** available adapter in the configured
/// order, and the order it selected is the order it was given.
///
/// The assertion is on the selected adapter's *name*, against the list the
/// resolver reports it considered. A resolver that sorted by guarantee level
/// would pass on a host where the strongest happens to be first, and fail
/// here.
#[test]
fn the_resolver_selects_the_first_available_adapter_in_the_configured_order() {
    // The confinement list from the plan's configuration example.
    let list = preference(&["landlock", "portable_confinement"]);
    let resolution = resolve_confinement(&list).expect("the portable adapter is always available");

    // The portable adapter is always available, so it is selected on any host
    // where Landlock is absent. Where Landlock *is* present, Landlock is
    // selected instead. Either way the selection is the first available
    // entry, not the strongest one.
    let expected = if host_provides("landlock") {
        "landlock"
    } else {
        "portable_confinement"
    };
    assert_eq!(
        resolution.selected_name(),
        expected,
        "the resolver must take the first available entry, not the strongest one"
    );
}

/// A list whose first entry is unavailable selects the second.
///
/// This is Misfit A in its general form: the operator named two adapters in
/// order, the host confirmed the second, and the second is what runs. The
/// first is recorded as skipped with the host's reason.
///
/// # The availability is supplied, not read from the host
///
/// The property is "the first available entry wins, in the configured
/// order", and it has to hold on every host — including one where the first
/// entry *is* available. A test that reads the running host exercises only
/// whichever case that host happens to be, so the algorithm is driven with a
/// supplied availability instead. The public `resolve_confinement` path is
/// checked separately, against the real adapters.
#[test]
fn an_unavailable_first_entry_selects_the_second() {
    let list = preference(&["landlock", "portable_confinement"]);

    // The host cannot provide Landlock, and can provide the portable
    // adapter.
    let resolution = resolve_with(HostCapability::PathConfinement, &list, |named| match named
        .as_str()
    {
        "landlock" => Some(AdapterAvailability::Unavailable {
            reason: "this host has no Landlock".to_string(),
        }),
        _ => Some(AdapterAvailability::Available),
    })
    .expect("the second entry is available");

    assert_eq!(
        resolution.selected_name(),
        "portable_confinement",
        "the second entry must be selected when the first is unavailable"
    );
    assert_eq!(
        resolution.skipped_names(),
        vec!["landlock"],
        "the skipped entry must be recorded, so the disclosure can say why the \
         first choice did not run"
    );
    assert_eq!(
        resolution.skipped()[0].reason(),
        "this host has no Landlock",
        "the skipped entry must carry the host's own reason"
    );
}

/// The first available entry wins, whatever the host provides.
///
/// The other half of the same property: where the first entry *is* available,
/// it is selected and the second is never reached. A resolver that always took
/// the last available entry would pass the test above.
#[test]
fn the_first_available_entry_wins_and_the_later_ones_are_not_reached() {
    let list = preference(&["landlock", "portable_confinement"]);

    let resolution = resolve_with(HostCapability::PathConfinement, &list, |_| {
        Some(AdapterAvailability::Available)
    })
    .expect("the first entry is available");

    assert_eq!(
        resolution.selected_name(),
        "landlock",
        "the first available entry must win"
    );
    assert!(
        resolution.skipped().is_empty(),
        "an entry after the selected one was never consulted, so it was never \
         skipped: {:?}",
        resolution.skipped_names()
    );
}

/// A list whose every entry is unavailable is a refusal, carrying each
/// reason.
///
/// The availability is supplied, so the case is established on every host.
#[test]
fn a_list_whose_every_entry_is_unavailable_is_a_refusal() {
    let list = preference(&["memfd_secret", "sealed_memfd", "mlock"]);

    let refusal = resolve_with(HostCapability::MemoryBarrier, &list, |named| {
        Some(AdapterAvailability::Unavailable {
            reason: format!("this host does not provide {}", named.as_str()),
        })
    })
    .expect_err("no named adapter is available, so the capability is unavailable");

    assert_eq!(
        refusal.capability(),
        HostCapability::MemoryBarrier,
        "the refusal must name the capability"
    );
    for entry in refusal.reasons() {
        assert!(
            entry.reason().contains(entry.name()),
            "each rejected adapter must carry its own reason; got: {entry:?}"
        );
    }
    assert_eq!(
        refusal.reasons().len(),
        3,
        "every rejected adapter must be carried, not just the first"
    );
}

/// The resolver never selects an adapter the configuration did not name.
///
/// NFR-006: an adapter runs because the configuration named it and the host
/// confirmed it — never because the host happens to offer it. The assertion
/// is that the selected adapter is one of the named entries, checked against
/// the list the caller passed in.
#[test]
fn the_resolver_never_selects_an_adapter_the_configuration_did_not_name() {
    // A list naming only the portable adapter. On a host with Landlock, a
    // resolver that inferred from the host would select Landlock instead.
    let list = preference(&["portable_confinement"]);
    let resolution = resolve_confinement(&list).expect("the portable adapter is always available");

    assert_eq!(
        resolution.selected_name(),
        "portable_confinement",
        "the resolver must not infer an adapter the configuration did not name"
    );
    assert!(
        resolution.skipped().is_empty(),
        "no adapter was skipped, so none can have been inferred: {:?}",
        resolution.skipped_names()
    );
}

/// Every name the resolver reports — selected or skipped — is one the
/// configuration named.
///
/// This is the *other* half of the inference check, and it needs a
/// non-empty skipped list to say anything: on a list whose first entry is
/// available the skipped list is empty, so a loop over it never runs and the
/// assertion inside it proves nothing. The availability is therefore supplied,
/// so the list is populated on every host.
///
/// The first version of this assertion looped over the skipped list of a
/// single-entry list. That list is always empty, so the loop body was dead
/// code: instrumenting it with an unconditional panic did not fail the test.
#[test]
fn every_name_the_resolution_reports_is_one_the_configuration_named() {
    let list = preference(&["landlock", "portable_confinement"]);

    // The first entry is unavailable, so the resolver skips it and the list is
    // populated on every host.
    let resolution = resolve_with(HostCapability::PathConfinement, &list, |named| match named
        .as_str()
    {
        "landlock" => Some(AdapterAvailability::Unavailable {
            reason: "this host has no Landlock".to_string(),
        }),
        _ => Some(AdapterAvailability::Available),
    })
    .expect("the second entry is available");

    // The list must be populated, or the loop below says nothing.
    assert_eq!(
        resolution.skipped_names(),
        vec!["landlock"],
        "the skipped list must be populated for this check to mean anything"
    );

    for name in resolution
        .skipped_names()
        .iter()
        .copied()
        .chain([resolution.selected_name()])
    {
        assert!(
            list.iter().any(|named| named.as_str() == name),
            "{name} was reported but was never named"
        );
    }
}

// ---------------------------------------------------------------------------
// The empty list is a refusal, not an inference
// ---------------------------------------------------------------------------

/// An empty preference list is a refusal (NFR-006, FR-010).
///
/// The failure this catches is the resolver looking at the host and picking
/// something the operator never asked for. An empty list means the capability
/// is unconfigured, and the honest answer is to say so.
#[test]
fn an_empty_preference_list_is_a_refusal() {
    let refusal = resolve_confinement(&[])
        .expect_err("an empty preference list must not resolve to an adapter");

    // The refusal names the capability, so the operator knows which one is
    // unconfigured.
    assert_eq!(
        refusal.capability(),
        HostCapability::PathConfinement,
        "the refusal must name the capability that is unconfigured"
    );
    assert!(
        !refusal.to_string().is_empty(),
        "the refusal must say something the operator can act on"
    );

    // And the same for the other capability, with its own name.
    let refusal = resolve_memory_barrier(&[])
        .expect_err("an empty preference list must not resolve to an adapter");
    assert_eq!(
        refusal.capability(),
        HostCapability::MemoryBarrier,
        "the refusal must name the capability that is unconfigured"
    );
}

// ---------------------------------------------------------------------------
// Misfit B — the skipped list is part of the result
// ---------------------------------------------------------------------------

/// The resolution carries the skipped list, so a caller can always say what
/// did not run.
///
/// The skipped list is not a log line: it is part of the result, because the
/// disclosure surface (WP05) reads it and has nowhere else to get the fact.
#[test]
fn the_resolution_carries_the_skipped_list_with_the_hosts_reason() {
    let list = preference(&["landlock", "portable_confinement"]);

    // The availability is supplied so the skipped list is populated: on a host
    // where Landlock is available the list would be empty, and a loop over an
    // empty list never runs.
    let resolution = resolve_with(HostCapability::PathConfinement, &list, |named| match named
        .as_str()
    {
        "landlock" => Some(AdapterAvailability::Unavailable {
            reason: "this host has no Landlock".to_string(),
        }),
        _ => Some(AdapterAvailability::Available),
    })
    .expect("the second entry is available");

    // The list must be populated, or the loop below says nothing.
    assert!(
        !resolution.skipped().is_empty(),
        "the skipped list must be populated for this check to mean anything"
    );

    // The skipped entries carry the adapter's name and the host's reason.
    for entry in resolution.skipped() {
        assert!(
            !entry.name().is_empty(),
            "a skipped entry must name the adapter that did not run"
        );
        assert!(
            !entry.reason().is_empty(),
            "a skipped entry must carry the host's reason, or the disclosure \
             cannot say why the first choice did not run"
        );
    }

    // Every skipped entry is one the configuration named, and none of them is
    // the selected adapter.
    for entry in resolution.skipped() {
        assert!(
            list.iter().any(|named| named.as_str() == entry.name()),
            "{} was skipped but was never named",
            entry.name()
        );
        assert_ne!(
            entry.name(),
            resolution.selected_name(),
            "the selected adapter must not also appear in the skipped list"
        );
    }
}

/// The skipped list is ordered: the entries appear in the configured order.
///
/// A reader who compares the skipped list against the configuration expects
/// them to line up. A list sorted by guarantee would not.
#[test]
fn the_skipped_list_follows_the_configured_order() {
    let list = preference(&["landlock", "memfd_secret", "sealed_memfd", "mlock"]);
    let resolution = resolve_memory_barrier(&list).expect("at least one barrier adapter works");

    let skipped: Vec<&str> = resolution.skipped_names();
    let named: Vec<&str> = list.iter().map(|n| n.as_str()).collect();

    // The skipped entries are a subsequence of the named ones, in order.
    let mut cursor = 0;
    for entry in &skipped {
        let position = named[cursor..]
            .iter()
            .position(|n| n == entry)
            .unwrap_or_else(|| panic!("{entry} is not in the named list in order"));
        cursor += position + 1;
    }
}

// ---------------------------------------------------------------------------
// The guarantee travels with the selection
// ---------------------------------------------------------------------------

/// The resolution reports the selected adapter's guarantee level.
///
/// The guarantee is the adapter's own claim, and the disclosure must report
/// *that* rather than the level of a stronger adapter the operator preferred
/// (FR-030). The assertion compares it against the adapter's own answer.
#[test]
fn the_resolution_reports_the_selected_adapters_own_guarantee() {
    for value in ["landlock", "portable_confinement"] {
        // An adapter the host cannot provide is *skipped*, not selected, so
        // the case cannot be established here — and saying so beats asserting
        // the opposite of what was measured.
        if !host_provides(value) {
            continue;
        }
        let list = preference(&[value]);
        let resolution = resolve_confinement(&list).expect("the named adapter is available");
        assert_eq!(
            resolution.guarantee(),
            confinement(value).guarantee(),
            "{value}: the resolution must report the selected adapter's own level"
        );
    }

    for value in ["memfd_secret", "sealed_memfd", "mlock"] {
        // Same: an unavailable adapter is skipped, not selected.
        if !host_provides(value) {
            continue;
        }
        let list = preference(&[value]);
        let resolution = resolve_memory_barrier(&list).expect("the named adapter is available");
        assert_eq!(
            resolution.guarantee(),
            barrier(value).guarantee(),
            "{value}: the resolution must report the selected adapter's own level"
        );
    }
}

// ---------------------------------------------------------------------------
// Misfit M — the requirement check
// ---------------------------------------------------------------------------

/// A `None` guarantee never satisfies `Required`, whatever the configuration
/// named (FR-035, Misfit M).
///
/// The portable confinement adapter establishes nothing, so it satisfies
/// nothing. The configuration naming it does not change that.
#[test]
fn a_none_guarantee_never_satisfies_required() {
    assert!(
        !satisfies(GuaranteeLevel::None, RequirementLevel::Required),
        "FR-035: a `none` guarantee must never satisfy a `required` capability"
    );
}

/// A real mechanism satisfies `Required`.
#[test]
fn a_real_mechanism_satisfies_required() {
    assert!(satisfies(GuaranteeLevel::Full, RequirementLevel::Required));
    assert!(satisfies(
        GuaranteeLevel::Weakened,
        RequirementLevel::Required
    ));
}

/// `Optional` is not "anything goes": the adapter that ran and its level are
/// still reported (FR-030).
///
/// The check is one function, so it is the only place the answer is given.
/// `Optional` changes whether the run *refuses*, not what the adapter
/// guarantees: an optional capability whose adapter established nothing still
/// lets the run proceed, and the disclosure reports that nothing was
/// established (FR-036).
#[test]
fn optional_does_not_mean_anything_goes() {
    // The requirement level changes whether the run refuses. It does not
    // change what the adapter guarantees, and it must not turn a `None`
    // guarantee into a mechanism that reads as enforced.
    assert!(
        satisfies(GuaranteeLevel::None, RequirementLevel::Optional),
        "FR-036: an optional capability proceeds even when nothing was established"
    );
    assert!(satisfies(
        GuaranteeLevel::Weakened,
        RequirementLevel::Optional
    ));
    assert!(satisfies(GuaranteeLevel::Full, RequirementLevel::Optional));

    // And the two levels must disagree, or the requirement level would be a
    // constant in the code path (FR-027).
    assert_ne!(
        satisfies(GuaranteeLevel::None, RequirementLevel::Required),
        satisfies(GuaranteeLevel::None, RequirementLevel::Optional),
        "the requirement level must decide whether a `none` guarantee refuses"
    );
}

/// The guarantee level a selected adapter carries is what the check judges.
///
/// This ties the two decisions together: the resolver reports the adapter's own
/// guarantee, and the check judges that guarantee. A resolver that reported a
/// stronger adapter's level would make a `Required` capability pass on a host
/// where only a weaker mechanism ran.
#[test]
fn the_requirement_check_judges_the_reported_guarantee() {
    let list = preference(&["portable_confinement"]);
    let resolution = resolve_confinement(&list).expect("the portable adapter is always available");

    assert_eq!(resolution.guarantee(), GuaranteeLevel::None);
    assert!(
        !satisfies(resolution.guarantee(), RequirementLevel::Required),
        "a portable adapter must not satisfy a required capability, whatever \
         the configuration named"
    );
}

// ---------------------------------------------------------------------------
// Misfit F — a required capability with nothing available
// ---------------------------------------------------------------------------

/// A capability with no available adapter yields a refusal that names it.
///
/// The refusal is the whole of Misfit F: the caller must be able to say which
/// capability could not be established.
#[test]
fn a_capability_with_nothing_available_yields_a_refusal_naming_it() {
    let refusal =
        UnavailableCapability::for_capability(HostCapability::PathConfinement, Vec::new());

    assert_eq!(
        refusal.capability(),
        HostCapability::PathConfinement,
        "the refusal must name the capability"
    );
    assert!(
        refusal.reasons().is_empty(),
        "no adapter was named, so there is no reason to report"
    );
}

/// The refusal says nothing about the requirement level.
///
/// The resolver receives the adapter list and nothing else, so it does not know
/// whether the configuration marked the capability `required` or `optional`. A
/// refusal that stated a level would be making a claim about the operator's
/// own configuration that the value cannot support — and FR-029 governs
/// exactly this case, where an optional capability that cannot be established
/// is a weakened posture and the run continues.
///
/// The assertion is on the *absence* of the claim, and it is deliberately
/// checked against both words: a refusal that said "optional" would be just as
/// wrong as one that said "required".
#[test]
fn the_refusal_does_not_claim_a_requirement_level() {
    let refusal = UnavailableCapability::for_capability(
        HostCapability::PathConfinement,
        vec![SkippedAdapter::new(
            name("landlock"),
            "this host has no Landlock",
        )],
    );

    let rendered = refusal.to_string();
    assert!(
        !rendered.contains("required"),
        "the refusal must not claim the capability was required; got: {rendered}"
    );
    assert!(
        !rendered.contains("optional"),
        "the refusal must not claim the capability was optional; got: {rendered}"
    );
    // It must still say what it does know.
    assert!(
        rendered.contains("confinement"),
        "the refusal must name the capability; got: {rendered}"
    );
    assert!(
        rendered.contains("landlock"),
        "the refusal must name the adapter it could not use; got: {rendered}"
    );
}

/// The resolver's own refusal carries no requirement level either.
///
/// The refusal the resolver produces goes through the same type, so the same
/// claim would be made. This test drives the resolver so the assertion is on
/// the value a caller actually receives.
#[test]
fn a_resolver_refusal_does_not_claim_a_requirement_level() {
    let list = preference(&["landlock"]);
    let refusal = resolve_with(HostCapability::PathConfinement, &list, |named| {
        Some(AdapterAvailability::Unavailable {
            reason: format!("this host does not provide {}", named.as_str()),
        })
    })
    .expect_err("no named adapter is available");

    let rendered = refusal.to_string();
    assert!(
        !rendered.contains("required") && !rendered.contains("optional"),
        "the resolver must not state a requirement level it was never told; got: {rendered}"
    );
    assert!(
        rendered.contains("landlock"),
        "the refusal must name the adapter it could not use; got: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// The refusal names the host's reason
// ---------------------------------------------------------------------------

/// The refusal carries each rejected adapter with the host's reason.
///
/// The operator decides whether to fix the host from the text, so a generic
/// "not available" is not enough.
#[test]
fn the_refusal_carries_each_rejected_adapter_with_the_hosts_reason() {
    let reasons = vec![
        SkippedAdapter::new(name("landlock"), "this host has no Landlock"),
        SkippedAdapter::new(name("memfd_secret"), "the mechanism is Linux-only"),
    ];

    let refusal = UnavailableCapability::for_capability(HostCapability::PathConfinement, reasons);

    for entry in refusal.reasons() {
        assert!(!entry.name().is_empty(), "a rejected adapter must be named");
        assert!(
            !entry.reason().is_empty(),
            "a rejected adapter must carry the host's reason"
        );
    }
    assert_eq!(
        refusal.reasons().len(),
        2,
        "every rejected adapter must be carried, not just the first"
    );
}

/// The refusal's text names the capability and the adapter it could not use.
///
/// A refusal that does not say which capability failed leaves the operator
/// with two candidate explanations, and one that does not say which adapter
/// was rejected leaves them with a mechanism to guess at.
#[test]
fn the_refusal_names_the_capability_and_the_adapter() {
    let refusal = UnavailableCapability::for_capability(
        HostCapability::PathConfinement,
        vec![SkippedAdapter::new(name("landlock"), "no Landlock here")],
    );

    let rendered = refusal.to_string();
    assert!(
        rendered.contains("confinement"),
        "the refusal must name the capability; got: {rendered}"
    );
    assert!(
        rendered.contains("landlock"),
        "the refusal must name the adapter it could not use; got: {rendered}"
    );
}
