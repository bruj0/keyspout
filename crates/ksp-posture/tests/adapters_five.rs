//! The five adapters, and the four properties WP03 owes them.
//!
//! WP02 pinned the *traits* and the registry's shape. This file pins the
//! *adapters*: what each one guarantees, what each one says about the host it
//! is running on, and — the property that matters most — the refusals.
//!
//! # The distinction this file exists to keep
//!
//! Two different questions, two different answers:
//!
//! - **Is the adapter in this build?** The registry answers that, and on a
//!   target with no dedicated mechanism the answer is still *yes*: the adapter
//!   is compiled everywhere (NFR-007), so a host with no Landlock still has an
//!   adapter for path confinement and the CLI can run and say what it lacks.
//! - **Does this host provide the mechanism?** The adapter answers that, and
//!   off Linux the answer is *no* (FR-017).
//!
//! Conflating them would make the mechanism difference a **compiler** error,
//! which is exactly what NFR-003 forbids: the difference must be expressed as
//! adapter availability.
//!
//! # What is asserted here, and why each assertion can fail
//!
//! Every assertion is against a value the code under test produced, or against
//! an independent fact about the host. A test that compared the adapter's
//! `availability()` against another value the same expression produced would
//! pass whatever the code did.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_posture::adapters::{
    ConfinementAdapter, MemoryBarrierAdapter, capability_of, confinement_adapter,
    memory_barrier_adapter,
};
use ksp_types::{AdapterName, GuaranteeLevel, HostCapability};

/// The name, as the configuration file spells it.
fn name(value: &str) -> AdapterName {
    AdapterName::parse(value).expect("a name in the closed set parses")
}

/// The path-confinement adapter for `value`, or a panic naming the value.
fn confinement(value: &str) -> &'static dyn ConfinementAdapter {
    confinement_adapter(&name(value))
        .unwrap_or_else(|| panic!("{value} must be in this build on every target"))
}

/// The memory-barrier adapter for `value`, or a panic naming the value.
fn barrier(value: &str) -> &'static dyn MemoryBarrierAdapter {
    memory_barrier_adapter(&name(value))
        .unwrap_or_else(|| panic!("{value} must be in this build on every target"))
}

// ---------------------------------------------------------------------------
// Misfit G — an unusable host still has an adapter for every capability
// ---------------------------------------------------------------------------

/// Misfit G — a host with no Landlock and no `memfd_secret` still has an
/// adapter for every capability.
///
/// The failure this catches is a build that stops compiling on such a host, or
/// a registry that answers `None` and leaves the CLI with no way to say what
/// it lacks. The assertion is about the **registry**, which is the build's
/// fact; the mechanism's absence is the **availability**'s fact, asserted
/// separately below.
#[test]
fn every_capability_has_an_adapter_on_this_host() {
    // Path confinement: both names are in the build.
    assert!(
        confinement_adapter(&name("landlock")).is_some(),
        "the landlock adapter must be compiled on every target (NFR-007)"
    );
    assert!(
        confinement_adapter(&name("portable_confinement")).is_some(),
        "the portable adapter must be compiled on every target (NFR-007)"
    );

    // Memory barrier: all three names are in the build.
    for value in ["memfd_secret", "sealed_memfd", "mlock"] {
        assert!(
            memory_barrier_adapter(&name(value)).is_some(),
            "{value} must be compiled on every target (NFR-007)"
        );
    }
}

/// The registry's answer is the **build's** fact, and it does not depend on the
/// host.
///
/// This is the property that lets the same binary run on a host with no
/// Landlock: the adapter is present, and the adapter's own `availability()`
/// says the mechanism is missing. A registry that hid the adapter would make
/// the two facts indistinguishable.
#[test]
fn the_registry_answer_does_not_depend_on_the_host() {
    // The registry holds statics, so a lookup cannot depend on anything the
    // host does at the moment of the call.
    for value in AdapterName::ALL {
        let adapter_name = name(value);
        let first = confinement_adapter(&adapter_name);
        let second = confinement_adapter(&adapter_name);
        match (first, second) {
            (Some(a), Some(b)) => assert!(
                std::ptr::eq(a, b),
                "{value} must resolve to one adapter, not a fresh one per lookup"
            ),
            (None, None) => {}
            _ => panic!("{value} resolved differently on two consecutive lookups"),
        }
    }
}

// ---------------------------------------------------------------------------
// Misfit A — a silent fallback: the two barrier adapters are distinguishable
// ---------------------------------------------------------------------------

/// Misfit A — the `memfd_secret` and `sealed_memfd` adapters report their
/// availability **independently**, so a host with no `memfd_secret` is
/// visible.
///
/// The failure this catches is the silent fallback: a host that cannot provide
/// the primary barrier being reported exactly as a host that can.
///
/// # The property, and why it is stated this way
///
/// The two adapters legitimately agree on a host that has both mechanisms —
/// that is what "available" means, and forcing them to differ would assert
/// something false. They also legitimately agree on a host that has neither,
/// which is the macOS case. What must hold on *every* host is that each
/// adapter answers for **its own** mechanism:
///
/// - an adapter that is unavailable names the mechanism that is missing, so
///   the operator is sent to that mechanism rather than to a generic "the
///   barrier is unavailable";
/// - the two adapters do not answer for each other, so a host with one but not
///   the other shows exactly one of them unavailable.
///
/// The second point is what makes the first observable: if the two shared one
/// probe, a host with `memfd_create` but no `memfd_secret` would report both
/// as available, and the primary's absence would be invisible.
#[test]
fn the_two_memfd_adapters_report_their_availability_independently() {
    let secret = barrier("memfd_secret");
    let sealed = barrier("sealed_memfd");

    // Each unavailable adapter must name its own mechanism. A shared reason —
    // or a generic one — would send the operator to the wrong place.
    if let Some(reason) = secret.availability().reason() {
        assert!(
            reason.contains("memfd_secret"),
            "the primary's reason must name memfd_secret; got: {reason}"
        );
    }
    if let Some(reason) = sealed.availability().reason() {
        assert!(
            reason.contains("memfd_create"),
            "the fallback's reason must name memfd_create; got: {reason}"
        );
    }

    // The two adapters do not answer for each other. `memfd_create(2)` predates
    // `memfd_secret(2)`, so a host with the newer mechanism has the older one;
    // the reverse is not true, and a kernel between the two is exactly where
    // the silent fallback would hide.
    let secret_available = secret.availability().is_available();
    let sealed_available = sealed.availability().is_available();
    if secret_available {
        assert!(
            sealed_available,
            "a host with memfd_secret has memfd_create too: the older \
             mechanism is always present where the newer one is"
        );
    }
}

/// An `Unavailable` adapter names the host's reason.
///
/// The reason is the host's own, not a generic "not supported": the operator
/// decides whether to fix it from the text. A bare `Unavailable` with no
/// reason is what makes an operator give up and route around the refusal.
#[test]
fn an_unavailable_adapter_names_a_reason() {
    for value in AdapterName::ALL {
        let adapter_name = name(value);
        if let Some(adapter) = confinement_adapter(&adapter_name)
            && let Some(reason) = adapter.availability().reason()
        {
            assert!(
                !reason.trim().is_empty(),
                "{value} reported Unavailable with an empty reason"
            );
        }
        if let Some(adapter) = memory_barrier_adapter(&adapter_name)
            && let Some(reason) = adapter.availability().reason()
        {
            assert!(
                !reason.trim().is_empty(),
                "{value} reported Unavailable with an empty reason"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Misfit H — a portable adapter overstates
// ---------------------------------------------------------------------------

/// Misfit H — the portable adapter's guarantee is `None` and it establishes
/// nothing (FR-020).
///
/// The guarantee is the claim; the refusal is the proof. A portable adapter
/// that reported `Weakened` would be read as "a weaker confinement", which it
/// is not: it confines nothing at all.
#[test]
fn the_portable_adapter_guarantees_nothing_and_establishes_nothing() {
    let adapter = confinement("portable_confinement");

    assert_eq!(
        adapter.guarantee(),
        GuaranteeLevel::None,
        "FR-020: a portable adapter that establishes no mechanism must report `None`"
    );

    let spec = ksp_posture::ConfinementSpec::required(Vec::new());
    let error = adapter
        .establish(&spec)
        .expect_err("the portable adapter establishes nothing, so it refuses");
    assert!(
        error.to_string().contains("not confined"),
        "the refusal must say the child is not confined; got: {error}"
    );
}

/// Every adapter that establishes no mechanism reports `None`, and every
/// adapter that establishes one reports at least `Weakened`.
///
/// This is the general form of Misfit H, applied to all five adapters rather
/// than only to the portable one. A `None` guarantee on an adapter that does
/// enforce something would understate it; a `Full` guarantee on one that
/// enforces nothing would overstate it. Either way the posture is a lie.
///
/// # Why this test does not call `establish`
///
/// The first version of this test asked each adapter to `establish`, and read
/// "establishes nothing" off the `NoMechanism` refusal. That is wrong, and it
/// is wrong in a way no gate on this project could see:
/// [`crate::confinement::restrict_then_launch`] calls `restrict_self` on the
/// **calling** process *before* it decides whether to refuse. Calling it from
/// a test therefore applies an irreversible ruleset to the test harness. It
/// only passed because neither gate target has Landlock: the macOS host has no
/// Landlock at all, and the Linux VM reports no ABI. On a kernel that does
/// enforce it, the empty ruleset below would confine the whole test binary —
/// process-wide on ABI >= V8, where `all_threads` is accepted.
///
/// So the test reads the fact from the closed set instead, which is where the
/// design states it: `portable_confinement` is the only adapter that
/// establishes no mechanism, and no barrier adapter is portable — every one of
/// the three names a real mechanism. The kernel evidence for the confinement
/// path lives where it can be taken safely, in the re-executed probes in
/// `tests/confinement.rs` and `tests/confinement_writable.rs`, which confine a
/// throwaway process rather than the harness.
#[test]
fn a_guarantee_level_matches_what_the_adapter_establishes() {
    for value in AdapterName::ALL {
        let adapter_name = name(value);
        let guarantee = if let Some(adapter) = confinement_adapter(&adapter_name) {
            adapter.guarantee()
        } else if let Some(adapter) = memory_barrier_adapter(&adapter_name) {
            adapter.guarantee()
        } else {
            panic!("{value} is in no registry");
        };

        // The one adapter in the closed set with no mechanism behind it. Every
        // other name — `landlock`, `memfd_secret`, `sealed_memfd`, `mlock` —
        // establishes something, and the value is a mechanism rather than a
        // name: `mlock` is weaker than the `memfd` pair, not absent.
        let establishes = value != "portable_confinement";
        if establishes {
            assert_ne!(
                guarantee,
                GuaranteeLevel::None,
                "{value} establishes a mechanism, so it must not report `None`"
            );
        } else {
            assert_eq!(
                guarantee,
                GuaranteeLevel::None,
                "{value} establishes no mechanism, so it must report `None` (FR-020)"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// FR-019 — each adapter declares its own guarantee
// ---------------------------------------------------------------------------

/// FR-019 — each adapter declares the guarantee the plan assigns it.
///
/// The levels are the plan's table, and the table is the design decision: the
/// Landlock adapter enforces the whole capability, `sealed_memfd` and `mlock`
/// enforce a stated smaller part of it, and `portable_confinement` enforces
/// none of it. A level that moved would be a claim the adapter cannot back.
#[test]
fn each_adapter_declares_the_guarantee_the_plan_assigns_it() {
    assert_eq!(
        confinement("landlock").guarantee(),
        GuaranteeLevel::Full,
        "the landlock adapter enforces the whole capability"
    );
    assert_eq!(
        confinement("portable_confinement").guarantee(),
        GuaranteeLevel::None,
        "the portable adapter establishes nothing"
    );
    assert_eq!(
        barrier("memfd_secret").guarantee(),
        GuaranteeLevel::Full,
        "the primary barrier keeps key material out of ordinary memory"
    );
    assert_eq!(
        barrier("sealed_memfd").guarantee(),
        GuaranteeLevel::Weakened,
        "the sealed fallback is ordinary memory, sealed against later writes"
    );
    assert_eq!(
        barrier("mlock").guarantee(),
        GuaranteeLevel::Weakened,
        "mlock keeps pages resident and out of swap, and does no more"
    );
}

/// The `mlock` adapter is weaker than `memfd_secret`, and the two are not
/// interchangeable.
///
/// The `mlock` mechanism locks pages; it does not remove them from the
/// kernel's direct map, and it cannot exclude them from a dump. A run that
/// chose `mlock` must not be reported as having the primary barrier.
#[test]
fn the_mlock_adapter_is_weaker_than_the_primary_barrier() {
    let mlock = barrier("mlock");
    let secret = barrier("memfd_secret");

    assert!(
        mlock.guarantee() < secret.guarantee(),
        "mlock must not be reported as the primary barrier; got {:?} against {:?}",
        mlock.guarantee(),
        secret.guarantee()
    );
}

// ---------------------------------------------------------------------------
// The adapter's identifier is the closed set's spelling
// ---------------------------------------------------------------------------

/// Every adapter reports the name the operator writes in the configuration
/// file.
///
/// A drift here makes the adapter unreachable by the name that selects it: the
/// configuration says `mlock`, the registry resolves `mlock`, and the adapter
/// answers `something else` — so the posture names a mechanism that was never
/// selected.
#[test]
fn every_adapter_reports_the_name_the_closed_set_spells() {
    for value in AdapterName::ALL {
        let adapter_name = name(value);
        let reported = if let Some(adapter) = confinement_adapter(&adapter_name) {
            adapter.name()
        } else if let Some(adapter) = memory_barrier_adapter(&adapter_name) {
            adapter.name()
        } else {
            panic!("{value} is in no registry");
        };

        assert_eq!(
            reported, value,
            "the adapter's identifier must be the closed set's spelling"
        );
    }
}

/// Each adapter's name belongs to the capability the registry filed it under.
///
/// The registry derives the capability from one fact, and the adapter's own
/// name is a second. A disagreement between them would let a barrier adapter be
/// selected for path confinement.
#[test]
fn each_adapter_belongs_to_the_capability_its_registry_filed_it_under() {
    for value in AdapterName::ALL {
        let adapter_name = name(value);
        let capability = capability_of(adapter_name.kind());

        if let Some(adapter) = confinement_adapter(&adapter_name) {
            assert_eq!(
                capability,
                HostCapability::PathConfinement,
                "{value} came from the confinement registry"
            );
            assert_eq!(adapter.name(), value);
        }
        if let Some(adapter) = memory_barrier_adapter(&adapter_name) {
            assert_eq!(
                capability,
                HostCapability::MemoryBarrier,
                "{value} came from the barrier registry"
            );
            assert_eq!(adapter.name(), value);
        }
    }
}
