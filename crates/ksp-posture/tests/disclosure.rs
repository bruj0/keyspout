//! The posture record and the disclosure surface.
//!
//! A reader must be able to tell a configured `memfd_secret` that ran from
//! one that fell back to `sealed_memfd`, and must be able to read that a
//! capability was accepted as unenforced rather than left unmentioned.
//!
//! # The three facts, and why all three are needed
//!
//! - **the adapter's name** says which mechanism ran;
//! - **the guarantee level** says how far to trust it;
//! - **the configured order** says what the operator asked for first.
//!
//! Two of the three are useless without the other: an adapter name without a
//! level does not say whether the mechanism was the whole capability or a
//! smaller part of it, and a level without a name does not say which mechanism
//! produced it.
//!
//! # A `none` guarantee is an accepted absence, not an error
//!
//! The disclosure renders it in the **same terms** as an enforced capability:
//! the row is present, the level is named, and the difference is the level
//! (FR-038). A capability that was accepted as unenforced must be legible in
//! the status line and durable in the audit log (Misfit N) — otherwise a later
//! reader cannot tell an accepted absence from an unnoticed one (NFR-009).
//!
//! # What these tests assert against
//!
//! Every assertion is against a value the code under test produced, or against
//! an independent fact. A test that compared the rendering against another
//! value the same expression produced could not fail.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_posture::adapters::{
    ConfinementAdapter, LandlockConfinement, MemfdSecretBarrier, MemoryBarrierAdapter,
    PortableConfinement, SealedMemfdBarrier,
};
use ksp_posture::posture::{
    BarrierPosture, CapabilityDisclosure, ConfinementPosture, LandlockObservation,
};
use ksp_posture::{BarrierKind, MemlockObservation};
use ksp_types::{AdapterName, GuaranteeLevel, HostCapability};

/// An adapter name from the closed set.
fn adapter(name: &str) -> AdapterName {
    AdapterName::parse(name).expect("the name is in the closed set")
}

/// The `RLIMIT_MEMLOCK` a test posture carries.
fn memlock() -> MemlockObservation {
    MemlockObservation {
        soft_bytes: Some(8 * 1024 * 1024),
        hard_bytes: Some(8 * 1024 * 1024),
    }
}

/// A modern Landlock observation, as a Linux host would report it.
fn landlock() -> LandlockObservation {
    LandlockObservation::Available {
        effective_abi: 8,
        kernel_abi: None,
    }
}

/// A barrier posture, built by the **production** constructor.
///
/// The adapter and its level are derived inside `BarrierPosture::of`, so an
/// assertion against this value is an assertion about what a real run renders.
/// An earlier version of this file assembled the struct by hand and passed a
/// name it had chosen itself — which is how the suite stayed green while every
/// production run printed `no adapter`.
fn barrier(kind: BarrierKind) -> BarrierPosture {
    BarrierPosture::of(kind, memlock())
}

/// A barrier posture for a run that established no barrier.
fn no_barrier() -> BarrierPosture {
    BarrierPosture::unavailable(memlock())
}

/// A disclosure in which `selected` ran and established `guarantee`.
///
/// The adapter is a closed [`AdapterName`], so a disclosure cannot name a
/// mechanism the build does not contain.
fn disclosure_of(
    capability: HostCapability,
    selected: &str,
    guarantee: GuaranteeLevel,
) -> CapabilityDisclosure {
    CapabilityDisclosure {
        capability,
        platform: "Linux".to_string(),
        configured_order: vec![adapter(selected)],
        requirement: None,
        selected: Some(adapter(selected)),
        guarantee,
        skipped: vec![],
    }
}

/// A confinement posture, built by the **production** constructor.
///
/// The adapter and its level are the arguments `enforced` requires, so a
/// posture that claims enforcement cannot exist without naming what enforced
/// it.
fn confined() -> ConfinementPosture {
    ConfinementPosture::enforced(
        landlock(),
        true,
        LandlockConfinement::NAME,
        LandlockConfinement.guarantee(),
    )
}

// ---------------------------------------------------------------------------
// Misfit B — the adapter is undisclosed
// ---------------------------------------------------------------------------

/// A run that fell back is distinguishable from a run that did not.
///
/// This is Misfit B: the posture reported a barrier *kind* but not the
/// *adapter*, so a reader could not tell a configured `memfd_secret` that ran
/// from one that fell back to `sealed_memfd`.
#[test]
fn a_fallback_is_distinguishable_from_a_full_strength_run() {
    let full = barrier(BarrierKind::MemfdSecret);
    let fallback = barrier(BarrierKind::SealedMemfd);

    assert_eq!(
        full.adapter,
        Some(MemfdSecretBarrier::NAME),
        "the posture must name the adapter that ran"
    );
    assert_eq!(
        fallback.adapter,
        Some(SealedMemfdBarrier::NAME),
        "a fallback must name the adapter that actually ran, not the one that \
         was preferred"
    );

    // And the renderings must differ, because a reader reads the rendering.
    assert_ne!(
        full.to_string(),
        fallback.to_string(),
        "a fallback and a full-strength run must render differently"
    );
}

/// The posture reports the adapter's own guarantee, not a stronger one.
///
/// The guarantee is the adapter's claim. A posture that reported `full` for a
/// run that fell back would describe a mechanism that did not run (FR-030).
#[test]
fn the_posture_reports_the_adapters_own_guarantee() {
    let fallback = barrier(BarrierKind::SealedMemfd);
    assert_eq!(
        fallback.guarantee,
        SealedMemfdBarrier.guarantee(),
        "the posture must report the guarantee of the adapter that ran"
    );
    assert_eq!(
        fallback.guarantee,
        GuaranteeLevel::Weakened,
        "the sealed-memfd fallback must not be reported at the primary's level"
    );

    let confinement = confined();
    assert_eq!(
        confinement.guarantee,
        LandlockConfinement.guarantee(),
        "the posture must report the guarantee of the adapter that ran"
    );
    assert_eq!(
        confinement.guarantee,
        GuaranteeLevel::Full,
        "Landlock enforces exactly the rules the run asks for"
    );
}

/// A capability with no adapter reports no adapter, and says so.
///
/// The unconfigured case is a different fact from the unenforced case: one
/// has no adapter, the other has an adapter that establishes nothing. The
/// posture must not blur them.
#[test]
fn a_capability_with_no_adapter_reports_no_adapter() {
    let posture = no_barrier();
    assert_eq!(
        posture.adapter, None,
        "a capability with no adapter must not name one"
    );
    assert_eq!(
        posture.guarantee,
        GuaranteeLevel::None,
        "a capability with no adapter guarantees nothing"
    );
}

// ---------------------------------------------------------------------------
// Misfit H — a portable adapter overstates
// ---------------------------------------------------------------------------

/// A `none` guarantee is rendered as `none`, in the same terms as `full`.
///
/// FR-038: the difference must be the guarantee level and not the presence of a
/// row. A `none` that is omitted, hidden in a footnote, or rendered as
/// "unavailable" alongside a differently-shaped `full` row would all fail.
///
/// The state under test is a *disclosure* rather than a posture, because a
/// posture can only name an adapter when the mechanism ran, and no mechanism
/// reports a `none` guarantee — the adapter that establishes nothing is
/// reported by the disclosure that selected it.
#[test]
fn a_none_guarantee_is_rendered_as_none_in_the_same_terms_as_full() {
    let none = disclosure_of(
        HostCapability::PathConfinement,
        PortableConfinement::NAME,
        GuaranteeLevel::None,
    );
    let full = disclosure_of(
        HostCapability::PathConfinement,
        LandlockConfinement::NAME,
        GuaranteeLevel::Full,
    );

    let none_text = none.to_string();
    let full_text = full.to_string();

    assert!(
        none_text.contains("none"),
        "a `none` guarantee must be rendered as `none`; got: {none_text}"
    );
    assert!(
        full_text.contains("full"),
        "a `full` guarantee must be rendered as `full`; got: {full_text}"
    );

    // Same terms: both renderings name the adapter and the level, in the same
    // shape. The only difference is the level's word.
    for (text, label) in [(none_text.as_str(), "none"), (full_text.as_str(), "full")] {
        assert!(
            text.contains(label),
            "the {label} rendering must name its level; got: {text}"
        );
        assert!(
            text.contains("path confinement"),
            "the {label} rendering must name the capability; got: {text}"
        );
        assert!(
            text.contains("ran"),
            "the {label} rendering must name the adapter that ran; got: {text}"
        );
    }
}

/// The rendered level is the level the caller stated, not a synonym.
///
/// A rendering that said "unavailable" for `none` would be legible but wrong:
/// the operator configured `optional` and the capability established nothing,
/// which is an accepted absence, not a failure (FR-036, Misfit H).
#[test]
fn the_rendered_level_is_the_stated_level_and_not_a_synonym() {
    let none = disclosure_of(
        HostCapability::PathConfinement,
        PortableConfinement::NAME,
        GuaranteeLevel::None,
    );
    let text = none.to_string();
    assert!(
        !text.contains("unavailable"),
        "a `none` guarantee is an accepted absence, not an unavailable one; got: {text}"
    );
}

// ---------------------------------------------------------------------------
// Misfit L — support implies confinement
// ---------------------------------------------------------------------------

/// The disclosure names the platform and the configured order.
///
/// FR-014: `ksp status` reports, per capability, the configured order, the
/// adapter selected, and the mechanism enforced. The order is what tells a
/// reader whether the run got what was asked for.
#[test]
fn the_disclosure_names_the_platform_the_order_and_the_adapter() {
    let disclosure = CapabilityDisclosure {
        capability: HostCapability::MemoryBarrier,
        platform: "macOS".to_string(),
        configured_order: vec![
            adapter("memfd_secret"),
            adapter("sealed_memfd"),
            adapter("mlock"),
        ],
        requirement: None,
        selected: Some(adapter("mlock")),
        guarantee: GuaranteeLevel::None,
        skipped: vec![],
    };

    let text = disclosure.to_string();
    assert!(
        text.contains("macOS"),
        "the disclosure must name the platform; got: {text}"
    );
    assert!(
        text.contains("memfd_secret"),
        "the disclosure must name the configured order; got: {text}"
    );
    assert!(
        text.contains("mlock"),
        "the disclosure must name the selected adapter; got: {text}"
    );
    assert!(
        text.contains("none"),
        "the disclosure must name the guarantee level; got: {text}"
    );
}

/// The disclosure says when nothing was enforced on this host.
///
/// Misfit L: a host with no path confinement must not read as a host where
/// confinement is enforced. The disclosure's job is to make the absence
/// legible.
#[test]
fn the_disclosure_states_that_nothing_was_enforced() {
    let disclosure = CapabilityDisclosure {
        capability: HostCapability::PathConfinement,
        platform: "macOS".to_string(),
        configured_order: vec![adapter("portable_confinement")],
        requirement: None,
        selected: Some(adapter("portable_confinement")),
        guarantee: GuaranteeLevel::None,
        skipped: vec![],
    };

    let text = disclosure.to_string();
    assert!(
        text.contains("none"),
        "a capability that established nothing must say so; got: {text}"
    );
    assert!(
        text.contains("portable_confinement"),
        "the disclosure must name the adapter that ran; got: {text}"
    );
}

/// An unconfigured capability is reported as unconfigured, and names what the
/// build could have offered.
///
/// FR-010: while a capability has no adapter selected, the CLI reports it as
/// unconfigured and names the adapters the build could have provided.
#[test]
fn an_unconfigured_capability_is_reported_as_unconfigured() {
    let disclosure = CapabilityDisclosure {
        capability: HostCapability::MemoryBarrier,
        platform: "macOS".to_string(),
        configured_order: vec![],
        requirement: None,
        selected: None,
        guarantee: GuaranteeLevel::None,
        skipped: vec![],
    };

    let text = disclosure.to_string();
    assert!(
        text.contains("unconfigured"),
        "a capability with no adapter must be reported as unconfigured; got: {text}"
    );
}

/// The disclosure names what it skipped, with the host's reason.
///
/// Misfit B: the skipped list is what makes a fallback explainable. A reader
/// who sees `sealed_memfd` selected needs to know `memfd_secret` did not run
/// and why.
#[test]
fn the_disclosure_names_what_it_skipped_and_why() {
    let disclosure = CapabilityDisclosure {
        capability: HostCapability::MemoryBarrier,
        platform: "macOS".to_string(),
        configured_order: vec![adapter("memfd_secret"), adapter("sealed_memfd")],
        requirement: None,
        selected: Some(adapter("sealed_memfd")),
        guarantee: GuaranteeLevel::Weakened,
        skipped: vec![(adapter("memfd_secret"), "no such syscall".to_string())],
    };

    let text = disclosure.to_string();
    assert!(
        text.contains("memfd_secret"),
        "the disclosure must name the adapter that did not run; got: {text}"
    );
    assert!(
        text.contains("no such syscall"),
        "the disclosure must carry the host's reason; got: {text}"
    );
}
