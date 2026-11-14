//! The adapter traits and the registry that maps a name to an adapter.
//!
//! A **host capability** — path confinement, or the memory barrier — is
//! established by a named adapter behind a trait. The trait describes a
//! *mechanism*; the registry says which mechanisms this build contains. The
//! two are kept apart on purpose:
//!
//! - The trait's `availability` answers "does this host provide the
//!   mechanism?". It is the host's fact.
//! - The registry's `None` answers "does this build contain the adapter?".
//!   It is the build's fact.
//!
//! Those are different questions with different messages, and conflating them
//! is how a run ends up on a weaker mechanism without saying so.
//!
//! # The registry is closed at compile time
//!
//! The registry is a `match` over [`AdapterKind`], not a map and not a runtime
//! lookup. Adding an adapter to the closed name set without adding a registry
//! arm breaks the build rather than being discovered at run time. A match on a
//! string cannot be exhaustive; a match on a fieldless enum can, and the
//! compiler checks it.
//!
//! The registry holds `&'static dyn Trait`, so the traits are object-safe: no
//! generic methods, and no `Self` in a return position.
//!
//! # What this module does not contain
//!
//! Nothing is missing from the registry: all five names in the closed set have
//! an adapter and an arm. What differs between targets is not the registry but
//! the **mechanism** an adapter uses — and that difference is reported by the
//! adapter's own [`availability`](ConfinementAdapter::availability), not by the
//! registry's answer.
//!
//! This is the distinction NFR-003 requires: the mechanism difference must be
//! expressed as adapter availability rather than as a compiler error. A host
//! with no Landlock still finds the Landlock adapter in the registry, and that
//! adapter reports that this host does not provide the mechanism.

pub mod barrier;
pub mod confinement;

use ksp_types::{AdapterKind, AdapterName, HostCapability};

pub use barrier::{MemfdSecretBarrier, MemoryBarrierAdapter, MlockBarrier, SealedMemfdBarrier};
pub use confinement::{
    ConfinementAdapter, LANDLOCK_CONFINEMENT, LandlockConfinement, PORTABLE_CONFINEMENT,
    PortableConfinement,
};

/// The capability an adapter name belongs to.
///
/// One fact, and both registries are derived from it, so the two cannot
/// disagree about which capability owns a name. The match is exhaustive over
/// the closed name set, so a new adapter name breaks the build here until it
/// is given a capability.
pub const fn capability_of(kind: AdapterKind) -> HostCapability {
    match kind {
        AdapterKind::Landlock | AdapterKind::PortableConfinement => HostCapability::PathConfinement,
        AdapterKind::MemfdSecret | AdapterKind::SealedMemfd | AdapterKind::Mlock => {
            HostCapability::MemoryBarrier
        }
    }
}

/// The adapter for path confinement, looked up by name.
///
/// Returns `None` only for a name that belongs to the *other* capability. Every
/// confinement name in the closed set has an adapter in this build, on every
/// target: the Landlock adapter is compiled everywhere, and on a host with no
/// Landlock it reports itself as unavailable (FR-017, NFR-007).
///
/// The lookup is by [`AdapterKind`] rather than by string, so the match is
/// exhaustive and the compiler proves it. A name the type does not contain
/// cannot reach this function at all: [`AdapterName`] only holds a kind that
/// is in the closed set.
pub fn confinement_adapter(name: &AdapterName) -> Option<&'static dyn ConfinementAdapter> {
    match name.kind() {
        AdapterKind::PortableConfinement => Some(&confinement::PORTABLE_CONFINEMENT),
        // The Landlock adapter is in this build on every target. Whether the
        // *host* provides the mechanism is the adapter's own answer.
        AdapterKind::Landlock => Some(&confinement::LANDLOCK_CONFINEMENT),
        // A barrier name is not a confinement adapter. The registry answers
        // `None` rather than picking a default, because a default here would
        // silently confine the run by a mechanism the operator never named.
        AdapterKind::MemfdSecret | AdapterKind::SealedMemfd | AdapterKind::Mlock => None,
    }
}

/// The adapter for the memory barrier, looked up by name.
///
/// Returns `None` only for a name that belongs to the *other* capability. Every
/// barrier name in the closed set has an adapter in this build, on every
/// target: the two `memfd` adapters are compiled everywhere, and on a host with
/// no `memfd` they report themselves as unavailable (FR-017, NFR-007).
///
/// The two registries are disjoint: a barrier name asked of the confinement
/// registry yields `None`, and the reverse.
pub fn memory_barrier_adapter(name: &AdapterName) -> Option<&'static dyn MemoryBarrierAdapter> {
    match name.kind() {
        // The barrier adapters are in this build on every target. Whether the
        // *host* provides the mechanism is each adapter's own answer.
        AdapterKind::MemfdSecret => Some(&barrier::MEMFD_SECRET_BARRIER),
        AdapterKind::SealedMemfd => Some(&barrier::SEALED_MEMFD_BARRIER),
        AdapterKind::Mlock => Some(&barrier::MLOCK_BARRIER),
        // A confinement name is not a barrier adapter. The registry answers
        // `None` rather than picking a default, because a default here would
        // silently hold key material by a mechanism the operator never named.
        AdapterKind::Landlock | AdapterKind::PortableConfinement => None,
    }
}
