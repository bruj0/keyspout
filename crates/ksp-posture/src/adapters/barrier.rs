//! The memory-barrier adapter trait.
//!
//! The trait describes a **mechanism**: a way of keeping key material out of
//! ordinary memory. It carries no policy and no configuration, and it knows
//! nothing about the file format the operator wrote.

use crate::barrier::{BarrierError, BarrierKind, BarrieredRegion};
use ksp_types::{AdapterAvailability, GuaranteeLevel};

/// A mechanism that establishes the memory barrier for a region.
///
/// The trait is object-safe, so the registry can hold
/// `&'static dyn MemoryBarrierAdapter`. That rules out generic methods and
/// any `Self` in a return position.
///
/// A barrier adapter never implements a confinement method, and a confinement
/// adapter never implements a barrier method. The two registries are disjoint,
/// and a name asked of the registry that does not own it yields nothing.
pub trait MemoryBarrierAdapter: Send + Sync {
    /// The stable identifier of this adapter.
    fn name(&self) -> &'static str;

    /// What this adapter establishes for the memory barrier.
    ///
    /// The level is relative to the capability. An adapter that establishes
    /// no mechanism at all reports [`GuaranteeLevel::None`], and no caller
    /// may read that as a weaker form of a barrier.
    fn guarantee(&self) -> GuaranteeLevel;

    /// Whether this host provides the mechanism.
    ///
    /// Must be cheap and must have no side effect: the resolver asks every
    /// named adapter, and the first-run probe asks every adapter in the
    /// build.
    fn availability(&self) -> AdapterAvailability;

    /// Allocates `bytes` of key material behind this adapter's barrier.
    ///
    /// The region must be as protected as the adapter's guarantee claims. An
    /// adapter that cannot protect the region refuses; it never hands back an
    /// unprotected one.
    fn allocate(&self, bytes: usize) -> Result<BarrieredRegion, BarrierError>;
}

/// The adapter that holds key material behind `memfd_secret(2)`.
///
/// The **primary** barrier: the pages backing the file are absent from the
/// kernel's direct map and are locked against swap by construction. That is a
/// strictly larger guarantee than either fallback, so the level is
/// [`GuaranteeLevel::Full`].
///
/// # The availability check
///
/// The mechanism's availability *is* whether `memfd_secret(2)` succeeds, and
/// the only honest way to answer that is to call it. The probe creates a
/// descriptor and closes it again, so nothing is left behind: the check leaves
/// no file, no mapping and no seal.
///
/// The probe is **not** the allocation. The allocation maps and locks the
/// pages; the probe only asks whether the syscall works at all, which is the
/// question the availability check exists to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemfdSecretBarrier;

impl MemfdSecretBarrier {
    /// The adapter's stable identifier.
    pub const NAME: &'static str = "memfd_secret";

    /// The reason the adapter gives on a host that does not provide the
    /// mechanism.
    pub const ABSENT: &'static str =
        "this host has no memfd_secret(2): the mechanism is Linux-only";
}

impl MemoryBarrierAdapter for MemfdSecretBarrier {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn guarantee(&self) -> GuaranteeLevel {
        // The pages are out of the kernel's direct map and cannot be swapped.
        // That is the capability's whole guarantee.
        GuaranteeLevel::Full
    }

    fn availability(&self) -> AdapterAvailability {
        match crate::barrier::probe_secret_available() {
            Ok(()) => AdapterAvailability::Available,
            Err(reason) => AdapterAvailability::Unavailable { reason },
        }
    }

    fn allocate(&self, bytes: usize) -> Result<BarrieredRegion, BarrierError> {
        // `RequireSecret`: the caller asked for this adapter, and a different
        // mechanism would not be the mechanism it named.
        crate::barrier::allocate(bytes, crate::barrier::BarrierPreference::RequireSecret)
    }
}

/// The adapter that holds key material behind a sealed `memfd`.
///
/// The **fallback**: an ordinary `memfd_create(2)` file with `MFD_ALLOW_SEALING`,
/// `F_SEAL_SEAL` and the shrink/grow seals applied, plus `MADV_DONTDUMP` and
/// `PR_SET_DUMPABLE=0`. The pages sit in ordinary memory and remain reachable
/// by a kernel-side read, so the guarantee is [`GuaranteeLevel::Weakened`].
///
/// It is a real mechanism and it is never reported as the primary one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedMemfdBarrier;

impl SealedMemfdBarrier {
    /// The adapter's stable identifier.
    pub const NAME: &'static str = "sealed_memfd";

    /// The reason the adapter gives on a host that does not provide the
    /// mechanism.
    pub const ABSENT: &'static str =
        "this host has no memfd_create(2): the mechanism is Linux-only";
}

impl MemoryBarrierAdapter for SealedMemfdBarrier {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn guarantee(&self) -> GuaranteeLevel {
        // Sealed against later writes and growth, but in ordinary memory.
        GuaranteeLevel::Weakened
    }

    fn availability(&self) -> AdapterAvailability {
        match crate::barrier::probe_sealed_available() {
            Ok(()) => AdapterAvailability::Available,
            Err(reason) => AdapterAvailability::Unavailable { reason },
        }
    }

    fn allocate(&self, bytes: usize) -> Result<BarrieredRegion, BarrierError> {
        // The sealed path is reached directly rather than through `allocate`'s
        // preference logic: this adapter *is* the fallback, and going through
        // the preference would let the primary be chosen for it.
        crate::barrier::allocate_sealed(bytes)
    }
}

/// The adapter that holds key material in `mlock(2)`-locked pages.
///
/// The **portable** barrier, and the weakest of the three. `mlock` keeps the
/// pages resident and stops them reaching swap, but it does **not** remove them
/// from the kernel's direct map and it does **not** exclude them from a dump:
/// Apple's own `mlock(2)` page says locked pages can be mapped by multiple
/// processes.
///
/// The level is [`GuaranteeLevel::Weakened`] for exactly that reason. The
/// adapter is a real mechanism and must never be reported as the primary
/// barrier.
///
/// # It adds no syscall
///
/// The mechanism is the existing [`crate::sys::Mapping::lock`], which already
/// calls `libc::mlock` unconditionally and is therefore already portable to
/// Darwin. The adapter adds a name, a guarantee level and an availability
/// check; it adds no `unsafe` and no syscall of its own.
///
/// # It refuses rather than degrades
///
/// FR-032: a failed lock is a refusal, not an unprotected region. The region
/// this adapter produces is locked *before* it is handed back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlockBarrier;

impl MlockBarrier {
    /// The adapter's stable identifier.
    pub const NAME: &'static str = "mlock";

    /// The reason the adapter gives on a host that cannot lock.
    pub const REFUSAL: &'static str =
        "the mlock adapter cannot lock the region: the pages would be ordinary memory";
}

impl MemoryBarrierAdapter for MlockBarrier {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn guarantee(&self) -> GuaranteeLevel {
        // Locked against swap, but still in the kernel's direct map and not
        // excluded from a dump. Weaker than the `memfd` mechanisms.
        GuaranteeLevel::Weakened
    }

    fn availability(&self) -> AdapterAvailability {
        // The mechanism's availability is whether `mlock` succeeds on a region
        // of a realistic size. The probe locks and unlocks a page, so it leaves
        // nothing behind.
        match crate::barrier::probe_mlock_available() {
            Ok(()) => AdapterAvailability::Available,
            Err(reason) => AdapterAvailability::Unavailable { reason },
        }
    }

    fn allocate(&self, bytes: usize) -> Result<BarrieredRegion, BarrierError> {
        // The refusal names the adapter (FR-013), so the operator can tell
        // which mechanism failed rather than being told only that a barrier
        // could not be established. The nested refusal still carries the
        // `LimitMEMLOCK=` value the operator would change.
        crate::barrier::allocate_mlock(bytes).map_err(|err| match err {
            BarrierError::NotLockable(refusal) => BarrierError::AdapterRefused {
                adapter: Self::NAME,
                reason: refusal.to_string(),
            },
            other => other,
        })
    }
}

/// The `memfd_secret` adapter, as the registry hands it out.
pub static MEMFD_SECRET_BARRIER: MemfdSecretBarrier = MemfdSecretBarrier;

/// The sealed-`memfd` adapter, as the registry hands it out.
pub static SEALED_MEMFD_BARRIER: SealedMemfdBarrier = SealedMemfdBarrier;

/// The `mlock` adapter, as the registry hands it out.
pub static MLOCK_BARRIER: MlockBarrier = MlockBarrier;

/// The adapter that establishes `kind`.
///
/// The mapping is 1:1: each [`BarrierKind`] is the residue of exactly one
/// mechanism, and each mechanism has exactly one adapter. The match is
/// exhaustive, so a new kind breaks the build here until it is given an
/// adapter — a kind with no adapter would be a region that no status line
/// could attribute.
///
/// [`crate::barrier`] calls this at every allocation site so the region carries
/// the name and level of the mechanism that produced it, rather than of the
/// kind it happened to leave behind.
pub fn adapter_for_kind(kind: BarrierKind) -> &'static dyn MemoryBarrierAdapter {
    match kind {
        BarrierKind::MemfdSecret => &MEMFD_SECRET_BARRIER,
        BarrierKind::SealedMemfd => &SEALED_MEMFD_BARRIER,
        BarrierKind::Mlock => &MLOCK_BARRIER,
    }
}
