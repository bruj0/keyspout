//! The path-confinement adapter trait, and the one adapter that needs no
//! platform mechanism.
//!
//! The trait describes a **mechanism**: a way of restricting which paths a
//! process tree may reach. It carries no policy and no configuration, and it
//! knows nothing about the file format the operator wrote.

use crate::confinement::{ConfinedChild, ConfinementError, ConfinementSpec};
use ksp_types::{AdapterAvailability, GuaranteeLevel};

/// A mechanism that establishes path confinement for a process tree.
///
/// The trait is object-safe, so the registry can hold
/// `&'static dyn ConfinementAdapter`. That rules out generic methods and any
/// `Self` in a return position.
///
/// The three facts it reports are separate on purpose:
///
/// - [`name`](Self::name) is what the adapter is called;
/// - [`guarantee`](Self::guarantee) is what it establishes for the capability;
/// - [`availability`](Self::availability) is whether **this host** provides the
///   mechanism.
///
/// The availability is the host's fact. Whether the adapter is *in this
/// build* is the registry's fact, and the registry answers it separately.
pub trait ConfinementAdapter: Send + Sync {
    /// The stable identifier of this adapter.
    fn name(&self) -> &'static str;

    /// What this adapter establishes for path confinement.
    ///
    /// The level is relative to the capability. An adapter that establishes
    /// no mechanism at all reports [`GuaranteeLevel::None`], and no caller
    /// may read that as a weaker form of confinement.
    fn guarantee(&self) -> GuaranteeLevel;

    /// Whether this host provides the mechanism.
    ///
    /// Must be cheap and must have no side effect: the resolver asks every
    /// named adapter, and the first-run probe asks every adapter in the
    /// build.
    fn availability(&self) -> AdapterAvailability;

    /// Applies the confinement and yields the value that can launch a child.
    ///
    /// The ruleset must be in force before the child exists. The existing
    /// ordering in [`crate::confinement::restrict_then_launch`] already
    /// guarantees that, and an adapter must not invert it.
    ///
    /// # It confines the caller, irreversibly
    ///
    /// This is not a dry run. Applying a ruleset calls `restrict_self` on the
    /// **calling** process, and the restriction holds for the rest of that
    /// process's life. A refusal is decided *after* the restriction is in
    /// force, so a caller cannot rely on `Err` meaning "nothing happened".
    ///
    /// Never call this from a test harness, a probe that shares its process,
    /// or any long-lived process that intends to keep reaching paths outside
    /// the ruleset. A test that needs the kernel's answer re-executes a
    /// throwaway child and calls it there — see the probes in
    /// `tests/confinement.rs`.
    fn establish(&self, spec: &ConfinementSpec) -> Result<ConfinedChild, ConfinementError>;
}

/// The adapter that establishes no confinement at all.
///
/// It exists so that a host with no kernel path confinement still has an
/// answer for the capability: the CLI runs, and the posture says plainly that
/// the child is not confined.
///
/// It is **not** a weaker confinement. It establishes nothing, so its
/// guarantee is [`GuaranteeLevel::None`] and its
/// [`establish`](ConfinementAdapter::establish) always refuses.
///
/// The refusal is structural rather than a special case: a [`ConfinedChild`]
/// can only be produced by applying a real ruleset, so an adapter that
/// applies none cannot hand one back. Returning `Ok` here would mean
/// inventing a confined child that is not confined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortableConfinement;

impl PortableConfinement {
    /// The adapter's stable identifier.
    ///
    /// It is the same string the closed name set spells, so the identifier the
    /// adapter reports and the name the registry answers to cannot drift apart.
    /// The name set is closed, so a sixth adapter would not have a spelling
    /// here at all.
    pub const NAME: &'static str = "portable_confinement";

    /// The reason the adapter gives when it is asked to confine anything.
    ///
    /// It names the adapter and says it establishes no mechanism, so a
    /// disclosure can quote it rather than paraphrase it.
    pub const REFUSAL: &'static str =
        "portable_confinement establishes no mechanism: the child is not confined";
}

impl ConfinementAdapter for PortableConfinement {
    fn name(&self) -> &'static str {
        // The spelling is pinned to the closed name set by a test, so a
        // spelling that drifts from the set fails the build rather than
        // making the adapter unreachable by the name the operator configured.
        Self::NAME
    }

    fn guarantee(&self) -> GuaranteeLevel {
        // No mechanism, so no guarantee. A level above `None` here would be a
        // claim the adapter cannot back.
        GuaranteeLevel::None
    }

    fn availability(&self) -> AdapterAvailability {
        // The adapter can always be *selected*: it needs nothing from the
        // host. That is a different fact from the mechanism being enforced,
        // and the guarantee above is what carries the difference.
        AdapterAvailability::Available
    }

    fn establish(&self, _spec: &ConfinementSpec) -> Result<ConfinedChild, ConfinementError> {
        // `NoMechanism`, not `NotEnforced`: this adapter never asks the kernel
        // for anything, so there is no kernel status to report. Naming Landlock
        // would send the operator to inspect a kernel the run never called.
        Err(ConfinementError::NoMechanism {
            adapter: Self::NAME,
            reason: Self::REFUSAL.to_string(),
        })
    }
}

/// The one portable confinement adapter, as the registry hands it out.
pub static PORTABLE_CONFINEMENT: PortableConfinement = PortableConfinement;

/// The adapter that confines through the kernel's Landlock mechanism.
///
/// # What it wraps
///
/// The existing ruleset code in [`crate::confinement`], unchanged. The adapter
/// adds a name, a guarantee level and an availability check; it does not add a
/// mechanism, and it does not change the ordering.
///
/// # The ordering is not the adapter's to change
///
/// FR-012 requires the ruleset to be in force before the child exists. The
/// existing [`crate::confinement::restrict_then_launch`] already guarantees
/// that: it applies the ruleset inside itself and yields the only value that
/// can launch. The adapter calls it and returns what it produced, so the
/// ordering stays structural rather than becoming a convention the adapter
/// upholds.
///
/// # The availability is the ABI query, and it is the *same* query
///
/// The crate already asks the kernel for its Landlock ABI in
/// [`crate::confinement::ConfinementSpec::refusal`]. The adapter reuses
/// [`crate::sys::landlock_abi`] rather than making a second query: two queries
/// are two chances to disagree, and a refusal computed against one ABI while
/// the adapter reported another would describe two different kernels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LandlockConfinement;

impl LandlockConfinement {
    /// The adapter's stable identifier.
    ///
    /// The same string the closed name set spells, so the identifier the
    /// adapter reports and the name the registry answers to cannot drift apart.
    pub const NAME: &'static str = "landlock";

    /// The reason the adapter gives on a host with no Landlock.
    ///
    /// It names the mechanism and says the kernel does not provide it, so an
    /// operator is sent to the kernel rather than to a rule path.
    pub const ABSENT: &'static str = "this host has no Landlock: the mechanism is Linux-only and this kernel does not provide it";
}

impl ConfinementAdapter for LandlockConfinement {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn guarantee(&self) -> GuaranteeLevel {
        // Landlock enforces exactly the rules the run asks for, and a required
        // spec refuses rather than degrading. That is the capability's whole
        // guarantee.
        GuaranteeLevel::Full
    }

    fn availability(&self) -> AdapterAvailability {
        // The kernel's own answer, and the same query the refusal path makes.
        match crate::sys::landlock_abi() {
            Some(_abi) => AdapterAvailability::Available,
            None => AdapterAvailability::Unavailable {
                reason: Self::ABSENT.to_string(),
            },
        }
    }

    fn establish(&self, spec: &ConfinementSpec) -> Result<ConfinedChild, ConfinementError> {
        // The existing code, unchanged. It applies the ruleset before it
        // yields the value that can launch, so FR-012 holds by construction
        // rather than by this adapter's care.
        let mut child = crate::confinement::restrict_then_launch(spec)?;

        // The adapter names itself on the result. The mechanism does not know
        // which adapter called it — the adapter is a wrapper around it — so
        // without this the posture could not say which mechanism ran, and a
        // reader could not tell a configured `landlock` from another adapter
        // (FR-007).
        child.applied_mut().named(Self::NAME, self.guarantee());
        Ok(child)
    }
}

/// The Landlock adapter, as the registry hands it out.
pub static LANDLOCK_CONFINEMENT: LandlockConfinement = LandlockConfinement;
