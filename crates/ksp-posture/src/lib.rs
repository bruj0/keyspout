//! Host confinement and key-material posture (subsystem S5).
//!
//! This crate states, before a run, what the host can actually enforce. It
//! applies kernel path confinement to the opted-in process tree, keeps key
//! material out of ordinary memory, and reports both facts honestly —
//! including when a fact is weaker than it should be.
//!
//! Two misfits drive it:
//!
//! - **Misfit G (level escape)** — an agent on the `file` backend is the same
//!   principal as the user, so the levels tree is only a naming convention
//!   unless the kernel enforces it. [`confinement`] makes it real for the
//!   opted-in tree; [`descriptors`] removes the inherited descriptors that
//!   would otherwise sidestep the rules.
//! - **Misfit K (silent memory-barrier degradation)** — a host that cannot lock
//!   secret memory leaves the unsealed value in ordinary heap, indistinguishable
//!   from the secured path until it is too late. [`barrier`] and [`memlock`] make
//!   that failure loud and unavoidable.
//!
//! [`posture`] reports the two outcomes **separately**, because a run can be
//! perfectly confined and still hold an unlocked key in ordinary memory.
//!
//! [`permissions`] is the third measurement: whether each protected root still
//! carries the mode and owner it was created with. It is a measurement and not a
//! control — it reports a drift and refuses nothing by itself — because the
//! boundary is the mode, and a mode that drifted is not repaired by a check.
//!
//! # Confinement is not authentication
//!
//! Path confinement restricts *which paths* a process may reach. Only a
//! signature establishes *which key* is speaking. Both are required; neither
//! substitutes for the other. Nothing in this crate authenticates an agent, and
//! a `0711` parent directory letting its owner enumerate is not evidence of
//! identity either.

pub mod adapters;
pub mod barrier;
pub mod confinement;
pub mod descriptors;
pub mod landlock_types;
pub mod memlock;
pub mod permissions;
pub mod posture;
pub mod resolver;
pub mod rights;
mod sys;

pub use adapters::{
    ConfinementAdapter, LANDLOCK_CONFINEMENT, MemoryBarrierAdapter, PORTABLE_CONFINEMENT,
    capability_of, confinement_adapter, memory_barrier_adapter,
};
pub use barrier::{
    BarrierError, BarrierKind, BarrierPreference, BarrieredRegion, allocate as allocate_region,
};
pub use confinement::{
    AppliedRuleset, ConfinedChild, ConfinementError, ConfinementRefusal, ConfinementRule,
    ConfinementSpec, RefusalStage, restrict_then_launch,
};
pub use descriptors::{DescriptorError, DescriptorPolicy, SanitationReport, sanitize};
pub use landlock_types::{CompatLevel, LandlockAbi};
pub use memlock::{
    CORE_DUMP_MECHANISM, ControlOutcome, LockabilityRefusal, MemlockError, MemlockObservation,
    UndumpablePosture, ptrace_mechanism,
};

/// Applies both dump controls to the calling process and reports each one.
///
/// The barrier calls this itself when it allocates a region. It is public for
/// the one caller that reports a posture without allocating one — `ksp status`
/// — so the control it prints is one it actually applied rather than one it
/// inferred from the configuration.
///
/// The attach refusal is permanent for this process: a debugger attached after
/// this call kills it. Call it as late as the caller can.
pub fn refuse_dumping() -> UndumpablePosture {
    memlock::set_undumpable()
}
pub use permissions::{
    ExpectedOwner, ExpectedRoot, PERMISSION_BITS, PermissionFinding, RootKind, Verdict, audit,
    drifted, effective_uid, first_drift,
};
pub use posture::{
    BackendShape, BarrierPosture, CapabilityDisclosure, ConfinementPosture, ConfinementState,
    HostPosture, LandlockObservation, PostureDecision, Requirement, RunDecision,
};
pub use resolver::{
    Resolution, SelectedAdapter, SkippedAdapter, UnavailableCapability, resolve_confinement,
    resolve_memory_barrier, resolve_with, satisfies,
};
pub use rights::{AccessRight, RightSet};
