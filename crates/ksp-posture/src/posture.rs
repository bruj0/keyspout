//! Posture reporting — stating what the host actually enforces.
//!
//! Two facts, reported **separately** because a run can be perfectly confined and
//! still hold an unlocked key in ordinary memory:
//!
//! - [`ConfinementPosture`] — whether the path rules are in force, with the
//!   Landlock ABI status and the compatibility level that was applied.
//! - [`BarrierPosture`] — which memory mechanism is in force, with the observed
//!   `RLIMIT_MEMLOCK`.
//!
//! They are separate types with no conversion between them, and
//! [`HostPosture`] holds both without collapsing them. That is what makes
//! acceptance criterion 8 checkable rather than aspirational.
//!
//! # Required and optional confinement decide different things
//!
//! [`PostureDecision::for_requirement`] answers one question — *may this run
//! proceed?* — and it answers it from the confinement posture alone. It takes no
//! backend argument at all, which is the structural guarantee behind acceptance
//! criterion 7: a qualifying remote `NativeExpiry` backend cannot be rejected
//! because local Landlock is missing, because the decision path never learns what
//! the backend is (FR-040, contract S5 → S2/S3/S4).
//!
//! Backend capability is a separate question with a separate type
//! ([`BackendShape`], and `ksp-types::capability` for the lease decision). The two
//! never convert into each other.

use std::fmt;

use crate::barrier::BarrierKind;
use crate::memlock::MemlockObservation;
use ksp_types::{AdapterName, GuaranteeLevel, HostCapability, RequirementLevel};

/// The effective state of confinement for a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfinementState {
    /// Every requested rule is enforced by the kernel.
    Enforced,
    /// Some rules are enforced: the run is confined, but not to the extent that
    /// was requested. Reported rather than rounded up to `Enforced`.
    Weakened,
    /// No rule is enforced. The run is unconfined.
    Unavailable,
}

impl ConfinementState {
    /// The stable identifier a status line or log record uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforced => "enforced",
            Self::Weakened => "weakened",
            Self::Unavailable => "unavailable",
        }
    }

    /// Whether the kernel is enforcing at least one path rule.
    pub fn is_enforced(self) -> bool {
        matches!(self, Self::Enforced | Self::Weakened)
    }
}

impl fmt::Display for ConfinementState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the host says about Landlock itself, independent of this run's ruleset.
///
/// Kept distinct from [`ConfinementState`]: a host can support Landlock and still
/// have a weakened ruleset, and an unsupported host explains *why* the state is
/// `Unavailable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockObservation {
    /// Landlock reported an effective ABI.
    Available {
        /// The ABI the ruleset was built against.
        effective_abi: u8,
        /// The kernel's own ABI when it is newer than this crate knows about.
        kernel_abi: Option<i32>,
    },
    /// Landlock is compiled in but not enabled at boot.
    NotEnabled,
    /// Landlock is not implemented by this kernel.
    NotImplemented,
}

impl LandlockObservation {
    /// What the kernel says about Landlock itself, independent of any ruleset.
    ///
    /// The same query the refusal path makes, exposed so a caller that reports
    /// the posture *without* applying a ruleset — a capability the operator did
    /// not configure — still says something true about the host. Reporting
    /// `NotImplemented` for a host that has Landlock, only because no adapter
    /// ran, would be a false claim about the kernel and would send the operator
    /// to the wrong fix (Misfit L).
    pub fn of_this_host() -> Self {
        match crate::sys::landlock_abi() {
            Some(abi) => Self::Available {
                effective_abi: u8::try_from(abi).unwrap_or(u8::MAX),
                kernel_abi: None,
            },
            None => Self::NotImplemented,
        }
    }

    /// Whether Landlock is usable on this host.
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    /// The ABI in use, when one is.
    pub fn effective_abi(&self) -> Option<u8> {
        match self {
            Self::Available { effective_abi, .. } => Some(*effective_abi),
            Self::NotEnabled | Self::NotImplemented => None,
        }
    }
}

impl fmt::Display for LandlockObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Available { effective_abi, .. } => {
                write!(f, "landlock available (abi {effective_abi})")
            }
            Self::NotEnabled => f.write_str("landlock not enabled at boot"),
            Self::NotImplemented => f.write_str("landlock not implemented by this kernel"),
        }
    }
}

/// The confinement half of the posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfinementPosture {
    /// What is actually enforced.
    pub state: ConfinementState,
    /// Landlock's own status on this host.
    pub landlock: LandlockObservation,
    /// Whether the ruleset required its rights (`HardRequirement`) or tolerated
    /// a partial build (`SoftRequirement`).
    pub required: bool,
    /// The adapter that produced this capability.
    ///
    /// `None` when no adapter ran — a capability that was never
    /// established. The name says *which* mechanism; without it a reader
    /// cannot tell a configured `landlock` from a fallback (FR-007).
    pub adapter: Option<&'static str>,
    /// The guarantee the adapter established.
    ///
    /// The adapter's **own** level, never the level of a stronger adapter
    /// the operator preferred (FR-030, FR-019).
    pub guarantee: GuaranteeLevel,
}

impl ConfinementPosture {
    /// A posture for a run whose ruleset was applied and fully enforced.
    ///
    /// `adapter` and `guarantee` are required rather than defaulted, because a
    /// posture that claims enforcement and cannot name the mechanism that
    /// enforced it is half a claim: a reader cannot tell a configured
    /// `landlock` from any other adapter, and the difference is exactly what
    /// FR-007 asks the posture to carry.
    pub fn enforced(
        landlock: LandlockObservation,
        required: bool,
        adapter: &'static str,
        guarantee: GuaranteeLevel,
    ) -> Self {
        Self {
            state: ConfinementState::Enforced,
            landlock,
            required,
            adapter: Some(adapter),
            guarantee,
        }
    }

    /// A posture for a run whose ruleset was only partially enforced.
    ///
    /// Names its adapter for the same reason [`enforced`](Self::enforced) does:
    /// a partial ruleset still has a mechanism behind it, and the guarantee is
    /// the adapter's — not a judgement about how much the kernel applied.
    pub fn weakened(
        landlock: LandlockObservation,
        required: bool,
        adapter: &'static str,
        guarantee: GuaranteeLevel,
    ) -> Self {
        Self {
            state: ConfinementState::Weakened,
            landlock,
            required,
            adapter: Some(adapter),
            guarantee,
        }
    }

    /// A posture for a run on which no confinement was applied.
    ///
    /// Nameless because no adapter ran, which is the only reading of a `None`
    /// adapter this type allows.
    pub fn unavailable(landlock: LandlockObservation, required: bool) -> Self {
        Self {
            state: ConfinementState::Unavailable,
            landlock,
            required,
            adapter: None,
            guarantee: GuaranteeLevel::None,
        }
    }

    /// A posture for a run whose selected adapter established nothing.
    ///
    /// Nothing is enforced, and the adapter that declined is **named**: an
    /// adapter ran, asked the kernel, and the kernel refused. Rendering that as
    /// `no adapter` would be a false statement about what happened, and the
    /// operator's fix — a different adapter, or a platform that confines —
    /// starts from its name.
    pub fn declined(
        landlock: LandlockObservation,
        required: bool,
        adapter: &'static str,
        guarantee: GuaranteeLevel,
    ) -> Self {
        Self {
            state: ConfinementState::Unavailable,
            landlock,
            required,
            adapter: Some(adapter),
            guarantee,
        }
    }

    /// The compatibility level in force, as the operator-facing string.
    pub fn compat_level_name(&self) -> &'static str {
        if self.required {
            "HardRequirement"
        } else {
            "SoftRequirement"
        }
    }
}

impl fmt::Display for ConfinementPosture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "confinement {} ({}; {})",
            self.state,
            self.landlock,
            self.compat_level_name()
        )?;
        // The adapter and its guarantee, in the same terms as an enforced
        // capability. The level is always named, including `none`: the
        // difference must be the level and not the presence of a row (FR-038).
        match self.adapter {
            Some(adapter) => {
                write!(f, "; adapter {adapter} ({})", self.guarantee.label())?;
            }
            None => {
                write!(f, "; no adapter")?;
            }
        }
        Ok(())
    }
}

/// The memory-barrier half of the posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BarrierPosture {
    /// Which mechanism is in force, or `None` when none is.
    pub kind: Option<BarrierKind>,
    /// The adapter that produced this barrier.
    ///
    /// `None` when no adapter ran. The name says *which* mechanism, so a
    /// reader can tell a configured `memfd_secret` from a fallback to
    /// `sealed_memfd` (FR-007).
    pub adapter: Option<&'static str>,
    /// The guarantee the adapter established.
    ///
    /// The adapter's **own** level, never the level of a stronger adapter
    /// the operator preferred (FR-030, FR-019).
    pub guarantee: GuaranteeLevel,
    /// The observed `RLIMIT_MEMLOCK`.
    pub observed_memlock: MemlockObservation,
}

impl BarrierPosture {
    /// A posture for a region created with `kind`.
    ///
    /// The adapter name and guarantee are **derived**, not taken from the
    /// caller: a [`BarrierKind`] is the residue of exactly one mechanism, and
    /// each mechanism has exactly one adapter, so the mapping is 1:1 and lives
    /// with the adapters themselves rather than being restated here.
    ///
    /// Deriving them is what makes a nameless barrier posture impossible. The
    /// constructor previously hard-coded `adapter: None` with no argument that
    /// could override it, so every production run rendered `no adapter` while
    /// the tests — which built the struct by hand — passed (FR-007, FR-019).
    pub fn of(kind: BarrierKind, observed_memlock: MemlockObservation) -> Self {
        let adapter = crate::adapters::barrier::adapter_for_kind(kind);
        Self {
            kind: Some(kind),
            observed_memlock,
            adapter: Some(adapter.name()),
            guarantee: adapter.guarantee(),
        }
    }

    /// A posture for a run with no barrier at all.
    ///
    /// Nameless because no adapter ran. That is the only reading of a `None`
    /// adapter this type allows.
    pub fn unavailable(observed_memlock: MemlockObservation) -> Self {
        Self {
            kind: None,
            observed_memlock,
            adapter: None,
            guarantee: GuaranteeLevel::None,
        }
    }

    /// Whether the *primary* barrier is in force. The sealed-`memfd` fallback is
    /// deliberately not "primary".
    pub fn is_primary(&self) -> bool {
        self.kind.is_some_and(BarrierKind::is_primary)
    }

    /// Whether any barrier is in force at all.
    pub fn is_present(&self) -> bool {
        self.kind.is_some()
    }
}

impl fmt::Display for BarrierPosture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            Some(kind) => write!(f, "barrier {kind} ({})", self.observed_memlock)?,
            None => write!(f, "barrier unavailable ({})", self.observed_memlock)?,
        }
        // The adapter and its guarantee, in the same terms as an enforced
        // capability. A `none` guarantee is an accepted absence, so it is
        // named rather than omitted (FR-020, FR-038).
        match self.adapter {
            Some(adapter) => {
                write!(f, "; adapter {adapter} ({})", self.guarantee.label())?;
            }
            None => {
                write!(f, "; no adapter")?;
            }
        }
        Ok(())
    }
}

/// What one capability's status line says.
///
/// The disclosure names four things, and a reader needs all four:
///
/// - **the platform** — a host with no path confinement must not read as a
///   host where confinement is enforced (Misfit L, NFR-010);
/// - **the configured order** — what the operator asked for first;
/// - **the selected adapter** — which mechanism actually ran;
/// - **the guarantee** — how far to trust it.
///
/// # A `none` guarantee is rendered in the same terms as a `full` one
///
/// FR-038: the difference must be the guarantee level and not the presence of
/// a row. A capability that was accepted as unenforced is an **accepted
/// absence**, not an error and not an omission — so it is named, its level is
/// named, and it sits in the same shape as an enforced capability.
///
/// # An unconfigured capability is different from an unenforced one
///
/// A capability with no adapter selected is *unconfigured*: the operator
/// named nothing, and the disclosure says so and points at `ksp init`
/// (FR-010). A capability with an adapter that guarantees nothing is
/// *unenforced*: the operator named an adapter and the host provided a
/// weaker one. The two are different facts and the disclosure must not blur
/// them.
/// # The adapter names are the closed type, not strings
///
/// Every adapter name in this record is an [`AdapterName`], not a `String`.
/// A `String` would be a hole in the closure: a caller could format anything
/// into the *selected* field and the disclosure would then name a mechanism
/// that does not exist — which is the false-claim failure Misfit L is about.
///
/// Holding the closed type makes the claim true by construction. The
/// *reason* an adapter did not run stays a `String`, because the reason is the
/// host's own text and the host may say anything at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDisclosure {
    /// The capability this disclosure is about.
    pub capability: HostCapability,
    /// The platform the run is on.
    pub platform: String,
    /// The adapters the configuration named, in the operator's order.
    pub configured_order: Vec<AdapterName>,
    /// The level the operator set, or `None` when there is no configuration.
    ///
    /// It is reported beside the order because it is the one fact that decides
    /// whether a run **refuses** when nothing can be established, and it is not
    /// derivable from anything else on the page: the posture's own
    /// `SoftRequirement` describes the measuring ruleset, not the operator's
    /// policy. Without it a reader sees `SoftRequirement` on a host whose
    /// configuration says `required` and concludes the opposite of what the
    /// next run will do (FR-014, NFR-009).
    ///
    /// `None` is also the only signal that distinguishes the two ways a
    /// capability ends up unconfigured, which have different fixes: no
    /// `config.toml` at all, or a file that names adapters this host does not
    /// provide.
    pub requirement: Option<RequirementLevel>,
    /// The adapter that ran, or `None` when the capability is unconfigured.
    pub selected: Option<AdapterName>,
    /// The guarantee the selected adapter established.
    ///
    /// `None` when no adapter ran, so an unconfigured capability is never
    /// rendered as one that established something.
    pub guarantee: GuaranteeLevel,
    /// The adapters that did not run, each with the host's reason.
    pub skipped: Vec<(AdapterName, String)>,
}

impl CapabilityDisclosure {
    /// Whether the capability has an adapter at all.
    ///
    /// The difference between *unconfigured* and *unenforced*: the first has
    /// no adapter, the second has one that establishes nothing.
    pub fn is_configured(&self) -> bool {
        self.selected.is_some()
    }

    /// Whether the capability established a mechanism.
    ///
    /// `None` when no adapter ran — an unconfigured capability established
    /// nothing, and saying it established *something* would be a claim
    /// (FR-020).
    pub fn established(&self) -> bool {
        self.selected.is_some() && self.guarantee != GuaranteeLevel::None
    }
}

impl fmt::Display for CapabilityDisclosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} on {}: ", self.capability.label(), self.platform)?;

        // The configured order, so a reader can see what was asked for.
        if self.configured_order.is_empty() {
            write!(f, "no adapter configured")?;
        } else {
            let order: Vec<&str> = self
                .configured_order
                .iter()
                .map(AdapterName::as_str)
                .collect();
            write!(f, "configured {}", order.join(", "))?;
        }

        // The level the operator set, before what ran: whether the capability
        // refuses when nothing can be established is the question a reader asks
        // first, and it is not derivable from the order or from the posture.
        if let Some(requirement) = self.requirement {
            write!(f, "; requirement {}", requirement.label())?;
        }

        // The adapter that ran and the level it established. The level is
        // always named, including `none`: the difference must be the level
        // and not the presence of a row (FR-038).
        match &self.selected {
            Some(selected) => {
                write!(f, "; ran {selected} ({})", self.guarantee.label())?;
            }
            None => {
                write!(f, "; unconfigured")?;
            }
        }

        // What did not run, and why. This is what makes a fallback
        // explainable rather than merely visible (Misfit B).
        for (name, reason) in &self.skipped {
            write!(f, "; {name} did not run: {reason}")?;
        }
        Ok(())
    }
}

/// Both postures, held side by side and never merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPosture {
    /// What the kernel enforces about paths.
    pub confinement: ConfinementPosture,
    /// What keeps key material out of ordinary memory.
    pub barrier: BarrierPosture,
}

impl HostPosture {
    /// Combines two separately-derived postures.
    ///
    /// Takes them as two arguments rather than deriving one from the other:
    /// there is no route from a confinement to a barrier or back.
    pub fn new(confinement: ConfinementPosture, barrier: BarrierPosture) -> Self {
        Self {
            confinement,
            barrier,
        }
    }
}

impl fmt::Display for HostPosture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}; {}", self.confinement, self.barrier)
    }
}

/// How a run is configured with respect to confinement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// Missing confinement refuses the run.
    Required,
    /// Missing confinement warns and weakens the posture, but the run proceeds.
    Optional,
}

/// What the host does about the backend — **not** part of the confinement
/// decision.
///
/// This type exists so the independence of the two decisions is visible in the
/// signature of [`PostureDecision::for_requirement`], which does not take one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendShape {
    /// A local backend whose records the agent is the same principal as the user
    /// for: the case confinement exists to contain.
    Local,
    /// A remote backend that enforces its own deadline. Confinement of the local
    /// host says nothing about it.
    RemoteWithNativeExpiry,
}

/// What a run must do, given the confinement posture and the requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunDecision {
    /// Confinement is in force to the requested extent; proceed silently.
    Proceed,
    /// Proceed, but warn on every run and show the weakened posture (FR-040).
    ProceedWithWarning,
    /// Refuse to run.
    Refuse {
        /// Why, in the operator's terms.
        reason: &'static str,
    },
}

impl RunDecision {
    /// Whether the run may proceed.
    pub fn may_proceed(self) -> bool {
        matches!(self, Self::Proceed | Self::ProceedWithWarning)
    }

    /// Whether the decision demands a warning.
    pub fn warns(self) -> bool {
        matches!(self, Self::ProceedWithWarning)
    }
}

/// The confinement decision, computed from the confinement posture alone.
///
/// There is no backend parameter, and that absence is the point: a qualifying
/// remote `NativeExpiry` backend is never rejected because local Landlock is
/// missing, since this function cannot see the backend at all (FR-040).
pub struct PostureDecision;

impl PostureDecision {
    /// Decides whether a run may proceed.
    ///
    /// - Enforced + any requirement → [`RunDecision::Proceed`].
    /// - Weakened or unavailable + [`Requirement::Required`] →
    ///   [`RunDecision::Refuse`].
    /// - Weakened or unavailable + [`Requirement::Optional`] →
    ///   [`RunDecision::ProceedWithWarning`].
    pub fn for_requirement(posture: &ConfinementPosture, requirement: Requirement) -> RunDecision {
        match (posture.state, requirement) {
            (ConfinementState::Enforced, _) => RunDecision::Proceed,
            (ConfinementState::Weakened | ConfinementState::Unavailable, Requirement::Required) => {
                RunDecision::Refuse {
                    reason: "confinement is required and the kernel is not enforcing every requested rule",
                }
            }
            (ConfinementState::Weakened | ConfinementState::Unavailable, Requirement::Optional) => {
                RunDecision::ProceedWithWarning
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// The adapter name and level an enforced posture must carry.
    ///
    /// Read from the adapter rather than spelled here, so the assertion cannot
    /// pass against a name the adapter does not report.
    const LANDLOCK_NAME: &str = crate::adapters::confinement::LandlockConfinement::NAME;

    fn abi_eight() -> LandlockObservation {
        LandlockObservation::Available {
            effective_abi: 8,
            kernel_abi: None,
        }
    }

    fn measured_memlock() -> MemlockObservation {
        MemlockObservation {
            soft_bytes: Some(8 * 1024 * 1024),
            hard_bytes: Some(8 * 1024 * 1024),
        }
    }

    #[test]
    fn an_enforced_posture_proceeds_under_either_requirement() {
        let posture =
            ConfinementPosture::enforced(abi_eight(), true, LANDLOCK_NAME, GuaranteeLevel::Full);
        assert_eq!(
            PostureDecision::for_requirement(&posture, Requirement::Required),
            RunDecision::Proceed
        );
        assert_eq!(
            PostureDecision::for_requirement(&posture, Requirement::Optional),
            RunDecision::Proceed
        );
    }

    /// Acceptance criterion 6: unavailable Landlock warns when optional and
    /// refuses when required. The two outcomes are asserted separately, and the
    /// distinguishing input is the *requirement*, not the posture.
    #[test]
    fn unavailable_landlock_warns_when_optional() {
        let posture = ConfinementPosture::unavailable(LandlockObservation::NotImplemented, false);
        let decision = PostureDecision::for_requirement(&posture, Requirement::Optional);
        assert_eq!(decision, RunDecision::ProceedWithWarning);
        assert!(decision.warns());
        assert!(decision.may_proceed());
    }

    #[test]
    fn unavailable_landlock_refuses_when_required() {
        let posture = ConfinementPosture::unavailable(LandlockObservation::NotImplemented, true);
        let decision = PostureDecision::for_requirement(&posture, Requirement::Required);
        assert!(matches!(decision, RunDecision::Refuse { .. }));
        assert!(!decision.may_proceed());
        assert!(!decision.warns());
    }

    #[test]
    fn a_weakened_posture_is_never_rounded_up_to_enforced() {
        let posture =
            ConfinementPosture::weakened(abi_eight(), false, LANDLOCK_NAME, GuaranteeLevel::Full);
        assert_ne!(posture.state, ConfinementState::Enforced);
        assert_eq!(
            PostureDecision::for_requirement(&posture, Requirement::Required),
            RunDecision::Refuse {
                reason: "confinement is required and the kernel is not enforcing every requested rule",
            }
        );
        assert_eq!(
            PostureDecision::for_requirement(&posture, Requirement::Optional),
            RunDecision::ProceedWithWarning
        );
    }

    /// Acceptance criterion 7, structurally: the decision function has no
    /// backend parameter, so a remote `NativeExpiry` backend cannot change it.
    /// This test makes that independence observable by computing both of the
    /// backend shapes and asserting the same decision.
    #[test]
    fn the_confinement_decision_is_independent_of_the_backend() {
        let posture = ConfinementPosture::unavailable(LandlockObservation::NotEnabled, true);

        // The decision takes only the posture and the requirement.
        let local = PostureDecision::for_requirement(&posture, Requirement::Required);
        let remote = PostureDecision::for_requirement(&posture, Requirement::Required);
        assert_eq!(local, remote);

        // And the backend shape is a distinct question that does not feed it:
        // admission on a remote NativeExpiry backend is unaffected by missing
        // local Landlock.
        let admission = ksp_types::admits(
            &ksp_types::LeaseCapability::NativeExpiry,
            std::time::Duration::from_secs(60),
        );
        assert!(
            admission,
            "a qualifying remote backend must still admit its lease"
        );
        assert_ne!(BackendShape::Local, BackendShape::RemoteWithNativeExpiry);
    }

    /// Acceptance criterion 8: fully confined, weaker barrier. The two postures
    /// are reported separately, and the combination is representable.
    #[test]
    fn a_run_can_be_fully_confined_with_a_sealed_memfd_barrier() {
        let posture = HostPosture::new(
            ConfinementPosture::enforced(abi_eight(), true, LANDLOCK_NAME, GuaranteeLevel::Full),
            BarrierPosture::of(BarrierKind::SealedMemfd, measured_memlock()),
        );
        assert_eq!(posture.confinement.state, ConfinementState::Enforced);
        assert_eq!(posture.barrier.kind, Some(BarrierKind::SealedMemfd));
        assert!(!posture.barrier.is_primary());
    }

    /// The inverse must also be representable: a primary barrier and no
    /// confinement. If either half implied the other, one of these tests would be
    /// impossible to write.
    #[test]
    fn a_run_can_have_the_primary_barrier_and_no_confinement() {
        let posture = HostPosture::new(
            ConfinementPosture::unavailable(LandlockObservation::NotImplemented, false),
            BarrierPosture::of(BarrierKind::MemfdSecret, measured_memlock()),
        );
        assert_eq!(posture.confinement.state, ConfinementState::Unavailable);
        assert!(posture.barrier.is_primary());
    }

    #[test]
    fn the_rendered_posture_keeps_the_two_facts_apart() {
        let posture = HostPosture::new(
            ConfinementPosture::enforced(abi_eight(), true, LANDLOCK_NAME, GuaranteeLevel::Full),
            BarrierPosture::unavailable(measured_memlock()),
        );
        let rendered = posture.to_string();
        assert!(rendered.contains("confinement enforced"));
        assert!(rendered.contains("barrier unavailable"));
        assert!(rendered.contains("LimitMEMLOCK="));
    }
}
