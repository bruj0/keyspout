//! Kernel path confinement — the Misfit G fix.
//!
//! An agent on the `file` backend is the same principal as the user, so the
//! levels tree is only a naming convention unless the kernel enforces it. This
//! module applies `LANDLOCK_RULE_PATH_BENEATH` rules over `O_PATH` descriptors
//! **before** the opted-in process tree is launched, so the ordering
//! (restrict, then `fork`/`exec`) is structural rather than a convention.
//!
//! # Confinement is not authentication
//!
//! The rules restrict *which paths* a process may reach. Only a signature
//! establishes *which key* is speaking, and nothing here authenticates an agent.
//! A `0711` parent directory lets its **owner** enumerate while a non-owner
//! cannot list; neither fact establishes identity.
//!
//! # Compatibility is a requirement, not a preference
//!
//! `landlock` 0.4.7's default [`CompatLevel::BestEffort`] silently downgrades
//! unsupported features, which would let the crate claim enforcement it did not
//! achieve. A [`ConfinementSpec`] that requires confinement builds its ruleset
//! with [`CompatLevel::HardRequirement`], so an unsupported right is an error
//! instead of a silent reduction.
//!
//! # The ordering
//!
//! [`restrict_then_launch`] is the only way to run a child under a
//! ruleset. It takes the [`ConfinementSpec`], applies the ruleset to the calling
//! process, and only then yields a [`ConfinedChild`] — which is the only value
//! that can launch. There is no API that launches first and restricts after,
//! because that order is the bug.

use std::fmt;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use landlock::{
    Compatible, LandlockStatus, RestrictSelfAttr, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
};

use crate::landlock_types::{CompatLevel, LandlockAbi};
use crate::posture::{ConfinementPosture, ConfinementState, LandlockObservation};
use crate::rights::{AccessRight, RightSet};
use ksp_types::GuaranteeLevel;

/// Converts this crate's compatibility level into the `landlock` crate's.
///
/// The one place the two vocabularies meet, for the level. A second conversion
/// is a second chance to disagree with the first: a spec that asked for
/// `HardRequirement` and got `BestEffort` would silently downgrade the
/// ruleset, which is the exact failure this crate exists to prevent.
#[cfg(target_os = "linux")]
fn to_landlock_compat(level: CompatLevel) -> landlock::CompatLevel {
    match level {
        CompatLevel::BestEffort => landlock::CompatLevel::BestEffort,
        CompatLevel::SoftRequirement => landlock::CompatLevel::SoftRequirement,
        CompatLevel::HardRequirement => landlock::CompatLevel::HardRequirement,
    }
}

/// One allowed path and the access rights granted beneath it.
///
/// The vault root and each level subtree are separate rules with separate
/// rights, which is what makes the levels tree real: the confined run may read
/// its own level and is denied a [`Sibling Path`].
///
/// A read-only rule does not mean "only reads are confined": the ruleset handles
/// the write rights whether or not any rule grants one, so a path no rule names
/// is denied a read, a create and a delete alike.
///
/// What the handled set does not cover is a path-based `truncate(2)`. That is
/// `AccessFs::Truncate`, introduced by Landlock ABI V3, and the handled set stops
/// at the V1 floor (DEVELOPMENT.md §2.1). An `O_TRUNC` open *is* covered, because
/// it also needs `WriteFile`. The residual is recorded rather than claimed
/// closed; widening the ABI floor is a separate decision.
///
/// [`Sibling Path`]: ../index.html
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinementRule {
    /// The directory the rule grants access beneath.
    pub path: PathBuf,
    /// Whether the run may write beneath this path.
    pub writable: bool,
}

impl ConfinementRule {
    /// A read-only rule: the run may list, read and execute beneath `path`.
    pub fn read_only(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            writable: false,
        }
    }

    /// A writable rule: additionally create, write, truncate and remove.
    pub fn writable(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            writable: true,
        }
    }

    /// The rights this rule grants.
    ///
    /// The ABI V1 floor is deliberate: a right a later ABI introduces cannot be
    /// handled on a kernel that does not implement it, so a ruleset that asked
    /// for one under `HardRequirement` would never build (DEVELOPMENT.md §7.2).
    pub fn access_rights(&self) -> RightSet {
        if self.writable {
            RightSet::READ_V1.union(RightSet::WRITE_V1)
        } else {
            RightSet::READ_V1
        }
    }
}

/// What a confined run is allowed to reach, and whether confinement is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinementSpec {
    rules: Vec<ConfinementRule>,
    required: bool,
}

impl ConfinementSpec {
    /// A spec that requires confinement: missing rights refuse the run (FR-040).
    pub fn required(rules: impl IntoIterator<Item = ConfinementRule>) -> Self {
        Self {
            rules: rules.into_iter().collect(),
            required: true,
        }
    }

    /// A spec for which confinement is optional: a missing right warns and
    /// weakens the reported posture, but the run proceeds.
    pub fn optional(rules: impl IntoIterator<Item = ConfinementRule>) -> Self {
        Self {
            rules: rules.into_iter().collect(),
            required: false,
        }
    }

    /// The rules, in the order they were given.
    pub fn rules(&self) -> &[ConfinementRule] {
        &self.rules
    }

    /// Whether a missing right refuses the run.
    pub fn is_required(&self) -> bool {
        self.required
    }

    /// The compatibility level this spec forces on the ruleset.
    pub fn compat_level(&self) -> CompatLevel {
        if self.required {
            CompatLevel::HardRequirement
        } else {
            // `SoftRequirement` rather than `BestEffort`: a whole-build drop is
            // reported as `NotEnforced` instead of being partially applied, so an
            // optional run never claims enforcement it did not achieve either.
            CompatLevel::SoftRequirement
        }
    }
}

/// Why confinement could not be applied.
#[derive(Debug)]
pub enum ConfinementError {
    /// A rule's path could not be opened as an `O_PATH` descriptor.
    ///
    /// `path_beneath_rules` silently skips a path it cannot open, which would
    /// leave a rule missing without saying so. The rules are therefore built one
    /// at a time so this error can name the path.
    RulePath {
        /// The path that could not be opened.
        path: PathBuf,
        /// The kernel's reason.
        cause: String,
    },
    /// The ruleset could not be built. Under `HardRequirement` this is where an
    /// unsupported access right surfaces rather than being downgraded.
    Ruleset {
        /// The underlying reason.
        cause: String,
    },
    /// The kernel declined to apply the ruleset.
    NotEnforced {
        /// The status the kernel reported.
        status: String,
    },
    /// The adapter applies no mechanism at all, so there was nothing to enforce.
    ///
    /// This is not a kernel failure. An adapter that establishes no mechanism
    /// never calls the kernel, so naming Landlock here would send the operator
    /// to look at a kernel that was never asked, and the ABI reported with the
    /// refusal would describe a mechanism the run never intended to use.
    NoMechanism {
        /// The adapter that applies no mechanism.
        adapter: &'static str,
        /// The adapter's own reason.
        reason: String,
    },
}

impl fmt::Display for ConfinementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RulePath { path, cause } => {
                write!(f, "cannot open the rule path {}: {cause}", path.display())
            }
            Self::Ruleset { cause } => write!(f, "cannot build the Landlock ruleset: {cause}"),
            Self::NotEnforced { status } => {
                write!(f, "Landlock did not enforce the ruleset: {status}")
            }
            Self::NoMechanism { adapter, reason } => {
                write!(
                    f,
                    "no confinement mechanism was applied by {adapter}: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for ConfinementError {}

/// How many rights a message names before it summarises the rest.
const NAMED_RIGHTS: usize = 4;

impl ConfinementSpec {
    /// Every right this spec asks the kernel to handle.
    ///
    /// The handled set is the read and write rights of the ABI V1 floor plus
    /// whatever the rules grant, which is exactly what
    /// [`restrict_then_launch`] hands to `handle_access`. A refusal that named
    /// only a rule's rights would therefore understate what the run loses.
    pub fn required_rights(&self) -> RightSet {
        let mut rights = RightSet::READ_V1.union(RightSet::WRITE_V1);
        for rule in &self.rules {
            rights = rights.union(rule.access_rights());
        }
        rights
    }

    /// The rights this spec needs that a kernel reporting `abi` does not
    /// implement, in the order the kernel introduced them.
    ///
    /// `None` means the kernel has no Landlock at all, where every required
    /// right is missing. The answer is a description, not a decision: an
    /// optional spec reports the same missing rights and still proceeds.
    pub fn unsupported_rights_for(&self, abi: Option<u32>) -> Vec<&'static str> {
        let required = self.required_rights();
        AccessRight::ALL
            .iter()
            .filter(|right| required.contains(**right))
            .filter(|right| abi.is_none_or(|abi| abi < right.since()))
            .map(|right| right.name())
            .collect()
    }

    /// The refusal this spec would produce on a kernel reporting `abi`.
    ///
    /// Always `None` for an optional spec: a missing right weakens the posture
    /// and is reported, but it never refuses. That asymmetry is the whole of the
    /// required/optional split, and it is asserted in one test so it cannot be
    /// collapsed by a later refactor.
    pub fn refusal_for(&self, abi: Option<u32>) -> Option<ConfinementRefusal> {
        if !self.required {
            return None;
        }
        let missing = self.unsupported_rights_for(abi);
        if missing.is_empty() {
            return None;
        }
        Some(ConfinementRefusal {
            mechanism: "landlock",
            abi,
            stage: if abi.is_some() {
                RefusalStage::Rights
            } else {
                RefusalStage::Mechanism
            },
            missing,
            detail: None,
        })
    }

    /// The refusal this spec would produce on this host.
    pub fn refusal(&self) -> Option<ConfinementRefusal> {
        self.refusal_for(crate::sys::landlock_abi())
    }
}

/// Which step of establishing the ruleset refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalStage {
    /// The kernel has no Landlock, so no right is enforced at all.
    Mechanism,
    /// The kernel's ABI is older than the rights this run needs.
    Rights,
    /// The ruleset could not be built or installed.
    Ruleset,
    /// A rule's path could not be opened, so the rule would have been silently
    /// missing.
    RulePath(PathBuf),
    /// The kernel built the ruleset and then declined to enforce all of it.
    NotEnforced,
    /// The adapter applies no mechanism, so nothing was enforced because
    /// nothing was ever attempted.
    ///
    /// This stage carries no kernel fact. There is no ABI to report and no
    /// right the kernel is missing, because the run never asked the kernel for
    /// anything.
    NoMechanism,
}

/// A required confinement that the host cannot establish, ready to print.
///
/// # Why this is a type and not a string
///
/// "Landlock failed" is not actionable. The operator needs the mechanism, the ABI
/// the kernel reported and the right that is missing, because those three decide
/// whether the fix is a newer kernel, an enabled feature, a container profile or
/// a different backend. Building the sentence in one place keeps every refusal
/// naming the same three things.
///
/// It carries no plaintext, no key material and no path the operator did not
/// already name as a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinementRefusal {
    mechanism: &'static str,
    abi: Option<u32>,
    stage: RefusalStage,
    missing: Vec<&'static str>,
    detail: Option<String>,
}

impl ConfinementRefusal {
    /// A refusal for `spec` that failed for `error`.
    ///
    /// The missing rights come from the spec, not from the error: `landlock`
    /// reports an unsupported right as a ruleset-construction failure whose text
    /// does not say which right it was, so the only place that can name it is the
    /// spec that asked.
    ///
    /// An adapter that applies no mechanism is not a kernel failure, so it does
    /// not go through the Landlock path: the refusal names the adapter, and no
    /// ABI and no missing right is reported, because the kernel was never asked
    /// for anything.
    pub fn of(spec: &ConfinementSpec, error: ConfinementError) -> Self {
        if let ConfinementError::NoMechanism { adapter, reason } = error {
            return Self {
                mechanism: adapter,
                abi: None,
                stage: RefusalStage::NoMechanism,
                // The kernel is missing no right: the run never asked it for
                // one. Listing the spec's rights here would say the kernel
                // declined to enforce rules it was never shown.
                missing: Vec::new(),
                detail: Some(reason),
            };
        }
        let (stage, detail) = match error {
            ConfinementError::RulePath { path, cause } => {
                (RefusalStage::RulePath(path), Some(cause))
            }
            ConfinementError::Ruleset { cause } => (RefusalStage::Ruleset, Some(cause)),
            ConfinementError::NotEnforced { status } => (RefusalStage::NotEnforced, Some(status)),
            ConfinementError::NoMechanism { .. } => unreachable!("handled above"),
        };
        // One query for both fields: two calls could describe two different
        // kernels if the first one raced a kernel change, and the sentence would
        // then name an ABI the missing rights were not computed against.
        let abi = crate::sys::landlock_abi();
        Self {
            mechanism: "landlock",
            abi,
            stage,
            missing: spec.unsupported_rights_for(abi),
            detail,
        }
    }

    /// The mechanism that could not be established.
    pub fn mechanism(&self) -> &'static str {
        self.mechanism
    }

    /// The Landlock ABI the kernel reported, or `None` when it has none.
    pub fn abi(&self) -> Option<u32> {
        self.abi
    }

    /// The stage that refused.
    pub fn stage(&self) -> &RefusalStage {
        &self.stage
    }

    /// The rights this run needed and the kernel does not enforce.
    pub fn missing_rights(&self) -> &[&'static str] {
        &self.missing
    }
}

impl fmt::Display for ConfinementRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The ABI is always printed, including when there is none: "no ABI" is
        // the fact that decides whether the operator looks at the kernel or at
        // the backend. A refusal that names no mechanism is the exception: it
        // reports no ABI because there was no kernel to ask, and printing one
        // would point the operator at a kernel the run never touched.
        let abi = match (&self.stage, self.abi) {
            (RefusalStage::NoMechanism, _) => String::new(),
            (_, Some(abi)) => format!(" (ABI {abi})"),
            (_, None) => " (no ABI)".to_string(),
        };
        write!(
            f,
            "required confinement cannot be established by {}{abi}: ",
            self.mechanism
        )?;
        match &self.stage {
            RefusalStage::Mechanism | RefusalStage::Rights => {
                write!(f, "the kernel does not enforce {}", self.rights())?;
            }
            RefusalStage::Ruleset => {
                write!(f, "the ruleset could not be built: {}", self.detail())?;
            }
            RefusalStage::RulePath(path) => {
                write!(
                    f,
                    "the rule path {} could not be opened: {}",
                    path.display(),
                    self.detail()
                )?;
            }
            RefusalStage::NotEnforced => {
                write!(
                    f,
                    "the kernel declined to enforce the ruleset ({})",
                    self.detail()
                )?;
            }
            RefusalStage::NoMechanism => {
                write!(f, "the adapter applies no mechanism ({})", self.detail())?;
            }
        }
        // The consequence belongs to the sentence: a caller that saw only the
        // reason could read it as a warning.
        write!(f, "; the child was not started")
    }
}

impl ConfinementRefusal {
    /// The missing rights, named up to a limit and then counted.
    fn rights(&self) -> String {
        let named: Vec<&str> = self.missing.iter().take(NAMED_RIGHTS).copied().collect();
        let rest = self.missing.len().saturating_sub(named.len());
        match (named.is_empty(), rest) {
            // Reachable only for a runtime refusal whose reason already says
            // everything: the rights are in the detail.
            (true, _) => "the requested rights".to_string(),
            (false, 0) => named.join(", "),
            (false, rest) => format!("{} and {rest} more", named.join(", ")),
        }
    }

    fn detail(&self) -> &str {
        self.detail.as_deref().unwrap_or("no reason reported")
    }
}

impl std::error::Error for ConfinementRefusal {}

/// A ruleset applied to this process, and what the kernel reported about it.
///
/// Holding one means the calling thread (and every child forked from it) is
/// confined. It cannot be constructed without `restrict_self()` succeeding, so
/// "confined" is a property of the value rather than a claim in a comment.
///
/// Every field is taken from the `RestrictionStatus` the kernel returned, so
/// [`posture`](Self::posture) reports what happened rather than what was
/// requested.
///
/// The type is portable: it holds this crate's own [`LandlockAbi`] and
/// [`CompatLevel`] rather than the `landlock` crate's, so a consumer on a host
/// with no Landlock can still name the value it was handed.
#[derive(Debug)]
pub struct AppliedRuleset {
    state: ConfinementState,
    compat_level: CompatLevel,
    effective_abi: LandlockAbi,
    kernel_abi: Option<i32>,
    all_threads: bool,
    required: bool,
    /// The adapter that applied this ruleset.
    ///
    /// `None` until an adapter stamps it. The mechanism does not know
    /// which adapter called it, so the adapter names itself afterwards.
    adapter: Option<&'static str>,
    /// The guarantee the adapter establishes.
    ///
    /// The adapter's **own** level, not the level the kernel enforced —
    /// that is the `state` field. The two are different facts: a `full`
    /// adapter that the kernel only partly enforced reports `weakened`
    /// state and `full` guarantee.
    guarantee: GuaranteeLevel,
}

impl AppliedRuleset {
    /// Names the adapter that applied this ruleset and the guarantee it
    /// establishes.
    ///
    /// The mechanism does not know which adapter called it — the adapter
    /// is a wrapper around it — so the adapter names itself here. The
    /// guarantee is the adapter's **own** level: what it establishes when
    /// it runs, which is a different fact from how much the kernel
    /// enforced on this particular run.
    pub fn named(&mut self, adapter: &'static str, guarantee: GuaranteeLevel) {
        self.adapter = Some(adapter);
        self.guarantee = guarantee;
    }

    /// Whether every requested restriction is enforced.
    pub fn is_fully_enforced(&self) -> bool {
        matches!(self.state, ConfinementState::Enforced)
    }

    /// The compatibility level that was in force.
    pub fn compat_level(&self) -> CompatLevel {
        self.compat_level
    }

    /// The effective Landlock ABI the kernel reported.
    ///
    /// [`LandlockAbi::Unsupported`] when Landlock was not available at all; the
    /// ruleset would then have been reported as not enforced.
    pub fn abi(&self) -> LandlockAbi {
        self.effective_abi
    }

    /// The kernel's own ABI when it is newer than this crate understands.
    ///
    /// Purely informational, exactly as `landlock` documents it.
    pub fn kernel_abi(&self) -> Option<i32> {
        self.kernel_abi
    }

    /// Whether the ruleset was applied to every thread rather than only the
    /// calling one.
    ///
    /// `false` is not a failure: the confined child is forked from the
    /// restricted thread and inherits the domain. It means a *sibling thread of
    /// this process* is not covered, which matters only to a caller that spawns
    /// threads of its own before confining.
    pub fn applied_to_all_threads(&self) -> bool {
        self.all_threads
    }

    /// What the kernel said about Landlock itself, independent of this run's
    /// ruleset.
    pub fn landlock(&self) -> LandlockObservation {
        match self.effective_abi {
            LandlockAbi::Unsupported => LandlockObservation::NotImplemented,
            abi => LandlockObservation::Available {
                effective_abi: abi.as_u32() as u8,
                kernel_abi: self.kernel_abi,
            },
        }
    }

    /// The confinement half of the posture, derived from what was enforced.
    ///
    /// This is the bridge the S5 contract owes its consumers: a caller that has
    /// an `AppliedRuleset` must not have to re-derive `Enforced` versus
    /// `Weakened`, because getting that wrong is how a partial ruleset starts
    /// being reported as full enforcement.
    pub fn posture(&self) -> ConfinementPosture {
        ConfinementPosture {
            state: self.state,
            landlock: self.landlock(),
            required: self.required,
            adapter: self.adapter,
            guarantee: self.guarantee,
        }
    }
}

/// Applies `spec` to the calling process, then yields the only value that can
/// launch a child.
///
/// This is the structural fix for the ordering problem: the ruleset is applied
/// inside this function, and [`ConfinedChild`] cannot be constructed any other
/// way, so a child cannot be launched before the rules are in force.
///
/// An optional spec whose rights are unavailable returns an `AppliedRuleset`
/// reporting `is_fully_enforced() == false`; a required spec returns
/// [`ConfinementError`] instead. A user-visible warning does not belong in a
/// library, so the caller decides how to surface it — but it cannot mistake the
/// weakened result for a full one.
///
/// # A host with no Landlock
///
/// The Landlock mechanism is Linux-only (NFR-003), so on another target this
/// function has nothing to apply. It refuses, and the refusal says the
/// mechanism is absent rather than that a rule failed: the operator must be
/// sent to the kernel, not to a rule path that was never opened.
#[cfg(target_os = "linux")]
pub fn restrict_then_launch(spec: &ConfinementSpec) -> Result<ConfinedChild, ConfinementError> {
    let compat = spec.compat_level();

    let mut ruleset = landlock::Ruleset::default().set_compatibility(to_landlock_compat(compat));

    // Handle the read *and* write sets, then every rule's own rights in the same
    // `handle_access` call. The ruleset must handle a right before any rule may
    // grant it — and, just as importantly, it restricts *only* what it handles.
    // Deriving the handled set from the rules alone would mean a spec whose rules
    // are all read-only handles no write at all, so Landlock denies none: reads
    // would be confined and every write would pass, while `restrict_self` still
    // reported the ruleset as fully enforced. The V1 floor is used for the
    // reason above: a right a later ABI introduces cannot be handled on a
    // kernel that does not implement it (DEVELOPMENT.md §2.1).
    let mut handled = RightSet::READ_V1.union(RightSet::WRITE_V1);
    for rule in spec.rules() {
        handled = handled.union(rule.access_rights());
    }

    ruleset = ruleset
        .handle_access(crate::rights::to_landlock(handled))
        .map_err(|err| ConfinementError::Ruleset {
            cause: err.to_string(),
        })?;

    let mut created = ruleset.create().map_err(|err| ConfinementError::Ruleset {
        cause: err.to_string(),
    })?;

    // Build each rule explicitly rather than through `path_beneath_rules`, which
    // filters out a path it cannot open and would otherwise leave a missing rule
    // invisible.
    for rule in spec.rules() {
        let path_fd =
            landlock::PathFd::new(&rule.path).map_err(|err| ConfinementError::RulePath {
                path: rule.path.clone(),
                cause: err.to_string(),
            })?;
        created = created
            .add_rule(landlock::PathBeneath::new(
                path_fd,
                crate::rights::to_landlock(rule.access_rights()),
            ))
            .map_err(|err| ConfinementError::Ruleset {
                cause: err.to_string(),
            })?;
    }

    // Take the pre-call clone *before* `all_threads`, so the fallback is a
    // faithful copy of the ruleset with the flag never attempted. `try_clone`
    // duplicates the ruleset fd; a failed compat check does not update `compat`,
    // so the clone carries the original state.
    let pre_call = created
        .try_clone()
        .map_err(|err| ConfinementError::Ruleset {
            cause: format!("cannot duplicate the ruleset before setting the thread scope: {err}"),
        })?;

    // `all_threads` widens the domain to the sibling threads of *this* process.
    // The confined child is forked after this point and inherits the calling
    // thread's domain, so the child tree is covered either way — this is defence
    // in depth for a multithreaded parent, not one of the filesystem rights
    // FR-040 scopes a refusal to.
    //
    // `landlock` rejects the flag under `CompatLevel::HardRequirement` on any
    // kernel with ABI < V8 (`RestrictSelfFlag::AllThreads::since() == ABI::V8`;
    // DEVELOPMENT.md §2.1), and `AllThreads` is not a "selected `file` Landlock
    // right". Turning that rejection into a refusal would therefore reject a run
    // that has every right it asked for, on every kernel before Linux 7.0 —
    // including the stock Ubuntu 24.04 kernel 6.8 / ABI V4 that DEVELOPMENT.md
    // §2.1 names as the plan's target. The flag is attempted and its loss is
    // reported through `status.all_threads`, never converted into a refusal.
    let created = match created.all_threads(true) {
        Ok(created) => created,
        Err(_) => {
            // `all_threads` consumed the builder on failure, and a failed
            // compat check leaves the pre-call clone untouched (`try_clone`
            // copies `compat` and the applied flags verbatim), so the clone is
            // the same ruleset without the flag.
            pre_call
                .try_clone()
                .map_err(|err| ConfinementError::Ruleset {
                    cause: format!(
                        "cannot keep the ruleset after the thread-scope flag was rejected: {err}"
                    ),
                })?
        }
    };

    // `restrict_self()` returns the status directly; there is no `.status()`
    // accessor (DEVELOPMENT.md §7.2).
    let status = created
        .restrict_self()
        .map_err(|err| ConfinementError::Ruleset {
            cause: err.to_string(),
        })?;

    let state = match status.ruleset {
        RulesetStatus::FullyEnforced => ConfinementState::Enforced,
        RulesetStatus::PartiallyEnforced => ConfinementState::Weakened,
        RulesetStatus::NotEnforced => ConfinementState::Unavailable,
    };

    if !matches!(state, ConfinementState::Enforced) && spec.is_required() {
        return Err(ConfinementError::NotEnforced {
            status: format!("{:?}", status.ruleset),
        });
    }

    let (effective_abi, kernel_abi) = match status.landlock {
        LandlockStatus::Available {
            effective_abi,
            kernel_abi,
        } => (LandlockAbi::from_number(effective_abi as i32), kernel_abi),
        // Landlock unavailable: `restrict_self` reports `NotEnforced`, so this
        // arm is reachable only for an optional run (a required one was refused
        // above).
        LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => {
            (LandlockAbi::Unsupported, None)
        }
    };

    Ok(ConfinedChild {
        applied: AppliedRuleset {
            state,
            compat_level: compat,
            effective_abi,
            kernel_abi,
            all_threads: status.all_threads,
            required: spec.is_required(),
            adapter: None,
            guarantee: GuaranteeLevel::None,
        },
    })
}

/// A host with no Landlock: the ruleset cannot be applied, so the run refuses.
///
/// The refusal names the mechanism as absent rather than reporting a rule
/// failure, because the operator's fix is a different kernel and not a
/// different path. The `NoMechanism` stage is *not* used here — that stage
/// means "this adapter never asked the kernel", while this host *does* have a
/// Landlock adapter, it simply has no Landlock to ask.
#[cfg(not(target_os = "linux"))]
pub fn restrict_then_launch(_spec: &ConfinementSpec) -> Result<ConfinedChild, ConfinementError> {
    Err(ConfinementError::NotEnforced {
        status: "this host has no Landlock: the mechanism is Linux-only".to_string(),
    })
}

/// The only value that can launch a child under a ruleset.
///
/// It is produced exclusively by [`restrict_then_launch`], so obtaining one
/// proves the rules are already in force for this process and every child it
/// forks.
#[derive(Debug)]
pub struct ConfinedChild {
    applied: AppliedRuleset,
}

impl ConfinedChild {
    /// The ruleset in force, mutably.
    ///
    /// So an adapter can name itself on the result. The mechanism does not
    /// know which adapter called it, so the adapter stamps its own name and
    /// guarantee afterwards — and the posture can then say which mechanism ran
    /// (FR-007).
    pub fn applied_mut(&mut self) -> &mut AppliedRuleset {
        &mut self.applied
    }

    /// The ruleset in force.
    pub fn applied(&self) -> &AppliedRuleset {
        &self.applied
    }

    /// Launches `command` as a child of this confined process.
    ///
    /// The child inherits the Landlock domain through `fork`/`exec`, so it is
    /// confined from its first instruction. Nothing in this call re-applies a
    /// ruleset; the ordering is established before the call exists.
    ///
    /// The caller is responsible for [`crate::descriptors::sanitize`] before
    /// this, because a descriptor opened before confinement survives it.
    pub fn launch(
        &self,
        mut command: std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        command.spawn()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_required_spec_forces_hard_requirement() {
        let spec = ConfinementSpec::required([ConfinementRule::read_only("/tmp")]);
        assert!(spec.is_required());
        assert_eq!(spec.compat_level(), CompatLevel::HardRequirement);
    }

    #[test]
    fn an_optional_spec_never_uses_best_effort() {
        let spec = ConfinementSpec::optional([ConfinementRule::read_only("/tmp")]);
        assert!(!spec.is_required());
        assert_eq!(spec.compat_level(), CompatLevel::SoftRequirement);
        assert_ne!(
            spec.compat_level(),
            CompatLevel::BestEffort,
            "BestEffort silently downgrades, which is exactly what the crate forbids"
        );
    }

    #[test]
    fn a_read_only_rule_grants_no_write_rights() {
        let rule = ConfinementRule::read_only("/tmp");
        let rights = rule.access_rights();
        assert!(rights.contains(AccessRight::ReadDir));
        assert!(rights.contains(AccessRight::ReadFile));
        assert!(!rights.contains(AccessRight::WriteFile));
        assert!(!rights.contains(AccessRight::MakeReg));
    }

    #[test]
    fn a_writable_rule_grants_write_rights() {
        let rule = ConfinementRule::writable("/tmp");
        let rights = rule.access_rights();
        assert!(rights.contains(AccessRight::WriteFile));
        assert!(rights.contains(AccessRight::MakeReg));
        assert!(rights.contains(AccessRight::RemoveFile));
    }

    #[test]
    fn rules_keep_their_order_and_identity() {
        let spec = ConfinementSpec::required([
            ConfinementRule::read_only("/vault"),
            ConfinementRule::writable("/vault/p/u/agent-a"),
        ]);
        assert_eq!(spec.rules().len(), 2);
        assert_eq!(spec.rules()[0].path, PathBuf::from("/vault"));
        assert!(!spec.rules()[0].writable);
        assert!(spec.rules()[1].writable);
    }

    /// Runs this test in a fresh process, and returns whether the body should
    /// run.
    ///
    /// [`restrict_then_launch`] applies its ruleset to the calling **process**
    /// (that is what makes the token it returns meaningful), so a test that
    /// calls it in the shared test binary confines every other test in that
    /// binary: the next test that creates a temporary directory fails with
    /// `EACCES` for a reason that has nothing to do with what it asserts.
    ///
    /// The child re-runs this one test by exact name in its own process, where
    /// the sandbox dies with it. `cargo test` runs the body twice — once in the
    /// parent, which spawns and checks the child, and once in the child, which
    /// does the measuring — so the assertion is made where the ruleset is
    /// applied and nowhere else.
    ///
    /// Linux only: the ruleset is Landlock's, and Landlock is Linux-only.
    #[cfg(target_os = "linux")]
    fn isolated_process(test_name: &str) -> bool {
        /// Set in the child so it runs the body instead of spawning again.
        const MARKER: &str = "KSP_LANDLOCK_ISOLATED_CHILD";

        if std::env::var_os(MARKER).is_some() {
            return true;
        }
        let exe = std::env::current_exe().expect("the test binary has a path");
        let output = std::process::Command::new(exe)
            .args([test_name, "--exact", "--nocapture"])
            .env(MARKER, "1")
            .output()
            .expect("the test binary re-runs itself");
        assert!(
            output.status.success(),
            "the isolated child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_rule_pointing_at_a_missing_path_is_an_error_not_a_skipped_rule() {
        let spec = ConfinementSpec::optional([ConfinementRule::read_only(
            "/definitely/not/a/real/path/for/keyspout",
        )]);
        match restrict_then_launch(&spec) {
            Err(ConfinementError::RulePath { path, .. }) => {
                assert_eq!(
                    path,
                    PathBuf::from("/definitely/not/a/real/path/for/keyspout")
                );
            }
            other => panic!("a missing rule path must be reported, got {other:?}"),
        }
    }

    /// Asks the kernel for its Landlock ABI directly.
    ///
    /// The independent oracle for the ABI test below: it reaches the same syscall
    /// `landlock` uses, without going through either the crate's report or this
    /// module's cached field. Without an oracle outside the value under test, a
    /// hardcoded constant is self-consistent and passes.
    #[cfg(target_os = "linux")]
    fn kernel_abi() -> Option<i32> {
        // `LANDLOCK_CREATE_RULESET_VERSION` is 1; libc does not export it.
        const VERSION_FLAG: libc::c_uint = 1;
        // SAFETY (test-only): `landlock_create_ruleset(NULL, 0, VERSION)` is the
        // documented ABI query — it takes no pointer and returns the version or a
        // negated errno. No Rust memory crosses the boundary.
        #[allow(unsafe_code)]
        let version = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0usize,
                VERSION_FLAG,
            )
        };
        if version < 0 {
            None
        } else {
            Some(version as i32)
        }
    }

    /// The applied ruleset must report the ABI the kernel actually gave, not a
    /// constant. `AppliedRuleset::abi()` previously returned `ABI::V1`
    /// unconditionally while discarding `RestrictionStatus.landlock`, which is
    /// the kind of false report this subsystem exists to prevent.
    #[test]
    #[cfg(target_os = "linux")]
    fn the_applied_ruleset_reports_the_observed_abi() {
        if !isolated_process("confinement::tests::the_applied_ruleset_reports_the_observed_abi") {
            return;
        }
        let spec = ConfinementSpec::optional([ConfinementRule::read_only("/tmp")]);
        let confined =
            restrict_then_launch(&spec).expect("an optional spec must apply on this host");
        let applied = confined.applied();

        let kernel = kernel_abi().expect("this host must be able to report its Landlock ABI");
        assert!(
            applied.landlock().is_available(),
            "the reported observation must reflect an available Landlock, got {:?}",
            applied.landlock()
        );
        assert_eq!(
            applied.abi() as u8,
            kernel as u8,
            "the reported ABI must be the kernel's own, not a constant"
        );

        // A second, independent cross-check from the same status object: the
        // kernel accepts `all_threads` only from ABI V8, so a granted flag
        // contradicts any reported ABI below V8.
        if applied.applied_to_all_threads() {
            assert!(
                applied.abi() >= LandlockAbi::V8,
                "the thread-scope flag was granted, so the ABI cannot be below V8; got {:?}",
                applied.abi()
            );
        }
    }

    /// The posture bridge: what was enforced must produce the matching state, so
    /// a consumer cannot report `Enforced` for a partial ruleset by hand.
    #[test]
    #[cfg(target_os = "linux")]
    fn the_applied_ruleset_derives_its_posture_from_what_was_enforced() {
        if !isolated_process(
            "confinement::tests::the_applied_ruleset_derives_its_posture_from_what_was_enforced",
        ) {
            return;
        }
        let required = ConfinementSpec::required([ConfinementRule::read_only("/tmp")]);
        let confined = restrict_then_launch(&required).expect("a required spec must apply here");
        let posture = confined.applied().posture();

        assert!(confined.applied().is_fully_enforced());
        assert_eq!(posture.state, ConfinementState::Enforced);
        assert!(posture.required, "the posture must carry the requirement");
        assert_eq!(posture.compat_level_name(), "HardRequirement");
        assert!(posture.landlock.is_available());

        let optional = ConfinementSpec::optional([ConfinementRule::read_only("/tmp")]);
        let confined = restrict_then_launch(&optional).expect("an optional spec must apply here");
        let posture = confined.applied().posture();
        assert!(!posture.required);
        assert_eq!(posture.compat_level_name(), "SoftRequirement");
    }

    /// T017: the two postures, both asserted in one test.
    ///
    /// A future refactor that made `optional` refuse, or `required` warn, would
    /// fail here rather than at the operator's terminal. The same absent
    /// mechanism is fed to both specs, so the only difference between them is the
    /// one that is supposed to matter.
    #[test]
    fn an_absent_mechanism_refuses_a_required_spec_and_only_weakens_an_optional_one() {
        let rule = [ConfinementRule::read_only("/tmp")];
        let required = ConfinementSpec::required(rule.clone());
        let optional = ConfinementSpec::optional(rule);

        // A kernel with no Landlock at all: every required right is missing.
        let refusal = required
            .refusal_for(None)
            .expect("a required spec must refuse when the mechanism is absent");
        assert_eq!(refusal.stage(), &RefusalStage::Mechanism);
        assert_eq!(refusal.mechanism(), "landlock");
        assert_eq!(refusal.abi(), None);
        assert!(
            refusal.missing_rights().contains(&"READ_FILE"),
            "the refusal must name the rights the run loses: {:?}",
            refusal.missing_rights()
        );

        assert!(
            optional.refusal_for(None).is_none(),
            "an optional spec must weaken, not refuse, or a host without Landlock \
             could not provision at all"
        );
        // And the same host does not refuse a required spec that a modern kernel
        // does satisfy: the refusal is about the missing right, not the policy.
        assert!(required.refusal_for(Some(4)).is_none());
    }

    /// T014: the sentence names the mechanism, the ABI and the right.
    #[test]
    fn a_refusal_names_the_mechanism_the_abi_and_the_rights() {
        let required = ConfinementSpec::required([ConfinementRule::read_only("/tmp")]);

        let sentence = required
            .refusal_for(None)
            .expect("no Landlock must refuse")
            .to_string();
        assert!(sentence.contains("landlock"), "no mechanism in {sentence}");
        assert!(sentence.contains("no ABI"), "no ABI in {sentence}");
        assert!(sentence.contains("EXECUTE"), "no right in {sentence}");
        assert!(
            sentence.contains("the child was not started"),
            "a refusal must state its consequence: {sentence}"
        );

        // An ABI too old for the rights the floor asks for names the boundary
        // instead of the mechanism: ABI 0 is a kernel that has the call and none
        // of the rights.
        let sentence = required
            .refusal_for(Some(0))
            .expect("an ABI below the floor must refuse")
            .to_string();
        assert!(sentence.contains("ABI 0"), "no ABI in {sentence}");
        assert!(sentence.contains("READ_DIR"), "no right in {sentence}");
        // The list is bounded, so an 18-right refusal stays readable.
        assert!(
            sentence.contains("more"),
            "a long rights list must be summarised: {sentence}"
        );
    }

    /// A ruleset failure keeps the spec's rights *and* the kernel's reason, so
    /// the operator sees both what was wanted and what went wrong.
    #[test]
    fn a_runtime_failure_still_names_the_rule_path() {
        let required = ConfinementSpec::required([ConfinementRule::read_only("/tmp")]);
        let refusal = ConfinementRefusal::of(
            &required,
            ConfinementError::RulePath {
                path: PathBuf::from("/nowhere/at/all"),
                cause: "No such file or directory (os error 2)".to_string(),
            },
        );

        let sentence = refusal.to_string();
        assert_eq!(
            refusal.stage(),
            &RefusalStage::RulePath(PathBuf::from("/nowhere/at/all"))
        );
        assert!(sentence.contains("landlock"), "no mechanism in {sentence}");
        assert!(
            sentence.contains("/nowhere/at/all"),
            "the path that refused is missing from {sentence}"
        );
        assert!(
            sentence.contains("No such file"),
            "the kernel's reason is missing from {sentence}"
        );
    }
}
