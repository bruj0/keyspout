//! The real child launcher and confiner, behind the gate's two traits.
//!
//! # Why this adapter exists
//!
//! S5's [`ksp_posture::confinement::restrict_then_launch`] yields a
//! [`ConfinedChild`] and nothing else can
//! launch a child, which is how the confinement order is made structural. The
//! gate in [`crate::run_gate`] keeps the same order by calling a [`Confiner`]
//! and then a [`ChildLauncher`]. This module bridges the two without weakening
//! either: the value that can launch is stashed by the confiner and taken by the
//! launcher, both of which are this one type, so a `launch` that ran before an
//! `apply` finds nothing to launch with.
//!
//! # The plaintext
//!
//! The child receives a value through its environment and nowhere else. That is
//! the declared `ksp run --env` exception (FR-044): explicit, documented, and
//! never implicit.

use std::cell::RefCell;
use std::process::{Command, Stdio};

use ksp_posture::ConfinementSpec;
use ksp_posture::adapters::ConfinementAdapter;
use ksp_posture::confinement::{ConfinedChild, ConfinementRefusal};
use ksp_posture::descriptors::{DescriptorPolicy, sanitize};

use crate::run_gate::{CapabilityRefusal, ChildLauncher, Confiner, LaunchError};

/// Confines this process through the configured adapter, then launches once.
///
/// # Two states, and the constructor is where the difference lives
///
/// [`new`](Self::new) holds the adapter the configuration selected: the value
/// that can launch is the one that adapter produced, and a `launch` that ran
/// before an `apply` finds nothing to launch with.
///
/// [`unconfined`](Self::unconfined) holds no adapter at all, which is what an
/// `optional` capability whose `None`-guarantee adapter was selected amounts
/// to: the run proceeds, no ruleset is applied, and the caller has already said
/// so in its own output. The alternative — a confiner that silently succeeds —
/// would make "nothing was confined" indistinguishable from "confinement
/// worked", which is the failure this module exists to prevent.
pub struct ConfinedProcess {
    adapter: Option<&'static dyn ConfinementAdapter>,
    applied: RefCell<Option<ConfinedChild>>,
}

impl ConfinedProcess {
    /// A confiner that establishes `adapter` and then launches.
    pub fn new(adapter: &'static dyn ConfinementAdapter) -> Self {
        Self {
            adapter: Some(adapter),
            applied: RefCell::new(None),
        }
    }

    /// A launcher that applies no ruleset.
    ///
    /// Only for a capability the configuration marked `optional` and the host
    /// established nothing for. Nothing is confined, and the caller states that
    /// in its own output rather than leaving it to be inferred (NFR-010).
    ///
    /// There is deliberately no accessor saying which variant this is. The
    /// caller already knew before it chose the constructor, and a second way to
    /// ask the same question is a second answer that can disagree.
    pub fn unconfined() -> Self {
        Self {
            adapter: None,
            applied: RefCell::new(None),
        }
    }
}

impl Confiner for ConfinedProcess {
    fn apply(&self, spec: &ConfinementSpec) -> Result<(), CapabilityRefusal> {
        let Some(adapter) = self.adapter else {
            // Nothing selected, nothing to establish. The caller has already
            // reported the absence.
            return Ok(());
        };

        // A descriptor opened before confinement survives it, so it is closed
        // first. Kept to the standard streams: the child needs nothing else, and
        // anything else that is inherited is something the kernel would let the
        // confined child write through.
        sanitize(&DescriptorPolicy::standard_streams_only())
            .map_err(|err| CapabilityRefusal::Descriptors(err.to_string()))?;

        // Name the missing rights *before* building the ruleset. `landlock`
        // reports an unsupported right as a ruleset-construction failure whose
        // text does not say which right it was, and a refusal an operator cannot
        // act on is one they route around.
        if let Some(refusal) = spec.refusal() {
            return Err(CapabilityRefusal::Confinement(refusal));
        }

        // Through the adapter, not the mechanism. The adapter is what stamps
        // its name and guarantee on the result, so the posture this child
        // reports can say *which* mechanism confined it (FR-007). Calling
        // `restrict_then_launch` here would apply the same ruleset and leave
        // the posture nameless, which is precisely the defect this route
        // removes.
        let child = adapter
            .establish(spec)
            .map_err(|err| CapabilityRefusal::Confinement(ConfinementRefusal::of(spec, err)))?;
        *self.applied.borrow_mut() = Some(child);
        Ok(())
    }
}

impl ChildLauncher for ConfinedProcess {
    fn launch(&self, argv: &[String], env: &[(String, String)]) -> Result<i32, LaunchError> {
        let (program, arguments) = argv.split_first().ok_or(LaunchError::Spawn)?;
        let mut command = Command::new(program);
        command
            .args(arguments)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        // The declared exception. This is the only place a plaintext value is
        // handed to anything outside this process.
        for (name, value) in env {
            command.env(name, value);
        }

        // No ruleset, no launch — when a ruleset was the point. The only value
        // that can start a *confined* child is the one the confiner produced;
        // an unconfined confiner has nothing to produce and nothing to check.
        let applied = self.applied.borrow();
        let mut child = match (self.adapter.is_some(), applied.as_ref()) {
            (false, _) => command.spawn().map_err(|_| LaunchError::Spawn)?,
            (true, Some(confined)) => confined.launch(command).map_err(|_| LaunchError::Spawn)?,
            (true, None) => return Err(LaunchError::Spawn),
        };
        let status = child.wait().map_err(|_| LaunchError::Spawn)?;
        match status.code() {
            Some(0) => Ok(0),
            Some(code) => Err(LaunchError::NonZero { code }),
            // A signalled child is not a success: reporting zero would tell the
            // caller the run completed.
            None => Err(LaunchError::Spawn),
        }
    }
}
