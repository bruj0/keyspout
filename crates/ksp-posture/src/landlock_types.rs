//! The crate's own Landlock vocabulary, so the crate builds on a host with no
//! Landlock.
//!
//! # Why this exists
//!
//! The `landlock` crate 0.4.7 does not compile on macOS: it imports
//! `libc::O_PATH`, `libc::prctl` and `libc::PR_{SET,GET}_NO_NEW_PRIVS`, none of
//! which exist in Darwin's libc. The crate is therefore a Linux-only
//! dependency (NFR-003).
//!
//! That alone is not enough. Two of this crate's public signatures returned
//! `landlock`'s own types:
//!
//! - [`crate::confinement::ConfinementSpec::compat_level`] → `landlock::CompatLevel`
//! - [`crate::confinement::AppliedRuleset::abi`] → `landlock::ABI`
//!
//! A public signature that names a target-gated type makes the *crate* a
//! target-gated type: a consumer on macOS could not name the value it got
//! back. The types below are this crate's own, mirroring `landlock`'s
//! semantics, so the seam is the module boundary rather than the public API.
//!
//! # What the mirroring does and does not claim
//!
//! The variants and their meanings are copied from `landlock` 0.4.7, because
//! the crate's refusals and postures are written in those terms and a reader
//! who knows Landlock must not have to learn a second vocabulary.
//!
//! The mirroring is **not** a claim that this crate re-implements Landlock. It
//! does not: on Linux the real crate builds the ruleset, and this module only
//! names the result. The conversion happens at exactly one place —
//! [`crate::confinement`] — so there is one translation to check rather than
//! one per caller.
//!
//! # Why not a bare integer
//!
//! An `ABI` that was a `u32` would compile everywhere, but it would also lose
//! the distinction that matters: `Unsupported` is not "ABI 0", it is "the
//! kernel has no Landlock", and the two produce different refusals. A
//! fieldless enum keeps the compiler checking every match over it, which is the
//! same property that makes [`ksp_types::AdapterKind`] safe to match on.

use std::fmt;

/// How strictly a ruleset is built against the running kernel.
///
/// Mirrors `landlock::CompatLevel`. The crate never uses
/// [`BestEffort`](Self::BestEffort): it silently downgrades unsupported
/// features, which would let the crate claim enforcement it did not achieve.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompatLevel {
    /// Silently ignore what the kernel does not support.
    ///
    /// The crate never selects this. It is present because the level is a
    /// faithful mirror, and a mirror that omitted a variant could not be
    /// compared against the value it mirrors.
    #[default]
    BestEffort,
    /// Ignore the whole ruleset if part of it is unsupported.
    ///
    /// The kernel reports `NotEnforced`, and the run's posture says the rules
    /// were not applied rather than reporting a partial enforcement.
    SoftRequirement,
    /// Refuse to build a ruleset the kernel cannot fully support.
    ///
    /// A required run uses this, so an unsupported access right is an error
    /// instead of a silent reduction.
    HardRequirement,
}

impl CompatLevel {
    /// The name the landlock crate gives this level.
    ///
    /// The refusal and posture text quotes this, and an operator reading it
    /// alongside Landlock's own documentation must see the same word.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BestEffort => "BestEffort",
            Self::SoftRequirement => "SoftRequirement",
            Self::HardRequirement => "HardRequirement",
        }
    }
}

impl fmt::Display for CompatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The Landlock ABI the effective ruleset was built against.
///
/// Mirrors `landlock::ABI`, including its `Unsupported` case: a kernel with no
/// Landlock is not "ABI 0", it is a kernel with no Landlock, and the two
/// produce different refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LandlockAbi {
    /// The kernel does not implement Landlock at all.
    Unsupported,
    /// The first Landlock ABI (Linux 5.13).
    V1,
    /// The second Landlock ABI (Linux 5.19).
    V2,
    /// The third Landlock ABI (Linux 6.2).
    V3,
    /// The fourth Landlock ABI (Linux 6.7).
    V4,
    /// The fifth Landlock ABI (Linux 6.10).
    V5,
    /// The sixth Landlock ABI (Linux 6.12).
    V6,
    /// The seventh Landlock ABI (Linux 6.15).
    V7,
    /// The eighth Landlock ABI (Linux 7.0).
    V8,
    /// The ninth Landlock ABI (Linux 7.1).
    V9,
}

impl LandlockAbi {
    /// The ABI as the number the kernel reports.
    ///
    /// `0` for [`Unsupported`](Self::Unsupported), which is the value the
    /// kernel's version query returns when it has no Landlock.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Unsupported => 0,
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
            Self::V4 => 4,
            Self::V5 => 5,
            Self::V6 => 6,
            Self::V7 => 7,
            Self::V8 => 8,
            Self::V9 => 9,
        }
    }

    /// The ABI a kernel reporting `number` implements.
    ///
    /// A number above the highest ABI this crate knows is the **highest known
    /// one**, not a new variant: the crate cannot use a right it does not know
    /// about, so the effective ABI is the one it can actually build against.
    /// This mirrors `landlock`'s own `From<i32>`.
    pub fn from_number(number: i32) -> Self {
        match number {
            n if n <= 0 => Self::Unsupported,
            1 => Self::V1,
            2 => Self::V2,
            3 => Self::V3,
            4 => Self::V4,
            5 => Self::V5,
            6 => Self::V6,
            7 => Self::V7,
            8 => Self::V8,
            _ => Self::V9,
        }
    }
}

impl fmt::Display for LandlockAbi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The landlock crate prints `unsupported` for this case, and the
            // posture text is written in Landlock's vocabulary.
            Self::Unsupported => f.write_str("unsupported"),
            abi => write!(f, "{}", abi.as_u32()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_abi_numbers_match_the_kernels_own() {
        // The kernel's version query returns the ABI number directly, so the
        // number this crate prints must be the number the kernel reported.
        assert_eq!(LandlockAbi::Unsupported.as_u32(), 0);
        assert_eq!(LandlockAbi::V1.as_u32(), 1);
        assert_eq!(LandlockAbi::V8.as_u32(), 8);
        assert_eq!(LandlockAbi::V9.as_u32(), 9);
    }

    #[test]
    fn an_unknown_abi_number_falls_back_to_the_highest_known_one() {
        // A kernel newer than this crate: the effective ABI is the highest one
        // the crate can build against, not the kernel's own.
        assert_eq!(LandlockAbi::from_number(999), LandlockAbi::V9);
        assert_eq!(LandlockAbi::from_number(9), LandlockAbi::V9);
        assert_eq!(LandlockAbi::from_number(0), LandlockAbi::Unsupported);
        assert_eq!(LandlockAbi::from_number(-1), LandlockAbi::Unsupported);
    }

    #[test]
    fn the_round_trip_through_the_number_is_stable() {
        for abi in [
            LandlockAbi::V1,
            LandlockAbi::V2,
            LandlockAbi::V3,
            LandlockAbi::V4,
            LandlockAbi::V5,
            LandlockAbi::V6,
            LandlockAbi::V7,
            LandlockAbi::V8,
            LandlockAbi::V9,
        ] {
            assert_eq!(LandlockAbi::from_number(abi.as_u32() as i32), abi);
        }
    }

    #[test]
    fn the_compat_level_names_match_landlocks_own() {
        // The refusal text quotes the level, and an operator reading it next to
        // Landlock's documentation must see the same word.
        assert_eq!(CompatLevel::BestEffort.as_str(), "BestEffort");
        assert_eq!(CompatLevel::SoftRequirement.as_str(), "SoftRequirement");
        assert_eq!(CompatLevel::HardRequirement.as_str(), "HardRequirement");
        assert_eq!(CompatLevel::HardRequirement.to_string(), "HardRequirement");
    }
}
