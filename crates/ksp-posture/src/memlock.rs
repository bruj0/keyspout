//! The lockability check — the Misfit K fix.
//!
//! A host that cannot lock secret memory must refuse to unseal, and it must say
//! why in the operator's own vocabulary. The measured failure mode is an **8 MB**
//! `RLIMIT_MEMLOCK` hard limit on LXC guests that cannot be raised
//! unprivileged, so this failure is the *expected* path on that deployment
//! class rather than an edge case.
//!
//! There is no silent fallback to ordinary heap (FR-009). When the region
//! cannot be locked, [`LockabilityRefusal`] names the current `RLIMIT_MEMLOCK`
//! and the systemd directive an operator would change.
//!
//! Two mechanisms satisfy the check, and they fail differently:
//!
//! - **`memfd_secret`** locks its pages as a property of the mapping. Asking for
//!   an explicit `mlock` of that mapping fails with `ENOMEM` **on a healthy
//!   host** (measured, kernel 7.0), because the pages are already accounted. Its
//!   gate is therefore the map call itself: `mmap` refuses beyond
//!   `RLIMIT_MEMLOCK`.
//! - **The sealed `memfd` fallback** is ordinary anonymous memory, so its gate
//!   is an explicit `mlock` call.
//!
//! Getting this wrong in either direction produces a silent lie: gating
//! secretmem on `mlock` would refuse every healthy host, and skipping `mlock`
//! on the fallback would return an unlocked region.

use std::fmt;

use crate::sys::{self, Mapping};

/// The observed `RLIMIT_MEMLOCK`, in bytes, with `None` meaning unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemlockObservation {
    /// The soft limit that applies to this process right now.
    pub soft_bytes: Option<u64>,
    /// The hard ceiling the soft limit may be raised to.
    pub hard_bytes: Option<u64>,
}

impl MemlockObservation {
    /// Reads `RLIMIT_MEMLOCK` for the running process.
    ///
    /// Fails only when `getrlimit(2)` itself fails, which no supported Linux
    /// kernel does for `RLIMIT_MEMLOCK`.
    pub fn read() -> Result<Self, MemlockError> {
        let (soft_bytes, hard_bytes) = sys::memlock_limit().map_err(MemlockError::Query)?;
        Ok(Self {
            soft_bytes,
            hard_bytes,
        })
    }

    /// Whether a region of `bytes` fits inside the soft limit.
    ///
    /// A *policy admission*, not a proof — the kernel still decides. It exists so
    /// an operator learns the constraint from the tool rather than from a failed
    /// unseal.
    pub fn admits_bytes(&self, bytes: u64) -> bool {
        match self.soft_bytes {
            None => true,
            Some(limit) => bytes <= limit,
        }
    }

    /// The value an operator would put after `LimitMEMLOCK=`.
    pub fn limitmemlock_value(&self) -> String {
        match self.hard_bytes.or(self.soft_bytes) {
            Some(bytes) => bytes.to_string(),
            None => "infinity".to_string(),
        }
    }
}

impl fmt::Display for MemlockObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `LimitMEMLOCK=` is the operator-facing form, so it is what a reader of a
        // status line recognises (design-spec §4A.3).
        match (self.soft_bytes, self.hard_bytes) {
            (Some(soft), Some(hard)) => {
                write!(f, "LimitMEMLOCK={soft} (hard LimitMEMLOCK={hard})")
            }
            (Some(soft), None) => write!(f, "LimitMEMLOCK={soft} (hard unlimited)"),
            (None, _) => write!(f, "LimitMEMLOCK=infinity"),
        }
    }
}

/// A refusal to lock the region, carrying the value the operator must change.
///
/// The display form contains the literal `LimitMEMLOCK=` substring: that is the
/// contract FR-009 states and the string acceptance criterion 4 asserts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockabilityRefusal {
    /// How many bytes the caller asked to lock.
    pub requested_bytes: u64,
    /// The limit observed at the moment of refusal.
    pub observed: MemlockObservation,
    /// The kernel's own error text, kept for logs, never for a response body.
    pub cause: String,
}

impl fmt::Display for LockabilityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the memory barrier cannot lock {} bytes: {}; {}",
            self.requested_bytes,
            self.cause,
            self.remedy()
        )
    }
}

impl LockabilityRefusal {
    /// The change that would make the region lockable, named for the platform
    /// that is running.
    ///
    /// FR-012: a refusal that tells an operator to edit a systemd unit on a host
    /// that has no systemd is a refusal with no remedy. The knob differs per
    /// platform, so the sentence does too — an operator should never be sent to
    /// a file that does not exist on their machine.
    pub fn remedy(&self) -> String {
        let value = self.observed.limitmemlock_value();
        #[cfg(target_os = "linux")]
        {
            format!("raise LimitMEMLOCK={value} for the unit that runs `ksp`")
        }
        #[cfg(target_os = "macos")]
        {
            format!(
                "raise the memlock limit with `launchctl limit memlock <soft> <hard>` \
                 (this host reports {value}); macOS has no systemd unit to change"
            )
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            format!(
                "raise the process memory-lock limit through this host's service \
                 manager (this host reports {value})"
            )
        }
    }
}

impl std::error::Error for LockabilityRefusal {}

/// Why a lockability check could not be completed.
#[derive(Debug)]
pub enum MemlockError {
    /// `getrlimit(2)` failed.
    Query(std::io::Error),
    /// The region could not be locked. There is deliberately no variant that
    /// means "carried on unlocked".
    Refused(Box<LockabilityRefusal>),
}

impl fmt::Display for MemlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query(err) => write!(f, "cannot read RLIMIT_MEMLOCK: {err}"),
            Self::Refused(refusal) => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for MemlockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Query(err) => Some(err),
            Self::Refused(refusal) => Some(refusal.as_ref()),
        }
    }
}

impl MemlockError {
    /// The refusal alone, or `None` when the failure was a query error. Callers
    /// that surface a policy refusal want this, so they never print a raw OS
    /// error into a status line.
    pub fn refusal(&self) -> Option<&LockabilityRefusal> {
        match self {
            Self::Refused(refusal) => Some(refusal),
            Self::Query(_) => None,
        }
    }
}

/// Builds a refusal, reading the limit at the moment of failure.
///
/// A read failure falls back to a zero observation so the message still names
/// `LimitMEMLOCK=`; reporting "cannot read the limit" would lose the one fact
/// the operator needs.
fn refusal(requested_bytes: u64, cause: impl fmt::Display) -> LockabilityRefusal {
    let observed = MemlockObservation::read().unwrap_or(MemlockObservation {
        soft_bytes: Some(0),
        hard_bytes: Some(0),
    });
    LockabilityRefusal {
        requested_bytes,
        observed,
        cause: cause.to_string(),
    }
}

/// Locks the caller's bytes of a mapping this crate made.
///
/// Used for the sealed-`memfd` fallback, whose pages are ordinary memory. The
/// caller must discard the region on error rather than keep using it unlocked;
/// [`crate::barrier::allocate`] enforces that by returning the error instead of a
/// region.
pub(crate) fn lock_region(
    mapping: &mut Mapping,
    offset: usize,
    len: usize,
) -> Result<(), LockabilityRefusal> {
    // Lock the whole rounded-up data extent: a partially locked region would
    // leave the tail of the last page in ordinary memory.
    let page = sys::page_size();
    let padded = len
        .checked_add(page - 1)
        .map(|value| value & !(page - 1))
        .unwrap_or(len);
    mapping
        .lock(offset, padded)
        .map_err(|err| refusal(len as u64, err))
}

/// Builds the refusal a secretmem mapping failure produces.
///
/// `memfd_secret` pages are locked by construction, so the map call is the gate
/// that `RLIMIT_MEMLOCK` constrains.
///
/// Linux only: there is no `memfd_secret` mapping off Linux.
#[cfg(target_os = "linux")]
pub(crate) fn mapping_refusal(len: usize, cause: std::io::Error) -> LockabilityRefusal {
    refusal(len as u64, cause)
}

/// Applies `MADV_DONTDUMP` to the caller's bytes of a mapping this crate made.
///
/// A core dump is the cheapest way an ordinary mapping leaks, and the advice
/// costs nothing. `EINVAL` from a kernel that does not know the advice is not a
/// policy failure: the region is still locked, so the report says "not applied"
/// rather than "unsafe".
///
/// Linux only: Darwin's SDK has no `MADV_DONTDUMP`. A host without it cannot
/// exclude a region from a dump, and the barrier reports that fact rather than
/// claiming the exclusion.
#[cfg(target_os = "linux")]
pub(crate) fn dont_dump(mapping: &Mapping, offset: usize, len: usize) -> bool {
    mapping.advise(offset, len, libc::MADV_DONTDUMP).is_ok()
}

/// Applies `MADV_DONTDUMP` on a host that has the advice, and reports honestly
/// on a host that does not.
///
/// The portable form of [`dont_dump`]. A host without the advice cannot exclude
/// the region from a dump, so it returns `false` — "not applied" — rather than
/// implying the exclusion happened.
#[cfg(not(target_os = "linux"))]
pub(crate) fn dont_dump(_mapping: &Mapping, _offset: usize, _len: usize) -> bool {
    false
}

/// What one dump-prevention control did when it was applied.
///
/// There is deliberately no third variant meaning "probably". A control is
/// either in force because its call returned success, or it is not, and then
/// the reason says why. The barrier narrows its claim to what this enum can
/// prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlOutcome {
    /// The call returned success, so the control is in force.
    Applied,
    /// The call failed, or this target has no such call. The reason is the
    /// kernel's own text, prefixed with the call that produced it.
    Unavailable {
        /// Why the control is absent, in a form a reader can act on.
        reason: String,
    },
}

impl ControlOutcome {
    /// Whether this control is in force.
    pub fn is_applied(&self) -> bool {
        matches!(self, Self::Applied)
    }
}

impl fmt::Display for ControlOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Applied => f.write_str("applied"),
            Self::Unavailable { reason } => write!(f, "not applied: {reason}"),
        }
    }
}

/// The two controls that decide whether this process can be dumped, answered
/// separately.
///
/// One boolean conflated two independent mechanisms, and the conflation is what
/// let a host print `weakened` without saying which half was missing. On Linux
/// the attach refusal is `PR_SET_DUMPABLE` and on Darwin it is
/// `PT_DENY_ATTACH`; `RLIMIT_CORE` is the core-dump exclusion on both, and it
/// is independent of the attach path because a process that takes a fatal
/// signal needs no debugger to be dumped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndumpablePosture {
    /// `RLIMIT_CORE = 0`, so no core file is written.
    pub core_limit: ControlOutcome,
    /// The attach refusal this target provides.
    pub ptrace: ControlOutcome,
}

impl UndumpablePosture {
    /// Whether the process cannot be dumped by either route.
    ///
    /// True only when both controls applied. One of two is still dumpable, and
    /// the name of this method has always claimed the conjunction.
    pub fn is_undumpable(&self) -> bool {
        self.core_limit.is_applied() && self.ptrace.is_applied()
    }
}

impl fmt::Display for UndumpablePosture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "core dumps {}; ptrace {}", self.core_limit, self.ptrace)
    }
}

/// The core-dump control's name on every target this crate builds for.
pub const CORE_DUMP_MECHANISM: &str = "RLIMIT_CORE";

/// The attach refusal this target uses, named for the document.
pub fn ptrace_mechanism() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "PR_SET_DUMPABLE"
    }
    #[cfg(target_os = "macos")]
    {
        "PT_DENY_ATTACH"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "none available on this target"
    }
}

/// Turns a syscall result into an outcome, keeping the kernel's own reason.
fn applied_or(result: std::io::Result<()>, call: &str) -> ControlOutcome {
    match result {
        Ok(()) => ControlOutcome::Applied,
        Err(error) => ControlOutcome::Unavailable {
            reason: format!("{call}: {error}"),
        },
    }
}

/// Disables core dumps and debugger attachment for the calling process.
///
/// Both controls are applied and both are reported, because either one alone
/// leaves a window: `RLIMIT_CORE = 0` stops a dump after a fatal signal, and the
/// attach refusal stops a same-UID debugger that would read the plaintext
/// directly. A host that can only do one of them is not undumpable, and
/// [`UndumpablePosture::is_undumpable`] says so.
///
/// Linux refuses attach with `PR_SET_DUMPABLE`; Darwin has no `prctl` and
/// refuses it with `ptrace(PT_DENY_ATTACH)`. That refusal is permanent for this
/// process — a debugger attached after this call kills it — so this function is
/// the last safe point to inspect the process under one.
#[cfg(target_os = "linux")]
pub(crate) fn set_undumpable() -> UndumpablePosture {
    UndumpablePosture {
        core_limit: applied_or(sys::exclude_core_dumps(), "setrlimit(RLIMIT_CORE)"),
        ptrace: applied_or(
            sys::prctl(libc::PR_SET_DUMPABLE, 0),
            "prctl(PR_SET_DUMPABLE)",
        ),
    }
}

/// Disables core dumps and debugger attachment for the calling process.
///
/// The Darwin form. It reports each control separately for the same reason the
/// Linux form does; only the attach mechanism differs.
#[cfg(target_os = "macos")]
pub(crate) fn set_undumpable() -> UndumpablePosture {
    UndumpablePosture {
        core_limit: applied_or(sys::exclude_core_dumps(), "setrlimit(RLIMIT_CORE)"),
        ptrace: applied_or(sys::deny_ptrace_attach(), "ptrace(PT_DENY_ATTACH)"),
    }
}

/// Reports both controls as absent on a target with neither mechanism.
///
/// The honest answer, not a plausible `Applied`: this crate builds for other
/// Unix targets, and a host that cannot refuse a dump must say so rather than
/// claim the barrier held.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn set_undumpable() -> UndumpablePosture {
    let absent = || ControlOutcome::Unavailable {
        reason: "this target provides neither RLIMIT_CORE wiring nor a prctl/ptrace \
                 refusal in this build"
            .to_owned(),
    };
    UndumpablePosture {
        core_limit: absent(),
        ptrace: absent(),
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn reading_the_limit_yields_a_displayable_observation() {
        let observed = MemlockObservation::read().expect("RLIMIT_MEMLOCK is always readable");
        let rendered = observed.to_string();
        assert!(
            rendered.starts_with("LimitMEMLOCK="),
            "the operator-facing form must name the directive, got {rendered:?}"
        );
    }

    #[test]
    fn an_unbounded_limit_admits_any_region() {
        let observed = MemlockObservation {
            soft_bytes: None,
            hard_bytes: None,
        };
        assert!(observed.admits_bytes(u64::MAX));
        assert!(observed.to_string().contains("infinity"));
        assert_eq!(observed.limitmemlock_value(), "infinity");
    }

    #[test]
    fn a_finite_limit_admits_only_what_fits() {
        let observed = MemlockObservation {
            soft_bytes: Some(8 * 1024 * 1024),
            hard_bytes: Some(8 * 1024 * 1024),
        };
        // The boundary, not just the far case: 8 MB is the measured LXC value.
        assert!(observed.admits_bytes(8 * 1024 * 1024));
        assert!(!observed.admits_bytes(8 * 1024 * 1024 + 1));
    }

    #[test]
    fn a_refusal_names_the_observed_value_and_a_remedy_this_platform_has() {
        let refusal = LockabilityRefusal {
            requested_bytes: 4096,
            observed: MemlockObservation {
                soft_bytes: Some(8 * 1024 * 1024),
                hard_bytes: Some(8 * 1024 * 1024),
            },
            cause: "Cannot allocate memory".to_string(),
        };
        let message = refusal.to_string();
        assert!(
            message.contains("8388608"),
            "the refusal must state the current value, got {message:?}"
        );
        assert!(message.contains("4096"));
        assert!(
            message.contains(platform_remedy()),
            "FR-012 requires a remedy the running platform has, got {message:?}"
        );
    }

    /// The remedy substring is pinned exactly; a reword would otherwise pass
    /// silently and leave the operator without an actionable fix.
    #[test]
    fn the_remedy_substring_is_never_reworded() {
        let refusal = LockabilityRefusal {
            requested_bytes: 1,
            observed: MemlockObservation {
                soft_bytes: Some(0),
                hard_bytes: Some(0),
            },
            cause: "nope".to_string(),
        };
        assert!(refusal.to_string().contains(platform_remedy()));
    }

    /// The substring each platform's remedy must contain.
    ///
    /// Linux names the systemd directive an operator would edit; macOS names
    /// the `launchctl` limit, because there is no systemd unit to change there.
    fn platform_remedy() -> &'static str {
        #[cfg(target_os = "linux")]
        {
            "LimitMEMLOCK="
        }
        #[cfg(target_os = "macos")]
        {
            "launchctl limit memlock"
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            "service manager"
        }
    }

    #[test]
    fn a_query_error_is_not_mistaken_for_a_refusal() {
        let error = MemlockError::Query(std::io::Error::from_raw_os_error(libc::EINVAL));
        assert!(
            error.refusal().is_none(),
            "a failed getrlimit must not read as a policy refusal"
        );
    }
}
