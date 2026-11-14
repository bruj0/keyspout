//! Descriptor sanitation — closing unrelated inherited descriptors.
//!
//! A confined child's path rules are only as strong as the descriptors it
//! inherits. An `O_PATH` or directory descriptor opened *before* confinement
//! survives `restrict_self()` and lets the child reach a [`Sibling Path`] with
//! `openat(2)`, bypassing the rules entirely. Closing those descriptors turns
//! the rule from a client-side convention into a kernel-enforced fact (Misfit G,
//! FR-039).
//!
//! The policy is an allow-list, never a deny-list: only stdin, stdout and stderr
//! survive, plus the descriptors the caller names explicitly (for example a
//! pipe it is about to hand to the child). Everything else is closed.
//!
//! [`Sibling Path`]: crate#sibling-path

use std::fmt;

use crate::sys;

/// Which descriptors survive sanitation.
///
/// Built by the caller, because only the caller knows which pipes it intends the
/// child to inherit. The standard streams are always kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DescriptorPolicy {
    keep: Vec<libc::c_int>,
}

impl DescriptorPolicy {
    /// A policy that keeps only stdin, stdout and stderr.
    pub fn standard_streams_only() -> Self {
        Self { keep: Vec::new() }
    }

    /// Also keep `fd`, for example a pipe the child is about to read.
    ///
    /// Zero, one and two are already kept; adding them is not an error, because
    /// a caller that rebuilds a list from an environment may not know.
    pub fn keep(mut self, fd: libc::c_int) -> Self {
        if !Self::is_standard_stream(fd) && !self.keep.contains(&fd) {
            self.keep.push(fd);
        }
        self
    }

    /// Whether `fd` is one of the three standard streams.
    pub fn is_standard_stream(fd: libc::c_int) -> bool {
        matches!(
            fd,
            libc::STDIN_FILENO | libc::STDOUT_FILENO | libc::STDERR_FILENO
        )
    }

    /// Whether `fd` survives this policy.
    pub fn keeps(&self, fd: libc::c_int) -> bool {
        Self::is_standard_stream(fd) || self.keep.contains(&fd)
    }

    /// The explicitly kept descriptors, excluding the standard streams.
    pub fn explicitly_kept(&self) -> &[libc::c_int] {
        &self.keep
    }
}

/// The outcome of a sanitation pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitationReport {
    /// Descriptors that were open and are now closed.
    pub closed: Vec<libc::c_int>,
    /// Descriptors kept open by the policy.
    pub kept: Vec<libc::c_int>,
}

impl SanitationReport {
    /// How many descriptors were closed.
    pub fn closed_count(&self) -> usize {
        self.closed.len()
    }

    /// Whether `fd` was closed by the pass.
    pub fn closed_includes(&self, fd: libc::c_int) -> bool {
        self.closed.contains(&fd)
    }
}

/// Why sanitation could not complete.
#[derive(Debug)]
pub enum DescriptorError {
    /// Enumerating the process's descriptors failed, so the process cannot know
    /// what it inherits. Refusing is the safe answer: an unknown inheritance is
    /// exactly the state that lets a sibling descriptor survive.
    Enumeration {
        /// The underlying reason.
        cause: String,
    },
    /// A descriptor that should have been closed is still open.
    StillOpen {
        /// The descriptor number.
        fd: libc::c_int,
        /// The kernel's reason.
        cause: String,
    },
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enumeration { cause } => {
                write!(f, "cannot enumerate inherited descriptors: {cause}")
            }
            Self::StillOpen { fd, cause } => {
                write!(f, "descriptor {fd} is still open after sanitation: {cause}")
            }
        }
    }
}

impl std::error::Error for DescriptorError {}

/// The directory that lists this process's open descriptors.
///
/// `/proc/self/fd` on Linux, `/dev/fd` on Darwin and the other BSDs. Both list
/// exactly the descriptors the process holds, which is the property this
/// function needs: a fixed range would miss a high-numbered descriptor and
/// would silently skip the very case this function exists to catch.
///
/// The path is a constant per platform rather than a runtime choice because the
/// two are not interchangeable — `/dev/fd` on Linux is a symlink to
/// `/proc/self/fd`, but on Darwin it is the only listing there is — and a
/// runtime probe would be a second thing that can go wrong on a host the
/// operator did not choose.
#[cfg(target_os = "linux")]
const DESCRIPTOR_DIRECTORY: &str = "/proc/self/fd";

/// The directory that lists this process's open descriptors.
///
/// See the Linux variant for why this is a constant per platform.
#[cfg(not(target_os = "linux"))]
const DESCRIPTOR_DIRECTORY: &str = "/dev/fd";

/// Closes every inherited descriptor the policy does not keep.
///
/// Enumeration reads [`DESCRIPTOR_DIRECTORY`], which lists exactly the
/// descriptors this process holds. It requires that directory to be present;
/// when it is not, the function refuses rather than guessing.
///
/// The directory handle used for enumeration is itself a descriptor and is
/// excluded from the pass, then closed with the reader.
pub fn sanitize(policy: &DescriptorPolicy) -> Result<SanitationReport, DescriptorError> {
    let entries =
        std::fs::read_dir(DESCRIPTOR_DIRECTORY).map_err(|err| DescriptorError::Enumeration {
            cause: err.to_string(),
        })?;

    let mut candidates = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| DescriptorError::Enumeration {
            cause: err.to_string(),
        })?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(fd) = name.parse::<libc::c_int>() else {
            continue;
        };
        candidates.push(fd);
    }

    // The listing includes the handle `read_dir` is using to read it, so that
    // number is among the candidates. `entries` was consumed by the loop above,
    // which dropped the `ReadDir` and closed its handle, so the candidate is now
    // a free number: closing it yields `EBADF`, which the arm below records as
    // closed. Nothing else can have taken the number in between, because this
    // function does not open anything after the reader is dropped.
    let mut closed = Vec::new();
    let mut kept = Vec::new();
    for fd in candidates {
        if policy.keeps(fd) {
            kept.push(fd);
            continue;
        }
        match sys::close(fd) {
            Ok(()) => closed.push(fd),
            // The descriptor vanished between enumeration and close. That is the
            // desired end state, so it is recorded as closed rather than retried.
            Err(err) if err.raw_os_error() == Some(libc::EBADF) => closed.push(fd),
            Err(err) => {
                return Err(DescriptorError::StillOpen {
                    fd,
                    cause: err.to_string(),
                });
            }
        }
    }

    closed.sort_unstable();
    kept.sort_unstable();
    Ok(SanitationReport { closed, kept })
}

/// Whether `fd` is still open in this process.
///
/// Exposed so a test can observe the effect of sanitation on a descriptor it
/// opened itself, without reaching into `/proc` a second time.
pub fn is_open(fd: libc::c_int) -> bool {
    sys::fcntl_getfd(fd).is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_standard_streams_always_survive() {
        let policy = DescriptorPolicy::standard_streams_only();
        assert!(policy.keeps(libc::STDIN_FILENO));
        assert!(policy.keeps(libc::STDOUT_FILENO));
        assert!(policy.keeps(libc::STDERR_FILENO));
        assert!(!policy.keeps(9));
    }

    #[test]
    fn an_explicitly_kept_descriptor_survives_and_is_reported() {
        let policy = DescriptorPolicy::standard_streams_only().keep(42);
        assert!(policy.keeps(42));
        assert_eq!(policy.explicitly_kept(), &[42]);
    }

    #[test]
    fn keeping_a_standard_stream_is_idempotent() {
        let policy = DescriptorPolicy::standard_streams_only()
            .keep(libc::STDOUT_FILENO)
            .keep(libc::STDOUT_FILENO);
        assert!(
            policy.explicitly_kept().is_empty(),
            "the standard streams are already kept and must not be duplicated"
        );
    }
    // The two destructive properties — "a named descriptor survives" and "an
    // unnamed one is closed" — are asserted in `tests/confinement.rs` against a
    // re-executed process. Running them here would close the libtest harness's
    // own standard streams and break every later test in this binary.
}
