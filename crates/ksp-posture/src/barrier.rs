//! The memory barrier — keeping key material out of ordinary memory.
//!
//! Two mechanisms, in order of preference:
//!
//! 1. **`memfd_secret(2)`** — the pages backing the file are removed from the
//!    kernel's direct map and are locked against swap by construction. This is
//!    *the* barrier.
//! 2. **A sealed `memfd`** — an ordinary `memfd_create(2)` file with
//!    `MFD_ALLOW_SEALING`, `F_SEAL_SEAL` and the shrink/grow seals applied,
//!    plus `MADV_DONTDUMP` and `PR_SET_DUMPABLE=0`. This is a **weaker**
//!    barrier: the pages sit in ordinary memory and remain reachable by a
//!    kernel-side read. It is reported as [`BarrierKind::SealedMemfd`] and
//!    never as equivalent to the primary.
//!
//! The two are distinguishable in the type system, not by a comment: a caller
//! cannot obtain a [`BarrieredRegion`] without also obtaining the
//! [`BarrierKind`] that says which mechanism produced it, and
//! [`BarrierKind::supports_sealing`] records that `memfd_secret` does **not**
//! support `F_SEAL` — a posture that claimed sealing for it would describe a
//! mechanism it does not have.

use std::fmt;

#[cfg(target_os = "linux")]
use std::io;

#[cfg(target_os = "linux")]
use memfd::{FileSeal, Memfd, MemfdOptions};

use crate::memlock::{self, LockabilityRefusal, MemlockObservation};
use crate::sys::Mapping;

/// Which mechanism is actually keeping key material out of ordinary memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BarrierKind {
    /// `memfd_secret(2)`. Pages are absent from the kernel direct map and are
    /// locked by construction.
    MemfdSecret,
    /// A sealed `memfd`. Ordinary memory, sealed against later writes and
    /// growth; weaker than [`Self::MemfdSecret`] and reported as such.
    SealedMemfd,
    /// `mlock(2)` on an anonymous mapping. Pages stay resident and never reach
    /// swap; they are **not** absent from the kernel's direct map, and they are
    /// **not** excluded from a dump.
    ///
    /// This is the portable barrier, and it is the weakest of the three. It
    /// must never be reported as [`Self::MemfdSecret`]: a run that believed its
    /// key material was out of the kernel's reach while it was in ordinary
    /// locked memory would be a false claim about a security control.
    Mlock,
}

impl BarrierKind {
    /// Whether this is the primary barrier rather than the fallback.
    ///
    /// A method rather than an inline comparison, so no caller accidentally
    /// treats the two as interchangeable.
    pub fn is_primary(self) -> bool {
        matches!(self, Self::MemfdSecret)
    }

    /// Whether this mechanism supports `F_SEAL`. Only `memfd_create` does;
    /// `memfd_secret`'s descriptor does not, and neither does `mlock`.
    pub fn supports_sealing(self) -> bool {
        matches!(self, Self::SealedMemfd)
    }

    /// The stable identifier a status line or log record uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MemfdSecret => "memfd_secret",
            Self::SealedMemfd => "sealed_memfd",
            Self::Mlock => "mlock",
        }
    }
}

impl fmt::Display for BarrierKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which mechanism a caller is willing to accept.
///
/// The choice is explicit because "use the fallback quietly" is exactly the
/// silent degradation Misfit K is about. A caller that needs the primary says
/// so and receives an error when the mechanism is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierPreference {
    /// Require `memfd_secret`; refuse rather than degrade onto ordinary memory.
    RequireSecret,
    /// Prefer `memfd_secret`; accept the sealed `memfd` fallback and report it
    /// as the weaker barrier it is.
    AllowFallback,
}

/// A region of memory holding key material, together with its barrier kind.
///
/// The region is deliberately opaque: it hands out a byte slice only for the
/// length the caller asked for, behind a borrow, so the mapping cannot be
/// reached while it is being written or after it is gone.
pub struct BarrieredRegion {
    kind: BarrierKind,
    mapping: Mapping,
    data_offset: usize,
    len: usize,
    guarded: bool,
    dont_dump: bool,
    undumpable: memlock::UndumpablePosture,
    /// Keeps the `memfd_create` file alive for the region's lifetime. `None`
    /// for `memfd_secret`, whose mapping outlives its descriptor, and for
    /// `mlock`, whose mapping is anonymous.
    #[cfg(target_os = "linux")]
    _file: Option<Memfd>,
    observed_memlock: MemlockObservation,
}

impl BarrieredRegion {
    /// Which barrier is in force.
    pub fn kind(&self) -> BarrierKind {
        self.kind
    }

    /// The `RLIMIT_MEMLOCK` observed when the region was created.
    pub fn observed_memlock(&self) -> MemlockObservation {
        self.observed_memlock
    }

    /// Whether guard pages delineate the region, so a sequential over-read
    /// faults instead of reaching adjacent memory.
    pub fn is_guarded(&self) -> bool {
        self.guarded
    }

    /// Whether the mapping is excluded from core dumps.
    pub fn is_excluded_from_dumps(&self) -> bool {
        self.dont_dump
    }

    /// Whether the process cannot be dumped by either route.
    ///
    /// True only when both controls applied. The answer is narrower than it was
    /// when one boolean covered one call, and the conjunction is what this name
    /// has always claimed.
    pub fn is_undumpable(&self) -> bool {
        self.undumpable.is_undumpable()
    }

    /// Each control that decides whether this process can be dumped.
    ///
    /// A caller that reports a posture needs the half that is *missing*, not
    /// only the conjunction: `weakened` with no parts was the defect this
    /// accessor exists to make impossible.
    pub fn undumpable(&self) -> &memlock::UndumpablePosture {
        &self.undumpable
    }

    /// The caller's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.mapping.slice(self.data_offset, self.len)
    }

    /// The caller's bytes, mutably.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.mapping.slice_mut(self.data_offset, self.len)
    }

    /// Wipes the caller's bytes in place.
    ///
    /// The map's destructor calls this before unmapping, and callers may also
    /// call it to shorten the window a value is resident.
    pub fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.as_bytes_mut().zeroize();
    }
}

impl Drop for BarrieredRegion {
    fn drop(&mut self) {
        // Wipe before the mapping goes away, so the pages are overwritten while
        // they are still addressable. `Mapping::drop` then unmaps.
        self.wipe();
    }
}

impl fmt::Debug for BarrieredRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the contents: a debug format is the easiest way to leak
        // key material into a log.
        f.debug_struct("BarrieredRegion")
            .field("kind", &self.kind)
            .field("len", &self.len)
            .field("guarded", &self.guarded)
            .field("dont_dump", &self.dont_dump)
            .field("undumpable", &self.undumpable)
            .finish_non_exhaustive()
    }
}

/// Why a region could not be created.
#[derive(Debug)]
pub enum BarrierError {
    /// The primary mechanism is unavailable and the caller required it.
    SecretUnavailable {
        /// The kernel's reason, kept for logs. `ENOSYS` means the mechanism is
        /// absent or not enabled on the kernel command line.
        cause: String,
    },
    /// `memfd_secret` rejected its flags with `EINVAL`. Deliberately distinct
    /// from an absent mechanism: a working kernel demoted by a wrong flag
    /// would otherwise look identical to a host without `memfd_secret`
    /// (DEVELOPMENT.md §7.1).
    SecretFlagRejected {
        /// The kernel's reason.
        cause: String,
    },
    /// The region could not be locked, so there is no barrier — and no
    /// unlocked substitute either (FR-009).
    NotLockable(Box<LockabilityRefusal>),
    /// The adapter named in the refusal could not establish its mechanism.
    ///
    /// FR-013: a refusal must name the adapter that produced it, so the
    /// operator can tell *which* mechanism failed rather than being told only
    /// that a barrier could not be established. The nested refusal carries the
    /// host's own reason, and the remedy for the platform it is printed on.
    AdapterRefused {
        /// The adapter that could not establish its mechanism.
        adapter: &'static str,
        /// The adapter's own reason.
        reason: String,
    },
    /// The fallback could not be created, sized, mapped or sealed.
    Fallback {
        /// The operation that failed.
        operation: &'static str,
        /// The underlying reason.
        cause: String,
    },
}

impl fmt::Display for BarrierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecretUnavailable { cause } => write!(
                f,
                "memfd_secret is unavailable on this host ({cause}); \
                 the required barrier cannot be established"
            ),
            Self::SecretFlagRejected { cause } => write!(
                f,
                "memfd_secret rejected its flags ({cause}); \
                 this is a flag defect, not an absent mechanism"
            ),
            Self::NotLockable(refusal) => write!(f, "{refusal}"),
            Self::AdapterRefused { adapter, reason } => write!(
                f,
                "the {adapter} adapter cannot establish its mechanism: {reason}"
            ),
            Self::Fallback { operation, cause } => {
                write!(
                    f,
                    "the sealed-memfd fallback failed to {operation}: {cause}"
                )
            }
        }
    }
}

impl std::error::Error for BarrierError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotLockable(refusal) => Some(refusal.as_ref()),
            _ => None,
        }
    }
}

impl BarrierError {
    /// Whether the failure means the mechanism is *absent*, as opposed to
    /// misconfigured or too small. Absence legitimately selects the fallback;
    /// a rejected flag and a lockable-region refusal do not.
    pub fn is_mechanism_absent(&self) -> bool {
        matches!(self, Self::SecretUnavailable { .. })
    }
}

/// Whether `memfd_secret(2)` works on this host.
///
/// The probe creates a descriptor and closes it again, so it leaves no file,
/// no mapping and no seal behind. It is the availability check, not the
/// allocation: the allocation maps and locks the pages, while this only asks
/// whether the syscall works at all.
///
/// Off Linux the mechanism does not exist, so the answer is the host's reason
/// rather than a syscall error.
pub(crate) fn probe_secret_available() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        match crate::sys::memfd_secret(libc::O_CLOEXEC) {
            Ok(fd) => {
                // Close it: the probe must not leave a descriptor behind.
                let _ = crate::sys::close(fd);
                Ok(())
            }
            Err(err) => Err(format!("this host does not provide memfd_secret(2): {err}")),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("this host does not provide memfd_secret(2): the mechanism is Linux-only".to_string())
    }
}

/// Whether `memfd_create(2)` works on this host.
///
/// The probe creates a sealable descriptor and closes it again. Off Linux the
/// `memfd` crate does not exist, so the answer is the host's reason.
pub(crate) fn probe_sealed_available() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        match memfd::MemfdOptions::default()
            .allow_sealing(true)
            .create("ksp-probe")
        {
            Ok(memfd) => {
                drop(memfd);
                Ok(())
            }
            Err(err) => Err(format!("this host does not provide memfd_create(2): {err}")),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("this host does not provide memfd_create(2): the mechanism is Linux-only".to_string())
    }
}

/// Whether `mlock(2)` works on this host.
///
/// The probe maps one page of anonymous memory, locks it and unmaps it. It
/// leaves nothing behind, and it answers the question the availability check
/// exists to answer: can this host lock a page at all?
///
/// The limit is read first, because a host whose `RLIMIT_MEMLOCK` is exhausted
/// cannot lock — and that is a *host* fact, not a mechanism's absence. The
/// reason says which it was, so the operator is sent to the right place.
pub(crate) fn probe_mlock_available() -> Result<(), String> {
    let page = crate::sys::page_size();
    let mapping = crate::sys::Mapping::anonymous(page, libc::PROT_READ | libc::PROT_WRITE)
        .map_err(|err| format!("this host cannot map a page to lock it: {err}"))?;

    mapping.lock(0, page).map_err(|err| {
        let observed = MemlockObservation::read().unwrap_or(MemlockObservation {
            soft_bytes: None,
            hard_bytes: None,
        });
        format!("this host cannot lock a page: {err}; the current limit is {observed}")
    })
}

/// Allocates a region behind the sealed-`memfd` mechanism.
///
/// This is the fallback path, reached directly rather than through
/// [`allocate`]'s preference logic: a caller that named the sealed adapter
/// asked for *that* mechanism, and routing it through the preference would let
/// the primary be chosen instead.
///
/// Off Linux the mechanism does not exist, so the call refuses. The adapter is
/// still in the build and still reports itself as unavailable — the refusal is
/// what a caller gets if it ignores that answer and allocates anyway.
#[cfg(target_os = "linux")]
pub(crate) fn allocate_sealed(bytes: usize) -> Result<BarrieredRegion, BarrierError> {
    let observed_memlock = MemlockObservation::read().unwrap_or(MemlockObservation {
        soft_bytes: None,
        hard_bytes: None,
    });
    create_sealed_region(bytes, observed_memlock)
}

/// Allocates a region behind the sealed-`memfd` mechanism, on a host that has
/// no `memfd`.
///
/// The mechanism is Linux-only, so there is nothing to allocate. The refusal
/// says the mechanism is absent rather than reporting a fallback failure: a
/// caller that asked for the sealed mechanism must not silently receive a
/// different one.
#[cfg(not(target_os = "linux"))]
pub(crate) fn allocate_sealed(_bytes: usize) -> Result<BarrieredRegion, BarrierError> {
    Err(BarrierError::SecretUnavailable {
        cause: "this host does not provide memfd_create(2): the mechanism is Linux-only"
            .to_string(),
    })
}

/// Allocates a region whose pages are held in memory by `mlock(2)`.
///
/// The refusal is the point: a failed lock is an error, never an unprotected
/// region (FR-032).
pub(crate) fn allocate_mlock(bytes: usize) -> Result<BarrieredRegion, BarrierError> {
    let observed_memlock = MemlockObservation::read().unwrap_or(MemlockObservation {
        soft_bytes: None,
        hard_bytes: None,
    });
    create_mlock_region(bytes, observed_memlock)
}

/// Allocates a barriered region of `len` bytes, zeroed.
///
/// The region is bracketed by `PROT_NONE` guard pages where the kernel allows
/// them, excluded from core dumps, and — for the fallback — locked before it is
/// returned. A region that could not be locked is never returned.
///
/// With [`BarrierPreference::RequireSecret`], an absent `memfd_secret` is an
/// error rather than a silent demotion.
///
/// # A host with neither `memfd_secret` nor `memfd_create`
///
/// Both mechanisms are Linux-only (NFR-003). On another target the only
/// barrier this crate can establish is `mlock`, which is a real mechanism and a
/// real — but weaker — guarantee: the pages stay resident and never reach swap,
/// and they are still in the kernel's direct map. The region reports
/// [`BarrierKind::Mlock`], so a status line cannot mistake it for the primary
/// barrier.
#[cfg(target_os = "linux")]
pub fn allocate(
    len: usize,
    preference: BarrierPreference,
) -> Result<BarrieredRegion, BarrierError> {
    let observed_memlock = MemlockObservation::read().unwrap_or(MemlockObservation {
        soft_bytes: None,
        hard_bytes: None,
    });

    match create_secret_region(len) {
        Ok(region) => {
            return Ok(BarrieredRegion {
                kind: BarrierKind::MemfdSecret,
                mapping: region.mapping,
                data_offset: region.data_offset,
                len,
                guarded: region.guarded,
                dont_dump: region.dont_dump,
                undumpable: memlock::set_undumpable(),
                _file: None,
                observed_memlock,
            });
        }
        Err(SecretFailure::FlagRejected { cause }) => {
            // A rejected flag is a defect in this crate, never a reason to
            // demote the host silently.
            return Err(BarrierError::SecretFlagRejected { cause });
        }
        Err(SecretFailure::Absent { cause }) => {
            if preference == BarrierPreference::RequireSecret {
                return Err(BarrierError::SecretUnavailable { cause });
            }
        }
        Err(SecretFailure::NotLockable(refusal)) => {
            if preference == BarrierPreference::RequireSecret {
                return Err(BarrierError::NotLockable(Box::new(refusal)));
            }
        }
    }

    create_sealed_region(len, observed_memlock)
}

/// Allocates a barriered region of `len` bytes on a host with no `memfd`.
///
/// The only mechanism available off Linux is `mlock`. It is a real barrier and
/// a weaker one: the pages stay resident and never reach swap, but they remain
/// in the kernel's direct map and are not excluded from a dump.
///
/// A `RequireSecret` caller refuses here, because the host cannot provide the
/// mechanism it asked for. An `AllowFallback` caller gets the `mlock` region,
/// and the region says which mechanism produced it.
#[cfg(not(target_os = "linux"))]
pub fn allocate(
    len: usize,
    preference: BarrierPreference,
) -> Result<BarrieredRegion, BarrierError> {
    if preference == BarrierPreference::RequireSecret {
        return Err(BarrierError::SecretUnavailable {
            cause: "memfd_secret is a Linux mechanism and this host does not provide it"
                .to_string(),
        });
    }
    let observed_memlock = MemlockObservation::read().unwrap_or(MemlockObservation {
        soft_bytes: None,
        hard_bytes: None,
    });
    create_mlock_region(len, observed_memlock)
}

/// The shape both mechanisms share before the barrier kind is attached.
#[cfg(target_os = "linux")]
struct RawRegion {
    mapping: Mapping,
    data_offset: usize,
    guarded: bool,
    dont_dump: bool,
}

/// Why `memfd_secret(2)` did not produce a region.
///
/// Linux only: off Linux there is no `memfd_secret` to fail.
#[cfg(target_os = "linux")]
enum SecretFailure {
    /// `ENOSYS` (or another error): the mechanism is not implemented or not
    /// enabled.
    Absent { cause: String },
    /// `EINVAL`: the kernel rejected the flags. A defect, not absence.
    FlagRejected { cause: String },
    /// The mapping was refused because `RLIMIT_MEMLOCK` is too small. This is
    /// the Misfit K condition in its secretmem form.
    NotLockable(LockabilityRefusal),
}

/// `memfd_secret(2)` — Linux only.
///
/// The syscall does not exist off Linux, so the function is gated rather than
/// stubbed. The *adapter* reports the absence; the syscall layer simply has
/// nothing to call.
#[cfg(target_os = "linux")]
fn create_secret_region(len: usize) -> Result<RawRegion, SecretFailure> {
    let fd = match crate::sys::memfd_secret(libc::O_CLOEXEC) {
        Ok(fd) => fd,
        Err(err) => {
            return Err(match err.raw_os_error() {
                Some(libc::EINVAL) => SecretFailure::FlagRejected {
                    cause: err.to_string(),
                },
                // `ENOSYS` is the documented "not implemented / not enabled"
                // signal. Any other error is treated the same way: the
                // mechanism is not available to this process.
                _ => SecretFailure::Absent {
                    cause: err.to_string(),
                },
            });
        }
    };

    let region = map_region(fd, len);
    // The mapping keeps the pages alive, so the descriptor is closed whether or
    // not the map succeeded.
    let _ = crate::sys::close(fd);

    region.map_err(|err| {
        if err.raw_os_error() == Some(libc::ENOMEM) || err.kind() == io::ErrorKind::OutOfMemory {
            // `memfd_secret` pages are locked by construction, so the map call is
            // exactly where `RLIMIT_MEMLOCK` bites. An explicit `mlock` of the
            // same mapping would fail with `ENOMEM` on a healthy host too.
            SecretFailure::NotLockable(memlock::mapping_refusal(len, err))
        } else {
            SecretFailure::Absent {
                cause: err.to_string(),
            }
        }
    })
}

/// A sealed `memfd` region — Linux only.
///
/// The `memfd` crate is gated to Linux and Android, so this path exists only
/// there. A host without it gets the `mlock` region instead.
#[cfg(target_os = "linux")]
fn create_sealed_region(
    len: usize,
    observed_memlock: MemlockObservation,
) -> Result<BarrieredRegion, BarrierError> {
    let memfd = MemfdOptions::default()
        .allow_sealing(true)
        .create("ksp-secret")
        .map_err(|err| BarrierError::Fallback {
            operation: "create a sealable memfd",
            cause: err.to_string(),
        })?;

    let fd = {
        use std::os::unix::io::AsRawFd;
        memfd.as_file().as_raw_fd()
    };

    let mut raw = map_region(fd, len).map_err(|cause| BarrierError::Fallback {
        operation: "map the memfd",
        cause: cause.to_string(),
    })?;

    // The fallback is ordinary memory, so nothing has locked it yet. Fail here
    // rather than hand back a region that is silently unlocked (FR-009).
    memlock::lock_region(&mut raw.mapping, raw.data_offset, len)
        .map_err(|refusal| BarrierError::NotLockable(Box::new(refusal)))?;

    memfd
        .add_seals(&[FileSeal::SealSeal, FileSeal::SealShrink, FileSeal::SealGrow])
        .map_err(|err| BarrierError::Fallback {
            operation: "seal the memfd",
            cause: err.to_string(),
        })?;

    Ok(BarrieredRegion {
        kind: BarrierKind::SealedMemfd,
        mapping: raw.mapping,
        data_offset: raw.data_offset,
        len,
        guarded: raw.guarded,
        dont_dump: raw.dont_dump,
        undumpable: memlock::set_undumpable(),
        _file: Some(memfd),
        observed_memlock,
    })
}

/// Allocates a region whose pages are held in memory by `mlock(2)`.
///
/// The portable barrier. It is real and it is weaker than either `memfd`
/// mechanism: the pages stay resident and never reach swap, but they remain in
/// the kernel's direct map and are not excluded from a dump.
///
/// The mapping is anonymous, so no descriptor is needed — `MAP_ANONYMOUS`
/// exists on every target this crate builds for.
///
/// The lock is taken **before** the region is handed back, and a failed lock
/// is a refusal rather than an unprotected region (FR-032). That is the whole
/// point of this mechanism: handing back an unlocked region while reporting a
/// barrier would be the silent degradation this subsystem exists to prevent.
pub(crate) fn create_mlock_region(
    len: usize,
    observed_memlock: MemlockObservation,
) -> Result<BarrieredRegion, BarrierError> {
    let page = crate::sys::page_size();
    let data_offset = page;
    // Round the data length up so the trailing guard starts on a page boundary.
    let padded = len
        .checked_add(page - 1)
        .map(|value| value & !(page - 1))
        .unwrap_or(len);
    let total_len = padded.saturating_add(2 * page);

    let mut mapping =
        Mapping::anonymous(total_len, libc::PROT_READ | libc::PROT_WRITE).map_err(|err| {
            BarrierError::Fallback {
                operation: "map an anonymous region",
                cause: err.to_string(),
            }
        })?;

    // Guard pages. A kernel that refuses the protection change leaves the
    // region unguarded rather than failing: the barrier is the mechanism, the
    // guard is defence in depth.
    let front = mapping.protect(0, page, libc::PROT_NONE);
    let back = mapping.protect(page + padded, page, libc::PROT_NONE);
    let guarded = front.is_ok() && back.is_ok();

    // The lock is the mechanism. Fail here rather than hand back a region that
    // is silently unlocked (FR-009, FR-032).
    memlock::lock_region(&mut mapping, data_offset, len)
        .map_err(|refusal| BarrierError::NotLockable(Box::new(refusal)))?;

    // The dump advice is read before the mapping moves into the region, because
    // the region owns it from here on.
    let dont_dump = memlock::dont_dump(&mapping, data_offset, len);
    let undumpable = memlock::set_undumpable();

    Ok(BarrieredRegion {
        kind: BarrierKind::Mlock,
        mapping,
        data_offset,
        len,
        guarded,
        dont_dump,
        undumpable,
        // The `mlock` region maps anonymous memory: it has no `memfd`
        // descriptor to keep alive.
        #[cfg(target_os = "linux")]
        _file: None,
        observed_memlock,
    })
}

/// Maps `len` bytes of `fd` into a fresh reservation with guard pages.
///
/// The reservation is `page + padded(len) + page`; the first and last pages are
/// set to `PROT_NONE`, so a sequential over-read or over-write faults inside
/// the process instead of reaching adjacent memory (design-spec §4A.4 layer 2).
///
/// Linux only: it maps a `memfd` descriptor, and neither `memfd_secret` nor
/// `memfd_create` exists off Linux. The `mlock` region maps anonymous memory
/// instead.
#[cfg(target_os = "linux")]
fn map_region(fd: libc::c_int, len: usize) -> io::Result<RawRegion> {
    let page = crate::sys::page_size();
    let data_offset = page;
    // Round the data length up so the trailing guard starts on a page boundary.
    let padded = len
        .checked_add(page - 1)
        .map(|value| value & !(page - 1))
        .unwrap_or(len);
    let total_len = padded.saturating_add(2 * page);

    // Size first: a mapping past end-of-file raises `SIGBUS` on first touch rather
    // than failing at `mmap`, so getting this order wrong crashes instead of
    // erroring.
    crate::sys::ftruncate(fd, total_len)?;

    let mapping = Mapping::new(fd, total_len, libc::PROT_READ | libc::PROT_WRITE)?;

    // Guard pages. A kernel that refuses the protection change leaves the
    // region unguarded rather than failing: the barrier is the mechanism, the
    // guard is defence in depth.
    let front = mapping.protect(0, page, libc::PROT_NONE);
    let back = mapping.protect(page + padded, page, libc::PROT_NONE);
    // A refused guard means those pages stay writable, which is weaker but not
    // unsafe; report it honestly rather than refusing to run.
    let guarded = front.is_ok() && back.is_ok();

    let dont_dump = memlock::dont_dump(&mapping, data_offset, len);

    Ok(RawRegion {
        mapping,
        data_offset,
        guarded,
        dont_dump,
    })
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn observed() -> MemlockObservation {
        MemlockObservation::read().expect("RLIMIT_MEMLOCK is readable")
    }

    /// The `mlock` region is the portable barrier, and it must be locked
    /// before it is handed back.
    ///
    /// The check is on the *refusal* path's counterpart: the region exists,
    /// it is the length that was asked for, and it reports the mechanism that
    /// produced it. A region that reported `MemfdSecret` here would be a claim
    /// about a mechanism this host does not have.
    #[test]
    fn the_mlock_region_reports_the_mechanism_that_produced_it() {
        let region =
            create_mlock_region(4096, observed()).expect("the mlock region must construct");

        assert_eq!(region.kind(), BarrierKind::Mlock);
        assert!(
            !region.kind().is_primary(),
            "mlock is not the primary barrier and must never report itself as one"
        );
        assert!(
            !region.kind().supports_sealing(),
            "mlock has no F_SEAL support"
        );
        assert_eq!(region.as_bytes().len(), 4096);
        assert!(
            region.as_bytes().iter().all(|byte| *byte == 0),
            "the region must start zeroed"
        );
    }

    /// The sealed-`memfd` fallback is unreachable through `allocate` on a host
    /// where `memfd_secret` works, so it is constructed directly here. Without
    /// this test the whole fallback is dead code in every CI run: a dropped seal,
    /// a skipped `mlock`, or a missing `MADV_DONTDUMP` would go unnoticed while
    /// the criterion-5 test kept passing by comparing enum variants.
    #[test]
    #[cfg(target_os = "linux")]
    fn the_sealed_fallback_is_constructed_sealed_locked_and_guarded() {
        let region =
            create_sealed_region(4096, observed()).expect("the sealed fallback must construct");

        assert_eq!(region.kind(), BarrierKind::SealedMemfd);
        assert!(!region.kind().is_primary());

        // The seals are the weaker mechanism's whole guarantee, so they are
        // asserted rather than assumed.
        let memfd = region
            ._file
            .as_ref()
            .expect("a sealed-memfd region must keep its file alive");
        let seals = memfd.seals().expect("the seals must be readable");
        for seal in [FileSeal::SealSeal, FileSeal::SealShrink, FileSeal::SealGrow] {
            assert!(
                seals.contains(&seal),
                "the fallback must apply {seal:?}; applied: {seals:?}"
            );
        }

        // Ordinary memory, so this region is only safe because it really is
        // locked. `memfd_secret` locks by construction; this one does not.
        assert!(
            region.is_guarded(),
            "the fallback must be bracketed by guard pages"
        );
        assert!(
            region.is_excluded_from_dumps(),
            "the fallback must be excluded from core dumps"
        );
        assert_eq!(region.as_bytes().len(), 4096);
        assert!(
            region.as_bytes().iter().all(|byte| *byte == 0),
            "the region must start zeroed"
        );
    }

    /// The fallback must fail closed. Ordinary memory that cannot be locked is
    /// exactly the silent degradation Misfit K is about, so no region may be
    /// returned.
    #[test]
    #[cfg(target_os = "linux")]
    fn the_sealed_fallback_refuses_when_it_cannot_lock() {
        // `root` holds `CAP_IPC_LOCK`, so `RLIMIT_MEMLOCK` does not bind and
        // `mlock` of 1 MiB succeeds under a 64 KiB cap. The precondition cannot
        // be established for that uid — asserting it there would assert the
        // opposite of what was measured — so this variant runs unprivileged
        // only. The refusal's wording is covered for every uid by
        // `memlock::tests::a_refusal_names_limitmemlock_and_the_observed_value`.
        // SAFETY (test-only): `geteuid` takes no arguments and touches no memory.
        #[allow(unsafe_code)]
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            return;
        }

        // Lower the limit in this process only. `mlock` of 1 MiB cannot succeed
        // under a 64 KiB cap, and nothing restores it afterwards — which is why
        // this test is the last thing this binary needs the old limit for.
        let limit = libc::rlimit {
            rlim_cur: 64 * 1024,
            rlim_max: 64 * 1024,
        };
        // SAFETY (test-only): `limit` is a fully initialized `libc::rlimit` that
        // outlives the call, and `setrlimit` only reads it.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
        assert_eq!(rc, 0, "the test must be able to lower RLIMIT_MEMLOCK");

        let observed = MemlockObservation::read().expect("the lowered limit is readable");
        match create_sealed_region(1024 * 1024, observed) {
            Err(BarrierError::NotLockable(refusal)) => {
                let remedy = refusal.remedy();
                if cfg!(target_os = "macos") {
                    assert!(
                        remedy.contains("launchctl limit memlock"),
                        "the refusal must name the knob this host has: {refusal}"
                    );
                } else if cfg!(target_os = "linux") {
                    assert!(
                        remedy.contains("LimitMEMLOCK="),
                        "the refusal must name the systemd directive: {refusal}"
                    );
                }
            }
            Err(other) => panic!("expected a lock refusal, got {other}"),
            Ok(_) => panic!("a 1 MiB region must not be returned under a 64 KiB memlock cap"),
        }
    }
}
