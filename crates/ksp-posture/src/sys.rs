//! The one module in the workspace that may write `unsafe`.
//!
//! `libc` exposes the `memfd_secret(2)` **syscall number** and no wrapper
//! function, and glibc has no wrapper either (plan R3). Calling it therefore
//! requires `unsafe`. The workspace sets `unsafe_code = "deny"`, which an
//! inner `#[allow]` can lift — unlike `forbid` — so the exemption is taken
//! here and nowhere else.
//!
//! Every block below carries a `// SAFETY:` comment naming the invariant it
//! relies on. Nothing in this module interprets mapped memory as a Rust value
//! of a secret type: a [`Mapping`] owns an address and a length, and every
//! reference it hands out borrows the `Mapping` itself.

// SAFETY: this module's whole purpose is the syscall boundary. The exemption
// is scoped here so no other module in the workspace can write `unsafe`.
#![allow(unsafe_code)]

use std::io;

/// `memfd_secret(2)` — create a secret memory file descriptor.
///
/// The kernel accepts exactly one flag, `O_CLOEXEC`. `MFD_CLOEXEC` is `0x0001`
/// and is **not** a `memfd_secret` flag; passing it yields `EINVAL` on an
/// otherwise working kernel (DEVELOPMENT.md §7.1, measured):
///
/// | call | result |
/// |---|---|
/// | `memfd_secret(O_CLOEXEC)` | `fd`, `FD_CLOEXEC` set |
/// | `memfd_secret(MFD_CLOEXEC)` | `-1`, `EINVAL` |
///
/// The distinction matters more than it looks: `EINVAL` means *this kernel
/// rejects the flag* — a programming error — while `ENOSYS` means the
/// mechanism is absent and the sealed-`memfd` fallback is the honest answer.
/// Conflating them would silently demote a working barrier everywhere.
///
/// The kernel signature is `memfd_secret(unsigned int flags)`; it takes **no**
/// name.
/// `geteuid(2)` — the effective uid of this process.
///
/// The other half of an ownership comparison: `stat` says who owns a root, and
/// this says who is asking. `std` has no API for it, so it lives beside the
/// syscall boundary rather than being re-derived with an `unsafe` block in every
/// caller.
pub(crate) fn geteuid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
    unsafe { libc::geteuid() }
}

/// `getegid(2)` — the effective group of this process.
///
/// The group half of the same ownership question. A directory created by this
/// process inherits the *parent's* group, which is a property of where the
/// directory happens to live; this is the group the process is certain to belong
/// to. A store that has to be shared between two accounts needs the second, not
/// the first.
pub(crate) fn getegid() -> u32 {
    // SAFETY: `getegid` takes no arguments, touches no memory and cannot fail.
    unsafe { libc::getegid() }
}

/// `memfd_secret(2)` — Linux only.
///
/// The syscall number does not exist in Darwin's libc, so the function is
/// gated rather than stubbed: a host with no `memfd_secret` has no way to
/// create one, and a stub that returned an error would be indistinguishable
/// from a kernel that declined the flags. The *adapter* reports the absence;
/// the syscall layer simply does not exist there.
#[cfg(target_os = "linux")]
pub(crate) fn memfd_secret(flags: libc::c_int) -> io::Result<libc::c_int> {
    // SAFETY: `syscall` is variadic and only reads its arguments. The syscall
    // number comes from `libc`, the only argument is a `c_int` passed by
    // value, and no pointer is involved, so no Rust memory is borrowed or
    // aliased across the call. The return is a `c_long` the syscall ABI defines
    // as an fd or a negated errno, which is what `last_os_error` reads.
    let fd = unsafe { libc::syscall(libc::SYS_memfd_secret, flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd as libc::c_int)
}

/// `prctl(2)` with one integer argument — enough for `PR_SET_DUMPABLE`.
///
/// Linux only: Darwin has no `prctl`, so it refuses a debugger attach through
/// [`deny_ptrace_attach`] instead. Neither target is left without a way to say
/// "not dumpable"; the two ask different kernels.
#[cfg(target_os = "linux")]
pub(crate) fn prctl(option: libc::c_int, arg2: libc::c_ulong) -> io::Result<()> {
    // SAFETY: `prctl` is variadic and reads only the arguments given. All are
    // plain integers; no pointer, borrow or ownership crosses the boundary.
    let rc = unsafe {
        libc::prctl(
            option,
            arg2,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The Landlock ABI the running kernel implements, or `None` when it has none.
///
/// `landlock` 0.4.7 keeps its own ABI detection private, so the only way to
/// learn the number without building a ruleset is the documented
/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` query:
/// with `attr_size == 0` and the version flag the call reads no memory at all
/// and returns the highest ABI the kernel implements.
///
/// The answer is used only to *describe* a refusal. It never decides whether a
/// right is enforced — `restrict_self()` reports that, and a claim derived from
/// this number would be a guess where the kernel already gives an answer.
#[cfg(target_os = "linux")]
pub(crate) fn landlock_abi() -> Option<u32> {
    landlock_abi_linux()
}

/// The Landlock ABI the running kernel implements, or `None` when it has none.
///
/// A host that has no Landlock at all answers `None`, which is the same fact
/// the Linux version reports for a kernel without the mechanism. Keeping one
/// function with two bodies means the callers — the refusal builder and the
/// adapter's availability check — need no target-specific branch of their own,
/// and the refusal machinery behaves identically on both targets.
#[cfg(not(target_os = "linux"))]
pub(crate) fn landlock_abi() -> Option<u32> {
    // Landlock is a Linux mechanism. On any other target the answer is `None`,
    // and the syscall does not exist to ask.
    None
}

/// The Landlock ABI the running kernel implements, or `None` when it has none.
///
/// `landlock` 0.4.7 keeps its own ABI detection private, so the only way to
/// learn the number without building a ruleset is the documented
/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` query:
/// with `attr_size == 0` and the version flag the call reads no memory at all
/// and returns the highest ABI the kernel implements.
///
/// The answer is used only to *describe* a refusal. It never decides whether a
/// right is enforced — `restrict_self()` reports that, and a claim derived from
/// this number would be a guess where the kernel already gives an answer.
#[cfg(target_os = "linux")]
fn landlock_abi_linux() -> Option<u32> {
    // Not exported by `libc`: `include/uapi/linux/landlock.h` defines it as the
    // single acceptable flag of the version query.
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;

    // SAFETY: the version query writes nothing. `attr` is null and `size` is 0,
    // so the kernel dereferences neither; `flags` is a `c_uint` passed by value.
    // The syscall number comes from `libc` and the return value is an `i` that
    // is only compared and cast.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0 as libc::size_t,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };

    // `ENOSYS` (no Landlock), `EOPNOTSUPP` (compiled out or disabled at boot)
    // and `EINVAL` (a kernel older than the version flag itself) all mean the
    // same thing to a caller: the mechanism cannot be established here.
    (rc > 0).then_some(rc as u32)
}

/// `getrlimit(2)` for `RLIMIT_MEMLOCK`, as `(soft, hard)` with `None` meaning
/// "unbounded".
pub(crate) fn memlock_limit() -> io::Result<(Option<u64>, Option<u64>)> {
    let mut raw = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `raw` is a live, fully initialized `libc::rlimit`, and the call
    // writes exactly one `libc::rlimit` through the pointer. The pointer comes
    // from `&mut raw`, so it is valid, aligned and unique for the call.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut raw) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((to_bytes(raw.rlim_cur), to_bytes(raw.rlim_max)))
}

/// `RLIM_INFINITY` is the maximum representable value; report it as unbounded
/// rather than as a byte count the operator cannot usefully read.
fn to_bytes(value: libc::rlim_t) -> Option<u64> {
    if value == libc::RLIM_INFINITY {
        None
    } else {
        Some(value)
    }
}

/// `setrlimit(2)` for `RLIMIT_CORE`, set to zero.
///
/// This is the control both targets have. `RLIMIT_CORE` decides whether the
/// kernel writes a core file when the process takes a fatal signal, and that is
/// independent of the attach path: no debugger is needed to dump a process that
/// crashes while holding a passphrase.
///
/// Both the soft and the hard limit go to zero. The hard limit is what stops
/// this process — or a library it calls later — from raising the soft limit
/// back, so the control holds by construction rather than by convention. A
/// limit that is already zero is a success here: the control is in force, and
/// reporting "already zero" as a failure would refuse a host that is protected.
pub(crate) fn exclude_core_dumps() -> io::Result<()> {
    let raw = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `raw` is a live, fully initialized `libc::rlimit` and `setrlimit`
    // reads exactly one through the pointer. The pointer comes from `raw`, is
    // valid and aligned for the call, and nothing borrows it afterwards.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `ptrace(2)` with `PT_DENY_ATTACH` — Darwin's refusal of a debugging attach.
///
/// The kernel takes no pointer for this request: `pid`, `addr` and `data` are
/// ignored, and zero is what Apple's own documented call passes for all three.
/// The refusal is permanent for the calling process. No call reverses it and no
/// query reports whether it is in force, so the return value of this call is
/// the only honest source for "it applied".
#[cfg(target_os = "macos")]
pub(crate) fn deny_ptrace_attach() -> io::Result<()> {
    // SAFETY: `PT_DENY_ATTACH` dereferences no memory. The null `addr` is what
    // the request expects — the kernel ignores it — so nothing is borrowed
    // across the boundary and no pointer is followed.
    let rc = unsafe {
        libc::ptrace(
            libc::PT_DENY_ATTACH,
            0,
            std::ptr::null_mut::<libc::c_char>(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `close(2)` for descriptor sanitation and for dropping `memfd_secret` fds.
///
/// Only ever called on descriptors this process owns. `EBADF` means another
/// closer won a race, which is the desired end state either way; the caller
/// decides whether that is worth reporting.
pub(crate) fn close(fd: libc::c_int) -> io::Result<()> {
    // SAFETY: `fd` is a descriptor the caller enumerated as open and owns. The
    // call transfers no Rust memory; the only invariant is that no code path
    // uses the number afterwards, which the caller guarantees by discarding
    // the number from its table.
    let rc = unsafe { libc::close(fd) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `ftruncate(2)` — size a `memfd`/`memfd_secret` file.
///
/// Required before mapping: a mapping beyond end-of-file faults with `SIGBUS` on
/// first access, not with an `EINVAL` at `mmap` time, so the size must be set
/// first.
///
/// Linux only: it sizes a `memfd` descriptor, and neither `memfd_secret` nor
/// `memfd_create` exists off Linux.
#[cfg(target_os = "linux")]
pub(crate) fn ftruncate(fd: libc::c_int, len: usize) -> io::Result<()> {
    // SAFETY: `fd` is a live descriptor the caller owns and `len` is a plain
    // integer. `ftruncate` only changes the file's size; it reads no Rust memory.
    let rc = unsafe { libc::ftruncate(fd, len as libc::off_t) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `fcntl(fd, F_GETFD)` — whether the descriptor is open at all.
pub(crate) fn fcntl_getfd(fd: libc::c_int) -> io::Result<libc::c_int> {
    // SAFETY: `F_GETFD` takes no pointer argument, so `fcntl` reads only the
    // descriptor number and the command from the registers. No Rust value
    // crosses the boundary.
    let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc)
}

/// The system page size.
pub(crate) fn page_size() -> usize {
    // SAFETY: `sysconf` takes a constant selector and no pointer; it reads no
    // Rust memory.
    let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if raw > 0 { raw as usize } else { 4096 }
}

/// An owned `mmap` reservation.
///
/// The reservation is invisible to Rust's borrow checker by construction: the
/// struct owns the address, and every slice it hands out borrows the struct.
/// Unmapping happens exactly once, in `Drop`, after the last borrow ends.
pub(crate) struct Mapping {
    base: *mut libc::c_void,
    len: usize,
}

// SAFETY: `Mapping` owns its reservation exclusively — no other value holds the
// address or the length — and the slices it produces are bounded by borrows of
// `self`. Sending the owner to another thread moves the only handle, which is
// exactly the guarantee `Send` needs. `Sync` is deliberately not implemented:
// the barrier code that owns a `Mapping` is single-threaded by design.
unsafe impl Send for Mapping {}

impl Mapping {
    /// Reserves `len` bytes of **anonymous** memory with `protection`.
    ///
    /// `MAP_ANONYMOUS` exists on every target this crate builds for — Linux
    /// and Darwin alike — so this constructor is not gated. It is what the
    /// `mlock` adapter maps: the pages need to be locked, and a `memfd`
    /// descriptor is not needed for that.
    pub(crate) fn anonymous(len: usize, protection: libc::c_int) -> io::Result<Self> {
        // SAFETY: the call takes a length and a protection mask by value and
        // returns an address. No Rust memory is borrowed or aliased across the
        // boundary, and the returned reservation is owned by the `Mapping` this
        // function returns and unmapped exactly once in `Drop`. The `fd` of -1
        // with `MAP_ANONYMOUS` is the documented way to ask for anonymous
        // memory.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                protection,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { base, len })
    }

    /// Reserves `len` bytes with `protection`, backed by `fd` with
    /// `MAP_SHARED`, which both `memfd_secret` and a sealed `memfd` require.
    ///
    /// Linux only: it maps a `memfd` descriptor. The `mlock` region maps
    /// anonymous memory through [`Self::anonymous`] instead.
    #[cfg(target_os = "linux")]
    pub(crate) fn new(fd: libc::c_int, len: usize, protection: libc::c_int) -> io::Result<Self> {
        // SAFETY: `fd` is a live descriptor supplied by the caller and lives for
        // the duration of the call. The returned address is owned by the
        // `Mapping` this function returns and is unmapped once in `Drop`.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                protection,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { base, len })
    }

    /// Checks that `offset..offset+len` stays inside this reservation.
    fn check(&self, offset: usize, len: usize) -> io::Result<()> {
        offset
            .checked_add(len)
            .filter(|end| *end <= self.len)
            .map(|_| ())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))
    }

    /// Changes the protection of `len` bytes starting at `offset`.
    ///
    /// `offset` is a byte offset inside this reservation, not a pointer, so the
    /// caller cannot name memory this mapping does not own.
    pub(crate) fn protect(
        &self,
        offset: usize,
        len: usize,
        protection: libc::c_int,
    ) -> io::Result<()> {
        self.check(offset, len)?;
        // SAFETY: `offset..offset+len` was bounds-checked against `self.len`, so
        // the computed address lies inside this reservation. `mprotect` needs
        // page alignment, which the caller supplies by using `page_size`
        // multiples. It never dereferences the pointer as a Rust value.
        let rc =
            unsafe { libc::mprotect(self.base.cast::<u8>().add(offset).cast(), len, protection) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Applies `madvise` to `len` bytes starting at `offset`.
    ///
    /// Linux only: the only advice this crate applies is `MADV_DONTDUMP`,
    /// which Darwin's SDK does not have.
    #[cfg(target_os = "linux")]
    pub(crate) fn advise(&self, offset: usize, len: usize, advice: libc::c_int) -> io::Result<()> {
        self.check(offset, len)?;
        // SAFETY: the range was bounds-checked against `self.len`, so the
        // address lies inside this reservation. `madvise` only changes residency
        // advice for pages already mapped; it does not read the region as a Rust
        // value.
        let rc = unsafe { libc::madvise(self.base.cast::<u8>().add(offset).cast(), len, advice) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Locks `len` bytes starting at `offset` into memory.
    pub(crate) fn lock(&self, offset: usize, len: usize) -> io::Result<()> {
        self.check(offset, len)?;
        // SAFETY: the range was bounds-checked against `self.len`, so the
        // address lies inside this reservation. `mlock` only changes page
        // residency; it does not read the region as a Rust value.
        let rc = unsafe { libc::mlock(self.base.cast::<u8>().add(offset).cast(), len) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The bytes at `offset..offset+len`, borrowed for the mapping's life.
    pub(crate) fn slice(&self, offset: usize, len: usize) -> &[u8] {
        debug_assert!(self.check(offset, len).is_ok());
        // SAFETY: the range was checked against `self.len`, so the pointer is in
        // bounds of the allocation. The returned slice borrows `self`, so the
        // mapping cannot be unmapped while the slice is alive.
        unsafe { std::slice::from_raw_parts(self.base.cast::<u8>().add(offset), len) }
    }

    /// The bytes at `offset..offset+len`, mutably and uniquely.
    pub(crate) fn slice_mut(&mut self, offset: usize, len: usize) -> &mut [u8] {
        debug_assert!(self.check(offset, len).is_ok());
        // SAFETY: the range was checked against `self.len`, so the pointer is in
        // bounds of the allocation. The `&mut self` borrow proves the slice is
        // unique, and it cannot outlive the mapping because `Drop` takes
        // ownership back.
        unsafe { std::slice::from_raw_parts_mut(self.base.cast::<u8>().add(offset), len) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `base` and `len` are exactly the pair `mmap` produced and
        // requested, and no slice can outlive `self` because every slice borrows
        // it. Unmapping the reservation once is the whole contract.
        unsafe {
            libc::munmap(self.base, self.len);
        }
    }
}

impl std::fmt::Debug for Mapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render contents: a debug format is the easiest way to leak key
        // material into a log.
        f.debug_struct("Mapping")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}
