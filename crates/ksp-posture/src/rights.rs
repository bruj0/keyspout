//! The access rights this crate asks the kernel to enforce.
//!
//! # Why this exists
//!
//! The rights a ruleset handles are `landlock::AccessFs` values, and
//! `landlock` is a Linux-only dependency (NFR-003). Two of this crate's public
//! signatures leaked the type:
//!
//! - [`crate::confinement::ConfinementRule::access_rights`]
//! - [`crate::confinement::ConfinementSpec::required_rights`]
//!
//! A public signature that names a target-gated type makes the crate a
//! target-gated type. The types below are this crate's own, so the seam stays
//! at the module boundary.
//!
//! # The two facts a right carries
//!
//! - **the name** — the kernel's `LANDLOCK_ACCESS_FS_*` without the prefix,
//!   because an operator fixes a refusal by matching it against a kernel or a
//!   container profile, and "[read file]" matches nothing;
//! - **the ABI that introduced it** — because a kernel older than the right
//!   does not enforce it, and a refusal that named the right without saying so
//!   would send the operator to the wrong fix.
//!
//! # What this does not re-implement
//!
//! The crate does not implement Landlock. On Linux the real crate builds the
//! ruleset; this module only names what was asked for and converts that to the
//! real crate's bits at exactly one place ([`to_landlock`]). A caller cannot
//! ask for a right this module does not name, because the enumeration is
//! closed and the compiler checks every match over it.

use std::fmt;

/// A Landlock filesystem access right.
///
/// The variants and their order mirror `landlock::AccessFs` in the `landlock`
/// crate, so the kernel's own numbering and this crate's numbering agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum AccessRight {
    /// `LANDLOCK_ACCESS_FS_EXECUTE`.
    Execute = 0,
    /// `LANDLOCK_ACCESS_FS_READ_FILE`.
    ReadFile = 1,
    /// `LANDLOCK_ACCESS_FS_READ_DIR`.
    ReadDir = 2,
    /// `LANDLOCK_ACCESS_FS_WRITE_FILE`.
    WriteFile = 3,
    /// `LANDLOCK_ACCESS_FS_REMOVE_DIR`.
    RemoveDir = 4,
    /// `LANDLOCK_ACCESS_FS_REMOVE_FILE`.
    RemoveFile = 5,
    /// `LANDLOCK_ACCESS_FS_MAKE_CHAR`.
    MakeChar = 6,
    /// `LANDLOCK_ACCESS_FS_MAKE_DIR`.
    MakeDir = 7,
    /// `LANDLOCK_ACCESS_FS_MAKE_REG`.
    MakeReg = 8,
    /// `LANDLOCK_ACCESS_FS_MAKE_SOCK`.
    MakeSock = 9,
    /// `LANDLOCK_ACCESS_FS_MAKE_FIFO`.
    MakeFifo = 10,
    /// `LANDLOCK_ACCESS_FS_MAKE_BLOCK`.
    MakeBlock = 11,
    /// `LANDLOCK_ACCESS_FS_MAKE_SYM`.
    MakeSym = 12,
    /// `LANDLOCK_ACCESS_FS_REFER`.
    Refer = 13,
    /// `LANDLOCK_ACCESS_FS_TRUNCATE`.
    Truncate = 14,
    /// `LANDLOCK_ACCESS_FS_IOCTL_DEV`.
    IoctlDev = 15,
    /// `LANDLOCK_ACCESS_FS_RESOLVE_UNIX`.
    ResolveUnix = 16,
}

impl AccessRight {
    /// Every right, in the order the kernel introduced them.
    pub const ALL: [AccessRight; 17] = [
        AccessRight::Execute,
        AccessRight::ReadFile,
        AccessRight::ReadDir,
        AccessRight::WriteFile,
        AccessRight::RemoveDir,
        AccessRight::RemoveFile,
        AccessRight::MakeChar,
        AccessRight::MakeDir,
        AccessRight::MakeReg,
        AccessRight::MakeSock,
        AccessRight::MakeFifo,
        AccessRight::MakeBlock,
        AccessRight::MakeSym,
        AccessRight::Refer,
        AccessRight::Truncate,
        AccessRight::IoctlDev,
        AccessRight::ResolveUnix,
    ];

    /// The kernel's own name for the right, without the prefix.
    ///
    /// The names are the kernel's rather than prose, because an operator
    /// matches a refusal against a kernel or a container profile.
    pub fn name(self) -> &'static str {
        match self {
            Self::Execute => "EXECUTE",
            Self::ReadFile => "READ_FILE",
            Self::ReadDir => "READ_DIR",
            Self::WriteFile => "WRITE_FILE",
            Self::RemoveDir => "REMOVE_DIR",
            Self::RemoveFile => "REMOVE_FILE",
            Self::MakeChar => "MAKE_CHAR",
            Self::MakeDir => "MAKE_DIR",
            Self::MakeReg => "MAKE_REG",
            Self::MakeSock => "MAKE_SOCK",
            Self::MakeFifo => "MAKE_FIFO",
            Self::MakeBlock => "MAKE_BLOCK",
            Self::MakeSym => "MAKE_SYM",
            Self::Refer => "REFER",
            Self::Truncate => "TRUNCATE",
            Self::IoctlDev => "IOCTL_DEV",
            Self::ResolveUnix => "RESOLVE_UNIX",
        }
    }

    /// The Landlock ABI that introduced this right.
    ///
    /// Copied from the `landlock` crate's own `since()` rather than derived
    /// here: the ABI is a closed enumeration whose numeric conversion that
    /// crate documents as testing-only, and a mapping built here could
    /// silently disagree with the kernel's own introduction commits.
    pub fn since(self) -> u32 {
        match self {
            Self::Execute
            | Self::ReadFile
            | Self::ReadDir
            | Self::WriteFile
            | Self::RemoveDir
            | Self::RemoveFile
            | Self::MakeChar
            | Self::MakeDir
            | Self::MakeReg
            | Self::MakeSock
            | Self::MakeFifo
            | Self::MakeBlock
            | Self::MakeSym => 1,
            Self::Refer => 2,
            Self::Truncate => 3,
            Self::IoctlDev => 5,
            Self::ResolveUnix => 9,
        }
    }
}

impl fmt::Display for AccessRight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A set of access rights.
///
/// A bit set over [`AccessRight`] rather than a `Vec`, because the set is
/// combined and compared, never enumerated in an order that matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RightSet {
    bits: u32,
}

impl RightSet {
    /// The empty set.
    pub const EMPTY: RightSet = RightSet { bits: 0 };

    /// The read rights of the ABI V1 floor.
    ///
    /// `Execute`, `ReadFile` and `ReadDir`. This is the floor rather than a
    /// later ABI because a right a later ABI introduces cannot be handled on a
    /// kernel that does not implement it.
    pub const READ_V1: RightSet = RightSet {
        bits: (1 << AccessRight::Execute as u32)
            | (1 << AccessRight::ReadFile as u32)
            | (1 << AccessRight::ReadDir as u32),
    };

    /// The write rights of the ABI V1 floor.
    ///
    /// Everything that creates, removes or modifies. `Truncate` is **not**
    /// here: it was introduced by ABI V3, and asking for it under
    /// `HardRequirement` would make the ruleset unbuildable on a kernel before
    /// Linux 6.2.
    pub const WRITE_V1: RightSet = RightSet {
        bits: (1 << AccessRight::WriteFile as u32)
            | (1 << AccessRight::RemoveDir as u32)
            | (1 << AccessRight::RemoveFile as u32)
            | (1 << AccessRight::MakeChar as u32)
            | (1 << AccessRight::MakeDir as u32)
            | (1 << AccessRight::MakeReg as u32)
            | (1 << AccessRight::MakeSock as u32)
            | (1 << AccessRight::MakeFifo as u32)
            | (1 << AccessRight::MakeBlock as u32)
            | (1 << AccessRight::MakeSym as u32),
    };

    /// The set with `right` added.
    pub fn with(self, right: AccessRight) -> Self {
        Self {
            bits: self.bits | (1 << right as u32),
        }
    }

    /// The union of two sets.
    pub fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Whether the set contains `right`.
    pub fn contains(self, right: AccessRight) -> bool {
        self.bits & (1 << right as u32) != 0
    }

    /// Whether the set is empty.
    pub fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// The rights in the set, in the order the kernel introduced them.
    pub fn iter(self) -> impl Iterator<Item = AccessRight> {
        AccessRight::ALL
            .into_iter()
            .filter(move |right| self.contains(*right))
    }
}

/// Converts the crate's rights into the `landlock` crate's bits.
///
/// The one place the two vocabularies meet. Keeping it here means a reader
/// checking the translation has one function to read, rather than a
/// conversion at every call site — and a second conversion is a second chance
/// to disagree with the first.
#[cfg(target_os = "linux")]
pub(crate) fn to_landlock(rights: RightSet) -> landlock::BitFlags<landlock::AccessFs> {
    let mut bits = landlock::BitFlags::EMPTY;
    for right in rights.iter() {
        let bit = match right {
            AccessRight::Execute => landlock::AccessFs::Execute,
            AccessRight::ReadFile => landlock::AccessFs::ReadFile,
            AccessRight::ReadDir => landlock::AccessFs::ReadDir,
            AccessRight::WriteFile => landlock::AccessFs::WriteFile,
            AccessRight::RemoveDir => landlock::AccessFs::RemoveDir,
            AccessRight::RemoveFile => landlock::AccessFs::RemoveFile,
            AccessRight::MakeChar => landlock::AccessFs::MakeChar,
            AccessRight::MakeDir => landlock::AccessFs::MakeDir,
            AccessRight::MakeReg => landlock::AccessFs::MakeReg,
            AccessRight::MakeSock => landlock::AccessFs::MakeSock,
            AccessRight::MakeFifo => landlock::AccessFs::MakeFifo,
            AccessRight::MakeBlock => landlock::AccessFs::MakeBlock,
            AccessRight::MakeSym => landlock::AccessFs::MakeSym,
            AccessRight::Refer => landlock::AccessFs::Refer,
            AccessRight::Truncate => landlock::AccessFs::Truncate,
            AccessRight::IoctlDev => landlock::AccessFs::IoctlDev,
            AccessRight::ResolveUnix => landlock::AccessFs::ResolveUnix,
        };
        bits |= bit;
    }
    bits
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_read_set_is_exactly_the_three_read_rights() {
        assert!(RightSet::READ_V1.contains(AccessRight::Execute));
        assert!(RightSet::READ_V1.contains(AccessRight::ReadFile));
        assert!(RightSet::READ_V1.contains(AccessRight::ReadDir));
        assert!(!RightSet::READ_V1.contains(AccessRight::WriteFile));
        assert!(!RightSet::READ_V1.contains(AccessRight::MakeReg));
    }

    #[test]
    fn the_write_set_excludes_truncate() {
        // `Truncate` arrived with ABI V3, and asking for it at the V1 floor
        // would make the ruleset unbuildable on a kernel before Linux 6.2.
        assert!(RightSet::WRITE_V1.contains(AccessRight::WriteFile));
        assert!(RightSet::WRITE_V1.contains(AccessRight::MakeSym));
        assert!(
            !RightSet::WRITE_V1.contains(AccessRight::Truncate),
            "TRUNCATE is ABI V3 and must not be in the V1 floor"
        );
    }

    #[test]
    fn a_union_is_the_combination_of_both_sets() {
        let both = RightSet::READ_V1.union(RightSet::WRITE_V1);
        assert!(both.contains(AccessRight::Execute));
        assert!(both.contains(AccessRight::MakeSym));
        assert!(!both.contains(AccessRight::Truncate));
        assert!(!both.contains(AccessRight::Refer));
    }

    #[test]
    fn the_rights_are_listed_in_the_order_the_kernel_introduced_them() {
        // The order is what a refusal reads out, so it must be the kernel's.
        let mut previous = 0;
        for right in AccessRight::ALL {
            assert!(
                right.since() >= previous,
                "{right} must not be introduced before the right before it"
            );
            previous = right.since();
        }
    }

    #[test]
    fn the_names_are_the_kernels_own() {
        assert_eq!(AccessRight::ReadFile.name(), "READ_FILE");
        assert_eq!(AccessRight::MakeSym.name(), "MAKE_SYM");
        assert_eq!(AccessRight::ResolveUnix.name(), "RESOLVE_UNIX");
        assert_eq!(AccessRight::Execute.to_string(), "EXECUTE");
    }
}
