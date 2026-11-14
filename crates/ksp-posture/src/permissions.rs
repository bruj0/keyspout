//! Whether each protected root still carries the owner and mode it was created with.
//!
//! # Why this is a measurement and not a check
//!
//! Misfit B is that the admin ↔ user boundary *is* mode bits, and mode bits
//! drift: an inherited `umask`, an `rsync` without `-p`, a tree copied by
//! hand. Every command keeps working while the boundary is gone, so nothing
//! fails until someone reads the wrong file. The only way to notice is to
//! measure, compare, and say what was measured.
//!
//! So [`audit`] returns a [`PermissionFinding`] per root — path, expected mode,
//! actual mode, expected owner, actual owner, verdict — and a [`Verdict`] that
//! is `Missing` when there is nothing to measure. A missing root is not a
//! drifted root, and reporting one as the other would make a fresh home look
//! broken and a broken home look fresh.
//!
//! # What it refuses to do
//!
//! - It never follows a symlink. `lstat` is the measurement; a protected root
//!   that *is* a symlink is drift, because following it would measure whatever
//!   it points at and call that the root.
//! - It never judges an owner it has no record for. [`ExpectedOwner::Unrecorded`]
//!   is disclosed as such: the mode is still compared, the owner is reported and
//!   left unjudged, because guessing the owner would be a claim this crate cannot
//!   support.
//! - It changes no state. Tightening a directory someone else created would be a
//!   silent edit of a boundary the caller was not asked about, and it would hide
//!   the drift that the operator needs to see.

use std::fmt;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

/// The permission bits compared, including setuid, setgid and sticky.
///
/// A sticky bit on a shared directory is a real difference, so masking it away
/// would report two different boundaries as equal.
pub const PERMISSION_BITS: u32 = 0o7777;

/// Which kind of entry a protected root must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootKind {
    /// A directory, such as a key root or the store.
    Directory,
    /// A single file, such as the vault or the policy.
    File,
}

impl fmt::Display for RootKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Directory => "directory",
            Self::File => "file",
        })
    }
}

/// Who the layout record says should own a root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedOwner {
    /// The UNIX uid recorded when the root was created.
    Recorded(u32),
    /// No owner was recorded, so the measured owner is reported but not judged.
    Unrecorded,
}

impl fmt::Display for ExpectedOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recorded(uid) => write!(f, "uid {uid}"),
            Self::Unrecorded => f.write_str("unrecorded"),
        }
    }
}

/// The effective uid of this process.
///
/// Reported next to an owner so a caller can compare the two: a measurement that
/// says "uid 1001 owns this" answers nothing until something asks "and who am I?".
pub fn effective_uid() -> u32 {
    crate::sys::geteuid()
}

/// One root the layout expects, with the mode and owner it must carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedRoot {
    /// Where the root lives.
    pub path: PathBuf,
    /// The mode bits it was created with.
    pub mode: u32,
    /// The directory-entry kind it must be.
    pub kind: RootKind,
    /// Who should own it.
    pub owner: ExpectedOwner,
}

impl ExpectedRoot {
    /// A directory root expected at `path` with `mode`.
    pub fn directory(path: impl Into<PathBuf>, mode: u32, owner: ExpectedOwner) -> Self {
        Self {
            path: path.into(),
            mode,
            kind: RootKind::Directory,
            owner,
        }
    }

    /// A file root expected at `path` with `mode`.
    pub fn file(path: impl Into<PathBuf>, mode: u32, owner: ExpectedOwner) -> Self {
        Self {
            path: path.into(),
            mode,
            kind: RootKind::File,
            owner,
        }
    }
}

/// What the measurement concluded about one root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// The measured kind, owner and mode are the expected ones.
    Match,
    /// Nothing is at the path, so no claim is made about it.
    Missing,
    /// The root is no wider than recorded: it grants strictly less. A tighter
    /// directory is a functional problem for whoever needs to write it, never a
    /// weaker boundary, so it must not read as drift.
    Narrowed,
    /// Something is at the path and it is not the recorded root, or it is wider
    /// than recorded.
    Drift,
}

impl Verdict {
    /// Whether this verdict should stop a delivery.
    pub fn is_drift(self) -> bool {
        matches!(self, Self::Drift)
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Match => "match",
            Self::Drift => "drift",
            Self::Missing => "missing",
            Self::Narrowed => "narrowed",
        })
    }
}

/// What one root measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionFinding {
    /// The root that was measured.
    pub path: PathBuf,
    /// The mode the record expects.
    pub expected_mode: u32,
    /// The mode observed, unless the path could not be read.
    pub actual_mode: Option<u32>,
    /// The owner the record expects.
    pub expected_owner: ExpectedOwner,
    /// The owner observed, unless the path could not be read.
    pub actual_owner: Option<u32>,
    /// The entry kind the record expects.
    pub expected_kind: RootKind,
    /// The conclusion.
    pub verdict: Verdict,
}

impl PermissionFinding {
    /// The sentence a disclosure or a refusal prints.
    ///
    /// It reports a measurement. It does not say the root was attacked, because
    /// a `0775` directory is not evidence of anything except that a mode is
    /// `0775`.
    pub fn describe(&self) -> String {
        let expected = format!(
            "expected {} mode {:04o} owned by {}",
            self.expected_kind, self.expected_mode, self.expected_owner
        );
        match (self.actual_mode, self.actual_owner) {
            (Some(mode), Some(owner)) => format!(
                "{} is mode {mode:04o} owned by uid {owner}; {expected}",
                self.path.display()
            ),
            _ => format!("{} could not be measured; {expected}", self.path.display()),
        }
    }
}

/// Measure every expected root.
///
/// `lstat` only: a symlink is reported as drift rather than followed.
pub fn audit(roots: &[ExpectedRoot]) -> Vec<PermissionFinding> {
    roots.iter().map(audit_one).collect()
}

fn audit_one(root: &ExpectedRoot) -> PermissionFinding {
    match std::fs::symlink_metadata(&root.path) {
        Ok(metadata) => {
            let actual_mode = metadata.mode() & PERMISSION_BITS;
            let actual_owner = metadata.uid();
            let file_type = metadata.file_type();
            let kind_matches = match root.kind {
                RootKind::Directory => file_type.is_dir(),
                RootKind::File => file_type.is_file(),
            };
            let expected_mode = root.mode & PERMISSION_BITS;
            // Only bits the record does not grant can widen the boundary. A bit
            // the record grants and the disk withholds narrows it.
            let wider = actual_mode & !expected_mode != 0;
            let narrower = expected_mode & !actual_mode != 0;
            let owner_matches = match root.owner {
                ExpectedOwner::Recorded(uid) => actual_owner == uid,
                // Judging an owner nobody recorded would be a guess. The mode is
                // still compared, so a widened root is still drift.
                ExpectedOwner::Unrecorded => true,
            };
            // `is_dir` and `is_file` are both false for a symlink, so a symlink
            // fails `kind_matches` and is never followed.
            let verdict = if !kind_matches || wider || !owner_matches {
                Verdict::Drift
            } else if narrower {
                Verdict::Narrowed
            } else {
                Verdict::Match
            };
            PermissionFinding {
                path: root.path.clone(),
                expected_mode: root.mode,
                actual_mode: Some(actual_mode),
                expected_owner: root.owner,
                actual_owner: Some(actual_owner),
                expected_kind: root.kind,
                verdict,
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => PermissionFinding {
            path: root.path.clone(),
            expected_mode: root.mode,
            actual_mode: None,
            expected_owner: root.owner,
            actual_owner: None,
            expected_kind: root.kind,
            verdict: Verdict::Missing,
        },
        // Present but unreadable is not absent and is not a match: the only
        // honest verdict is that it is not the root the record describes.
        Err(_) => PermissionFinding {
            path: root.path.clone(),
            expected_mode: root.mode,
            actual_mode: None,
            expected_owner: root.owner,
            actual_owner: None,
            expected_kind: root.kind,
            verdict: Verdict::Drift,
        },
    }
}

/// Whether any finding is drift, and the first one, for a refusal that names it.
pub fn first_drift(findings: &[PermissionFinding]) -> Option<&PermissionFinding> {
    findings.iter().find(|finding| finding.verdict.is_drift())
}

/// The roots that drifted, in the order they were measured.
pub fn drifted(findings: &[PermissionFinding]) -> impl Iterator<Item = &PermissionFinding> {
    findings.iter().filter(|finding| finding.verdict.is_drift())
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::*;

    fn dir_with_mode(dir: &Path, name: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn owner_uid() -> u32 {
        // The test process owns what it created, so this is the recorded owner
        // that must match without needing `chown`.
        std::fs::metadata(".").unwrap().uid()
    }

    #[test]
    fn a_root_with_the_recorded_mode_and_owner_matches() {
        let temp = tempfile::tempdir().unwrap();
        let path = dir_with_mode(temp.path(), "admin", 0o700);
        let finding = audit_one(&ExpectedRoot::directory(
            &path,
            0o700,
            ExpectedOwner::Recorded(owner_uid()),
        ));

        assert_eq!(finding.verdict, Verdict::Match);
        assert_eq!(finding.actual_mode, Some(0o700));
        assert_eq!(finding.actual_owner, Some(owner_uid()));
    }

    #[test]
    fn a_widened_mode_is_drift() {
        // Misfit B: the observed `0775` on `store/` and `enrolments/`. A group
        // bit hands the admin level to the user's group and nothing else fails.
        let temp = tempfile::tempdir().unwrap();
        let path = dir_with_mode(temp.path(), "store", 0o775);
        let finding = audit_one(&ExpectedRoot::directory(
            &path,
            0o755,
            ExpectedOwner::Unrecorded,
        ));

        assert_eq!(finding.verdict, Verdict::Drift);
        assert_eq!(finding.actual_mode, Some(0o775));
        assert!(finding.describe().contains("0775"));
        assert!(finding.describe().contains("0755"));
    }

    #[test]
    fn a_narrower_root_is_not_drift() {
        // `0700` where the table says `0755` grants less than recorded. It breaks
        // whoever needed to read the directory; it does not widen the boundary,
        // and refusing a delivery for it would be a false alarm.
        let temp = tempfile::tempdir().unwrap();
        let path = dir_with_mode(temp.path(), "enrolments", 0o700);
        let finding = audit_one(&ExpectedRoot::directory(
            &path,
            0o755,
            ExpectedOwner::Unrecorded,
        ));

        assert_eq!(finding.verdict, Verdict::Narrowed);
        assert!(!finding.verdict.is_drift());
    }

    #[test]
    fn a_root_owned_by_another_uid_is_drift() {
        let temp = tempfile::tempdir().unwrap();
        let path = dir_with_mode(temp.path(), "admin", 0o700);
        let somebody_else = ExpectedOwner::Recorded(owner_uid().wrapping_add(1));
        let finding = audit_one(&ExpectedRoot::directory(&path, 0o700, somebody_else));

        assert_eq!(finding.verdict, Verdict::Drift);
        assert!(finding.describe().contains("owned by uid"));
    }

    #[test]
    fn an_unrecorded_owner_is_reported_and_not_judged() {
        let temp = tempfile::tempdir().unwrap();
        let path = dir_with_mode(temp.path(), "enrolments", 0o755);
        let finding = audit_one(&ExpectedRoot::directory(
            &path,
            0o755,
            ExpectedOwner::Unrecorded,
        ));

        // Not judging the owner must not be the same as not reporting it.
        assert_eq!(finding.verdict, Verdict::Match);
        assert_eq!(finding.actual_owner, Some(owner_uid()));
        assert_eq!(finding.expected_owner, ExpectedOwner::Unrecorded);
    }

    #[test]
    fn an_absent_root_is_missing_and_not_drift() {
        // A fresh home has no `vault.cbor` yet. Calling that drift would refuse
        // the very command that is about to create it.
        let temp = tempfile::tempdir().unwrap();
        let finding = audit_one(&ExpectedRoot::file(
            temp.path().join("vault.cbor"),
            0o600,
            ExpectedOwner::Unrecorded,
        ));

        assert_eq!(finding.verdict, Verdict::Missing);
        assert_eq!(finding.actual_mode, None);
        assert!(!finding.verdict.is_drift());
    }

    #[test]
    fn a_symlink_at_a_protected_root_is_drift_even_when_its_target_matches() {
        // Following the link would measure whatever it points at and call that
        // the root, which is how a replaced root passes an audit.
        let temp = tempfile::tempdir().unwrap();
        let real = dir_with_mode(temp.path(), "real", 0o700);
        let link = temp.path().join("admin");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let finding = audit_one(&ExpectedRoot::directory(
            &link,
            0o700,
            ExpectedOwner::Unrecorded,
        ));
        assert_eq!(finding.verdict, Verdict::Drift);
    }

    #[test]
    fn a_directory_where_a_file_is_recorded_is_drift() {
        // 0700 on a directory and 0700 on a file are different boundaries; the
        // mode alone cannot tell them apart.
        let temp = tempfile::tempdir().unwrap();
        let path = dir_with_mode(temp.path(), "vault.cbor", 0o700);
        let finding = audit_one(&ExpectedRoot::file(&path, 0o700, ExpectedOwner::Unrecorded));

        assert_eq!(finding.verdict, Verdict::Drift);
    }

    #[test]
    fn the_first_drift_names_the_root_a_refusal_prints() {
        let temp = tempfile::tempdir().unwrap();
        let good = dir_with_mode(temp.path(), "agent", 0o700);
        let bad = dir_with_mode(temp.path(), "admin", 0o775);
        let findings = audit(&[
            ExpectedRoot::directory(&good, 0o700, ExpectedOwner::Unrecorded),
            ExpectedRoot::directory(&bad, 0o700, ExpectedOwner::Unrecorded),
        ]);

        assert_eq!(drifted(&findings).count(), 1);
        let first = first_drift(&findings).unwrap();
        assert_eq!(first.path, bad);
    }
}
