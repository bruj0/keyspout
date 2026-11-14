//! The mutable half of a use bound.
//!
//! # Why this is not a field the sweep rewrites
//!
//! The arm record carries the **bound** (`remaining_uses`), and it is
//! create-only: `arm_once` refuses different bytes under the same identity,
//! because an identity is an idempotency key and rewriting it would let a retry
//! silently replace the lease it was meant to repeat. That is the right rule for
//! the record and the wrong shape for a counter, which has to change on every
//! consume.
//!
//! So the counter is a separate durable file, and the arm record stays the
//! immutable statement of what the bound *was*. The sweep reads both: the record
//! says whether a bound exists, and this file says how much of it is left.
//!
//! # The directory is already reserved
//!
//! The file lives under `intents/.ksp-machinery/<identity>/uses`, which
//! `list_arms` already skips: it ignores any path containing `/` after the
//! `intents/` prefix. No listing rule changes, and no arm record is mistaken for
//! a counter.

use std::path::{Path, PathBuf};

/// The file that holds how many deliveries an arm permits.
pub const USES_FILE: &str = "uses";

/// Why a counter could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UseBoundError {
    /// The identity is not one this store may name.
    #[error("invalid operation identity")]
    InvalidIdentity,
    /// The counter could not be read or written.
    #[error("the use bound could not be read or written")]
    Io,
}

/// Where one arm's counter lives, under a store root.
///
/// One function, so the writer and every reader cannot disagree about the path.
pub fn uses_path(store_root: &Path, operation_identity: &str) -> Result<PathBuf, UseBoundError> {
    if operation_identity.is_empty()
        || operation_identity.contains('/')
        || operation_identity.contains("..")
    {
        return Err(UseBoundError::InvalidIdentity);
    }
    Ok(store_root
        .join("intents")
        .join(".ksp-machinery")
        .join(operation_identity)
        .join(USES_FILE))
}

/// Record the bound an arm was created with.
///
/// Written once, at arm time, so a later consume has something to decrement. A
/// counter that already exists is left alone: re-arming under the same identity
/// is a retry, and a retry must not restore a use.
pub fn seed(
    store_root: &Path,
    operation_identity: &str,
    remaining: u32,
) -> Result<(), UseBoundError> {
    let path = uses_path(store_root, operation_identity)?;
    if path.exists() {
        return Ok(());
    }
    let parent = path.parent().ok_or(UseBoundError::Io)?;
    std::fs::create_dir_all(parent).map_err(|_| UseBoundError::Io)?;
    write_durably(&path, remaining)
}

/// How many deliveries the arm still permits.
///
/// `None` is an arm with no bound, which is every arm written before the bound
/// existed: the record says so and there is no counter file to read.
pub fn remaining(store_root: &Path, operation_identity: &str) -> Option<u32> {
    let path = uses_path(store_root, operation_identity).ok()?;
    let text = std::fs::read_to_string(path).ok()?;
    text.trim().parse().ok()
}

/// Spend one delivery, durably, and return what is left.
///
/// The decrement happens **before** the child runs, so a crash after delivery
/// loses a use rather than restoring one. That is the safe direction: a bound
/// that can be spent twice is not a bound.
///
/// A counter already at zero is left at zero and reported as such; the caller
/// decides whether that is a refusal, and this function does not invent one.
pub fn spend(store_root: &Path, operation_identity: &str) -> Result<Option<u32>, UseBoundError> {
    let path = uses_path(store_root, operation_identity)?;
    let Some(current) = remaining(store_root, operation_identity) else {
        // No counter: an unbounded arm, and spending nothing is correct.
        return Ok(None);
    };
    let next = current.saturating_sub(1);
    write_durably(&path, next)?;
    Ok(Some(next))
}

/// Write a counter and make it durable before returning.
///
/// `sync_all` on the file, then on its directory: a counter that survived the
/// write but not the directory entry would be a use restored by a crash.
fn write_durably(path: &Path, value: u32) -> Result<(), UseBoundError> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|_| UseBoundError::Io)?;
    file.write_all(value.to_string().as_bytes())
        .map_err(|_| UseBoundError::Io)?;
    file.sync_all().map_err(|_| UseBoundError::Io)?;
    if let Some(parent) = path.parent()
        && let Ok(directory) = std::fs::File::open(parent)
    {
        let _ = directory.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn an_identity_that_could_escape_is_refused() {
        let root = Path::new("/tmp/store");
        for bad in ["", "../escape", "a/b"] {
            assert!(
                matches!(uses_path(root, bad), Err(UseBoundError::InvalidIdentity)),
                "{bad:?} must not name a path"
            );
        }
    }

    #[test]
    fn a_counter_lives_under_the_reserved_directory() {
        let path = uses_path(Path::new("/tmp/store"), "op-1").unwrap();
        assert_eq!(
            path,
            PathBuf::from("/tmp/store/intents/.ksp-machinery/op-1/uses")
        );
    }

    #[test]
    fn spending_decrements_and_stops_at_zero() {
        let dir = tempfile::tempdir().unwrap();
        seed(dir.path(), "op-1", 2).unwrap();
        assert_eq!(remaining(dir.path(), "op-1"), Some(2));

        assert_eq!(spend(dir.path(), "op-1").unwrap(), Some(1));
        assert_eq!(spend(dir.path(), "op-1").unwrap(), Some(0));
        // A third spend does not wrap: a bound that goes negative is not a bound.
        assert_eq!(spend(dir.path(), "op-1").unwrap(), Some(0));
        assert_eq!(remaining(dir.path(), "op-1"), Some(0));
    }

    #[test]
    fn seeding_twice_does_not_restore_a_spent_use() {
        let dir = tempfile::tempdir().unwrap();
        seed(dir.path(), "op-1", 1).unwrap();
        spend(dir.path(), "op-1").unwrap();
        // A retry of the same arming must not hand the use back.
        seed(dir.path(), "op-1", 1).unwrap();
        assert_eq!(remaining(dir.path(), "op-1"), Some(0));
    }

    #[test]
    fn an_unbounded_arm_has_no_counter() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(remaining(dir.path(), "op-none"), None);
        assert_eq!(
            spend(dir.path(), "op-none").unwrap(),
            None,
            "spending an unbounded arm is a no-op, not an error"
        );
    }
}
