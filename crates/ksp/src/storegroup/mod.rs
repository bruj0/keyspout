//! The store-group step: resolve the gid that owns the store to a group name,
//! and add the bound account to it.
//!
//! The step exists because the agent level needs a group both accounts share,
//! and a group is a host object with host tools. Linux answers with `getent` and
//! edits with `usermod`; Darwin answers with `dscacheutil` and edits with
//! `dseditgroup`. The platform selection happens here, once, at compile time;
//! the argv and the parsing are pure functions in [`tools`] so that each
//! platform's logic is tested on either host.
//!
//! Every failure names the operation and the tool that was run. An operator who
//! reads "this host could not answer whether there is a UNIX account named X"
//! when the missing thing is a group tool will check an account that exists.

mod tools;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as host;

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
use darwin as host;

// The crate targets Linux and macOS. A third target would compile a module with
// no `host` at all, and the error it produced would name an import rather than
// the missing portability work.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("the store-group step has no implementation for this target");

use crate::admin::AdminError;
use crate::config::Layout;
use std::os::unix::fs::MetadataExt;

/// The group name that owns this host's store root.
///
/// The gid comes from the store root itself rather than from configuration: a
/// group recorded in a file can disagree with the directory the records are
/// written under, and the directory is what the kernel enforces.
pub(crate) fn resolve(layout: &Layout, account: &str) -> Result<String, AdminError> {
    let root = layout.store_root();
    let gid = std::fs::metadata(&root)
        .map_err(|error| AdminError::StoreRootUnreadable {
            path: root.display().to_string(),
            reason: error.to_string(),
        })?
        .gid();
    host::resolve(gid, account)
}

/// Add `account` to `group`, idempotently.
///
/// Both tools report "already a member" as an answer, so a second provisioning
/// run is safe. A real failure is a binding this host could not make.
pub(crate) fn join(account: &str, group: &str) -> Result<(), AdminError> {
    host::join(account, group)
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::resolve;
    use super::tools;

    /// The one thing this module must not do is name a tool the host lacks.
    ///
    /// Both paths are absolute because the step runs under `sudo`, where `PATH`
    /// belongs to the operator. A typo in one of them is not a portability bug
    /// the type system can catch: it is an `ENOENT` at the last step of a
    /// provisioning run, which is the defect this module was written to remove.
    #[test]
    fn the_host_tools_exist_at_their_absolute_paths() {
        let host_tools: &[&str] = if cfg!(target_os = "macos") {
            &[tools::DSCACHEUTIL, tools::DSEDITGROUP]
        } else {
            &[tools::GETENT, tools::USERMOD]
        };
        let absent: Vec<&str> = host_tools
            .iter()
            .copied()
            .filter(|path| !std::path::Path::new(path).exists())
            .collect();
        assert!(
            absent.is_empty(),
            "the host platform's tools were expected at these paths: {absent:?}"
        );
    }

    /// The parser tests prove the shapes; this one proves the spawn.
    ///
    /// A wrong absolute path or a wrong argv shape is invisible to a pure test,
    /// and it is exactly the failure the old inline code had. This calls the real
    /// host tool against a real directory, which needs no root.
    #[test]
    fn the_host_resolves_a_real_store_root_to_a_real_group_name() {
        let dir = tempfile::tempdir().expect("a temporary home");
        let layout = crate::config::Layout::new(dir.path());
        std::fs::create_dir_all(layout.store_root()).expect("a store root");

        let name = resolve(&layout, "some-account").expect("this host resolves its own store root");
        assert!(
            !name.is_empty(),
            "a resolved group name is never empty; an empty one would be used as a group"
        );
    }

    /// A store root that is not there is not a failed write.
    #[test]
    fn a_missing_store_root_is_named_rather_than_reported_as_a_write() {
        let dir = tempfile::tempdir().expect("a temporary home");
        let layout = crate::config::Layout::new(dir.path().join("absent"));

        match resolve(&layout, "some-account") {
            Err(crate::admin::AdminError::StoreRootUnreadable { path, reason }) => {
                assert!(
                    path.ends_with("store"),
                    "the refusal names the root: {path}"
                );
                assert!(
                    !reason.is_empty(),
                    "the refusal carries the filesystem's words"
                );
            }
            other => panic!("a store root that is absent is not a write failure: {other:?}"),
        }
    }
}
