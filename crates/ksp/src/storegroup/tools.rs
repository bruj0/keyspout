//! The argv and the output parsing the store-group step needs, per platform.
//!
//! Kept free of `cfg` on purpose. The two platforms resolve a gid and add a
//! member differently, and a branch selected at compile time can only be tested
//! on the host that compiles it. Everything here is a pure function of text, so
//! a Linux host exercises the Darwin parser from a captured fixture and the
//! reverse. The spawns live in `linux.rs` and `darwin.rs`.
//!
//! The tool paths are absolute because the step runs under `sudo`, where `PATH`
//! is the operator's and not this program's.
//!
//! Half of this module is unused on any single host: `getent` and `usermod` are
//! named on Linux, `dscacheutil` and `dseditgroup` on Darwin. That is the trade
//! this module exists to make — the unused half is what the other platform's
//! tests run against — so the dead-code lint is turned off here rather than
//! letting a `cfg` gate hide the portability tests from the host that has CI.
#![allow(dead_code)]

use std::fmt::Write as _;

/// The Linux gid-to-name tool.
pub(super) const GETENT: &str = "/usr/bin/getent";
/// The Linux group-membership tool.
pub(super) const USERMOD: &str = "/usr/sbin/usermod";
/// The Darwin gid-to-name tool.
pub(super) const DSCACHEUTIL: &str = "/usr/bin/dscacheutil";
/// The Darwin group-membership tool.
pub(super) const DSEDITGROUP: &str = "/usr/sbin/dseditgroup";

/// What `dseditgroup -o checkmember` exits with when the account is not a member.
///
/// Measured on Darwin: a member exits `0` with `yes <account> is a member of
/// <group>`, a non-member exits **`67`** with `no <account> is NOT a member of
/// <group>`. `67` is an answer, not a failure — treating it as a failure would
/// refuse the binding on every host where the account is not yet a member, which
/// is every first run.
pub(super) const NOT_A_MEMBER: i32 = 67;

/// What a `checkmember` exit status means for the membership step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Membership {
    /// The account is already in the group, so the step has nothing to do.
    AlreadyMember,
    /// The account is not in the group: the edit is the next step.
    NotAMember,
    /// The tool could not answer, which is neither of the two above.
    ///
    /// Measured: a group that does not exist and a user record that does not
    /// exist both exit **`64`**, not `67`. Folding that into a privilege
    /// refusal would tell an operator to run as root when the group they named
    /// is not there.
    Refused { status: Option<i32> },
}

/// Classify a `checkmember` exit status.
pub(super) fn classify_checkmember(code: Option<i32>) -> Membership {
    match code {
        Some(0) => Membership::AlreadyMember,
        Some(NOT_A_MEMBER) => Membership::NotAMember,
        other => Membership::Refused { status: other },
    }
}

/// Render an exit status for a refusal, including the case a status cannot say.
pub(super) fn describe_status(code: Option<i32>) -> String {
    match code {
        Some(status) => format!("exit {status}"),
        None => "terminated by a signal".to_string(),
    }
}

/// The first non-empty line of a tool's stderr, as a reason.
///
/// A tool's first line is what it considers the headline. Taking all of it would
/// put a usage block into a refusal, and taking none of it would discard the only
/// thing the tool said.
pub(super) fn first_line(stderr: &[u8]) -> Option<String> {
    String::from_utf8_lossy(stderr)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

/// The argv that asks `getent` for one gid.
pub(super) fn getent_argv(gid: u32) -> Vec<String> {
    vec!["group".to_string(), gid.to_string()]
}

/// The group name in `getent group <gid>` output.
///
/// The line is colon-separated and the name is the first field. An empty or
/// unparsable answer is `None`: a caller that treated it as a name would ask the
/// next tool to add an account to a group called `""`.
pub(super) fn getent_group_name(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .next()
        .and_then(|line| line.split(':').next())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

/// The argv that asks `dscacheutil` for one gid.
pub(super) fn dscacheutil_argv(gid: u32) -> Vec<String> {
    vec![
        "-q".to_string(),
        "group".to_string(),
        "-a".to_string(),
        "gid".to_string(),
        gid.to_string(),
    ]
}

/// The group name in `dscacheutil -q group -a gid` output.
///
/// The answer is a block of `key: value` lines and the name is `name: <group>`.
/// An unknown gid prints **nothing and exits `0`**, measured on this host, so
/// the empty answer is detected here rather than from an exit status.
pub(super) fn dscacheutil_group_name(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        line.strip_prefix("name:")
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
    })
}

/// The Linux argv that adds one account to one group.
pub(super) fn usermod_argv(account: &str, group: &str) -> Vec<String> {
    vec![
        "-a".to_string(),
        "-G".to_string(),
        group.to_string(),
        account.to_string(),
    ]
}

/// The Darwin argv that adds one account to one group.
pub(super) fn dseditgroup_add_argv(account: &str, group: &str) -> Vec<String> {
    vec![
        "-o".to_string(),
        "edit".to_string(),
        "-a".to_string(),
        account.to_string(),
        "-t".to_string(),
        "user".to_string(),
        group.to_string(),
    ]
}

/// The Darwin argv that asks whether one account is already a member.
pub(super) fn dseditgroup_checkmember_argv(account: &str, group: &str) -> Vec<String> {
    vec![
        "-o".to_string(),
        "checkmember".to_string(),
        "-m".to_string(),
        account.to_string(),
        group.to_string(),
    ]
}

/// Render an argv for a refusal, so the operator can run it themselves.
///
/// Only ever rendered for a refusal: the arguments are an account name and a
/// group name, never a secret. Quoting is applied so the line can be pasted into
/// a shell as-is.
pub(super) fn render(tool: &str, argv: &[String]) -> String {
    let mut line = tool.to_string();
    for argument in argv {
        let quoted = if argument
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c))
        {
            argument.clone()
        } else {
            format!("'{}'", argument.replace('\'', r#"'\''"#))
        };
        let _ = write!(line, " {quoted}");
    }
    line
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// Captured from `dscacheutil -q group -a gid 20` on this host.
    const DSCACHEUTIL_STAFF: &str = "name: staff\npassword: *\ngid: 20\nusers: root \n";
    /// Captured from `getent group 20` on a Linux host.
    const GETENT_STAFF: &str = "staff:x:20:\n";

    #[test]
    fn the_darwin_argv_names_the_darwin_tools() {
        let argv = dseditgroup_add_argv("alice", "ksp-store");
        assert_eq!(
            argv,
            vec!["-o", "edit", "-a", "alice", "-t", "user", "ksp-store"]
        );
        let rendered = render(DSEDITGROUP, &argv);
        assert!(
            rendered.starts_with("/usr/sbin/dseditgroup"),
            "the Darwin step must name dseditgroup, got {rendered:?}"
        );
        assert!(
            !rendered.contains("usermod"),
            "a Darwin host has no usermod, got {rendered:?}"
        );
    }

    #[test]
    fn the_linux_argv_is_unchanged() {
        assert_eq!(
            usermod_argv("alice", "ksp-store"),
            vec!["-a", "-G", "ksp-store", "alice"]
        );
        assert_eq!(getent_argv(20), vec!["group", "20"]);
    }

    #[test]
    fn the_darwin_membership_check_asks_about_the_account_and_the_group() {
        assert_eq!(
            dseditgroup_checkmember_argv("alice", "ksp-store"),
            vec!["-o", "checkmember", "-m", "alice", "ksp-store"]
        );
    }

    #[test]
    fn a_darwin_block_is_read_for_its_name() {
        assert_eq!(
            dscacheutil_group_name(DSCACHEUTIL_STAFF),
            Some("staff".to_string())
        );
    }

    #[test]
    fn a_linux_line_is_read_for_its_name() {
        assert_eq!(getent_group_name(GETENT_STAFF), Some("staff".to_string()));
    }

    /// An unknown gid is empty output and exit `0` on Darwin. The empty answer
    /// has to be a refusal here, because nothing downstream can tell it from a
    /// group whose name is the empty string.
    #[test]
    fn an_unknown_gid_is_no_name_on_either_platform() {
        assert_eq!(dscacheutil_group_name(""), None);
        assert_eq!(dscacheutil_group_name("\n"), None);
        assert_eq!(dscacheutil_group_name("password: *\ngid: 54321\n"), None);
        assert_eq!(dscacheutil_group_name("name:   \n"), None);
        assert_eq!(getent_group_name(""), None);
        assert_eq!(getent_group_name(":x:54321:\n"), None);
    }

    #[test]
    fn a_membership_check_has_three_outcomes_and_a_missing_group_is_not_privilege() {
        assert_eq!(classify_checkmember(Some(0)), Membership::AlreadyMember);
        assert_eq!(
            classify_checkmember(Some(NOT_A_MEMBER)),
            Membership::NotAMember
        );
        // Measured: a group that does not exist, and a user record that does not
        // exist, both exit 64. Reporting that as "run as root" sends the operator
        // to fix a privilege that is not the problem.
        assert_eq!(
            classify_checkmember(Some(64)),
            Membership::Refused { status: Some(64) }
        );
        assert_eq!(
            classify_checkmember(None),
            Membership::Refused { status: None }
        );
        assert_eq!(describe_status(Some(64)), "exit 64");
        assert_eq!(describe_status(None), "terminated by a signal");
    }

    #[test]
    fn a_refusal_can_be_pasted_into_a_shell() {
        let rendered = render(USERMOD, &usermod_argv("a b", "g"));
        assert_eq!(rendered, "/usr/sbin/usermod -a -G g 'a b'");
    }
}
