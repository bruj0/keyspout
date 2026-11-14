//! The Linux store-group step: `getent` to resolve, `usermod` to add.

use super::tools;
use crate::admin::AdminError;

/// The group name `getent group <gid>` reports.
///
/// A spawn failure is a host that lacks the tool, which is a different finding
/// from a gid with no group: the first is an environment the operator can fix by
/// installing shadow-utils, the second is a store root owned by a group that no
/// longer exists.
pub(super) fn resolve(gid: u32, account: &str) -> Result<String, AdminError> {
    let argv = tools::getent_argv(gid);
    let output = std::process::Command::new(tools::GETENT)
        .args(&argv)
        .output()
        .map_err(|error| AdminError::GroupTool {
            tool: tools::GETENT,
            command: tools::render(tools::GETENT, &argv),
            reason: error.to_string(),
        })?;

    if !output.status.success() {
        return Err(AdminError::GroupUnreadable {
            gid,
            account: account.to_string(),
            tool: tools::GETENT,
            reason: tools::first_line(&output.stderr).unwrap_or_else(|| {
                format!(
                    "it printed no name ({})",
                    tools::describe_status(output.status.code())
                )
            }),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    tools::getent_group_name(&stdout).ok_or_else(|| AdminError::GroupUnreadable {
        gid,
        account: account.to_string(),
        tool: tools::GETENT,
        reason: "it printed no group name for this gid".to_string(),
    })
}

/// Add `account` to `group`.
///
/// `usermod` reports "no changes" as success, so re-running provisioning is
/// safe. A non-zero exit is a binding this host could not make, which needs the
/// privilege the refused sentence names.
pub(super) fn join(account: &str, group: &str) -> Result<(), AdminError> {
    let argv = tools::usermod_argv(account, group);
    let status = std::process::Command::new(tools::USERMOD)
        .args(&argv)
        .status()
        .map_err(|error| AdminError::MembershipTool {
            tool: tools::USERMOD,
            command: tools::render(tools::USERMOD, &argv),
            reason: error.to_string(),
            account: account.to_string(),
        })?;

    if !status.success() {
        return Err(AdminError::GroupJoin {
            account: account.to_string(),
            group: group.to_string(),
            tool: tools::USERMOD,
        });
    }
    Ok(())
}
