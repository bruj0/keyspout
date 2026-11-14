//! The Darwin store-group step: `dscacheutil` to resolve, `dseditgroup` to add.

use super::tools;
use crate::admin::AdminError;

/// The group name `dscacheutil -q group -a gid` reports.
///
/// Two Darwin facts decide this function, both measured on a Mac:
///
/// - An **unknown gid prints nothing and exits `0`**. A check on the exit status
///   alone would accept the empty answer and hand the caller a group name of
///   `""`, which the next step would then try to use.
/// - The answer is a block of `key: value` lines, and the name is the `name:`
///   line. The `/Groups/<name>` path `dscl` prints would need a second strip for
///   no gain.
pub(super) fn resolve(gid: u32, account: &str) -> Result<String, AdminError> {
    let argv = tools::dscacheutil_argv(gid);
    let output = std::process::Command::new(tools::DSCACHEUTIL)
        .args(&argv)
        .output()
        .map_err(|error| AdminError::GroupTool {
            tool: tools::DSCACHEUTIL,
            command: tools::render(tools::DSCACHEUTIL, &argv),
            reason: error.to_string(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    tools::dscacheutil_group_name(&stdout).ok_or_else(|| AdminError::GroupUnreadable {
        gid,
        account: account.to_string(),
        tool: tools::DSCACHEUTIL,
        // The tool's own words, because an empty answer has two very different
        // causes: a gid with no group, and a tool that refused for a reason it
        // already printed.
        reason: tools::first_line(&output.stderr).unwrap_or_else(|| {
            format!(
                "it printed no name ({})",
                tools::describe_status(output.status.code())
            )
        }),
    })
}

/// Add `account` to `group`, asking first so a second run is a no-op.
///
/// `dseditgroup -o checkmember` exits `0` for a member and **`67`** for a
/// non-member, both with an answer on stdout. `67` is therefore not a failure:
/// treating it as one would refuse the binding on every host where the account is
/// is not yet a member, which is every first run.
///
/// It exits **`64`** when it cannot answer at all — measured for a group that
/// does not exist and for a user record that does not exist. That is neither
/// answer, and it is not the privilege the `-o edit` step needs either, so it
/// gets its own refusal instead of borrowing the `Binding` sentence.
pub(super) fn join(account: &str, group: &str) -> Result<(), AdminError> {
    let check = tools::dseditgroup_checkmember_argv(account, group);
    let answer = std::process::Command::new(tools::DSEDITGROUP)
        .args(&check)
        .output()
        .map_err(|error| AdminError::MembershipTool {
            tool: tools::DSEDITGROUP,
            command: tools::render(tools::DSEDITGROUP, &check),
            reason: error.to_string(),
            account: account.to_string(),
        })?;

    match tools::classify_checkmember(answer.status.code()) {
        // Already a member. Changing nothing is what makes the step idempotent.
        tools::Membership::AlreadyMember => return Ok(()),
        // Not a member: the answer this step exists to act on.
        tools::Membership::NotAMember => {}
        // Neither answer. A missing group or a missing user record lands here,
        // and so does a tool that failed for its own reason — which is not the
        // privilege the edit step needs, so it must not borrow that sentence.
        tools::Membership::Refused { status } => {
            return Err(AdminError::MembershipRefused {
                account: account.to_string(),
                group: group.to_string(),
                tool: tools::DSEDITGROUP,
                status: tools::describe_status(status),
                reason: tools::first_line(&answer.stderr).unwrap_or_default(),
            });
        }
    }

    let argv = tools::dseditgroup_add_argv(account, group);
    let status = std::process::Command::new(tools::DSEDITGROUP)
        .args(&argv)
        .status()
        .map_err(|error| AdminError::MembershipTool {
            tool: tools::DSEDITGROUP,
            command: tools::render(tools::DSEDITGROUP, &argv),
            reason: error.to_string(),
            account: account.to_string(),
        })?;

    if !status.success() {
        return Err(AdminError::GroupJoin {
            account: account.to_string(),
            group: group.to_string(),
            tool: tools::DSEDITGROUP,
        });
    }
    Ok(())
}
