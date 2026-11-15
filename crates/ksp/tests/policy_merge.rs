//! `admin policy` merges a grant instead of replacing the whole set.
//!
//! # Why this file exists
//!
//! `write_policy` built a fresh `PolicyBody` from the flags on one invocation.
//! There was no merge and no diff, so a call naming one agent withdrew every
//! other — and reported success. The loss was invisible without a read-back, and
//! it surfaced later, on the first agent's next share, as a policy refusal that
//! named neither the grant nor the command that overwrote it.
//!
//! These tests drive the real binary. The first grants two agents in two separate
//! calls and asserts both survive; the second asserts `--replace` still produces
//! the old behaviour, because a caller that wants to drop grants must be able to
//! say so explicitly.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Stdio};

use ksp::exit;

/// The vault password every invocation in this file uses.
const PASSWORD: &str = "a long enough password";

fn ksp() -> &'static str {
    env!("CARGO_BIN_EXE_ksp")
}

fn configure(home: &Path) {
    let _ = Command::new(ksp())
        .env("KSP_HOME", home)
        .arg("init")
        .output();
}

fn ksp_in(home: &Path, args: &[&str], stdin: Option<&str>) -> (i32, String) {
    configure(home);
    let mut command = Command::new(ksp());
    command
        .env("KSP_HOME", home)
        .env("LC_ALL", "C")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = command.spawn().expect("the binary runs");
    if let Some(text) = stdin {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(text.as_bytes())
            .expect("the password is written");
    }
    let output = child.wait_with_output().expect("the binary finishes");
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.code().unwrap_or(-1), combined)
}

fn provision_vault(home: &Path) {
    let (code, output) = ksp_in(
        home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin init failed: {output}");
    let (code, output) = ksp_in(home, &["admin", "user", "add"], Some(PASSWORD));
    assert_eq!(code, exit::SUCCESS, "admin user add failed: {output}");
}

/// Enrol an agent and return the principal UUID it issued.
fn enrol(home: &Path, name: &str) -> String {
    let (code, output) = ksp_in(home, &["agent", "enroll", "--agent", name], None);
    assert_eq!(code, exit::SUCCESS, "enrol {name} failed: {output}");
    output
        .split("agent:")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no agent identity in {output}"))
        .to_string()
}

/// The grants the host currently holds, as `--show --json` reports them.
fn grants(home: &Path) -> (Vec<String>, Vec<String>) {
    let (code, output) = ksp_in(home, &["--json", "admin", "policy", "--show"], None);
    assert_eq!(code, exit::SUCCESS, "admin policy --show failed: {output}");
    let value: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|error| panic!("not one JSON document ({error}): {output}"));
    let strings = |field: &str| -> Vec<String> {
        value[field]
            .as_array()
            .unwrap_or_else(|| panic!("{field} is not an array: {value}"))
            .iter()
            .map(|item| item.as_str().unwrap_or_default().to_string())
            .collect()
    };
    (strings("shareable_agents"), strings("shareable_secrets"))
}

/// A second grant adds to the set instead of replacing it.
///
/// This is the defect: two sequential calls, each naming one agent, and the first
/// agent's grant must still be there afterwards.
#[test]
fn a_second_grant_leaves_the_first_in_place() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let first = enrol(home.path(), "first");
    let second = enrol(home.path(), "second");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &first, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the first grant failed: {output}");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &second, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the second grant failed: {output}");

    let (agents, secrets) = grants(home.path());
    assert!(
        agents.contains(&first),
        "the first agent's grant was revoked by the second call: {agents:?}"
    );
    assert!(
        agents.contains(&second),
        "the second agent's grant is missing: {agents:?}"
    );
    assert_eq!(agents.len(), 2, "expected exactly two agents: {agents:?}");
    assert_eq!(secrets, vec!["s1".to_string()], "{secrets:?}");

    // A merged policy is re-signed, so it must still verify. Asserted here rather
    // than in a test of its own: on its own this property holds before the change
    // too, because a replacing write also verifies, so it would pass both before
    // and after and discriminate nothing.
    let (code, output) = ksp_in(home.path(), &["--json", "admin", "policy", "--show"], None);
    assert_eq!(code, exit::SUCCESS, "{output}");
    let value: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|error| panic!("not one JSON document ({error}): {output}"));
    assert_eq!(
        value["issuer_verified"], true,
        "a merged policy must verify against the anchor: {value}"
    );
}

/// `--replace` keeps the old behaviour, and says so.
///
/// A caller that wants the whole set replaced must be able to ask for it. Without
/// the flag the merge above would be the only behaviour, and a caller that
/// deliberately wants one grant would have to revoke the others one at a time.
#[test]
fn replace_still_drops_the_grants_it_does_not_name() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let first = enrol(home.path(), "first");
    let second = enrol(home.path(), "second");

    let (code, output) = ksp_in(
        home.path(),
        &[
            "admin", "policy", "--agent", &first, "--agent", &second, "--secret", "s1",
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the first grant failed: {output}");

    let (code, output) = ksp_in(
        home.path(),
        &[
            "admin",
            "policy",
            "--replace",
            "--agent",
            &second,
            "--secret",
            "s1",
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the replace failed: {output}");

    let (agents, _) = grants(home.path());
    assert!(
        !agents.contains(&first),
        "`--replace` must drop the grants it does not name: {agents:?}"
    );
    assert!(
        agents.contains(&second),
        "`--replace` must keep the grants it names: {agents:?}"
    );
}

/// The write names what it added and what it removed.
///
/// A caller reading stdout learns what changed without a second command. Without
/// this, the only way to know a merge happened is to run `--show` and diff it
/// against a set the caller had to remember.
#[test]
fn the_write_names_the_grants_it_added_and_removed() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let first = enrol(home.path(), "first");
    let second = enrol(home.path(), "second");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &first, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the first grant failed: {output}");
    assert!(
        output.contains(&first) && output.contains("added"),
        "the first write must report the grant it added: {output}"
    );

    // A merge that adds a second agent and removes nothing.
    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &second, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the second grant failed: {output}");
    assert!(
        output.contains(&second) && output.contains("added"),
        "the merge must report the grant it added: {output}"
    );
    // The removal line is read on its own. A whole-output `contains` would pass on
    // the *added* line naming the agent, which is the opposite claim.
    let removed = output
        .lines()
        .find(|line| line.trim_start().starts_with("removed:"))
        .unwrap_or_else(|| panic!("the write must report what it removed: {output}"));
    assert!(
        removed.contains("none") && !removed.contains(&first),
        "a merge that removes nothing must say so rather than claim a removal: {removed}"
    );
}

/// The revision advances on a merge, like any write.
///
/// A merge is a new signed policy, not a re-presentation of the old one. A
/// revision that did not advance would look to a client like the policy it already
/// accepted.
#[test]
fn a_merge_advances_the_revision() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let first = enrol(home.path(), "first");
    let second = enrol(home.path(), "second");

    let revision = |home: &Path| -> u64 {
        let (code, output) = ksp_in(home, &["--json", "admin", "policy", "--show"], None);
        assert_eq!(code, exit::SUCCESS, "{output}");
        let value: serde_json::Value = serde_json::from_str(output.trim())
            .unwrap_or_else(|error| panic!("not one JSON document ({error}): {output}"));
        value["revision"]
            .as_u64()
            .unwrap_or_else(|| panic!("revision is not a number: {value}"))
    };

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &first, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "{output}");
    let before = revision(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &second, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "{output}");
    let after = revision(home.path());

    assert!(
        after > before,
        "a merge must advance the revision: {before} -> {after}"
    );
}

/// A merge onto a host with no policy behaves like the first write.
///
/// The first `admin policy` on a fresh deployment has nothing to merge with. It
/// must not fail, and it must not invent a grant.
#[test]
fn a_merge_with_no_existing_policy_is_the_first_write() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "laptop");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &agent, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the first write failed: {output}");

    let (agents, secrets) = grants(home.path());
    assert_eq!(agents, vec![agent], "{agents:?}");
    assert_eq!(secrets, vec!["s1".to_string()], "{secrets:?}");
}

/// `admin revoke` still removes a grant and records the withdrawal.
///
/// The complement of the merge: adding is `admin policy`, removing is
/// `admin revoke`. A merge that also removed would put two operations behind one
/// flag.
#[test]
fn revoke_still_removes_a_grant() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let first = enrol(home.path(), "first");
    let second = enrol(home.path(), "second");

    for agent in [&first, &second] {
        let (code, output) = ksp_in(
            home.path(),
            &["admin", "policy", "--agent", agent, "--secret", "s1"],
            None,
        );
        assert_eq!(code, exit::SUCCESS, "a grant failed: {output}");
    }

    let (code, output) = ksp_in(home.path(), &["admin", "revoke", "--agent", &first], None);
    assert_eq!(code, exit::SUCCESS, "the revoke failed: {output}");

    let (agents, _) = grants(home.path());
    assert!(
        !agents.contains(&first),
        "the revoked grant is still present: {agents:?}"
    );
    assert!(
        agents.contains(&second),
        "the revoke removed the wrong grant: {agents:?}"
    );
}

/// `--replace` produces the same policy whatever order the grants are named in.
///
/// The body is signed over its encoded bytes, so two invocations that name the
/// same grants in a different order must produce the same signed body. `union`
/// sorts for this reason, but the `replace` path returned the caller's order
/// untouched: the same grant set named `--agent A --agent B` and `--agent B
/// --agent A` produced two different signatures for one policy, and a client
/// comparing digests would report a change that did not happen.
#[test]
fn replace_is_independent_of_the_order_the_grants_are_named_in() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let first = enrol(home.path(), "first");
    let second = enrol(home.path(), "second");

    let (code, output) = ksp_in(
        home.path(),
        &[
            "admin",
            "policy",
            "--replace",
            "--agent",
            &first,
            "--agent",
            &second,
            "--secret",
            "s1",
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the first replace failed: {output}");
    let (agents_forward, _) = grants(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &[
            "admin",
            "policy",
            "--replace",
            "--agent",
            &second,
            "--agent",
            &first,
            "--secret",
            "s1",
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the second replace failed: {output}");
    let (agents_backward, _) = grants(home.path());

    assert_eq!(
        agents_forward, agents_backward,
        "the same grant set named in a different order produced a different policy"
    );
}

/// The JSON report names the same difference the text report does.
///
/// A machine reads `--json`, and the two reports are built from one view. Pinning
/// the JSON is what makes the field names a contract: the renderer could print
/// the right sentence while the object a consumer parses carried nothing.
#[test]
fn the_json_report_names_what_the_write_added_and_removed() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let first = enrol(home.path(), "first");
    let second = enrol(home.path(), "second");

    let (code, output) = ksp_in(
        home.path(),
        &[
            "admin", "policy", "--agent", &first, "--agent", &second, "--secret", "s1",
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the first grant failed: {output}");

    // A replace that keeps one agent and drops the other. This is the only path
    // that can report a removal, so it is the only one that can prove the field.
    let (code, output) = ksp_in(
        home.path(),
        &[
            "--json",
            "admin",
            "policy",
            "--replace",
            "--agent",
            &second,
            "--secret",
            "s1",
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the replace failed: {output}");
    let value: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|error| panic!("not one JSON document ({error}): {output}"));

    assert_eq!(value["kind"], "policy_granted", "{value}");
    assert_eq!(value["replaced"], true, "{value}");
    assert_eq!(
        value["removed_agents"],
        serde_json::json!([first]),
        "the replace must name the grant it dropped: {value}"
    );
    assert_eq!(
        value["added_agents"],
        serde_json::json!([]),
        "a replace that adds nothing must say so: {value}"
    );
}
