//! The policy read-back, end to end through the binary.
//!
//! # Why this file exists
//!
//! `admin policy` replaces the whole grant set: a revision names every grant it
//! carries, so a call that names one agent withdraws every other. Before
//! `--show` an agent had to hold the current grants in its own context, which a
//! fresh session does not, so granting a second agent silently revoked the
//! first.
//!
//! These tests drive the real binary: they grant, read back, revoke, read back
//! again, and assert that the read-back follows the file rather than a grant set
//! the command remembers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
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

/// `admin policy --show` names every grant the current revision carries.
#[test]
fn the_read_back_names_every_grant() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let first = enrol(home.path(), "first");
    let second = enrol(home.path(), "second");

    // Grant both in one call, because a second call replaces the first.
    let (code, output) = ksp_in(
        home.path(),
        &[
            "admin", "policy", "--agent", &first, "--agent", &second, "--secret", "s1", "--secret",
            "s2",
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");

    let (code, output) = ksp_in(home.path(), &["admin", "policy", "--show"], None);
    assert_eq!(code, exit::SUCCESS, "admin policy --show failed: {output}");
    assert!(
        output.contains(&first),
        "the first agent is missing: {output}"
    );
    assert!(
        output.contains(&second),
        "the second agent is missing: {output}"
    );
    assert!(
        output.contains("s1"),
        "the first secret is missing: {output}"
    );
    assert!(
        output.contains("s2"),
        "the second secret is missing: {output}"
    );
    assert!(output.contains("revision"), "{output}");
    assert!(
        output.contains("verified against the pinned anchor"),
        "the issuer must be reported: {output}"
    );
}

/// The read-back is one object under `--json`, with the grants as arrays.
#[test]
fn the_read_back_is_one_object_under_json() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "laptop");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &agent, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");

    let (code, output) = ksp_in(home.path(), &["--json", "admin", "policy", "--show"], None);
    assert_eq!(
        code,
        exit::SUCCESS,
        "admin policy --show --json failed: {output}"
    );

    let value: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|error| panic!("not one JSON document ({error}): {output}"));
    assert_eq!(value["kind"], "policy", "{value}");
    assert!(value["revision"].is_number(), "{value}");
    assert_eq!(value["issuer_verified"], true, "{value}");

    let agents = value["shareable_agents"]
        .as_array()
        .unwrap_or_else(|| panic!("shareable_agents is not an array: {value}"));
    assert_eq!(agents.len(), 1, "{value}");
    assert_eq!(agents[0], agent, "{value}");

    let secrets = value["shareable_secrets"]
        .as_array()
        .unwrap_or_else(|| panic!("shareable_secrets is not an array: {value}"));
    assert_eq!(secrets.len(), 1, "{value}");
    assert_eq!(secrets[0], "s1", "{value}");
}

/// A revoke narrows what the read-back reports.
///
/// The complement of the test above: the read-back must reflect the file that
/// exists, not a grant set the command remembers.
#[test]
fn the_read_back_follows_a_revoke() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "laptop");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &agent, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");

    let (code, output) = ksp_in(home.path(), &["admin", "revoke", "--agent", &agent], None);
    assert_eq!(code, exit::SUCCESS, "admin revoke failed: {output}");

    let (code, output) = ksp_in(home.path(), &["--json", "admin", "policy", "--show"], None);
    assert_eq!(code, exit::SUCCESS, "admin policy --show failed: {output}");
    let value: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
    let agents = value["shareable_agents"].as_array().expect("an array");
    assert!(
        agents.is_empty(),
        "the revoked grant must be gone from the read-back: {value}"
    );
}

/// A host with no policy refuses the read-back rather than inventing one.
///
/// The assertion is on the *code*, not on the absence of output: before the
/// command existed it exited `2` because the parser did not know the flag, which
/// would make an absence-only assertion pass without the feature. So the test
/// also asserts the *message*, which only the real refusal can produce.
///
/// `AdminError::NoPolicy` maps to `POLICY_DENIAL`: "this host holds no signed
/// policy" is a refusal a caller acts on, not missing key material. That mapping
/// predates this command and is left alone.
#[test]
fn the_read_back_refuses_on_an_unprovisioned_host() {
    let home = tempfile::tempdir().unwrap();

    let (code, output) = ksp_in(home.path(), &["admin", "policy", "--show"], None);
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "an unprovisioned host holds no policy, so the read-back refuses: {output}"
    );
    assert!(
        output.contains("no signed policy"),
        "the refusal must name what is missing, which is what distinguishes it \
         from the parser rejecting an unknown flag: {output}"
    );
    assert!(
        !output.contains("shareable_agents"),
        "the refusal must not print a policy it does not hold: {output}"
    );
}

/// The read-back writes nothing: a second call sees the same revision.
#[test]
fn the_read_back_does_not_change_the_policy() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "laptop");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &agent, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");

    let (_, before) = ksp_in(home.path(), &["--json", "admin", "policy", "--show"], None);
    let (_, after) = ksp_in(home.path(), &["--json", "admin", "policy", "--show"], None);
    let before: serde_json::Value = serde_json::from_str(before.trim()).unwrap();
    let after: serde_json::Value = serde_json::from_str(after.trim()).unwrap();
    assert_eq!(
        before["revision"], after["revision"],
        "a read must not advance the revision: {before} vs {after}"
    );
}

/// The policy file is the only source: a hand-edited file is what the read-back
/// reports, and the issuer check catches an edit that broke the signature.
///
/// The assertion is on `issuer_verified`, because that is the field a reader
/// acts on: a policy that does not verify is printed, and says so, rather than
/// being silently withheld.
#[test]
fn a_tampered_policy_is_reported_as_unverified() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "laptop");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &agent, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");

    // Flip one byte in the sealed body. The file decodes or it does not; either
    // way the read-back must not claim a verified issuer.
    let policy = home.path().join("policy.cbor");
    let mut bytes = std::fs::read(&policy).expect("the policy exists");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&policy, &bytes).expect("the policy is writable");

    let (code, output) = ksp_in(home.path(), &["--json", "admin", "policy", "--show"], None);
    if code == exit::SUCCESS {
        let value: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(
            value["issuer_verified"], false,
            "a tampered policy must not report a verified issuer: {value}"
        );
    } else {
        // A file that will not decode is refused outright, which is also
        // honest: the read-back does not invent a policy it cannot read.
        assert!(
            !output.contains("verified against the pinned anchor"),
            "a refusal must not claim verification: {output}"
        );
    }
}

/// `PathBuf` is used by the helper signature above; keep the import honest.
#[allow(dead_code)]
fn _path_buf_is_used(_: PathBuf) {}

/// Read the revision the current policy carries.
fn revision(home: &Path) -> u64 {
    let (code, output) = ksp_in(home, &["--json", "admin", "policy", "--show"], None);
    assert_eq!(code, exit::SUCCESS, "admin policy --show failed: {output}");
    let value: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|error| panic!("not one JSON document ({error}): {output}"));
    value["revision"]
        .as_u64()
        .unwrap_or_else(|| panic!("no revision in {value}"))
}

/// Every write advances the revision.
///
/// The revision is described in the code as "the monotonic revision", and it
/// participates in rollback detection: `PolicyRefusal::Rollback` refuses a policy
/// whose revision is below a trusted checkpoint. A hardcoded `1` made two
/// different policies claim the same revision, so a reader could not tell "the
/// policy I just wrote" from "the policy that was already there".
///
/// The assertions are on the *advance*, not on absolute numbers: `admin user add`
/// already signs a policy, so the first `admin policy` is not revision 1. Pinning
/// an absolute value would make this test a statement about provisioning order
/// rather than about the counter.
#[test]
fn every_policy_write_advances_the_revision() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "laptop");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &agent, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");
    let first = revision(home.path());

    // A second write signs the next revision.
    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &agent, "--secret", "s2"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");
    let second = revision(home.path());
    assert_eq!(
        second,
        first + 1,
        "a second write must advance the revision by one: {first} then {second}"
    );

    // And a third, so the test cannot pass on a two-valued counter.
    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &agent, "--secret", "s3"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");
    let third = revision(home.path());
    assert_eq!(
        third,
        second + 1,
        "the revision keeps advancing: {second} then {third}"
    );
}

/// A re-grant after a revoke does not regress the revision.
///
/// This is the case that made the defect a rollback hazard rather than a
/// cosmetic one: `admin revoke` already advanced the revision, and the next
/// `admin policy` reset it to 1. A deployment with a trusted checkpoint armed
/// would then refuse its own legitimate re-grant as a replay of an older policy.
#[test]
fn a_regrant_after_a_revoke_does_not_regress_the_revision() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "laptop");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &agent, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");
    let before_revoke = revision(home.path());

    let (code, output) = ksp_in(home.path(), &["admin", "revoke", "--agent", &agent], None);
    assert_eq!(code, exit::SUCCESS, "admin revoke failed: {output}");
    let after_revoke = revision(home.path());
    assert!(
        after_revoke > before_revoke,
        "a revoke advances the revision: {before_revoke} then {after_revoke}"
    );

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", &agent, "--secret", "s1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");
    let after_regrant = revision(home.path());
    assert!(
        after_regrant > after_revoke,
        "a re-grant must advance past the revoke, not regress: revoke was \
         {after_revoke}, re-grant wrote {after_regrant}"
    );
}
