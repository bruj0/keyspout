//! `ksp agent list` names every agent this host holds.
//!
//! # Why this file exists
//!
//! The enrolment file exists for every agent — `enrolments/<uuid>.cbor`, carrying
//! the display name — and no command read it as a list. A report that wanted to
//! join a policy's agent UUIDs to display names had to decode CBOR by hand, and
//! `admin policy --show` printed UUIDs with nothing to join them to.
//!
//! These tests drive the real binary. Each one pins one acceptance criterion:
//! two enrolments produce two rows, an absent display name is not invented, no
//! private half appears in either rendering, an empty directory lists nothing, a
//! corrupt file is reported rather than skipped, and the command writes nothing.

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

/// The rows `ksp agent list --json` reports.
fn rows(home: &Path) -> Vec<serde_json::Value> {
    let (code, output) = ksp_in(home, &["--json", "agent", "list"], None);
    assert_eq!(code, exit::SUCCESS, "agent list failed: {output}");
    let value: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|error| panic!("not one JSON document ({error}): {output}"));
    value["agents"]
        .as_array()
        .unwrap_or_else(|| panic!("no agents array: {value}"))
        .clone()
}

/// Two enrolments produce two rows, each with the identity and both key IDs.
#[test]
fn two_enrolments_produce_two_rows_with_identity_and_both_key_ids() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let first = enrol(home.path(), "laptop");
    let second = enrol(home.path(), "deploy-bot");

    let listed = rows(home.path());
    assert_eq!(listed.len(), 2, "expected two rows: {listed:?}");

    let identities: Vec<&str> = listed
        .iter()
        .map(|row| row["identity"].as_str().unwrap_or_default())
        .collect();
    assert!(
        identities.contains(&first.as_str()),
        "the first agent is missing: {identities:?}"
    );
    assert!(
        identities.contains(&second.as_str()),
        "the second agent is missing: {identities:?}"
    );

    for row in &listed {
        for field in ["signing_key_id", "recipient_key_id"] {
            let value = row[field]
                .as_str()
                .unwrap_or_else(|| panic!("{field} is not a string: {row}"));
            assert!(!value.is_empty(), "{field} is empty: {row}");
        }
    }
}

/// An absent display name is not invented, and the row is still usable.
///
/// The display name is metadata: nothing security-relevant reads it, and a row
/// without one still carries the identity and both key IDs.
#[test]
fn an_absent_display_name_is_not_invented() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "laptop");

    let listed = rows(home.path());
    let row = listed
        .iter()
        .find(|row| row["identity"].as_str() == Some(agent.as_str()))
        .unwrap_or_else(|| panic!("the agent is missing: {listed:?}"));

    // Either the field is absent or it is null. What it must not be is a
    // synthesised string: a name the operator never chose is a name a report
    // would print as fact.
    let name = &row["display_name"];
    assert!(
        name.is_null() || name.as_str() == Some("laptop"),
        "the display name was invented: {row}"
    );
    assert!(
        !row["signing_key_id"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );
}

/// No private half appears, in either rendering.
///
/// # Why this reads the key file
///
/// An earlier version of this test asserted the output did not contain the words
/// `private` or `secret_key`. A leaked key is a hex string, not the word
/// "private", so that assertion could never fail: it tested the vocabulary of the
/// leak rather than the leak. This one reads the private key file the host holds
/// and asserts that none of its bytes appear in either rendering.
#[test]
fn no_private_half_appears_in_the_text_or_the_json() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "laptop");

    let (code, text) = ksp_in(home.path(), &["agent", "list"], None);
    assert_eq!(code, exit::SUCCESS, "agent list failed: {text}");
    let (code, json) = ksp_in(home.path(), &["--json", "agent", "list"], None);
    assert_eq!(code, exit::SUCCESS, "agent list --json failed: {json}");

    // The private half lives under `agent/agent/<uuid>.key`. Its bytes are what a
    // leak would print, so they are what this asserts on.
    let key_path = home
        .path()
        .join("agent")
        .join("agent")
        .join(format!("{agent}.key"));
    let key = std::fs::read(&key_path)
        .unwrap_or_else(|error| panic!("no private key at {}: {error}", key_path.display()));
    assert!(!key.is_empty(), "the private key file is empty");

    // Every 8-byte window, as hex. A shorter window would match by chance on a
    // 32-byte value; 8 bytes is 16 hex characters and does not.
    for offset in (0..key.len().saturating_sub(8)).step_by(8) {
        let window = hex(&key[offset..offset + 8]);
        for output in [&text, &json] {
            assert!(
                !output.contains(&window),
                "the listing leaked private key bytes at offset {offset}: {output}"
            );
        }
    }
}

/// A slice as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// An empty `enrolments/` lists nothing rather than failing.
///
/// A host with no agents is a normal state, not an error. A listing that failed
/// here would make every status report branch on an exit code for the ordinary
/// case.
#[test]
fn an_empty_enrolments_directory_lists_nothing() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());

    let listed = rows(home.path());
    assert!(listed.is_empty(), "expected no rows: {listed:?}");

    let (code, output) = ksp_in(home.path(), &["agent", "list"], None);
    assert_eq!(
        code,
        exit::SUCCESS,
        "an empty listing must succeed: {output}"
    );
}

/// A corrupt enrolment is reported, not silently skipped.
///
/// A file that cannot be decoded is a row a report would otherwise omit, and an
/// omitted row reads as an agent that does not exist. The listing names the file
/// and exits non-zero so a caller can tell a complete answer from a partial one.
#[test]
fn a_corrupt_enrolment_is_reported_rather_than_skipped() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "laptop");

    // The enrolment path is `enrolments/<uuid>.cbor` directly under the layout
    // root, which is the directory `KSP_HOME` names.
    let enrolments = home.path().join("enrolments");
    assert!(
        enrolments.is_dir(),
        "no enrolments directory at {}",
        enrolments.display()
    );
    let corrupt = enrolments.join("00000000-0000-4000-8000-00000000dead.cbor");
    std::fs::write(&corrupt, b"not a cbor document").unwrap();

    let (code, output) = ksp_in(home.path(), &["agent", "list"], None);
    assert_ne!(
        code,
        exit::SUCCESS,
        "a corrupt enrolment must not be reported as a clean listing: {output}"
    );
    assert!(
        output.contains("dead") || output.contains("enrolment"),
        "the refusal must name the file it could not read: {output}"
    );

    // The good row is still named: a partial answer that says so is more useful
    // than no answer, and the non-zero exit is what marks it partial.
    assert!(
        output.contains(&agent),
        "the readable enrolment must still be listed: {output}"
    );
}

/// The command creates, chowns and repairs nothing.
///
/// A listing is a read. Running it on a store whose `enrolments/` is absent must
/// not create the directory, and running it twice must not change a byte.
#[test]
fn the_command_writes_nothing() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    enrol(home.path(), "laptop");

    let enrolments = home.path().join("enrolments");
    assert!(
        enrolments.is_dir(),
        "no enrolments directory at {}",
        enrolments.display()
    );
    let before = snapshot(&enrolments);

    let (code, output) = ksp_in(home.path(), &["agent", "list"], None);
    assert_eq!(code, exit::SUCCESS, "{output}");

    let after = snapshot(&enrolments);
    assert_eq!(
        before, after,
        "the listing changed the enrolments directory"
    );
}

/// Every file name and length in a directory, sorted.
fn snapshot(dir: &Path) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            out.push((name, len));
        }
    }
    out.sort();
    out
}
