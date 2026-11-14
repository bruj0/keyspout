//! The output and exit contract an agent depends on.
//!
//! # What these prove that a unit test cannot
//!
//! An agent drives `ksp` by reading stdout and branching on the exit code. Both
//! halves have failed silently in this tree, and each test here pins the failure
//! that was measured rather than the fix that was written.
//!
//! 1. A serialization failure used to print the string `"unserializable"` — a
//!    valid JSON document with no fields and no error. The scan below fails if
//!    that substitution returns anywhere under `crates/`.
//! 2. Three usage errors used to exit `1`, which the contract defines as an
//!    unexpected internal failure. An agent cannot tell a typo from a crash when
//!    both return the same integer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ksp_cli::exit;

/// The vault password every invocation in this file uses.
const PASSWORD: &str = "a long enough password";

fn ksp() -> &'static str {
    env!("CARGO_BIN_EXE_ksp")
}

/// The repository root, derived from this test binary's location.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives two levels below the workspace root")
        .to_path_buf()
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

/// Every `.rs` file under `crates/`, pruned so a build tree is never walked.
///
/// The walk skips `target` and every hidden directory during traversal rather
/// than filtering afterwards: a workspace `target/` holds tens of gigabytes, and
/// enumerating it to discard it is the cost this pruning exists to avoid.
fn rust_sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if name.starts_with('.') || name == "target" || name == "node_modules" {
                    continue;
                }
                walk(&path, out);
            } else if name.ends_with(".rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&repo_root().join("crates"), &mut out);
    out
}

/// The `"unserializable"` substitution must not come back.
///
/// It was a fallback that turned a serialization bug into plausible output: the
/// caller received a valid JSON document containing one string, parsed it
/// successfully, and reported an empty result. Nothing anywhere raised an error.
/// A report that will not serialize is a defect in this tool, and the command
/// must fail rather than print a substitute.
///
/// The scan looks for the *substitution*, not the word: this file and the source
/// it guards both name the string in prose, and a plain substring match would
/// report the explanation as the defect. A `Value::String` construction is the
/// shape the fallback had, so that is what is matched.
///
/// The needle is assembled from two pieces so this test does not match its own
/// source line. A scan that reports itself is a scan nobody can keep green.
#[test]
fn no_command_substitutes_a_string_for_a_report_it_cannot_serialize() {
    let needle = concat!("unserial", "izable");
    let mut offenders = Vec::new();
    for path in rust_sources() {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (number, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains("Value::String") && code.contains(needle) {
                offenders.push(format!("{}:{}", path.display(), number + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a report that cannot be serialized must fail the command, not print a \
         substitute string. Found at: {offenders:?}"
    );
}

/// The new usage code is distinct from every other published code.
///
/// `3`, `4` and `5` are reserved by the design specification for token expiry, an
/// unreachable backend and a sealed vault. Reusing one would make a future
/// implementation contradict a shipped contract, so the absence is asserted
/// rather than assumed.
#[test]
fn the_usage_code_is_distinct_from_every_other_code() {
    let published = [
        exit::SUCCESS,
        exit::INTERNAL,
        exit::POLICY_DENIAL,
        exit::MISSING_KEY,
        exit::CAPABILITY_REFUSAL,
        exit::UNPROVEN,
        exit::DELETE_FAILED,
        exit::LOST_FRESH_FETCH,
        exit::UNCONSUMED_REFUSED,
        exit::AUDIT_UNVERIFIED,
    ];
    assert!(
        !published.contains(&exit::USAGE),
        "the usage code {} collides with a published code",
        exit::USAGE
    );
    for reserved in [3, 4, 5] {
        assert_ne!(
            exit::USAGE,
            reserved,
            "the usage code must not reuse the reserved code {reserved}"
        );
    }
}

/// A usage code reads as one, and does not read as the other two.
///
/// An agent branches on the integer without reading the message, so the sentence
/// is what a human gets. It must not say "internal" (that is `1`) and must not
/// say "policy" (that is `2`), or the two meanings collapse again.
#[test]
fn the_usage_code_describes_itself_without_borrowing_another_meaning() {
    let sentence = exit::describe(exit::USAGE);
    assert!(!sentence.is_empty(), "the code has no description");
    assert_ne!(sentence, "unrecognised outcome", "{sentence}");
    let lowered = sentence.to_lowercase();
    assert!(
        !lowered.contains("internal"),
        "a usage error is not an internal failure: {sentence}"
    );
    assert!(
        !lowered.contains("policy"),
        "a usage error is not a policy decision: {sentence}"
    );
}

/// A display name where a UUID is required is the caller's mistake, not a crash.
#[test]
fn a_display_name_where_a_uuid_is_required_exits_the_usage_code() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "policy", "--agent", "laptop", "--secret", "s1"],
        None,
    );
    assert_eq!(
        code,
        exit::USAGE,
        "a malformed agent id is a usage error, not exit {code}: {output}"
    );
    assert!(
        output.contains("canonical lowercase v4 UUID"),
        "the refusal must name the accepted form: {output}"
    );
}

/// A display name already enrolled is a usage error too.
#[test]
fn a_taken_display_name_exits_the_usage_code() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());

    let (code, output) = ksp_in(home.path(), &["agent", "enroll", "--agent", "laptop"], None);
    assert_eq!(code, exit::SUCCESS, "the first enrolment failed: {output}");

    let (code, output) = ksp_in(home.path(), &["agent", "enroll", "--agent", "laptop"], None);
    assert_eq!(
        code,
        exit::USAGE,
        "a taken display name is a usage error, not exit {code}: {output}"
    );
    assert!(
        output.contains("already enrolled"),
        "the refusal must name the existing principal: {output}"
    );
}

/// An empty value is a usage error, and the refusal names the flag that fixes it.
///
/// The password reader consumes the whole stream, so a caller that pipes
/// `password\nvalue` leaves the value empty. That is the caller's pipeline, and
/// the message has to say so: `--passphrase-file` is the way to supply the
/// password separately.
#[test]
fn an_empty_value_exits_the_usage_code_and_names_the_flag() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &["secret", "set", "s1", "--name", "n"],
        Some(PASSWORD),
    );
    assert_eq!(
        code,
        exit::USAGE,
        "an empty value is a usage error, not exit {code}: {output}"
    );
    assert!(
        output.contains("--passphrase-file"),
        "the refusal must name the flag that supplies the password separately: \
         {output}"
    );
}

/// A missing key file is still a missing key, not a usage error.
///
/// The mapping change moves three named variants. `AgentError::Keys` is not one
/// of them, and a test that only asserted the new mapping would not notice if the
/// change widened to cover it.
///
/// `agent rotate` is the command that reads the protected key file; `agent
/// pubkey` reads the enrolment and succeeds without it, so the removal below
/// would prove nothing there.
#[test]
fn a_missing_agent_key_still_exits_the_missing_key_code() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let (code, output) = ksp_in(home.path(), &["agent", "enroll", "--agent", "laptop"], None);
    assert_eq!(code, exit::SUCCESS, "enrol failed: {output}");

    let uuid = output
        .split("agent:")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .expect("the enrolment printed an identity")
        .to_string();

    // Remove the protected key file. The pin remains, so the reload fails on the
    // key rather than on the enrolment.
    let mut removed = 0;
    for entry in walkdir(&home.path().join("agent")) {
        if entry.extension().is_some_and(|ext| ext == "key") {
            std::fs::remove_file(&entry).unwrap();
            removed += 1;
        }
    }
    assert!(removed > 0, "no key file was found under the agent root");

    let (code, output) = ksp_in(
        home.path(),
        &[
            "agent",
            "rotate",
            "--agent",
            &uuid,
            "--signing-key-id",
            "rotated-ed25519-2",
            "--recipient-key-id",
            "rotated-x25519-2",
        ],
        None,
    );
    assert_eq!(
        code,
        exit::MISSING_KEY,
        "a missing key is missing key material, not a usage error: {output}"
    );
}

fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walkdir(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// Both documents that publish the exit-code table name the new code.
///
/// A code an agent must learn is useless if the two places a reader looks do not
/// list it. The spec's table and `QUICKSTART.md` are those two places, and a
/// change that updates one and not the other leaves a reader with a contract they
/// cannot check.
#[test]
fn both_documents_publish_the_usage_code() {
    let root = repo_root();
    for (name, path) in [
        ("QUICKSTART.md", root.join("QUICKSTART.md")),
        (
            "docs/keyspout-design-spec.md",
            root.join("docs/keyspout-design-spec.md"),
        ),
    ] {
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{name} is unreadable: {error}"));
        assert!(
            text.contains("`13`"),
            "{name} does not list exit code 13 in its exit-code table"
        );
    }
}
