//! `ksp audit` as one projection, rendered twice.
//!
//! # What these prove that a unit test cannot
//!
//! The human view and the JSON view are both projections of the same decoded record,
//! so they cannot disagree about what the log holds. These tests drive one fixture log
//! that contains three shapes — a record this build decodes, a record of a kind it does
//! not know, and a frame that is not a record — and assert that both renderings agree on
//! the counts, that neither drops what it cannot parse, and that neither asserts the log
//! is whole (FR-039…FR-045, misfits T and V).
//!
//! The unknown record is written as raw bytes on purpose: it is a record the running
//! command did not write and cannot type, which is exactly the case the projection is
//! for.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ksp_cli::config::Layout;
use ksp_cli::exit;
use ksp_types::PrincipalId;
use ksp_types::cbor::RawValue;

/// The value every invocation in this file stores.
const VALUE: &str = "correct-horse-battery-staple";
/// The vault password every invocation in this file uses.
const PASSWORD: &str = "a long enough password";
/// The kind a future writer might use, which this build does not know.
const FUTURE_DOMAIN: &str = "keyspout-audit-record-v2";
/// A value a future record must never print, whatever its field is called.
const FUTURE_MATERIAL: &str = "card-4242-4242-4242-4242";

fn ksp() -> &'static str {
    env!("CARGO_BIN_EXE_ksp")
}

/// Give this home the capability configuration a real host has.
///
/// `ksp init` is the production probe: it writes the strongest configuration
/// this host can satisfy and never overwrites one that exists, so calling it on
/// every invocation is safe. A host with no configuration has no adapter for
/// either capability, and every unseal and every delivery refuses — the
/// product's intended first-run behaviour, and therefore a precondition of every
/// test below that reaches one.
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
    if let Some(text) = stdin
        && let Err(error) = child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(text.as_bytes())
    {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe,
            "the input is written: {error}"
        );
    }
    let output = child.wait_with_output().expect("the binary finishes");
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.code().unwrap_or(-1), combined)
}

fn password_file(home: &Path) -> PathBuf {
    let path = home.join("passphrase");
    std::fs::write(&path, PASSWORD).unwrap();
    path
}

/// Initialise the deployment and enrol the user, through the binary.
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

/// Store one secret as the tenant, so the log holds a record it authored.
fn set_secret(home: &Path, id: &str) {
    let passphrase = password_file(home);
    let (code, output) = ksp_in(
        home,
        &[
            "secret",
            "set",
            id,
            "--name",
            "db_password",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "secret set failed: {output}");
}

/// Read the log, with the password on stdin.
fn audit(home: &Path, args: &[&str]) -> (i32, String) {
    let mut full = vec!["audit"];
    full.extend_from_slice(args);
    ksp_in(home, &full, Some(PASSWORD))
}

fn tenant(home: &Path) -> PrincipalId {
    ksp_cli::deployment::require(&Layout::new(home.to_path_buf()))
        .unwrap()
        .0
        .user
}

/// One frame: a four-byte big-endian length, then the body.
fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::from((u32::try_from(body.len()).unwrap()).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// A record of a kind this build does not know, with a field that carries material.
fn future_record() -> Vec<u8> {
    let field = |name: &str, value: RawValue| (RawValue::Text(name.to_string()), value);
    let body = RawValue::Map(vec![
        field("domain", RawValue::Text(FUTURE_DOMAIN.into())),
        field(
            "record",
            RawValue::Map(vec![
                field("actor", RawValue::Text("unknown-writer".into())),
                field("card_number", RawValue::Text(FUTURE_MATERIAL.into())),
                field("blob", RawValue::Bytes(vec![1, 2, 3])),
                field("count", RawValue::Integer(7.into())),
            ]),
        ),
        field("signature", RawValue::Bytes(vec![0; 64])),
    ]);
    ksp_types::cbor::encode(&body).unwrap()
}

/// The tenant's own segment file, whichever key signed the records already there.
fn tenant_segment(home: &Path) -> PathBuf {
    let layout = Layout::new(home.to_path_buf());
    let directory = layout.audit_root().join(tenant(home).to_string());
    std::fs::read_dir(&directory)
        .expect("the tenant has written a record")
        .flatten()
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.starts_with("segment-"))
                .unwrap_or(false)
        })
        .expect("the tenant's segment exists")
}

/// One home holding all three shapes: a record this build decodes, one it does not,
/// and a frame that is not a record.
fn fixture() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    set_secret(home.path(), "db-password");

    let segment = tenant_segment(home.path());
    let mut bytes = std::fs::read(&segment).unwrap();
    // Appended after the known record, so the fixture is one segment with all three.
    bytes.extend(frame(&future_record()));
    bytes.extend(frame(b"\xff\xff not cbor"));
    std::fs::write(&segment, bytes).unwrap();
    home
}

/// The `(operation, outcome)` of every known record in one JSON line per object.
fn json_objects(output: &str) -> Vec<serde_json::Value> {
    output
        .lines()
        .filter(|line| line.starts_with('{'))
        .map(|line| serde_json::from_str(line).expect("each record line is one object"))
        .collect()
}

/// The number after `name=` in the view's header line.
fn counted(output: &str, name: &str) -> usize {
    let start = output
        .find(&format!("{name}="))
        .unwrap_or_else(|| panic!("{name}= is in the header: {output}"))
        + name.len()
        + 1;
    output[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("{name}= is followed by a number: {output}"))
}

/// Acceptance 1 and T063: one fixture log, two renderings, one answer.
#[test]
fn the_human_and_json_views_agree_on_one_log() {
    let home = fixture();
    let (code, text) = audit(home.path(), &["--admin"]);
    assert_eq!(code, exit::SUCCESS, "the text view failed: {text}");
    let (code, json) = audit(home.path(), &["--admin", "--json"]);
    assert_eq!(code, exit::SUCCESS, "the JSON view failed: {json}");

    let objects = json_objects(&json);
    let kind_count = |kind: &str| {
        objects
            .iter()
            .filter(|object| object["kind"] == kind)
            .count()
    };
    assert_eq!(
        counted(&text, "records"),
        kind_count("audit-record"),
        "the text view's record count is the JSON view's: {text}"
    );
    assert_eq!(
        counted(&text, "unknown"),
        kind_count("unknown-record"),
        "the text view's unknown count is the JSON view's: {text}"
    );
    assert_eq!(
        counted(&text, "malformed"),
        kind_count("malformed"),
        "the text view's malformed count is the JSON view's: {text}"
    );
    assert_eq!(kind_count("audit-record"), 1, "{json}");
    assert_eq!(kind_count("unknown-record"), 1, "{json}");
    assert_eq!(kind_count("malformed"), 1, "{json}");

    // Same operations and outcomes, record by record.
    for object in objects.iter().filter(|o| o["kind"] == "audit-record") {
        let operation = object["operation"].as_str().unwrap();
        let outcome = object["outcome"].as_str().unwrap();
        assert!(
            text.contains(&format!("operation={operation}"))
                && text.contains(&format!("outcome={outcome}")),
            "the text view shows {operation}/{outcome}: {text}"
        );
    }
}

/// Acceptance 2: an unknown kind is printed as itself, with its fields, in both views.
#[test]
fn an_unknown_kind_is_printed_with_its_fields_in_both_views() {
    let home = fixture();
    let (code, text) = audit(home.path(), &["--admin"]);
    assert_eq!(code, exit::SUCCESS, "the text view failed: {text}");
    assert!(
        text.contains(&format!("record: kind={FUTURE_DOMAIN}")),
        "the unknown kind is named: {text}"
    );
    assert!(
        text.contains("actor=<text of 14 chars>"),
        "a text value is reported by length, not printed: {text}"
    );
    assert!(
        text.contains(&format!(
            "card_number=<text of {} chars>",
            FUTURE_MATERIAL.chars().count()
        )),
        "and a field named for material is the same, whatever it holds: {text}"
    );
    assert!(
        !text.contains(FUTURE_MATERIAL),
        "and no text value reaches the view: {text}"
    );
    assert!(
        text.contains("blob=<3 bytes>"),
        "a byte string is reported by its size: {text}"
    );
    assert!(text.contains("count=7"), "a number is printed: {text}");

    let (code, json) = audit(home.path(), &["--admin", "--json"]);
    assert_eq!(code, exit::SUCCESS, "the JSON view failed: {json}");
    let unknown = json_objects(&json)
        .into_iter()
        .find(|object| object["kind"] == "unknown-record")
        .expect("the unknown record is in the JSON view");
    assert_eq!(unknown["domain"], FUTURE_DOMAIN, "{unknown}");
    let fields = unknown["fields"].as_array().expect("the fields are a list");
    assert!(
        fields.iter().any(|field| {
            field["name"] == "card_number"
                && field["value"]["Text"]["chars"].as_u64()
                    == Some(FUTURE_MATERIAL.chars().count() as u64)
        }),
        "the JSON carries the length, not the text: {unknown}"
    );
    assert!(
        fields
            .iter()
            .any(|field| field["name"] == "count" && field["value"]["Integer"] == 7),
        "a number is printed: {unknown}"
    );
    assert!(
        !json.contains(FUTURE_MATERIAL),
        "and never the value: {json}"
    );
}

/// Acceptance 3 and FR-042: a frame that is not a record is counted and printed.
#[test]
fn a_malformed_record_is_counted_and_printed_not_skipped() {
    let home = fixture();
    let (code, text) = audit(home.path(), &["--admin"]);
    assert_eq!(code, exit::SUCCESS, "the text view failed: {text}");
    assert!(
        text.contains("malformed: segment=") && text.contains("index=2"),
        "the finding names where it is: {text}"
    );
    assert!(
        text.contains("the frame does not decode as a record"),
        "and says what is wrong with it: {text}"
    );

    let (code, json) = audit(home.path(), &["--admin", "--json"]);
    assert_eq!(code, exit::SUCCESS, "the JSON view failed: {json}");
    let malformed = json_objects(&json)
        .into_iter()
        .find(|object| object["kind"] == "malformed")
        .expect("the finding is in the JSON view");
    assert_eq!(malformed["index"], 2, "{malformed}");
    assert!(
        malformed["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "{malformed}"
    );
}

/// Misfit S, applied to a record this build cannot attribute: a narrowed view counts it
/// and withholds it rather than showing one principal's record to another.
#[test]
fn a_narrowed_view_withholds_a_record_it_cannot_attribute() {
    let home = fixture();
    let (code, text) = audit(home.path(), &[]);
    assert_eq!(code, exit::SUCCESS, "the tenant view failed: {text}");
    assert_eq!(
        counted(&text, "unknown"),
        1,
        "the tenant's own directory holds it, so it is counted: {text}"
    );
    assert_eq!(
        counted(&text, "withheld"),
        1,
        "and withheld, because its actor cannot be established: {text}"
    );
    assert!(
        !text.contains("unknown-writer") && !text.contains(FUTURE_DOMAIN),
        "its fields are not shown to a narrowed view: {text}"
    );
    assert!(
        text.contains("their actor cannot be established"),
        "the count says why: {text}"
    );

    // The complete view is the one that may print it.
    let (code, complete) = audit(home.path(), &["--admin"]);
    assert_eq!(code, exit::SUCCESS, "the admin view failed: {complete}");
    assert!(complete.contains(FUTURE_DOMAIN), "{complete}");
}

/// Acceptance 4 and T061: no rendering states the log is whole.
///
/// The vocabulary the spec itself uses — `completeness unknown`, a count of records
/// whose signature verified — is not a claim, so what this asserts is the absence of the
/// *assertion*: no sentence says the log is complete or valid.
#[test]
fn no_rendering_states_the_log_is_complete_or_valid() {
    let home = fixture();
    let (code, text) = audit(home.path(), &["--admin"]);
    assert_eq!(code, exit::SUCCESS, "the text view failed: {text}");

    // A clean home, so the verification summary is about wording and not about the
    // fixture's deliberately malformed frames.
    let clean = tempfile::tempdir().unwrap();
    provision_vault(clean.path());
    set_secret(clean.path(), "db-password");
    let (code, verify) = ksp_in(clean.path(), &["audit", "verify"], None);
    assert_eq!(code, exit::SUCCESS, "verify failed: {verify}");
    assert!(
        verify.contains("completeness unknown"),
        "verification states what it does not know: {verify}"
    );

    for output in [&text, &verify] {
        let lowered = output.to_lowercase();
        for claim in [
            "the log is complete",
            "log is valid",
            "is valid and complete",
            "valid and complete",
            "fully verified",
            "chain is valid",
            "nothing is missing",
        ] {
            assert!(
                !lowered.contains(claim),
                "no rendering may claim {claim:?}: {output}"
            );
        }
    }
}

/// Acceptance 5: the human line and the JSON object carry the same explicit field list.
#[test]
fn the_record_field_allow_list_is_explicit() {
    let home = fixture();
    let (code, json) = audit(home.path(), &["--admin", "--json"]);
    assert_eq!(code, exit::SUCCESS, "the JSON view failed: {json}");
    let record = json_objects(&json)
        .into_iter()
        .find(|object| object["kind"] == "audit-record")
        .expect("a known record is in the view");

    let mut keys = record
        .as_object()
        .expect("a record is an object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            // `acceptance` is the capability acceptance the record carries,
            // rendered. It is `null` for every record that established no
            // capability, which is most of them — but it is always a declared
            // field, so a reader can tell "nothing was accepted" from "the view
            // did not say".
            "acceptance",
            "actor",
            "component",
            "exit_code",
            "index",
            "kind",
            "observed_at",
            "operation",
            "outcome",
            "segment",
            "signer_key_id",
            "target",
        ],
        "the allow-list is the record's own identifiers and labels: {record}"
    );

    // Nothing the record carries but the projection does not declare can appear.
    for forbidden in ["prev_digest", "signature", "payload", "record"] {
        assert!(
            record.get(forbidden).is_none(),
            "{forbidden} must not be a printed field: {record}"
        );
    }
    let (code, text) = audit(home.path(), &["--admin"]);
    assert_eq!(code, exit::SUCCESS, "the text view failed: {text}");
    assert!(
        !text.contains("prev_digest") && !text.contains("signature="),
        "the human line prints the allow-list too: {text}"
    );
}

/// Acceptance 3 and FR-042, for the entry that is not a frame at all: a file inside a
/// writer's directory that is not a segment is counted and named, not skipped. A view
/// that drops a renamed or half-written segment is a view that reads whole.
#[test]
fn an_entry_that_is_not_a_segment_is_counted_not_skipped() {
    let home = fixture();
    let layout = Layout::new(home.path().to_path_buf());
    let directory = layout.audit_root().join(tenant(home.path()).to_string());
    std::fs::write(directory.join("segment-00000.cbor.bak"), b"renamed").unwrap();

    let (code, text) = audit(home.path(), &["--admin"]);
    assert_eq!(code, exit::SUCCESS, "the text view failed: {text}");
    assert_eq!(
        counted(&text, "unreadable"),
        1,
        "the stray entry is counted: {text}"
    );
    assert!(
        text.contains("segment-00000.cbor.bak"),
        "and named, so the operator can look: {text}"
    );

    let (code, json) = audit(home.path(), &["--admin", "--json"]);
    assert_eq!(code, exit::SUCCESS, "the JSON view failed: {json}");
    let header = json_objects(&json)
        .into_iter()
        .find(|object| object["kind"] == "log")
        .expect("the header object is in the JSON view");
    assert_eq!(header["unreadable"], 1, "{header}");
    assert!(
        header["trouble"]
            .as_array()
            .is_some_and(|paths| paths.iter().any(|path| path
                .as_str()
                .is_some_and(|path| path.ends_with("segment-00000.cbor.bak")))),
        "{header}"
    );
}

/// A writer-controlled name cannot forge a record on the next line of the view.
#[test]
fn a_crafted_field_name_cannot_print_a_second_record() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    set_secret(home.path(), "db-password");
    let segment = tenant_segment(home.path());
    let mut bytes = std::fs::read(&segment).unwrap();
    let field = |name: &str, value: RawValue| (RawValue::Text(name.to_string()), value);
    let hostile = RawValue::Map(vec![
        field("domain", RawValue::Text("future-renderer-v1".into())),
        field(
            "record",
            RawValue::Map(vec![
                field(
                    "note\nrecord: actor=admin  operation=grant  outcome=success",
                    RawValue::Text("x".into()),
                ),
                field("count", RawValue::Integer(1.into())),
            ]),
        ),
    ]);
    bytes.extend(frame(&ksp_types::cbor::encode(&hostile).unwrap()));
    std::fs::write(&segment, bytes).unwrap();

    let (code, text) = audit(home.path(), &["--admin"]);
    assert_eq!(code, exit::SUCCESS, "the text view failed: {text}");
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("record: kind=future-renderer-v1"))
            .count(),
        1,
        "one record, one line: {text}"
    );
    assert!(
        !text
            .lines()
            .any(|line| line.starts_with("record: actor=admin")),
        "the newline in a field name did not start a line: {text}"
    );
    assert!(text.contains(r"note\nrecord: actor=admin"), "{text}");
}
