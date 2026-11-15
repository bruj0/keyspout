//! Audit view scope through the real binary.
//!
//! # What these prove that a unit test cannot
//!
//! `ksp_identity::scope` proves the decision. These prove that the command asks
//! that decision and then obeys it: the tenant's view omits a sibling's chain, a
//! request for another principal exits `2` and says what decided, an absent UUID
//! answers exactly like a forbidden one, and the admin's complete view states that
//! the order between chains is a timestamp claim.
//!
//! A sibling chain is written straight through [`AuditChain`], because the point
//! of the test is a record the running command did not write and must not show.
//! Both writers land in one `KSP_HOME`, so the separation under test is the scope
//! and not the file mode.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ksp::config::Layout;
use ksp::exit;
use ksp_deletion::AuditChain;
use ksp_deletion::signing::EvidenceSigningKey;
use ksp_types::evidence::{AuditComponent, AuditOperation, AuditRecord, AuditTarget, Outcome};
use ksp_types::{Level, OpaqueSecretId, PrincipalId, VaultId};

/// The value every invocation in this file stores.
const VALUE: &str = "correct-horse-battery-staple";
/// The vault password every invocation in this file uses.
const PASSWORD: &str = "a long enough password";
/// The secret name the sibling's record names, so its presence is observable.
const SIBLING_SECRET: &str = "sibling-only";

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
    if let Some(text) = stdin {
        // A command that refuses before it reads input closes the pipe first; the
        // broken pipe is this test's own write, not the refusal under test.
        if let Err(error) = child
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

/// Store one secret as the tenant, so the log holds a record the tenant authored.
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

/// Read the log as the tenant, with the password on stdin.
fn audit(home: &Path, args: &[&str]) -> (i32, String) {
    let mut full = vec!["audit"];
    full.extend_from_slice(args);
    ksp_in(home, &full, Some(PASSWORD))
}

/// The tenant's principal UUID, as the deployment recorded it.
fn tenant(home: &Path) -> PrincipalId {
    let (deployment, _anchor) = ksp::deployment::require(&Layout::new(home.to_path_buf())).unwrap();
    deployment.user
}

/// A principal no command in this file acts as.
fn sibling() -> PrincipalId {
    PrincipalId::parse("1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f").unwrap()
}

/// Append one record as a second principal with its own key.
fn write_sibling_chain(home: &Path) -> PrincipalId {
    let layout = Layout::new(home.to_path_buf());
    let chain = AuditChain::new(layout.audit_root());
    let signer = EvidenceSigningKey::generate();
    let actor = sibling();
    let record = AuditRecord {
        actor,
        signer_key_id: "agent-2026".to_string(),
        component: AuditComponent::Agent,
        operation: AuditOperation::Deliver,
        target: Some(AuditTarget::Record {
            vault: VaultId::new("vault-1"),
            level: Level::Agent(ksp_types::AgentId::new(actor)),
            secret: OpaqueSecretId::new(SIBLING_SECRET),
            version: 1,
        }),
        outcome: Outcome::Success,
        exit_code: 0,
        observed_at: 1_700_000_000,
        prev_digest: None,

        acceptance: None,
    };
    chain.append(&signer, actor, "agent-2026", record).unwrap();
    actor
}

/// Acceptance 1 and Misfit S: the tenant's view is its own.
#[test]
fn the_tenant_view_lists_its_own_records_and_omits_a_siblings() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    set_secret(home.path(), "db-password");
    let hidden = write_sibling_chain(home.path());

    let (code, output) = audit(home.path(), &[]);
    assert_eq!(code, exit::SUCCESS, "audit failed: {output}");
    assert!(
        output.contains("db-password"),
        "the tenant's own record must be listed: {output}"
    );
    assert!(
        !output.contains(SIBLING_SECRET),
        "a sibling's operation must not appear: {output}"
    );
    assert!(
        !output.contains(&hidden.to_string()),
        "the sibling's principal UUID must not appear: {output}"
    );
    assert!(
        output.contains("records=1"),
        "the view must count what it shows: {output}"
    );
    // A line that looks like evidence must not be read as evidence (Issue 4).
    assert!(
        output.contains("has not checked signatures"),
        "the view must say what it did not check: {output}"
    );

    // The same scope on the machine path: filtering only the human view would make
    // the JSON the weaker of the two, and this is the one place the brief names.
    let (code, json) = audit(home.path(), &["--json"]);
    assert_eq!(code, exit::SUCCESS, "--json failed: {json}");
    assert!(json.contains("\"kind\":\"log\""), "{json}");
    assert!(
        !json.contains(SIBLING_SECRET),
        "the JSON view is scoped too: {json}"
    );

    // FR-041: one object per record, not one array to unwrap. Each record line parses
    // on its own, which is what a consumer reading a line at a time needs.
    let records: Vec<&str> = json
        .lines()
        .filter(|line| line.contains("\"operation\""))
        .collect();
    assert_eq!(records.len(), 1, "one record, one object: {json}");
    for line in records {
        let value: serde_json::Value = serde_json::from_str(line).expect("each line is JSON");
        assert!(value.get("actor").is_some(), "{line}");
        assert!(value.get("observed_at").is_some(), "{line}");
    }
}

/// Acceptance 1 and T025: another principal's records are refused, not filtered.
#[test]
fn asking_for_another_principal_exits_two_and_names_the_scope_mechanism() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    set_secret(home.path(), "db-password");
    let hidden = write_sibling_chain(home.path());
    let asked = hidden.to_string();

    let (code, output) = audit(home.path(), &["--principal", &asked]);
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "asking for another principal must exit 2: {output}"
    );
    assert!(
        output.contains("scoped to the principal whose pinned key signs the invocation"),
        "the refusal must name what decided it: {output}"
    );
    assert!(
        output.contains(&asked),
        "the refusal must name the requested principal: {output}"
    );
    assert!(
        !output.contains(SIBLING_SECRET) && !output.contains("db-password"),
        "a refused view must publish no record: {output}"
    );
}

/// Acceptance 3: the command cannot be used to enumerate principals.
#[test]
fn an_absent_uuid_is_refused_exactly_like_a_forbidden_one() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let real = sibling().to_string();
    let absent = "8a0e2d4c-1b3f-4a5e-9c7d-0e1f2a3b4c5d";

    let (real_code, real_output) = audit(home.path(), &["--principal", &real]);
    let (absent_code, absent_output) = audit(home.path(), &["--principal", absent]);
    assert_eq!(real_code, exit::POLICY_DENIAL, "{real_output}");
    // Named explicitly so this test cannot pass on a command that does not exist:
    // clap's unknown-subcommand exit is also `2`, and two identical non-answers
    // would otherwise look like the property under test.
    assert!(
        real_output.contains("scoped to the principal whose pinned key signs the invocation"),
        "the refusal must name what decided it: {real_output}"
    );
    assert_eq!(
        absent_code, real_code,
        "an absent UUID must answer like a forbidden one: {absent_output}"
    );
    assert_eq!(
        real_output.replace(&real, "<asked>"),
        absent_output.replace(absent, "<asked>"),
        "the two answers must be identical apart from the UUID"
    );
}

/// T024: a subject narrows the admin's view instead of being ignored.
#[test]
fn the_admin_subject_filter_narrows_the_complete_view() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    set_secret(home.path(), "db-password");
    let hidden = write_sibling_chain(home.path());
    let asked = hidden.to_string();

    let (code, output) = audit(home.path(), &["--admin", "--principal", &asked]);
    assert_eq!(code, exit::SUCCESS, "the subject view failed: {output}");
    assert!(
        output.contains(&format!("subject={asked}")),
        "the view must say whose records these are: {output}"
    );
    assert!(
        output.contains(SIBLING_SECRET),
        "the subject's own record must be there: {output}"
    );
    assert!(
        !output.contains("db-password"),
        "another principal's record must not be: {output}"
    );
    assert!(output.contains("records=1"), "{output}");
}

/// Misfit S down to the count: a tenant does not even enumerate another principal's
/// directory, so an unreadable segment there cannot show up as a number in its view.
#[test]
fn another_principals_unreadable_segment_is_invisible_to_the_tenant() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    set_secret(home.path(), "db-password");
    let other = write_sibling_chain(home.path());
    let directory = Layout::new(home.path().to_path_buf())
        .audit_root()
        .join(other.to_string());
    std::fs::write(directory.join("segment-broken.cbor"), b"xx").unwrap();

    let (code, output) = audit(home.path(), &[]);
    assert_eq!(code, exit::SUCCESS, "the tenant view failed: {output}");
    assert!(
        output.contains("unreadable=0"),
        "a sibling's unreadable segment is not the tenant's to count: {output}"
    );
    assert!(
        !output.contains("segment-broken.cbor"),
        "not even the path: {output}"
    );

    // The admin reads every directory and does count it. A file whose bytes do not
    // frame is a malformed record rather than an unreadable entry: the difference is
    // whether the reader could open the file or could not make a record of what it
    // holds (FR-042).
    let (code, output) = audit(home.path(), &["--admin"]);
    assert_eq!(code, exit::SUCCESS, "the admin view failed: {output}");
    assert!(
        output.contains("malformed=1"),
        "the admin sees the frame it could not read: {output}"
    );
    assert!(
        output.contains("segment-broken.cbor"),
        "the count names the entry behind it: {output}"
    );
}

/// T024: asking for your own UUID is the same view, never a narrower or wider one.
#[test]
fn asking_for_your_own_uuid_is_allowed_and_is_the_same_view() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    set_secret(home.path(), "db-password");
    let own = tenant(home.path()).to_string();

    let (code, output) = audit(home.path(), &["--principal", &own]);
    assert_eq!(
        code,
        exit::SUCCESS,
        "your own UUID must be readable: {output}"
    );
    assert!(output.contains("db-password"), "{output}");
    assert!(output.contains("records=1"), "{output}");
}

/// Acceptance 2 and T026: the admin's view is complete and states the ordering
/// claim.
#[test]
fn the_admin_view_lists_every_chain_and_labels_the_order_as_a_timestamp_claim() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    set_secret(home.path(), "db-password");
    write_sibling_chain(home.path());

    let (code, output) = audit(home.path(), &["--admin"]);
    assert_eq!(code, exit::SUCCESS, "the admin view failed: {output}");
    assert!(
        output.contains("db-password") && output.contains(SIBLING_SECRET),
        "the admin sees every chain: {output}"
    );
    assert!(
        output.contains("timestamp"),
        "cross-chain order must be labelled a claim, not a sequence: {output}"
    );
}

/// T027: a caller with no key and no vault is refused with its own class's code,
/// not with the scope code.
#[test]
fn a_caller_with_no_credential_is_refused_with_missing_key_not_policy_denial() {
    let home = tempfile::tempdir().unwrap();

    let (code, output) = ksp_in(home.path(), &["audit"], Some(PASSWORD));
    assert_eq!(
        code,
        exit::MISSING_KEY,
        "an unprovisioned host has no key to prove: {output}"
    );
    assert_ne!(code, exit::POLICY_DENIAL, "{output}");

    // A provisioned host with no password proves nothing either.
    provision_vault(home.path());
    let (code, output) = ksp_in(home.path(), &["audit"], Some(""));
    assert_eq!(
        code,
        exit::MISSING_KEY,
        "an unopened vault proves nothing: {output}"
    );
    assert!(!output.contains("scoped to the principal"), "{output}");
}

// ---------------------------------------------------------------------------
// The read an agent can perform (feature 011)
// ---------------------------------------------------------------------------

/// Spawn `ksp audit` with an **open** stdin pipe that is never closed, and bound
/// the wait.
///
/// This is the shape a process supervisor hands a child by default, and it is the
/// one that hung: `app::password` called `read_to_end` on stdin with no terminal
/// check, so the read blocked until something killed the process. A hang is the
/// worst failure available — no exit code, no message, no evidence — so the test
/// must fail by *timing out*, which `Command::output()` cannot express.
fn audit_with_open_stdin(home: &Path) -> (i32, String) {
    configure(home);
    let mut child = Command::new(ksp())
        .env("KSP_HOME", home)
        .env("LC_ALL", "C")
        .arg("audit")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Piped and never written to, and never closed: an open pipe.
        .stdin(Stdio::piped())
        .spawn()
        .expect("the binary runs");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait().expect("the child is waitable") {
            Some(status) => {
                let output = child.wait_with_output().expect("the output is readable");
                let combined = String::from_utf8_lossy(&output.stdout).to_string()
                    + &String::from_utf8_lossy(&output.stderr);
                return (status.code().unwrap_or(-1), combined);
            }
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "`ksp audit` did not exit within 5s with an open stdin pipe: it blocked \
                     waiting for a password that pipe will never deliver"
                );
            }
            None => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    }
}

/// An open stdin pipe is refused, not waited on, and the refusal names the flag.
#[test]
fn an_open_stdin_pipe_is_refused_rather_than_waited_on() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());

    let (code, output) = audit_with_open_stdin(home.path());
    assert_eq!(
        code,
        exit::MISSING_KEY,
        "an open pipe cannot supply a password, so the view proves nothing: {output}"
    );
    assert!(
        output.contains("--passphrase-file"),
        "the refusal must name the flag that supplies the password: {output}"
    );
}

/// A pipe that *does* carry the password still works.
///
/// The guard must not break the one shape that functioned before it: a caller
/// that pipes the password and closes the pipe.
#[test]
fn a_closed_pipe_carrying_the_password_still_reads_the_view() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    set_secret(home.path(), "db_password");

    let (code, output) = ksp_in(home.path(), &["audit"], Some(PASSWORD));
    assert_eq!(
        code,
        exit::SUCCESS,
        "a piped password must still work: {output}"
    );
    assert!(output.contains("audit: scope="), "{output}");
}

/// `--passphrase-file` works, and is the documented way to supply the password.
#[test]
fn the_passphrase_file_still_reads_the_view() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    set_secret(home.path(), "db_password");
    let passphrase = password_file(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &["audit", "--passphrase-file", passphrase.to_str().unwrap()],
        None,
    );
    assert_eq!(
        code,
        exit::SUCCESS,
        "the passphrase file must work: {output}"
    );
    assert!(output.contains("audit: scope="), "{output}");
}

/// The `--json` output is JSONL: one header line, then one line per record.
///
/// FR-041 asks for one object per record so a consumer reads a record at a time,
/// and a log grows without bound, so a stream is the right shape. It is the only
/// command whose `--json` is not a single object, which is why the shape is
/// asserted here rather than left to the reader of `QUICKSTART.md`.
#[test]
fn the_json_view_is_a_header_line_then_one_line_per_record() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    set_secret(home.path(), "first");
    set_secret(home.path(), "second");
    let passphrase = password_file(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &[
            "--json",
            "audit",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "audit --json failed: {output}");

    let lines: Vec<&str> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert!(
        lines.len() >= 2,
        "a header and at least one record: {output}"
    );

    let header: serde_json::Value = serde_json::from_str(lines[0])
        .unwrap_or_else(|error| panic!("the first line is not JSON ({error}): {}", lines[0]));
    assert_eq!(
        header["kind"], "log",
        "the first line is the header: {header}"
    );

    for line in &lines[1..] {
        let record: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("a record line is not JSON ({error}): {line}"));
        assert_eq!(
            record["kind"], "audit-record",
            "every later line is a record: {record}"
        );
    }

    // The header's count describes what this invocation emitted.
    let emitted = header["records"].as_u64().unwrap_or(0) as usize;
    assert_eq!(
        emitted,
        lines.len() - 1,
        "the header count must match the record lines: {header}"
    );
}

/// `--limit` bounds the record lines, and the header reports both counts.
#[test]
fn the_limit_bounds_the_record_lines_and_the_header_says_so() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    for id in ["one", "two", "three"] {
        set_secret(home.path(), id);
    }
    let passphrase = password_file(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &[
            "--json",
            "audit",
            "--limit",
            "1",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "audit --limit failed: {output}");

    let lines: Vec<&str> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        2,
        "a header and exactly one record line: {output}"
    );

    let header: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(
        header["records"], 1,
        "the header reports one emitted: {header}"
    );
    assert!(
        header["total"].as_u64().unwrap_or(0) > 1,
        "the header must report the total beside the emitted count, or a bounded \
         view reads as a complete one: {header}"
    );
}

/// `--limit 0` is unbounded, so today's behaviour stays reachable.
#[test]
fn a_limit_of_zero_reads_without_a_bound() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    for id in ["one", "two", "three"] {
        set_secret(home.path(), id);
    }
    let passphrase = password_file(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &[
            "--json",
            "audit",
            "--limit",
            "0",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "audit --limit 0 failed: {output}");
    let lines: Vec<&str> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert!(lines.len() >= 4, "three records plus the header: {output}");
}

/// `--since` filters by the record's own timestamp, and a bad duration is a usage
/// error naming the accepted forms.
#[test]
fn the_since_filter_selects_by_time_and_refuses_a_bad_duration() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    set_secret(home.path(), "recent");
    let passphrase = password_file(home.path());

    // A window that certainly contains the record just written.
    let (code, output) = ksp_in(
        home.path(),
        &[
            "--json",
            "audit",
            "--since",
            "1h",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "audit --since 1h failed: {output}");
    let header: serde_json::Value = serde_json::from_str(output.lines().next().unwrap()).unwrap();
    assert!(
        header["records"].as_u64().unwrap_or(0) >= 1,
        "a record written now is inside a one-hour window: {header}"
    );

    // A window that excludes it.
    let (code, output) = ksp_in(
        home.path(),
        &[
            "--json",
            "audit",
            "--since",
            "1s",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "audit --since 1s failed: {output}");

    // A duration that will not parse is the caller's mistake.
    let (code, output) = ksp_in(
        home.path(),
        &[
            "audit",
            "--since",
            "nonsense",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(
        code,
        exit::USAGE,
        "a bad duration is a usage error, not exit {code}: {output}"
    );
    assert!(
        output.contains("30m") || output.contains("1h") || output.contains("7d"),
        "the refusal must name an accepted form: {output}"
    );
}

/// The three password-free paths keep working with any stdin.
///
/// `audit --admin` reads the admin key, and `audit verify` and `admin audit` read
/// public material. None of them needs a password, so the terminal guard must not
/// touch them.
#[test]
fn the_password_free_paths_are_unaffected_by_the_guard() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    set_secret(home.path(), "db_password");

    for args in [
        vec!["audit", "--admin"],
        vec!["audit", "verify"],
        vec!["admin", "audit"],
    ] {
        let (code, output) = audit_with_open_stdin_for(home.path(), &args);
        assert_eq!(
            code,
            exit::SUCCESS,
            "`{}` needs no password, so an open stdin must not stop it: {output}",
            args.join(" ")
        );
    }
}

/// The same bounded spawn, for an arbitrary argument list.
fn audit_with_open_stdin_for(home: &Path, args: &[&str]) -> (i32, String) {
    configure(home);
    let mut child = Command::new(ksp())
        .env("KSP_HOME", home)
        .env("LC_ALL", "C")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()
        .expect("the binary runs");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait().expect("the child is waitable") {
            Some(status) => {
                let output = child.wait_with_output().expect("the output is readable");
                let combined = String::from_utf8_lossy(&output.stdout).to_string()
                    + &String::from_utf8_lossy(&output.stderr);
                return (status.code().unwrap_or(-1), combined);
            }
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "`{}` did not exit within 5s with an open stdin pipe",
                    args.join(" ")
                );
            }
            None => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    }
}

/// `QUICKSTART.md` documents the JSONL shape and the two flags.
///
/// The shape is the only one in the CLI that is not a single object, so a reader
/// who learns the pattern from every other command is surprised by it. The
/// sentence is asserted rather than trusted, because a documentation line that
/// silently disappears is how the surprise comes back.
#[test]
fn the_quickstart_documents_the_jsonl_shape_and_the_flags() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives two levels below the workspace root");
    let text =
        std::fs::read_to_string(root.join("QUICKSTART.md")).expect("QUICKSTART.md is readable");

    for needle in [
        "JSONL",
        "--limit",
        "--since",
        "--passphrase-file",
        "Extra data",
    ] {
        assert!(
            text.contains(needle),
            "QUICKSTART.md must document {needle:?}: a consumer that learns the \
             single-object pattern from every other command is surprised by this one"
        );
    }
}

/// The window excludes records from `total` too, and the note names the window.
///
/// A bound and a window are both filters, and only the bound may truncate. A
/// `total` that counted records the window excluded would tell a consumer it saw
/// more than it did — the opposite of what the field is for — and a note that
/// said "raise --limit" when the bound is 200 sends the caller to a flag that
/// changes nothing.
///
/// The window is one second and the wait is three, because a record's
/// `observed_at` is whole seconds: a 1.2s wait can leave the record inside a
/// one-second window when the write and the read straddle a second boundary. The
/// margin is the assertion's subject, so it is generous on purpose.
#[test]
fn the_window_excludes_from_total_and_the_note_names_the_window() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    set_secret(home.path(), "old");
    let passphrase = password_file(home.path());

    std::thread::sleep(std::time::Duration::from_secs(3));

    let (code, output) = ksp_in(
        home.path(),
        &[
            "--json",
            "audit",
            "--since",
            "1s",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "audit --since failed: {output}");

    let header: serde_json::Value = serde_json::from_str(
        output
            .lines()
            .find(|line| !line.trim().is_empty())
            .expect("a header line"),
    )
    .expect("the header is JSON");

    assert_eq!(
        header["records"], 0,
        "the record is older than the window: {header}"
    );
    assert_eq!(
        header["total"], 0,
        "total must count what the window admits, not what the log holds: {header}"
    );

    let notes = header["notes"].to_string();
    assert!(
        !notes.contains("raise --limit"),
        "the bound is 200, so raising --limit changes nothing here: {notes}"
    );
    assert!(
        notes.contains("--since"),
        "the note must name the filter that actually truncated: {notes}"
    );
}

/// The bound still truncates, and `total` still reports what the window admitted.
///
/// The complement of the test above: with no window, the bound is the only filter,
/// so `total` counts every record the scope permits and the note names `--limit`.
#[test]
fn the_bound_truncates_and_total_reports_what_the_window_admitted() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    for id in ["one", "two", "three"] {
        set_secret(home.path(), id);
    }
    let passphrase = password_file(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &[
            "--json",
            "audit",
            "--limit",
            "1",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "audit --limit failed: {output}");

    let header: serde_json::Value = serde_json::from_str(
        output
            .lines()
            .find(|line| !line.trim().is_empty())
            .expect("a header line"),
    )
    .expect("the header is JSON");

    assert_eq!(header["records"], 1, "{header}");
    assert_eq!(
        header["total"], 3,
        "with no window, total counts every record the scope permits: {header}"
    );
    assert!(
        header["notes"].to_string().contains("raise --limit"),
        "the bound is what truncated, so the note names it: {header}"
    );
}
