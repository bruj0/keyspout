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

use ksp_cli::config::Layout;
use ksp_cli::exit;
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
    let (deployment, _anchor) =
        ksp_cli::deployment::require(&Layout::new(home.to_path_buf())).unwrap();
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
