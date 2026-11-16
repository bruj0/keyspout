//! The commands that describe rather than act, end to end through the binary.
//!
//! # What this covers
//!
//! `secret ls`, `secret rm`, the `--reveal` default on `secret get`, `backend
//! list`, `backend test` and `token inspect`. Each one is a command whose *whole*
//! contract is what reaches a caller's stdout or exit code, so a unit test on the
//! helper would prove the wrong thing.
//!
//! # The two rules this file exists to hold
//!
//! 1. A value reaches stdout only when `--reveal` asked for it. Before this, a
//!    `get` wrote the plaintext to whatever the shell had redirected.
//! 2. An inspection prints scope, issuer and expiry and never a key. The token is
//!    built here with the libraries because `ksp token mint` correctly refuses on
//!    the `file` backend (exit `7`), and the assertion is made against the actual
//!    public key so a `Debug` that leaked one would fail.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ksp::config::Layout;
use ksp::exit;
use ksp::keys::{Anchor, StoredEnrolment};
use ksp_identity::delivery::{self, VerifiedRecipientKey};
use ksp_identity::{SelectedRecord, UnsignedEnrolment};
use ksp_posture::LANDLOCK_CONFINEMENT;
use ksp_posture::adapters::ConfinementAdapter;
use ksp_record::{ContentBlob, Record, RecordEnvelope, commit_version};
use ksp_types::{
    ActorId, AdapterAvailability, AdapterName, BoundMetadata, ContentKey, Level, OpaqueSecretId,
    RecordVersion, VaultId,
};

/// A secret with a value nobody could guess by accident.
const VALUE: &str = "correct-horse-battery-staple";
/// The vault password every invocation in this file uses.
const PASSWORD: &str = "a long enough password";

fn ksp() -> &'static str {
    env!("CARGO_BIN_EXE_ksp")
}

/// Run `ksp` with this home, optionally writing `stdin`, and return (code, output).
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
        .args(args)
        // Piped as well as stdin: `wait_with_output` captures what is piped, so
        // without these the child's output would go to the test runner's terminal
        // and every assertion below would compare against an empty string.
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = command.spawn().expect("the binary runs");
    if let Some(text) = stdin {
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

/// Write the vault password to a file and return its path.
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

/// A fixed agent principal for tests that only need a grant or a ledger row.
fn some_agent() -> ksp_types::AgentId {
    ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap()
}

/// Enrol an agent under a display name and return the principal UUID it issued.
fn enrol(home: &Path, name: &str) -> ksp_types::AgentId {
    let (code, output) = ksp_in(home, &["agent", "enroll", "--agent", name], None);
    assert_eq!(code, exit::SUCCESS, "enrol {name} failed: {output}");
    let start = output
        .find("agent:")
        .unwrap_or_else(|| panic!("no agent identity in {output}"));
    let uuid: String = output[start + "agent:".len()..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit() || *c == '-')
        .collect();
    ksp_types::AgentId::parse(&uuid)
        .unwrap_or_else(|_| panic!("the printed identity is not canonical: {uuid}"))
}

/// Build a delivery for `agent` and return (token path, agent recipient key hex).
fn write_token(home: &Path, agent: ksp_types::AgentId) -> (PathBuf, String) {
    let layout = Layout::new(home);
    let anchor = Anchor::load(&layout.admin_anchor_file()).unwrap();
    let admin = ksp::admin::load_admin(&layout, &anchor).unwrap();
    let deployment = ksp::deployment::Deployment::load(&layout).unwrap();
    let stored = StoredEnrolment::load(&layout.enrolment_file(&agent.to_string())).unwrap();

    let unsigned = UnsignedEnrolment::bind(
        ActorId::Agent(agent),
        stored.signing_key,
        stored.recipient_key,
        stored.signing_key_id.clone(),
        stored.recipient_key_id.clone(),
    )
    .unwrap();
    let enrolment = admin
        .sign_enrolment(unsigned, anchor.key_id.clone())
        .unwrap();
    let confirmed = *enrolment.fingerprint();
    let recipient = VerifiedRecipientKey::confirm(&enrolment, &confirmed).unwrap();

    let metadata = BoundMetadata {
        vault_id: VaultId::new("vault-1"),
        user_id: deployment.user,
        level: Level::Agent(agent),
        secret_id: OpaqueSecretId::new("s3cr3t-id-1"),
        version: 1,
    };
    let content_key = ContentKey::generate();
    let aad = metadata.bound_aad().unwrap();
    let blob = ContentBlob::seal(&content_key, b"db_password", VALUE.as_bytes(), &aad).unwrap();
    let envelope =
        RecordEnvelope::seal(&content_key, &stored.recipient_key.to_bytes(), &metadata).unwrap();
    // The level is the table's, not the store's `create_dir_all`: its mode is
    // what lets the admin's sweep delete the copy without reading it.
    ksp::layout::ensure_level(
        layout.root(),
        &metadata.vault_id,
        metadata.user_id,
        &metadata.level,
    )
    .unwrap();
    commit_version(
        &ksp_backend::file::FileStore::new(layout.store_root()).unwrap(),
        &metadata,
        &Record {
            metadata: metadata.clone(),
            blob,
            envelope,
        },
    )
    .unwrap();

    let selected = SelectedRecord {
        secret: metadata.secret_id.clone(),
        version: RecordVersion(1),
    };
    let header = ksp_identity::DeliveryHeader::new(
        metadata.vault_id.clone(),
        metadata.user_id,
        deployment
            .user_signing_key_id
            .clone()
            .expect("the binding recorded her key id"),
        agent,
        stored.signing_key,
        stored.recipient_key,
        stored.signing_key_id.clone(),
        stored.recipient_key_id.clone(),
        metadata.level.clone(),
        Level::User,
        Level::Agent(agent).path_segment(),
        vec![selected.clone()],
        u64::MAX,
        "jti-surface-1".to_string(),
    )
    .unwrap();
    let keys =
        ksp_identity::SelectedContentKeys::new(&header, vec![(selected, content_key)]).unwrap();
    // Alice signs her own lease with the key her vault holds: a mint never uses
    // the admin's private half (spec §3.7 step 2).
    let unsealed = ksp::secret::unseal(&layout, PASSWORD.as_bytes()).unwrap();
    let artifact = unsealed
        .vault
        .with_signing_key(|signer| delivery::seal(signer, &header, &keys, &recipient))
        .unwrap();

    let token = home.join(format!("{agent}.token"));
    std::fs::write(&token, artifact.to_bytes().unwrap()).unwrap();
    (token, ksp::agent::hex(&stored.recipient_key.to_bytes()))
}

#[test]
fn a_value_reaches_stdout_only_when_reveal_asked_for_it() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let passphrase = password_file(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "set",
            "db_password",
            "--name",
            "db_password",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "secret set failed: {output}");

    // Without `--reveal` the value is not on stdout, and the redaction is there
    // so the caller can tell the difference between redacted and empty.
    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "get",
            "db_password",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "secret get failed: {output}");
    assert!(!output.contains(VALUE), "get printed the value: {output}");
    assert!(
        output.contains("••••"),
        "get printed no redaction: {output}"
    );

    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "get",
            "db_password",
            "--reveal",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "secret get --reveal failed: {output}");
    assert!(
        output.contains(VALUE),
        "--reveal did not print the value: {output}"
    );
}

/// `--json` on `secret get` emits a document, not the human line.
///
/// The flag was accepted and ignored: the command printed `name<TAB>value` and
/// exited `0` whatever `--json` said. An agent that passed `--json` and parsed
/// stdout got a tab-separated line where it expected an object, which is the
/// same silent-plausible-output failure feature 010 removed from the listing
/// commands.
///
/// The value still does not enter `Report`, and that is deliberate: `Report` is
/// what the audit path renders, and a value with a route into it is a value in
/// the log. The object is built in the command arm that already holds the value
/// and writes it straight to stdout, so the invariant holds and the flag works.
///
/// Both halves are asserted: the redacted form must not carry the value, and the
/// revealed form must. A test that only checked the shape would pass on an
/// implementation that printed `{"value":""}`.
#[test]
fn json_on_get_emits_a_document_and_still_honours_reveal() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let passphrase = password_file(home.path());
    let passphrase = passphrase.to_str().unwrap();

    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "set",
            "db_password",
            "--name",
            "db_password",
            "--passphrase-file",
            passphrase,
        ],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "secret set failed: {output}");

    let (code, output) = ksp_in(
        home.path(),
        &[
            "--json",
            "secret",
            "get",
            "db_password",
            "--passphrase-file",
            passphrase,
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "secret get --json failed: {output}");
    let parsed: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|error| panic!("`--json` did not emit a document: {error}\n{output}"));
    assert_eq!(parsed["kind"], "secret");
    assert_eq!(parsed["record"], "db_password");
    assert_eq!(parsed["name"], "db_password");
    assert_eq!(parsed["revealed"], false);
    assert!(
        !output.contains(VALUE),
        "the redacted document carried the value: {output}"
    );

    let (code, output) = ksp_in(
        home.path(),
        &[
            "--json",
            "secret",
            "get",
            "db_password",
            "--reveal",
            "--passphrase-file",
            passphrase,
        ],
        None,
    );
    assert_eq!(
        code,
        exit::SUCCESS,
        "secret get --json --reveal failed: {output}"
    );
    let parsed: serde_json::Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|error| panic!("`--json` did not emit a document: {error}\n{output}"));
    assert_eq!(parsed["revealed"], true);
    assert_eq!(
        parsed["value"], VALUE,
        "`--reveal` with `--json` did not carry the value: {output}"
    );
}

#[test]
fn a_listing_names_the_versions_that_are_stored_and_a_removal_takes_one() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let passphrase = password_file(home.path());

    let (_, output) = ksp_in(home.path(), &["secret", "ls"], None);
    assert_eq!(
        output.trim(),
        "",
        "an empty store listed something: {output}"
    );

    for value in ["first-value", "second-value"] {
        let (code, output) = ksp_in(
            home.path(),
            &[
                "secret",
                "set",
                "db_password",
                "--name",
                "db_password",
                "--passphrase-file",
                passphrase.to_str().unwrap(),
            ],
            Some(value),
        );
        assert_eq!(code, exit::SUCCESS, "secret set failed: {output}");
    }

    // Two versions of one record: the chain is append-only, so both are stored.
    let (code, output) = ksp_in(home.path(), &["secret", "ls"], None);
    assert_eq!(code, exit::SUCCESS, "secret ls failed: {output}");
    assert!(
        output.contains("db_password  level=user  version=1"),
        "{output}"
    );
    assert!(
        output.contains("db_password  level=user  version=2"),
        "{output}"
    );

    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "rm",
            "db_password",
            "--version",
            "1",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "secret rm failed: {output}");

    let (_, output) = ksp_in(home.path(), &["secret", "ls"], None);
    assert!(
        !output.contains("version=1"),
        "the removed version is still listed: {output}"
    );
    assert!(
        output.contains("version=2"),
        "the removal took more than the version it named: {output}"
    );
}

/// Parse one JSON object out of a command's output.
///
/// The emitter writes one object per invocation, so a parse failure here is the
/// defect under test rather than a test bug: `"unserializable"` parses as a
/// string, which is why the assertion below checks the *shape* and not merely
/// that the bytes are valid JSON.
fn json_object(output: &str) -> serde_json::Value {
    serde_json::from_str(output.trim())
        .unwrap_or_else(|error| panic!("the output is not one JSON document ({error}): {output}"))
}

/// A listing is one object carrying a `kind` tag and a `records` array.
///
/// Before this feature `secret ls --json` printed the string
/// `"unserializable"`: valid JSON, no fields, and no error anywhere. An agent
/// that read it reported zero records and nothing said why.
#[test]
fn a_listing_is_one_object_with_a_records_array() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let passphrase = password_file(home.path());

    // An empty store is the case that distinguishes "nothing stored" from "the
    // listing could not be produced".
    let (code, output) = ksp_in(home.path(), &["--json", "secret", "ls"], None);
    assert_eq!(code, exit::SUCCESS, "secret ls --json failed: {output}");
    let value = json_object(&output);
    assert!(
        value.is_object(),
        "a listing must be an object, not {value}"
    );
    assert_eq!(value["kind"], "records", "{value}");
    assert_eq!(
        value["records"].as_array().map(Vec::len),
        Some(0),
        "an empty store must emit an empty array: {value}"
    );

    for value in ["first-value", "second-value"] {
        let (code, output) = ksp_in(
            home.path(),
            &[
                "secret",
                "set",
                "db_password",
                "--name",
                "db_password",
                "--passphrase-file",
                passphrase.to_str().unwrap(),
            ],
            Some(value),
        );
        assert_eq!(code, exit::SUCCESS, "secret set failed: {output}");
    }

    let (code, output) = ksp_in(home.path(), &["--json", "secret", "ls"], None);
    assert_eq!(code, exit::SUCCESS, "secret ls --json failed: {output}");
    let value = json_object(&output);
    assert_eq!(value["kind"], "records", "{value}");
    let records = value["records"]
        .as_array()
        .unwrap_or_else(|| panic!("records is not an array: {value}"));
    assert_eq!(records.len(), 2, "two versions are stored: {value}");
    for record in records {
        assert!(record["record"].is_string(), "{record}");
        assert_eq!(record["level"], "user", "{record}");
        assert!(record["version"].is_number(), "{record}");
    }

    // The text output must not have moved: the same two versions, one per line.
    let (code, output) = ksp_in(home.path(), &["secret", "ls"], None);
    assert_eq!(code, exit::SUCCESS, "secret ls failed: {output}");
    assert!(
        output.contains("db_password  level=user  version=1"),
        "{output}"
    );
    assert!(
        output.contains("db_password  level=user  version=2"),
        "{output}"
    );
}

/// `admin list` emits the same shape, and names every level the text output does.
#[test]
fn the_admin_listing_is_one_object_naming_every_level() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let passphrase = password_file(home.path());
    let agent = enrol(home.path(), "laptop");

    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "set",
            "s1",
            "--name",
            "n",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        Some("a-value"),
    );
    assert_eq!(code, exit::SUCCESS, "secret set failed: {output}");

    let (code, output) = ksp_in(home.path(), &["--json", "admin", "list"], None);
    assert_eq!(code, exit::SUCCESS, "admin list --json failed: {output}");
    let value = json_object(&output);
    assert_eq!(value["kind"], "records", "{value}");
    let records = value["records"]
        .as_array()
        .unwrap_or_else(|| panic!("records is not an array: {value}"));
    assert!(
        !records.is_empty(),
        "the user level holds a record: {value}"
    );

    // The text output names the same levels. A JSON shape that dropped one would
    // be a narrower answer than the text, which is the defect this guards.
    let (code, text) = ksp_in(home.path(), &["admin", "list"], None);
    assert_eq!(code, exit::SUCCESS, "admin list failed: {text}");
    assert!(text.contains("level=user"), "{text}");
    let _ = agent;
}

#[test]
fn the_backend_description_names_the_capability_and_a_lease_refusal_exits_seven() {
    let home = tempfile::tempdir().unwrap();

    let (code, output) = ksp_in(home.path(), &["backend", "list"], None);
    assert_eq!(code, exit::SUCCESS, "backend list failed: {output}");
    assert!(output.contains("backend=file"), "{output}");
    assert!(
        output.contains("capability=None"),
        "file holds no deadline mechanism: {output}"
    );

    // The refusal a mint would give, from the same gate, and it has to name the
    // mechanism rather than only the number.
    let (code, output) = ksp_in(home.path(), &["backend", "test"], None);
    assert_eq!(
        code,
        exit::CAPABILITY_REFUSAL,
        "a lease on file must be refused: {output}"
    );
    assert!(output.contains("admitted=false"), "{output}");
    assert!(output.contains("capability None"), "{output}");
}

#[test]
fn an_inspection_prints_scope_and_expiry_and_never_a_key() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "agent-7");
    let (token, recipient_key_hex) = write_token(home.path(), agent);

    let (code, output) = ksp_in(
        home.path(),
        &["token", "inspect", "--token", token.to_str().unwrap()],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "token inspect failed: {output}");
    assert!(output.contains("jti=jti-surface-1"), "{output}");
    assert!(output.contains(&format!("agent={agent}")), "{output}");
    assert!(
        output.contains(&format!("level={}", Level::Agent(agent).path_segment())),
        "{output}"
    );
    // The opaque identifier, not the name: a record's name is sealed inside the
    // blob with its value, so no metadata surface can print it without the key.
    assert!(
        output.contains(&format!(
            "s3cr3t-id-1  level={}  version=1",
            Level::Agent(agent).path_segment()
        )),
        "{output}"
    );
    assert!(
        !output.contains("db_password"),
        "the inspection printed a sealed name: {output}"
    );
    assert!(
        !output.contains(&recipient_key_hex),
        "the inspection printed the agent's public key: {output}"
    );
}

#[test]
fn an_inspection_of_a_token_this_host_does_not_trust_exits_two() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "agent-7");
    let (token, _) = write_token(home.path(), agent);

    // Re-pin *her* key to one that did not sign the token: a delivery is
    // verified against the principal's enrolled key, not the admin's anchor. The
    // claims inside are perfectly well formed, so only the verification can
    // refuse this.
    let layout = Layout::new(home.path());
    let mut deployment = ksp::deployment::Deployment::load(&layout).unwrap();
    deployment.user_signing_key =
        Some(ksp_identity::SigningSecretKey::generate().verifying_public());
    deployment.save(&layout).unwrap();

    let (code, output) = ksp_in(
        home.path(),
        &["token", "inspect", "--token", token.to_str().unwrap()],
        None,
    );
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "a token signed by nobody this host pinned must exit 2: {output}"
    );
}

// ---------------------------------------------------------------------------
// The issuance ledger: what this host minted, and what it holds against a token
// ---------------------------------------------------------------------------

/// Seed one row, so the readers below are tested with a ledger they control.
///
/// `crates/ksp/tests/issuance.rs` covers the writer — a mint records through
/// this same append, end to end through the binary. This helper exists so that
/// `token list`, `token revoke` and `ksp run` can be tested against a row whose
/// values the test chose, without a mint and a proof in the way.
fn record_an_issuance(home: &Path, token_id: &str, agent: ksp_types::AgentId) {
    let layout = Layout::new(home);
    let ledger = ksp_identity::IssuanceLedger::at(layout.issuance_ledger());
    ledger
        .publish_recorded(
            ksp_identity::Issuance {
                token_id: token_id.to_string(),
                agent,
                secret: OpaqueSecretId::new("s3cr3t-id-1"),
                version: RecordVersion(1),
                deadline: 2_000,
                policy_revision: 1,
            },
            || Ok::<(), std::convert::Infallible>(()),
        )
        .unwrap();
}

#[test]
fn a_listing_of_an_empty_ledger_lists_no_token_and_claims_only_this_host() {
    let home = tempfile::TempDir::new().unwrap();

    let (code, output) = ksp_in(home.path(), &["token", "list"], None);

    assert_eq!(
        code,
        exit::SUCCESS,
        "an empty ledger is not a failure: {output}"
    );
    assert!(
        !output.contains("token_id="),
        "an empty ledger prints no row: {output}"
    );
    assert!(
        output.contains("this host"),
        "the listing must scope itself to this host: {output}"
    );
    assert!(
        !output.contains("no tokens exist"),
        "a local absence is not a global claim: {output}"
    );
}

#[test]
fn a_listing_names_what_this_host_minted() {
    let home = tempfile::TempDir::new().unwrap();
    record_an_issuance(home.path(), "jti-1", some_agent());

    let (code, output) = ksp_in(home.path(), &["token", "list"], None);

    assert_eq!(code, exit::SUCCESS, "{output}");
    assert!(output.contains("jti-1"), "{output}");
    assert!(
        output.contains(&format!("agent={}", some_agent())),
        "{output}"
    );
    assert!(output.contains("version=1"), "{output}");

    // The standing is not `live`, and that is the point of the column. This
    // fixture records a ledger entry and **no sealed record** — the state a
    // `--consume` run leaves behind — so the row must not offer a copy.
    //
    // It reads `unknown: the deployment or store could not be opened` rather than
    // `consumed`, because the fixture has no deployment to look the record up
    // under. That is the honest answer for this state: this host could not check,
    // which is a different claim from "it checked and found nothing". Reporting
    // `live` here — which this test used to assert — told an operator a copy
    // existed while `ksp run` would refuse the token with exit 6.
    assert!(
        !output.contains("live"),
        "the listing must not offer a copy it has not confirmed: {output}"
    );
    assert!(
        output.contains("unknown:") || output.contains("consumed"),
        "an unconfirmed copy is unknown or consumed, never live: {output}"
    );
}

#[test]
fn a_revocation_marks_the_identifier_and_states_what_it_does_not_reach() {
    let home = tempfile::TempDir::new().unwrap();
    record_an_issuance(home.path(), "jti-1", some_agent());

    let (code, output) = ksp_in(home.path(), &["token", "revoke", "jti-1"], None);
    assert_eq!(code, exit::SUCCESS, "{output}");
    assert!(output.contains("jti-1"), "{output}");
    let lowered = output.to_lowercase();
    assert!(
        lowered.contains("does not recall") && lowered.contains("copy"),
        "the command must state that a copy survives: {output}"
    );

    let (code, listing) = ksp_in(home.path(), &["token", "list"], None);
    assert_eq!(code, exit::SUCCESS, "{listing}");
    assert!(
        listing.contains("revoked"),
        "the listing must show the mark: {listing}"
    );
}

#[test]
fn revoking_an_identifier_this_host_never_minted_exits_two_and_changes_nothing() {
    let home = tempfile::TempDir::new().unwrap();
    record_an_issuance(home.path(), "jti-1", some_agent());
    let layout = Layout::new(home.path());
    let before = std::fs::read(layout.issuance_ledger()).unwrap();

    let (code, output) = ksp_in(home.path(), &["token", "revoke", "minted-elsewhere"], None);

    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "nothing to revoke is a refusal, not a silent success: {output}"
    );
    assert!(
        output.contains("minted elsewhere is unknown here"),
        "the refusal must not accuse the token: {output}"
    );
    assert_eq!(
        std::fs::read(layout.issuance_ledger()).unwrap(),
        before,
        "a refused mark must not touch the ledger"
    );
}

/// Give the policy one grant: `agent-7` may receive `s3cr3t-id-1`.
fn grant_the_share(home: &Path, agent: ksp_types::AgentId) {
    let (code, output) = ksp_in(
        home,
        &[
            "admin",
            "policy",
            "--agent",
            &agent.to_string(),
            "--secret",
            "s3cr3t-id-1",
        ],
        Some(PASSWORD),
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");
}

#[test]
fn withdrawing_a_grant_signs_one_narrower_revision_and_records_it() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    grant_the_share(home.path(), some_agent());

    let layout = Layout::new(home.path());
    let before = ksp::admin::read_policy(&layout).unwrap();
    // Without this the assertions below would pass on a policy that never had
    // the grant at all.
    assert_eq!(
        before.shareable_secrets(),
        [OpaqueSecretId::new("s3cr3t-id-1")]
    );

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "revoke", "--secret", "s3cr3t-id-1"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin revoke failed: {output}");
    assert!(
        output.contains("grant=secret s3cr3t-id-1"),
        "the report must name what was withdrawn: {output}"
    );
    // Derived from the revision the grant actually signed, not from a literal.
    // The literal was `2` while `write_policy` hardcoded `1`: enrolment wrote
    // revision 1 and the grant overwrote it at revision 1, so a revision that
    // never advanced was asserted as correct. A withdrawal is one revision more
    // than the policy it narrows, whatever that revision is.
    let expected = before.revision() + 1;
    assert!(
        output.contains(&format!("policy_revision={expected}")),
        "a withdrawal is one revision, not a re-issue: expected {expected}, got {output}"
    );
    assert!(
        output.contains("does not recall a copy taken earlier"),
        "the report must not claim a recall it cannot perform: {output}"
    );

    let after = ksp::admin::read_policy(&layout).unwrap();
    // The same property as the report check above: the withdrawal advanced the
    // revision by one. A literal `2` here was a claim about provisioning order.
    assert_eq!(
        after.revision(),
        expected,
        "the recorded policy carries the revision the report named"
    );
    assert!(
        after.shareable_secrets().is_empty(),
        "the withdrawn secret is still shareable"
    );
    assert_eq!(
        after.shareable_agents(),
        [some_agent()],
        "a withdrawal removes one grant, not the whole agent list"
    );
}

#[test]
fn a_run_of_a_token_minted_under_a_withdrawn_grant_refuses_and_delivers_nothing() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "agent-7");
    let (token, _) = write_token(home.path(), agent);
    // The token is one this host minted, so the ledger can say what it was.
    record_an_issuance(home.path(), "jti-surface-1", agent);

    let (code, output) = ksp_in(
        home.path(),
        &["token", "inspect", "--token", token.to_str().unwrap()],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "inspect failed: {output}");

    // The grant this token was minted under.
    grant_the_share(home.path(), agent);
    let (code, output) = ksp_in(
        home.path(),
        &["admin", "revoke", "--agent", &agent.to_string()],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin revoke failed: {output}");

    let (code, output) = ksp_in(
        home.path(),
        &[
            "run",
            "--token",
            token.to_str().unwrap(),
            "--env",
            "KSP_TEST_SECRET",
            "--",
            "printenv",
            "KSP_TEST_SECRET",
        ],
        None,
    );
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "a token whose grant was withdrawn must refuse: {output}"
    );
    assert!(
        !output.contains(VALUE),
        "a refused run delivered the value: {output}"
    );

    // With the record removed, the two refusals are distinguishable: a run that
    // consults the ledger first exits 2, and one that reads the record first
    // exits 6 because the record is gone. The point of the check is that a
    // withdrawn token never reaches the store.
    let layout = Layout::new(home.path());
    std::fs::remove_dir_all(layout.store_root()).unwrap();
    let (code, output) = ksp_in(
        home.path(),
        &[
            "run",
            "--token",
            token.to_str().unwrap(),
            "--env",
            "KSP_TEST_SECRET",
            "--",
            "printenv",
            "KSP_TEST_SECRET",
        ],
        None,
    );
    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "the ledger must be consulted before the record is read: {output}"
    );
}

#[test]
fn a_host_with_no_ledger_runs_and_says_it_cannot_tell_whether_the_token_was_revoked() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "agent-7");
    let (token, _) = write_token(home.path(), agent);

    // `admin init` creates both ledger files, because provisioning creates every
    // protected root. The state this test is about is a host that has no ledger at
    // all — one where the files were removed, or where the deployment predates
    // them — so the files are removed here rather than assumed absent.
    //
    // Removing them is the honest fixture: the code path that answers "cannot
    // judge" still exists and still has to be reachable, and a test that only
    // passed because provisioning happened not to create the file would stop
    // covering it the moment provisioning changed.
    let layout = ksp::config::Layout::new(home.path().to_path_buf());
    for path in [layout.issuance_ledger(), layout.withdrawals_ledger()] {
        let _ = std::fs::remove_file(&path);
    }

    let (code, output) = ksp_in(
        home.path(),
        &[
            "run",
            "--token",
            token.to_str().unwrap(),
            "--env",
            "KSP_TEST_SECRET",
            "--",
            "printenv",
            "KSP_TEST_SECRET",
        ],
        None,
    );
    assert_eq!(
        code,
        exit::SUCCESS,
        "an unminted-here token is not an accusation: {output}"
    );
    assert!(
        output.contains(VALUE),
        "the value was not delivered: {output}"
    );
    assert!(
        output.contains("cannot tell whether it was revoked"),
        "a host that cannot judge the token must say so: {output}"
    );
}

#[test]
fn purge_expired_states_that_the_file_backend_has_no_deadline_mechanism() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());

    let (code, output) = ksp_in(home.path(), &["secret", "purge-expired"], None);

    assert_eq!(
        code,
        exit::SUCCESS,
        "a backend that cannot sweep is an answer, not a failure: {output}"
    );
    assert!(output.contains("capability=None"), "{output}");
    assert!(
        output.contains("removed=0") && output.contains("selected=0"),
        "the counts must be stated: {output}"
    );
    assert!(
        output.contains("this backend has no deadline mechanism"),
        "the command must say why it removed nothing: {output}"
    );
    assert!(
        output.contains("says nothing about whether a copy still exists"),
        "the note must not let zero removals read as an erasure: {output}"
    );
}

#[test]
fn gc_runs_unbounded_and_says_the_bound_was_not_the_limit() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());

    let (code, output) = ksp_in(home.path(), &["secret", "gc"], None);

    assert_eq!(code, exit::SUCCESS, "gc failed: {output}");
    assert!(
        output.contains("bound_reached=false"),
        "gc has no bound to reach: {output}"
    );
    assert!(
        output.contains("not_yet_due=0"),
        "no armed record is claimed to exist on a backend with no mechanism: {output}"
    );
}

#[test]
fn purge_expired_on_an_unprovisioned_host_names_the_missing_deployment() {
    let home = tempfile::TempDir::new().unwrap();

    let (code, output) = ksp_in(home.path(), &["secret", "purge-expired"], None);

    assert_eq!(
        code,
        exit::MISSING_KEY,
        "a host with no deployment cannot sweep: {output}"
    );
    assert!(
        output.contains("not provisioned"),
        "the refusal must name what is missing: {output}"
    );
}

#[test]
fn admin_put_seals_to_the_recorded_public_key_and_the_user_opens_it_with_her_own_password() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let passphrase = password_file(home.path());

    // No password on stdin: only the value. The command has no use for hers.
    let (code, output) = ksp_in(
        home.path(),
        &["admin", "put", "admin-written", "--name", "rotation-note"],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "admin put failed: {output}");
    assert!(
        output.contains("version=1"),
        "the first put is version one: {output}"
    );

    // The user reads it back with her vault password. If `put` had sealed to a
    // key it invented instead of the recorded one, this is where it fails.
    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "get",
            "admin-written",
            "--reveal",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the user cannot open it: {output}");
    assert!(
        output.contains(VALUE),
        "the value did not survive: {output}"
    );

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "put", "admin-written", "--name", "rotation-note"],
        Some("the second value"),
    );
    assert_eq!(code, exit::SUCCESS, "the second put failed: {output}");
    assert!(
        output.contains("version=2"),
        "a put after a put is a new version, not an overwrite: {output}"
    );
}

#[test]
fn admin_put_refuses_when_the_recipient_public_key_was_never_recorded() {
    let home = tempfile::TempDir::new().unwrap();
    // `admin init` alone: identifiers and anchor, no user and no policy.
    let (code, output) = ksp_in(
        home.path(),
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin init failed: {output}");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "put", "orphan", "--name", "orphan"],
        Some("a value nobody could read"),
    );

    assert_eq!(
        code,
        exit::MISSING_KEY,
        "a put with nothing to seal to must refuse: {output}"
    );
    assert!(
        output.contains("recipient public key was never recorded"),
        "the refusal must name what is missing: {output}"
    );
    let layout = Layout::new(home.path());
    assert!(
        !layout.store_root().join("p").exists(),
        "a refused put must not write a record"
    );
}

/// Misfit L: the binding moves, the files do not.
///
/// Rewriting the persisted principal UUID must not make the old principal's
/// directory read as the new one's. The lookup fails loudly — it finds nothing —
/// rather than adopting records that belong to somebody else.
#[test]
fn moving_the_persisted_principal_does_not_read_the_old_principals_records() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let (code, output) = ksp_in(
        home.path(),
        &["admin", "put", "db_password", "--name", "db_password"],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "admin put failed: {output}");

    let (code, output) = ksp_in(home.path(), &["admin", "list"], None);
    assert_eq!(code, exit::SUCCESS, "{output}");
    assert!(output.contains("db_password"), "{output}");

    let layout = Layout::new(home.path());
    let mut deployment = ksp::deployment::Deployment::load(&layout).unwrap();
    let old = deployment.user;
    deployment.user =
        ksp_types::PrincipalId::parse("8a0e2d4c-1b3f-4a5e-9c7d-0e1f2a3b4c5d").unwrap();
    deployment.save(&layout).unwrap();
    assert_ne!(deployment.user, old);

    let (code, output) = ksp_in(home.path(), &["admin", "list"], None);
    assert_eq!(code, exit::SUCCESS, "{output}");
    assert!(
        !output.contains("db_password"),
        "a moved binding read the old principal's records: {output}"
    );
}

#[test]
fn admin_list_names_every_level_without_a_value_and_admin_audit_is_empty_at_first() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "agent-7");
    // One agent-level record from the token fixture, one user-level from the admin.
    let _token = write_token(home.path(), agent);
    let (code, output) = ksp_in(
        home.path(),
        &["admin", "put", "admin-written", "--name", "rotation-note"],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "admin put failed: {output}");

    let (code, output) = ksp_in(home.path(), &["admin", "list"], None);

    assert_eq!(code, exit::SUCCESS, "admin list failed: {output}");
    assert!(
        output.contains(&format!(
            "s3cr3t-id-1  level={}  version=1",
            Level::Agent(agent).path_segment()
        )),
        "an agent-level record must be listed under its own level: {output}"
    );
    assert!(
        output.contains(&format!(
            "admin-written  level={}  version=1",
            Level::Admin.path_segment()
        )),
        "an admin-written record is listed at the admin level, which is its provenance: {output}"
    );
    assert!(
        !output.contains(VALUE),
        "a listing can see a path and never a value: {output}"
    );

    let (code, output) = ksp_in(home.path(), &["admin", "audit"], None);
    assert_eq!(
        code,
        exit::SUCCESS,
        "an empty journal is not a failure: {output}"
    );
    assert!(
        output.contains("0 entry/entries, 0 unreadable"),
        "the audit must state that it found nothing rather than stay silent: {output}"
    );
}

/// Write one acknowledgement and one report the way S4 does, so `admin audit`
/// reads the same files a consume would leave behind — including the signer: a
/// consume report is signed by the agent's own enrolled key, not by the admin.
fn journal_one_deletion(home: &Path, signer: ReportSigner, agent: ksp_types::AgentId) {
    use ksp::consume::{FileJournal, FileReports};
    use ksp_deletion::ReportSink;
    use ksp_deletion::journal::AcknowledgementEvent;
    use ksp_deletion::report::SignedReport;
    use ksp_types::evidence::{DeletionReport, Outcome as ReportOutcome};

    let layout = Layout::new(home);
    let actor = ActorId::Agent(agent);
    let journal = Acknowledgements::new(FileJournal::new(layout.journal_root()));
    journal
        .record(&AcknowledgementEvent {
            intent_id: "intent-1".to_string(),
            version: 1,
            actor,
            event_id: "event-1".to_string(),
            acknowledged_at: 1_700_000_000,
        })
        .unwrap();

    let anchor = Anchor::load(&layout.admin_anchor_file()).unwrap();
    let report = DeletionReport {
        intent_id: "intent-1".to_string(),
        actor,
        signer_key_id: "agent-signing-1".to_string(),
        reason: "the lease deadline passed".to_string(),
        outcome: ReportOutcome::Success,
        reported_deleted_at: 1_700_000_100,
        level: Level::Agent(agent),
        secret_id: OpaqueSecretId::new("s3cr3t-id-1"),
        version: 1,
    };
    let signed = match signer {
        // The honest signer: the agent's own protected key, the way consume does it.
        ReportSigner::Agent => {
            let stored = StoredEnrolment::load(&layout.enrolment_file(&agent.to_string())).unwrap();
            let store = ksp_key_lifecycle::KeyStore::new(
                ksp_key_lifecycle::KeyRoot::open(layout.agent_key_root()).unwrap(),
            );
            let bundle = store.load_agent(&stored.pin()).unwrap();
            bundle
                .with_signing_secret(|seed| {
                    SignedReport::sign(&ksp_deletion::EvidenceSigningKey::from_seed(*seed), report)
                })
                .unwrap()
        }
        // A key nobody enrolled: the signature exists and this host cannot tie
        // it to the actor that made the claim.
        ReportSigner::Foreign => {
            let foreign = ksp_deletion::EvidenceSigningKey::from_seed([9u8; 32]);
            let _ = anchor;
            SignedReport::sign(&foreign, report).unwrap()
        }
    };
    FileReports::new(layout.journal_root().join("reports"))
        .write(&ksp_types::cbor::encode(&signed).unwrap())
        .unwrap();
}

/// Which key signs the fixture report.
#[derive(Clone, Copy)]
enum ReportSigner {
    /// The agent's own enrolled key, as consume signs.
    Agent,
    /// A key this host has no pin for.
    Foreign,
}

/// The journal type, so the helpers above stay readable.
type Acknowledgements = ksp_deletion::journal::AcknowledgementJournal<ksp::consume::FileJournal>;

#[test]
fn admin_audit_reads_the_journal_and_verifies_the_report_beside_it() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "agent-7");
    journal_one_deletion(home.path(), ReportSigner::Agent, agent);

    let (code, output) = ksp_in(home.path(), &["admin", "audit"], None);

    assert_eq!(code, exit::SUCCESS, "admin audit failed: {output}");
    assert!(
        output.contains("acknowledgement  intent=intent-1"),
        "the journal entry must be listed: {output}"
    );
    assert!(
        output.contains("is not a deletion time"),
        "an acknowledgement time must not read as a deletion: {output}"
    );
    assert!(
        output.contains("report  intent=intent-1") && output.contains("verified=true"),
        "the unsigned-and-verified report must say so: {output}"
    );
}

#[test]
fn a_report_this_host_cannot_verify_is_printed_and_exits_two() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let agent = enrol(home.path(), "agent-7");
    journal_one_deletion(home.path(), ReportSigner::Foreign, agent);

    let (code, output) = ksp_in(home.path(), &["admin", "audit"], None);

    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "an unverifiable claim must not read as a clean audit: {output}"
    );
    assert!(
        output.contains("verified=false"),
        "the line must show that it did not verify: {output}"
    );
    assert!(
        output.contains("1 unreadable or unverified"),
        "the count must name what did not verify: {output}"
    );
}

#[test]
fn the_binary_rejects_vault_unseal_and_vault_seal_by_name() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());

    for name in ["unseal", "seal"] {
        let (code, output) = ksp_in(home.path(), &["vault", name], None);
        assert_eq!(
            code,
            exit::POLICY_DENIAL,
            "an unknown subcommand is a usage error, not an internal one: {output}"
        );
        assert!(
            output.contains("unrecognized subcommand"),
            "`vault {name}` must be rejected by the parser, not implemented: {output}"
        );
    }
}

#[test]
fn vault_rekey_prints_a_phrase_that_recovers_exactly_the_file_it_wrote() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let layout = Layout::new(home.path());
    let vault_file = ksp::vault::VaultHome::new(layout.root().to_path_buf()).vault_file();
    let before = std::fs::read(&vault_file).unwrap();

    let (code, output) = ksp_in(
        home.path(),
        &["vault", "rekey", "--threshold", "2", "--shares", "3"],
        Some(PASSWORD),
    );
    assert_eq!(code, exit::SUCCESS, "vault rekey failed: {output}");
    assert!(
        output.contains("threshold=2  shares=3"),
        "the split must be stated: {output}"
    );
    assert!(
        output.contains("the previous phrase no longer recovers this vault"),
        "a rekey retires the old phrase, and the operator has to be told: {output}"
    );

    // The phrase the operator now holds reconstructs the bytes on disk, not some
    // other bundle: that equality is what makes the printed phrase worth writing
    // down.
    let stored = std::fs::read(&vault_file).unwrap();
    assert_ne!(
        stored, before,
        "a rekey re-seals under a fresh salt; identical bytes would mean the old \
         phrase still recovers it"
    );
    let start = output
        .find(ksp_identity::RecoveryPhrase::HEADER)
        .expect("the phrase is printed");
    let phrase = ksp_identity::RecoveryPhrase::parse(&output[start..]).unwrap();
    let recovered = phrase.recover().unwrap();
    assert_eq!(
        recovered.as_bytes(),
        stored.as_slice(),
        "the phrase must recover the file that exists"
    );

    // The password is unchanged, and the vault still opens with it.
    let passphrase = password_file(home.path());
    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "set",
            "after-rekey",
            "--name",
            "after-rekey",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        Some(VALUE),
    );
    assert_eq!(
        code,
        exit::SUCCESS,
        "the re-sealed vault must still open with the same password: {output}"
    );
}

#[test]
fn a_rekey_with_the_wrong_password_leaves_the_vault_untouched() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let layout = Layout::new(home.path());
    let vault_file = ksp::vault::VaultHome::new(layout.root().to_path_buf()).vault_file();
    let before = std::fs::read(&vault_file).unwrap();

    let (code, output) = ksp_in(
        home.path(),
        &["vault", "rekey"],
        Some("the wrong password entirely"),
    );

    assert_eq!(
        code,
        exit::MISSING_KEY,
        "a password that does not open the vault cannot re-share it: {output}"
    );
    assert!(
        output.contains("could not be opened with that password"),
        "the refusal must say what failed: {output}"
    );
    assert_eq!(
        std::fs::read(&vault_file).unwrap(),
        before,
        "a refused rekey must not touch the only copy of the sealed vault"
    );
}

#[test]
fn secret_share_refuses_on_a_backend_with_no_deadline_mechanism() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let passphrase = password_file(home.path());
    let token = home.path().join("agent-7.token");

    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "share",
            "personal_api_key",
            "--agent",
            &some_agent().to_string(),
            "--name",
            "personal_api_key",
            "--out",
            token.to_str().unwrap(),
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        None,
    );

    assert_eq!(
        code,
        exit::CAPABILITY_REFUSAL,
        "a share is a lease, and `file` cannot enforce one: {output}"
    );
    assert!(
        output.contains("no sweep proof"),
        "the refusal must name what was observed, not the lease length: {output}"
    );
    assert!(
        !token.exists(),
        "a refused share must not leave a token behind"
    );
}

#[test]
fn token_lease_refuses_and_names_the_escrow_it_would_need() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());

    let (code, output) = ksp_in(home.path(), &["token", "lease"], None);

    assert_eq!(
        code,
        exit::CAPABILITY_REFUSAL,
        "a lease over an existing copy is not a thing this host can build: {output}"
    );
    assert!(
        output.contains("sealed to the agent's key"),
        "the refusal must give the structural reason: {output}"
    );
    assert!(
        output.contains("token mint") && output.contains("secret share"),
        "the refusal must name what does work: {output}"
    );
}

#[test]
fn admin_revoke_refuses_a_policy_the_pinned_key_did_not_sign() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    grant_the_share(home.path(), some_agent());

    // A policy a host attacker could plant: the admin's identifiers, an extra
    // grant, and a signature from a key this host does not pin. `withdraw` would
    // re-sign that body with the admin key on its way out, so the refusal has to
    // happen before the withdrawal.
    let layout = Layout::new(home.path());
    let valid = ksp::admin::read_policy(&layout).unwrap();
    let foreign = ksp_identity::AdminSigningKey::generate();
    let forged = ksp_identity::Policy::new(
        &foreign,
        ksp_identity::KeyId::new("admin-2026"),
        ksp_identity::PolicyBody::new(
            valid.revision() + 1,
            valid.vault().clone(),
            *valid.user(),
            valid.trusted().clone(),
            vec![
                OpaqueSecretId::new("s3cr3t-id-1"),
                OpaqueSecretId::new("a-secret-the-admin-never-granted"),
            ],
            vec![ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap()],
            valid.max_ttl_for(&Level::User),
            valid.max_ttl_for(&Level::Agent(
                ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap(),
            )),
            0,
            u64::MAX,
        ),
    )
    .unwrap();
    ksp::admin::write_signed_policy(&layout, &forged).unwrap();
    let planted = std::fs::read(layout.policy_file()).unwrap();

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "revoke", "--secret", "s3cr3t-id-1"],
        None,
    );

    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "a policy this host cannot attribute to the admin must not be re-signed: {output}"
    );
    assert!(
        output.contains("not signed by the pinned admin key"),
        "the refusal must name the reason: {output}"
    );
    assert_eq!(
        std::fs::read(layout.policy_file()).unwrap(),
        planted,
        "a refused withdrawal must leave the planted policy exactly as it found it"
    );
}

#[test]
fn a_rekey_whose_write_fails_leaves_the_vault_whole_and_prints_no_phrase() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let layout = Layout::new(home.path());
    let vault_file = ksp::vault::VaultHome::new(layout.root().to_path_buf()).vault_file();
    let before = std::fs::read(&vault_file).unwrap();

    // The staged file cannot be created, so the write fails after the shares
    // were cut. The previous vault must survive it byte for byte, and no phrase
    // may reach the operator: a phrase for a file that was never written opens
    // nothing.
    let staged = vault_file.with_extension("new");
    std::fs::create_dir_all(&staged).unwrap();

    let (code, output) = ksp_in(home.path(), &["vault", "rekey"], Some(PASSWORD));

    assert_ne!(code, exit::SUCCESS, "the rekey cannot succeed: {output}");
    assert!(
        !output.contains(ksp_identity::RecoveryPhrase::HEADER),
        "no phrase may be printed when the write did not happen: {output}"
    );
    assert_eq!(
        std::fs::read(&vault_file).unwrap(),
        before,
        "the only copy of the vault must survive a failed rekey"
    );
}

#[test]
fn vault_init_refuses_and_names_the_command_that_creates_a_vault() {
    let home = tempfile::TempDir::new().unwrap();

    let (code, output) = ksp_in(home.path(), &["vault", "init"], None);

    assert_eq!(
        code,
        exit::CAPABILITY_REFUSAL,
        "a vault with no deployment to seal to is refused: {output}"
    );
    assert!(
        output.contains("admin user add"),
        "the refusal must name the command that does work: {output}"
    );
    let layout = Layout::new(home.path());
    assert!(
        !ksp::vault::VaultHome::new(layout.root().to_path_buf())
            .vault_file()
            .exists(),
        "a refused init must write no vault"
    );
}

#[test]
fn status_discloses_the_backend_mechanism_posture_and_freshness() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());

    let (code, output) = ksp_in(home.path(), &["status"], None);

    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    assert!(
        output.contains("capability:  None"),
        "the file backend has no deadline mechanism: {output}"
    );
    assert!(
        output.contains("mechanism:"),
        "the mechanism line must be present: {output}"
    );
    assert!(
        output.contains("confinement:") && output.contains("barrier:"),
        "the posture is disclosed, and measured rather than asserted: {output}"
    );
    assert!(
        output.contains("freshness:"),
        "replay detection must be disclosed, including its absence: {output}"
    );
    assert!(
        !output.contains("correct-horse"),
        "a disclosure never carries a value: {output}"
    );
}

#[test]
fn status_measures_the_posture_on_a_home_with_no_store_and_no_enrolment() {
    let home = tempfile::TempDir::new().unwrap();

    let (code, output) = ksp_in(home.path(), &["status"], None);

    assert_eq!(
        code,
        exit::SUCCESS,
        "status needs no deployment to describe the backend and the host: {output}"
    );
    // The regression this binds: the first version built the *run's* ruleset, whose
    // store and key-root rules refuse a path that does not exist yet, so a fresh
    // home reported `unavailable` — a false statement about the kernel caused by
    // the command's own inputs.
    //
    // The expected confinement now depends on the platform, because macOS is a
    // supported host with no kernel path confinement. What must never happen is
    // the *home* being named as the reason, so the assertion reads the host's own
    // answer from the adapter rather than assuming one host's.
    let confinement = output
        .lines()
        .find(|line| line.contains("confinement:"))
        .unwrap_or_else(|| panic!("the status output has a confinement line: {output}"));
    assert!(
        !confinement.contains("No such file"),
        "a fresh home must not be reported as a host that cannot reach a path: {confinement}"
    );
    match LANDLOCK_CONFINEMENT.availability() {
        AdapterAvailability::Available => assert!(
            confinement.contains("confinement enforced"),
            "a fresh home must not be reported as a host that cannot confine: {confinement}"
        ),
        AdapterAvailability::Unavailable { .. } => {
            // `ksp init` wrote `portable_confinement` for this host, so the line
            // names the adapter that established nothing and says so.
            assert!(
                confinement.contains("adapter portable_confinement"),
                "a host with no kernel confinement must name the adapter that \
                 established nothing: {confinement}"
            );
            assert!(
                confinement.contains("none"),
                "and it must state the guarantee: {confinement}"
            );
        }
    }
    let layout = Layout::new(home.path());
    assert!(
        !layout.store_root().exists(),
        "status must not create the store to measure the host"
    );
}

/// The status line names the adapter that established each capability.
///
/// # Why this test exists and the posture tests cannot replace it
///
/// The WP05 review found that both postures rendered `no adapter` on a host
/// where the mechanism was in force. The cause was not the posture types alone:
/// `run_status` called `restrict_then_launch` directly, and nothing in
/// production called the adapter that stamps the name. A change of call site is
/// invisible to a test that calls the adapter itself, so only the rendered
/// output of the real binary can catch it.
///
/// `restrict_self` confines the calling process for the rest of its life, so
/// this path cannot be exercised in-process. Running `ksp status` is the only
/// honest way to reach it.
///
/// # The expected value comes from the adapter, not from this test
///
/// The two gate hosts disagree: the colima VM has Landlock and macOS does not.
/// Asking the adapter which host this is keeps the assertion true on both,
/// instead of asserting one host's answer on the other.
#[test]
fn status_names_the_adapter_that_established_each_capability() {
    let home = tempfile::TempDir::new().unwrap();
    let (code, output) = ksp_in(home.path(), &["status"], None);
    assert_eq!(
        code,
        exit::SUCCESS,
        "status must describe a fresh home: {output}"
    );

    let line = |prefix: &str| -> String {
        output
            .lines()
            .find(|line| line.contains(prefix))
            .unwrap_or_else(|| panic!("the status output has a {prefix} line: {output}"))
            .to_string()
    };

    let confinement = line("confinement:");
    match LANDLOCK_CONFINEMENT.availability() {
        AdapterAvailability::Available => {
            let expected = format!("adapter {}", LANDLOCK_CONFINEMENT.name());
            assert!(
                confinement.contains(&expected),
                "a host that enforces Landlock must name the adapter that enforced it; \
                 expected `{expected}`; got: {confinement}"
            );
            assert!(
                confinement.contains(LANDLOCK_CONFINEMENT.guarantee().label()),
                "the line must carry the adapter's own guarantee level: {confinement}"
            );
        }
        AdapterAvailability::Unavailable { .. } => {
            assert!(
                confinement.contains("adapter portable_confinement"),
                "a host with no Landlock must name the adapter that ran instead of \
                 claiming enforcement: {confinement}"
            );
            assert!(
                confinement.contains("none"),
                "and it must carry that adapter's own guarantee: {confinement}"
            );
            assert!(
                !confinement.contains("enforced"),
                "nothing is enforced on this host, and the line must not suggest \
                 otherwise: {confinement}"
            );
        }
    }

    let barrier = line("barrier:");
    if barrier.contains("barrier unavailable") {
        assert!(
            barrier.contains("no adapter"),
            "a run with no barrier has no adapter to name: {barrier}"
        );
    } else {
        assert!(
            !barrier.contains("no adapter"),
            "a barrier that exists must name the adapter that allocated it: {barrier}"
        );
        // And the name is one the closed set spells, not a free string.
        assert!(
            AdapterName::ALL
                .iter()
                .any(|name| barrier.contains(&format!("adapter {name}"))),
            "the named adapter must be one the closed set spells: {barrier}"
        );
    }
}
