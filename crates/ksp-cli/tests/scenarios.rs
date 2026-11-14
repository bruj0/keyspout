//! The integration scenarios: one per user story this binary can reach.
//!
//! # Why these are here and not in `wired_surface`
//!
//! That file holds the *command contract* — what one command prints or exits
//! with. These hold the story: provision, write, share or steal, and observe what
//! an adversary gets. Each one names the user story it answers and the property
//! that would be false if the story failed.
//!
//! # What is NOT here, and why
//!
//! User Story 3 (native expiry on `valkey`) and User Story 6 (a backend test
//! against valkey and S3) need a host whose configured backend is not `file`, and
//! `ksp token mint`, `secret share` and the sweeps open the local store only. That
//! is a wiring gap rather than a scenario that fails, and it is recorded in the
//! WP history instead of being faked here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ksp_cli::config::Layout;
use ksp_cli::exit;
use ksp_cli::keys::{Anchor, StoredEnrolment};
use ksp_identity::delivery::{self, VerifiedRecipientKey};
use ksp_identity::{SelectedRecord, UnsignedEnrolment};
use ksp_record::{ContentBlob, Record, RecordEnvelope, commit_version};
use ksp_types::{
    ActorId, BoundMetadata, ContentKey, Level, OpaqueSecretId, RecordVersion, VaultId,
};

/// A value nobody could guess by accident, so finding it anywhere is a leak.
const VALUE: &str = "correct-horse-battery-staple";
/// The vault password every invocation in this file uses.
const PASSWORD: &str = "a long enough password";

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

/// Enrol an agent under a display name and return the principal UUID it issued.
///
/// The name is metadata; the UUID printed beside it is the identity every later
/// command names.
fn enrol_agent(home: &Path, name: &str) -> ksp_types::AgentId {
    let (code, output) = ksp_in(home, &["agent", "enroll", "--agent", name], None);
    assert_eq!(code, exit::SUCCESS, "enrol {name} failed: {output}");
    printed_identity(&output)
}

/// Read the `agent:<uuid>` identity out of an enrolment report.
fn printed_identity(output: &str) -> ksp_types::AgentId {
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

/// Build an agent-level delivery for `agent`, the way a mint would, but with the
/// libraries: `ksp token mint` refuses on `file` (exit 7) because a lease cannot
/// be armed here.
fn write_token(home: &Path, agent: ksp_types::AgentId) -> PathBuf {
    let layout = Layout::new(home);
    let anchor = Anchor::load(&layout.admin_anchor_file()).unwrap();
    let admin = ksp_cli::admin::load_admin(&layout, &anchor).unwrap();
    let deployment = ksp_cli::deployment::Deployment::load(&layout).unwrap();
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
    ksp_cli::layout::ensure_level(
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
        "jti-scenario-1".to_string(),
    )
    .unwrap();
    let keys =
        ksp_identity::SelectedContentKeys::new(&header, vec![(selected, content_key)]).unwrap();
    // Alice signs her own lease, with the key her vault holds: the mint never
    // touches the admin's half (spec §3.7 step 2).
    let unsealed = ksp_cli::secret::unseal(&layout, PASSWORD.as_bytes()).unwrap();
    let artifact = unsealed
        .vault
        .with_signing_key(|signer| delivery::seal(signer, &header, &keys, &recipient))
        .unwrap();
    let token = home.join(format!("{agent}.token"));
    std::fs::write(&token, artifact.to_bytes().unwrap()).unwrap();
    token
}

/// Every file under `root`, so a scan cannot miss a directory it did not expect.
fn every_file(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

/// User Story 1: the admin publishes a value and never holds the means to read it.
#[test]
fn us1_a_value_the_admin_put_is_absent_from_storage_and_from_every_listing() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "put", "admin-written", "--name", "rotation-note"],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "admin put failed: {output}");

    // The store holds ciphertext. If the plaintext were anywhere under it, the
    // admin — who can read every byte of that store — would hold the value.
    let layout = Layout::new(home.path());
    for path in every_file(layout.root()) {
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes
                .windows(VALUE.len())
                .any(|window| window == VALUE.as_bytes()),
            "the plaintext is in {}",
            path.display()
        );
    }

    // And nothing this host prints to describe the record carries it either.
    let (code, output) = ksp_in(home.path(), &["admin", "list"], None);
    assert_eq!(code, exit::SUCCESS);
    assert!(
        !output.contains(VALUE),
        "the listing leaked the value: {output}"
    );

    // Alice, who holds the vault password, can read it: the value exists, it is
    // simply not the admin's to read.
    let passphrase = password_file(home.path());
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
    assert_eq!(
        code,
        exit::SUCCESS,
        "Alice cannot read her own record: {output}"
    );
    assert!(
        output.contains(VALUE),
        "the value did not survive: {output}"
    );
}

/// User Story 2: a phrase recovers the vault after the original is gone.
#[test]
fn us2_two_of_three_shares_recover_a_deleted_vault_and_the_value_inside_it() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let passphrase = password_file(home.path());

    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "set",
            "personal_api_key",
            "--name",
            "personal_api_key",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        Some(VALUE),
    );
    assert_eq!(code, exit::SUCCESS, "secret set failed: {output}");

    let (code, output) = ksp_in(
        home.path(),
        &["vault", "rekey", "--threshold", "2", "--shares", "3"],
        Some(PASSWORD),
    );
    assert_eq!(code, exit::SUCCESS, "vault rekey failed: {output}");
    let start = output
        .find(ksp_identity::RecoveryPhrase::HEADER)
        .expect("the phrase is printed");
    let printed = ksp_identity::RecoveryPhrase::parse(&output[start..]).unwrap();

    // The original is destroyed: this is the loss the phrase exists for.
    let layout = Layout::new(home.path());
    let vault_file = ksp_cli::vault::VaultHome::new(layout.root().to_path_buf()).vault_file();
    std::fs::remove_file(&vault_file).unwrap();

    // Two of three shares, and nothing else.
    let two =
        ksp_identity::RecoveryPhrase::new(ksp_types::Threshold(2), printed.shares()[..2].to_vec())
            .unwrap();
    let recovered = two.recover().unwrap();
    std::fs::write(&vault_file, recovered.as_bytes()).unwrap();

    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "get",
            "personal_api_key",
            "--reveal",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(
        code,
        exit::SUCCESS,
        "the recovered vault did not open the record: {output}"
    );
    assert!(
        output.contains(VALUE),
        "the value did not come back: {output}"
    );
}

/// Misfit J: a display name is not an identity.
///
/// Enrolment issues one UUID. A second enrolment under the same name is refused
/// and names the principal that already holds it, rather than minting a second
/// identity a human cannot tell apart from the first.
#[test]
fn a_repeated_display_name_does_not_mint_a_second_principal() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let agent = enrol_agent(home.path(), "agent-7");

    let (code, output) = ksp_in(
        home.path(),
        &["agent", "enroll", "--agent", "agent-7"],
        None,
    );
    assert_eq!(
        code,
        exit::INTERNAL,
        "a repeated display name must not enrol a second principal: {output}"
    );
    assert!(
        output.contains(&agent.to_string()),
        "the refusal must name the UUID that already holds the name: {output}"
    );

    // A different name is a different principal, and gets a different UUID.
    let second = enrol_agent(home.path(), "agent-8");
    assert_ne!(agent, second, "two enrolments are two identities");
}

/// User Story 4: a stolen token file is inert.
/// T043 and T045: the whole session, and the capability it accepted.
///
/// # What this binds that no unit test can
///
/// The pieces were built in separate work packages. This is the only test that
/// runs the first-run probe, the configuration reader, the resolver, the unseal,
/// the delivery, the audit chain and the status document **in one session**, in
/// that order — so a subsystem that was never wired is caught here rather than by
/// a reader of the deployment (the "end to end" TDD target).
///
/// It also binds NFR-009: the status line and the audit record name the same
/// guarantee level. A later reader has to be able to tell an accepted absence
/// from an unnoticed one, which needs both halves to agree.
///
/// The consume half of the sequence is `sc008_consume`, which builds the intent
/// that authorises the removal; it runs in the VM part of the gate.
#[test]
fn the_session_discloses_the_capability_it_established_and_records_the_absence() {
    let home = tempfile::TempDir::new().unwrap();

    // 1. The first run. `ksp init` probes the host and writes the strongest
    //    configuration it can satisfy, which is what makes every command below
    //    reachable at all (FR-021).
    let (code, output) = ksp_in(home.path(), &["init"], None);
    assert_eq!(code, exit::SUCCESS, "ksp init failed: {output}");
    assert!(
        Layout::new(home.path()).capability_config_file().is_file(),
        "the first run must leave a configuration behind: {output}"
    );

    // 2. Provision and write, through the binary.
    provision_vault(home.path());
    let passphrase = password_file(home.path());
    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "set",
            "session_secret",
            "--name",
            "session_secret",
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        Some(VALUE),
    );
    assert_eq!(
        code,
        exit::SUCCESS,
        "a configured host must be able to unseal and write: {output}"
    );

    // 3. Deliver. The token is built with the libraries because `ksp token mint`
    //    refuses on the `file` backend, which is a different feature's fact.
    let agent = enrol_agent(home.path(), "agent-7");
    let token = write_token(home.path(), agent);
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
    assert_eq!(code, exit::SUCCESS, "the delivery failed: {output}");
    assert!(
        output.contains(VALUE),
        "the child must receive the value it was delivered: {output}"
    );

    // 4. Read the status, and take the guarantee level from it.
    let (code, status) = ksp_in(home.path(), &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {status}");
    let confinement = status
        .lines()
        .filter(|line| line.starts_with("host:"))
        .find(|line| line.contains("path confinement"))
        .unwrap_or_else(|| panic!("no confinement row in {status}"));
    assert!(
        status.contains("platform:"),
        "the document names the platform: {status}"
    );

    // 4b. NFR-010: the delivery says the absence in its own output, before the
    //     child exists — not only in `status`. A record nobody printed and a
    //     line nobody read are the same to the operator launching a child.
    if confinement.contains("(none)") {
        assert!(
            output.contains("no path confinement is enforced"),
            "a delivery that ran unconfined must say so on its own output, not \
             only in `status`: the status says {confinement}\nthe delivery said:\n{output}"
        );
        assert!(
            output.contains("`optional`"),
            "and it names the level that allowed it: {output}"
        );
    } else {
        assert!(
            !output.contains("no path confinement is enforced"),
            "a confined delivery must not announce an absence it does not have: \
             the status says {confinement}\nthe delivery said:\n{output}"
        );
    }

    // 5. The audit log, read from the chain rather than from one principal's
    //    view. A delivery that ran with no mechanism behind it records the
    //    acceptance; one that was confined does not, because there is nothing to
    //    accept.
    //
    //    The record is signed by the agent, so it lands in the user's chain and
    //    not the admin's — which is why this reads every segment on disk instead
    //    of asking one principal's view (NFR-009, and the two-principal
    //    boundary: an acceptance only the admin could write would be an
    //    acceptance nobody records).
    let records = chain_records(home.path());
    let accepted: Vec<&ksp_types::evidence::CapabilityAcceptance> = records
        .iter()
        .filter_map(|signed| signed.record.acceptance())
        .collect();

    if confinement.contains("(none)") {
        assert_eq!(
            accepted.len(),
            1,
            "an unenforced capability must be recorded exactly once, not only \
             printed: the status says {confinement}",
        );
        assert_eq!(
            accepted[0].capability,
            ksp_types::HostCapability::PathConfinement,
            "the record names the capability it accepted"
        );
        assert_eq!(
            accepted[0].guarantee,
            ksp_types::GuaranteeLevel::None,
            "and the guarantee level, which is what makes an accepted absence \
             readable"
        );
        assert_eq!(
            accepted[0].adapter.as_str(),
            "portable_confinement",
            "and the adapter that established nothing"
        );
    } else {
        assert!(
            accepted.is_empty(),
            "a confined delivery accepted nothing, so nothing is recorded: the \
             status says {confinement}, and the log holds {} acceptance(s)",
            accepted.len()
        );
    }

    // 6. And the chain still verifies: an acceptance that broke the links would
    //    be a record nobody can rely on (criterion 6).
    let (code, verify) = ksp_in(home.path(), &["audit", "verify"], None);
    assert_eq!(
        code,
        exit::SUCCESS,
        "a log holding an acceptance must still verify: {verify}"
    );
}

/// Every audit record the home holds, read from the segments on disk.
///
/// The chain is per signing principal, so the delivery's record lives in the
/// user's chain and an admin-scoped view does not show it. Reading the segments
/// directly is what a later auditor does, and it is the only way this test can see
/// what was actually written.
fn chain_records(home: &Path) -> Vec<ksp_deletion::SignedAuditRecord> {
    let root = Layout::new(home).audit_root();
    let chain = ksp_deletion::AuditChain::new(&root);

    let mut found = Vec::new();
    let Ok(actors) = std::fs::read_dir(&root) else {
        return found;
    };
    for actor in actors.flatten() {
        let Ok(principal_id) =
            ksp_types::metadata::PrincipalId::parse(&actor.file_name().to_string_lossy())
        else {
            continue;
        };
        let Ok(files) = std::fs::read_dir(actor.path()) else {
            continue;
        };
        for file in files.flatten() {
            let name = file.file_name().to_string_lossy().to_string();
            let Some(key_id) = name
                .strip_prefix("segment-")
                .and_then(|rest| rest.strip_suffix(".cbor"))
            else {
                continue;
            };
            found.extend(chain.read(principal_id, key_id).expect("the segment reads"));
        }
    }
    found
}

#[test]
fn us4_a_stolen_token_is_inert_without_the_recipients_private_key() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let agent = enrol_agent(home.path(), "agent-7");
    let token = write_token(home.path(), agent);

    // The artifact is a file an attacker can copy, so it must not contain the
    // value and must not contain a private half.
    let bytes = std::fs::read(&token).unwrap();
    assert!(
        !bytes
            .windows(VALUE.len())
            .any(|window| window == VALUE.as_bytes()),
        "the token file carries the plaintext"
    );

    // The precise claim: the artifact does not open with another recipient's
    // private half. This is the HPKE unwrap an attacker with a stolen file tries.
    let layout = Layout::new(home.path());
    let artifact = ksp_identity::DeliveryArtifact::from_bytes(&bytes).unwrap();
    // Her key, pinned from the deployment: the artifact is a lease she signed.
    let signer = ksp_cli::deployment::user_verifying_key(&layout).unwrap();
    let verified = delivery::verify(&artifact, &signer).unwrap();
    let key_root = ksp_key_lifecycle::KeyRoot::open(layout.agent_key_root()).unwrap();
    let store = ksp_key_lifecycle::KeyStore::new(key_root);
    let stranger = enrol_agent(home.path(), "agent-8");
    let stranger = StoredEnrolment::load(&layout.enrolment_file(&stranger.to_string())).unwrap();
    let bundle = store.load_agent(&stranger.pin()).unwrap();
    let opened = bundle.with_recipient_secret(|secret| delivery::open(&verified, secret));
    assert!(
        opened.is_err(),
        "another recipient's private half must not open this delivery"
    );

    // And a host with only the copied file opens nothing either.
    let elsewhere = tempfile::TempDir::new().unwrap();
    let stolen = elsewhere.path().join("stolen.token");
    std::fs::copy(&token, &stolen).unwrap();
    let (code, output) = ksp_in(
        elsewhere.path(),
        &[
            "run",
            "--token",
            stolen.to_str().unwrap(),
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
        exit::MISSING_KEY,
        "a token without its key material is missing key material: {output}"
    );
    assert!(
        !output.contains(VALUE),
        "a stolen token delivered the value: {output}"
    );
}

/// User Story 5: one agent's delivery is not another agent's to use.
#[test]
fn us5_a_delivery_for_one_agent_stays_inert_where_only_another_agent_is_enrolled() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let agent = enrol_agent(home.path(), "agent-7");
    let stranger = enrol_agent(home.path(), "agent-8");
    assert_ne!(agent, stranger, "two enrolments are two identities");
    let token = write_token(home.path(), agent);
    let layout = Layout::new(home.path());

    // The first agent is gone from this host; only the stranger's keys remain.
    // The token still names the first, and the stranger's key is not a substitute.
    std::fs::remove_file(layout.enrolment_file(&agent.to_string())).unwrap();
    std::fs::remove_file(
        layout
            .agent_key_root()
            .join("agent")
            .join(format!("{agent}.key")),
    )
    .unwrap();

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
        exit::MISSING_KEY,
        "another agent's presence must not open this delivery: {output}"
    );
    assert!(
        !output.contains(VALUE),
        "the value crossed agents: {output}"
    );
}

/// The redaction scan: every describing command, one value, no leak.
#[test]
fn every_describing_command_redacts_the_one_value_in_the_store() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let agent = enrol_agent(home.path(), "agent-7");
    let token = write_token(home.path(), agent);
    let passphrase = password_file(home.path());
    // A real user-level value, so `secret get` has something to redact.
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
    let token_arg = token.to_str().unwrap().to_string();
    let passphrase_arg = passphrase.to_str().unwrap().to_string();

    let commands: Vec<Vec<&str>> = vec![
        vec!["admin", "list"],
        vec!["admin", "audit"],
        vec!["token", "list"],
        vec!["backend", "list"],
        vec!["secret", "ls"],
        vec!["token", "inspect", "--token", &token_arg],
        vec![
            "secret",
            "get",
            "db_password",
            "--passphrase-file",
            &passphrase_arg,
        ],
    ];
    for args in &commands {
        let (code, output) = ksp_in(home.path(), args, None);
        // Some of these refuse on an unprovisioned or absent artifact; the claim
        // is about what they print, not about their exit code.
        assert!(
            !output.contains(VALUE),
            "`{}` printed the value (exit {code}): {output}",
            args.join(" ")
        );
    }

    // The positive control: `--reveal` is the one route that prints it, so a scan
    // that found nothing anywhere would be a scan that could not see it at all.
    let (code, output) = ksp_in(
        home.path(),
        &[
            "secret",
            "get",
            "db_password",
            "--reveal",
            "--passphrase-file",
            &passphrase_arg,
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the control failed: {output}");
    assert!(
        output.contains(VALUE),
        "--reveal is the route that prints a value, and it did not: {output}"
    );
}

/// User Story 9, rotation clause: a rotation changes future minting and does not
/// revoke an artifact already sealed to the old key.
#[test]
fn us9_rotation_archives_the_old_bundle_and_an_old_artifact_still_opens_with_it() {
    let home = tempfile::TempDir::new().unwrap();
    provision_vault(home.path());
    let agent = enrol_agent(home.path(), "agent-7");
    let token = write_token(home.path(), agent);
    let layout = Layout::new(home.path());

    let before = StoredEnrolment::load(&layout.enrolment_file(&agent.to_string())).unwrap();
    let old_pin = before.pin();
    let (code, output) = ksp_in(
        home.path(),
        &[
            "agent",
            "rotate",
            "--agent",
            &agent.to_string(),
            "--signing-key-id",
            "agent-ed25519-2",
            "--recipient-key-id",
            "agent-x25519-2",
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "agent rotate failed: {output}");
    assert!(
        output.contains("signing_key_id=agent-ed25519-2"),
        "the rotation must state the new IDs: {output}"
    );

    // The pin now names the new keys, and the old ones are still on disk.
    let after = StoredEnrolment::load(&layout.enrolment_file(&agent.to_string())).unwrap();
    assert_ne!(
        after.signing_key.to_bytes(),
        before.signing_key.to_bytes(),
        "the signing key did not change"
    );
    let archive = layout.agent_key_root().join("agent").join("archive");
    let archived: Vec<PathBuf> = every_file(&archive);
    assert_eq!(
        archived.len(),
        1,
        "the replaced bundle must be retained, got {archived:?}"
    );

    // The artifact was sealed before the rotation. Opening it needs the archived
    // private half, and that is the point: rotation does not recall it.
    let verified = delivery::verify(
        &ksp_identity::DeliveryArtifact::from_bytes(&std::fs::read(&token).unwrap()).unwrap(),
        &ksp_cli::deployment::user_verifying_key(&layout).unwrap(),
    )
    .unwrap();
    let retained =
        ksp_identity::AgentKeyBundle::from_bytes(&std::fs::read(&archived[0]).unwrap(), &old_pin)
            .unwrap();
    assert!(
        retained
            .with_recipient_secret(|secret| delivery::open(&verified, secret))
            .is_ok(),
        "the retained bundle still opens the artifact it was sealed for"
    );

    // The new bundle must not: otherwise the rotation would have replaced the
    // key without changing which key the old artifact answers to.
    let store = ksp_key_lifecycle::KeyStore::new(
        ksp_key_lifecycle::KeyRoot::open(layout.agent_key_root()).unwrap(),
    );
    let current = store.load_agent(&after.pin()).unwrap();
    assert!(
        current
            .with_recipient_secret(|secret| delivery::open(&verified, secret))
            .is_err(),
        "the new key must not open an artifact sealed to the old one"
    );
}
