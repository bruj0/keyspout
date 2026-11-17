//! Confinement is required for a delivery, and it reaches one level (Misfit A).
//!
//! # What a unit test cannot prove
//!
//! `landlock` can be applied and still grant the wrong subtree. The only
//! assertion that means anything is the kernel's answer to a real `open()` from
//! inside the delivered child, so this file launches the real binary, lets it
//! confine itself, and has the child probe paths with `ls`/`cat`. The reason
//! strings the child prints come from the kernel through libc, not from Keyspout:
//! a Keyspout message would prove only that Keyspout decided something.
//!
//! The same home is probed four ways, so a ruleset that granted the store root
//! (the misfit) would be caught by the sibling probe alone, while a ruleset that
//! granted nothing would be caught by the own-level probe.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

use ksp::config::Layout;
use ksp::exit;
use ksp::keys::{Anchor, StoredEnrolment};
use ksp_identity::delivery::{self, VerifiedRecipientKey};
use ksp_identity::{AdminSigningKey, KeyId, UnsignedEnrolment};
use ksp_record::{ContentBlob, Record, RecordEnvelope, commit_version};
use ksp_types::{
    ActorId, AgentId, BoundMetadata, ContentKey, Level, OpaqueSecretId, RecordVersion, VaultId,
};

/// The value delivered to the child, so a refusal that leaked it would be caught.
const VALUE: &str = "correct-horse-battery-staple";

/// Run `ksp` with this home and return the exit code and both streams
/// separately.
///
/// The separation is load-bearing for the containment probe: the shell's verdict
/// goes to stdout and the kernel's `strerror` text to stderr, and merging them
/// would destroy the order that says which probe refused.
fn ksp_streams(home: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    configure(home);
    let output = Command::new(ksp())
        .env("KSP_HOME", home)
        .env("LC_ALL", "C")
        .args(args)
        .output()
        .expect("the binary runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn ksp() -> &'static str {
    env!("CARGO_BIN_EXE_ksp")
}

/// Run `ksp` with this home and return the exit code and both streams.
///
/// `LC_ALL=C` because the assertions read the kernel's own `strerror` text:
/// "Permission denied" is `EACCES`, and a translated string would hide that.
/// Give this home the capability configuration a real host has.
///
/// `ksp init` is the production probe: it writes the strongest configuration
/// this host can satisfy and never overwrites one that exists, so calling it on
/// every invocation is safe. A host with no configuration has no adapter for
/// either capability, and every unseal and every delivery refuses — the
/// product's intended first-run behaviour, and therefore a precondition of every
/// test below that reaches one.
fn configure(home: &std::path::Path) {
    let _ = Command::new(ksp())
        .env("KSP_HOME", home)
        .arg("init")
        .output();
}

fn ksp_in(home: &std::path::Path, args: &[&str]) -> (i32, String) {
    configure(home);
    let output = Command::new(ksp())
        .env("KSP_HOME", home)
        .env("LC_ALL", "C")
        .args(args)
        .output()
        .expect("the binary runs");
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.code().unwrap_or(-1), text)
}

/// Enrol one agent and return the principal UUID the enrolment issued.
fn enrol(home: &std::path::Path, name: &str) -> AgentId {
    let (code, stdout) = ksp_in(home, &["agent", "enroll", "--agent", name]);
    assert_eq!(code, exit::SUCCESS, "enrol {name} failed: {stdout}");
    let start = stdout
        .find("agent:")
        .unwrap_or_else(|| panic!("no agent identity in {stdout}"));
    let uuid: String = stdout[start + "agent:".len()..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit() || *c == '-')
        .collect();
    AgentId::parse(&uuid).unwrap_or_else(|_| panic!("not a canonical UUID: {uuid}"))
}

fn metadata(version: u32, agent: AgentId) -> BoundMetadata {
    BoundMetadata {
        vault_id: VaultId::new("vault-1"),
        user_id: ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        level: Level::Agent(agent),
        secret_id: OpaqueSecretId::new("s3cr3t-id-1"),
        version,
    }
}

/// Act as Alice: pin the anchor, record the enrolment, seal one record and one
/// delivery to the agent's recipient key.
fn provision(home: &std::path::Path, agent: AgentId) -> (std::path::PathBuf, BoundMetadata) {
    let layout = Layout::new(home);
    let admin = AdminSigningKey::generate();
    Anchor {
        key_id: KeyId::new("admin-2026"),
        key: admin.verifying_public(),
    }
    .save(&layout.admin_anchor_file())
    .unwrap();

    let stored = StoredEnrolment::load(&layout.enrolment_file(&agent.to_string())).unwrap();
    let unsigned = UnsignedEnrolment::bind(
        ActorId::Agent(agent),
        stored.signing_key,
        stored.recipient_key,
        stored.signing_key_id.clone(),
        stored.recipient_key_id.clone(),
    )
    .unwrap();
    let record = admin
        .sign_enrolment(unsigned, KeyId::new("admin-2026"))
        .unwrap();
    let confirmed = *record.fingerprint();
    let recipient = VerifiedRecipientKey::confirm(&record, &confirmed).unwrap();

    let meta = metadata(1, agent);
    let content_key = ContentKey::generate();
    let aad = meta.bound_aad().unwrap();
    let blob = ContentBlob::seal(&content_key, b"db_password", VALUE.as_bytes(), &aad).unwrap();
    let envelope =
        RecordEnvelope::seal(&content_key, &stored.recipient_key.to_bytes(), &meta).unwrap();
    // The level is a table row: created by `ensure_level`, so its mode is the
    // table's `0730` rather than the process's umask (misfit B).
    ksp::layout::ensure_level(layout.root(), &meta.vault_id, meta.user_id, &meta.level).unwrap();
    let sealed_record = Record {
        metadata: meta.clone(),
        blob,
        envelope,
    };
    let store = ksp_backend::file::FileStore::new(layout.store_root()).unwrap();
    commit_version(&store, &meta, &sealed_record).unwrap();

    let selected = ksp_identity::SelectedRecord {
        secret: meta.secret_id.clone(),
        version: RecordVersion(1),
        policy: None,
    };
    let header = ksp_identity::DeliveryHeader::new(
        meta.vault_id.clone(),
        meta.user_id,
        KeyId::new("admin-2026"),
        agent,
        stored.signing_key,
        stored.recipient_key,
        stored.signing_key_id.clone(),
        stored.recipient_key_id.clone(),
        meta.level.clone(),
        Level::User,
        Level::Agent(agent).path_segment(),
        vec![selected.clone()],
        u64::MAX,
        "jti-confinement-1".to_string(),
    )
    .unwrap();
    let keys = ksp_identity::SelectedContentKeys::new(
        &header,
        vec![(selected, ksp_identity::DeliveredKey::Content(content_key))],
    )
    .unwrap();
    // The lease is Alice's, so the host pins *her* enrolled public key: the run
    // path verifies a delivery against it and never against the admin's key.
    let user_signer = ksp_identity::SigningSecretKey::generate();
    ksp::deployment::Deployment {
        vault: meta.vault_id.clone(),
        // Two principals, because a deployment always has two: the admin who
        // signed the policy and the user who owns the record.
        admin: ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        user: meta.user_id,
        user_name: Some("alice".to_string()),
        user_account: None,
        admin_key_id: KeyId::new("admin-2026"),
        admin_vault_signing_key_id: None,
        admin_vault_recipient_key_id: None,
        admin_vault_recipient_key: None,
        user_signing_key_id: Some(KeyId::new("alice-ed25519-1")),
        user_signing_key: Some(user_signer.verifying_public()),
        user_recipient_key_id: None,
        user_recipient_key: None,
    }
    .save(&layout)
    .unwrap();

    let artifact = delivery::seal(&user_signer, &header, &keys, &recipient).unwrap();

    let token_path = home.join(format!("{agent}.token"));
    std::fs::write(&token_path, artifact.to_bytes().unwrap()).unwrap();
    (token_path, meta)
}

/// The kernel's output for one probe, from its name to the next probe.
///
/// Probing by block rather than by line is deliberate: a denial is one line and
/// the next probe's name is the only thing that ends it, and matching the text
/// alone would let the denial of one probe satisfy the assertion for another.
fn probe_block(stderr: &str, probe: &str) -> String {
    let start = stderr
        .find(&format!("probe {probe}\n"))
        .unwrap_or_else(|| panic!("no {probe} probe in {stderr}"));
    let rest = &stderr[start + probe.len() + "probe \n".len()..];
    let end = rest.find("probe ").unwrap_or(rest.len());
    rest[..end].to_string()
}

/// Put a readable placeholder in `vault.cbor`.
///
/// The mode is exact because the layout audit refuses a drifted root, and a
/// `0600` file is what the table expects: the point of the test is what the child
/// can open, not whether this fixture happens to look like a vault.
fn write_vault_placeholder(layout: &Layout) {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(layout.vault_file())
        .unwrap();
    file.write_all(b"not really sealed").unwrap();
    file.sync_all().unwrap();
    // `mode` is masked by the process umask; chmod states the final mode.
    std::fs::set_permissions(layout.vault_file(), PermissionsExt::from_mode(0o600)).unwrap();
}

/// The level directory of `meta` inside this home's store.
fn level_directory(home: &std::path::Path, meta: &BoundMetadata) -> std::path::PathBuf {
    Layout::new(home)
        .store_root()
        .join(ksp_record::RecordPath::directory(
            &meta.vault_id,
            meta.user_id,
            Some(&meta.level),
        ))
}

#[test]
fn the_delivered_child_reaches_its_own_level_and_nothing_else() {
    let home = tempfile::tempdir().unwrap();
    let agent = enrol(home.path(), "agent-7");
    // A second agent on the same host is the sibling this misfit is about.
    let stranger = enrol(home.path(), "agent-8");
    let (token, meta) = provision(home.path(), agent);

    let layout = Layout::new(home.path());
    // Give every probed path something *readable* to hold, so a refusal cannot be
    // confused with an absence: the child is denied the file, not told it is
    // missing. `vault.cbor` is never read by `run`, so a placeholder is enough;
    // the admin anchor is the one `provision` wrote and must not be touched.
    write_vault_placeholder(&layout);
    assert!(
        layout.admin_anchor_file().is_file(),
        "provisioning must have written the anchor this test probes"
    );
    // Created through the layout table, because that is how a level comes into
    // being: `create_dir_all` takes the process's umask and a `0775` level is a
    // drifted root the run gate refuses before confinement is ever tried.
    let stranger_meta = metadata(1, stranger);
    let sibling = ksp::layout::ensure_level(
        home.path(),
        &stranger_meta.vault_id,
        stranger_meta.user_id,
        &stranger_meta.level,
    )
    .unwrap();
    std::fs::write(sibling.join("marker"), b"sibling secret").unwrap();
    let own = level_directory(home.path(), &meta);
    assert!(own.is_dir(), "the record's own level must exist");

    let key = layout
        .agent_key_root()
        .join("agent")
        .join(format!("{agent}.key"));
    assert!(key.is_file(), "the agent key must exist");

    // One probe per path, plus the child's own level: the same ruleset must deny
    // the first four and grant the last.
    //
    // Each probe **opens** the path in a subshell. `test -r` and `ls -d` would not do:
    // Landlock restricts `open`, not `stat`, so a stat-based probe would report a
    // denied path as readable. Nothing is redirected — `/dev/null` is outside every
    // rule and the shell's own redirection would be the thing denied — so the
    // kernel's message arrives on stderr and the verdict on stdout, in the order
    // the probes ran. The subshell matters: a failed `exec` redirection aborts the
    // shell that runs it, so the probe must not run in the child's own process.
    let script = "\
o() { printf 'probe %s\\n' \"$1\" >&2; \
if ( exec 3<\"$2\" ); then printf 'allowed %s\\n' \"$1\"; \
else printf 'denied %s\\n' \"$1\"; fi }; \
o vault \"$1\"; o admin \"$2\"; o sibling \"$3\"; o key \"$4\"; o own \"$5\"; echo DONE";
    let args = vec![
        "run".to_string(),
        "--token".to_string(),
        token.display().to_string(),
        "--".to_string(),
        "/bin/sh".to_string(),
        "-c".to_string(),
        script.to_string(),
        "probe".to_string(),
        layout.vault_file().display().to_string(),
        layout.admin_anchor_file().display().to_string(),
        sibling.display().to_string(),
        key.display().to_string(),
        own.display().to_string(),
    ];
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, stdout, stderr) = ksp_streams(home.path(), &refs);
    assert_eq!(
        code,
        exit::SUCCESS,
        "the confined child did not run: {stdout}{stderr}"
    );
    assert!(
        stdout.contains("DONE"),
        "the probe did not finish: {stdout}{stderr}"
    );

    // The kernel's answer, not Keyspout's: `EACCES` arrives as libc's text.
    for probe in ["vault", "admin", "sibling", "key"] {
        assert!(
            stdout.contains(&format!("denied {probe}\n")),
            "{probe} must be refused, got {stdout}{stderr}"
        );
        let block = probe_block(&stderr, probe);
        assert!(
            block.contains("Permission denied"),
            "{probe} must be denied by the kernel, got {block}"
        );
        assert!(
            !block.contains("No such file"),
            "{probe} must exist and be denied, not missing: {block}"
        );
    }
    assert!(
        stdout.contains("allowed own\n"),
        "the record's own level must stay reachable: {stdout}{stderr}"
    );
    assert!(
        !stdout.contains(VALUE),
        "the delivered value must not appear in the child's output: {stdout}"
    );
}

#[test]
fn a_level_that_cannot_be_granted_refuses_with_seven_and_starts_nothing() {
    let home = tempfile::tempdir().unwrap();
    // Probe this host's configuration, so `__deliver` has an adapter to
    // establish. Without it the refusal is the missing configuration, which is a
    // different sentence from the ruleset refusing a path.
    configure(home.path());
    let marker = home.path().join("launched");

    // `__deliver` with the same arguments `ksp run --consume` passes, except that
    // the level it must confine to does not exist. A ruleset cannot be built over
    // a path that is not there, and the delivery must refuse rather than run the
    // child unconfined.
    let missing = home.path().join("no-such-level");
    let mut child = Command::new(ksp())
        .env("KSP_HOME", home.path())
        .env("LC_ALL", "C")
        .args([
            "__deliver",
            "--env",
            "KSP_TEST_SECRET",
            "--level",
            missing.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            &format!("touch {}", marker.display()),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the binary runs");
    // The plaintext arrives the way `ksp run --consume` sends it, so the refusal
    // is exercised on the path that has a value to lose.
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(VALUE.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().expect("the binary finishes");
    let text = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(exit::CAPABILITY_REFUSAL),
        "an unconfined delivery must exit 7: {text}"
    );
    // T014: the sentence names the mechanism, the ABI and the path that refused.
    assert!(
        text.contains("required confinement cannot be established"),
        "the refusal must say what it is: {text}"
    );
    assert!(text.contains("landlock"), "no mechanism in {text}");
    assert!(text.contains("ABI"), "no ABI in {text}");
    assert!(
        text.contains(missing.to_str().unwrap()),
        "the path that refused must be named: {text}"
    );
    assert!(
        text.contains("the child was not started"),
        "the refusal must state its consequence: {text}"
    );
    assert!(
        !marker.exists(),
        "a refused delivery launched the child anyway"
    );
    assert!(
        !text.contains(VALUE),
        "a refused delivery wrote the plaintext somewhere: {text}"
    );
}

#[test]
fn status_reports_the_optional_posture_and_never_refuses() {
    let home = tempfile::tempdir().unwrap();

    // A home with no store, no enrolment and no keys: the measurement must not
    // depend on any of them, and a host that cannot confine must be *reported*
    // rather than refused — an operator needs the disclosure of a broken host.
    let (code, stdout) = ksp_in(home.path(), &["status"]);
    assert_eq!(code, exit::SUCCESS, "status must not refuse: {stdout}");
    assert!(
        stdout.contains("confinement "),
        "the status line must disclose confinement: {stdout}"
    );
    assert!(
        stdout.contains("SoftRequirement"),
        "status reports the optional posture, not the delivery's required one: {stdout}"
    );
    assert!(
        !stdout.contains("required confinement cannot be established"),
        "status must not print a delivery refusal: {stdout}"
    );
}
