//! Layout drift, as the operator and the delivery path meet it.
//!
//! `ksp status` must name a widened protected root, and a delivery must refuse
//! with exit `7` rather than read records through it. Both are FR-014, and both
//! are checked here against the real binary so the wiring — not just the audit
//! function — is what passes.
//!
//! The cross-uid half of the boundary lives in `principals.rs`, which needs root.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use ksp::exit;

/// The vault password every provisioning step in this file uses.
const PASSWORD: &str = "a long enough password";
/// An agent principal for the policy that grants it a record.
const AGENT: &str = "00000000-0000-4000-8000-000000000007";

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
            .expect("stdin accepts the write");
    }
    let output = child.wait_with_output().expect("the binary finishes");
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.code().unwrap_or(-1), combined)
}

/// The one way these tests change a mode: the point is a chmod the operator
/// could have done by hand.
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Provision a deployment through the binary, so the layout is the one the
/// commands actually create.
fn provision(home: &Path) {
    let (code, output) = ksp_in(
        home,
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin init failed: {output}");
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

/// Provision everything a host holds: the deployment, the vault and the policy.
fn provision_fully(home: &Path) {
    provision(home);
    let (code, output) = ksp_in(home, &["admin", "user", "add"], Some(PASSWORD));
    assert_eq!(code, exit::SUCCESS, "admin user add failed: {output}");
    let (code, output) = ksp_in(
        home,
        &[
            "admin",
            "policy",
            "--agent",
            AGENT,
            "--secret",
            "secret-id-1",
        ],
        Some(PASSWORD),
    );
    assert_eq!(code, exit::SUCCESS, "admin policy failed: {output}");
}

/// C1: the level directories are created by the record write with the table's
/// modes, never with the caller's `umask`.
///
/// The parent is `0711` so the sweeper can traverse to a level it can name
/// without listing the siblings; the level is `0700`, because a `0775` level is
/// another principal's write access to this principal's records.
#[test]
fn a_record_write_leaves_its_level_and_parent_with_the_table_modes() {
    let home = tempfile::tempdir().unwrap();
    provision_fully(home.path());
    let layout = ksp::config::Layout::new(home.path().to_path_buf());
    let (deployment, _) = ksp::deployment::require(&layout).expect("the deployment exists");
    let relative = ksp_record::RecordPath::directory(
        &deployment.vault,
        deployment.user,
        Some(&ksp_types::Level::User),
    );
    let level = layout.store_root().join(relative);
    let parent = level.parent().expect("a level has a parent");

    // The write is what creates both directories: nothing above them writes a
    // record before this.
    ksp::secret::set(
        &layout,
        PASSWORD.as_bytes(),
        &ksp_types::OpaqueSecretId::new("db-password"),
        b"db_password",
        b"correct-horse",
    )
    .expect("the record is written");

    assert_eq!(
        mode_of(&level),
        0o700,
        "the level is the principal's own, not the caller's umask"
    );
    assert_eq!(
        mode_of(parent),
        0o711,
        "the parent is traversable and not listable"
    );
}

#[test]
fn every_row_of_the_table_exists_with_its_mode_after_provisioning() {
    // Acceptance criterion 1 through the commands, row by row, including the two
    // file rows: `policy.cbor` is written `0644` because the *user* principal is
    // one of the readers, and `vault.cbor` `0600` because only she is.
    //
    // # Why the import ledger is excluded
    //
    // Provisioning (`admin init`, `admin user add`, `admin policy`) imports
    // nothing, so `imports.jsonl` is legitimately absent until the first import
    // appends to it. Its row is still in the table, and `status` reports it as
    // "not created yet" — which is the honest answer. Asserting it existed here
    // would force `admin init` to create a file that would then claim the
    // deployment had imported something, and an empty ledger makes "never
    // imported" indistinguishable from "imported nothing".
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("ksp");
    provision_fully(&home);

    for (relative, expected) in [
        ("admin", 0o700),
        ("agent", 0o700),
        ("enrolments", 0o755),
        ("store", 0o755),
        ("sweeper/proofs", 0o755),
        ("journal", 0o700),
        // `0711`: every principal traverses the audit root to reach its own chain
        // directory, and none may list it (FR-016, FR-023).
        ("audit", 0o711),
        ("vault.cbor", 0o600),
        ("policy.cbor", 0o644),
    ] {
        assert_eq!(
            mode_of(&home.join(relative)),
            expected,
            "{relative} has the wrong mode"
        );
    }

    let (code, output) = ksp_in(&home, &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    // Exactly one row is absent here, and the assertion names it so a second
    // absent row is a failure rather than a silently widened tolerance: a row
    // that provisioning stopped creating would otherwise read as this one.
    assert!(
        output.contains("1 not created yet"),
        "only the import ledger may be absent after provisioning: {output}"
    );
}

#[test]
fn a_fresh_deployment_reports_every_protected_root_as_matching() {
    // Acceptance criterion 1 through the command surface: the layout `admin init`
    // creates is the layout the table describes, and status says so.
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("ksp");
    provision(&home);

    let (code, output) = ksp_in(&home, &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status failed: {output}");
    assert!(
        output.contains("protected roots match the layout"),
        "a freshly provisioned home must report a matching layout: {output}"
    );
}

#[test]
fn a_widened_key_root_is_named_by_status_and_refuses_a_delivery() {
    // Acceptance criterion 2: `chmod 0775` on `admin/` is reported *and* refuses
    // a delivery with exit 7. This is misfit B end to end — the observation that
    // started the work package.
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("ksp");
    provision(&home);

    let admin_root = home.join("admin");
    set_mode(&admin_root, 0o775);

    let (code, output) = ksp_in(&home, &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status must still report: {output}");
    assert!(
        output.contains("drift"),
        "status must name the drift: {output}"
    );
    assert!(
        output.contains("admin"),
        "status must name the path: {output}"
    );
    assert!(
        output.contains("0775"),
        "status must report the mode: {output}"
    );
    assert!(
        output.contains("0700"),
        "status must report the expected mode: {output}"
    );

    // A delivery reads keys and records; neither may happen through a widened
    // key root. The token path does not exist, so an exit of 7 (not 6) is also
    // proof the layout was measured *before* the token was opened.
    let (code, output) = ksp_in(
        &home,
        &["run", "--token", "/definitely/not/a/token", "--", "true"],
        None,
    );
    assert_eq!(
        code,
        exit::CAPABILITY_REFUSAL,
        "a drifted layout must refuse a delivery with 7: {output}"
    );
    assert!(
        output.contains("drifted"),
        "the refusal must name the drift: {output}"
    );
    assert!(
        output.contains("0775"),
        "the refusal must report the measured mode: {output}"
    );
}

#[test]
fn an_administrative_write_refuses_through_a_drifted_layout() {
    // `admin put` writes into the store. If a protected root drifted, the write
    // would land in a directory another principal can reach — so it refuses, and
    // the refusal carries the measurement rather than a code with no cause.
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("ksp");
    provision(&home);
    set_mode(&home.join("store"), 0o775);

    let (code, output) = ksp_in(
        &home,
        &["admin", "put", "record-1", "--name", "a name"],
        Some("a value"),
    );
    assert_eq!(
        code,
        exit::CAPABILITY_REFUSAL,
        "a drifted root must refuse an administrative write with 7: {output}"
    );
    assert!(
        output.contains("store"),
        "the refusal names the root: {output}"
    );
    assert!(
        output.contains("0775"),
        "the refusal names the mode: {output}"
    );
}

#[test]
fn status_json_carries_the_measurement_losslessly() {
    // A human line is for reading; the JSON is for everything that has to act on
    // it, so the mode and the verdict must survive as fields.
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("ksp");
    provision(&home);
    set_mode(&home.join("admin"), 0o775);

    let (code, output) = ksp_in(&home, &["status", "--json"], None);
    assert_eq!(code, exit::SUCCESS, "status --json failed: {output}");
    let document: serde_json::Value = serde_json::from_str(&output).expect("status is JSON");

    let findings = document["permissions"]
        .as_array()
        .expect("the measurement is an array");
    let drifted: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|finding| finding["verdict"] == "drift")
        .collect();
    assert_eq!(drifted.len(), 1, "exactly one root drifted: {output}");
    assert_eq!(drifted[0]["actual_mode"], "0775");
    assert_eq!(drifted[0]["expected_mode"], "0700");
    assert!(
        drifted[0]["path"].as_str().unwrap().ends_with("/admin"),
        "the drifted root is admin/: {output}"
    );
}

/// C2: a level is a protected root too. `0700` on the principal's own level is
/// what keeps every other principal out of her records, so widening it must be
/// named by `status` and refuse a write the same way a widened key root does.
#[test]
fn a_widened_level_is_named_by_status_and_refuses_a_delivery() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("ksp");
    provision_fully(&home);

    let layout = ksp::config::Layout::new(home.clone());
    let (deployment, _) = ksp::deployment::require(&layout).expect("the deployment exists");
    let relative = ksp_record::RecordPath::directory(
        &deployment.vault,
        deployment.user,
        Some(&ksp_types::Level::User),
    );
    let level = layout.store_root().join(relative);
    // The record write is what creates the level with the table's mode.
    ksp::secret::set(
        &layout,
        PASSWORD.as_bytes(),
        &ksp_types::OpaqueSecretId::new("db-password"),
        b"db_password",
        b"correct-horse",
    )
    .expect("the record is written");
    set_mode(&level, 0o755);

    let (code, output) = ksp_in(&home, &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status must still report: {output}");
    assert!(
        output.contains("drift"),
        "status must name the level drift: {output}"
    );
    assert!(
        output.contains(&level.display().to_string()),
        "status must name the level path: {output}"
    );
    assert!(
        output.contains("0755"),
        "status must report the measured mode: {output}"
    );

    let (code, output) = ksp_in(
        &home,
        &["admin", "put", "record-1", "--name", "a name"],
        Some("a value"),
    );
    assert_eq!(
        code,
        exit::CAPABILITY_REFUSAL,
        "a drifted level must refuse a write with 7: {output}"
    );
    assert!(
        output.contains("0755"),
        "the refusal reports the measured mode: {output}"
    );
}

/// The agent rows come from the enrolments, not from listing a `0711` parent:
/// an enrolled agent's level is measured and named, so `0730` cannot silently
/// become `0775` outside the table.
#[test]
fn a_widened_agent_level_is_named_by_status() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("ksp");
    provision_fully(&home);
    let (code, output) = ksp_in(&home, &["agent", "enroll", "--agent", AGENT], None);
    assert_eq!(code, exit::SUCCESS, "agent enroll failed: {output}");

    let layout = ksp::config::Layout::new(home.clone());
    let (deployment, _) = ksp::deployment::require(&layout).expect("the deployment exists");
    // `--agent` is the display name; the identity is minted by the enrol command
    // and named by the enrolment file, which is where the level rows come from.
    let mut identities: Vec<ksp_types::AgentId> = std::fs::read_dir(layout.enrolments_dir())
        .expect("the enrolments directory exists")
        .flatten()
        .filter_map(|entry| {
            entry
                .path()
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| ksp_types::AgentId::parse(stem).ok())
        })
        .collect();
    assert_eq!(identities.len(), 1, "one agent was enrolled");
    let agent = identities.pop().expect("the enrolled identity");
    let level = ksp::layout::ensure_level(
        &home,
        &deployment.vault,
        deployment.user,
        &ksp_types::Level::Agent(agent),
    )
    .expect("the agent level is created");
    set_mode(&level, 0o755);

    let (code, output) = ksp_in(&home, &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status must still report: {output}");
    assert!(
        output.contains("drift") && output.contains("0755"),
        "status must name the widened agent level: {output}"
    );
    assert!(
        output.contains(&level.display().to_string()),
        "status must name the agent level path: {output}"
    );
}

/// FR-014 puts a protected key file in the same class as a key root. The anchor
/// is public and `0644` by design, but a pin another principal can *rewrite*
/// pins nothing, so widening it is a drift that refuses a delivery rather than a
/// note beside a working command.
#[test]
fn a_widened_anchor_is_a_boundary_and_refuses_a_delivery() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("ksp");
    provision(&home);

    let anchor = home.join("admin-anchor.cbor");
    assert_eq!(
        ksp::layout::table(&home)
            .into_iter()
            .find(|row| row.path == anchor)
            .expect("the anchor is a table row")
            .mode,
        0o644,
        "the anchor is readable by the principals that verify against it"
    );
    set_mode(&anchor, 0o664);

    let (code, output) = ksp_in(&home, &["status"], None);
    assert_eq!(code, exit::SUCCESS, "status must still report: {output}");
    assert!(output.contains("drift"), "status names the drift: {output}");
    assert!(
        output.contains("admin-anchor.cbor"),
        "status names the file: {output}"
    );

    let (code, output) = ksp_in(
        &home,
        &["run", "--token", "/definitely/not/a/token", "--", "true"],
        None,
    );
    assert_eq!(
        code,
        exit::CAPABILITY_REFUSAL,
        "a writable anchor refuses a delivery with 7: {output}"
    );
    assert!(
        output.contains("drifted"),
        "and says so rather than failing to open the token: {output}"
    );
}
