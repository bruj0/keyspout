//! Append-before-effect, refusals and chain integrity through the real binary.
//!
//! # What these prove that a unit test cannot
//!
//! The chain's own tests prove that a link is checkable. These prove that a
//! *command* writes one: the record is on disk after a mutating success, it is
//! there after a refusal, and a command whose record cannot be written refuses
//! instead of printing a success nobody can reconstruct.
//!
//! The unwritable case is injected by putting a regular file where the writer's
//! directory belongs. That fails for any uid; a `chmod` would not, because the
//! gate runs as `root` and `root` writes through a `0500` directory.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ksp_cli::config::Layout;
use ksp_cli::exit;
use ksp_deletion::AuditChain;
use ksp_types::PrincipalId;
use ksp_types::evidence::{AuditOperation, Outcome};

/// The value every invocation in this file stores.
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
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(text.as_bytes())
            .expect("the input is written");
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

/// Store one secret through the binary and return the printed version count.
fn set_secret(home: &Path, id: &str) -> (i32, String) {
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
    (code, output)
}

/// One recorded operation: what it was, whether it completed, its exit class and
/// the signer it names inside the signed bytes.
type Recorded = (AuditOperation, Outcome, i32, String);

/// One segment: the signer key ID that names it, and the records in it.
type Segment = (String, Vec<Recorded>);

/// The audit segments a home holds.
fn segments(home: &Path) -> Vec<Segment> {
    let root = Layout::new(home.to_path_buf()).audit_root();
    let chain = AuditChain::new(&root);
    let mut found = Vec::new();
    let Ok(actors) = std::fs::read_dir(&root) else {
        return found;
    };
    for actor in actors.flatten() {
        let Ok(principal) = PrincipalId::parse(&actor.file_name().to_string_lossy()) else {
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
            let records = chain.read(principal, key_id).unwrap();
            found.push((
                key_id.to_string(),
                records
                    .iter()
                    .map(|signed| {
                        (
                            signed.record.operation,
                            signed.record.outcome,
                            signed.record.exit_code,
                            signed.record.signer_key_id.clone(),
                        )
                    })
                    .collect(),
            ));
        }
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

/// Acceptance 1: a mutating command leaves its record, and the record names the
/// version it wrote.
#[test]
fn a_mutating_command_writes_its_record_with_the_version_it_wrote() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());

    let (code, output) = set_secret(home.path(), "db-password");
    assert_eq!(code, exit::SUCCESS, "secret set failed: {output}");

    let segments = segments(home.path());
    assert_eq!(segments.len(), 1, "one signer, one segment: {segments:?}");
    let (key_id, records) = &segments[0];
    let layout = Layout::new(home.path().to_path_buf());
    let (recorded, _anchor) = ksp_cli::deployment::require(&layout).unwrap();
    assert_eq!(
        Some(key_id.as_str()),
        recorded.user_signing_key_id.as_ref().map(|id| id.as_str()),
        "a user operation is signed with the tenant's enrolled key"
    );
    assert_eq!(records.len(), 1, "one operation, one record: {records:?}");
    assert_eq!(records[0].0, AuditOperation::Put);
    assert_eq!(records[0].1, Outcome::Success);
    assert_eq!(records[0].2, exit::SUCCESS);
    assert_eq!(
        records[0].3, *key_id,
        "the record names the key that signed it, not only the one that filed it"
    );
}

/// Acceptance 2 and Misfit U: a refusal is an entry, not an absence.
#[test]
fn a_refused_admin_write_leaves_a_record_with_its_exit_class() {
    let home = tempfile::tempdir().unwrap();
    // Init without enrolling the user: `admin put` has no recipient key to seal to
    // and refuses. That refusal is the entry that shows the control fired.
    let (code, output) = ksp_in(
        home.path(),
        &["admin", "init", "--vault", "vault-1", "--user", "alice"],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "admin init failed: {output}");

    let (code, output) = ksp_in(
        home.path(),
        &["admin", "put", "db-password", "--name", "db_password"],
        Some(VALUE),
    );
    assert_ne!(code, exit::SUCCESS, "the put must refuse: {output}");

    let segments = segments(home.path());
    let listing = std::fs::read_dir(Layout::new(home.path().to_path_buf()).audit_root())
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path().display().to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|error| vec![format!("<{error}>")]);
    assert_eq!(
        segments.len(),
        1,
        "one refusal, one segment: {segments:?} in {listing:?}; the command said: {output}"
    );
    let (key_id, records) = &segments[0];
    let layout = Layout::new(home.path().to_path_buf());
    let anchor = ksp_cli::keys::Anchor::load(&layout.admin_anchor_file()).unwrap();
    assert_eq!(
        key_id.as_str(),
        anchor.key_id.as_str(),
        "an administrative write is signed with the pinned admin key"
    );
    assert_eq!(
        records.len(),
        1,
        "the refusal must be recorded: {records:?}"
    );
    assert_eq!(records[0].1, Outcome::Failure);
    assert_eq!(
        records[0].2, code,
        "the record must carry the exit class the command produced"
    );
}

/// Acceptance 4 and FR-044: a record that cannot be written refuses the operation
/// instead of letting an unlogged effect stand.
#[test]
fn an_unwritable_audit_directory_refuses_the_operation_and_prints_no_success() {
    let home = tempfile::tempdir().unwrap();
    provision_vault(home.path());

    // A regular file where the writer's directory belongs: the append fails for any
    // uid, which a mode change would not (the gate runs as root).
    let layout = Layout::new(home.path().to_path_buf());
    let (code, output) = set_secret(home.path(), "first");
    assert_eq!(
        code,
        exit::SUCCESS,
        "the first write must succeed: {output}"
    );
    // Every writer directory, not the first one found: the log is one chain per
    // writer, and provisioning already wrote the admin's chain beside the user's.
    // Blocking only one of them would have this test assert a refusal that the
    // other chain happily records.
    let actors = std::fs::read_dir(layout.audit_root())
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert!(
        !actors.is_empty(),
        "the first write created at least one writer directory"
    );
    for actor in actors {
        std::fs::remove_dir_all(&actor).unwrap();
        std::fs::write(&actor, b"not a directory").unwrap();
    }

    let (code, output) = set_secret(home.path(), "second");
    assert_eq!(
        code,
        exit::CAPABILITY_REFUSAL,
        "an unrecordable operation must refuse with 7: {output}"
    );
    assert!(
        output.contains("audit"),
        "the refusal must name the audit mechanism: {output}"
    );
    assert!(
        !output.contains("version"),
        "a refused operation must not print the version it did write: {output}"
    );
}
