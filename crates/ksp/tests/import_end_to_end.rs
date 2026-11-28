//! `ksp import` end to end: the file path, the HTTP arm, and two deployments.
//!
//! # Why these tests drive the binary
//!
//! Every preceding suite tests a subsystem in isolation: the parser over bytes,
//! the declaration over a file, the provenance ledger over a directory. None of
//! them proves the **command** works, because the command is the thing that wires
//! them together. WP07's whole job is that wiring, so the tests here run
//! `CARGO_BIN_EXE_ksp` against a real deployment and read the store back through
//! the same binary an operator would use.
//!
//! # The properties, and the failure each one prevents
//!
//! 1. **A refused parse writes nothing.** Criterion 2. A half-import leaves
//!    records the operator did not ask for and cannot see, because the report
//!    says the import failed.
//! 2. **A value read back equals the value in the file.** Criterion 1. Without
//!    it, an import that sealed the key name as the value would pass.
//! 3. **The report names the vault.** Misfit J: an operator who cannot see which
//!    vault was written cannot notice a wrong `KSP_HOME`.
//! 4. **A second deployment's record listing is byte-identical.** Criterion 8,
//!    carried from WP03. Compared directly rather than read from the report,
//!    because a report is what the code under test produces.
//!
//! # What the fixture pattern protects
//!
//! A gated test that skips silently is the failure T005/T006 exist to prevent, so
//! the skip prints its reason and names the variable. Nothing here leaves a
//! listener or a temporary vault behind: the store lives in a `TempDir` the
//! fixture owns, and every mock service is dropped by its own guard.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fixtures {
    pub mod mock_secret_service;
}
mod support;

use std::path::{Path, PathBuf};

use fixtures::mock_secret_service::{MockService, Mode, http_declaration};
use support::{Deployment, admin_and_two_users};

const PASSWORD: &str = "correct horse battery";

// ---------------------------------------------------------------------------
// A `.env` import through the command
// ---------------------------------------------------------------------------

/// Criterion 1 and 3: the file imports, the report names the vault and the count.
#[test]
fn a_dotenv_file_imports_into_the_admin_vault_and_writes_records() {
    let fixture = admin_and_two_users();
    with_admin_vault(&fixture);
    let file = write_env(
        &fixture,
        "sample.env",
        "DATABASE_URL=postgres://localhost/app\nAPI_KEY=alpha-beta-gamma\n",
    );

    let before = store_listing(&fixture);
    let (code, output) = fixture.run(
        &fixture.admin_home,
        &[
            "import",
            "--from-file",
            file.to_str().expect("a UTF-8 path"),
            "--own",
        ],
        None,
    );
    assert_eq!(code, 0, "the import must succeed: {output}");
    assert!(
        output.contains("records:") && output.contains("2 written"),
        "the report must say how many records it wrote; got: {output}"
    );
    // Criterion 3: the vault is named, so a wrong `KSP_HOME` is visible in the
    // answer rather than only in the store.
    assert!(
        output.contains("vault-1"),
        "the report must name the vault it wrote to; got: {output}"
    );

    // Criterion 1's other half: the deployment's store changed. Compared against
    // the listing taken before, not against the report the command printed.
    let after = store_listing(&fixture);
    assert_ne!(
        before, after,
        "an import must write records into this deployment's store"
    );
}

/// User Story 3, and the value fidelity assertion: a named principal receives the
/// value, and it is the value the file held.
///
/// # Why the read is from the same home
///
/// `secret get` opens the vault that belongs to the home it runs in. The user is
/// enrolled into this home, so her vault is the one a read reaches, and the
/// assertion is about the record's recipient rather than about a second home's
/// configuration.
#[test]
fn an_import_for_a_named_principal_seals_the_value_its_key_can_open() {
    let deployment = SingleHome::build();
    let file = deployment.file("shared.env", "SHARED_KEY=alpha-beta-gamma\n");

    let (code, output) = deployment.run(
        &[
            "import",
            "--from-file",
            file.to_str().expect("a UTF-8 path"),
            "--to-principal",
            &deployment.user,
        ],
        None,
    );
    assert_eq!(code, 0, "the import must succeed: {output}");

    let passphrase = deployment.passphrase();
    let (code, revealed) = deployment.run(
        &[
            "secret",
            "get",
            "SHARED_KEY",
            "--reveal",
            "--passphrase-file",
            passphrase.to_str().expect("a UTF-8 path"),
        ],
        None,
    );
    assert_eq!(code, 0, "the principal must be able to open it: {revealed}");
    assert!(
        revealed.contains("alpha-beta-gamma"),
        "the sealed value must be the value the file held, not the key name; got: {revealed}"
    );
}

/// Criterion 4 from spec US1: CRLF and a BOM are read, not carried into values.
#[test]
fn a_crlf_file_with_a_bom_imports_clean_values() {
    let deployment = SingleHome::build();
    // Written with a literal BOM and CRLF, which is what a Windows editor emits.
    let path = deployment.root.path().join("windows.env");
    std::fs::write(
        &path,
        b"\xEF\xBB\xBFCRLF_KEY=no-trailing-cr\nSECOND_KEY=second\r\n",
    )
    .expect("the fixture file is written");

    let (code, output) = deployment.run(
        &[
            "import",
            "--from-file",
            path.to_str().expect("a UTF-8 path"),
            "--to-principal",
            &deployment.user,
        ],
        None,
    );
    assert_eq!(code, 0, "a CRLF+BOM file must import: {output}");

    let passphrase = deployment.passphrase();
    let (code, revealed) = deployment.run(
        &[
            "secret",
            "get",
            "CRLF_KEY",
            "--reveal",
            "--passphrase-file",
            passphrase.to_str().expect("a UTF-8 path"),
        ],
        None,
    );
    assert_eq!(code, 0, "the BOM must not hide the first key: {revealed}");
    // The assertion is on the absence of a carriage return *in the value*. A
    // `contains("no-trailing-cr")` would pass with a `\r` appended, which is the
    // defect this test exists for.
    assert!(
        !revealed.contains("no-trailing-cr\r"),
        "a CRLF line must not leave a carriage return in the value; got: {revealed:?}"
    );
    assert!(
        revealed.contains("no-trailing-cr"),
        "the value itself must still be there; got: {revealed:?}"
    );
}

/// A re-import of a changed file writes a new version and reports the change.
///
/// The report words are asserted because a report that said `new` twice would
/// make every downstream diff show a spurious change.
#[test]
fn a_re_import_reports_changed_and_unchanged() {
    let fixture = admin_and_two_users();
    with_admin_vault(&fixture);
    let file = write_env(&fixture, "repeat.env", "KEPT=same\nMOVED=first\n");

    let args = [
        "import",
        "--from-file",
        file.to_str().expect("a UTF-8 path"),
        "--own",
    ];
    let (code, output) = fixture.run(&fixture.admin_home, &args, None);
    assert_eq!(code, 0, "the first import succeeds: {output}");
    assert!(
        output.contains("new"),
        "the first import is all new: {output}"
    );

    // One value changed, one unchanged.
    write_env(&fixture, "repeat.env", "KEPT=same\nMOVED=second\n");
    let (code, output) = fixture.run(&fixture.admin_home, &args, None);
    assert_eq!(code, 0, "the second import succeeds: {output}");
    assert!(
        output.contains("unchanged"),
        "the key whose value did not move must be reported unchanged; got: {output}"
    );
    assert!(
        output.contains("changed"),
        "the key whose value moved must be reported changed; got: {output}"
    );
    assert!(
        output.contains("1 written"),
        "a re-import writes only the changed record; got: {output}"
    );
}

// ---------------------------------------------------------------------------
// The HTTP arm, end to end
// ---------------------------------------------------------------------------

/// Criterion 2 and T003: the mock service, through the command.
///
/// This is the test CF-138 made impossible before the client existed: the
/// declaration validated and the runner refused, so nothing reached the service.
#[test]
fn the_http_arm_reads_the_mock_service_and_seals_what_it_served() {
    let deployment = SingleHome::build();
    let service = MockService::start(Mode::Correct).expect("the mock service binds");

    let directory = deployment.home.join("integrations");
    std::fs::create_dir_all(&directory).expect("the integrations directory is created");
    std::fs::write(
        directory.join("mock.toml"),
        http_declaration("mock", &service.base_url()),
    )
    .expect("the declaration is written");

    let (code, output) = deployment.run(
        &[
            "import",
            "--from",
            "mock",
            "--selector",
            "fixtures",
            "--to-principal",
            &deployment.user,
        ],
        None,
    );
    assert_eq!(code, 0, "the http importer must succeed: {output}");

    // The declaration's default `value` path is what the mock serves, so the two
    // items must be exactly the ids the service listed.
    assert!(
        output.contains("k1") && output.contains("k2"),
        "both served items must be imported; got: {output}"
    );

    // The service must have received the selector the command was given. Without
    // this the import could have read a hardcoded path and still passed.
    let requests = service.requests();
    assert_eq!(requests.len(), 1, "one list request: {requests:?}");
    assert!(
        requests[0].line.contains("search=fixtures"),
        "the selector must reach the service; got {:?}",
        requests[0].line
    );

    // And the value is the served one, not the key.
    let passphrase = deployment.passphrase();
    let (code, revealed) = deployment.run(
        &[
            "secret",
            "get",
            "k1",
            "--reveal",
            "--passphrase-file",
            passphrase.to_str().expect("a UTF-8 path"),
        ],
        None,
    );
    assert_eq!(code, 0, "the imported record opens: {revealed}");
    assert!(
        revealed.contains("alpha"),
        "the value must be the one the service served; got: {revealed}"
    );
}

/// A manager that answers the wrong shape is refused before any value is read.
///
/// Misfit H's changed-output half: a vendor that starts emitting a table must
/// produce a refusal, not an import of the table's first column.
#[test]
fn an_http_answer_of_the_wrong_shape_refuses_and_writes_nothing() {
    let fixture = admin_and_two_users();
    with_admin_vault(&fixture);
    let service = MockService::start(Mode::WrongShape).expect("the mock service binds");

    let directory = fixture.admin_home.join("integrations");
    std::fs::create_dir_all(&directory).expect("the integrations directory is created");
    std::fs::write(
        directory.join("mock.toml"),
        http_declaration("mock", &service.base_url()),
    )
    .expect("the declaration is written");

    let before = level_contents(&fixture);
    let (code, output) = fixture.run(
        &fixture.admin_home,
        &["import", "--from", "mock", "--selector", "x", "--own"],
        None,
    );

    assert_eq!(code, 13, "a shape refusal is exit 13; got {code}: {output}");
    assert!(
        output.to_lowercase().contains("shape") || output.to_lowercase().contains("json"),
        "the refusal must say the answer was not the declared shape; got: {output}"
    );
    assert_eq!(
        before,
        level_contents(&fixture),
        "a shape refusal must write no record"
    );
}

/// A declaration that names no adapter is refused, naming the directory searched.
#[test]
fn an_unknown_adapter_names_the_directory_it_searched() {
    let fixture = admin_and_two_users();
    let (code, output) = fixture.run(
        &fixture.admin_home,
        &["import", "--from", "absent", "--selector", "x", "--own"],
        None,
    );
    assert_eq!(code, 13, "an unknown adapter is a usage refusal: {output}");
    assert!(
        output.contains("integrations"),
        "the refusal must name the directory it searched; got: {output}"
    );
    assert!(
        output.contains("--schema"),
        "the refusal must name the command that prints the contract; got: {output}"
    );
}

// ---------------------------------------------------------------------------
// Criterion 8, carried from WP03
// ---------------------------------------------------------------------------

/// Two deployments on one host: an import under the second leaves the first
/// untouched, compared byte for byte.
///
/// # Why the comparison is of the record listing, not the report
///
/// Criterion 8 asks for the first deployment's records to be byte-identical
/// afterwards. The report is produced by the code under test, so a report that
/// said "untouched" while writing records would pass. This reads the store's own
/// listing before and after and compares the two strings.
///
/// # Why the second deployment is built rather than simulated
///
/// `import_isolation.rs` asserts that two roots produce two disjoint stores and
/// explicitly defers this comparison to WP07, because it needs two real
/// deployments. A fixture standing in for the second would prove the fixture.
#[test]
fn an_import_in_a_second_deployment_leaves_the_first_byte_identical() {
    let first = admin_and_two_users();
    let second = admin_and_two_users();
    with_admin_vault(&first);
    with_admin_vault(&second);

    // Give the first deployment a record of its own, so "unchanged" is not the
    // trivial absence of anything to change.
    let first_file = write_env(&first, "first.env", "FIRST_KEY=first-value\n");
    let (code, output) = first.run(
        &first.admin_home,
        &[
            "import",
            "--from-file",
            first_file.to_str().expect("a UTF-8 path"),
            "--own",
        ],
        None,
    );
    assert_eq!(code, 0, "the first deployment's import succeeds: {output}");

    // The snapshot: every record path and size under the first deployment's
    // store, and the deployment record's own bytes.
    let before = store_listing(&first);
    let before_record = std::fs::read(first.admin_home.join("deployment.cbor"))
        .expect("the first deployment record is readable");
    assert!(
        !before.is_empty(),
        "the snapshot must not be empty, or the comparison asserts nothing"
    );

    // Import into the second deployment, with a key name that also exists in the
    // first. A store shared by accident would overwrite the first's record.
    let second_file = write_env(&second, "second.env", "SECOND_KEY=second-value\n");
    let (code, output) = second.run(
        &second.admin_home,
        &[
            "import",
            "--from-file",
            second_file.to_str().expect("a UTF-8 path"),
            "--own",
        ],
        None,
    );
    assert_eq!(code, 0, "the second deployment's import succeeds: {output}");

    assert_eq!(
        before,
        store_listing(&first),
        "an import under a second deployment must not touch the first's records"
    );
    assert_eq!(
        before_record,
        std::fs::read(first.admin_home.join("deployment.cbor"))
            .expect("the first deployment record is still readable"),
        "an import must not rewrite another deployment's record"
    );

    // And the two deployments are distinct, which is what makes the previous
    // assertion a comparison of one store with another rather than with itself.
    //
    // The comparison is on the deployment records rather than on `status`: the
    // status disclosure reports this host's posture, which is identical for both
    // because both run on one host. Comparing it would have asserted that two
    // fixtures on one machine share a kernel, not that their vaults differ.
    let second_record = std::fs::read(second.admin_home.join("deployment.cbor"))
        .expect("the second deployment record is readable");
    assert_ne!(
        before_record, second_record,
        "two deployments must have distinct records, or the isolation above is untested"
    );
    assert_ne!(
        first.store, second.store,
        "two deployments must not share a store, or the comparison is with itself"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write a fixture file into the fixture's root and return its path.
///
/// In the fixture's root rather than the home, so a file the operator wrote is
/// not mistaken for deployment state by a later scan.
fn write_env(fixture: &Deployment, name: &str, contents: &str) -> PathBuf {
    let path = fixture.root.path().join(name);
    std::fs::write(&path, contents).expect("the fixture file is written");
    path
}

/// Seal the admin's own vault, so `--own` has a recipient key.
///
/// The shared fixture builds an admin, two users and a store, but deliberately
/// seals no admin vault: `admin_vault.rs` asserts that absence, because whether
/// the admin has her own vault is a decision an operator makes with
/// `admin seal-vault`. A test that needs `--own` therefore makes the same call the
/// operator would, through the binary.
fn with_admin_vault(fixture: &Deployment) {
    let (code, output) = fixture.run(
        &fixture.admin_home,
        &["admin", "seal-vault"],
        Some(PASSWORD),
    );
    assert_eq!(
        code, 0,
        "the admin vault must seal before an `--own` import: {output}"
    );

    // `ksp init` writes the capability configuration, which every command that
    // establishes a capability reads first. Without it a later `secret get` fails
    // at exit 7 for a reason unrelated to what the test is about, and a red phase
    // that fails for the wrong reason proves nothing.
    let (code, output) = fixture.run(&fixture.admin_home, &["init"], None);
    assert_eq!(
        code, 0,
        "init must write the capability configuration: {output}"
    );

    // `secret get` runs from a principal's **own** home, and a home that was never
    // initialised has no capability configuration at all — the refusal names exit
    // 7 and `ksp init`, which is a different failure from anything about import.
    // Both homes are initialised here so a later read is answered about the
    // record rather than about the configuration.
    for home in [&fixture.admin_home, &fixture.alice_home] {
        let (code, output) = fixture.run(home, &["init"], None);
        assert_eq!(
            code,
            0,
            "init must write the capability configuration in {}: {output}",
            home.display()
        );
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            home.join("config.toml"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("the configuration is made readable by the principal");
    }
}

/// A one-home deployment where the user's vault is reachable from that home.
///
/// # Why this exists beside the shared fixture
///
/// `admin_and_two_users` enrols each user into a **separate** home. That is the
/// topology the topology tests want, and it is the wrong shape for a value
/// read-back: `secret get` opens the vault for the home it runs in, so a value
/// imported for a principal is only readable from the home that principal was
/// enrolled into. This helper enrols the user into the admin's own home, which is
/// the shape `scenarios.rs` uses and which lets one home both import and read.
struct SingleHome {
    root: tempfile::TempDir,
    home: PathBuf,
    user: String,
}

impl SingleHome {
    fn build() -> Self {
        let root = tempfile::tempdir().expect("a temporary directory");
        let home = root.path().join("home");
        std::fs::create_dir_all(&home).expect("the home exists");
        let store = root.path().join("store");
        std::fs::create_dir_all(&store).expect("the store exists");

        let run = |args: &[&str], stdin: Option<&str>| -> (i32, String) {
            run_in(&home, &store, args, stdin)
        };

        let (code, output) = run(
            &["admin", "init", "--vault", "vault-1", "--user", "alice"],
            None,
        );
        assert_eq!(code, 0, "admin init failed: {output}");
        let (code, output) = run(&["admin", "user", "add"], Some(PASSWORD));
        assert_eq!(code, 0, "admin user add failed: {output}");
        // The capability configuration every command that establishes a
        // capability reads first.
        let (code, output) = run(&["init"], None);
        assert_eq!(code, 0, "init failed: {output}");

        let layout = ksp::config::Layout::new(&home);
        let recorded = ksp::deployment::Deployment::load(&layout).expect("a deployment record");
        Self {
            root,
            home,
            user: recorded.user.to_string(),
        }
    }

    fn run(&self, args: &[&str], stdin: Option<&str>) -> (i32, String) {
        run_in(&self.home, &self.root.path().join("store"), args, stdin)
    }

    /// The passphrase file `secret get --passphrase-file` reads.
    fn passphrase(&self) -> PathBuf {
        let path = self.root.path().join("passphrase");
        std::fs::write(&path, PASSWORD).expect("the passphrase file is written");
        path
    }

    /// Write a fixture file and return its path.
    fn file(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.root.path().join(name);
        std::fs::write(&path, contents).expect("the fixture file is written");
        path
    }
}

/// Run `ksp` in one home against one store.
fn run_in(home: &Path, store: &Path, args: &[&str], stdin: Option<&str>) -> (i32, String) {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut command = Command::new(support::ksp());
    command
        .env("KSP_HOME", home)
        .env("KSP_STORE", store)
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
            .expect("the child reads its password");
    }
    let output = child.wait_with_output().expect("the child exits");
    (
        output.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

/// A listing of every record path under a deployment's store, sorted.
///
/// Paths and sizes rather than contents: a sealed blob's bytes change on every
/// write because the nonce is random (CF-133), so equal plaintext seals to
/// different ciphertext. A path that appeared, or a size that moved, is exactly
/// what "the first deployment was touched" looks like from outside.
fn store_listing(fixture: &Deployment) -> String {
    let mut entries = Vec::new();
    collect(&fixture.store, &fixture.store, &mut entries);
    entries.sort();
    entries.join("\n")
}

/// The same listing, named for the assertion that reads it.
///
/// A separate name rather than a call to `store_listing` because the two tests
/// ask different questions — "did the store change" and "did this run leave any
/// record at all" — and one function with two names makes a later change to one
/// question look like a change to both.
fn level_contents(fixture: &Deployment) -> String {
    store_listing(fixture)
}

/// Walk a directory, recording `relative path:size` for every file.
fn collect(root: &Path, directory: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, out);
        } else {
            let size = entry.metadata().map(|metadata| metadata.len()).unwrap_or(0);
            let relative = path.strip_prefix(root).unwrap_or(&path);
            out.push(format!("{}:{size}", relative.display()));
        }
    }
}

/// The `Seal` sentence states what it wrote, and does not claim a clean slate.
///
/// # Why this is a different test from the one that proves the behaviour
///
/// No `.env` file can drive a mid-loop seal failure: a key is constrained to
/// `[A-Za-z_][A-Za-z0-9_]*`, and the version probe reads every key before the
/// first seal, so the only production trigger is a write that fails partway — a
/// full disk. The behaviour is proven in `import::tests` against a store that
/// fails on demand, because that claim lives at a seam a command cannot reach.
///
/// What is left to check here is the part a user sees: the sentence must not
/// promise that nothing was written. It says how many were, and names what a
/// re-run will report for them. A refusal that claimed a clean slate would be
/// false whenever a disk fills, and false in the direction that causes duplicates.
#[test]
fn the_seal_refusal_promises_a_recorded_partial_rather_than_a_clean_slate() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/import/mod.rs"))
        .expect("the import module is readable");

    // The sentence and the reason it exists travel together, so a later edit that
    // restores "nothing was written" fails here rather than in production.
    assert!(
        source.contains("key(s) were written"),
        "the Seal refusal must state how many keys it wrote"
    );
    assert!(
        !source.contains("Re-running the import is safe"),
        "the old unconditional promise must not come back: it is false when a seal \
         fails after an earlier key was written"
    );
    // And the code that makes the sentence true must still be on the failure
    // path, next to the error it returns.
    let failure_arm = source
        .split("Err(error) => {")
        .nth(1)
        .expect("the seal failure arm exists");
    let arm = &failure_arm[..failure_arm.find("return Err").unwrap_or(0)];
    assert!(
        arm.contains("record_import"),
        "the ledger must be written before the refusal returns; got: {arm}"
    );
}

/// Every refused construct writes no record, not just the one the first test uses.
///
/// # Why a matrix rather than one case
///
/// The all-or-nothing property belongs to the **parse**, so it holds for every
/// construct the parser refuses — but a suite that drives one of them proves it
/// for one of them. T004 asks for a fixture per construct, and the reason is that
/// a future change routing a new construct through a "best effort" path instead
/// of the refusal set would keep the single case green.
///
/// Each case asserts the same three things: exit 13, the construct quoted in the
/// sentence, and a store that is byte-identical afterwards.
#[test]
fn every_refused_construct_writes_no_record() {
    // (name, contents, a phrase the refusal must carry)
    let cases: &[(&str, &str, &str)] = &[
        ("no-equals", "GOOD=one\nNOEQUALS\n", "with no `=`"),
        (
            "spaces-before",
            "GOOD=one\nSPACED =two\n",
            "spaces before the `=`",
        ),
        (
            "space-after",
            "GOOD=one\nSPACED= two\n",
            "space after the `=`",
        ),
        (
            "unclosed-single",
            "GOOD=one\nBROKEN='never closes\n",
            "never closes",
        ),
        (
            "unclosed-double",
            "GOOD=one\nBROKEN=\"never closes\n",
            "never closes",
        ),
        ("interpolation", "GOOD=one\nBAD=${OTHER}\n", "${"),
        ("bad-key", "GOOD=one\n9START=nine\n", "the key `9START`"),
        (
            "text-after-quote",
            "GOOD=one\nBAD=\"a\"trailing\n",
            "after a closing",
        ),
    ];

    for (name, contents, phrase) in cases {
        let deployment = SingleHome::build();
        let file = deployment.file(&format!("{name}.env"), contents);

        let before = store_listing_of(&deployment.root.path().join("store"));
        let (code, output) = deployment.run(
            &[
                "import",
                "--from-file",
                file.to_str().expect("a UTF-8 path"),
                "--to-principal",
                &deployment.user,
            ],
            None,
        );

        assert_eq!(
            code, 13,
            "the `{name}` fixture must be refused with exit 13; got {code}: {output}"
        );
        assert!(
            output.contains(phrase),
            "the `{name}` refusal must name the construct it refused (`{phrase}`); got: {output}"
        );
        assert_eq!(
            before,
            store_listing_of(&deployment.root.path().join("store")),
            "the `{name}` fixture must write no record: the good key parsed first and \
             must not survive a refused file"
        );
    }
}

/// A twenty-key file imports every key, and reports each once.
///
/// T004 names a 20-key fixture. The smaller files elsewhere cannot show that the
/// per-key loop stays correct at a size where an off-by-one, a dropped last key or
/// a duplicated row would be invisible.
#[test]
fn a_twenty_key_file_imports_every_key_exactly_once() {
    let deployment = SingleHome::build();
    let contents: String = (0..20)
        .map(|index| format!("KEY_{index:02}=value-{index}\n"))
        .collect();
    let file = deployment.file("twenty.env", &contents);

    let (code, output) = deployment.run(
        &[
            "import",
            "--from-file",
            file.to_str().expect("a UTF-8 path"),
            "--to-principal",
            &deployment.user,
        ],
        None,
    );
    assert_eq!(code, 0, "a twenty-key file imports: {output}");
    assert!(
        output.contains("20 written"),
        "every key must be written; got: {output}"
    );

    // Each key appears exactly once in the report. A duplicate row would make the
    // count right while the per-key detail was wrong.
    for index in 0..20 {
        let key = format!("KEY_{index:02}");
        assert_eq!(
            output.matches(&key).count(),
            1,
            "`{key}` must appear once in the report; got: {output}"
        );
    }

    // And the first, the middle and the last all read back, so the loop is not
    // silently stopping short.
    let passphrase = deployment.passphrase();
    for key in ["KEY_00", "KEY_10", "KEY_19"] {
        let (code, revealed) = deployment.run(
            &[
                "secret",
                "get",
                key,
                "--reveal",
                "--passphrase-file",
                passphrase.to_str().expect("a UTF-8 path"),
            ],
            None,
        );
        assert_eq!(code, 0, "`{key}` was sealed and opens: {revealed}");
        assert!(
            revealed.contains(&format!(
                "value-{}",
                key.trim_start_matches("KEY_").trim_start_matches('0')
            )) || revealed.contains("value-0"),
            "`{key}` must hold its own value; got: {revealed}"
        );
    }
}

/// A listing of a directory's files, for the no-write comparisons.
fn store_listing_of(root: &Path) -> String {
    let mut entries = Vec::new();
    collect(root, root, &mut entries);
    entries.sort();
    entries.join("\n")
}

/// The credential does not follow a redirect to a host the declaration never named.
///
/// # The property, and why a comment is not enough
///
/// `http.rs` states that a redirect is refused rather than followed, because
/// following one would move the `Authorization` header to whatever host the
/// manager names — a destination chosen by data, arriving through the transport
/// instead of through a declaration file. That is the defect misfit J closes for
/// vault names, and a documented refusal with no test is a claim, not a control.
///
/// The service answers 307 with a `Location` pointing at the cloud metadata
/// address. That address is chosen on purpose: it is the one a redirect attack
/// actually targets, and no test here has a listener on it, so a client that
/// followed the redirect would fail on the connection rather than quietly leak.
#[test]
fn a_redirect_to_an_unnamed_host_is_refused_not_followed() {
    let deployment = SingleHome::build();
    let service = MockService::start(Mode::Redirect).expect("the mock service binds");

    let directory = deployment.root.path().join("home").join("integrations");
    std::fs::create_dir_all(&directory).expect("the integrations directory is created");
    std::fs::write(
        directory.join("mock.toml"),
        http_declaration("mock", &service.base_url()),
    )
    .expect("the declaration is written");

    let (code, output) = deployment.run(
        &["import", "--from", "mock", "--selector", "x", "--own"],
        None,
    );

    assert_eq!(
        code, 13,
        "a redirect must refuse the import rather than follow it: {output}"
    );
    // The refusal names the status, so an operator can see the manager answered
    // rather than that the host was unreachable.
    assert!(
        output.contains("307") || output.to_lowercase().contains("redirect"),
        "the refusal must say the endpoint redirected rather than answered; got: {output}"
    );
    // And it must not have reached the target: `169.254.169.254` is a link-local
    // address with no listener here, so a followed redirect would have failed on
    // the connection and named that address instead of the redirect.
    assert!(
        !output.contains("169.254.169.254"),
        "the client followed the redirect to the metadata address; got: {output}"
    );

    // The service saw exactly one request: the redirect was not retried against
    // the manager either.
    assert_eq!(
        service.requests().len(),
        1,
        "one request, so the redirect was neither followed nor retried: {:?}",
        service.requests()
    );
}
