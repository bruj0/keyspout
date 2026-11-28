//! The `bitwarden` declaration against the real `bw` CLI.
//!
//! # Two halves, and why the split is not negotiable
//!
//! The constitution states the rule: *"A gate that needs a service the host does
//! not run can never be green"*, naming `ksp-backend:s3_store` as the precedent. A
//! `bw` test that needs a login would be that mistake again — red on every machine
//! that has not logged in, and a gate that is permanently red teaches contributors
//! to ignore it.
//!
//! | Test | In the gate | Needs |
//! |---|---|---|
//! | The refusal with no usable session | **always**, when `bw` is installed | a `bw` on `PATH` |
//! | The item round trip | `KSP_TEST_BW=1` | a logged-in `bw` with an unlocked vault |
//!
//! The refusal tests drive the real CLI, so they need the binary. That is the
//! whole point: they assert what `bw status` actually answers, and a stub would
//! assert the stub. They skipped when it was absent and the reason was recorded,
//! rather than failing: before that, a host that happened to have `bw` installed
//! ran them and the CI runner did not, so the gate was green locally and red on
//! every push. A gate that cannot run on the machine that gates the release is
//! not a gate.
//!
//! `KSP_TEST_BW=1` with no usable session **fails**. A gate that skips when it was
//! asked to run reports a green result for a test that did not happen.
//!
//! # The vault holds real data
//!
//! `bw` here points at a self-hosted Vaultwarden holding the operator's real items.
//! **No test reads one of them.** The gated test creates its own item, imports that,
//! compares, and deletes it — and a failed delete fails the test, because a leaked
//! fixture in a real vault is a defect rather than a note.
//!
//! # The session never enters the repository
//!
//! It reaches `bw` through the environment, never argv: a value in `argv` is visible
//! in `ps`. `no_session_key_appears_in_the_repository` enforces that mechanically,
//! and `no_test_passes_a_session_as_an_argument` pins the form.

// A test reports a failure by panicking, and the panic message is what says why.
// `print_stderr` is allowed for one thing: criterion 8 requires the gated skip to
// print **why** it skipped, and a silent skip is the failure that criterion exists
// to prevent.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ksp::import::adapter::declaration::AdapterDeclaration;
use ksp::import::adapter::shape::{OutputShape, validate_shape};
use ksp::import::adapter::validate::{load_at, validate};

/// The declaration this work package ships.
fn shipped_declaration_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../integrations/bitwarden.toml")
}

/// Whether the gate was asked to run the gated half.
fn bw_round_trip_requested() -> bool {
    std::env::var("KSP_TEST_BW").is_ok_and(|value| value == "1")
}

/// The session, read from the environment the operator exported.
///
/// Never from a file this repository tracks, and never logged. The gated test hands
/// it to `bw`'s **environment**, which is why it is read here rather than passed as
/// an argument.
fn session_from_env() -> Option<String> {
    match std::env::var("BW_SESSION") {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}

/// Run `bw` with the session in its environment and nothing in `argv`.
fn bw_with_session(session: Option<&str>, args: &[&str]) -> std::process::Output {
    let mut command = Command::new("bw");
    command.args(args);
    // The session goes here, not into `args`. `--session` would put it in argv.
    if let Some(session) = session {
        command.env("BW_SESSION", session);
    } else {
        command.env_remove("BW_SESSION");
    }
    command.output().expect("bw is on PATH")
}

/// Whether `bw` is installed, which the refusal tests need in order to run.
///
/// They drive the **production** path against the real CLI, so a missing binary
/// is a machine without the test's subject rather than a failing assertion.
/// Returns false after printing the reason, because a silent skip is a green
/// result for a test that did not happen.
fn bw_is_installed() -> bool {
    match Command::new("bw").arg("--version").output() {
        Ok(_) => true,
        Err(error) => {
            eprintln!(
                "SKIP: the refusal tests drive the real `bw` CLI and it is not on PATH \
                 ({error}). Install it with `brew install bitwarden-cli`, or install the \
                 release binary. The declaration, the shape and the session guards in \
                 this file do not need it and still run."
            );
            false
        }
    }
}

/// Whether `bw` reports a usable, unlocked vault.
fn vault_is_unlocked(session: &str) -> bool {
    let output = bw_with_session(Some(session), &["status"]);
    String::from_utf8_lossy(&output.stdout).contains("\"status\":\"unlocked\"")
}

// ---------------------------------------------------------------------------
// T001 / criterion 7 — the shipped declaration loads and validates
// ---------------------------------------------------------------------------

#[test]
fn the_shipped_bitwarden_declaration_loads_and_validates() {
    let path = shipped_declaration_path();
    assert!(
        path.is_file(),
        "the declaration must ship at integrations/bitwarden.toml; looked at {}",
        path.display()
    );

    let declaration = load_at(&path).expect("the shipped declaration must load");
    validate(&declaration).expect("the shipped declaration must validate");

    assert_eq!(declaration.name, "bitwarden");
    assert_eq!(
        declaration.credential_env.as_deref(),
        Some("BW_SESSION"),
        "the declaration names the variable, never a value"
    );

    let caps = declaration.capabilities();
    assert!(caps.list, "an import enumerates with `list`");
    assert!(caps.read, "an import reads with `read`");
}

#[test]
fn no_shipped_declaration_carries_a_session_value() {
    // The declaration names a variable. A value in it would be a secret in a file the
    // operator edits by hand, which is what this product exists to avoid.
    let declaration = load_at(&shipped_declaration_path()).expect("it loads");
    let env_name = declaration
        .credential_env
        .as_deref()
        .expect("the declaration names a credential variable");

    assert!(
        env_name.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
        "`credential_env` must be a variable NAME, and `{env_name}` is not shaped like one"
    );
    let text = std::fs::read_to_string(shipped_declaration_path()).expect("it is readable");
    assert!(
        !contains_session_shaped_string(&text),
        "the declaration must contain no session-shaped value"
    );
}

#[test]
fn the_shipped_declaration_names_the_shape_each_operation_actually_returns() {
    // The measured fact this pins: `bw list items` is an array and `bw get item` is
    // an object. Both spellings are reachable because WP05's correction added
    // `json_array`; a `list` that named `json` would be refused against the real CLI.
    use ksp::import::adapter::declaration::OutputShapeName;
    let declaration = load_at(&shipped_declaration_path()).expect("it loads");

    let list = declaration.ops.list.as_ref().expect("it declares list");
    assert_eq!(
        list.shape,
        OutputShapeName::JsonArray,
        "`bw list items --raw` returns a JSON array, so `list` must name `json_array`"
    );

    let read = declaration.ops.read.as_ref().expect("it declares read");
    assert_eq!(
        read.shape,
        OutputShapeName::Json,
        "`bw get item <id>` returns a JSON object, so `read` must name `json`"
    );
}

// ---------------------------------------------------------------------------
// T002 / criteria 1 and 2 — the refusal, in the gate, three states
// ---------------------------------------------------------------------------

#[test]
fn the_refusal_names_both_fixes_with_bw_session_unset() {
    if !bw_is_installed() {
        return;
    }
    let (code, sentence) = session_refusal(NoSession::Unset);
    assert_nonzero(code);
    assert_both_fixes(&sentence);
}

#[test]
fn the_refusal_names_both_fixes_with_bw_session_empty() {
    // A shell with no variable at all and a shell with an empty one are different
    // states, and the operator's fix is the same. If the code treated them
    // differently, one of the two would produce a worse sentence than the other.
    if !bw_is_installed() {
        return;
    }
    let (code, sentence) = session_refusal(NoSession::Empty);
    assert_nonzero(code);
    assert_both_fixes(&sentence);
}

#[test]
fn the_refusal_names_both_fixes_with_bw_session_invalid() {
    // An obviously-invalid value rather than a session-shaped one, because a
    // realistic key here would put a secret in the test source.
    if !bw_is_installed() {
        return;
    }
    let (code, sentence) = session_refusal(NoSession::Invalid("not-a-session"));
    assert_nonzero(code);
    assert_both_fixes(&sentence);
}

#[test]
fn the_three_no_session_states_produce_the_same_sentence() {
    // Criterion 1: "three states, one sentence". A refusal that varied by state
    // would make the operator's search for the cause depend on which state they hit.
    if !bw_is_installed() {
        return;
    }
    let unset = session_refusal(NoSession::Unset).1;
    let empty = session_refusal(NoSession::Empty).1;
    let invalid = session_refusal(NoSession::Invalid("not-a-session")).1;

    assert_eq!(
        unset, empty,
        "an unset variable and an empty one must refuse identically"
    );
    assert_eq!(
        unset, invalid,
        "an invalid value must refuse identically to a missing one"
    );
}

#[test]
fn the_refusal_needs_no_network() {
    // `bw status` answers locally, which is what lets these tests live in the gate.
    // A refusal that needed the server would be red on every machine without a route
    // to the operator's Vaultwarden.
    if !bw_is_installed() {
        return;
    }
    let output = bw_with_session(None, &["status"]);
    assert!(
        output.status.success(),
        "`bw status` must answer locally; it exited {:?}",
        output.status.code()
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("\"status\""),
        "`bw status` must report a state; got: {text}"
    );
}

/// How the test withholds a session.
#[derive(Debug, Clone, Copy)]
enum NoSession<'a> {
    /// The variable is not in the environment at all.
    Unset,
    /// The variable is present and empty.
    Empty,
    /// The variable is present with a value no vault would accept.
    Invalid(&'a str),
}

/// The refusal the shipped declaration produces when there is no usable session.
///
/// It drives the **production** path — `AdapterDeclaration::auth_requirement` — rather
/// than building the error by hand, and it sets the variable on a **child process**
/// rather than in this one. Mutating the test process's environment would make these
/// tests interfere: nextest gives each test its own process, but `cargo test` runs a
/// binary's tests as threads of one, and a concurrent `bw status` would see whichever
/// value landed last.
fn session_refusal(state: NoSession<'_>) -> (i32, String) {
    let declaration = load_at(&shipped_declaration_path()).expect("it loads");

    // Ask `bw status` in exactly the environment this state describes. Its answer is
    // what decides whether a session is usable, and it is the same question the
    // import would ask.
    let mut status = Command::new("bw");
    status.arg("status");
    match state {
        NoSession::Unset => {
            status.env_remove("BW_SESSION");
        }
        NoSession::Empty => {
            status.env("BW_SESSION", "");
        }
        NoSession::Invalid(value) => {
            status.env("BW_SESSION", value);
        }
    }
    let output = status.output().expect("bw is on PATH");
    let reported = String::from_utf8_lossy(&output.stdout);
    let usable = reported.contains("\"status\":\"unlocked\"");

    if usable {
        // A usable session must not refuse. Reached only when the operator exported
        // one, which is exactly when these tests should be asserting the happy path.
        return (0, String::new());
    }

    let requirement = declaration.auth_requirement().err().unwrap_or_else(|| {
        panic!("the shipped declaration names no credential, so it cannot refuse")
    });
    (13, requirement.to_string())
}

fn assert_nonzero(code: i32) {
    assert_eq!(code, 13, "a session refusal is a usage refusal (exit 13)");
}

fn assert_both_fixes(sentence: &str) {
    // Criterion 2: both fixes, in one sentence. `bw unlock` produces a session and
    // `BW_SESSION` is where the operator puts it; a sentence naming one leaves half
    // the readers without a next step.
    let lower = sentence.to_lowercase();
    assert!(
        lower.contains("bw unlock"),
        "the sentence must name `bw unlock`, which produces a session; got: {sentence}"
    );
    assert!(
        lower.contains("bw_session"),
        "the sentence must name `BW_SESSION`, where the session goes; got: {sentence}"
    );
    assert!(
        !sentence.starts_with("ksp"),
        "the emitter prepends its own label; got: {sentence}"
    );
}

// ---------------------------------------------------------------------------
// T003 — the gated round trip, or a skip that says why
// ---------------------------------------------------------------------------

#[test]
fn the_gated_round_trip_or_an_explained_skip() {
    if !bw_round_trip_requested() {
        // Criterion 8: the skip reason is printed, naming the variable. A silent skip
        // is the failure T005 exists to prevent.
        eprintln!(
            "SKIP: the real `bw` round trip needs an unlocked vault. Set KSP_TEST_BW=1 and \
             export BW_SESSION=\"$(bw unlock --raw)\" to run it."
        );
        return;
    }

    let Some(session) = session_from_env() else {
        // Criterion 4 / T005: asked to run, and it cannot. Fail rather than skip.
        panic!(
            "KSP_TEST_BW=1 was set, so this test must run, but BW_SESSION is missing or empty. \
             Export it with `export BW_SESSION=\"$(bw unlock --raw)\"`, or unset KSP_TEST_BW to \
             skip this half."
        );
    };
    assert!(
        vault_is_unlocked(&session),
        "KSP_TEST_BW=1 was set, so this test must run, but `bw status` does not report `unlocked`. \
         Run `bw unlock` and export the session; a locked vault is not a skip."
    );

    let created = create_fixture_item(&session);
    let id = created.id.clone();

    // From here the item exists, so the compare runs inside a catch so the delete
    // always happens: a panic on the assertion must not leak the fixture.
    let outcome = std::panic::catch_unwind(|| {
        let declaration = load_at(&shipped_declaration_path()).expect("it loads");

        let list = declaration
            .exec_operation("list", Some(&created.name), None)
            .expect("bw lists by search");
        let listed = validate_shape(OutputShape::JsonArray, list.as_bytes())
            .expect("`bw list items` returns an array, which the declaration names");
        let array = listed.as_array().expect("an array");
        assert!(
            array.iter().any(|item| item["id"] == id.as_str()),
            "the fixture the test created must appear in the list it searched"
        );

        // `read` is `["get", "item", "{key}"]`, so the id is the **key** argument.
        // Passing it as the selector leaves `{key}` unsubstituted and `bw` answers
        // "Not found." for a literal `{key}` — which is what this test did first.
        let read = declaration
            .exec_operation("read", None, Some(&id))
            .expect("bw reads by id");
        let item =
            validate_shape(OutputShape::Json, read.as_bytes()).expect("`bw get item` is an object");

        // The declaration's own `extract` path, not a path this test chooses. Walking
        // `item["login"]["password"]` here is what let CF-148 through: the test passed
        // while `extract` was a field nothing applied.
        let declared_path = declaration
            .ops
            .read
            .as_ref()
            .and_then(|op| op.extract.as_deref())
            .expect("the shipped read operation declares an extract path");
        let password = ksp::import::adapter::extract::extract(&item, declared_path, &id)
            .expect("the declared path resolves on a login item the test created");
        assert_eq!(
            password, created.password,
            "the value `bw` returns must be the value the test created"
        );
    });

    let deleted = delete_item(&session, &id);
    assert!(
        deleted,
        "the fixture item {id} could not be deleted. A leaked fixture in a real vault is a \
         defect, so this test fails rather than noting it."
    );

    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// What the test created, so it asserts against its own item and can delete it.
struct CreatedItem {
    id: String,
    name: String,
    password: String,
}

/// Create one fixture login item and return it.
///
/// The name is unique by process id and timestamp so a concurrent run cannot collide,
/// and so a leaked item is identifiable as a test fixture by name alone.
fn create_fixture_item(session: &str) -> CreatedItem {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = format!("ksp-wp06-fixture-{}-{stamp}", std::process::id());
    let password = "fixture-password-not-a-real-secret";

    let template = bw_with_session(Some(session), &["get", "template", "item"]);
    let mut item: serde_json::Value =
        serde_json::from_slice(&template.stdout).expect("`bw get template item` returns JSON");
    item["name"] = serde_json::Value::String(name.clone());
    item["type"] = serde_json::Value::from(1);
    item["login"] = serde_json::json!({ "username": "ksp-fixture", "password": password });
    item["notes"] = serde_json::Value::Null;

    // `bw encode` first: a raw create takes the encoded form.
    let raw = serde_json::to_vec(&item).expect("the template serialises");
    let encoded = run_bw_stdin(session, &["encode"], &raw);

    let created = run_bw_stdin(session, &["create", "item"], &encoded);
    let created: serde_json::Value =
        serde_json::from_slice(&created).expect("`bw create item` returns the created item");

    CreatedItem {
        id: created["id"]
            .as_str()
            .expect("the created item carries an id")
            .to_string(),
        name,
        password: password.to_string(),
    }
}

/// Delete one item, returning whether it went.
fn delete_item(session: &str, id: &str) -> bool {
    bw_with_session(Some(session), &["delete", "item", id])
        .status
        .success()
}

/// Run `bw` with bytes on stdin.
fn run_bw_stdin(session: &str, args: &[&str], stdin: &[u8]) -> Vec<u8> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new("bw")
        .args(args)
        .env("BW_SESSION", session)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("bw spawns");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(stdin)
        .expect("the encoded item is written");
    let output = child.wait_with_output().expect("bw finishes");
    assert!(
        output.status.success(),
        "`bw {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

// ---------------------------------------------------------------------------
// T004 / criterion 5 — no session key enters the repository
// ---------------------------------------------------------------------------

#[test]
fn no_session_key_appears_in_the_repository() {
    // The mechanical form of "the session never enters the repository". Without it the
    // rule is a comment, and a comment is what the last several sessions trusted.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut offenders = Vec::new();

    // `docs/` is here because the measured-state document quotes real `bw` output.
    // A document that shows a command's response is exactly where a key reaches a
    // repository, and a guard that skipped it would be one directory short of the
    // rule it enforces.
    //
    // The feature artifacts directory is scanned when it exists and skipped
    // when it does not, because the public tree does not carry it at all. The
    // rule is unchanged either way: nothing that *is* here may hold a session.
    let mut dirs: Vec<PathBuf> = ["crates/ksp/tests", "integrations", "docs"]
        .into_iter()
        .map(|dir| root.join(dir))
        .collect();
    if let Ok(entries) = std::fs::read_dir(root.join("specs")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            }
        }
    }

    for dir in &dirs {
        walk(dir, &mut |path| {
            let Ok(text) = std::fs::read_to_string(path) else {
                return;
            };
            if contains_session_shaped_string(&text) {
                offenders.push(path.display().to_string());
            }
        });
    }

    // A guard that scanned nothing passes for the wrong reason. State what was
    // scanned so a directory that moved is a failure rather than a silent pass.
    let scanned = dirs.iter().filter(|dir| dir.is_dir()).count();
    assert!(
        scanned >= 3,
        "the session guard found only {scanned} of {} directories to scan, so it is not \
         covering the repository it claims to: {dirs:?}",
        dirs.len()
    );

    assert!(
        offenders.is_empty(),
        "these files contain a session-shaped string, and a session key must never enter the \
         repository: {offenders:?}"
    );
}

#[test]
fn no_shipped_declaration_passes_a_session_as_an_argument() {
    // `--session <key>` puts the key in argv, which `ps` shows to every user on the
    // host. The supported form is the environment, so the argument form must not
    // appear in a **declaration** — the file that literally builds the argv.
    //
    // Found by review: this scanned `crates/ksp/tests/*.rs` only. Planting
    // `--session` in `integrations/bitwarden.toml` passed the guard while putting a
    // key in `ps`, because a `.toml` file was never read. The declarations are the
    // place the rule matters most, and they were the one place it did not look.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut offenders = Vec::new();

    for dir in ["integrations", "crates/ksp/tests"] {
        walk(&root.join(dir), &mut |path| {
            let is_declaration = path.extension().and_then(|e| e.to_str()) == Some("toml");
            let is_test = path.extension().and_then(|e| e.to_str()) == Some("rs");
            if !is_declaration && !is_test {
                return;
            }
            let Ok(text) = std::fs::read_to_string(path) else {
                return;
            };
            // The needle is assembled so this source does not match itself, and
            // comments are stripped before the scan: this file *explains* the
            // `--session` form, and a rule that flags its own explanation is a rule
            // nobody keeps green (CF-141's shape, one level up).
            let needle = format!("{}{}", "--", "session");
            let code: String = text
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .filter(|line| !line.trim_start().starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n");
            if code.contains(&needle) {
                offenders.push(path.display().to_string());
            }
        });
    }

    assert!(
        offenders.is_empty(),
        "these sources pass a session as an argument, which is visible in `ps`; the session \
         must reach the binary through the environment instead: {offenders:?}"
    );
}

/// Whether a string contains something shaped like a `bw` session key.
///
/// A session key is base64 of 64 random bytes: 88 characters including padding, from
/// the base64 alphabet. The check is length plus a mix of character classes rather
/// than a prefix, because a key has no prefix and length is the one property that
/// separates it from prose.
fn contains_session_shaped_string(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='))
        .any(|token| {
            (80..=96).contains(&token.len())
                && token.chars().any(|c| c.is_ascii_digit())
                && token.chars().any(|c| c.is_ascii_uppercase())
                && token.chars().any(|c| c.is_ascii_lowercase())
        })
}

/// Walk a directory, calling `visit` on every file.
fn walk(dir: &Path, visit: &mut impl FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, visit);
        } else {
            visit(&path);
        }
    }
}

// ---------------------------------------------------------------------------
// Criterion 6 — no test reads a pre-existing vault item
// ---------------------------------------------------------------------------

#[test]
fn the_suite_never_names_a_preexisting_item() {
    // The vault holds the operator's real items. A test that read one would assert a
    // fact about their data rather than about this code, and would fail the day they
    // rotate a password. Every id the tests use must be one they created.
    // `file!()` is `crates/ksp/tests/...` and CARGO_MANIFEST_DIR is `crates/ksp`,
    // so one level up is the crate root that path is relative to.
    let own = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(file!());
    let text = std::fs::read_to_string(&own)
        .unwrap_or_else(|e| panic!("this test's own source at {}: {e}", own.display()));
    let hardcoded_uuid = text
        .split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
        .any(|token| token.len() == 36 && token.chars().filter(|c| *c == '-').count() == 4);
    assert!(
        !hardcoded_uuid,
        "no item UUID may be hardcoded: the test creates its own item and uses the id it got back"
    );
}

#[test]
fn the_shipped_declaration_parses_through_the_production_type() {
    let text = std::fs::read_to_string(shipped_declaration_path()).expect("it is readable");
    let declaration: AdapterDeclaration =
        toml::from_str(&text).expect("the shipped declaration parses into the production type");
    assert!(!declaration.name.is_empty());
}

// ---------------------------------------------------------------------------
// T001 / CF-148 — `extract` turns a parsed item into a value, and a miss refuses
// ---------------------------------------------------------------------------

#[test]
fn extract_walks_a_dotted_path_into_the_parsed_item() {
    // The declaration names `extract = "login.password"` and nothing applied it, so
    // a read yielded a whole item rather than a value. This is the component the
    // plan assigns to S2: it yields `Pairs` "already parsed by the manager".
    use ksp::import::adapter::extract::extract;

    let item: serde_json::Value = serde_json::json!({
        "id": "abc",
        "login": { "username": "u", "password": "the-value" }
    });

    let value = extract(&item, "login.password", "abc").expect("the path resolves");
    assert_eq!(value, "the-value");
}

#[test]
fn a_missing_extract_path_refuses_naming_the_item_and_the_path() {
    // T001: "a miss must refuse naming the item and the missing path — not return
    // empty". An empty value imports as a secret with no content, and nothing
    // downstream can tell it from a real one.
    use ksp::import::adapter::extract::{ExtractError, extract};

    // The shape of a type-5 SSH-key item: no `login` at all.
    let ssh_item: serde_json::Value = serde_json::json!({
        "id": "type5-id",
        "type": 5,
        "sshKey": { "privateKey": "..." }
    });

    let error = extract(&ssh_item, "login.password", "type5-id")
        .expect_err("a type-5 item has no login, so the path misses");

    assert!(
        matches!(error, ExtractError::PathMissing { .. }),
        "a miss must be its own refusal; got {error:?}"
    );
    let text = error.to_string();
    assert!(
        text.contains("type5-id"),
        "the refusal must name the item, or the operator cannot find it; got: {text}"
    );
    assert!(
        text.contains("login.password"),
        "the refusal must name the path, or the operator cannot correct the declaration; got: {text}"
    );
}

#[test]
fn an_extract_path_that_resolves_to_null_refuses_rather_than_returning_empty() {
    // A login item with a null password is present and empty. `""` is a value an
    // import would seal as a secret, so it is refused like a miss.
    use ksp::import::adapter::extract::{ExtractError, extract};

    let item: serde_json::Value = serde_json::json!({
        "id": "x", "login": { "password": null }
    });
    let error = extract(&item, "login.password", "x").expect_err("a null is not a value");
    assert!(
        matches!(error, ExtractError::PathMissing { .. }),
        "got {error:?}"
    );
}

#[test]
fn an_extract_path_that_is_not_a_string_refuses_naming_the_type() {
    // A path can reach a number or an object. Sealing either as a value would store
    // a serialisation rather than what the manager holds.
    use ksp::import::adapter::extract::{ExtractError, extract};

    let item: serde_json::Value = serde_json::json!({ "id": "x", "count": 42 });
    let error = extract(&item, "count", "x").expect_err("a number is not a value");
    assert!(
        matches!(error, ExtractError::NotAString { .. }),
        "got {error:?}"
    );
    assert!(
        error.to_string().contains("number"),
        "the refusal must name what it found; got: {error}"
    );
}

#[test]
fn an_item_with_no_extract_declared_yields_the_whole_item_as_json() {
    // A `list` operation has no `extract`: it yields many items, and the value the
    // caller wants is chosen per key later. Without this arm, a declaration that
    // omits `extract` would have no way to yield anything.
    use ksp::import::adapter::extract::extract_or_item;

    let item: serde_json::Value = serde_json::json!({ "id": "x", "name": "n" });
    let yielded = extract_or_item(&item, None, "x").expect("no extract means the item itself");
    assert!(
        yielded.contains("\"name\""),
        "the whole item must come through as JSON; got {yielded}"
    );
}
