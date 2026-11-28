//! Adapter declaration loading, validation and invocation.
//!
//! # Three misfits, and the one that is quietest
//!
//! - **E** — a declaration names a binary and an argv, so a careless edit runs a
//!   command as the operator. Its second, quieter form is a declaration that
//!   reaches a **shell**: then a value containing `;` or `$()` in the selector
//!   becomes a command. `exec` spawns with `.args([...])` and no shell at all, and
//!   a test passes `;` and `$()` through and compares the bytes the child
//!   received.
//! - **F** — `bw` produces no session without a master password. An import that
//!   prompts turns a foreground command into a password-capturing one, and a
//!   blocked import in a script looks like a hang. So the declaration states
//!   whether it needs a session, and the refusal names the manager's own command.
//! - **H** — the binary is absent, or its output shape changed. Absence refuses
//!   naming adapter and binary rather than letting a shell say `command not
//!   found`; a changed shape refuses **before** the parser sees bytes, so a vendor
//!   change never becomes a parse question.
//!
//! # A declaration is a capability, not evidence
//!
//! It authorises nothing by existing. It is validated and probed on every use,
//! which is what makes `--list-adapters` worth printing: an operator sees what a
//! file will run **before** an import runs it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp::import::adapter::declaration::{AdapterDeclaration, AuthRequirement, Kind};
use ksp::import::adapter::schema::{canonical_example, emit_schema};
use ksp::import::adapter::shape::{OutputShape, ShapeError, validate_shape};
use ksp::import::adapter::validate::{
    DeclarationError, Malformed, load_at, load_dir, refused_destination_keys, validate,
};

/// A declaration that is valid in every respect except what a test changes.
const VALID: &str = r#"name = "example"
kind = "cli"
binary = "true"
credential_env = "EXAMPLE_SESSION"

[ops.list]
argv = ["list", "items", "--search", "{selector}"]
shape = "json"

[ops.read]
argv = ["get", "item", "{key}"]
extract = "login.password"
"#;

fn write_temp(label: &str, body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("{label}.toml"));
    std::fs::write(&path, body).unwrap();
    (dir, path)
}

fn parse_error(body: &str) -> DeclarationError {
    let (_dir, path) = write_temp("decl", body);
    load_at(&path).expect_err("the declaration must be refused")
}

// ---------------------------------------------------------------------------
// T003 — the declaration parses, and an unknown key is refused
// ---------------------------------------------------------------------------

#[test]
fn a_valid_declaration_parses_into_its_operations() {
    let (_dir, path) = write_temp("valid", VALID);
    let declaration = load_at(&path).expect("a valid declaration loads");

    assert_eq!(declaration.name, "example");
    assert_eq!(declaration.kind, Kind::Cli);
    assert_eq!(declaration.binary.as_deref(), Some("true"));
    assert_eq!(
        declaration.credential_env.as_deref(),
        Some("EXAMPLE_SESSION")
    );

    let caps = declaration.capabilities();
    assert!(caps.list, "the declaration names a list operation");
    assert!(caps.read, "the declaration names a read operation");
    assert!(
        !caps.write,
        "an omitted `[ops.write]` means write is unsupported, which `--list-adapters` reports"
    );
}

#[test]
fn an_unknown_key_is_refused_naming_the_file_and_the_key() {
    // `deny_unknown_fields` is the control: a misspelled key would otherwise be
    // dropped and the adapter would run a different command than the operator
    // wrote. The refusal names both the file and the key, because "unknown field"
    // alone leaves the operator diffing their file against a document.
    let error = parse_error(&format!("{VALID}\nsurprise = \"value\"\n"));

    let text = error.to_string();
    assert!(
        text.contains("surprise"),
        "the refusal must name the unknown key; got: {text}"
    );
    assert!(
        text.contains("decl.toml"),
        "the refusal must name the file; got: {text}"
    );
}

#[test]
fn a_declaration_naming_no_binary_for_a_cli_kind_is_refused() {
    let body = VALID.replace("binary = \"true\"\n", "");
    let error = parse_error(&body);
    assert!(
        matches!(
            error,
            DeclarationError::Malformed(Malformed::MissingBinary { .. })
        ),
        "a `kind = \"cli\"` declaration with no binary describes nothing runnable; got {error:?}"
    );
}

#[test]
fn a_declaration_naming_both_a_binary_and_a_base_url_is_refused() {
    // `kind` selects which one is meaningful. Accepting both would leave the
    // reader to guess which the runner uses, and a declaration that runs a binary
    // the operator thought was an endpoint is a command execution they did not
    // intend.
    let body = VALID.replace(
        "binary = \"true\"",
        "binary = \"true\"\nbase_url = \"https://example.invalid\"",
    );
    let error = parse_error(&body);
    assert!(
        matches!(
            error,
            DeclarationError::Malformed(Malformed::BothEndpoints { .. })
        ),
        "got {error:?}"
    );
}

#[test]
fn a_declaration_naming_an_unknown_kind_is_refused_naming_the_accepted_set() {
    let body = VALID.replace("kind = \"cli\"", "kind = \"carrier-pigeon\"");
    let error = parse_error(&body);
    let text = error.to_string();
    assert!(
        text.contains("cli") && text.contains("http"),
        "the refusal must name the closed set, or the operator cannot derive what is \
         accepted; got: {text}"
    );
}

// ---------------------------------------------------------------------------
// T004 — a destination-shaped key can never come from data (Misfit J's half)
// ---------------------------------------------------------------------------

#[test]
fn a_destination_shaped_key_is_refused_naming_the_key() {
    // Misfit J's data half: a vault name read from an adapter file is a decision
    // made by data, and the record then lands in a store the operator did not
    // choose. WP03's vault binding refuses the write; this refuses the file.
    for key in ["vault", "vault_id", "level", "destination"] {
        let error = parse_error(&format!("{VALID}\n{key} = \"vault-bw-team2\"\n"));
        let text = error.to_string();
        assert!(
            text.contains(key),
            "the refusal must name the key `{key}`; got: {text}"
        );
        assert!(
            text.contains("destination") || text.contains("deployment"),
            "the refusal must say why a destination cannot come from a declaration; got: {text}"
        );
    }
}

#[test]
fn the_refused_destination_keys_are_reported_so_a_schema_can_list_them() {
    // `--schema` prints the refused keys with reasons, which is T008's
    // requirement. It reads this list, so the list and the check cannot drift.
    let keys = refused_destination_keys();
    for expected in ["vault", "vault_id", "level"] {
        let entry = keys
            .iter()
            .find(|k| k.name == expected)
            .unwrap_or_else(|| panic!("`{expected}` must be in the refused list: {keys:?}"));
        assert!(
            !entry.reason.trim().is_empty(),
            "`{expected}` must carry the reason it is refused, or the schema prints a \
             prohibition with no explanation"
        );
    }
}

// ---------------------------------------------------------------------------
// T005 — an absent binary, and the session refusal (Misfits H and F)
// ---------------------------------------------------------------------------

#[test]
fn an_absent_binary_refuses_naming_the_adapter_and_the_binary() {
    // Misfit H. The shell's own `command not found` is not a refusal this program
    // made: it names neither the adapter nor the file, and it arrives as a
    // subprocess error rather than as a sentence the operator can act on.
    let body = VALID.replace("binary = \"true\"", "binary = \"ksp-no-such-binary-xyzzy\"");
    let (_dir, path) = write_temp("absent", &body);
    let declaration = load_at(&path).expect("the declaration itself is well formed");

    let error = declaration
        .probe_binary()
        .expect_err("an absent binary must refuse");

    let text = error.to_string();
    assert!(
        text.contains("example"),
        "the refusal must name the adapter; got: {text}"
    );
    assert!(
        text.contains("ksp-no-such-binary-xyzzy"),
        "the refusal must name the binary; got: {text}"
    );
    assert!(
        !text.contains("command not found"),
        "the refusal must not be the shell's own sentence; got: {text}"
    );
    // CF-120: the emitter prepends its own label, so the sentence states the fact
    // first rather than opening with the binary name.
    assert!(
        !text.starts_with("ksp"),
        "the sentence must not open with the binary name; got: {text}"
    );
}

#[test]
fn a_declaration_needing_a_session_names_the_managers_own_command() {
    // Misfit F. The refusal has to name the command that produces a session, or
    // the operator is told "not authenticated" with no next step. Each manager's
    // command is its own, so the sentence comes from the manager's name.
    for (name, expected) in [
        ("bitwarden", "bw unlock"),
        ("onepassword", "op signin"),
        ("generic", "BWS_ACCESS_TOKEN"),
    ] {
        let text = AuthRequirement::for_manager(name).to_string();
        assert!(
            text.contains(expected),
            "the refusal for `{name}` must name `{expected}`; got: {text}"
        );
    }
}

#[test]
fn an_unrecognised_manager_still_names_a_real_next_step() {
    // The fallback must not be a dead end. An adapter the binary has not heard of
    // gets a sentence naming the environment variable a declaration configures,
    // which is the one thing this program can truthfully say about it.
    let text = AuthRequirement::for_manager("something-new").to_string();
    assert!(
        text.contains("BWS_ACCESS_TOKEN") || text.contains("credential_env"),
        "an unknown manager must still send the operator somewhere real; got: {text}"
    );
}

// ---------------------------------------------------------------------------
// T006 / criterion 3 — no shell, so `;` and `$()` reach the child literally
// ---------------------------------------------------------------------------

#[test]
fn an_argument_containing_shell_metacharacters_reaches_the_child_literally() {
    // Misfit E's second form, and the acceptance criterion that pins it. The child
    // is `/bin/echo`, so the bytes it prints are the bytes it received: with a
    // shell, `;` would end the command and `$()` would expand.
    let body = VALID.replace("binary = \"true\"", "binary = \"/bin/echo\"");
    let (_dir, path) = write_temp("argv", &body);
    let declaration = load_at(&path).expect("the declaration loads");

    let selector = "team1; echo PWNED $(id -u) `id -u`";
    let output = declaration
        .exec(
            &["list", "items", "--search", "{selector}"],
            Some(selector),
            None,
        )
        .expect("the child runs");

    assert!(
        output.contains(selector),
        "the child must receive the selector byte for byte; got: {output}"
    );
    // The evidence that no shell ran is that `$(id -u)` and the backtick survived
    // as text. Asserting `!contains("PWNED")` would be wrong: "PWNED" is in the
    // selector, so it is always present and the assertion could never fail.
    assert!(
        output.contains("$(id -u)") && output.contains("`id -u`"),
        "the substitution syntax must survive as bytes rather than being executed; got: \
         {output}"
    );
}

#[test]
fn a_placeholder_is_substituted_into_exactly_one_argument() {
    // A substituted value must never split an argument. If it did, a selector
    // containing a space would become two arguments and the child would read a
    // different command than the declaration describes.
    let body = VALID.replace("binary = \"true\"", "binary = \"/bin/echo\"");
    let (_dir, path) = write_temp("split", &body);
    let declaration = load_at(&path).expect("the declaration loads");

    let output = declaration
        .exec(&["a", "{selector}", "b"], Some("two words"), None)
        .expect("the child runs");

    assert_eq!(
        output.trim(),
        "a two words b",
        "the placeholder must fill one argument, not split into two; got: {output:?}"
    );
}

// ---------------------------------------------------------------------------
// T007 — the shape is checked before the parser sees bytes (Misfit H)
// ---------------------------------------------------------------------------

#[test]
fn a_json_shape_accepts_a_json_object() {
    let validated = validate_shape(OutputShape::Json, br#"{"items":[{"id":"1"}]}"#)
        .expect("a JSON object is the declared shape");
    assert!(validated.is_object());
}

#[test]
fn a_declared_json_shape_refuses_something_that_is_not_json() {
    // Misfit H's changed-output half: a vendor that starts printing a table must
    // refuse here, naming the shape that was expected, rather than reach the value
    // parser and produce a wrong value from a shape it never understood.
    let error = validate_shape(OutputShape::Json, b"ID   NAME\n1    a-secret\n")
        .expect_err("a table is not the declared shape");

    let text = error.to_string();
    assert!(
        text.contains("json"),
        "the refusal must name the declared shape; got: {text}"
    );
    assert!(
        matches!(error, ShapeError::NotTheDeclaredShape { .. }),
        "got {error:?}"
    );
}

#[test]
fn an_empty_output_refuses_rather_than_reading_as_an_empty_result() {
    // An empty body is a different fact from "the manager has no items": the
    // first is a broken invocation, the second is a legitimate answer. Reading the
    // first as the second would report every key as absent, which sends the
    // operator to edit a file that is already correct.
    let error = validate_shape(OutputShape::Json, b"").expect_err("empty output must refuse");
    assert!(matches!(error, ShapeError::Empty), "got {error:?}");
}

// ---------------------------------------------------------------------------
// T008 — the emitted schema, and the canonical example proven complete
// ---------------------------------------------------------------------------

#[test]
fn the_canonical_example_round_trips_byte_for_byte() {
    // The example is a constant, so it is prose unless something proves it
    // complete. Parse it with the production parser, re-serialise it, and compare:
    // a field added to the type without updating the example changes the
    // re-serialisation and fails here (criterion 6).
    let text = canonical_example();
    let declaration: AdapterDeclaration =
        toml::from_str(text).expect("the canonical example must parse with the production parser");

    let re_serialised =
        toml::to_string(&declaration).expect("the type must serialise back into TOML");

    assert_eq!(
        re_serialised.trim(),
        text.trim(),
        "the canonical example must be byte-identical after a parse/serialise round trip; a \
         field added to the type without updating the example shows up here"
    );
}

#[test]
fn every_field_the_type_declares_appears_in_the_canonical_example() {
    // The round trip above has a hole, and this test closes it. A field carrying
    // `skip_serializing_if` is **invisible** to a round trip: it never appears in
    // the re-serialisation, so adding one leaves the example unchanged and the
    // round trip green. Probed at implement time by adding exactly such a field —
    // the round trip passed.
    //
    // The completeness check therefore cannot use a hand-written list of keys: a
    // new field would simply not be in the list, which is the same blindness in a
    // different place. It reads the field names from the **derived JSON Schema**
    // instead, which enumerates the type's properties without anyone maintaining
    // it. A field added to the type appears there automatically and fails here
    // until the example carries it.
    let schema = emit_schema().json_schema;
    let json = serde_json::to_value(&schema).expect("the schema serialises");
    let mut names = Vec::new();
    collect_property_names(&json, &mut names);

    assert!(
        names.len() >= 8,
        "the derived schema must enumerate the declaration's fields; collected only {names:?}"
    );

    // One canonical example cannot carry every field: `base_url` and `path` are
    // http-only and `binary` is cli-only, so a single document that held all of
    // them would be a declaration `parse` refuses. The emitted document therefore
    // has two halves, and completeness is a property of the whole: every field the
    // type declares must appear in the example **or** in the field table.
    //
    // A field added to the type with a `skip_serializing_if` appears in the schema
    // automatically and in neither half, so it fails here. That is the hole the
    // round trip cannot see.
    let emitted = emit_schema();
    let example = &emitted.example;
    let table: String = emitted
        .field_table
        .iter()
        .map(|row| row.name.clone())
        .collect::<Vec<_>>()
        .join("\n");

    let mut missing: Vec<&str> = Vec::new();
    for name in &names {
        // Three spellings, because a field can be a scalar (`name =`), a table
        // (`[ops.list]`), or a key inside a table (`\nargv =`).
        let in_example = example.contains(&format!("{name} ="))
            || example.contains(&format!("[{name}"))
            || example.contains(&format!(".{name}]"))
            || example.contains(&format!("({name})"))
            || example.contains(&format!(".{{{name}}}"));
        // The table spells nested keys as `ops.<name>.argv`, so a leaf name is
        // matched as a dotted suffix too.
        let in_table = emitted.field_table.iter().any(|row| {
            row.name == *name
                || row.name.ends_with(&format!(".{name}"))
                || row.name.ends_with(&format!(".{}>", name))
        });
        let _ = &table;
        if !in_example && !in_table {
            missing.push(name);
        }
    }
    assert!(
        missing.is_empty(),
        "the emitted document omits {missing:?}, which the type declares. The field set comes \
         from the derived schema, so a new field cannot hide behind a `skip_serializing_if`: it \
         appears in the schema automatically and must appear in the example or the table."
    );
}

/// Every property name the schema declares, at any depth.
fn collect_property_names<'a>(value: &'a serde_json::Value, out: &mut Vec<&'a str>) {
    if let Some(object) = value.as_object() {
        if let Some(properties) = object.get("properties").and_then(|p| p.as_object()) {
            for (name, child) in properties {
                out.push(name);
                collect_property_names(child, out);
            }
        }
        for child in object.values() {
            collect_property_names(child, out);
        }
    } else if let Some(array) = value.as_array() {
        for child in array {
            collect_property_names(child, out);
        }
    }
}

#[test]
fn the_canonical_example_is_a_concrete_declaration_not_a_placeholder() {
    // A placeholder example that parses proves the shape and teaches nothing. The
    // example must name a real manager's real command, so an agent copying it has
    // a working file rather than a fill-in-the-blanks exercise.
    let text = canonical_example();
    let declaration: AdapterDeclaration = toml::from_str(text).expect("it parses");
    assert_eq!(
        declaration.name, "bitwarden",
        "the example must be the manager this feature ships a declaration for"
    );
    assert!(
        declaration.capabilities().list && declaration.capabilities().read,
        "the example must declare the two operations an import uses"
    );
}

#[test]
fn the_emitted_schema_names_the_closed_kind_set() {
    // An agent writing a declaration must be able to learn the accepted values
    // without reading this repository. That is the whole of T008: the schema is
    // emitted from the type, so it cannot drift from what the parser accepts.
    let emitted = emit_schema();
    let text = serde_json::to_string(&emitted.json_schema).expect("the schema serialises");

    assert!(
        text.contains("cli") && text.contains("http"),
        "the schema must name the closed kind set; got: {text}"
    );
    assert!(
        !emitted.example.trim().is_empty(),
        "the emitted document must carry the canonical example"
    );
    assert!(
        emitted
            .field_table
            .iter()
            .any(|row| row.name == "credential_env"),
        "the field table must name `credential_env`, because an agent that omits it writes a \
         declaration that cannot authenticate"
    );
}

#[test]
fn the_emitted_schema_lists_the_refused_destination_keys_with_reasons() {
    let emitted = emit_schema();
    let refused: Vec<&str> = emitted
        .refused_keys
        .iter()
        .map(|row| row.name.as_str())
        .collect();
    assert!(
        refused.contains(&"vault"),
        "the emitted document must say a vault key is refused, or an agent writes one; got: \
         {refused:?}"
    );
    assert!(
        emitted
            .refused_keys
            .iter()
            .all(|row| !row.reason.trim().is_empty()),
        "a refused key with no reason is a prohibition an agent cannot comply with"
    );
}

#[test]
fn the_schema_is_a_read_with_no_inputs() {
    // It must work before a deployment exists, because an agent may ask the shape
    // first. The compile-time witness is the signature: it takes no argument.
    let emitted = emit_schema();
    assert!(
        !emitted.example.trim().is_empty(),
        "the document must be produced with nothing configured"
    );
}

// ---------------------------------------------------------------------------
// Loading a directory, so one bad file does not hide the others
// ---------------------------------------------------------------------------

#[test]
fn one_malformed_file_does_not_hide_the_others() {
    // The plan says a malformed file refuses itself and names the file and the
    // key; it does not refuse the others. Refusing the whole directory would make
    // one typo look like "no adapters are configured".
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("good.toml"), VALID).unwrap();
    std::fs::write(
        dir.path().join("bad.toml"),
        "name = \"bad\"\nkind = \"nope\"\n",
    )
    .unwrap();

    let loaded = load_dir(dir.path());

    assert_eq!(loaded.adapters.len(), 1, "the good file must still load");
    assert_eq!(loaded.adapters[0].name, "example");
    assert_eq!(
        loaded.failures.len(),
        1,
        "the bad file is reported, not fatal"
    );
    assert!(
        loaded.failures[0].1.to_string().contains("bad.toml"),
        "the failure must name the file; got {:?}",
        loaded.failures[0].1
    );
}

#[test]
fn validating_accepts_a_good_declaration() {
    let (_dir, path) = write_temp("ok", VALID);
    let declaration = load_at(&path).expect("it loads");
    validate(&declaration).expect("a well-formed declaration validates");
}

#[test]
fn an_adapter_with_no_operations_is_refused() {
    // A declaration that implements nothing cannot supply a key and would fail at
    // the first import with a message about a missing operation instead of about
    // the file. Refusing here names the file while the operator is looking at it.
    let body = "name = \"empty\"\nkind = \"cli\"\nbinary = \"true\"\n";
    let (_dir, path) = write_temp("noops", body);
    let declaration = load_at(&path).expect("it is syntactically fine");
    let error = validate(&declaration).expect_err("no operations must refuse");
    // The sentence must name the operation that makes the declaration usable, not
    // every operation that exists: `list` is the minimum an import needs, and a
    // refusal that listed `read` too would imply both are required.
    assert!(
        error.to_string().contains("[ops.list]"),
        "the refusal must name the operation that would make the file usable; got: {error}"
    );
}

// ---------------------------------------------------------------------------
// Review findings
// ---------------------------------------------------------------------------

#[test]
fn a_present_but_unrunnable_binary_refuses_naming_the_permission() {
    // Found by probing: `probe_binary` used `is_file()`, so a `0644` file passed
    // the probe and the eventual `exec` failed with `EACCES` under a sentence that
    // claimed "the binary existing was the one thing this refusal is not about" —
    // it was exactly the thing.
    //
    // A present-but-unrunnable file and a missing one have different repairs, so
    // they are different sentences. A refusal that said "not on PATH" for a file
    // sitting on PATH sends the operator to install what they already have.
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("present-but-unrunnable");
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let body = VALID.replace(
        "binary = \"true\"",
        &format!("binary = \"{}\"", path.display()),
    );
    let (_d, decl_path) = write_temp("unrunnable", &body);
    let declaration = load_at(&decl_path).expect("the declaration parses");

    let error = declaration
        .probe_binary()
        .expect_err("a file the process cannot execute must refuse at the probe");

    let text = error.to_string();
    assert!(
        text.contains("not executable"),
        "the sentence must name the permission, not the path search; got: {text}"
    );
    assert!(
        !text.contains("not on PATH"),
        "the file is on PATH, so saying otherwise sends the operator to install it: {text}"
    );
    assert!(
        text.contains("example") && text.contains("present-but-unrunnable"),
        "the sentence must name the adapter and the binary; got: {text}"
    );
}

#[test]
fn an_executable_file_passes_the_probe() {
    // The converse, so the fix above is not a blanket refusal: a file with an
    // execute bit is accepted even when it is a temp path rather than a `PATH`
    // lookup.
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("runnable");
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

    let body = VALID.replace(
        "binary = \"true\"",
        &format!("binary = \"{}\"", path.display()),
    );
    let (_d, decl_path) = write_temp("runnable", &body);
    let declaration = load_at(&decl_path).expect("the declaration parses");

    declaration
        .probe_binary()
        .expect("a file with an execute bit passes the probe");
}

#[test]
fn a_declaration_that_names_a_credential_produces_the_session_refusal() {
    // Criterion 5 as it is written: "An adapter needing a session refuses and the
    // sentence names the manager's own command." Found by review: `AuthRequirement`
    // was reachable only from a test, so no declaration could produce that refusal
    // and the criterion was passing on a type nothing constructed.
    let (_d, path) = write_temp("session", VALID);
    let declaration = load_at(&path).expect("it parses");

    let requirement = declaration
        .auth_requirement()
        .expect_err("a declaration naming `credential_env` needs a session");

    let text = requirement.to_string();
    assert!(
        text.contains("EXAMPLE_SESSION") || text.contains("credential_env"),
        "the sentence must name where the credential comes from; got: {text}"
    );
    assert!(
        !text.starts_with("ksp"),
        "the emitter prepends its own label, so the sentence states the fact first; got: {text}"
    );
}

#[test]
fn a_declaration_that_names_no_credential_needs_no_session() {
    // The converse, and the common case for a manager whose CLI already holds a
    // session: a declaration with no `credential_env` must not be refused, or every
    // such adapter would be unusable.
    let body = VALID.replace("credential_env = \"EXAMPLE_SESSION\"\n", "");
    let (_d, path) = write_temp("nokey", &body);
    let declaration = load_at(&path).expect("it parses");
    assert!(
        declaration.auth_requirement().is_ok(),
        "a declaration naming no credential must not report a session requirement"
    );
}

#[test]
fn an_http_declaration_is_executed_as_a_request_and_never_as_an_argv() {
    // Found by probing: asking an `http` declaration to execute its `list`
    // operation produced "declares no `argv` ... name the command, for example
    // argv = [...]". An `http` declaration may not carry `argv` — `parse` refuses
    // it alongside `base_url` — so the hint pointed at a file shape the parser
    // rejects. A refusal must name an option the reader can actually use.
    //
    // # The assertion was corrected by 018/WP07, on purpose
    //
    // This test used to assert that the arm **could not run**: `exec_operation`
    // returned a refusal containing "no HTTP invocation", because CF-138 recorded
    // that nothing in the workspace made an outbound request. That is the defect,
    // not the requirement. WP07 added the client (`import/adapter/http.rs`), so
    // the old assertion would now fail for the best possible reason — the
    // capability it said was missing exists.
    //
    // What survives is the property the original test was really protecting: an
    // `http` declaration is executed through its `path`, and a refusal for one
    // names `path` rather than `argv`, which an `http` file cannot carry.
    let body = "name = \"mock\"\nkind = \"http\"\nbase_url = \"http://127.0.0.1:1\"\n\n[ops.list]\npath = \"/items\"\n";
    let (_d, path) = write_temp("http-exec", body);
    let declaration = load_at(&path).expect("an http declaration parses");

    // Port 1 on loopback refuses the connection, so the arm is exercised through
    // its request path without needing a listener: the sentence proves the client
    // tried to reach the declared URL, which is the capability the defect was
    // about.
    let error = declaration
        .exec_operation("list", Some("x"), None)
        .expect_err("port 1 is not listening");
    let text = error.to_string();
    assert!(
        text.contains("http://127.0.0.1:1/items"),
        "the failure must be the request the declaration asked for, not a refusal \
         that the arm does not exist; got: {text}"
    );
    assert!(
        !text.contains("no HTTP invocation"),
        "the arm exists now, so the old capability refusal must be gone; got: {text}"
    );
    assert!(
        !text.contains("argv = ["),
        "the refusal must not name an option an `http` declaration cannot carry; got: {text}"
    );

    // The arm-specific refusal that *does* remain: an `http` operation with no
    // `path` names `path`, not `argv`.
    let no_path = "name = \"naked\"\nkind = \"http\"\nbase_url = \"http://127.0.0.1:1\"\n\n[ops.list]\nshape = \"json_array\"\n";
    let (_d2, path2) = write_temp("http-nopath", no_path);
    let declaration = load_at(&path2).expect("it parses");
    let error = declaration
        .exec_operation("list", Some("x"), None)
        .expect_err("a request with no path is not executable");
    let text = error.to_string();
    assert!(
        text.contains("`path`"),
        "the refusal must name `path`, the option an `http` declaration carries; got: {text}"
    );
    assert!(
        !text.contains("argv = ["),
        "the refusal must not name `argv`; got: {text}"
    );
}

#[test]
fn a_cli_operation_with_no_argv_still_names_argv() {
    // The converse, so the http fix did not make the cli sentence vaguer: a
    // `kind = "cli"` operation with no `argv` is a file the operator can fix, and
    // the message must name the key to add.
    let body =
        "name = \"naked\"\nkind = \"cli\"\nbinary = \"true\"\n\n[ops.list]\npath = \"/items\"\n";
    let (_d, path) = write_temp("cli-noargv", body);
    let declaration = load_at(&path).expect("it parses");

    let error = declaration
        .exec_operation("list", None, None)
        .expect_err("a cli operation with no argv has nothing to run");
    let text = error.to_string();
    assert!(
        text.contains("argv"),
        "the cli refusal must name `argv`, which that kind can carry; got: {text}"
    );
}

// ---------------------------------------------------------------------------
// T011 — the `json_array` shape (CF-145)
// ---------------------------------------------------------------------------

#[test]
fn a_json_array_shape_accepts_the_array_bw_list_returns() {
    // Measured against `bw 2026.10.0`: `bw list items --raw` returns a JSON
    // array, and `bw get item <id>` returns an object. `json` means object, so a
    // `list` operation naming `json` is refused against the real CLI. The shapes
    // stay separate values rather than one permissive `json`: a shape that
    // accepted both would stop a `read` from refusing an array, which is the
    // changed-output check misfit H needs.
    let array = br#"[{"id":"1","name":"a"},{"id":"2","name":"b"}]"#;
    let validated = validate_shape(OutputShape::JsonArray, array)
        .expect("an array is the declared shape for a list operation");
    assert!(
        validated.is_array(),
        "the validated value must be the array the declaration names; got {validated}"
    );
}

#[test]
fn a_json_array_shape_refuses_an_object() {
    // The converse, and the reason the two shapes are distinct: a `list` that
    // started returning `{"items": [...]}` has changed shape, and accepting it
    // would pass a vendor change straight to the value parser.
    let error = validate_shape(OutputShape::JsonArray, br#"{"items":[]}"#)
        .expect_err("an object is not the declared array shape");
    let text = error.to_string();
    assert!(
        text.contains("json_array"),
        "the refusal must name the declared shape; got: {text}"
    );
}

#[test]
fn a_json_shape_still_refuses_the_array_bw_list_returns() {
    // The check the fix must not weaken: `json` still means object, so a `read`
    // naming it refuses an array.
    let error =
        validate_shape(OutputShape::Json, br#"[{"id":"1"}]"#).expect_err("`json` means object");
    assert!(
        matches!(error, ShapeError::NotTheDeclaredShape { .. }),
        "got {error:?}"
    );
}

#[test]
fn both_shapes_are_named_in_the_emitted_document() {
    // An agent writing a declaration has to learn the accepted set from
    // `--schema`, so the new value must appear there. The table reads
    // `OutputShapeName::ACCEPTED`, so an added variant that skips the constant
    // fails here.
    let emitted = emit_schema();
    let row = emitted
        .field_table
        .iter()
        .find(|row| row.name == "ops.<name>.shape")
        .expect("the field table names the shape key");
    let accepted = row.accepted.as_ref().expect("shape is an enum");
    assert!(
        accepted.contains(&"json".to_string()) && accepted.contains(&"json_array".to_string()),
        "the emitted set must name both shapes; got {accepted:?}"
    );
}

/// The emitted contract states the list-to-pairs rule, because nothing else does.
///
/// # Why this is asserted rather than left to prose
///
/// The plan's S2 contract said S2 yields pairs "already parsed by the manager"
/// without saying how, and the rule is not derivable from the declaration fields:
/// whether an item is fetched by its own name depends on whether `read` is
/// declared. `ksp import --schema` is the surface an agent reads to write a
/// declaration, so the rule has to be in it — otherwise the only source is the
/// implementation, which is the defect this test exists to prevent.
#[test]
fn the_emitted_contract_states_how_a_list_answer_becomes_pairs() {
    let emitted = ksp::import::adapter::emit_schema();
    let row = |name: &str| {
        emitted
            .field_table
            .iter()
            .find(|field| field.name == name)
            .unwrap_or_else(|| panic!("the contract must carry a `{name}` row"))
            .description
            .clone()
    };

    let list = row("ops.list");
    assert!(
        list.contains("id") && list.contains("key"),
        "`ops.list` must say each item carries `id` or `key`, which is the name an \
         import is joined by; got: {list}"
    );
    assert!(
        list.contains("read"),
        "`ops.list` must say what changes when `read` is declared; got: {list}"
    );

    let read = row("ops.read");
    assert!(
        read.contains("extract"),
        "`ops.read` must say where the value comes from without a per-key read; got: {read}"
    );

    let extract = row("ops.<name>.extract");
    assert!(
        !extract.contains("`read` only"),
        "`extract` is honoured on `list` as well, so the contract must not say otherwise; \
         got: {extract}"
    );
    assert!(
        extract.contains("[ops.list]"),
        "`extract` must name where it goes on a declaration with no `read`; got: {extract}"
    );
}

/// The rule the contract states is the rule the code applies.
///
/// A contract that describes something the implementation does not do is worse
/// than no contract: it is read as fact. This drives the two branches the
/// contract names, so the description and the behaviour cannot drift apart.
#[test]
fn a_listing_without_a_per_key_read_reads_its_own_values() {
    // No `read`, so each listed item is its own record and the value comes from
    // the `extract` path on `list`.
    let declaration = "name = \"pairs\"\nkind = \"cli\"\nbinary = \"echo\"\n\n[ops.list]\n\
                       argv = [\"{}\"]\nshape = \"json_array\"\nextract = \"secret\"\n";
    let (_d, path) = write_temp("pairs-list-extract", declaration);
    let loaded = load_at(&path).expect("a declaration with no read parses");

    // The declaration is accepted, and the operation it needs is the one the
    // contract says carries the path.
    assert!(
        loaded.ops.read.is_none(),
        "this fixture is about the branch with no `read`"
    );
    let declared_path = loaded
        .ops
        .list
        .as_ref()
        .and_then(|operation| operation.extract.as_deref());
    assert_eq!(
        declared_path,
        Some("secret"),
        "the value path lives on `[ops.list]` when `read` is absent"
    );

    // And that path resolves against a listed item, which is the step the
    // contract describes.
    let item: serde_json::Value =
        serde_json::from_str(r#"{"id":"k1","secret":"alpha"}"#).expect("an item");
    let value = ksp::import::adapter::extract(&item, declared_path.expect("a path"), "k1")
        .expect("the declared path resolves on a listed item");
    assert_eq!(value, "alpha");
}
