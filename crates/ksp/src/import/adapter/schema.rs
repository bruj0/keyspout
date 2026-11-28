//! The declaration contract, emitted from the type so it cannot drift.
//!
//! # Why the schema is derived and the example is a constant
//!
//! An agent writing a declaration has no repository to read. It needs three
//! things: the JSON Schema (`#[derive(JsonSchema)]`, so it is the parser's own
//! type), a **concrete** TOML example it can copy, and a field table naming each
//! enum's accepted values and the refused keys with reasons.
//!
//! The schema cannot drift, because it is generated from the type the parser
//! deserialises. The **example can**, because a constant is prose: adding a field
//! to the type leaves the example compiling and out of date. So the example is
//! proven by a round-trip test — parse it with the production parser, serialise it
//! back, compare bytes — and that test is the control. Without it the example is a
//! claim nobody checks.
//!
//! # It is a read with no inputs
//!
//! No `Layout`, no deployment, no `integrations/`. An agent may ask the shape
//! **before** a deployment exists, which is exactly when it is writing its first
//! adapter file.

use serde::Serialize;

use super::declaration::{AdapterDeclaration, Kind, OutputShapeName};
use super::validate::RefusedKey;

/// The canonical example, as a constant beside the type.
///
/// Bitwarden, because it is the manager this feature ships a declaration for and
/// the one WP06 exercises with the real `bw`. Every field the type accepts is
/// populated: a field this example omits is a field no round-trip test protects.
///
/// The round-trip test is what keeps it honest. Adding a field to
/// `AdapterDeclaration` without adding it here changes the re-serialisation and
/// fails that test.
pub const CANONICAL_EXAMPLE: &str = r#"name = "bitwarden"
kind = "cli"
binary = "bw"
credential_env = "BW_SESSION"

[ops.list]
argv = ["list", "items", "--search", "{selector}"]

[ops.read]
argv = ["get", "item", "{key}"]
extract = "login.password"
"#;

/// The canonical example.
pub fn canonical_example() -> &'static str {
    CANONICAL_EXAMPLE
}

/// One row of the emitted field table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldRow {
    /// The key, as it appears in the file.
    pub name: String,
    /// What it means, and what leaving it out does.
    pub description: String,
    /// The accepted values, when it is an enum.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<Vec<String>>,
}

/// One refused key, carried into the emitted document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefusedRow {
    /// The key that is refused.
    pub name: String,
    /// Why, so a prohibition is one an agent can comply with rather than guess at.
    pub reason: String,
}

/// What `ksp import --schema` prints.
#[derive(Debug, Clone, Serialize)]
pub struct EmittedSchema {
    /// The JSON Schema, derived from the type the parser deserialises.
    pub json_schema: schemars::Schema,
    /// A concrete declaration an agent can copy.
    pub example: String,
    /// Every key, with the accepted values for each enum.
    pub field_table: Vec<FieldRow>,
    /// The keys that are refused, with reasons.
    pub refused_keys: Vec<RefusedRow>,
}

/// Build the emitted document.
///
/// Takes no argument on purpose: see the module docs. A parameter here would be a
/// deployment the reader must have before it can ask what a file looks like.
pub fn emit_schema() -> EmittedSchema {
    let json_schema = schemars::schema_for!(AdapterDeclaration);
    EmittedSchema {
        json_schema,
        example: CANONICAL_EXAMPLE.to_string(),
        field_table: field_table(),
        refused_keys: refused_rows(super::validate::refused_destination_keys()),
    }
}

/// The refused keys, as the emitted document carries them.
///
/// Takes the list rather than calling [`refused_destination_keys`] itself, so the
/// two lists cannot diverge: a caller that swapped one would fail to compile.
fn refused_rows(keys: &'static [RefusedKey]) -> Vec<RefusedRow> {
    keys.iter()
        .map(|key| RefusedRow {
            name: key.name.to_string(),
            reason: key.reason.to_string(),
        })
        .collect()
}

/// The field table, built from the types rather than from prose.
///
/// Every enum's accepted set comes from a constant beside its type
/// ([`Kind::ACCEPTED`], [`OutputShapeName::ACCEPTED`]), so a new variant added
/// without updating the constant is a compile error in the schema test rather than
/// a document that omits a value the parser accepts.
fn field_table() -> Vec<FieldRow> {
    let strings =
        |values: &'static [&'static str]| Some(values.iter().map(|v| v.to_string()).collect());

    vec![
        FieldRow {
            name: "name".into(),
            description: "The name `--from` selects. Must be unique in `integrations/`.".into(),
            accepted: None,
        },
        FieldRow {
            name: "kind".into(),
            description: "How the adapter acquires bytes. `cli` runs a binary; `http` calls an \
                          endpoint. The set is closed: a manager whose authentication is \
                          challenge-response or OAuth needs a new Rust arm, not a new file."
                .into(),
            accepted: strings(Kind::ACCEPTED),
        },
        FieldRow {
            name: "binary".into(),
            description: "For `kind = \"cli\"`: the executable on PATH. Mutually exclusive with \
                          `base_url`."
                .into(),
            accepted: None,
        },
        FieldRow {
            name: "base_url".into(),
            description: "For `kind = \"http\"`: the endpoint. Mutually exclusive with `binary`."
                .into(),
            accepted: None,
        },
        FieldRow {
            name: "credential_env".into(),
            description: "The **name** of the environment variable holding the credential, never \
                          its value. Import reads it from your environment and never prompts."
                .into(),
            accepted: None,
        },
        FieldRow {
            name: "ops.list".into(),
            description: "Enumerate what the selector matches. Required: an adapter with no \
                          `list` cannot supply keys. Each listed item must carry an `id` or a \
                          `key`, because that is the name an import is joined to the store by \
                          and a list position is not stable. When `read` is also declared, the \
                          listing need only carry that name: each item is then fetched by it."
                .into(),
            accepted: None,
        },
        FieldRow {
            name: "ops.read".into(),
            description: "Read one value by key. Omit it and `--list-adapters` reports that the \
                          adapter cannot supply a per-key read, and an import reads each value \
                          out of the listing instead — so a declaration without `read` must \
                          name where the value sits with `ops.list.extract`, or the listing must \
                          carry it in a `value` member."
                .into(),
            accepted: None,
        },
        FieldRow {
            name: "ops.write".into(),
            description: "Declared so a future write path has somewhere to live. Import never \
                          uses it, and omitting it is the normal case."
                .into(),
            accepted: None,
        },
        FieldRow {
            name: "ops.<name>.argv".into(),
            description: "For `kind = \"cli\"`: the command. `{selector}` and `{key}` are \
                          substituted into exactly one argument each, with no shell."
                .into(),
            accepted: None,
        },
        FieldRow {
            name: "ops.<name>.path".into(),
            description: "For `kind = \"http\"`: the path the request is sent to.".into(),
            accepted: None,
        },
        FieldRow {
            name: "ops.<name>.shape".into(),
            description: "The output shape, checked before the value parser reads anything. A \
                          manager that changed its output is refused here."
                .into(),
            accepted: strings(OutputShapeName::ACCEPTED),
        },
        FieldRow {
            name: "ops.<name>.extract".into(),
            description: "Where the value sits inside the parsed output, as a dotted path such \
                          as `login.password`. On a declaration that declares `read`, put it on \
                          `[ops.read]`, where it names the path inside the fetched item. On one \
                          that does not, put it on `[ops.list]`, where it names the path inside \
                          each listed item; with neither, a value is read from a `value` member \
                          and the refusal names that fix."
                .into(),
            accepted: None,
        },
    ]
}
