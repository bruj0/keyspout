//! The output shape check, and the argv the child actually receives.
//!
//! # Why the shape is checked before the parser
//!
//! Misfit H's second half: an adapter whose vendor changed the output shape should
//! refuse as **a shape mismatch**, not reach the value parser and produce a wrong
//! value from something it never understood. Checking first also gives the
//! operator a sentence naming what was expected, which a parse error deep inside a
//! JSON walker does not.
//!
//! # Why there is no shell
//!
//! Misfit E's quieter form: a declaration that shells out turns a selector
//! containing `;` or `$()` into a command. [`super::declaration::AdapterDeclaration::exec`]
//! builds a [`std::process::Command`] with `.args([...])`, so the operating system
//! receives an argv vector and there is nothing to interpolate into. A test passes
//! `;` and `$()` through and compares the bytes `/bin/echo` prints.

use serde_json::Value;

/// The shape a declaration names, as the checker uses it.
///
/// Two values, and they are deliberately separate rather than one permissive
/// `json`. Measured against the real `bw 2026.10.0`: `bw list items --raw`
/// returns a JSON **array**, and `bw get item <id>` returns an **object**. A
/// single shape that accepted both would stop a `read` from refusing an array,
/// which is the changed-output check misfit H needs — a vendor that started
/// wrapping its object in a list would pass through unnoticed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputShape {
    /// A JSON object. What a single-record read returns.
    Json,
    /// A JSON array. What a list operation returns.
    JsonArray,
}

impl OutputShape {
    /// The name this shape is printed under, matching the declaration's spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            OutputShape::Json => "json",
            OutputShape::JsonArray => "json_array",
        }
    }
}

/// Why an output did not have the declared shape.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShapeError {
    /// The output was empty.
    ///
    /// A different fact from "the manager has no items". Reading an empty body as
    /// an empty result would report every key as absent, which sends the operator
    /// to edit a file that is already correct.
    #[error(
        "the adapter produced no output, so its shape cannot be confirmed. An empty response \
         is a broken invocation rather than an empty answer, and reading it as one would report \
         every key as absent"
    )]
    Empty,

    /// The output was not the declared shape.
    #[error(
        "the adapter output is not the `{expected}` shape it declares: {cause}. A manager that \
         changed its output shape is refused here, before the value parser reads bytes it did \
         not expect"
    )]
    NotTheDeclaredShape {
        /// The shape the declaration names.
        expected: &'static str,
        /// What arrived, in one clause.
        cause: String,
    },
}

/// Check an output against the shape the declaration names.
pub fn validate_shape(shape: OutputShape, bytes: &[u8]) -> Result<Value, ShapeError> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(ShapeError::Empty);
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|error| ShapeError::NotTheDeclaredShape {
            expected: shape.as_str(),
            cause: error.to_string(),
        })?;

    // Each shape accepts exactly one JSON kind. Accepting either here would make
    // the declaration's `shape` a hint rather than a check.
    let matches = match shape {
        OutputShape::Json => value.is_object(),
        OutputShape::JsonArray => value.is_array(),
    };
    if !matches {
        return Err(ShapeError::NotTheDeclaredShape {
            expected: shape.as_str(),
            cause: format!(
                "it parsed, but a {} is not what `{}` names",
                json_type_name(&value),
                shape.as_str()
            ),
        });
    }
    Ok(value)
}

/// The JSON type name, for a sentence rather than a `Debug` rendering.
fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
