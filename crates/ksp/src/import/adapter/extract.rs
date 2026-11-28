//! Turning a parsed item into the value a declaration names.
//!
//! # Why this is a component and not four lines in a test
//!
//! A `read` operation returns a whole item: `bw get item <id>` is an object with a
//! `login`, an `sshKey`, `fields` and a dozen other keys. The declaration says where
//! the value sits (`extract = "login.password"`), and something has to walk that
//! path. The plan assigns it to S2, which "yields `Pairs` … already parsed by the
//! manager".
//!
//! It shipped as a declared field with no consumer: the field parsed, the schema
//! emitted it, and nothing applied it. Found by review (CF-148), and the shape of
//! the defect is that a **test** reached the value by walking the JSON itself — so
//! the suite was green while the declaration's own path was never honoured.
//!
//! # A miss is a refusal, never an empty value
//!
//! This is the whole reason the module is not a `?` chain. A vault holds items that
//! have no `login` at all — an SSH key, a note, a card — so `login.password` misses
//! on real data rather than only on a typo. Returning `""` for a miss would seal an
//! empty secret, and nothing downstream could tell it from a value the operator
//! meant to store.
//!
//! The refusal names the item and the path, because those are the two things the
//! operator needs: which record, and which line of the declaration to correct.

use serde_json::Value;

/// Why a declared `extract` path produced no value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtractError {
    /// The path does not resolve on this item.
    ///
    /// The common case, and not a defect in the declaration: a vault holds items of
    /// several types, and an SSH key has no `login`. The sentence names the item and
    /// the path so an operator can tell "this record has no password" from "the
    /// declaration names the wrong field".
    #[error(
        "item {item} has no value at `{path}`, so the declaration's `extract` misses on this \
         record. An item of another type has no `login`, which is a fact about the record rather \
         than about the declaration: skip this key in the selector, or point `extract` at a path \
         the item has"
    )]
    PathMissing {
        /// The item the read returned.
        item: String,
        /// The path the declaration named.
        path: String,
    },

    /// The path resolves to something that is not a string.
    #[error(
        "item {item} has `{path}` but it is a {found}, not a string, so it cannot be imported as \
         a value. A declaration whose `extract` reaches an object or a number names the wrong \
         path"
    )]
    NotAString {
        /// The item the read returned.
        item: String,
        /// The path the declaration named.
        path: String,
        /// The JSON type it found instead.
        found: &'static str,
    },
}

/// Walk a dotted path and return the string it reaches.
///
/// `item_id` is carried only for the refusal: a report that named the path without
/// the item would leave an operator scanning a vault of 1307 records for it.
pub fn extract(item: &Value, path: &str, item_id: &str) -> Result<String, ExtractError> {
    let mut cursor = item;
    for segment in path.split('.') {
        cursor = cursor
            .get(segment)
            .ok_or_else(|| ExtractError::PathMissing {
                item: item_id.to_string(),
                path: path.to_string(),
            })?;
    }

    match cursor {
        Value::String(value) => Ok(value.clone()),
        // A null is present and empty, and `""` is a value an import would seal.
        Value::Null => Err(ExtractError::PathMissing {
            item: item_id.to_string(),
            path: path.to_string(),
        }),
        other => Err(ExtractError::NotAString {
            item: item_id.to_string(),
            path: path.to_string(),
            found: json_type_name(other),
        }),
    }
}

/// What a read yields: the extracted value, or the whole item when no path is named.
///
/// A `list` operation declares no `extract`, because it yields many items and the
/// value per key is chosen later. A `read` declares one. Both are this function's
/// input, so a caller has one thing to call rather than a branch per operation.
pub fn extract_or_item(
    item: &Value,
    extract_path: Option<&str>,
    item_id: &str,
) -> Result<String, ExtractError> {
    match extract_path {
        Some(path) => extract(item, path, item_id),
        // Rendered rather than returned as a `Value` so the signature is one type:
        // a caller that had to handle both shapes would branch at every use.
        None => Ok(item.to_string()),
    }
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
