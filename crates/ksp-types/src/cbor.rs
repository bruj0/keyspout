//! The canonical encoding.
//!
//! Every structure that is signed, or that is ever hashed, is encoded through
//! this module. Two independent code paths must produce identical bytes, or a
//! signature made on one path will not verify on the other.
//!
//! # Why this is not "canonical CBOR"
//!
//! `ciborium` 0.2.2 encodes integers in the smallest lossless width and
//! represents maps as an order-preserving `Vec<(Value, Value)>`. It does
//! **not** implement RFC 8949 §4.2.1 canonical CBOR. A map therefore has no
//! guaranteed byte representation across encoders.
//!
//! The hazard is removed structurally rather than by trusting the encoder:
//!
//! - Every signed structure is a **fixed-order Rust `struct`** or an
//!   explicit CBOR **array**. Maps are forbidden for signed structures.
//! - The array form is used where the field order is itself load-bearing,
//!   such as the proof-of-possession preimage
//!   `[jti, record_version, record_path, argv_hash, window_ts]`.
//!
//! The struct form serializes to a CBOR map, but with a *fixed* key order
//! determined by the `struct`'s declaration order rather than by the
//! encoder's runtime choices, so the bytes are stable for a given struct
//! definition.

use std::io::Cursor;

pub use ciborium::value::Value as RawValue;
use ciborium::value::Value;
use serde::Serialize;
use serde::de::DeserializeOwned;

#[cfg(test)]
use serde::Deserialize;

/// The error produced when a canonical encoding or decoding fails.
#[derive(Debug, thiserror::Error)]
pub enum CborError {
    /// The value could not be encoded.
    #[error("encoding failed: {0}")]
    Encode(String),
    /// The bytes could not be decoded.
    #[error("decoding failed: {0}")]
    Decode(String),
}

/// Encode a value to its canonical byte representation.
///
/// The value must be a fixed-order struct or an array. A `HashMap` or a
/// `BTreeMap` serializes to a map whose key order is the map's own, which
/// is stable for a `BTreeMap` but is not the RFC 8949 canonical form — so
/// signed structures must not use one.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| CborError::Encode(e.to_string()))?;
    Ok(out)
}

/// Decode bytes produced by [`encode`] back into a value.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CborError> {
    ciborium::from_reader(Cursor::new(bytes)).map_err(|e| CborError::Decode(e.to_string()))
}

/// Encode an explicit ordered array of values.
///
/// This is the form used where the *order* of the elements is part of the
/// meaning, such as the proof-of-possession preimage. The values are
/// encoded individually and assembled into a CBOR array, so the order is
/// exactly the order given.
pub fn encode_array<T: Serialize>(values: &[T]) -> Result<Vec<u8>, CborError> {
    let items: Vec<Value> = values
        .iter()
        .map(|v| Value::serialized(v).map_err(|e| CborError::Encode(e.to_string())))
        .collect::<Result<_, _>>()?;

    let mut out = Vec::new();
    ciborium::into_writer(&Value::Array(items), &mut out)
        .map_err(|e| CborError::Encode(e.to_string()))?;
    Ok(out)
}

/// Decode bytes into a raw CBOR value, without a target type.
///
/// The one legitimate use is a reader that must show a record it cannot type:
/// `ksp audit` prints a kind this build does not know with the fields it carries
/// rather than dropping it (FR-040). No signed structure is ever decoded this way, and
/// nothing re-encodes the result — canonical bytes come from [`encode`] over a declared
/// type, never from a value that was read loose.
pub fn decode_value(bytes: &[u8]) -> Result<Value, CborError> {
    decode(bytes)
}

/// Decode a CBOR array into a vector of values.
pub fn decode_array<T: DeserializeOwned>(bytes: &[u8]) -> Result<Vec<T>, CborError> {
    let value: Value = decode(bytes)?;
    match value {
        Value::Array(items) => items
            .into_iter()
            .map(|item| {
                item.deserialized::<T>()
                    .map_err(|e| CborError::Decode(e.to_string()))
            })
            .collect(),
        _ => Err(CborError::Decode("expected a CBOR array".to_string())),
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is
    // what says why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Fixed {
        first: u32,
        second: String,
        third: [u8; 4],
    }

    #[test]
    fn a_value_read_loose_keeps_the_fields_a_typed_reader_would_reject() {
        #[derive(Serialize)]
        struct Unknown {
            future_field: &'static str,
            count: u32,
        }
        let bytes = encode(&Unknown {
            future_field: "kept",
            count: 7,
        })
        .unwrap();
        let value = decode_value(&bytes).unwrap();
        let RawValue::Map(entries) = value else {
            panic!("a struct encodes to a map");
        };
        assert_eq!(entries.len(), 2);
        assert!(
            decode::<Fixed>(&bytes).is_err(),
            "the typed reader refuses a shape it does not declare, which is why the view needs this"
        );
    }

    #[test]
    fn encoding_is_stable_across_calls() {
        let value = Fixed {
            first: 1,
            second: "a".into(),
            third: [1, 2, 3, 4],
        };
        assert_eq!(encode(&value).unwrap(), encode(&value).unwrap());
    }

    #[test]
    fn round_trips_a_fixed_order_struct() {
        let value = Fixed {
            first: 7,
            second: "hello".into(),
            third: [9, 8, 7, 6],
        };
        let bytes = encode(&value).unwrap();
        let back: Fixed = decode(&bytes).unwrap();
        assert_eq!(value, back);
    }

    #[test]
    fn array_order_is_preserved_and_significant() {
        let a = encode_array(&[1u32, 2, 3]).unwrap();
        let b = encode_array(&[3u32, 2, 1]).unwrap();
        assert_ne!(a, b, "array order must change the encoding");

        let decoded: Vec<u32> = decode_array(&a).unwrap();
        assert_eq!(decoded, vec![1, 2, 3]);
    }

    #[test]
    fn integers_use_the_smallest_lossless_width() {
        // ciborium encodes small integers in one byte. This pins the
        // behaviour the golden fixtures depend on: a change in the encoder
        // that widened integers would silently change every signature.
        let bytes = encode_array(&[1u32]).unwrap();
        assert_eq!(&bytes[..1], &[0x81], "array header");
        assert_eq!(&bytes[1..2], &[0x01], "smallest-width integer");
    }

    #[test]
    fn decoding_rejects_a_non_array() {
        let bytes = encode(&Fixed {
            first: 1,
            second: "a".into(),
            third: [0; 4],
        })
        .unwrap();
        let result: Result<Vec<u32>, _> = decode_array(&bytes);
        assert!(result.is_err(), "a map must not decode as an array");
    }
}
