//! The golden fixture harness.
//!
//! A golden fixture is a committed file holding exact expected bytes. It
//! pins an encoding so that a change to it fails a test rather than
//! silently altering the meaning of a signature.
//!
//! The fixtures here pin the encodings that every later subsystem depends
//! on: the bound associated data, the canonical encoding of a fixed-order
//! struct, and the ordered array form.

// A test reports a failure by panicking, and the panic message is
// what says why. The production library keeps the strict settings.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use ksp_types::cbor::{encode, encode_array};
use ksp_types::{BoundMetadata, Level, OpaqueSecretId, PrincipalId, VaultId};

/// The directory holding the committed fixtures.
fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Read a committed fixture.
fn read_fixture(name: &str) -> Vec<u8> {
    let path = fixture_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read fixture {}: {e}", path.display()))
}

/// The bound metadata the fixtures are pinned against.
fn pinned_metadata() -> BoundMetadata {
    BoundMetadata {
        vault_id: VaultId::new("vault-1"),
        user_id: PrincipalId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        level: Level::User,
        secret_id: OpaqueSecretId::new("secret-1"),
        version: 1,
    }
}

/// A byte-level difference report, so a mismatch says *where* it differs.
fn describe_difference(expected: &[u8], actual: &[u8]) -> String {
    if expected.len() != actual.len() {
        return format!(
            "length differs: expected {} bytes, got {} bytes",
            expected.len(),
            actual.len()
        );
    }
    for (index, (e, a)) in expected.iter().zip(actual.iter()).enumerate() {
        if e != a {
            return format!(
                "byte {index} differs: expected 0x{e:02x}, got 0x{a:02x}\n  expected: {expected:02x?}\n  actual:   {actual:02x?}"
            );
        }
    }
    "the bytes are equal".to_string()
}

#[test]
fn the_bound_associated_data_matches_its_fixture() {
    // The bound AAD is the deterministic CBOR of
    // `[vault_id, user_id, level, secret_id, version]`.
    let metadata = pinned_metadata();
    let actual = metadata.bound_aad().expect("the bound AAD must encode");

    let expected = read_fixture("bound-aad.cbor");
    assert_eq!(
        actual,
        expected,
        "the bound associated data changed:\n{}",
        describe_difference(&expected, &actual)
    );
}

#[test]
fn the_bound_associated_data_decodes_back_to_its_parts() {
    let metadata = pinned_metadata();
    let actual = metadata.bound_aad().expect("the bound AAD must encode");

    // The five elements have different types — four texts and one
    // integer — so the array is decoded as a CBOR value and inspected
    // element by element.
    let value: ciborium::value::Value =
        ksp_types::cbor::decode(&actual).expect("the bound AAD must decode");
    let items = match value {
        ciborium::value::Value::Array(items) => items,
        other => panic!("the bound AAD must be an array, got {other:?}"),
    };

    assert_eq!(items.len(), 5);
    let texts: Vec<&str> = items
        .iter()
        .take(4)
        .map(|item| match item {
            ciborium::value::Value::Text(text) => text.as_str(),
            other => panic!("expected a text element, got {other:?}"),
        })
        .collect();
    assert_eq!(
        texts,
        vec![
            "vault-1",
            "00000000-0000-4000-8000-000000000001",
            "user",
            "secret-1"
        ]
    );

    assert!(
        matches!(items[4], ciborium::value::Value::Integer(_)),
        "the version must be an integer"
    );
}

#[test]
fn the_ordered_array_form_matches_its_fixture() {
    // The array form is what a load-bearing field order uses. The order is
    // part of the meaning, so it is pinned exactly.
    let actual = encode_array(&["first", "second", "third"]).expect("encode");
    let expected = read_fixture("ordered-array.cbor");
    assert_eq!(
        actual,
        expected,
        "the ordered array form changed:\n{}",
        describe_difference(&expected, &actual)
    );
}

#[test]
fn the_fixed_order_struct_matches_its_fixture() {
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Pinned {
        alpha: u32,
        beta: String,
        gamma: [u8; 3],
    }

    let value = Pinned {
        alpha: 42,
        beta: "beta".into(),
        gamma: [1, 2, 3],
    };
    let actual = encode(&value).expect("encode");
    let expected = read_fixture("fixed-order-struct.cbor");
    assert_eq!(
        actual,
        expected,
        "the fixed-order struct encoding changed:\n{}",
        describe_difference(&expected, &actual)
    );
}

#[test]
fn a_changed_field_changes_the_encoding() {
    // A golden fixture is only useful if it actually detects a change.
    #[derive(serde::Serialize)]
    struct Pinned {
        alpha: u32,
        beta: String,
        gamma: [u8; 3],
    }

    let base = encode(&Pinned {
        alpha: 42,
        beta: "beta".into(),
        gamma: [1, 2, 3],
    })
    .unwrap();

    let changed = encode(&Pinned {
        alpha: 43,
        beta: "beta".into(),
        gamma: [1, 2, 3],
    })
    .unwrap();

    assert_ne!(base, changed, "a changed field must change the encoding");
}
