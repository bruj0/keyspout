//! Regenerate the committed golden fixtures.
//!
//! Run this only when a fixture is *intentionally* changed, and review the
//! resulting diff as a change to the pinned encoding.

// A test reports a failure by panicking, and the panic message is
// what says why. The production library keeps the strict settings.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

use ksp_types::cbor::{encode, encode_array};
use ksp_types::{BoundMetadata, Level, OpaqueSecretId, PrincipalId, VaultId};

fn main() {
    let metadata = BoundMetadata {
        vault_id: VaultId::new("vault-1"),
        user_id: PrincipalId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        level: Level::User,
        secret_id: OpaqueSecretId::new("secret-1"),
        version: 1,
    };
    let aad = metadata.bound_aad().unwrap();
    std::fs::write("crates/ksp-types/tests/fixtures/bound-aad.cbor", &aad).unwrap();

    let arr = encode_array(&["first", "second", "third"]).unwrap();
    std::fs::write("crates/ksp-types/tests/fixtures/ordered-array.cbor", &arr).unwrap();

    #[derive(serde::Serialize)]
    struct Pinned {
        alpha: u32,
        beta: String,
        gamma: [u8; 3],
    }
    let s = encode(&Pinned {
        alpha: 42,
        beta: "beta".into(),
        gamma: [1, 2, 3],
    })
    .unwrap();
    std::fs::write(
        "crates/ksp-types/tests/fixtures/fixed-order-struct.cbor",
        &s,
    )
    .unwrap();

    for (name, bytes) in [
        ("bound-aad", &aad),
        ("ordered-array", &arr),
        ("fixed-order-struct", &s),
    ] {
        println!(
            "{name}: {}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
    }
}
