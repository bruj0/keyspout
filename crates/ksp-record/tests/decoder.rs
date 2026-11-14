//! The acceptance tests for WP13: a stored record can be read back, and only in
//! the exact form this crate wrote.
//!
//! A test reports a failure by panicking, and the panic message is what says why.
//! The production code keeps the strict lints.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_record::blob::ContentBlob;
use ksp_record::envelope::{Record, RecordEnvelope, bound_aad};
use ksp_record::kem;
use ksp_record::version::{StoreError, decode_record, encode_record};
use ksp_types::{BoundMetadata, ContentKey, Level, OpaqueSecretId, PrincipalId, VaultId};

fn metadata() -> BoundMetadata {
    BoundMetadata {
        vault_id: VaultId::new("vault-1"),
        user_id: PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        level: Level::User,
        secret_id: OpaqueSecretId::new("secret-1"),
        version: 1,
    }
}

fn record() -> Record {
    let meta = metadata();
    let mut private = [0u8; 32];
    rand::fill(&mut private);
    let public = kem::public_key_for(&private).unwrap();
    let content_key = ContentKey::generate();
    let aad = bound_aad(&meta).unwrap();
    Record {
        blob: ContentBlob::seal(&content_key, b"db-password", b"hunter2", &aad).unwrap(),
        envelope: RecordEnvelope::seal(&content_key, &public, &meta).unwrap(),
        metadata: meta,
    }
}

#[test]
fn a_genuine_record_survives_a_round_trip() {
    let original = record();
    let bytes = encode_record(&original).unwrap();
    let read_back = decode_record(&bytes).unwrap();
    assert_eq!(read_back, original);
}

#[test]
fn a_truncated_buffer_is_refused() {
    let bytes = encode_record(&record()).unwrap();
    let shorter = &bytes[..bytes.len() - 1];
    assert!(matches!(decode_record(shorter), Err(StoreError::Decoding)));
}

#[test]
fn a_buffer_with_trailing_bytes_is_refused() {
    // Trailing bytes would let a store hold two different buffers for one
    // version; the canonical round-trip check catches it.
    let mut longer = encode_record(&record()).unwrap();
    longer.push(0x00);
    assert!(matches!(decode_record(&longer), Err(StoreError::Decoding)));
}

#[test]
fn a_buffer_whose_structure_does_not_re_encode_to_itself_is_refused() {
    // The metadata is decoded and re-encoded, so a canonical-round-trip check
    // catches a structure that is not the one this crate writes.
    //
    // The check deliberately does *not* cover the blob and envelope: those are
    // opaque bytes that survive any substitution, and a flipped byte in them is
    // caught by AEAD on open, not by decoding. Asserting otherwise here would
    // have been a test of my assumption rather than of the decoder.
    let bytes = encode_record(&record()).unwrap();

    // The metadata occupies the head of the document; a substitution there
    // changes a field name or value and cannot decode to the same structure.
    let mut tampered = bytes.clone();
    tampered[3] ^= 0x01;
    assert!(
        matches!(decode_record(&tampered), Err(StoreError::Decoding)),
        "a structural substitution must not decode"
    );
}

#[test]
fn the_decoder_and_encoder_share_one_wire_form() {
    // Encode → decode → encode is the identity. If a second wire form existed
    // anywhere, this would not hold.
    let original = record();
    let once = encode_record(&original).unwrap();
    let twice = encode_record(&decode_record(&once).unwrap()).unwrap();
    assert_eq!(once, twice);
}
