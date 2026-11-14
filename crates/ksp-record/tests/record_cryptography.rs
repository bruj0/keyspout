//! The acceptance tests for WP01, one per misfit.
//!
//! Each test here corresponds to a numbered acceptance criterion in the
//! work package prompt, and each names the misfit it closes.

// A test reports a failure by panicking, and the panic message is
// what says why. The production library keeps the strict settings.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_record::blob::ContentBlob;
use ksp_record::envelope::{Record, RecordEnvelope, bound_aad};
use ksp_record::kem::{self, KemError};
use ksp_record::path::RecordPath;
use ksp_record::version::{BlobStore, PublishOutcome, RecordError, StoreError, commit_version};
use ksp_types::{
    BoundMetadata, ContentKey, Level, OpaqueSecretId, PrincipalId, RecordVersion, VaultId,
};

/// The principal the fixture records belong to.
const PRINCIPAL: &str = "00000000-0000-4000-8000-000000000001";

/// A low-order X25519 point: the all-zero public key.
const LOW_ORDER_PUBLIC_KEY: [u8; 32] = [0u8; 32];

fn metadata(version: u32) -> BoundMetadata {
    BoundMetadata {
        vault_id: VaultId::new("vault-1"),
        user_id: PrincipalId::parse(PRINCIPAL).unwrap(),
        level: Level::User,
        secret_id: OpaqueSecretId::new("secret-1"),
        version,
    }
}

/// A valid X25519 key pair, derived through the provider.
fn key_pair() -> ([u8; 32], [u8; 32]) {
    let mut private = [0u8; 32];
    rand::fill(&mut private);
    let public = kem::public_key_for(&private).expect("a valid private key yields a public key");
    (private, public)
}

fn build_record(meta: &BoundMetadata) -> (Record, [u8; 32]) {
    let (private, public) = key_pair();
    let content_key = ContentKey::generate();
    let aad = bound_aad(meta).expect("the bound AAD must encode");
    let blob = ContentBlob::seal(&content_key, b"db-password", b"hunter2", &aad).expect("seal");
    let envelope = RecordEnvelope::seal(&content_key, &public, meta).expect("seal the envelope");
    (
        Record {
            metadata: meta.clone(),
            blob,
            envelope,
        },
        private,
    )
}

/// A minimal in-memory store that honours the conditional write.
#[derive(Default)]
struct MemoryStore {
    blobs: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    refuse_head: std::sync::atomic::AtomicBool,
}

impl MemoryStore {
    fn peek(&self, path: &str) -> Option<Vec<u8>> {
        self.blobs.lock().unwrap().get(path).cloned()
    }
}

impl BlobStore for MemoryStore {
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.peek(path))
    }

    fn put_if_absent(&self, path: &str, bytes: &[u8]) -> Result<bool, StoreError> {
        let mut blobs = self.blobs.lock().unwrap();
        if blobs.contains_key(path) {
            return Ok(false);
        }
        blobs.insert(path.to_string(), bytes.to_vec());
        Ok(true)
    }

    fn compare_and_set(
        &self,
        path: &str,
        expected: Option<&[u8]>,
        replacement: &[u8],
    ) -> Result<bool, StoreError> {
        if self.refuse_head.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(false);
        }
        let mut blobs = self.blobs.lock().unwrap();
        let current = blobs.get(path).map(Vec::as_slice);
        if current != expected {
            return Ok(false);
        }
        blobs.insert(path.to_string(), replacement.to_vec());
        Ok(true)
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        Ok(self
            .blobs
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
}

/// **Acceptance 1** — a low-order X25519 *recipient* key yields the typed
/// `KemInvalidPublicKey` and produces **no** envelope: encapsulate
/// direction.
#[test]
fn acceptance_1_a_low_order_recipient_key_is_rejected() {
    let error = kem::seal_to(&LOW_ORDER_PUBLIC_KEY, b"info", b"aad", b"payload")
        .expect_err("a low-order recipient key must be rejected");

    assert!(
        matches!(error, KemError::KemInvalidPublicKey),
        "the typed error is required, got {error:?}"
    );
}

/// **Acceptance 2** — a low-order *encapsulated ephemeral* key yields the
/// typed `KemInvalidPublicKey` and produces **no** plaintext: decapsulate
/// direction.
#[test]
fn acceptance_2_a_low_order_encapsulated_key_is_rejected() {
    let (private, _public) = key_pair();

    let error = kem::open_from(
        &private,
        &LOW_ORDER_PUBLIC_KEY,
        b"info",
        b"aad",
        b"ciphertext",
    )
    .expect_err("a low-order encapsulated key must be rejected");

    assert!(
        matches!(error, KemError::KemInvalidPublicKey),
        "the typed error is required, got {error:?}"
    );
}

/// **Acceptance 3** — a ciphertext relocated to another record version's
/// path fails to open, because the bound metadata is the AAD on both
/// sides.
#[test]
fn acceptance_3_a_relocated_ciphertext_fails_to_open() {
    let meta = metadata(1);
    let other_meta = metadata(2);
    let (record, private) = build_record(&meta);

    // The correct content key is recovered from the envelope first, so
    // that the blob test fails for the *AAD* reason and not because the
    // key was wrong. A wrong key would make the test pass for the wrong
    // reason.
    let content_key = record
        .envelope
        .open(&private, &meta)
        .expect("the envelope opens under its own metadata");

    // The blob opens under its own bound metadata.
    let own_aad = bound_aad(&meta).unwrap();
    assert!(
        record.blob.open(&content_key, &own_aad).is_ok(),
        "the blob must open under its own bound metadata"
    );

    // It does not open under another version's bound metadata.
    let other_aad = bound_aad(&other_meta).unwrap();
    assert!(
        record.blob.open(&content_key, &other_aad).is_err(),
        "a relocated blob must not open"
    );

    // Nor does the envelope.
    assert!(
        record.envelope.open(&private, &other_meta).is_err(),
        "a relocated envelope must not open"
    );
}

/// The record's own bound metadata *does* open it — the relocation test
/// above is only meaningful if the original still works.
#[test]
fn the_original_record_still_opens() {
    let meta = metadata(1);
    let (record, private) = build_record(&meta);

    let opened_key = record
        .envelope
        .open(&private, &meta)
        .expect("the envelope must open");
    let aad = bound_aad(&meta).unwrap();
    let (name, value) = record
        .blob
        .open(&opened_key, &aad)
        .expect("the blob must open");

    assert_eq!(name, b"db-password");
    assert_eq!(value, b"hunter2");
}

/// **Acceptance 4** — a competing writer's conflicting version is refused
/// with `PublishOutcome::Conflict`; the first writer's bytes are unchanged.
#[test]
fn acceptance_4_a_competing_writer_is_refused() {
    let store = MemoryStore::default();
    let meta = metadata(1);

    let (first, _private) = build_record(&meta);
    assert_eq!(
        commit_version(&store, &meta, &first).expect("the first commit succeeds"),
        PublishOutcome::Published
    );
    let first_bytes = store
        .peek(RecordPath::of(&meta).as_str())
        .expect("the version is stored");

    let (second, _private) = build_record(&meta);
    assert_eq!(
        commit_version(&store, &meta, &second).expect("the second commit is decided"),
        PublishOutcome::Conflict
    );

    assert_eq!(
        store
            .peek(RecordPath::of(&meta).as_str())
            .expect("the version is stored"),
        first_bytes,
        "the first writer's bytes must be unchanged"
    );
}

/// A retry after head contention must be able to publish its own stored version.
#[test]
fn a_contended_publication_can_be_retried_without_overwriting_a_competitor() {
    use std::sync::atomic::Ordering;

    let store = MemoryStore::default();
    let meta = metadata(1);
    let (record, _) = build_record(&meta);
    store.refuse_head.store(true, Ordering::SeqCst);

    assert!(matches!(
        commit_version(&store, &meta, &record),
        Err(RecordError::HeadContended)
    ));
    let original = store
        .peek(RecordPath::of(&meta).as_str())
        .expect("version was stored");
    assert!(store.peek(&ksp_record::version::head_path(&meta)).is_none());

    let (competitor, _) = build_record(&meta);
    assert_eq!(
        commit_version(&store, &meta, &competitor).expect("different bytes conflict"),
        PublishOutcome::Conflict
    );
    assert_eq!(
        store.peek(RecordPath::of(&meta).as_str()),
        Some(original.clone())
    );
    assert!(store.peek(&ksp_record::version::head_path(&meta)).is_none());

    store.refuse_head.store(false, Ordering::SeqCst);
    assert_eq!(
        commit_version(&store, &meta, &record).expect("same record can be retried"),
        PublishOutcome::Published
    );
    assert_eq!(
        store.peek(RecordPath::of(&meta).as_str()),
        Some(original.clone())
    );
    assert_eq!(
        store.peek(&ksp_record::version::head_path(&meta)),
        Some(b"1".to_vec())
    );

    assert_eq!(
        commit_version(&store, &meta, &competitor).expect("different bytes still conflict"),
        PublishOutcome::Conflict
    );
    assert_eq!(store.peek(RecordPath::of(&meta).as_str()), Some(original));
}

/// **Acceptance 5** — Shamir reconstruction succeeds for `k` of `n` and
/// fails for `k-1` of `n`, and the failure names the threshold explicitly.
#[test]
fn acceptance_5_shamir_reconstruction_respects_the_threshold() {
    use ksp_types::shamir::{SealedBundle, ShareCount, Threshold, recover, split};

    let secret = SealedBundle::new(vec![7, 11, 13, 17, 19]);
    let shares = split(&secret, Threshold(3), ShareCount(5)).expect("split");

    // k of n reconstructs.
    let recovered = recover(&shares[..3], Threshold(3)).expect("k of n reconstructs");
    assert_eq!(recovered.as_bytes(), secret.as_bytes());

    // k-1 of n fails, naming the threshold.
    let error = recover(&shares[..2], Threshold(3)).expect_err("k-1 of n must fail");
    assert!(
        error.to_string().contains('3'),
        "the failure must name the threshold, got: {error}"
    );
}

/// **Acceptance 7** — the golden fixture pins the exact CBOR bytes of the
/// bound metadata, the AAD and the record envelope structure.
///
/// The fixture comparison itself lives in `ksp-types`' fixture test. Here
/// the invariant that matters to this crate is asserted: the bound AAD
/// this crate produces is the one the shared type produces, byte for byte.
#[test]
fn acceptance_7_the_bound_aad_is_the_shared_binding() {
    let meta = metadata(1);
    assert_eq!(
        bound_aad(&meta).expect("the bound AAD must encode"),
        meta.bound_aad().expect("the shared binding must encode"),
        "the record crate and the shared type must produce identical bound bytes"
    );
}

/// **Acceptance 8** — the content key is zeroized on drop.
#[test]
fn acceptance_8_the_content_key_is_zeroized_on_drop() {
    use ksp_types::content_key::CONTENT_KEY_LEN;
    use ksp_types::{last_erasure, take_erasure};

    // The trait bounds a downstream crate depends on. A hand-written drop
    // path satisfies `ZeroizeOnDrop` but not `Zeroize`, and a `ContentKey`
    // that is not `Zeroize` cannot be held in a `Zeroizing`. Both bounds
    // are checked so the regression cannot return silently.
    fn assert_zeroize<T: zeroize::Zeroize>() {}
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize::<ContentKey>();
    assert_zeroize_on_drop::<ContentKey>();

    // The erasure must be observed on the real type. A test that only
    // checks the trait bounds cannot tell the working drop path from a
    // broken one, which is how the original defect reached review.
    let _ = take_erasure();

    let key = ContentKey::from_bytes([0x5A; CONTENT_KEY_LEN]);
    assert!(key.as_bytes().iter().all(|b| *b == 0x5A));

    drop(key);

    let erasure = last_erasure().expect("dropping a content key must erase it");
    assert_eq!(
        erasure.before, [0x5A; CONTENT_KEY_LEN],
        "the erasure must be about the bytes the key actually held"
    );
    assert_eq!(
        erasure.after, [0u8; CONTENT_KEY_LEN],
        "ContentKey must erase its own bytes before dropping"
    );
    let _ = take_erasure();
}

/// The record's metadata must match the metadata it is committed under.
#[test]
fn a_record_whose_metadata_does_not_match_is_refused() {
    let store = MemoryStore::default();
    let (record, _private) = build_record(&metadata(1));

    let outcome = commit_version(&store, &metadata(2), &record);
    assert!(matches!(outcome, Err(RecordError::MetadataMismatch)));
    assert!(store.peek(RecordPath::of(&metadata(2)).as_str()).is_none());
}

/// A record version's path is the immutable path the design specifies.
#[test]
fn the_record_path_is_the_immutable_version_path() {
    let meta = metadata(3);
    assert_eq!(
        RecordPath::of(&meta).as_str(),
        "p/vault-1/00000000-0000-4000-8000-000000000001/user/secret-1/3"
    );
    assert_eq!(RecordVersion(3).get(), 3);
}
