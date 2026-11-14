//! The immutable version commit and the conditional publication of it.
//!
//! # The misfit this resolves
//!
//! Two writers target the same version or the same head; one overwrites
//! the other, or a reader observes a torn record (misfit J, FR-012).
//!
//! # The rule
//!
//! A version is **immutable**. Once a version is committed, its bytes never
//! change. Publication of a version and of the head is **conditional**: it
//! happens only if no competing writer already holds that version or that
//! head. A conflict is *refused*, never overwritten.
//!
//! The backend sees opaque blobs and exposes no decrypt method (FR-010), so the
//! conditional publication uses the store's own conditional write primitives.

use ksp_types::BoundMetadata;

use crate::blob::ContentBlob;
use crate::envelope::{Record, RecordEnvelope};
use crate::path::RecordPath;

/// The store contract the record subsystem writes through.
///
/// The backend receives opaque blobs and has no decrypt method. The
/// conditional publication uses [`BlobStore::put_if_absent`] for immutable
/// versions and [`BlobStore::compare_and_set`] for head advancement.
pub trait BlobStore {
    /// Read the bytes stored at a path, if any.
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, StoreError>;

    /// Write bytes at a path **only if nothing is stored there**.
    ///
    /// Returns `true` when the bytes were written, `false` when something
    /// was already present. This is the conditional publication primitive.
    fn put_if_absent(&self, path: &str, bytes: &[u8]) -> Result<bool, StoreError>;

    /// Replace bytes only when the current value matches `expected`.
    /// `None` means the path must not exist.
    ///
    /// Returns `true` when the bytes were replaced and `false` when the
    /// current value did not match. A backend that cannot construct a
    /// genuine conditional replace reports
    /// [`StoreError::ConditionalReplaceUnsupported`] rather than
    /// returning `false`: a refusal and a lost race are different
    /// situations, and only one of them is worth retrying.
    fn compare_and_set(
        &self,
        path: &str,
        expected: Option<&[u8]>,
        replacement: &[u8],
    ) -> Result<bool, StoreError>;

    /// List the paths under a prefix.
    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError>;
}

/// The error produced by a store operation.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The store refused or failed the operation.
    #[error("the store failed: {0}")]
    Backend(String),
    /// The bytes could not be encoded.
    #[error("the record could not be encoded: {0}")]
    Encoding(String),
    /// The bytes could not be decoded as a record.
    ///
    /// Deliberately one variant for every decode failure: a caller that could
    /// tell "truncated" from "non-canonical" could probe the store's contents,
    /// and the distinction is of no use to a legitimate reader.
    #[error("the stored bytes are not a readable record")]
    Decoding,
    /// The backend cannot construct a genuine conditional replace.
    ///
    /// A backend that reports this is not admitted for a record it must
    /// publish under the conditional-publication contract. Reporting it
    /// keeps the refusal distinct from a lost race.
    #[error("the backend does not support a conditional replace")]
    ConditionalReplaceUnsupported,
}

/// The error produced by a version commit.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The record did not match the metadata it was committed under.
    #[error("the record's bound metadata does not match the metadata it was committed under")]
    MetadataMismatch,
    /// The head could not be advanced within the attempt budget.
    ///
    /// The version bytes are stored and the head was not published by this
    /// attempt. The caller may retry the same record: matching stored bytes
    /// allow the retry to reach the head without changing the immutable version.
    #[error("the head was contended: it could not be advanced within the attempt budget")]
    HeadContended,
}

/// The outcome of a conditional publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// The version and the head were published.
    Published,
    /// A competing writer already holds this version or head.
    ///
    /// The competing writer's bytes are unchanged. The immutable version may
    /// already have been written, but this version did not become the head.
    Conflict,
}

/// The path of the head pointer for a record.
///
/// Derived from the record path's own prefix, so there is one place that knows
/// the shape of a record location.
pub fn head_path(metadata: &BoundMetadata) -> String {
    RecordPath::of(metadata).head()
}

/// The serialized form of a record.
///
/// The record is stored as a canonical CBOR document: the bound metadata,
/// the content blob and the record envelope. The blob and the envelope are
/// opaque to the store.
pub fn encode_record(record: &Record) -> Result<Vec<u8>, StoreError> {
    use ksp_types::cbor::CborError;

    #[derive(serde::Serialize)]
    struct Serialized<'a> {
        metadata: &'a BoundMetadata,
        blob: &'a [u8],
        envelope: &'a [u8],
    }

    let blob = record.blob.to_bytes();
    let envelope = record.envelope.to_bytes();

    let serialized = Serialized {
        metadata: &record.metadata,
        blob: &blob,
        envelope: &envelope,
    };

    ksp_types::cbor::encode(&serialized).map_err(|e: CborError| StoreError::Encoding(e.to_string()))
}

/// Read back a record this crate wrote.
///
/// The decoder lives beside [`encode_record`] and shares one structure
/// definition, so the wire form has a single definition. A second decoder
/// elsewhere would be two definitions of the same format, which is how a record
/// gets read as something it is not.
///
/// The bytes must be **canonical**: decoding re-encodes and compares. Without
/// that check a store could hold a non-canonical encoding of a version and
/// republish it later in canonical form under the same version number, which is
/// a different byte sequence for one immutable version.
pub fn decode_record(bytes: &[u8]) -> Result<Record, StoreError> {
    #[derive(serde::Deserialize)]
    struct Serialized {
        metadata: BoundMetadata,
        blob: Vec<u8>,
        envelope: Vec<u8>,
    }

    let serialized: Serialized =
        ksp_types::cbor::decode(bytes).map_err(|_| StoreError::Decoding)?;

    let record = Record {
        metadata: serialized.metadata,
        blob: ContentBlob::from_bytes(&serialized.blob).map_err(|_| StoreError::Decoding)?,
        envelope: RecordEnvelope::from_bytes(&serialized.envelope)
            .map_err(|_| StoreError::Decoding)?,
    };

    // Canonical round trip. A buffer that decodes but does not re-encode to
    // itself is not the encoding this crate produces.
    if encode_record(&record)?.as_slice() != bytes {
        return Err(StoreError::Decoding);
    }

    Ok(record)
}

/// Commit one complete immutable record version and conditionally publish
/// it as the head.
///
/// The rules, in order:
///
/// 1. The record's bound metadata must be the metadata it is committed
///    under. A mismatch is an error, not a silent rebind.
/// 2. The version bytes are written with a conditional write. If a
///    competing writer's different bytes already exist, they remain unchanged
///    and the outcome is [`PublishOutcome::Conflict`]. Identical stored bytes
///    allow a retry to finish publication without proving writer identity.
/// 3. The head advances using the store's conditional replace operation.
///    A higher current version is never overwritten; a lower version may
///    be advanced. An unreadable head fails closed as a Version Conflict.
///
/// A Version Conflict may occur after the immutable version bytes were
/// written; it means this version did not become the head, not that the
/// operation left the store untouched.
///
/// A reader never observes a partial version: the version bytes are
/// written in full before the head is published, and the head is the only
/// thing a reader follows.
pub fn commit_version(
    backend: &dyn BlobStore,
    meta: &BoundMetadata,
    record: &Record,
) -> Result<PublishOutcome, RecordError> {
    if record.metadata != *meta {
        return Err(RecordError::MetadataMismatch);
    }

    let bytes = encode_record(record)?;
    let version_path = RecordPath::of(meta).as_str().to_string();

    // Step 1: the version is immutable. A failed conditional write may be
    // an earlier attempt whose head publication did not finish. Only
    // identical stored bytes may continue; never replace a competing version.
    if !backend.put_if_absent(&version_path, &bytes)?
        && backend.get(&version_path)?.as_deref() != Some(bytes.as_slice())
    {
        return Ok(PublishOutcome::Conflict);
    }

    // Step 2: publish or advance the head using a conditional replace. A
    // retry absorbs a concurrent head update without overwriting it
    // blindly. The retry budget is fixed: a backend whose conditional
    // replace can never succeed must fail the publication, not wedge the
    // writer.
    let head = head_path(meta);
    let replacement = meta.version.to_string();
    for _ in 0..MAX_HEAD_ATTEMPTS {
        let existing = backend.get(&head)?;
        if let Some(current) = existing.as_deref().and_then(head_version) {
            if current == meta.version {
                return Ok(PublishOutcome::Published);
            }
            if current > meta.version {
                return Ok(PublishOutcome::Conflict);
            }
        } else if existing.is_some() {
            return Ok(PublishOutcome::Conflict);
        }

        if backend.compare_and_set(&head, existing.as_deref(), replacement.as_bytes())? {
            return Ok(PublishOutcome::Published);
        }
    }

    // The budget is spent. The version bytes are stored, the head is
    // unchanged, and the caller is told the head was contended.
    Err(RecordError::HeadContended)
}

/// How many times the head's conditional replace is attempted before the
/// publication is reported as contended.
///
/// The retry exists to absorb a lost race, and a lost race resolves within
/// a couple of attempts. A backend that cannot perform a genuine
/// conditional replace reports refusal forever, so the budget converts that
/// refusal into an error instead of an unbounded wait.
const MAX_HEAD_ATTEMPTS: u32 = 8;

/// The version a stored head names, if its decimal representation is valid.
fn head_version(stored: &[u8]) -> Option<u32> {
    std::str::from_utf8(stored).ok()?.trim().parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is
    // what says why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::blob::ContentBlob;
    use crate::envelope::RecordEnvelope;
    use ksp_types::{ContentKey, Level, OpaqueSecretId, PrincipalId, VaultId};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A minimal in-memory store that honours the conditional write.
    #[derive(Default)]
    struct MemoryStore {
        blobs: Mutex<HashMap<String, Vec<u8>>>,
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

    fn metadata(version: u32) -> BoundMetadata {
        BoundMetadata {
            vault_id: VaultId::new("v-1"),
            user_id: PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
            level: Level::User,
            secret_id: OpaqueSecretId::new("s-1"),
            version,
        }
    }

    fn build_record(meta: &BoundMetadata) -> Record {
        let content_key = ContentKey::generate();
        let blob = ContentBlob::seal(&content_key, b"name", b"value", b"aad").unwrap();
        let mut sk = [0u8; 32];
        rand::fill(&mut sk);
        let pk = crate::kem::public_key_for(&sk).unwrap();
        let envelope = RecordEnvelope::seal(&content_key, &pk, meta).unwrap();
        Record {
            metadata: meta.clone(),
            blob,
            envelope,
        }
    }

    #[test]
    fn commits_a_version_and_publishes_the_head() {
        let store = MemoryStore::default();
        let meta = metadata(1);
        let record = build_record(&meta);

        let outcome = commit_version(&store, &meta, &record).unwrap();
        assert_eq!(outcome, PublishOutcome::Published);
        assert!(store.peek(RecordPath::of(&meta).as_str()).is_some());
        assert_eq!(store.peek(&head_path(&meta)).unwrap(), b"1");
    }

    #[test]
    fn a_competing_writer_conflicting_version_is_refused() {
        let store = MemoryStore::default();
        let meta = metadata(1);
        let first = build_record(&meta);

        assert_eq!(
            commit_version(&store, &meta, &first).unwrap(),
            PublishOutcome::Published
        );
        let first_bytes = store.peek(RecordPath::of(&meta).as_str()).unwrap();

        // A second writer targets the same version with different bytes.
        let second = build_record(&meta);
        let outcome = commit_version(&store, &meta, &second).unwrap();

        assert_eq!(outcome, PublishOutcome::Conflict);
        assert_eq!(
            store.peek(RecordPath::of(&meta).as_str()).unwrap(),
            first_bytes,
            "the first writer's bytes must be unchanged"
        );
    }

    /// A store whose conditional replace can never succeed.
    ///
    /// This is the shape of a backend that cannot construct a genuine
    /// conditional replace: it reports "I did not replace" rather than
    /// failing. The publication must not spin on that answer.
    ///
    /// The store gives up after a runaway number of attempts so that a
    /// failing publication reports an error instead of hanging the test
    /// run.
    #[derive(Default)]
    struct RefusingStore {
        blobs: Mutex<HashMap<String, Vec<u8>>>,
        attempts: Mutex<usize>,
    }

    /// How many conditional replaces this store answers before it gives up.
    const RUNAWAY_LIMIT: usize = 100;

    impl RefusingStore {
        fn attempts(&self) -> usize {
            *self.attempts.lock().unwrap()
        }
    }

    impl BlobStore for RefusingStore {
        fn get(&self, path: &str) -> Result<Option<Vec<u8>>, StoreError> {
            Ok(self.blobs.lock().unwrap().get(path).cloned())
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
            _path: &str,
            _expected: Option<&[u8]>,
            _replacement: &[u8],
        ) -> Result<bool, StoreError> {
            let attempts = {
                let mut attempts = self.attempts.lock().unwrap();
                *attempts += 1;
                *attempts
            };
            if attempts >= RUNAWAY_LIMIT {
                return Err(StoreError::Backend(
                    "the conditional replace was attempted far too many times".to_string(),
                ));
            }
            Ok(false)
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

    /// A store that says outright that it cannot do a conditional replace.
    #[derive(Default)]
    struct UnsupportedStore {
        blobs: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl BlobStore for UnsupportedStore {
        fn get(&self, path: &str) -> Result<Option<Vec<u8>>, StoreError> {
            Ok(self.blobs.lock().unwrap().get(path).cloned())
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
            _path: &str,
            _expected: Option<&[u8]>,
            _replacement: &[u8],
        ) -> Result<bool, StoreError> {
            Err(StoreError::ConditionalReplaceUnsupported)
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

    #[test]
    fn a_store_that_cannot_replace_the_head_does_not_spin_forever() {
        // A conditional replace that always refuses must not turn the
        // publication into an unbounded loop. The call must return, and it
        // must report that the head was contended rather than claiming the
        // version was published.
        let store = RefusingStore::default();
        let meta = metadata(1);

        let outcome = commit_version(&store, &meta, &build_record(&meta));

        assert!(
            matches!(outcome, Err(RecordError::HeadContended)),
            "the publication must report head contention, got {outcome:?}"
        );

        let attempts = store.attempts();
        assert!(
            attempts > 0 && attempts <= 16,
            "the conditional replace must be attempted a bounded number of times, got {attempts}"
        );
    }

    #[test]
    fn a_backend_without_a_conditional_replace_is_reported_not_retried() {
        // A backend that cannot do a conditional replace says so. The
        // publication must surface that refusal rather than retrying it
        // and calling it contention.
        let store = UnsupportedStore::default();
        let meta = metadata(1);

        let outcome = commit_version(&store, &meta, &build_record(&meta));

        assert!(
            matches!(
                outcome,
                Err(RecordError::Store(
                    StoreError::ConditionalReplaceUnsupported
                ))
            ),
            "the refusal must be surfaced, got {outcome:?}"
        );
    }

    #[test]
    fn a_contended_head_leaves_the_version_stored_but_does_not_claim_publication() {
        // The version bytes are immutable and are written before the head is
        // touched, so a contended head leaves the version stored. The
        // outcome must not claim the version became the head.
        let store = RefusingStore::default();
        let meta = metadata(2);

        let outcome = commit_version(&store, &meta, &build_record(&meta));

        assert!(
            matches!(outcome, Err(RecordError::HeadContended)),
            "the publication must not claim success, got {outcome:?}"
        );
        assert!(
            store
                .blobs
                .lock()
                .unwrap()
                .contains_key(RecordPath::of(&meta).as_str()),
            "the immutable version bytes are written before the head is touched"
        );
    }

    #[test]
    fn the_head_advances_to_a_higher_version() {
        let store = MemoryStore::default();
        let v1 = metadata(1);
        let v2 = metadata(2);
        assert_eq!(
            commit_version(&store, &v1, &build_record(&v1)).unwrap(),
            PublishOutcome::Published
        );
        assert_eq!(
            commit_version(&store, &v2, &build_record(&v2)).unwrap(),
            PublishOutcome::Published
        );
        assert_eq!(store.peek(&head_path(&v1)).unwrap(), b"2");
    }

    #[test]
    fn a_lower_version_does_not_move_the_head_backwards() {
        let store = MemoryStore::default();
        let v2 = metadata(2);
        let v1 = metadata(1);
        assert_eq!(
            commit_version(&store, &v2, &build_record(&v2)).unwrap(),
            PublishOutcome::Published
        );
        assert_eq!(
            commit_version(&store, &v1, &build_record(&v1)).unwrap(),
            PublishOutcome::Conflict
        );
        assert_eq!(store.peek(&head_path(&v2)).unwrap(), b"2");
    }

    #[test]
    fn the_same_head_version_is_idempotently_published() {
        let store = MemoryStore::default();
        let meta = metadata(3);
        let head = head_path(&meta);
        store
            .blobs
            .lock()
            .unwrap()
            .insert(head.clone(), b"3".to_vec());
        assert_eq!(
            commit_version(&store, &meta, &build_record(&meta)).unwrap(),
            PublishOutcome::Published
        );
        assert_eq!(store.peek(&head).unwrap(), b"3");
    }

    #[test]
    fn a_corrupt_head_is_refused_without_overwrite() {
        let store = MemoryStore::default();
        let meta = metadata(2);
        let head = head_path(&meta);
        store
            .blobs
            .lock()
            .unwrap()
            .insert(head.clone(), b"invalid".to_vec());
        assert_eq!(
            commit_version(&store, &meta, &build_record(&meta)).unwrap(),
            PublishOutcome::Conflict
        );
        assert_eq!(store.peek(&head).unwrap(), b"invalid");
    }

    #[test]
    fn a_record_whose_metadata_does_not_match_is_refused() {
        let store = MemoryStore::default();
        let record = build_record(&metadata(1));
        let outcome = commit_version(&store, &metadata(2), &record);
        assert!(matches!(outcome, Err(RecordError::MetadataMismatch)));
        assert!(store.peek(RecordPath::of(&metadata(2)).as_str()).is_none());
    }

    #[test]
    fn a_reader_never_sees_a_partial_version() {
        // The version is written in full before the head is published, so
        // following the head always finds a complete, decodable record.
        let store = MemoryStore::default();
        let meta = metadata(1);
        let record = build_record(&meta);
        commit_version(&store, &meta, &record).unwrap();

        let head = store.peek(&head_path(&meta)).unwrap();
        let version: u32 = String::from_utf8(head).unwrap().parse().unwrap();
        let version_meta = metadata(version);
        let stored = store.peek(RecordPath::of(&version_meta).as_str()).unwrap();

        // The stored bytes decode as a complete record: the metadata, the
        // blob and the envelope are all present.
        #[derive(serde::Deserialize)]
        struct Serialized {
            metadata: BoundMetadata,
            blob: Vec<u8>,
            envelope: Vec<u8>,
        }

        let decoded: Serialized = ksp_types::cbor::decode(&stored).unwrap();
        assert_eq!(decoded.metadata, version_meta);
        assert!(!decoded.blob.is_empty());
        assert!(!decoded.envelope.is_empty());
    }

    #[test]
    fn the_head_path_is_a_sibling_of_the_versions() {
        let meta = metadata(1);
        assert_eq!(
            head_path(&meta),
            "p/v-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/user/s-1/head"
        );
    }
}
