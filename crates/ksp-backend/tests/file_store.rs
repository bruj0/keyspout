//! The acceptance tests for the local file Blob Store.
//!
//! The file backend is the only backend that ships in the MVP and it is the
//! one that lives inside the trust boundary of the agent's own machine, so
//! its contract is narrow and must be asserted exactly:
//!
//! * a blob written once is readable byte-for-byte,
//! * a published blob is immutable — a second write is refused, not merged,
//! * a conditional replace happens only when the current bytes match. The
//!   comparison and the replacement are performed under an exclusive lock,
//!   so the backend can tell "another writer won the race" apart from "this
//!   backend has no such primitive", and only the first is worth retrying,
//! * a delete removes exactly one path and is idempotent,
//! * a listing is confined to the requested prefix,
//! * an arming write is durable and reconciled under the same operation
//!   identity,
//! * and no path ever escapes the store root.
//!
//! Each test names the misfit it closes. None of them uses key material or a
//! secret: the store is opaque, so plain distinguishable bytes are enough and
//! keep the fixture free of anything that must not be copied around.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_backend::file::FileStore;
use ksp_backend::store::BlobStore as BackendBlobStore;
// The backend trait extends the record-level one, so the supertrait has to
// be in scope for `get`, `put_if_absent`, `compare_and_set` and `list` to
// resolve on a `FileStore`.
use ksp_record::version::BlobStore as RecordBlobStore;
use tempfile::TempDir;

/// A store rooted in a fresh temporary directory.
///
/// The directory is removed when the returned [`TempDir`] is dropped, so no
/// test can leave a blob behind on a developer's machine.
fn store() -> (TempDir, FileStore) {
    let dir = TempDir::new().expect("a temporary directory");
    let store = FileStore::new(dir.path().to_path_buf()).expect("a store over a fresh directory");
    (dir, store)
}

#[test]
fn a_written_blob_reads_back_exactly() {
    let (_dir, store) = store();
    // Bytes that are not valid UTF-8, so the assertion cannot pass by
    // accident through a lossy text conversion somewhere in the stack.
    let bytes: Vec<u8> = vec![0x00, 0xff, 0x10, 0x80, 0x7f, 0x00];

    assert!(
        store.put_if_absent("p/blob", &bytes).unwrap(),
        "the first write of an absent path must succeed"
    );

    let read = store.get("p/blob").unwrap();
    assert_eq!(
        read,
        Some(bytes.clone()),
        "the blob must read back with the exact bytes that were written"
    );
}

#[test]
fn a_second_write_is_refused_and_the_first_bytes_survive() {
    let (_dir, store) = store();
    let first = b"first-publication".to_vec();
    let second = b"second-publication-attempt".to_vec();

    assert!(
        store.put_if_absent("p/version", &first).unwrap(),
        "the first write of an absent path must succeed"
    );

    // The second write carries *different* bytes. A backend that overwrote
    // would return true and silently replace a published version, which is
    // the immutability violation the record layer depends on.
    assert!(
        !store.put_if_absent("p/version", &second).unwrap(),
        "a second write of different bytes to the same path must be refused"
    );

    assert_eq!(
        store.get("p/version").unwrap(),
        Some(first),
        "the refused write must leave the first bytes unchanged"
    );
}

#[test]
fn a_conditional_replace_replaces_only_the_matching_bytes() {
    let (_dir, store) = store();
    store.put_if_absent("p/head", b"v1").unwrap();

    // A conditional replace that matches the current bytes replaces them.
    assert!(
        store.compare_and_set("p/head", Some(b"v1"), b"v2").unwrap(),
        "a matching expectation must replace the bytes"
    );
    assert_eq!(store.get("p/head").unwrap(), Some(b"v2".to_vec()));

    // A conditional replace that does not match is a lost race. It is
    // reported as `false`, not as a failure: the two are different
    // situations and only one is worth retrying.
    assert!(
        !store
            .compare_and_set("p/head", Some(b"wrong"), b"v3")
            .unwrap(),
        "a mismatching expectation must report a lost race"
    );
    assert_eq!(
        store.get("p/head").unwrap(),
        Some(b"v2".to_vec()),
        "a lost race must leave the stored bytes untouched"
    );

    // A conditional replace against an absent path cannot match either.
    assert!(
        !store
            .compare_and_set("p/absent", Some(b"anything"), b"v1")
            .unwrap(),
        "an absent path must not match an expectation"
    );
    assert_eq!(store.get("p/absent").unwrap(), None);
}

#[test]
fn a_conditional_replace_can_create_an_absent_path() {
    let (_dir, store) = store();
    // `None` means the path must not exist. The first create succeeds.
    assert!(store.compare_and_set("p/fresh", None, b"v1").unwrap());
    assert_eq!(store.get("p/fresh").unwrap(), Some(b"v1".to_vec()));
    // The second create must lose, because the path now exists.
    assert!(!store.compare_and_set("p/fresh", None, b"v2").unwrap());
    assert_eq!(store.get("p/fresh").unwrap(), Some(b"v1".to_vec()));
}

#[test]
fn the_store_mechanics_never_appear_in_a_listing() {
    let (_dir, store) = store();
    store.put_if_absent("p/blob", b"payload").unwrap();
    store
        .compare_and_set("p/blob", Some(b"payload"), b"replaced")
        .unwrap();

    // The lock and replacement files are the store's own machinery. A
    // listing must report only the blobs the store holds.
    let listed = store.list("").unwrap();
    assert_eq!(listed, vec!["p/blob".to_string()]);
    assert!(
        !listed
            .iter()
            .any(|path| path.contains("lock") || path.contains("replacement")),
        "the listing must not expose the store's machinery: {listed:?}"
    );
}

#[test]
fn the_store_machinery_never_overwrites_a_blob() {
    let (_dir, store) = store();

    // A blob whose name resembles the store's machinery must survive a
    // conditional replace on a neighbouring path. An earlier implementation
    // derived the lock and replacement names from the target's own name,
    // so the replace of `p/blob` wrote through `p/blob.ksp-replacement` and
    // destroyed this blob.
    store
        .put_if_absent("p/blob.ksp-replacement", b"precious")
        .unwrap();
    store
        .put_if_absent("p/blob.ksp-lock", b"also precious")
        .unwrap();
    store.put_if_absent("p/blob", b"v1").unwrap();
    store.compare_and_set("p/blob", Some(b"v1"), b"v2").unwrap();

    assert_eq!(
        store.get("p/blob.ksp-replacement").unwrap(),
        Some(b"precious".to_vec()),
        "the store's machinery must not overwrite a blob"
    );
    assert_eq!(
        store.get("p/blob.ksp-lock").unwrap(),
        Some(b"also precious".to_vec()),
        "the store's machinery must not overwrite a blob"
    );

    // Every blob is still listed, machinery or not.
    let mut listed = store.list("").unwrap();
    listed.sort();
    assert_eq!(
        listed,
        vec![
            "p/blob".to_string(),
            "p/blob.ksp-lock".to_string(),
            "p/blob.ksp-replacement".to_string(),
        ]
    );
}

#[test]
fn the_machinery_directory_is_reserved() {
    let (_dir, store) = store();
    // The store's own machinery lives under a reserved directory. A blob
    // may not be stored there, because the store's lock and replacement
    // files would overwrite it.
    assert!(
        store
            .put_if_absent(".ksp-machinery/blob", b"payload")
            .is_err(),
        "the machinery directory must be reserved"
    );
    assert!(
        store.get(".ksp-machinery/blob").is_err(),
        "the machinery directory must be reserved"
    );
    assert!(
        store.delete(".ksp-machinery/blob").is_err(),
        "the machinery directory must be reserved"
    );
}

#[test]
fn a_conditional_replace_survives_a_concurrent_writer() {
    use std::sync::Arc;

    let (_dir, store) = store();
    let store = Arc::new(store);
    store.put_if_absent("p/head", b"v1").unwrap();

    // Two writers race to advance the same head. Exactly one of them may
    // win each round, and the stored bytes must always be one of the two
    // candidates — never a mixture.
    let mut handles = Vec::new();
    for candidate in [b"v2".to_vec(), b"v3".to_vec(), b"v4".to_vec()] {
        let store = Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            (0..25)
                .filter(|_| {
                    store
                        .compare_and_set("p/head", Some(b"v1"), &candidate)
                        .unwrap_or(false)
                })
                .count()
        }));
    }
    let wins: usize = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .sum();

    let final_value = store.get("p/head").unwrap().unwrap();
    assert!(
        final_value == b"v2".to_vec()
            || final_value == b"v3".to_vec()
            || final_value == b"v4".to_vec(),
        "the head must hold exactly one candidate, got {final_value:?}"
    );
    // At least one writer must have won: the primitive works, it is not
    // refusing every attempt.
    assert!(wins > 0, "no writer ever won the conditional replace");
}

#[test]
fn a_delete_removes_the_blob_and_is_idempotent() {
    let (_dir, store) = store();
    store.put_if_absent("p/gone", b"payload").unwrap();

    store.delete("p/gone").unwrap();
    assert_eq!(
        store.get("p/gone").unwrap(),
        None,
        "a deleted blob must no longer be readable"
    );

    // A retried delete must succeed: the lease cleanup and the consume path
    // both retry, and a second failure would turn a completed operation into
    // a reported error.
    store
        .delete("p/gone")
        .expect("deleting an already absent path must succeed");
    store
        .delete("p/never-written")
        .expect("deleting a path that never existed must succeed");
}

#[test]
fn a_listing_is_confined_to_its_prefix() {
    let (_dir, store) = store();
    store.put_if_absent("alpha/one", b"1").unwrap();
    store.put_if_absent("alpha/two", b"2").unwrap();
    store.put_if_absent("beta/one", b"3").unwrap();

    assert_eq!(
        store.list("alpha/").unwrap(),
        vec!["alpha/one".to_string(), "alpha/two".to_string()],
        "a listing must return exactly the paths under the requested prefix"
    );
    assert_eq!(
        store.list("beta/").unwrap(),
        vec!["beta/one".to_string()],
        "a listing must not return paths under a different prefix"
    );
    assert!(
        store.list("gamma/").unwrap().is_empty(),
        "a listing of a prefix with nothing under it must be empty"
    );
}

#[test]
fn a_traversing_path_is_refused_and_nothing_escapes_the_root() {
    let dir = TempDir::new().expect("a temporary directory");
    // The store root is a *child* of the temporary directory, so an escaped
    // write would land next to it and be visible to the assertions below.
    let root = dir.path().join("store");
    let store = FileStore::new(root.clone()).expect("a store over a fresh directory");

    // Each of these would reach a file outside the root if the path were
    // joined naively: a parent escape, an escape in the middle of a path,
    // and an absolute path that ignores the root entirely.
    let hostile = ["../escape", "p/../../etc/passwd", "/etc/passwd"];

    for path in hostile {
        assert!(
            store.get(path).is_err(),
            "a traversing path must be refused by read, not silently resolved: {path}"
        );
        assert!(
            store.put_if_absent(path, b"payload").is_err(),
            "a traversing path must be refused by write, not silently resolved: {path}"
        );
        assert!(
            store.delete(path).is_err(),
            "a traversing path must be refused by delete, not silently resolved: {path}"
        );
    }

    assert!(
        !dir.path().join("escape").exists(),
        "a refused write must not create a file outside the store root"
    );
    assert!(
        !dir.path().join("etc/passwd").exists(),
        "a refused write must not create a file outside the store root"
    );

    let entries: Vec<String> = std::fs::read_dir(dir.path())
        .expect("the temporary directory is readable")
        .map(|entry| {
            entry
                .expect("a readable directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(
        entries,
        vec!["store".to_string()],
        "the store root must be the only thing the store created outside its own confinement"
    );
}

/// A symlink planted inside the root must not become an escape hatch.
///
/// A lexical check on the path components is a *check*, not containment:
/// anything sharing the root's owner can plant a symlink, and a store that
/// follows it would read or remove a file outside the root. The store must
/// refuse the path instead of following it.
#[test]
fn a_symlink_inside_the_root_does_not_escape_it() {
    let dir = tempfile::TempDir::new().expect("a temporary directory");
    let outside = dir.path().join("outside");
    std::fs::write(&outside, b"OUTSIDE-BYTES").expect("a file outside the store root");

    let root = dir.path().join("store");
    let store = FileStore::new(root.clone()).expect("a store over a fresh directory");
    std::fs::create_dir_all(root.join("nested")).expect("a nested directory");
    std::os::unix::fs::symlink(&outside, root.join("nested/link")).expect("a planted symlink");

    assert!(
        store.get("nested/link").is_err(),
        "a read through a symlink must be refused, not followed out of the root"
    );
    assert!(
        store.delete("nested/link").is_err(),
        "a delete through a symlink must be refused, not followed out of the root"
    );
    assert!(
        std::fs::read(&outside).is_ok_and(|bytes| bytes == b"OUTSIDE-BYTES"),
        "the file outside the root must be untouched"
    );
}

/// The file backend must be able to arm a lease durably.
///
/// WP08 refuses to publish a token before an acknowledged arm, so a
/// backend that cannot arm cannot be used for a lease at all. The file
/// backend is the reference backend, and the review of WP02 found that it
/// had no arming implementation while the classification already said it
/// was `None`.
#[test]
fn the_file_backend_arms_durably_and_reconciles_under_one_identity() {
    use ed25519_dalek::SigningKey;
    use ksp_backend::arming::{ArmError, ArmRecord, Durability, arm_intent};
    use ksp_types::{ActorId, DeletionIntent, Level, OpaqueSecretId, VaultId};

    let (dir, store) = store();
    let signer = SigningKey::from_bytes(&[7; 32]);
    let intent = DeletionIntent {
        intent_id: "intent-1".into(),
        vault_id: VaultId::new("vault-1"),
        user_id: ksp_types::PrincipalId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        level: Level::Agent(
            ksp_types::AgentId::parse("00000000-0000-4000-8000-0000000000a1").unwrap(),
        ),
        secret_id: OpaqueSecretId::new("opaque-1"),
        version: 3,
        deadline: 1_800_000_000,
        authorized_deleters: vec![ActorId::User(
            ksp_types::PrincipalId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        )],
    };
    let record = ArmRecord::sign(
        "operation-1".into(),
        intent.clone(),
        "signer-1".into(),
        None,
        &signer,
    )
    .unwrap();

    let ack = arm_intent(&store, &record).unwrap();
    assert_eq!(ack.durability, Durability::LocalSync);
    assert_eq!(ack.operation_identity, "operation-1");

    // The journal is shared, so the record crosses accounts: the armer is the
    // principal and the reader is the sweep. `0644` exactly, not "whatever the
    // armer's umask allows" — a principal who logs in with `umask 077` would
    // otherwise arm a record the sweep cannot read, and the lease would never be
    // removed at its deadline.
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(dir.path().join("intents/operation-1"))
            .expect("the arm record exists")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode, 0o644, "the arm record is readable across accounts");

    // A retry under the same identity with the same bytes reconciles
    // rather than duplicating.
    let again = arm_intent(&store, &record).unwrap();
    assert_eq!(again.durability, Durability::LocalSync);
    let listed = store.list("intents/").unwrap();
    assert_eq!(listed, vec!["intents/operation-1".to_string()]);

    // A different intent under the same identity is a conflict, not an
    // overwrite: the earlier arm's evidence must survive.
    let other = ArmRecord::sign(
        "operation-1".into(),
        DeletionIntent {
            deadline: 1_900_000_000,
            ..intent
        },
        "signer-1".into(),
        None,
        &signer,
    )
    .unwrap();
    assert!(matches!(
        arm_intent(&store, &other),
        Err(ArmError::IdentityConflict)
    ));
    assert_eq!(store.list("intents/").unwrap().len(), 1);
}

/// The file backend must be able to publish a record version.
///
/// The head pointer is published with a conditional replace, so a backend
/// that cannot perform one cannot commit a record at all. The review of
/// WP02 found that the file backend — the reference backend, and the one an
/// operator gets by default — could store the immutable version bytes and
/// then fail to publish the head.
#[test]
fn the_file_backend_publishes_a_record_version_and_its_head() {
    use ksp_record::version::commit_version;
    use ksp_types::{BoundMetadata, ContentKey, Level, OpaqueSecretId, VaultId};

    let (_dir, store) = store();
    let meta = BoundMetadata {
        vault_id: VaultId::new("v-1"),
        user_id: ksp_types::PrincipalId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        level: Level::User,
        secret_id: OpaqueSecretId::new("s-1"),
        version: 1,
    };
    let content_key = ContentKey::generate();
    let blob =
        ksp_record::blob::ContentBlob::seal(&content_key, b"name", b"value", b"aad").unwrap();
    let mut private_key = [0u8; 32];
    rand::fill(&mut private_key);
    let public_key = ksp_record::kem::public_key_for(&private_key).unwrap();
    let envelope =
        ksp_record::envelope::RecordEnvelope::seal(&content_key, &public_key, &meta).unwrap();
    let record = ksp_record::envelope::Record {
        metadata: meta.clone(),
        blob,
        envelope,
    };

    let outcome = commit_version(&store, &meta, &record).unwrap();
    assert_eq!(outcome, ksp_record::version::PublishOutcome::Published);
    assert!(
        store
            .get(ksp_record::RecordPath::of(&meta).as_str())
            .unwrap()
            .is_some(),
        "the immutable version bytes must be stored"
    );
    assert_eq!(
        store.get(&ksp_record::version::head_path(&meta)).unwrap(),
        Some(b"1".to_vec()),
        "the head must name the published version"
    );
}

/// Every backend must agree on what a valid blob path is.
///
/// A local filesystem collapses an empty interior segment, so `a//b` and
/// `a/b` name the same file. Silently accepting both would let two distinct
/// path strings alias one blob, so the path is refused instead.
/// Misfit B and C2: a record is its owner's. The store writes `0600` rather than
/// taking the caller's `umask`, because an agent level is group-writable for the
/// sweep and a `0644` record would be readable through it.
#[test]
fn a_written_record_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path().to_path_buf()).unwrap();
    store
        .put_if_absent(
            "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-1/secret-1",
            b"the sealed record",
        )
        .unwrap();

    let path = dir
        .path()
        .join("p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-1/secret-1");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "a record is readable by its owner only");
}

#[test]
fn a_path_that_a_filesystem_would_alias_is_refused() {
    let (_dir, store) = store();
    store.put_if_absent("a/b", b"original").unwrap();

    for malformed in ["a//b", "a/", "/a", "a/./b", "a/../b", ""] {
        assert!(
            store.put_if_absent(malformed, b"aliased").is_err(),
            "the path {malformed:?} must be refused"
        );
        assert!(
            store.get(malformed).is_err(),
            "the path {malformed:?} must be refused on read"
        );
    }
    assert_eq!(
        store.get("a/b").unwrap(),
        Some(b"original".to_vec()),
        "a malformed path must not reach the blob it resembles"
    );
}

/// A listing prefix may end in a slash; a blob path may not.
///
/// The two are different: a prefix names a range of paths, a path names one
/// blob. The same call must not succeed against one backend and fail
/// against another.
#[test]
fn a_listing_prefix_tolerates_one_trailing_slash() {
    let (_dir, store) = store();
    store.put_if_absent("records/one", b"a").unwrap();
    store.put_if_absent("records/two", b"b").unwrap();

    assert_eq!(
        store.list("records/").unwrap(),
        store.list("records").unwrap()
    );
    assert_eq!(store.list("records/").unwrap().len(), 2);
    // An interior empty segment is still malformed.
    assert!(store.list("records//one").is_err());
}

/// A listing whose prefix names a directory reaches what is *below* it.
///
/// `secret ls` and `admin list` name a level (`p/<vault>/<user>/user`) and expect
/// the records under it. The walk prunes directories a request does not reach, and
/// pruning the ones the request *does* reach is how a listing silently came back
/// empty on a store full of records: the prefix check covered the ancestors on the
/// way down and not the descendants below the prefix itself.
#[test]
fn a_listing_reaches_below_the_prefix_it_was_given() {
    let (_dir, store) = store();
    for path in ["a/b/c/1", "a/b/c/2", "a/b/d/1", "a/e/1"] {
        assert!(store.put_if_absent(path, b"x").unwrap(), "{path} is stored");
    }

    assert_eq!(
        store.list("a/b/c").unwrap(),
        vec!["a/b/c/1".to_string(), "a/b/c/2".to_string()],
        "a prefix that names a directory returns the files below it"
    );
    assert_eq!(
        store.list("a/b").unwrap(),
        vec![
            "a/b/c/1".to_string(),
            "a/b/c/2".to_string(),
            "a/b/d/1".to_string()
        ],
        "and so does a shallower one"
    );
    assert_eq!(
        store.list("a/b/c/").unwrap(),
        vec!["a/b/c/1".to_string(), "a/b/c/2".to_string()],
        "a trailing slash names the same prefix"
    );
}
