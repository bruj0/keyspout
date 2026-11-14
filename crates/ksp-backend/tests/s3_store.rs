#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The S3 Blob Store and its bucket configuration evidence.
//!
//! These tests run against a live S3-compatible server. The review of
//! WP02 found that the S3 module had no test at all, and that the paths
//! it exercised were broken: the evidence collection failed on every
//! bucket that had no lifecycle configuration, a listing prefix ending in
//! a slash was rejected, and a conditional replace against an absent
//! object reported a backend failure where the contract expects a lost
//! race. A test that never ran against a real server could not have
//! found any of them.
//!
//! The server is the one the development environment provides. When it is
//! not reachable the tests fail loudly rather than skipping: a backend
//! whose contract is only proven against a stub is not proven.

use std::time::Duration;

use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use ksp_backend::admission::{AdmissionError, S3Configuration, classify_s3};
use ksp_backend::s3::S3Store;
use ksp_backend::store::BlobStore;
use ksp_record::version::BlobStore as RecordBlobStore;

const ENDPOINT: &str = "http://127.0.0.1:9000";
const ACCESS_KEY: &str = "kspadmin";
const SECRET_KEY: &str = "kspadminsecret123";
const UNVERSIONED_BUCKET: &str = "ksp-s3-unversioned";
const VERSIONED_BUCKET: &str = "ksp-s3-versioned";

/// A client for the development S3 server.
fn client() -> Client {
    let credentials = Credentials::new(ACCESS_KEY, SECRET_KEY, None, None, "ksp-test");
    let config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .region(Region::new("us-east-1"))
        .credentials_provider(credentials)
        .endpoint_url(ENDPOINT)
        .force_path_style(true)
        .build();
    Client::from_conf(config)
}

/// A store over the unversioned bucket, with a prefix unique to one test.
///
/// The tests run in parallel against one bucket, so each needs its own
/// prefix: a shared prefix would let one test's objects appear in
/// another's listing.
fn store(label: &str) -> S3Store {
    let prefix = format!("ksp-test-{}-{label}/", std::process::id());
    S3Store::new(client(), UNVERSIONED_BUCKET.into(), prefix).unwrap()
}

fn configuration(cleanup_expected: bool) -> S3Configuration {
    S3Configuration {
        interval: Some(Duration::from_secs(86_400)),
        cleanup_expected,
    }
}

#[test]
fn the_store_round_trips_an_opaque_blob() {
    let store = store("blob");
    let path = "records/blob";

    assert!(store.put_if_absent(path, b"opaque bytes").unwrap());
    // A second create must be refused, not overwrite.
    assert!(!store.put_if_absent(path, b"different bytes").unwrap());
    assert_eq!(store.get(path).unwrap(), Some(b"opaque bytes".to_vec()));
    assert_eq!(store.list("records/").unwrap(), vec![path.to_string()]);

    store.delete(path).unwrap();
    assert_eq!(store.get(path).unwrap(), None);
}

#[test]
fn a_listing_prefix_may_end_in_a_trailing_slash() {
    let store = store("list");
    store.put_if_absent("records/one", b"a").unwrap();
    store.put_if_absent("records/two", b"b").unwrap();

    // The file and valkey backends both accept a trailing slash, so the S3
    // backend must too: the same call must not work against two backends
    // and fail against the third.
    assert_eq!(
        store.list("records/").unwrap(),
        store.list("records").unwrap()
    );
    assert_eq!(store.list("records/").unwrap().len(), 2);

    // An interior empty segment is still a different path and is refused.
    assert!(store.list("records//one").is_err());
}

#[test]
fn a_conditional_replace_reports_a_lost_race_rather_than_a_failure() {
    let store = store("cas");
    store.put_if_absent("cas/present", b"v1").unwrap();

    // A matching expectation replaces the bytes.
    assert!(
        store
            .compare_and_set("cas/present", Some(b"v1"), b"v2")
            .unwrap()
    );
    assert_eq!(store.get("cas/present").unwrap(), Some(b"v2".to_vec()));

    // A mismatching expectation is a lost race, not a failure.
    assert!(
        !store
            .compare_and_set("cas/present", Some(b"wrong"), b"v3")
            .unwrap()
    );
    assert_eq!(store.get("cas/present").unwrap(), Some(b"v2".to_vec()));

    // An absent object cannot match an expectation either. It is a lost
    // race, not a backend failure, and it must not create the object.
    assert!(
        !store
            .compare_and_set("cas/absent", Some(b"anything"), b"v1")
            .unwrap()
    );
    assert_eq!(store.get("cas/absent").unwrap(), None);

    // A create against an absent path succeeds; a second one does not.
    assert!(store.compare_and_set("cas/fresh", None, b"v1").unwrap());
    assert!(!store.compare_and_set("cas/fresh", None, b"v2").unwrap());
    assert_eq!(store.get("cas/fresh").unwrap(), Some(b"v1".to_vec()));
}

#[test]
fn the_evidence_of_an_unconfigured_bucket_is_readable() {
    // A bucket with no lifecycle configuration is the ordinary case. The
    // service answers "NoSuchLifecycleConfiguration", which is a fact about
    // the bucket, not unknown evidence. The review found that this made
    // evidence collection fail for every bucket, so no S3 classification
    // could ever be reached.
    let store = S3Store::new(client(), UNVERSIONED_BUCKET.into(), "ksp/".into()).unwrap();
    let evidence = store.evidence(configuration(false)).unwrap();
    assert!(
        !evidence.versioned,
        "the unversioned bucket must not be versioned"
    );
    assert!(
        !evidence.soft_delete,
        "a bucket without object lock must not report soft delete"
    );
    assert!(
        !evidence.lifecycle_covers_prefix,
        "a bucket without a lifecycle rule must not report coverage"
    );
}

#[test]
fn the_evidence_of_a_versioned_bucket_is_readable() {
    // A versioned bucket keeps old versions, so it is `None` for leases
    // even though a canary lookup would report absence.
    let store = S3Store::new(client(), VERSIONED_BUCKET.into(), "ksp/".into()).unwrap();
    let evidence = store.evidence(configuration(false)).unwrap();
    assert!(
        evidence.versioned,
        "the versioned bucket must be observed as versioned"
    );

    let classified = classify_s3(configuration(false), evidence).unwrap();
    assert_eq!(
        classified.capability,
        ksp_types::LeaseCapability::None,
        "a versioned bucket must stay None for leases"
    );
}

#[test]
fn a_known_absence_of_cleanup_does_not_contradict_a_declaration() {
    // The configuration does not expect cleanup and the bucket has none:
    // the two agree, and the classification is `None` rather than a
    // failure.
    let store = S3Store::new(client(), UNVERSIONED_BUCKET.into(), "ksp/".into()).unwrap();
    let evidence = store.evidence(configuration(false)).unwrap();
    let classified = classify_s3(configuration(false), evidence).unwrap();
    assert_eq!(classified.capability, ksp_types::LeaseCapability::None);

    // A configuration that expects cleanup the bucket does not have is a
    // known mismatch, and it must fail rather than downgrade silently.
    let store = S3Store::new(client(), UNVERSIONED_BUCKET.into(), "ksp/".into()).unwrap();
    let evidence = store.evidence(configuration(true)).unwrap();
    assert!(matches!(
        classify_s3(configuration(true), evidence),
        Err(AdmissionError::ConfigurationMismatch(_))
    ));
}
