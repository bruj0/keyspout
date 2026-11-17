//! The publication as a deployment artifact: its path, its modes, its entries.
//!
//! The token half of the same subject — issuing and running a policy-bound delivery —
//! is `policy_token.rs`, beside this file. The record layer itself is unchanged by
//! this work package, so `crates/ksp-record` gains no publication suite: there is no
//! envelope or blob behaviour to pin that `envelope.rs` does not already pin.
//!
//! # Where a publication may live, and the modes it is written with
//!
//! The path is fixed by FR-016 and refused by FR-036, because a publication is the
//! one readable artifact under the admin's principal: a second accepted shape is a
//! second place to widen. The modes are a `file` fact and are applied with
//! `set_permissions`, never through `open(2)`'s mode, which the caller's `umask`
//! masks.
//!
//! # Why the sibling assertion is here
//!
//! Misfit E is not "the publication is too readable" — it is "the widening reached
//! something else". So every other entry under the admin's principal is asserted
//! to keep its own mode, one by one, rather than trusting that a directory listing
//! which mentions `granted/` left its neighbours alone.
//!
//! A test reports a failure by panicking, and the panic message is what says why.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::os::unix::fs::PermissionsExt;

use ksp::publication::{PUBLICATION_DIR_MODE, PUBLICATION_FILE_MODE, PublicationPath};
use ksp_types::{OpaqueSecretId, PrincipalId, RecordVersion, VaultId};
use std::path::PathBuf;

use support::admin_and_two_users;

fn admin(layout: &ksp::config::Layout) -> PrincipalId {
    ksp::deployment::Deployment::load(layout)
        .expect("a deployment record")
        .admin
}

#[test]
fn only_the_derived_path_parses() {
    let fixture = admin_and_two_users();
    let layout = fixture.layout(&fixture.admin_home);
    let admin = admin(&layout);
    let derived = PublicationPath::derive(
        VaultId::new("vault-1"),
        admin,
        OpaqueSecretId::new("s1"),
        RecordVersion(3),
    );

    assert_eq!(
        derived.canonical(),
        format!("p/vault-1/{admin}/granted/s1/3")
    );
    assert_eq!(
        PublicationPath::parse(&derived.canonical())
            .expect("the derived path parses")
            .canonical(),
        derived.canonical()
    );

    // Every near miss: another level, another depth, a relative segment, an
    // unparseable version, an empty segment. A refusal names the accepted shape,
    // because a refusal that says only "invalid" leaves the caller guessing which
    // of six values was wrong.
    let near_misses = [
        format!("p/vault-1/{admin}/admin/s1/3"),
        format!("p/vault-1/{admin}/granted/s1"),
        format!("p/vault-1/{admin}/granted/s1/3/4"),
        format!("p/vault-1/{admin}/granted/../3"),
        format!("p/vault-1/{admin}/granted/s1/three"),
        "p/vault-1/granted/s1/3".to_string(),
        format!("p/vault-1/{admin}/granted//3"),
        format!("p/vault-1/{admin}/granted/s1/3 "),
    ];
    for near_miss in near_misses {
        let refused = PublicationPath::parse(&near_miss).unwrap_err().to_string();
        assert!(
            refused.contains("granted/<secret>/<version>"),
            "{near_miss} is refused naming the accepted shape: {refused}"
        );
    }
}

#[test]
fn the_file_sits_under_the_secret_directory_and_the_metadata_names_the_publication_level() {
    use ksp_types::Level;

    let fixture = admin_and_two_users();
    let layout = fixture.layout(&fixture.admin_home);
    let admin = admin(&layout);
    let path = PublicationPath::derive(
        VaultId::new("vault-1"),
        admin,
        OpaqueSecretId::new("s1"),
        RecordVersion(2),
    );

    assert!(
        path.dir(&layout).ends_with("granted/s1"),
        "{}",
        path.dir(&layout).display()
    );
    assert!(
        path.file(&layout).ends_with("granted/s1/2"),
        "{}",
        path.file(&layout).display()
    );

    // The AAD every entry authenticates names the publication level, the admin as
    // the owning principal and the exact version. A metadata naming anything else
    // would produce an envelope no agent can open — misfit C.
    let metadata = path.metadata();
    assert_eq!(metadata.level, Level::Granted);
    assert_eq!(metadata.user_id, admin);
    assert_eq!(metadata.secret_id, OpaqueSecretId::new("s1"));
    assert_eq!(metadata.version, 2);
    assert_eq!(metadata.vault_id, VaultId::new("vault-1"));
}

#[test]
fn publishing_applies_the_modes_and_leaves_every_sibling_alone() {
    let fixture = admin_and_two_users();
    let layout = fixture.layout(&fixture.admin_home);
    let admin = admin(&layout);
    let path = PublicationPath::derive(
        VaultId::new("vault-1"),
        admin,
        OpaqueSecretId::new("s1"),
        RecordVersion(1),
    );

    // The directories the publication needs, and one file, are created by the
    // operation under test rather than by the test: `umask` is the reason.
    std::fs::create_dir_all(path.dir(&layout)).unwrap();
    std::fs::write(path.file(&layout), b"publication").unwrap();
    ksp::publication::apply_modes(&path, &layout).expect("the modes are applied");

    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode(&path.file(&layout)),
        PUBLICATION_FILE_MODE,
        "the artifact is 0740"
    );
    assert_eq!(
        mode(&path.dir(&layout)),
        PUBLICATION_DIR_MODE,
        "the secret directory is 0750"
    );
    assert_eq!(
        mode(path.dir(&layout).parent().unwrap()),
        PUBLICATION_DIR_MODE,
        "granted/ itself is 0750"
    );

    // Misfit E: every sibling keeps the mode it had. Recorded before the widening
    // rather than compared against a guess — a sibling is *unchanged*, and which
    // modes the layout gives its own files (the registry is deliberately `0644`)
    // is not this module's business.
    let principal_root = path
        .dir(&layout)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let before: Vec<(PathBuf, u32)> = std::fs::read_dir(&principal_root)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_name() != "granted")
        .map(|entry| {
            let path = entry.path();
            let mode = mode(&path);
            (path, mode)
        })
        .collect();
    assert!(
        !before.is_empty(),
        "the principal root holds a registry to compare"
    );
    let store_mode = mode(&layout.store_root());

    ksp::publication::apply_modes(&path, &layout).expect("the modes are applied again");

    for (sibling, expected) in before {
        assert_eq!(
            mode(&sibling),
            expected,
            "{} keeps the mode it had: the widening reached a sibling",
            sibling.display()
        );
    }
    assert_eq!(
        mode(&principal_root),
        0o711,
        "the principal root keeps its traversal-only mode"
    );
    assert_eq!(
        mode(&layout.store_root()),
        store_mode,
        "the store root is untouched: the widening is one subtree"
    );
}
/// The artifact's own invariants: one entry per policy, idempotent publish, one
/// release at a time, and a refusal when its metadata is not its path's.
///
/// No vault and no store are needed: the blob and the seals are made directly, so
/// these tests are about the artifact's shape rather than about publication.
mod artifact {
    use ksp::publication::{Publication, PublicationError, PublicationPath};
    use ksp_record::blob::ContentBlob;
    use ksp_record::envelope::RecordEnvelope;
    use ksp_types::{ContentKey, OpaqueSecretId, PrincipalId, RecordVersion, VaultId};

    const ADMIN: &str = "6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f";

    fn path() -> PublicationPath {
        PublicationPath::derive(
            VaultId::new("vault-1"),
            PrincipalId::parse(ADMIN).unwrap(),
            OpaqueSecretId::new("s1"),
            RecordVersion(1),
        )
    }

    /// A deterministic, valid X25519 key pair: derived, never random bytes.
    fn key_pair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let sk = [seed; 32];
        let derived = ksp_record::kem::public_key_for(&sk).expect("a valid secret key");
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&derived);
        (sk, pk)
    }

    /// A publication with its blob and admin seal, and no entries yet.
    fn empty() -> (Publication, [u8; 32]) {
        let metadata = path().metadata();
        let aad = metadata.bound_aad().unwrap();
        let key = ContentKey::generate();
        let blob = ContentBlob::seal(&key, b"name", b"value", &aad).unwrap();
        let (admin_sk, admin_pk) = key_pair(7);
        let admin_seal = RecordEnvelope::seal(&key, &admin_pk, &metadata).unwrap();
        (Publication::new(metadata, blob, admin_seal), admin_sk)
    }

    fn envelope() -> RecordEnvelope {
        let (_sk, pk) = key_pair(9);
        RecordEnvelope::seal(&ContentKey::generate(), &pk, &path().metadata()).unwrap()
    }

    #[test]
    fn one_policy_one_entry_and_publishing_twice_changes_nothing() {
        let (mut publication, _) = empty();
        assert!(
            publication.add_entry("aa", false, envelope()),
            "the first publish adds"
        );
        let first = publication.entries();

        // The retried publish: same policy, a *different* envelope, and nothing moves.
        assert!(
            !publication.add_entry("aa", false, envelope()),
            "a second publish of one policy is not an addition"
        );
        assert_eq!(publication.reference_count(), 1);
        assert_eq!(publication.entries(), first, "the first entry is untouched");

        // A second policy is a second entry, in add order, and keeps its flag.
        assert!(publication.add_entry("bb", true, envelope()));
        assert_eq!(publication.reference_count(), 2);
        assert!(!publication.entries()[0].cooperative);
        assert!(
            publication.entries()[1].cooperative,
            "the cooperative flag survives"
        );
    }

    #[test]
    fn releasing_one_reference_leaves_the_other_and_the_last_release_reports_zero() {
        let (mut publication, _) = empty();
        publication.add_entry("aa", false, envelope());
        publication.add_entry("bb", false, envelope());

        assert!(publication.release("aa"), "the first release removes one");
        assert_eq!(publication.reference_count(), 1);
        assert!(!publication.holds("aa"));
        assert!(
            publication.holds("bb"),
            "the surviving policy keeps its entry"
        );

        // Releasing a policy that is not there changes nothing and says so.
        assert!(!publication.release("aa"));
        assert_eq!(publication.reference_count(), 1);

        assert_eq!(
            publication.references().survivors(),
            vec!["bb"],
            "the reference set names the surviving policy, not a count"
        );

        assert!(publication.release("bb"));
        assert_eq!(
            publication.reference_count(),
            0,
            "the last release reports zero"
        );
        assert!(
            publication.references().is_empty(),
            "an empty reference set is what tells the lifecycle the artifact may go"
        );
    }

    #[test]
    fn the_artifact_round_trips_and_the_admin_seal_still_opens_the_blob() {
        let (mut publication, admin_sk) = empty();
        publication.add_entry("aa", false, envelope());
        publication.add_entry("bb", true, envelope());

        let bytes = publication.encode().unwrap();
        let decoded = Publication::decode(&bytes).unwrap();
        assert_eq!(decoded.reference_count(), 2);
        assert_eq!(decoded.entries(), publication.entries());
        assert_eq!(
            decoded.encode().unwrap(),
            bytes,
            "encoding is a function of contents"
        );

        // A decode that lost the admin seal would make the artifact unextendable,
        // which is the one thing it exists for.
        let key = decoded
            .open_with_admin(&admin_sk)
            .expect("the admin seal survives the round trip");
        let aad = decoded.metadata().bound_aad().unwrap();
        // The blob is the wire's own field: reading it here is what proves the
        // decoded artifact still carries the bytes rather than a re-encoding.
        #[derive(serde::Deserialize)]
        struct Mirror {
            blob: Vec<u8>,
        }
        let mirror: Mirror = ksp_types::cbor::decode(&bytes).unwrap();
        let blob = ksp_record::blob::ContentBlob::from_bytes(&mirror.blob).unwrap();
        let (name, value) = blob.open(&key, &aad).unwrap();
        assert_eq!(name, b"name");
        assert_eq!(value, b"value");
    }

    #[test]
    fn two_entries_for_one_policy_are_refused_by_the_decoder() {
        let (publication, _) = empty();
        let bytes = publication.encode().unwrap();
        // The type cannot make a duplicate, so the wire is where a hostile artifact
        // would carry one.
        let refused = Publication::decode(&with_duplicate_entry()).unwrap_err();
        assert!(
            matches!(refused, PublicationError::DuplicateEntry { .. }),
            "a repeated policy id is refused: {refused}"
        );
        assert!(Publication::decode(&bytes).is_ok(), "the control decodes");
    }

    /// Rewrite an artifact so both entries name one policy.
    fn with_duplicate_entry() -> Vec<u8> {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Entry {
            policy: String,
            cooperative: bool,
            envelope: Vec<u8>,
        }
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Doc {
            version: u16,
            metadata: ksp_types::BoundMetadata,
            blob: Vec<u8>,
            admin_seal: Vec<u8>,
            entries: Vec<Entry>,
        }
        let (mut publication, _) = empty();
        publication.add_entry("aa", false, envelope());
        publication.add_entry("bb", true, envelope());
        let mut doc: Doc = ksp_types::cbor::decode(&publication.encode().unwrap()).unwrap();
        doc.entries[1].policy = "aa".to_string();
        ksp_types::cbor::encode(&doc).unwrap()
    }

    #[test]
    fn an_artifact_bound_to_another_path_is_refused() {
        let (publication, _) = empty();
        publication
            .verify_binding(&path())
            .expect("its own path binds");
        let other = PublicationPath::derive(
            VaultId::new("vault-1"),
            PrincipalId::parse(ADMIN).unwrap(),
            OpaqueSecretId::new("s2"),
            RecordVersion(1),
        );
        let refused = publication.verify_binding(&other).unwrap_err().to_string();
        assert!(
            refused.contains("bound to another level, principal, secret or version"),
            "the refusal says what disagreed: {refused}"
        );
    }
}

/// Publishing through the store: the artifact appears at its path, a second policy
/// adds an entry instead of replacing one, and a release removes exactly one.
///
/// The plaintext and the content key come from closures, so no vault and no
/// capability are needed: the point here is the artifact and the file system, not
/// the admin's password.
mod store {
    use std::os::unix::fs::PermissionsExt;

    use ksp::publication::{
        self, PUBLICATION_DIR_MODE, PUBLICATION_FILE_MODE, Publication, PublicationError,
        PublicationPath,
    };
    use ksp_types::{OpaqueSecretId, PrincipalId, RecordVersion, VaultId};

    const ADMIN: &str = "6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f";

    fn path() -> PublicationPath {
        PublicationPath::derive(
            VaultId::new("vault-1"),
            PrincipalId::parse(ADMIN).unwrap(),
            OpaqueSecretId::new("s1"),
            RecordVersion(1),
        )
    }

    fn key_pair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let sk = [seed; 32];
        let derived = ksp_record::kem::public_key_for(&sk).expect("a valid secret key");
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&derived);
        (sk, pk)
    }

    fn request<'a>(
        policy: &'a str,
        cooperative: bool,
        target: [u8; 32],
        admin_recipient: [u8; 32],
    ) -> ksp::publication::PublishRequest<'a> {
        ksp::publication::PublishRequest {
            policy,
            cooperative,
            target,
            admin_recipient,
        }
    }

    fn layout() -> (tempfile::TempDir, ksp::config::Layout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = ksp::config::Layout::new(dir.path());
        // The principal root is the layout's, and `apply_modes` refuses to widen a
        // root that is not `0711`: the store is built the way the layout builds it.
        let root = layout.store_root().join("p/vault-1").join(ADMIN);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o711)).unwrap();
        (dir, layout)
    }

    #[test]
    fn the_first_publish_writes_the_artifact_at_its_path_with_the_publication_modes() {
        let (_dir, layout) = layout();
        let (_admin_sk, admin_pk) = key_pair(7);
        let (_agent_sk, agent_pk) = key_pair(9);

        let publication = publication::publish(
            &layout,
            &path(),
            request("aa", false, agent_pk, admin_pk),
            || Ok((b"name".to_vec(), b"value".to_vec())),
            |_| None,
        )
        .expect("the first publish succeeds");

        assert_eq!(publication.reference_count(), 1);
        let file = path().file(&layout);
        assert!(file.is_file(), "the artifact is at {}", file.display());
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            PUBLICATION_FILE_MODE
        );
        assert_eq!(
            std::fs::metadata(path().dir(&layout))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            PUBLICATION_DIR_MODE
        );

        // And the agent it names is the one that can open it.
        let (_agent_sk, _) = key_pair(9);
        let (agent_sk, _) = key_pair(9);
        let (name, value) = publication
            .open_for("aa", &agent_sk)
            .expect("the named agent opens its own entry");
        assert_eq!(name, b"name");
        assert_eq!(value, b"value");
    }

    #[test]
    fn a_second_policy_adds_an_entry_and_leaves_the_first_one_openable() {
        let (_dir, layout) = layout();
        let (_admin_sk, admin_pk) = key_pair(7);
        let (agent_sk, agent_pk) = key_pair(9);
        let (_other_sk, other_pk) = key_pair(11);

        let first = publication::publish(
            &layout,
            &path(),
            request("aa", false, agent_pk, admin_pk),
            || Ok((b"name".to_vec(), b"value".to_vec())),
            |_| None,
        )
        .unwrap();
        let first_entry = first.entries();
        let key = first
            .open_with_admin(&[7u8; 32])
            .expect("the admin seal opens");

        // The misfit-B case: a second grant for the same secret version.
        let second = publication::publish(
            &layout,
            &path(),
            request("bb", false, other_pk, admin_pk),
            || panic!("an existing publication must not re-read the record"),
            |publication| publication.open_with_admin(&[7u8; 32]),
        )
        .expect("the second publish extends the artifact");

        assert_eq!(second.reference_count(), 2);
        assert_eq!(
            second.entries()[0],
            first_entry[0],
            "the first policy's entry is untouched"
        );
        assert_eq!(
            second.entries(),
            publication::load(&layout, &path()).unwrap().entries()
        );

        // Both agents open the one artifact, and the content key is the same one.
        let (name, value) = second
            .open_for("aa", &agent_sk)
            .expect("the first agent opens");
        assert_eq!(name, b"name");
        assert_eq!(value, b"value");
        let reopened = second.open_with_admin(&[7u8; 32]).unwrap();
        assert_eq!(
            reopened.as_bytes(),
            key.as_bytes(),
            "the blob was not re-sealed"
        );
    }

    #[test]
    fn publishing_one_policy_twice_changes_nothing_on_disk() {
        let (_dir, layout) = layout();
        let (_admin_sk, admin_pk) = key_pair(7);
        let (_agent_sk, agent_pk) = key_pair(9);
        let request = || {
            publication::publish(
                &layout,
                &path(),
                request("aa", false, agent_pk, admin_pk),
                || Ok((b"name".to_vec(), b"value".to_vec())),
                |publication| publication.open_with_admin(&[7u8; 32]),
            )
        };
        request().expect("the first publish");
        let before = std::fs::read(path().file(&layout)).unwrap();
        let again = request().expect("the second publish is idempotent");
        let after = std::fs::read(path().file(&layout)).unwrap();

        assert_eq!(again.reference_count(), 1, "one policy is one entry");
        assert_eq!(before, after, "a retried publish writes nothing new");
    }

    #[test]
    fn releasing_one_policy_removes_its_entry_and_keeps_the_other_openable() {
        let (_dir, layout) = layout();
        let (_admin_sk, admin_pk) = key_pair(7);
        let (agent_sk, agent_pk) = key_pair(9);
        let (other_sk, other_pk) = key_pair(11);

        for (policy, target) in [("aa", agent_pk), ("bb", other_pk)] {
            publication::publish(
                &layout,
                &path(),
                request(policy, false, target, admin_pk),
                || Ok((b"name".to_vec(), b"value".to_vec())),
                |publication| publication.open_with_admin(&[7u8; 32]),
            )
            .unwrap();
        }

        assert_eq!(
            publication::release(&layout, &path(), "aa").expect("the release succeeds"),
            vec!["bb".to_string()],
            "the release reports which policy still references the publication"
        );
        let remaining = publication::load(&layout, &path()).unwrap();
        assert!(
            remaining.holds("bb"),
            "the surviving policy keeps its entry"
        );
        assert!(
            remaining.open_for("bb", &other_sk).is_some(),
            "the surviving policy still opens the blob"
        );
        assert!(
            remaining.open_for("aa", &agent_sk).is_none(),
            "the released policy has no entry to open"
        );
    }

    #[test]
    fn an_artifact_whose_metadata_is_not_its_paths_is_refused_on_read() {
        use ksp_types::{BoundMetadata, Level};

        let (_dir, layout) = layout();
        let (_admin_sk, admin_pk) = key_pair(7);
        publication::publish(
            &layout,
            &path(),
            request(
                "aa",
                false,
                {
                    let (_sk, pk) = key_pair(9);
                    pk
                },
                admin_pk,
            ),
            || Ok((b"name".to_vec(), b"value".to_vec())),
            |_| None,
        )
        .unwrap();

        // Misfit C at read time: the artifact authenticates another version, so it
        // opens for nobody and must be refused before a read surface trusts it.
        let (mut publication, key) = Publication::fresh(
            BoundMetadata {
                vault_id: VaultId::new("vault-1"),
                user_id: PrincipalId::parse(ADMIN).unwrap(),
                level: Level::Granted,
                secret_id: OpaqueSecretId::new("s1"),
                version: 2,
            },
            b"name",
            b"value",
            &admin_pk,
        )
        .unwrap();
        publication
            .seal_entry("aa", false, &key, &{
                let (_sk, pk) = key_pair(9);
                pk
            })
            .unwrap();
        // Written at the version-1 path on purpose.
        publication::write(&layout, &path(), &publication).unwrap();

        let refused = publication::load(&layout, &path()).unwrap_err();
        assert!(
            matches!(refused, PublicationError::BindingMismatch { .. }),
            "an artifact bound to another version is refused: {refused}"
        );
    }
}
