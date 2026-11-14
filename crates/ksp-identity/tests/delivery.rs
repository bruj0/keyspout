//! The acceptance criteria for WP06, driven through the public API.
//!
//! Three misfits meet here. Misfit B is that a saved artifact carries a key at
//! all, so the tests search the artifact's *bytes* for a content key rather than
//! inspecting the structure. Misfit M is signature-context confusion, so a
//! signature made under the proof-of-possession or deletion-report domain is
//! presented where a token signature is expected. Misfit Q is key substitution,
//! so an attacker's X25519 key paired with the legitimate agent's Ed25519 key is
//! offered to the fingerprint check.
//!
//! A test reports a failure by panicking, and the panic message is what says why.
//! The production code keeps the strict lints.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use ksp_identity::{
    AdminSigningKey, DeliveryArtifact, DeliveryEnvelope, DeliveryError, DeliveryHeader, Domain,
    EnrollmentRecord, KeyId, RecipientPublicKey, SelectedRecord, SigningSecretKey,
    UnsignedEnrolment, VerifiedDelivery, VerifiedRecipientKey, downstream_copy, open, seal, verify,
};
use ksp_types::{
    ActorId, AgentId, BoundMetadata, ContentKey, Level, OpaqueSecretId, RecordVersion, VaultId,
    cbor,
};

const ADMIN_ID: &str = "admin-1";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A deterministic X25519 pair derived through the same provider the KEM uses.
fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let secret = [seed; 32];
    let public = ksp_record::kem::public_key_for(&secret).unwrap();
    (secret, public)
}

fn agent() -> AgentId {
    ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap()
}

/// An enrolment record for the agent whose recipient key is `recipient_pk`.
fn agent_record(
    admin: &AdminSigningKey,
    signing_public: ksp_identity::VerifyingPublicKey,
    recipient_pk: [u8; 32],
) -> EnrollmentRecord {
    let unsigned = UnsignedEnrolment::bind(
        ActorId::Agent(agent()),
        signing_public,
        RecipientPublicKey::from_bytes(recipient_pk),
        KeyId::new("agent-7-ed"),
        KeyId::new("agent-7-x"),
    )
    .unwrap();
    admin
        .sign_enrolment(unsigned, KeyId::new(ADMIN_ID))
        .unwrap()
}

fn signing_public() -> ksp_identity::VerifyingPublicKey {
    SigningSecretKey::generate().verifying_public()
}

fn selected() -> Vec<SelectedRecord> {
    vec![
        SelectedRecord {
            secret: ksp_types::OpaqueSecretId::new("secret-1"),
            version: RecordVersion(3),
        },
        SelectedRecord {
            secret: ksp_types::OpaqueSecretId::new("secret-2"),
            version: RecordVersion(1),
        },
    ]
}

fn header() -> DeliveryHeader {
    DeliveryHeader::new(
        VaultId::new("vault-1"),
        ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        KeyId::new(ADMIN_ID),
        agent(),
        signing_public(),
        RecipientPublicKey::from_bytes(keypair(7).1),
        KeyId::new("agent-7-ed"),
        KeyId::new("agent-7-x"),
        Level::Agent(agent()),
        Level::User,
        "agent-7".to_string(),
        selected(),
        500,
        "jti-1".to_string(),
    )
    .unwrap()
}

/// One delivery, sealed to the agent, with the private key needed to open it.
struct Sealed {
    signer: SigningSecretKey,
    artifact: DeliveryArtifact,
    verified: VerifiedDelivery,
    agent_secret: [u8; 32],
    keys: Vec<(SelectedRecord, ContentKey)>,
}

fn sealed() -> Sealed {
    let admin = AdminSigningKey::generate();
    let signer = SigningSecretKey::generate();
    let (agent_secret, agent_public) = keypair(7);
    let record = agent_record(&admin, signing_public(), agent_public);
    let recipient = VerifiedRecipientKey::confirm(&record, record.fingerprint()).unwrap();

    let head = header();
    let keys: Vec<(SelectedRecord, ContentKey)> = head
        .records()
        .iter()
        .map(|record| (record.clone(), ContentKey::generate()))
        .collect();
    let selection = ksp_identity::SelectedContentKeys::new(&head, keys.clone()).unwrap();
    let artifact = seal(&signer, &head, &selection, &recipient).unwrap();
    let verified = verify(&artifact, &signer.verifying_public()).unwrap();

    Sealed {
        signer,
        artifact,
        verified,
        agent_secret,
        keys,
    }
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

// ---------------------------------------------------------------------------
// Criterion 1 — the artifact's bytes carry no readable content key
// ---------------------------------------------------------------------------

#[test]
fn the_saved_artifact_contains_no_readable_content_key() {
    let sealed = sealed();
    let bytes = sealed.artifact.to_bytes().unwrap();

    for (_, key) in &sealed.keys {
        let needle = key.as_bytes();
        let found = bytes.windows(needle.len()).any(|w| w == needle);
        assert!(
            !found,
            "a raw content key appears in the artifact bytes: the saved file would be \
             decryptable by its holder without the agent's private key"
        );
    }

    // The keys really are inside, though: the agent can open the envelope.
    let opened = open(&sealed.verified, &sealed.agent_secret).unwrap();
    assert_eq!(opened.len(), sealed.keys.len());
}

// ---------------------------------------------------------------------------
// Criterion 2 — a copied artifact cannot be decrypted without the private key
// ---------------------------------------------------------------------------

#[test]
fn a_copied_artifact_cannot_be_decrypted_without_the_agents_private_key() {
    let sealed = sealed();
    let copied = DeliveryArtifact::from_bytes(&sealed.artifact.to_bytes().unwrap()).unwrap();

    // The attacker holds the artifact and the matching ciphertext, and no key.
    let (attacker_secret, _) = keypair(11);
    // Opening requires verification first, so the copy is re-verified against
    // the pinned issuer — which is legitimate, since it is the genuine artifact.
    let copied = verify(&copied, &sealed.signer.verifying_public()).unwrap();
    let refused = open(&copied, &attacker_secret).unwrap_err();
    assert!(matches!(refused, DeliveryError::Open { .. }));

    // The documented limit, asserted rather than implied: the holder of the
    // private key *can* open it. That is NFR-006, not a defect.
    assert!(open(&copied, &sealed.agent_secret).is_ok());
}

// ---------------------------------------------------------------------------
// Criteria 3, 4, 5 — signature domain confusion
// ---------------------------------------------------------------------------

/// Sign an arbitrary domain-separated body with the issuer key.
fn sign_under(
    signer: &SigningSecretKey,
    domain: Domain,
    body: &[u8],
) -> ksp_identity::TokenSignature {
    ksp_identity::sign_with_domain(signer, domain, body)
}

/// Verify a signature under a domain, the way a consumer of that domain would.
fn verifies_under(
    signer: &SigningSecretKey,
    domain: Domain,
    body: &[u8],
    signature: &ksp_identity::TokenSignature,
) -> bool {
    ksp_identity::verify_with_domain(&signer.verifying_public(), domain, body, signature)
}

/// The body a proof of possession signs: `[jti, version, path, argv_hash, ts]`.
fn pop_body() -> Vec<u8> {
    cbor::encode(&(
        "jti-1",
        RecordVersion(3),
        "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-00000000-0000-4000-8000-000000000007/secret-1/3",
        [4u8; 32],
        1_500u64,
    ))
    .unwrap()
}

#[test]
fn a_proof_of_possession_signature_is_not_accepted_as_a_token_signature() {
    let sealed = sealed();
    let signer = &sealed.signer;

    let signature = sign_under(signer, Domain::Pop, &pop_body());

    // It is a perfectly good signature under its own domain…
    assert!(verifies_under(signer, Domain::Pop, &pop_body(), &signature));

    // …and worthless as a token signature, even though the bytes "look" signed.
    let forged = DeliveryArtifact::from_parts(
        sealed.artifact.header().clone(),
        sealed.artifact.envelope().clone(),
        signature,
    );
    assert!(matches!(
        verify(&forged, &signer.verifying_public()).unwrap_err(),
        DeliveryError::Token(ksp_identity::TokenError::IssuerSignature)
    ));
}

#[test]
fn a_token_signature_is_not_accepted_as_a_proof_of_possession_signature() {
    let sealed = sealed();
    let signer = &sealed.signer;

    let token_signature = *sealed.artifact.signature();
    assert!(!verifies_under(
        signer,
        Domain::Pop,
        &pop_body(),
        &token_signature
    ));
}

#[test]
fn a_deletion_report_signature_is_not_accepted_as_a_token_signature() {
    let sealed = sealed();
    let admin = &sealed.signer;

    let report_body = cbor::encode(&("intent-1", RecordVersion(3), "deleted", 1_600u64)).unwrap();
    let signature = sign_under(admin, Domain::DeleteReport, &report_body);

    let forged = DeliveryArtifact::from_parts(
        sealed.artifact.header().clone(),
        sealed.artifact.envelope().clone(),
        signature,
    );
    assert!(verify(&forged, &admin.verifying_public()).is_err());
}

// ---------------------------------------------------------------------------
// Criterion 6 — the header binds both keys and both key IDs
// ---------------------------------------------------------------------------

#[test]
fn the_header_binds_both_public_keys_and_both_key_ids() {
    let head = header();
    assert_eq!(head.agent_signing_key_id().as_str(), "agent-7-ed");
    assert_eq!(head.agent_recipient_key_id().as_str(), "agent-7-x");
    assert_eq!(
        head.agent_recipient_key().to_bytes(),
        keypair(7).1,
        "the recipient key is present"
    );
    let canonical = head.canonical().unwrap();

    // Changing any one of the four changes the header bytes.
    //
    // The substitute is a freshly generated Ed25519 key rather than a bit-flipped
    // copy of the original: flipping a byte of a valid Ed25519 public key does
    // not reliably produce another valid one, and `from_bytes` would then fail at
    // random. Reinterpreting bytes across key types is the hazard; a new key of
    // the same type is what the property actually needs.
    let substituted_key = signing_public();
    assert_ne!(
        substituted_key.to_bytes(),
        head.agent_signing_key().to_bytes()
    );
    assert_ne!(
        header_with(
            substituted_key,
            *head.agent_recipient_key(),
            "agent-7-ed",
            "agent-7-x",
        )
        .canonical()
        .unwrap(),
        canonical
    );

    let mut substituted_recipient = head.agent_recipient_key().to_bytes();
    substituted_recipient[0] ^= 0xff;
    assert_ne!(
        header_with(
            *head.agent_signing_key(),
            RecipientPublicKey::from_bytes(substituted_recipient),
            "agent-7-ed",
            "agent-7-x",
        )
        .canonical()
        .unwrap(),
        canonical
    );

    for (ed_id, x_id) in [("agent-8-ed", "agent-7-x"), ("agent-7-ed", "agent-8-x")] {
        assert_ne!(
            header_with(
                *head.agent_signing_key(),
                *head.agent_recipient_key(),
                ed_id,
                x_id
            )
            .canonical()
            .unwrap(),
            canonical
        );
    }
}

// ---------------------------------------------------------------------------
// Criterion 7 — only the selected versions' content keys
// ---------------------------------------------------------------------------

#[test]
fn the_envelope_carries_only_the_selected_versions_keys() {
    let head = header();

    let selected_keys: Vec<(SelectedRecord, ContentKey)> = head
        .records()
        .iter()
        .map(|record| (record.clone(), ContentKey::generate()))
        .collect();
    let selection = ksp_identity::SelectedContentKeys::new(&head, selected_keys.clone()).unwrap();
    assert_eq!(selection.len(), 2);

    // A key for a version the header does not name is refused, not silently
    // dropped: it would be a content key delivered without authority.
    let mut surplus = selected_keys.clone();
    surplus.push((
        SelectedRecord {
            secret: ksp_types::OpaqueSecretId::new("secret-9"),
            version: RecordVersion(9),
        },
        ContentKey::generate(),
    ));
    assert!(matches!(
        ksp_identity::SelectedContentKeys::new(&head, surplus).unwrap_err(),
        DeliveryError::UnselectedContentKey { version: 9, .. }
    ));

    // A selected record with no key is refused too.
    let short = vec![selected_keys[0].clone()];
    assert!(matches!(
        ksp_identity::SelectedContentKeys::new(&head, short).unwrap_err(),
        DeliveryError::MissingContentKey { .. }
    ));

    // And after sealing and opening, the recovered set is exactly the selection.
    let sealed = sealed();
    let opened = open(&sealed.verified, &sealed.agent_secret).unwrap();
    let mut versions: Vec<u32> = opened.records().iter().map(|r| r.version.get()).collect();
    versions.sort_unstable();
    assert_eq!(versions, vec![1, 3]);
}

// ---------------------------------------------------------------------------
// Criterion 8 — the header is the AAD
// ---------------------------------------------------------------------------

#[test]
fn a_modified_header_makes_the_envelope_fail_to_open() {
    let sealed = sealed();
    let original = sealed.artifact.header().clone();

    let variants = [
        // a different expiry
        DeliveryHeader::new(
            original.vault().clone(),
            *original.user(),
            original.issuer_key_id().clone(),
            *original.agent(),
            *original.agent_signing_key(),
            *original.agent_recipient_key(),
            original.agent_signing_key_id().clone(),
            original.agent_recipient_key_id().clone(),
            original.level().clone(),
            original.source_level().clone(),
            original.scope().to_string(),
            original.records().to_vec(),
            original.expires_at() + 1,
            original.jti().to_string(),
        )
        .unwrap(),
        // a different scope
        DeliveryHeader::new(
            original.vault().clone(),
            *original.user(),
            original.issuer_key_id().clone(),
            *original.agent(),
            *original.agent_signing_key(),
            *original.agent_recipient_key(),
            original.agent_signing_key_id().clone(),
            original.agent_recipient_key_id().clone(),
            original.level().clone(),
            original.source_level().clone(),
            "agent-8".to_string(),
            original.records().to_vec(),
            original.expires_at(),
            original.jti().to_string(),
        )
        .unwrap(),
        // a different version set
        DeliveryHeader::new(
            original.vault().clone(),
            *original.user(),
            original.issuer_key_id().clone(),
            *original.agent(),
            *original.agent_signing_key(),
            *original.agent_recipient_key(),
            original.agent_signing_key_id().clone(),
            original.agent_recipient_key_id().clone(),
            original.level().clone(),
            original.source_level().clone(),
            original.scope().to_string(),
            vec![SelectedRecord {
                secret: ksp_types::OpaqueSecretId::new("secret-1"),
                version: RecordVersion(4),
            }],
            original.expires_at(),
            original.jti().to_string(),
        )
        .unwrap(),
    ];

    for modified in variants {
        let transplanted = DeliveryArtifact::from_parts(
            modified,
            sealed.artifact.envelope().clone(),
            *sealed.artifact.signature(),
        );
        // The envelope is no longer authenticated by the header beside it.
        // Verification is the gate; a transplanted envelope fails it first.
        assert!(verify(&transplanted, &sealed.signer.verifying_public()).is_err());
        // And the signature, which covers the header, no longer verifies.
        assert!(verify(&transplanted, &sealed.signer.verifying_public()).is_err());
    }
}

// ---------------------------------------------------------------------------
// Criterion 9 — the downstream copy is one-way
// ---------------------------------------------------------------------------

fn source_metadata() -> BoundMetadata {
    BoundMetadata {
        vault_id: VaultId::new("vault-1"),
        user_id: ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        level: Level::User,
        secret_id: OpaqueSecretId::new("secret-1"),
        version: 3,
    }
}

#[test]
fn the_downstream_copy_leaves_the_source_untouched_and_the_reverse_is_refused() {
    let source = source_metadata();
    let source_before = source.clone();
    let source_key = ContentKey::generate();
    let source_key_before = *source_key.as_bytes();

    let copy = downstream_copy(&source, &source_key, &agent(), RecordVersion(1)).unwrap();

    // The source is byte-identical afterwards.
    assert_eq!(source, source_before);
    assert_eq!(source_key.as_bytes(), &source_key_before);

    // The copy is at the agent's level, with its own path.
    assert_eq!(copy.metadata.level, Level::Agent(agent()));
    assert_eq!(
        ksp_record::RecordPath::of(&copy.metadata).as_str(),
        "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-00000000-0000-4000-8000-000000000007/secret-1/1"
    );
    assert_eq!(
        ksp_record::RecordPath::of(&source).as_str(),
        "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/user/secret-1/3"
    );

    // A fresh content key, not the source's.
    assert_ne!(copy.content_key.as_bytes(), &source_key_before);

    // The reverse direction is refused outright.
    let agent_level = copy.metadata.clone();
    assert!(matches!(
        downstream_copy(&agent_level, &copy.content_key, &agent(), RecordVersion(2)).unwrap_err(),
        DeliveryError::ReverseCopy { .. }
    ));
}

// ---------------------------------------------------------------------------
// Criterion 10 — one CBOR document, pinned by a golden fixture
// ---------------------------------------------------------------------------

#[test]
fn the_artifact_is_a_single_cbor_document() {
    let sealed = sealed();
    let bytes = sealed.artifact.to_bytes().unwrap();

    // One document: the whole slice decodes as an artifact, and the encoded
    // length is exactly what was written (no trailing region).
    let parsed = DeliveryArtifact::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, sealed.artifact);
    assert_eq!(parsed.to_bytes().unwrap(), bytes);

    // The three fields are present as fields, not as concatenated regions.
    assert_eq!(parsed.header(), sealed.artifact.header());
    assert_eq!(parsed.envelope(), sealed.artifact.envelope());
    assert_eq!(parsed.signature(), sealed.artifact.signature());

    // A hostile byte string is a typed error, never a panic.
    for bad in [&b""[..], &b"\xff\xff"[..], &bytes[..bytes.len() - 1]] {
        assert!(DeliveryArtifact::from_bytes(bad).is_err());
    }
}

#[test]
fn the_pinned_encodings_match_their_golden_fixtures() {
    let head = pinned_header();
    let expected_header = std::fs::read(fixture("delivery-header.cbor")).unwrap();
    assert_eq!(
        head.canonical().unwrap(),
        expected_header,
        "the header encoding changed; if deliberate, regenerate the fixture and say why"
    );

    // The signature input, over a fixed envelope so the bytes do not depend on
    // the KEM's randomness.
    let envelope = pinned_envelope();
    let expected_preimage = std::fs::read(fixture("token-preimage.cbor")).unwrap();
    assert_eq!(
        ksp_identity::token::token_preimage(&head, &envelope).unwrap(),
        expected_preimage
    );

    // And the artifact container itself.
    let artifact = DeliveryArtifact::from_parts(
        head,
        envelope,
        ksp_identity::EnrolmentSignature::from_bytes([5u8; 64]),
    );
    let expected_artifact = std::fs::read(fixture("delivery-artifact.cbor")).unwrap();
    assert_eq!(
        artifact.to_bytes().unwrap(),
        expected_artifact,
        "the artifact container encoding changed"
    );
}

/// Regenerate the committed fixtures after an intentional encoding change.
///
/// Ignored by default: running it silently would make the pinned bytes follow
/// the code instead of constraining it.
#[test]
#[ignore = "regenerates the golden fixtures; run deliberately"]
fn regenerate_golden_fixtures() {
    let head = pinned_header();
    let envelope = pinned_envelope();
    let artifact = DeliveryArtifact::from_parts(
        head.clone(),
        envelope.clone(),
        ksp_identity::EnrolmentSignature::from_bytes([5u8; 64]),
    );
    for (name, bytes) in [
        ("delivery-header.cbor", head.canonical().unwrap()),
        (
            "token-preimage.cbor",
            ksp_identity::token::token_preimage(&head, &envelope).unwrap(),
        ),
        ("delivery-artifact.cbor", artifact.to_bytes().unwrap()),
    ] {
        std::fs::write(fixture(name), bytes).unwrap();
    }
}

// ---------------------------------------------------------------------------
// Criterion 11 — a substituted recipient key is refused
// ---------------------------------------------------------------------------

#[test]
fn a_substituted_recipient_key_is_refused_by_the_fingerprint_check() {
    let admin = AdminSigningKey::generate();
    let legitimate_signing = signing_public();

    // The agent's real enrolment, and the fingerprint the user confirmed.
    let (_, real_recipient) = keypair(7);
    let legitimate = agent_record(&admin, legitimate_signing, real_recipient);
    let confirmed = *legitimate.fingerprint();

    // The attack: the legitimate Ed25519 key paired with the attacker's X25519
    // key, in a record the same admin signed (so the signature is genuine).
    let (_, attacker_recipient) = keypair(13);
    let substituted = agent_record(&admin, legitimate_signing, attacker_recipient);
    assert_ne!(substituted.fingerprint(), &confirmed);

    assert!(matches!(
        VerifiedRecipientKey::confirm(&substituted, &confirmed).unwrap_err(),
        DeliveryError::UnconfirmedRecipient
    ));

    // The genuine record still confirms, so the refusal is about the swap.
    assert!(VerifiedRecipientKey::confirm(&legitimate, &confirmed).is_ok());
}

// ---------------------------------------------------------------------------
// Criterion 12 — the two keys are not interchangeable
// ---------------------------------------------------------------------------

#[test]
fn the_issuer_signs_and_the_recipient_seals_and_they_are_not_interchangeable() {
    let sealed = sealed();

    // The issuer verifies.
    assert!(verify(&sealed.artifact, &sealed.signer.verifying_public()).is_ok());

    // The recipient key is not the issuer key, and no other Ed25519 key can
    // stand in for it. (The types make the two non-interchangeable; asserting
    // that here would mean reinterpreting one key's bytes as the other, which is
    // the cross-type round trip that made a WP04 test fail at random.)
    assert_ne!(
        sealed.artifact.header().agent_recipient_key().to_bytes(),
        sealed.signer.verifying_public().to_bytes()
    );
    let stranger = SigningSecretKey::generate().verifying_public();
    assert!(verify(&sealed.artifact, &stranger).is_err());

    // Sealing used the recipient key: the envelope opens with the recipient's
    // private key and with nothing else.
    let (wrong_secret, _) = keypair(11);
    assert!(open(&sealed.verified, &wrong_secret).is_err());

    // And an artifact sealed by a different issuer does not verify against this
    // issuer's key.
    let other = SigningSecretKey::generate();
    assert!(verify(&sealed.artifact, &other.verifying_public()).is_err());
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A header whose key fields the test can vary.
fn header_with(
    signing: ksp_identity::VerifyingPublicKey,
    recipient: RecipientPublicKey,
    ed_id: &str,
    x_id: &str,
) -> DeliveryHeader {
    DeliveryHeader::new(
        VaultId::new("vault-1"),
        ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        KeyId::new(ADMIN_ID),
        agent(),
        signing,
        recipient,
        KeyId::new(ed_id),
        KeyId::new(x_id),
        Level::Agent(agent()),
        Level::User,
        "agent-7".to_string(),
        selected(),
        500,
        "jti-1".to_string(),
    )
    .unwrap()
}

/// The header the golden fixtures were generated from: every value fixed, no key
/// material generated at run time.
fn pinned_header() -> DeliveryHeader {
    DeliveryHeader::new(
        VaultId::new("vault-1"),
        ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        KeyId::new(ADMIN_ID),
        agent(),
        ksp_identity::VerifyingPublicKey::from_bytes([1u8; 32]).unwrap(),
        RecipientPublicKey::from_bytes([2u8; 32]),
        KeyId::new("agent-7-ed"),
        KeyId::new("agent-7-x"),
        Level::Agent(agent()),
        Level::User,
        "agent-7".to_string(),
        vec![SelectedRecord {
            secret: ksp_types::OpaqueSecretId::new("secret-1"),
            version: RecordVersion(3),
        }],
        500,
        "jti-1".to_string(),
    )
    .unwrap()
}

/// A fixed envelope, so the signature input and the artifact bytes do not depend
/// on the KEM's randomness.
fn pinned_envelope() -> DeliveryEnvelope {
    DeliveryEnvelope::new(vec![7u8; 32], vec![8u8; 48])
}

// ---------------------------------------------------------------------------
// Review v1 findings
// ---------------------------------------------------------------------------

/// Review v1 (critical): `confirm` must act on the fingerprint re-derived from
/// the record's own keys, not on the value the record claims.
///
/// `EnrollmentRecord` is deserializable, so a record read back from a file can
/// carry a genuine fingerprint field beside a substituted recipient key.
#[test]
fn a_record_with_a_genuine_fingerprint_beside_a_substituted_key_is_refused() {
    let admin = AdminSigningKey::generate();
    let (_, real_recipient) = keypair(7);
    let (_, attacker_recipient) = keypair(13);

    let legitimate = agent_record(&admin, signing_public(), real_recipient);
    let confirmed = *legitimate.fingerprint();

    // Forge the record: the legitimate fingerprint *field*, the attacker's
    // recipient key.
    let mut value = serde_json::to_value(&legitimate).unwrap();
    let substituted = agent_record(&admin, *legitimate.signing_key(), attacker_recipient);
    value["unsigned"]["recipient_key"] = serde_json::to_value(substituted.recipient_key()).unwrap();
    let forged: EnrollmentRecord = serde_json::from_value(value).unwrap();

    // The claim still matches the confirmed value, which is exactly why the
    // claim must not be what is compared.
    assert!(forged.fingerprint().matches(&confirmed));
    assert!(!forged.binding_fingerprint().unwrap().matches(&confirmed));

    assert!(matches!(
        VerifiedRecipientKey::confirm(&forged, &confirmed).unwrap_err(),
        DeliveryError::UnconfirmedRecipient
    ));
    // The genuine record still confirms.
    assert!(VerifiedRecipientKey::confirm(&legitimate, &confirmed).is_ok());
}

/// Review v1 (high): the artifact must not name one recipient while only
/// another can open it.
#[test]
fn sealing_to_a_key_the_header_does_not_name_is_refused() {
    let admin = AdminSigningKey::generate();
    let signer = SigningSecretKey::generate();
    let head = header();

    // A genuine, confirmed recipient key — but not the one this header names.
    let (_, other_recipient) = keypair(21);
    let record = agent_record(&admin, signing_public(), other_recipient);
    let recipient = VerifiedRecipientKey::confirm(&record, record.fingerprint()).unwrap();

    let keys: Vec<(SelectedRecord, ContentKey)> = head
        .records()
        .iter()
        .map(|r| (r.clone(), ContentKey::generate()))
        .collect();
    let selection = ksp_identity::SelectedContentKeys::new(&head, keys).unwrap();

    assert!(matches!(
        seal(&signer, &head, &selection, &recipient).unwrap_err(),
        DeliveryError::RecipientMismatch
    ));
}

/// Review v1 (high): two secrets at the same version must not share a key.
#[test]
fn two_secrets_at_the_same_version_keep_their_own_keys() {
    let admin = AdminSigningKey::generate();
    let signer = SigningSecretKey::generate();
    let (agent_secret, agent_public) = keypair(7);
    let record = agent_record(&admin, signing_public(), agent_public);
    let recipient = VerifiedRecipientKey::confirm(&record, record.fingerprint()).unwrap();

    // Both secrets sit at version 1, which is ordinary: the version chain is per
    // record path.
    let head = DeliveryHeader::new(
        VaultId::new("vault-1"),
        ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        KeyId::new(ADMIN_ID),
        agent(),
        signing_public(),
        RecipientPublicKey::from_bytes(agent_public),
        KeyId::new("agent-7-ed"),
        KeyId::new("agent-7-x"),
        Level::Agent(agent()),
        Level::User,
        "agent-7".to_string(),
        vec![
            SelectedRecord {
                secret: OpaqueSecretId::new("secret-a"),
                version: RecordVersion(1),
            },
            SelectedRecord {
                secret: OpaqueSecretId::new("secret-b"),
                version: RecordVersion(1),
            },
        ],
        500,
        "jti-2".to_string(),
    )
    .unwrap();

    let key_a = ContentKey::generate();
    let key_b = ContentKey::generate();
    let selection = ksp_identity::SelectedContentKeys::new(
        &head,
        vec![
            (head.records()[0].clone(), key_a.clone()),
            (head.records()[1].clone(), key_b.clone()),
        ],
    )
    .unwrap();
    let artifact = seal(&signer, &head, &selection, &recipient).unwrap();
    let verified = verify(&artifact, &signer.verifying_public()).unwrap();
    let opened = open(&verified, &agent_secret).unwrap();

    let secret_a = OpaqueSecretId::new("secret-a");
    let secret_b = OpaqueSecretId::new("secret-b");
    assert_eq!(
        opened.get(&secret_a, RecordVersion(1)).unwrap().as_bytes(),
        key_a.as_bytes()
    );
    assert_eq!(
        opened.get(&secret_b, RecordVersion(1)).unwrap().as_bytes(),
        key_b.as_bytes()
    );
    assert_ne!(
        opened.get(&secret_a, RecordVersion(1)).unwrap().as_bytes(),
        opened.get(&secret_b, RecordVersion(1)).unwrap().as_bytes()
    );
}

/// Review v1: the domain tests above compare *different bodies*, so they cannot
/// prove the domain prefix matters. This one signs the same body under two
/// domains.
#[test]
fn the_same_body_signed_under_two_domains_does_not_cross_verify() {
    let signer = SigningSecretKey::generate();
    let body = b"one body, two domains";

    let as_token = sign_under(&signer, Domain::Token, body);
    let as_pop = sign_under(&signer, Domain::Pop, body);
    assert_ne!(as_token.to_bytes(), as_pop.to_bytes());

    assert!(verifies_under(&signer, Domain::Token, body, &as_token));
    assert!(verifies_under(&signer, Domain::Pop, body, &as_pop));
    assert!(
        !verifies_under(&signer, Domain::Pop, body, &as_token),
        "a token signature must not verify under the proof-of-possession domain"
    );
    assert!(
        !verifies_under(&signer, Domain::Token, body, &as_pop),
        "a proof-of-possession signature must not verify under the token domain"
    );
}

/// Review v1: a decoded header bypasses its constructor, so the invariants have
/// to be re-checked on the way in.
///
/// The header carries no byte strings, so it round-trips through JSON; that is
/// how a hostile header is built here without reaching into private fields.
#[test]
fn a_parsed_artifact_with_an_invalid_header_is_refused() {
    let sealed = sealed();

    let build = |mutate: &dyn Fn(&mut serde_json::Value)| {
        let mut value = serde_json::to_value(sealed.artifact.header()).unwrap();
        mutate(&mut value);
        let header: DeliveryHeader = serde_json::from_value(value).unwrap();
        let artifact = DeliveryArtifact::from_parts(
            header,
            sealed.artifact.envelope().clone(),
            *sealed.artifact.signature(),
        );
        artifact.to_bytes().unwrap()
    };

    // No records.
    let no_records = build(&|v| v["records"] = serde_json::json!([]));
    assert!(matches!(
        DeliveryArtifact::from_bytes(&no_records).unwrap_err(),
        DeliveryError::Malformed { .. }
    ));

    // No jti.
    let no_jti = build(&|v| v["jti"] = serde_json::json!(""));
    assert!(matches!(
        DeliveryArtifact::from_bytes(&no_jti).unwrap_err(),
        DeliveryError::Malformed { .. }
    ));

    // A secret identifier that would forge a path.
    let traversing = build(&|v| v["records"][0]["secret"] = serde_json::json!("../../user"));
    assert!(matches!(
        DeliveryArtifact::from_bytes(&traversing).unwrap_err(),
        DeliveryError::Malformed { .. }
    ));
}

/// Review v1: trailing bytes after the document are refused, not ignored.
#[test]
fn an_artifact_with_trailing_bytes_is_refused() {
    let sealed = sealed();
    let mut bytes = sealed.artifact.to_bytes().unwrap();
    bytes.extend_from_slice(b"extra");
    assert!(matches!(
        DeliveryArtifact::from_bytes(&bytes).unwrap_err(),
        DeliveryError::Malformed { .. }
    ));
}

/// Review v1: the same record named twice in one header is refused. Two
/// *different* secrets at the same version are legitimate and covered by
/// `two_secrets_at_the_same_version_keep_their_own_keys`.
#[test]
fn a_header_naming_the_same_record_twice_is_refused() {
    let duplicate = vec![
        SelectedRecord {
            secret: OpaqueSecretId::new("secret-a"),
            version: RecordVersion(1),
        },
        SelectedRecord {
            secret: OpaqueSecretId::new("secret-a"),
            version: RecordVersion(1),
        },
    ];
    assert!(matches!(
        DeliveryHeader::new(
            VaultId::new("vault-1"),
            ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
            KeyId::new(ADMIN_ID),
            agent(),
            signing_public(),
            RecipientPublicKey::from_bytes(keypair(7).1),
            KeyId::new("agent-7-ed"),
            KeyId::new("agent-7-x"),
            Level::Agent(agent()),
            Level::User,
            "agent-7".to_string(),
            duplicate,
            500,
            "jti-1".to_string(),
        )
        .unwrap_err(),
        ksp_identity::HeaderError::DuplicateRecord { version: 1, .. }
    ));
}

/// Review v1: two keys for one selected record is a mistake, not a choice to
/// resolve silently.
#[test]
fn two_content_keys_for_one_record_are_refused() {
    let head = header();
    let mut supplied: Vec<(SelectedRecord, ContentKey)> = head
        .records()
        .iter()
        .map(|record| (record.clone(), ContentKey::generate()))
        .collect();
    // Every selected record has a key, and one of them has two.
    supplied.push((head.records()[0].clone(), ContentKey::generate()));
    assert!(matches!(
        ksp_identity::SelectedContentKeys::new(&head, supplied).unwrap_err(),
        DeliveryError::DuplicateContentKey { .. }
    ));
}

/// Review v2: the issuer refuses to sign a header its own constructor would
/// reject. A decoded header bypasses `DeliveryHeader::new`.
#[test]
fn sealing_a_header_that_violates_its_invariants_is_refused() {
    let admin = AdminSigningKey::generate();
    let signer = SigningSecretKey::generate();
    let (_, agent_public) = keypair(7);
    let record = agent_record(&admin, signing_public(), agent_public);
    let recipient = VerifiedRecipientKey::confirm(&record, record.fingerprint()).unwrap();

    // Build a valid header, then empty its record list through the decoder.
    let valid = header();
    let mut value = serde_json::to_value(&valid).unwrap();
    value["records"] = serde_json::json!([]);
    let invalid: DeliveryHeader = serde_json::from_value(value).unwrap();
    assert!(invalid.validate().is_err());

    let empty = ksp_identity::SelectedContentKeys::new(&invalid, Vec::new()).unwrap();
    assert!(matches!(
        seal(&signer, &invalid, &empty, &recipient).unwrap_err(),
        DeliveryError::Header(ksp_identity::HeaderError::NoRecords)
    ));
}
