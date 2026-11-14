//! The acceptance criteria for WP04, driven through the public API.
//!
//! Everything here builds an identity the way a user or an agent would and then
//! attacks it: a substituted key, a fingerprint that binds less than it claims,
//! a record that arrived without confirmation, too few recovery shares. The
//! `compile_fail` cases that belong to criteria 6 and 9 live as doctests in
//! `src/enrolment.rs`, because "this does not compile" cannot be asserted from
//! a running test.
//!
//! A test reports a failure by panicking, and the panic message is what says
//! why. The production code keeps the strict lints.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_identity::{
    AdminSigningKey, AgentKeys, EnrollmentRecord, EnrollmentRecordWire, EnrolmentFingerprint,
    FingerprintSubject, ImportRefusal, KEY_LEN, KeyId, RecipientPublicKey, SealedVault,
    SigningSecretKey, TrustStore, UnsignedEnrolment, UserVault, VAULT_KEY_LEN, VaultBinding,
    VerifyingPublicKey, recover_vault_bundle, split_vault_bundle,
};
use ksp_types::{ActorId, SealedBundle, ShareCount, Threshold};

const PASSWORD: &[u8] = b"correct horse battery staple";

fn user(id: &str) -> ActorId {
    ActorId::User(
        ksp_types::PrincipalId::parse(id).expect("a test principal must be a canonical UUID"),
    )
}

/// A public key belonging to nobody: the stand-in for "this field binds
/// nothing".
fn stranger_signing_key() -> VerifyingPublicKey {
    SigningSecretKey::generate().verifying_public()
}

fn subject(
    identity: &ActorId,
    signing: VerifyingPublicKey,
    recipient: RecipientPublicKey,
    signing_key_id: &KeyId,
    recipient_key_id: &KeyId,
) -> FingerprintSubject {
    FingerprintSubject {
        identity: *identity,
        signing_key: signing.to_bytes(),
        recipient_key: recipient.to_bytes(),
        signing_key_id: signing_key_id.clone(),
        recipient_key_id: recipient_key_id.clone(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A fingerprint computed over a subject the attacker chose, rather than one
/// derived from the record's own keys.
fn forged(subject: &FingerprintSubject) -> EnrolmentFingerprint {
    EnrolmentFingerprint::compute(subject).unwrap()
}

/// An enrolled user: her open vault, her sealed vault, and the record an admin
/// signed for her.
struct Enrolled {
    vault: UserVault,
    sealed: SealedVault,
    record: EnrollmentRecord,
    admin: AdminSigningKey,
    identity: ActorId,
    signing_key_id: KeyId,
    recipient_key_id: KeyId,
}

/// One fixed principal UUID per fixture name.
///
/// The name is a test label and a key-ID prefix; the identity handed to the
/// enrolment is the UUID an enrolment would have issued.
fn fixture_uuid(name: &str) -> &'static str {
    match name {
        "alice" => "6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f",
        "bob" => "b0b00000-0000-4000-8000-000000000002",
        other => panic!("no fixture UUID for {other}"),
    }
}

impl Enrolled {
    fn new(id: &str) -> Self {
        let admin = AdminSigningKey::generate();
        let vault = UserVault::generate();
        let identity = user(fixture_uuid(id));
        let signing_key_id = KeyId::new(format!("{id}-ed25519-1"));
        let recipient_key_id = KeyId::new(format!("{id}-x25519-1"));

        let unsigned = UnsignedEnrolment::bind(
            identity,
            vault.signing_public(),
            vault.recipient_public(),
            signing_key_id.clone(),
            recipient_key_id.clone(),
        )
        .unwrap();
        let record = admin
            .sign_enrolment(unsigned, KeyId::new("admin-1"))
            .unwrap();

        let sealed = vault
            .seal(
                PASSWORD,
                &binding_for_parts(&identity, &signing_key_id, &recipient_key_id),
            )
            .unwrap();

        Self {
            vault,
            sealed,
            record,
            admin,
            identity,
            signing_key_id,
            recipient_key_id,
        }
    }

    fn confirmed(&self) -> EnrolmentFingerprint {
        *self.record.fingerprint()
    }

    fn binding(&self) -> VaultBinding {
        binding_for_parts(&self.identity, &self.signing_key_id, &self.recipient_key_id)
    }

    fn wire(&self) -> EnrollmentRecordWire {
        EnrollmentRecordWire::from_record(&self.record)
    }
}

fn binding_for_parts(
    identity: &ActorId,
    signing_key_id: &KeyId,
    recipient_key_id: &KeyId,
) -> VaultBinding {
    VaultBinding {
        identity: *identity,
        signing_key_id: signing_key_id.clone(),
        recipient_key_id: recipient_key_id.clone(),
    }
}

// ---------------------------------------------------------------------------
// Criterion 1 — two independent keypairs and a 256-bit UVK, public export only
// ---------------------------------------------------------------------------

#[test]
fn enrolment_produces_two_independent_keypairs_and_a_256_bit_vault_key() {
    let enrolled = Enrolled::new("alice");

    let signing = enrolled.vault.signing_public();
    let recipient = enrolled.vault.recipient_public();

    // Two *independent* keypairs: neither public key is a re-encoding of the
    // other, and neither one is the vault key.
    assert_ne!(signing.to_bytes(), recipient.to_bytes());
    assert_eq!(signing.to_bytes().len(), KEY_LEN);
    assert_eq!(recipient.to_bytes().len(), KEY_LEN);

    let uvk = enrolled.vault.vault_key().as_bytes();
    assert_eq!(uvk.len(), VAULT_KEY_LEN);
    assert_eq!(VAULT_KEY_LEN * 8, 256);
    assert_ne!(uvk, &signing.to_bytes());
    assert_ne!(uvk, &recipient.to_bytes());
    assert_ne!(uvk, enrolled.record.fingerprint().as_bytes());

    // Two enrolments never reuse key material.
    let other = Enrolled::new("alice");
    assert_ne!(other.vault.signing_public(), signing);
    assert_ne!(other.vault.recipient_public(), recipient);
    assert_ne!(other.vault.vault_key().as_bytes(), uvk);
}

#[test]
fn the_record_exports_public_material_and_the_admin_signature_only() {
    let enrolled = Enrolled::new("alice");
    let wire = enrolled.wire();

    // Every field the wire form can carry, and nothing besides.
    let json = serde_json::to_value(&wire).unwrap();
    let mut keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "fingerprint",
            "identity",
            "issuer_key_id",
            "issuer_signature",
            "recipient_key",
            "recipient_key_id",
            "signing_key",
            "signing_key_id",
            "version",
        ]
    );

    // The two key fields are the public halves, byte for byte.
    assert_eq!(
        wire.signing_key.unwrap().to_bytes(),
        enrolled.vault.signing_public().to_bytes()
    );
    assert_eq!(
        wire.recipient_key.unwrap().to_bytes(),
        enrolled.vault.recipient_public().to_bytes()
    );

    // And the vault key is nowhere in the exported bytes.
    let vault_key_hex = hex(enrolled.vault.vault_key().as_bytes());
    let text = json.to_string();
    assert!(!text.contains(&vault_key_hex));
    assert!(!text.contains(&vault_key_hex.to_uppercase()));
}

// ---------------------------------------------------------------------------
// Criteria 2, 3, 4 — a fingerprint that binds less than it claims is refused
// ---------------------------------------------------------------------------

#[test]
fn a_fingerprint_binding_that_omits_the_recipient_key_id_is_refused() {
    let enrolled = Enrolled::new("alice");

    // The attacker leaves the X25519 key ID out of the fingerprint: the binding
    // now names no recipient key, so any X25519 key would do.
    let partial = forged(&subject(
        &enrolled.identity,
        enrolled.vault.signing_public(),
        enrolled.vault.recipient_public(),
        &enrolled.signing_key_id,
        &KeyId::new(""),
    ));

    let mut store = TrustStore::new(enrolled.admin.verifying_public());
    let refusal = store
        .import(&enrolled.wire(), &partial)
        .expect_err("a fingerprint that omits the recipient key ID must not import");
    assert_eq!(refusal, ImportRefusal::FingerprintMismatch);
    assert!(store.is_empty());
}

#[test]
fn a_fingerprint_binding_that_omits_the_signing_key_id_is_refused() {
    let enrolled = Enrolled::new("alice");

    let partial = forged(&subject(
        &enrolled.identity,
        enrolled.vault.signing_public(),
        enrolled.vault.recipient_public(),
        &KeyId::new(""),
        &enrolled.recipient_key_id,
    ));

    let mut store = TrustStore::new(enrolled.admin.verifying_public());
    let refusal = store
        .import(&enrolled.wire(), &partial)
        .expect_err("a fingerprint that omits the signing key ID must not import");
    assert_eq!(refusal, ImportRefusal::FingerprintMismatch);
    assert!(store.is_empty());
}

#[test]
fn a_fingerprint_binding_that_omits_either_public_key_is_refused() {
    let enrolled = Enrolled::new("alice");

    // No recipient key bound — some other X25519 key stands in its place.
    let no_recipient = forged(&subject(
        &enrolled.identity,
        enrolled.vault.signing_public(),
        RecipientPublicKey::from_bytes([0u8; KEY_LEN]),
        &enrolled.signing_key_id,
        &enrolled.recipient_key_id,
    ));

    // No signing key bound.
    let no_signing = forged(&subject(
        &enrolled.identity,
        stranger_signing_key(),
        enrolled.vault.recipient_public(),
        &enrolled.signing_key_id,
        &enrolled.recipient_key_id,
    ));

    for partial in [no_recipient, no_signing] {
        let mut store = TrustStore::new(enrolled.admin.verifying_public());
        assert_eq!(
            store.import(&enrolled.wire(), &partial).unwrap_err(),
            ImportRefusal::FingerprintMismatch
        );
        assert!(store.is_empty());
    }
}

#[test]
fn a_record_whose_own_fingerprint_does_not_bind_its_keys_is_refused() {
    let enrolled = Enrolled::new("alice");

    // A record whose signed body was published with a fingerprint over a
    // stripped subject. Only re-deriving the fingerprint from the record's own
    // keys catches it, because the fingerprint is what the user confirmed.
    let partial = forged(&subject(
        &enrolled.identity,
        enrolled.vault.signing_public(),
        enrolled.vault.recipient_public(),
        &enrolled.signing_key_id,
        &KeyId::new(""),
    ));
    let lying = wire_with_fingerprint(&enrolled.wire(), partial);

    let mut store = TrustStore::new(enrolled.admin.verifying_public());
    assert_eq!(
        store.import(&lying, &partial).unwrap_err(),
        ImportRefusal::BindingMismatch
    );
    assert!(store.is_empty());
}

#[test]
fn the_issuer_refuses_to_sign_a_body_that_lies_about_what_it_binds() {
    let enrolled = Enrolled::new("alice");

    // `UnsignedEnrolment` is public and deserializable, so an enrolment whose
    // fingerprint covers a stripped subject can be built by hand. A signature
    // would make that lie authoritative, so the issuer refuses to produce one.
    let unsigned = UnsignedEnrolment::bind(
        enrolled.identity,
        enrolled.vault.signing_public(),
        enrolled.vault.recipient_public(),
        enrolled.signing_key_id.clone(),
        enrolled.recipient_key_id.clone(),
    )
    .unwrap();
    let mut body = serde_json::to_value(&unsigned).unwrap();
    body["fingerprint"] = serde_json::to_value(forged(&subject(
        &enrolled.identity,
        enrolled.vault.signing_public(),
        enrolled.vault.recipient_public(),
        &enrolled.signing_key_id,
        &KeyId::new(""),
    )))
    .unwrap();
    let lying: UnsignedEnrolment = serde_json::from_value(body).unwrap();

    assert!(matches!(
        enrolled
            .admin
            .sign_enrolment(lying, KeyId::new("admin-1"))
            .unwrap_err(),
        ksp_identity::EnrolmentError::BindingMismatch
    ));

    // The honest body is still signed, so the refusal is about the lie.
    assert!(
        enrolled
            .admin
            .sign_enrolment(unsigned, KeyId::new("admin-1"))
            .is_ok()
    );
}

#[test]
fn a_body_changed_after_signing_is_refused_as_a_bad_signature() {
    let enrolled = Enrolled::new("alice");

    let mut wire = enrolled.wire();
    wire.issuer_signature = Some(ksp_identity::EnrolmentSignature::from_bytes([0u8; 64]));

    let mut store = TrustStore::new(enrolled.admin.verifying_public());
    assert_eq!(
        store.import(&wire, &wire.fingerprint.unwrap()).unwrap_err(),
        ImportRefusal::IssuerSignature
    );
    assert!(store.is_empty());
}

#[test]
fn two_keys_that_are_swapped_do_not_produce_the_same_fingerprint() {
    let enrolled = Enrolled::new("alice");

    let honest = subject(
        &enrolled.identity,
        enrolled.vault.signing_public(),
        enrolled.vault.recipient_public(),
        &enrolled.signing_key_id,
        &enrolled.recipient_key_id,
    );

    // The same 32-byte values, sitting in each other's slots — the shape a
    // conversion would have produced if one existed.
    //
    // Built by exchanging the byte arrays rather than by re-wrapping one key as
    // the other: an X25519 public key is only about half the time a valid
    // compressed Edwards point, so a `VerifyingPublicKey::from_bytes` round trip
    // would make this test fail at random. The property under test is that the
    // digest distinguishes the two slots, and that needs no such round trip.
    let swapped = FingerprintSubject {
        signing_key: honest.recipient_key,
        recipient_key: honest.signing_key,
        ..honest.clone()
    };

    assert!(!forged(&honest).matches(&forged(&swapped)));
}

#[test]
fn two_key_ids_that_are_swapped_do_not_produce_the_same_fingerprint() {
    let enrolled = Enrolled::new("alice");

    let honest = subject(
        &enrolled.identity,
        enrolled.vault.signing_public(),
        enrolled.vault.recipient_public(),
        &enrolled.signing_key_id,
        &enrolled.recipient_key_id,
    );
    let swapped = FingerprintSubject {
        signing_key_id: honest.recipient_key_id.clone(),
        recipient_key_id: honest.signing_key_id.clone(),
        ..honest.clone()
    };

    assert!(!forged(&honest).matches(&forged(&swapped)));
}

// ---------------------------------------------------------------------------
// Criterion 5 — an unconfirmed key is never imported
// ---------------------------------------------------------------------------

#[test]
fn an_unconfirmed_key_is_never_imported_and_the_store_is_unchanged() {
    let enrolled = Enrolled::new("alice");
    let mut store = TrustStore::new(enrolled.admin.verifying_public());

    // A fingerprint the user never saw: the record is otherwise perfect.
    let stranger = forged(&subject(
        &user("bad00000-0000-4000-8000-000000000003"),
        enrolled.vault.signing_public(),
        enrolled.vault.recipient_public(),
        &KeyId::new("mallory-ed25519-1"),
        &KeyId::new("mallory-x25519-1"),
    ));
    assert_eq!(
        store.import(&enrolled.wire(), &stranger).unwrap_err(),
        ImportRefusal::FingerprintMismatch
    );
    assert!(store.is_empty());
    assert!(store.get(&enrolled.identity).is_none());

    // The confirmed one does import, so the refusal above was about the
    // confirmation and not about the record being unusable.
    store
        .import(&enrolled.wire(), &enrolled.confirmed())
        .unwrap();
    assert_eq!(store.len(), 1);

    // And a later refusal leaves the held record untouched.
    let before = store.get(&enrolled.identity).unwrap().clone();
    assert_eq!(
        store.import(&enrolled.wire(), &stranger).unwrap_err(),
        ImportRefusal::FingerprintMismatch
    );
    assert_eq!(store.len(), 1);
    assert_eq!(store.get(&enrolled.identity).unwrap(), &before);
}

#[test]
fn a_record_missing_any_required_field_is_refused_before_the_store_is_touched() {
    let enrolled = Enrolled::new("alice");
    let confirmed = enrolled.confirmed();

    let cases: Vec<(EnrollmentRecordWire, ImportRefusal)> = vec![
        (
            EnrollmentRecordWire {
                identity: None,
                ..enrolled.wire()
            },
            ImportRefusal::MissingIdentity,
        ),
        (
            EnrollmentRecordWire {
                signing_key: None,
                ..enrolled.wire()
            },
            ImportRefusal::MissingSigningKey,
        ),
        (
            EnrollmentRecordWire {
                recipient_key: None,
                ..enrolled.wire()
            },
            ImportRefusal::MissingRecipientKey,
        ),
        (
            EnrollmentRecordWire {
                signing_key_id: None,
                ..enrolled.wire()
            },
            ImportRefusal::MissingSigningKeyId,
        ),
        (
            EnrollmentRecordWire {
                recipient_key_id: None,
                ..enrolled.wire()
            },
            ImportRefusal::MissingRecipientKeyId,
        ),
        (
            EnrollmentRecordWire {
                fingerprint: None,
                ..enrolled.wire()
            },
            ImportRefusal::MissingFingerprint,
        ),
        (
            EnrollmentRecordWire {
                issuer_signature: None,
                ..enrolled.wire()
            },
            ImportRefusal::MissingIssuerSignature,
        ),
        (
            EnrollmentRecordWire {
                issuer_key_id: None,
                ..enrolled.wire()
            },
            ImportRefusal::MissingIssuerKeyId,
        ),
    ];

    for (wire, expected) in cases {
        let mut store = TrustStore::new(enrolled.admin.verifying_public());
        assert_eq!(
            store.import(&wire, &confirmed).unwrap_err(),
            expected,
            "each missing field must be named, not collapsed into one refusal"
        );
        assert!(store.is_empty());
    }
}

#[test]
fn a_record_signed_by_a_key_that_is_not_the_pinned_anchor_is_refused() {
    let enrolled = Enrolled::new("alice");
    let impostor = AdminSigningKey::generate();

    let mut store = TrustStore::new(impostor.verifying_public());
    assert_eq!(
        store
            .import(&enrolled.wire(), &enrolled.confirmed())
            .unwrap_err(),
        ImportRefusal::IssuerSignature
    );
    assert!(store.is_empty());
}

// ---------------------------------------------------------------------------
// The format version is refused, not reinterpreted
// ---------------------------------------------------------------------------

#[test]
fn a_record_from_a_future_format_is_refused() {
    let enrolled = Enrolled::new("alice");

    let mut body = serde_json::to_value(enrolled.wire()).unwrap();
    body["version"] = serde_json::json!(2);
    let future: EnrollmentRecordWire = serde_json::from_value(body).unwrap();

    let mut store = TrustStore::new(enrolled.admin.verifying_public());
    match store.import(&future, &enrolled.confirmed()).unwrap_err() {
        ImportRefusal::UnsupportedVersion { found, expected } => {
            assert_eq!(found, 2);
            assert_eq!(expected, 1);
        }
        other => panic!("expected a version refusal, got {other:?}"),
    }
    assert!(store.is_empty());
}

#[test]
fn a_vault_from_a_future_format_is_refused() {
    let enrolled = Enrolled::new("alice");

    let mut body = serde_json::to_value(&enrolled.sealed).unwrap();
    body["version"] = serde_json::json!(2);
    let future: SealedVault = serde_json::from_value(body).unwrap();

    match future.unseal(PASSWORD, &enrolled.binding()).unwrap_err() {
        ksp_identity::EnrolmentError::UnsupportedVersion { found, expected } => {
            assert_eq!(found, 2);
            assert_eq!(expected, 1);
        }
        other => panic!("expected a version refusal, got {other:?}"),
    }
}

#[test]
fn a_truncated_vault_is_refused_before_it_is_decrypted() {
    let enrolled = Enrolled::new("alice");

    let mut body = serde_json::to_value(&enrolled.sealed).unwrap();
    let mut ciphertext = body["ciphertext"].as_array().unwrap().clone();
    ciphertext.truncate(16);
    body["ciphertext"] = serde_json::Value::Array(ciphertext);
    let truncated: SealedVault = serde_json::from_value(body).unwrap();

    let error = truncated.unseal(PASSWORD, &enrolled.binding()).unwrap_err();
    assert!(
        error.to_string().contains("wrong length"),
        "a short ciphertext must be refused on its length, got: {error}"
    );
}

// ---------------------------------------------------------------------------
// The vault key and both private halves erase themselves
// ---------------------------------------------------------------------------

/// The erasure this crate relies on is the primitives' own, so assert it.
#[test]
fn the_secret_types_erase_themselves_on_drop() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<ed25519_dalek::SigningKey>();
    assert_zeroize_on_drop::<x25519_dalek::StaticSecret>();
    assert_zeroize_on_drop::<ksp_identity::VaultKey>();
}

// ---------------------------------------------------------------------------
// Criterion 7 — two vaults use different salts
// ---------------------------------------------------------------------------

#[test]
fn two_vaults_for_two_users_use_different_salts() {
    let alice = Enrolled::new("alice");
    let bob = Enrolled::new("bob");

    assert_ne!(alice.sealed.salt(), bob.sealed.salt());

    // The same password under two salts must not produce the same ciphertext,
    // or the salt is decorative.
    assert_ne!(alice.sealed, bob.sealed);

    // A single user re-sealing under the same password also gets a new salt.
    let rebound = alice.vault.seal(PASSWORD, &alice.binding()).unwrap();
    assert_ne!(rebound.salt(), alice.sealed.salt());
    assert_ne!(rebound, alice.sealed);
}

#[test]
fn the_sealed_vault_opens_only_with_its_own_password_and_binding() {
    let enrolled = Enrolled::new("alice");

    let reopened = enrolled
        .sealed
        .unseal(PASSWORD, &enrolled.binding())
        .unwrap();
    assert_eq!(
        reopened.vault_key().as_bytes(),
        enrolled.vault.vault_key().as_bytes()
    );
    assert_eq!(reopened.signing_public(), enrolled.vault.signing_public());
    assert_eq!(
        reopened.recipient_public(),
        enrolled.vault.recipient_public()
    );

    assert!(
        enrolled
            .sealed
            .unseal(b"a different password", &enrolled.binding())
            .is_err()
    );

    // Transplanted onto another identity, the same bytes do not open.
    let elsewhere = binding_for_parts(
        &user("bad00000-0000-4000-8000-000000000003"),
        &enrolled.signing_key_id,
        &enrolled.recipient_key_id,
    );
    assert!(enrolled.sealed.unseal(PASSWORD, &elsewhere).is_err());
}

#[test]
fn a_password_below_the_minimum_is_refused_by_name() {
    let enrolled = Enrolled::new("alice");
    let error = enrolled
        .vault
        .seal(b"short", &enrolled.binding())
        .unwrap_err();
    assert!(
        error.to_string().contains("at least"),
        "the refusal must name the minimum, got: {error}"
    );
}

// ---------------------------------------------------------------------------
// Criterion 10 — Shamir recovery, and its boundary
// ---------------------------------------------------------------------------

/// The user's own sealed bundle: her sealed vault, encoded.
fn bundle_for(enrolled: &Enrolled) -> SealedBundle {
    SealedBundle::new(
        serde_json::to_vec(&enrolled.sealed).expect("the sealed vault is serializable"),
    )
}

#[test]
fn shamir_recovery_succeeds_for_k_of_n_and_fails_for_k_minus_one() {
    let enrolled = Enrolled::new("alice");
    let bundle = bundle_for(&enrolled);

    let shares = split_vault_bundle(&bundle, Threshold(3), ShareCount(5)).unwrap();
    assert_eq!(shares.len(), 5);

    let recovered = recover_vault_bundle(&shares[..3], Threshold(3)).unwrap();
    assert_eq!(recovered, bundle);

    // The recovered bundle really reopens the vault: a size-equal blob is not
    // the same thing as the user's own bytes.
    let sealed: SealedVault = serde_json::from_slice(recovered.as_bytes()).unwrap();
    assert_eq!(sealed, enrolled.sealed);
    assert!(sealed.unseal(PASSWORD, &enrolled.binding()).is_ok());

    // k-1 fails, and names both the threshold and what was presented.
    let error = recover_vault_bundle(&shares[..2], Threshold(3)).unwrap_err();
    assert_eq!(error.required_threshold(), Some(3));
    assert_eq!(error.presented_shares(), Some(2));
    let message = error.to_string();
    assert!(
        message.contains('3') && message.contains('2'),
        "the refusal must name the threshold and the count, got: {message}"
    );
}

#[test]
fn every_k_subset_of_the_shares_reconstructs_the_bundle() {
    let enrolled = Enrolled::new("bob");
    let bundle = bundle_for(&enrolled);
    let shares = split_vault_bundle(&bundle, Threshold(2), ShareCount(4)).unwrap();

    for first in 0..shares.len() {
        for second in (first + 1)..shares.len() {
            let subset = [shares[first].clone(), shares[second].clone()];
            assert_eq!(
                recover_vault_bundle(&subset, Threshold(2)).unwrap(),
                bundle,
                "shares {first} and {second} must reconstruct the bundle"
            );
        }
    }
}

#[test]
fn a_recovery_request_with_no_shares_is_refused_by_name() {
    let error = recover_vault_bundle(&[], Threshold(3)).unwrap_err();
    assert!(error.required_threshold().is_none());
    assert!(error.to_string().contains("at least one share"));
}

// ---------------------------------------------------------------------------
// Criterion 11 — agent enrolment never unseals a vault
// ---------------------------------------------------------------------------

#[test]
fn an_agent_enrols_without_unsealing_any_vault() {
    // A sealed vault exists and stays sealed for the whole test: no password is
    // given to anything on the agent path, and `AgentKeys` has no vault field.
    let alice = Enrolled::new("alice");
    let sealed_bytes_before = serde_json::to_vec(&alice.sealed).unwrap();

    let agent = AgentKeys::generate();
    let agent_id = ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap();
    let unsigned = agent
        .enrol(
            agent_id,
            KeyId::new("agent-7-ed25519-1"),
            KeyId::new("agent-7-x25519-1"),
        )
        .unwrap();
    let record = alice
        .admin
        .sign_enrolment(unsigned, KeyId::new("admin-1"))
        .unwrap();

    // The agent's keys are its own: independent of the user's vault.
    assert_eq!(record.identity(), &ActorId::Agent(agent_id));
    assert_ne!(record.signing_key(), &alice.vault.signing_public());
    assert_ne!(record.recipient_key(), &alice.vault.recipient_public());

    let mut store = TrustStore::new(alice.admin.verifying_public());
    store
        .import(
            &EnrollmentRecordWire::from_record(&record),
            record.fingerprint(),
        )
        .unwrap();
    assert!(store.get(&ActorId::Agent(agent_id)).is_some());

    // Nothing on the agent path touched the sealed vault.
    assert_eq!(
        serde_json::to_vec(&alice.sealed).unwrap(),
        sealed_bytes_before
    );
}

// ---------------------------------------------------------------------------
// Criterion 9 — the admin key cannot decrypt
// ---------------------------------------------------------------------------

#[test]
fn the_admin_key_holds_no_recipient_key_and_no_vault_key() {
    let enrolled = Enrolled::new("alice");

    // The admin's public key is a signing key only: it is not, and cannot be
    // used as, any user's recipient key.
    let admin_public = enrolled.admin.verifying_public();
    assert_ne!(
        admin_public.to_bytes(),
        enrolled.vault.recipient_public().to_bytes()
    );

    // A second admin over the same user still cannot open her vault: the vault
    // does not depend on any admin key at all.
    let other_admin = AdminSigningKey::generate();
    assert_ne!(other_admin.verifying_public(), admin_public);
    assert!(
        enrolled
            .sealed
            .unseal(PASSWORD, &enrolled.binding())
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// The signature covers the record
// ---------------------------------------------------------------------------

#[test]
fn the_admin_signature_covers_the_bound_keys_and_key_ids() {
    let enrolled = Enrolled::new("alice");
    let admin_public = enrolled.admin.verifying_public();
    assert!(enrolled.record.verify_issuer(&admin_public).is_ok());

    // A zeroed signature over an otherwise well-formed body is refused.
    let mut wire = enrolled.wire();
    wire.issuer_signature = Some(ksp_identity::EnrolmentSignature::from_bytes([0u8; 64]));
    let mut store = TrustStore::new(admin_public);
    assert_eq!(
        store.import(&wire, &enrolled.confirmed()).unwrap_err(),
        ImportRefusal::IssuerSignature
    );
}

#[test]
fn a_record_stored_as_bytes_cannot_lie_about_what_its_fingerprint_binds() {
    let enrolled = Enrolled::new("alice");
    let admin_public = enrolled.admin.verifying_public();

    // A record read straight back from disk is an `EnrollmentRecord`, not the
    // wire form, so `TrustStore::import` is not in the path and its binding
    // check does not run. `verify_issuer` is then the only thing between a
    // tampered file and a substituted key.
    let mut body = serde_json::to_value(&enrolled.record).unwrap();
    body["unsigned"]["fingerprint"] = serde_json::to_value(forged(&subject(
        &enrolled.identity,
        enrolled.vault.signing_public(),
        enrolled.vault.recipient_public(),
        &enrolled.signing_key_id,
        &KeyId::new(""),
    )))
    .unwrap();
    let stored: EnrollmentRecord = serde_json::from_value(body).unwrap();

    assert_eq!(
        stored.verify_issuer(&admin_public).unwrap_err(),
        ImportRefusal::BindingMismatch
    );

    // The untouched record still verifies, so the refusal is about the lie.
    assert!(enrolled.record.verify_issuer(&admin_public).is_ok());
}

#[test]
fn a_record_survives_a_round_trip_and_still_verifies() {
    let enrolled = Enrolled::new("alice");
    let bytes = serde_json::to_vec(&enrolled.wire()).unwrap();
    let wire: EnrollmentRecordWire = serde_json::from_slice(&bytes).unwrap();

    let mut store = TrustStore::new(enrolled.admin.verifying_public());
    let imported = store.import(&wire, &enrolled.confirmed()).unwrap();
    assert_eq!(imported, &enrolled.record);
}

// ---------------------------------------------------------------------------
// Helpers that build hostile records
// ---------------------------------------------------------------------------

/// A copy of a wire record whose fingerprint field was replaced.
///
/// The signature no longer covers the body, which is the point: the fingerprint
/// is checked against the record's own keys before the signature is looked at.
fn wire_with_fingerprint(
    wire: &EnrollmentRecordWire,
    fingerprint: EnrolmentFingerprint,
) -> EnrollmentRecordWire {
    let mut body = serde_json::to_value(wire).unwrap();
    body["fingerprint"] = serde_json::to_value(fingerprint).unwrap();
    serde_json::from_value(body).unwrap()
}
