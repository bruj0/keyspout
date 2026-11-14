//! Misfit R — an identity that does not survive the process that created it.
//!
//! Each test models a **second** foreground invocation: keys are generated,
//! encoded, dropped, and then read back from bytes alone. A test that kept the
//! original value in scope would prove nothing, because the misfit is exactly
//! that a later process has nothing in scope.
//!
//! The pin used to reload is public data — identity, key IDs, public keys and
//! the out-of-band fingerprint — which is what a real host already holds from
//! the enrolment record. The private halves exist only inside the bundle.
//!
//! A test reports a failure by panicking, and the panic message is what says
//! why. The production code keeps the strict lints.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_identity::{
    AdminKeyBundle, AdminSigningKey, AdminSigningPin, AgentIdentityPin, AgentKeyBundle, AgentKeys,
    BundleError, EnrolmentFingerprint, FingerprintSubject, KeyId, RecipientPublicKey,
    VerifyingPublicKey,
};
use ksp_types::{ActorId, AgentId};

const SIGNING_KEY_ID: &str = "deploy-bot-ed25519-1";
const RECIPIENT_KEY_ID: &str = "deploy-bot-x25519-1";
const ADMIN_KEY_ID: &str = "admin-1";

fn agent_id() -> AgentId {
    ksp_types::AgentId::parse("d0000000-0000-4000-8000-00000000000b").unwrap()
}

fn subject(
    identity: &AgentId,
    signing: VerifyingPublicKey,
    recipient: RecipientPublicKey,
) -> FingerprintSubject {
    FingerprintSubject {
        identity: ActorId::Agent(*identity),
        signing_key: signing.to_bytes(),
        recipient_key: recipient.to_bytes(),
        signing_key_id: KeyId::new(SIGNING_KEY_ID),
        recipient_key_id: KeyId::new(RECIPIENT_KEY_ID),
    }
}

fn fingerprint(keys: &AgentKeys) -> EnrolmentFingerprint {
    EnrolmentFingerprint::compute(&subject(
        &agent_id(),
        keys.signing_public(),
        keys.recipient_public(),
    ))
    .unwrap()
}

/// The public pin a host already holds before it reads any key file.
fn pin(keys: &AgentKeys) -> AgentIdentityPin {
    AgentIdentityPin {
        identity: agent_id(),
        signing_key_id: KeyId::new(SIGNING_KEY_ID),
        recipient_key_id: KeyId::new(RECIPIENT_KEY_ID),
        signing_key: keys.signing_public(),
        recipient_key: keys.recipient_public(),
        confirmed_fingerprint: fingerprint(keys),
    }
}

fn bundle(keys: &AgentKeys) -> AgentKeyBundle {
    AgentKeyBundle::from_keys(
        keys,
        agent_id(),
        KeyId::new(SIGNING_KEY_ID),
        KeyId::new(RECIPIENT_KEY_ID),
    )
    .unwrap()
}

fn admin_pin(key: &AdminSigningKey) -> AdminSigningPin {
    AdminSigningPin {
        key_id: KeyId::new(ADMIN_KEY_ID),
        signing_key: key.verifying_public(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Wire-level patching helpers
//
// A bundle is a CBOR map whose keys are the field names, so a stated value can
// be rewritten without knowing the private wire struct. These helpers make the
// "unsupported version" and "explicit role" refusals reachable from a test
// crate, which cannot construct the struct directly.
// ---------------------------------------------------------------------------

fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap_or_else(|| panic!("the encoded bundle must contain {needle:?}"))
}

/// Rewrite the stated format version, returning the patched buffer.
fn with_stated_version(bytes: &[u8], version: u8) -> Vec<u8> {
    let mut patched = bytes.to_vec();
    // "version" is a CBOR text key: 0x67 followed by the seven name bytes. The
    // value follows it and is encoded minimally, so version 1 is the byte 0x01.
    let key = find(&patched, b"\x67version");
    let value_at = key + 8;
    assert_eq!(
        patched[value_at],
        ksp_identity::KEY_BUNDLE_VERSION as u8,
        "the fixture must state the current version before it is patched"
    );
    patched[value_at] = version;
    patched
}

/// Rewrite the stated role text, which is the same length either way.
fn with_stated_role(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    assert_eq!(from.len(), to.len(), "the patch must not change the length");
    let mut patched = bytes.to_vec();
    let key = find(&patched, b"\x64role");
    let text_at = key + 5 + 1; // 0x64 (len 4) + "role", then the length byte
    assert_eq!(&patched[text_at..text_at + from.len()], from.as_bytes());
    patched[text_at..text_at + from.len()].copy_from_slice(to.as_bytes());
    patched
}

/// Add one unknown field to the bundle's CBOR map.
///
/// The map is definite-length, so the count is bumped and a pair is appended.
/// If `deny_unknown_fields` works, this is refused while decoding; if the
/// attribute were removed, decoding would succeed and the canonical re-encode
/// would reject it later as NonCanonical — a different variant, so the
/// assertion below can tell the two apart.
fn with_unknown_field(bytes: &[u8]) -> Vec<u8> {
    let mut patched = bytes.to_vec();
    assert!(
        patched[0] & 0xe0 == 0xa0,
        "the fixture must start with a CBOR map"
    );
    let count = patched[0] & 0x1f;
    assert!(count < 23, "a definite small map count is expected");
    patched[0] = 0xa0 | (count + 1);
    patched.extend_from_slice(b"\x67unknown\x01");
    patched
}

/// The definite-length CBOR array header `[u8; 32]` produces.
const ARRAY_HEADER: [u8; 2] = [0x98, 0x20];

/// The bytes that locate a stored `[u8; 32]` field: its text key followed by
/// the array header.
///
/// `[u8; 32]` is encoded as an array of 32 integers, not as a byte string, and
/// each element takes one or two bytes — so the stored span is 34 to 66 bytes
/// wide. Including the array header in the needle is what keeps `signing_key`
/// from matching the `signing_key_id` field that precedes it.
fn stored_field_needle(name: &str) -> Vec<u8> {
    assert!(name.len() < 24, "a short text key is expected");
    let mut needle = vec![0x60 | name.len() as u8];
    needle.extend_from_slice(name.as_bytes());
    needle.extend_from_slice(&ARRAY_HEADER);
    needle
}

/// Where a stored field begins: the offset of its text key's length byte,
/// with the array header asserted to follow it.
fn stored_field_at(bytes: &[u8], name: &str) -> usize {
    let at = find(bytes, &stored_field_needle(name));
    assert_eq!(
        &bytes[at + 1 + name.len()..at + 1 + name.len() + ARRAY_HEADER.len()],
        &ARRAY_HEADER,
        "the field {name} must be a 32-element array"
    );
    at
}

/// Overwrite one stored `[u8; 32]` field with a value that disagrees with the
/// private half, leaving every other field and the caller's pin untouched.
///
/// `next` names the field that follows; pass `None` for the last field in the
/// map. The replacement carries its own array header, so the splice starts at
/// the old header and ends at the next field's *key*. The value is encoded by
/// the same encoder the bundle uses, so the patched buffer is still canonical —
/// a canonicality failure would mean this helper broke the bytes, not the
/// comparison under test.
fn with_stored_field(
    bytes: &[u8],
    field: &str,
    next: Option<&str>,
    replacement: [u8; 32],
) -> Vec<u8> {
    let start = stored_field_at(bytes, field) + 1 + field.len();
    let end = match next {
        Some(next) => stored_field_at(bytes, next),
        None => bytes.len(),
    };
    assert!(end > start, "the field {field} must hold a non-empty array");

    let mut patched = bytes[..start].to_vec();
    patched.extend_from_slice(&ksp_types::cbor::encode(&replacement).expect("the value encodes"));
    patched.extend_from_slice(&bytes[end..]);
    patched
}

// ---------------------------------------------------------------------------
// Criterion 1 — the identity survives the process that generated it
// ---------------------------------------------------------------------------

#[test]
fn a_reloaded_agent_is_the_same_agent_with_the_same_two_public_keys() {
    let generated = AgentKeys::generate();
    let pinned = pin(&generated);
    let expected_signing = generated.signing_public();
    let expected_recipient = generated.recipient_public();

    let bytes = bundle(&generated).to_bytes().unwrap();
    drop(generated);

    let reloaded = AgentKeyBundle::from_bytes(&bytes, &pinned).expect("the bundle must reload");

    assert_eq!(reloaded.identity(), &agent_id());
    assert_eq!(reloaded.signing_public(), expected_signing);
    assert_eq!(reloaded.recipient_public(), expected_recipient);
    assert_eq!(reloaded.signing_key_id().as_str(), SIGNING_KEY_ID);
    assert_eq!(reloaded.recipient_key_id().as_str(), RECIPIENT_KEY_ID);
    assert!(
        reloaded
            .fingerprint()
            .matches(&pinned.confirmed_fingerprint)
    );
}

#[test]
fn the_reloaded_signing_half_signs_under_the_original_public_key() {
    let generated = AgentKeys::generate();
    let pinned = pin(&generated);
    let expected = generated.signing_public();

    let bytes = bundle(&generated).to_bytes().unwrap();
    drop(generated);

    let reloaded = AgentKeyBundle::from_bytes(&bytes, &pinned).expect("the bundle must reload");

    assert_eq!(reloaded.signing_public(), expected);

    // The same domain-separated preimage a proof of possession signs. WP14
    // does not own the PoP preimage builder, so this asserts the *key*
    // survived, which is what a later `ksp run` depends on.
    let preimage = b"keyspout-pop-v1 test preimage";
    let signature = reloaded.signing_secret().sign_bytes(preimage);
    assert!(
        expected.verify(preimage, &signature.to_bytes()),
        "a reloaded signing half must verify under the enrolled public key"
    );
}

#[test]
fn the_reloaded_recipient_half_derives_the_original_public_key() {
    // The recipient half has no signing operation: its whole job is to be the
    // X25519 secret a delivery envelope is sealed to. A reloaded half that
    // derives the pinned public key is the same key, so every envelope sealed
    // to that key opens exactly as it did before the reload.
    let generated = AgentKeys::generate();
    let pinned = pin(&generated);
    let expected = generated.recipient_public();

    let bytes = bundle(&generated).to_bytes().unwrap();
    drop(generated);

    let reloaded = AgentKeyBundle::from_bytes(&bytes, &pinned).expect("the bundle must reload");

    assert_eq!(reloaded.recipient_public(), expected);

    let other = AgentKeys::generate();
    assert_ne!(
        other.recipient_public(),
        expected,
        "an unrelated key must not derive the enrolled public key"
    );
}

#[test]
fn a_retained_old_bundle_still_reloads_after_a_rotation() {
    let old = AgentKeys::generate();
    let old_pin = pin(&old);
    let old_bytes = bundle(&old).to_bytes().unwrap();

    let new = AgentKeys::generate();
    let new_pin = pin(&new);
    let new_bytes = bundle(&new).to_bytes().unwrap();

    // Rotation changes which key future minting uses.
    let reloaded_new =
        AgentKeyBundle::from_bytes(&new_bytes, &new_pin).expect("the new bundle must reload");
    assert_eq!(reloaded_new.signing_public(), new_pin.signing_key);

    // It does not invalidate the retained old identity, which still opens an
    // artifact captured before the rotation (SC-018).
    let reloaded_old =
        AgentKeyBundle::from_bytes(&old_bytes, &old_pin).expect("the old bundle must still reload");
    assert_eq!(reloaded_old.signing_public(), old_pin.signing_key);

    // And each pin refuses the other bundle.
    assert!(AgentKeyBundle::from_bytes(&new_bytes, &old_pin).is_err());
    assert!(AgentKeyBundle::from_bytes(&old_bytes, &new_pin).is_err());
}

// ---------------------------------------------------------------------------
// Criterion 2 — a substituted bundle is refused, and yields nothing
// ---------------------------------------------------------------------------

#[test]
fn a_bundle_from_another_agent_is_not_this_agents_bundle() {
    let mine = AgentKeys::generate();
    let theirs = AgentKeys::generate();
    let their_bytes = bundle(&theirs).to_bytes().unwrap();

    // Same agent ID and key IDs, different keys: Misfit Q across a file
    // boundary.
    let error = AgentKeyBundle::from_bytes(&their_bytes, &pin(&mine))
        .expect_err("a substituted bundle must be refused");
    assert!(
        matches!(
            error,
            BundleError::PublicKeyMismatch | BundleError::FingerprintMismatch
        ),
        "expected a key or fingerprint refusal, got {error:?}"
    );
}

#[test]
fn a_bundle_for_another_identity_is_refused_even_with_matching_keys() {
    let keys = AgentKeys::generate();
    let bytes = bundle(&keys).to_bytes().unwrap();

    let mut other = pin(&keys);
    other.identity = ksp_types::AgentId::parse("50e00000-0000-4000-8000-00000000000e").unwrap();

    assert!(matches!(
        AgentKeyBundle::from_bytes(&bytes, &other),
        Err(BundleError::IdentityMismatch)
    ));
}

#[test]
fn a_bundle_naming_different_key_ids_is_refused() {
    let keys = AgentKeys::generate();
    let bytes = bundle(&keys).to_bytes().unwrap();

    let mut renamed = pin(&keys);
    renamed.signing_key_id = KeyId::new("deploy-bot-ed25519-2");

    assert!(matches!(
        AgentKeyBundle::from_bytes(&bytes, &renamed),
        Err(BundleError::KeyIdMismatch)
    ));
}

#[test]
fn a_bundle_whose_fingerprint_does_not_match_the_confirmed_one_is_refused() {
    let keys = AgentKeys::generate();
    let bytes = bundle(&keys).to_bytes().unwrap();

    // A pin whose confirmed fingerprint was computed over a different identity
    // is the "user compared the wrong fingerprint" case.
    let other = AgentKeys::generate();
    let mut wrong = pin(&keys);
    wrong.confirmed_fingerprint = fingerprint(&other);

    assert!(matches!(
        AgentKeyBundle::from_bytes(&bytes, &wrong),
        Err(BundleError::FingerprintMismatch)
    ));
}

#[test]
fn an_agent_bundle_whose_stored_recipient_key_disagrees_with_its_secret_is_refused() {
    // The recipient half is the X25519 key that unwraps a delivery. A stored
    // copy that disagrees with the secret must be a refusal, not a silent
    // substitution: the substituted key is one the caller never pinned.
    let keys = AgentKeys::generate();
    let bytes = bundle(&keys).to_bytes().unwrap();
    let other = AgentKeys::generate();
    let patched = with_stored_field(
        &bytes,
        "recipient_key",
        Some("signing_secret"),
        other.recipient_public().to_bytes(),
    );

    let error = AgentKeyBundle::from_bytes(&patched, &pin(&keys))
        .expect_err("a rewritten recipient half must be refused");
    assert!(
        matches!(error, BundleError::PublicKeyMismatch),
        "the stored recipient half must be compared, not replaced: {error:?}"
    );
}

#[test]
fn a_pinned_recipient_key_that_disagrees_with_the_bundle_is_refused() {
    // Only the pin's recipient half is wrong, so the bundle and its own
    // fingerprint are internally consistent. The refusal has to come from the
    // pin comparison, which is why the exact variant is asserted: the
    // fingerprint check would also reject this, for the wrong reason.
    let keys = AgentKeys::generate();
    let bytes = bundle(&keys).to_bytes().unwrap();

    let mut mismatched = pin(&keys);
    mismatched.recipient_key = AgentKeys::generate().recipient_public();

    let error = AgentKeyBundle::from_bytes(&bytes, &mismatched)
        .expect_err("a pin holding another recipient key must refuse the bundle");
    assert!(
        matches!(error, BundleError::PublicKeyMismatch),
        "the pinned recipient key must be compared directly: {error:?}"
    );
}

#[test]
fn a_pinned_recipient_key_id_that_disagrees_with_the_bundle_is_refused() {
    let keys = AgentKeys::generate();
    let bytes = bundle(&keys).to_bytes().unwrap();

    let mut renamed = pin(&keys);
    renamed.recipient_key_id = KeyId::new("deploy-bot-x25519-2");

    let error = AgentKeyBundle::from_bytes(&bytes, &renamed)
        .expect_err("a pin naming another recipient key ID must refuse the bundle");
    assert!(
        matches!(error, BundleError::KeyIdMismatch),
        "the pinned recipient key ID must be compared: {error:?}"
    );
}

#[test]
fn a_pinned_public_key_that_disagrees_with_the_bundle_is_refused() {
    let keys = AgentKeys::generate();
    let bytes = bundle(&keys).to_bytes().unwrap();

    let mut mismatched = pin(&keys);
    mismatched.signing_key = AgentKeys::generate().signing_public();

    assert!(matches!(
        AgentKeyBundle::from_bytes(&bytes, &mismatched),
        Err(BundleError::PublicKeyMismatch)
    ));
}

#[test]
fn a_truncated_or_extended_bundle_is_refused() {
    let keys = AgentKeys::generate();
    let bytes = bundle(&keys).to_bytes().unwrap();
    let pin = pin(&keys);

    let truncated = &bytes[..bytes.len() - 1];
    assert!(
        AgentKeyBundle::from_bytes(truncated, &pin).is_err(),
        "a truncated bundle must not reload"
    );

    let mut extended = bytes.to_vec();
    extended.push(0x00);
    assert!(
        AgentKeyBundle::from_bytes(&extended, &pin).is_err(),
        "trailing bytes must not be ignored"
    );

    assert!(AgentKeyBundle::from_bytes(&[], &pin).is_err());
}

#[test]
fn an_admin_bundle_is_not_an_agent_bundle() {
    let admin = AdminSigningKey::generate();
    let admin_bytes = AdminKeyBundle::from_key(&admin, KeyId::new(ADMIN_KEY_ID))
        .to_bytes()
        .unwrap();

    let keys = AgentKeys::generate();
    // The first barrier is the field set, not the role string: the two wire
    // structs carry different mandatory fields and both deny unknown ones, so
    // an admin buffer cannot decode as an agent bundle at all.
    assert!(matches!(
        AgentKeyBundle::from_bytes(&admin_bytes, &pin(&keys)),
        Err(BundleError::Malformed)
    ));
}

#[test]
fn an_agent_bundle_is_not_an_admin_bundle() {
    let keys = AgentKeys::generate();
    let agent_bytes = bundle(&keys).to_bytes().unwrap();

    let admin = AdminSigningKey::generate();
    assert!(matches!(
        AdminKeyBundle::from_bytes(&agent_bytes, &admin_pin(&admin)),
        Err(BundleError::Malformed)
    ));
}

#[test]
fn an_agent_bundle_that_states_the_admin_role_is_refused_by_role() {
    // The role string is a second, independent barrier: a buffer that still
    // decodes as an agent bundle but claims another role must not be accepted.
    // Without this test the role comparison could be deleted and nothing would
    // notice, because the field sets alone refuse the cross-struct case.
    let keys = AgentKeys::generate();
    let bytes = bundle(&keys).to_bytes().unwrap();
    let relabelled = with_stated_role(&bytes, "agent", "admin");

    assert!(matches!(
        AgentKeyBundle::from_bytes(&relabelled, &pin(&keys)),
        Err(BundleError::WrongRole { expected: "agent" })
    ));
}

#[test]
fn an_admin_bundle_that_states_the_agent_role_is_refused_by_role() {
    let admin = AdminSigningKey::generate();
    let bytes = AdminKeyBundle::from_key(&admin, KeyId::new(ADMIN_KEY_ID))
        .to_bytes()
        .unwrap();
    let relabelled = with_stated_role(&bytes, "admin", "agent");

    assert!(matches!(
        AdminKeyBundle::from_bytes(&relabelled, &admin_pin(&admin)),
        Err(BundleError::WrongRole { expected: "admin" })
    ));
}

#[test]
fn an_agent_bundle_stating_another_version_is_refused() {
    let keys = AgentKeys::generate();
    let bytes = bundle(&keys).to_bytes().unwrap();
    let future = with_stated_version(&bytes, 2);

    assert!(matches!(
        AgentKeyBundle::from_bytes(&future, &pin(&keys)),
        Err(BundleError::UnsupportedVersion {
            found: 2,
            expected: 1
        })
    ));
}

#[test]
fn an_admin_bundle_stating_another_version_is_refused() {
    let admin = AdminSigningKey::generate();
    let bytes = AdminKeyBundle::from_key(&admin, KeyId::new(ADMIN_KEY_ID))
        .to_bytes()
        .unwrap();
    let future = with_stated_version(&bytes, 2);

    assert!(matches!(
        AdminKeyBundle::from_bytes(&future, &admin_pin(&admin)),
        Err(BundleError::UnsupportedVersion {
            found: 2,
            expected: 1
        })
    ));
}

#[test]
fn an_agent_bundle_with_an_unknown_field_is_refused_while_decoding() {
    // A field this build does not know may mean something the version has not
    // declared. It must be refused as undecodable, not carried through to the
    // canonical check, which would report the different NonCanonical variant.
    let keys = AgentKeys::generate();
    let bytes = bundle(&keys).to_bytes().unwrap();
    let extended = with_unknown_field(&bytes);

    assert!(matches!(
        AgentKeyBundle::from_bytes(&extended, &pin(&keys)),
        Err(BundleError::Malformed)
    ));
}

#[test]
fn an_admin_bundle_with_an_unknown_field_is_refused_while_decoding() {
    let admin = AdminSigningKey::generate();
    let bytes = AdminKeyBundle::from_key(&admin, KeyId::new(ADMIN_KEY_ID))
        .to_bytes()
        .unwrap();
    let extended = with_unknown_field(&bytes);

    assert!(matches!(
        AdminKeyBundle::from_bytes(&extended, &admin_pin(&admin)),
        Err(BundleError::Malformed)
    ));
}

#[test]
fn an_agent_bundle_whose_stored_fingerprint_disagrees_with_its_keys_is_refused() {
    // The fingerprint field is a claim *inside* the file. If it is rewritten
    // while the private half stays intact, the reload must refuse the file
    // rather than quietly return the recomputed value: a silently repaired
    // bundle is a tampered bundle the caller never learns about.
    let keys = AgentKeys::generate();
    let bytes = bundle(&keys).to_bytes().unwrap();
    let other = fingerprint(&AgentKeys::generate());
    let patched = with_stored_field(&bytes, "fingerprint", None, *other.as_bytes());

    let error = AgentKeyBundle::from_bytes(&patched, &pin(&keys))
        .expect_err("a rewritten fingerprint must be refused");
    assert!(
        matches!(error, BundleError::FingerprintMismatch),
        "the stored field must be compared, not replaced: {error:?}"
    );
}

#[test]
fn an_agent_bundle_whose_stored_public_key_disagrees_with_its_secret_is_refused() {
    let keys = AgentKeys::generate();
    let bytes = bundle(&keys).to_bytes().unwrap();
    let other = AgentKeys::generate();
    let patched = with_stored_field(
        &bytes,
        "signing_key",
        Some("recipient_key"),
        other.signing_public().to_bytes(),
    );

    let error = AgentKeyBundle::from_bytes(&patched, &pin(&keys))
        .expect_err("a rewritten public half must be refused");
    assert!(
        matches!(error, BundleError::PublicKeyMismatch),
        "the stored half must be compared, not replaced: {error:?}"
    );
}

#[test]
fn an_admin_bundle_whose_stored_public_key_disagrees_with_its_secret_is_refused() {
    // Same rule for the signing-only identity: the stored public half is not
    // the authority, the half derived from the secret is, and a disagreement
    // is a refusal rather than a silent substitution.
    let admin = AdminSigningKey::generate();
    let bytes = AdminKeyBundle::from_key(&admin, KeyId::new(ADMIN_KEY_ID))
        .to_bytes()
        .unwrap();
    let other = AdminSigningKey::generate();
    let patched = with_stored_field(
        &bytes,
        "signing_key",
        Some("signing_secret"),
        other.verifying_public().to_bytes(),
    );

    let error = AdminKeyBundle::from_bytes(&patched, &admin_pin(&admin))
        .expect_err("a rewritten admin public half must be refused");
    assert!(
        matches!(error, BundleError::PublicKeyMismatch),
        "the stored half must be compared, not replaced: {error:?}"
    );
}

// ---------------------------------------------------------------------------
// Criterion 3 — the admin reloads as signing-only authority
// ---------------------------------------------------------------------------

#[test]
fn a_reloaded_admin_signs_an_enrolment_under_the_pinned_public_key() {
    let admin = AdminSigningKey::generate();
    let pinned = admin_pin(&admin);
    let expected = admin.verifying_public();

    let bytes = AdminKeyBundle::from_key(&admin, KeyId::new(ADMIN_KEY_ID))
        .to_bytes()
        .unwrap();
    drop(admin);

    let reloaded =
        AdminKeyBundle::from_bytes(&bytes, &pinned).expect("the admin bundle must reload");
    assert_eq!(reloaded.key_id().as_str(), ADMIN_KEY_ID);
    assert_eq!(reloaded.signing_key(), expected);

    let keys = AgentKeys::generate();
    let unsigned = keys
        .enrol(
            agent_id(),
            KeyId::new(SIGNING_KEY_ID),
            KeyId::new(RECIPIENT_KEY_ID),
        )
        .unwrap();
    let record = reloaded
        .into_key()
        .sign_enrolment(unsigned, KeyId::new(ADMIN_KEY_ID))
        .expect("a reloaded admin key must sign an enrolment");

    assert!(
        record.verify_issuer(&expected).is_ok(),
        "the signature must verify under the pinned admin key"
    );
}

#[test]
fn an_admin_bundle_against_a_different_pinned_key_is_refused() {
    let admin = AdminSigningKey::generate();
    let bytes = AdminKeyBundle::from_key(&admin, KeyId::new(ADMIN_KEY_ID))
        .to_bytes()
        .unwrap();

    let other = AdminSigningKey::generate();
    let wrong_pin = AdminSigningPin {
        key_id: KeyId::new(ADMIN_KEY_ID),
        signing_key: other.verifying_public(),
    };

    assert!(matches!(
        AdminKeyBundle::from_bytes(&bytes, &wrong_pin),
        Err(BundleError::PublicKeyMismatch)
    ));
}

#[test]
fn an_admin_bundle_with_another_key_id_is_refused() {
    let admin = AdminSigningKey::generate();
    let bytes = AdminKeyBundle::from_key(&admin, KeyId::new(ADMIN_KEY_ID))
        .to_bytes()
        .unwrap();

    let wrong_id = AdminSigningPin {
        key_id: KeyId::new("admin-2"),
        signing_key: admin.verifying_public(),
    };

    assert!(matches!(
        AdminKeyBundle::from_bytes(&bytes, &wrong_id),
        Err(BundleError::KeyIdMismatch)
    ));
}

// ---------------------------------------------------------------------------
// Criterion 6 — nothing renders a private half
// ---------------------------------------------------------------------------

#[test]
fn a_bundle_never_renders_key_material() {
    let keys = AgentKeys::generate();
    let binder = bundle(&keys);

    let rendered = format!("{binder:?}");
    assert!(
        rendered.contains("redacted"),
        "a bundle must announce that it is redacted: {rendered}"
    );
    assert!(!rendered.contains(&hex(&keys.signing_public().to_bytes())));
    assert!(!rendered.contains(&hex(&keys.recipient_public().to_bytes())));

    let admin = AdminSigningKey::generate();
    let admin_rendered = format!(
        "{:?}",
        AdminKeyBundle::from_key(&admin, KeyId::new(ADMIN_KEY_ID))
    );
    assert!(admin_rendered.contains("redacted"));
    assert!(!admin_rendered.contains(&hex(&admin.verifying_public().to_bytes())));
}

#[test]
fn a_refusal_never_renders_key_material() {
    let mine = AgentKeys::generate();
    let theirs = AgentKeys::generate();
    let bytes = bundle(&theirs).to_bytes().unwrap();

    let error = AgentKeyBundle::from_bytes(&bytes, &pin(&mine)).unwrap_err();
    let rendered = format!("{error}");

    assert!(!rendered.contains(&hex(&theirs.recipient_public().to_bytes())));
    assert!(!rendered.contains(&hex(&theirs.signing_public().to_bytes())));
    assert!(!rendered.contains("0x"));
}
