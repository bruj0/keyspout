//! Scoped key use: a private half is lent to one closure, never handed out.
//!
//! # What these tests are for
//!
//! A type that publishes a private half has to prove two things at once: that
//! the bytes it lends are the *right* half, and that the only thing leaving the
//! call is the closure's own value. The first is checked by deriving a public
//! key from the borrowed bytes and comparing it with the public accessor the
//! type already reports — a copy, a regeneration or the other half would
//! disagree. The second is checked by calling the two shapes the integration
//! layer actually needs: sign a preimage, and perform an X25519 agreement with
//! the borrowed scalar.
//!
//! Nothing here calls a raw-key accessor, because there is no longer one to
//! call: that absence is the property, so the tests exercise it the way a
//! caller must.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_identity::{
    AgentKeyBundle, AgentKeys, KEY_LEN, KeyId, RecipientSecretKey, SigningSecretKey, UserVault,
};

/// A message whose signature proves which seed was used.
const PREIMAGE: &[u8] = b"keyspout-scoped-key-use";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The Ed25519 public key a 32-byte seed produces.
///
/// This is the same derivation `SigningSecretKey::verifying_public` performs,
/// written against the primitive directly so the test does not merely call the
/// accessor it is checking.
fn signing_public_of(seed: &[u8; KEY_LEN]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

/// The X25519 public key a 32-byte secret produces.
fn recipient_public_of(secret: &[u8; KEY_LEN]) -> [u8; 32] {
    let static_secret = x25519_dalek::StaticSecret::from(*secret);
    x25519_dalek::PublicKey::from(&static_secret).to_bytes()
}

fn agent_bundle() -> AgentKeyBundle {
    let keys = AgentKeys::generate();
    AgentKeyBundle::from_keys(
        &keys,
        ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap(),
        KeyId::new("agent-7-ed25519-1"),
        KeyId::new("agent-7-x25519-1"),
    )
    .expect("the bundle binds")
}

// ---------------------------------------------------------------------------
// T086 — each accessor lends the half whose public key it reports
// ---------------------------------------------------------------------------

#[test]
fn the_borrowed_signing_bytes_are_the_ones_this_key_reports() {
    let key = SigningSecretKey::generate();
    let reported = key.verifying_public().to_bytes();

    let derived = key.with_secret(signing_public_of);
    assert_eq!(
        derived, reported,
        "the lent seed must be the one whose public key this key reports"
    );
}

#[test]
fn the_borrowed_recipient_bytes_are_the_ones_this_key_reports() {
    let key = RecipientSecretKey::generate();
    let reported = key.recipient_public().to_bytes();

    let derived = key.with_secret(recipient_public_of);
    assert_eq!(
        derived, reported,
        "the lent secret must be the one whose public key this key reports"
    );
}

#[test]
fn a_user_vault_lends_each_half_to_its_own_public_key() {
    // The vault holds two unrelated keypairs. Lending the wrong one would still
    // produce a valid key, so the check has to be against the public accessor.
    let vault = UserVault::generate();

    let signing = vault.with_signing_secret(signing_public_of);
    let recipient = vault.with_recipient_secret(recipient_public_of);

    assert_eq!(signing, vault.signing_public().to_bytes());
    assert_eq!(recipient, vault.recipient_public().to_bytes());
}

#[test]
fn an_agent_bundle_lends_each_half_to_its_own_public_key() {
    let bundle = agent_bundle();

    let signing = bundle.with_signing_secret(signing_public_of);
    let recipient = bundle.with_recipient_secret(recipient_public_of);

    assert_eq!(signing, bundle.signing_public().to_bytes());
    assert_eq!(recipient, bundle.recipient_public().to_bytes());
}

#[test]
fn the_two_agent_bundle_accessors_lend_different_halves() {
    // The failure this catches: forwarding both accessors to the same field.
    // Each would still be "a key", so only comparing the halves against each
    // other and against their own public accessors catches it.
    let bundle = agent_bundle();

    let signing = bundle.with_signing_secret(|seed| *seed);
    let recipient = bundle.with_recipient_secret(|secret| *secret);

    assert_ne!(signing, recipient, "the two halves must not be the same");
    assert_eq!(
        signing_public_of(&signing),
        bundle.signing_public().to_bytes(),
        "the signing accessor lent the recipient half"
    );
    assert_eq!(
        recipient_public_of(&recipient),
        bundle.recipient_public().to_bytes(),
        "the recipient accessor lent the signing half"
    );
}

// ---------------------------------------------------------------------------
// T087 — the two call shapes the integration layer needs
// ---------------------------------------------------------------------------

#[test]
fn a_signature_made_inside_the_closure_verifies_under_the_public_key() {
    // This is the shape `ksp run --consume` needs: S4's evidence signer takes a
    // 32-byte seed, so the seed must be usable without being owned.
    let bundle = agent_bundle();
    let verifier = bundle.signing_public();

    let signature = bundle.with_signing_secret(|seed| {
        use ed25519_dalek::Signer;
        ed25519_dalek::SigningKey::from_bytes(seed)
            .sign(PREIMAGE)
            .to_bytes()
    });

    assert!(
        verifier.verify(PREIMAGE, &signature),
        "a signature made from the lent seed must verify under the reported key"
    );
}

#[test]
fn an_x25519_agreement_inside_the_closure_matches_the_peer() {
    // This is the shape opening a delivery needs: the peer's ephemeral secret
    // and the enrolled private scalar must agree. Doing it from both sides is
    // what proves the lent bytes are the actual scalar, not a hash of it.
    let bundle = agent_bundle();
    let peer = x25519_dalek::StaticSecret::from([7u8; KEY_LEN]);
    let peer_public = x25519_dalek::PublicKey::from(&peer);

    let ours = bundle.with_recipient_secret(|secret| {
        x25519_dalek::StaticSecret::from(*secret).diffie_hellman(&peer_public)
    });
    let theirs = peer.diffie_hellman(&x25519_dalek::PublicKey::from(
        bundle.recipient_public().to_bytes(),
    ));

    assert_eq!(
        ours.as_bytes(),
        theirs.as_bytes(),
        "the lent secret must produce the same agreement as the reported public key"
    );
}

// ---------------------------------------------------------------------------
// The closure's value, and the absence of a leak
// ---------------------------------------------------------------------------

#[test]
fn the_closure_result_is_passed_through_unchanged() {
    let key = SigningSecretKey::generate();

    let value = key.with_secret(|_| 42u8);
    assert_eq!(value, 42);

    // The value `f` builds is the caller's; the borrow is not. Returning a
    // `Result` is the shape every call site in the CLI actually has.
    let outcome: Result<&'static str, &'static str> = key.with_secret(|_| Ok("done"));
    assert_eq!(outcome, Ok("done"));

    let borrowed_len = key.with_secret(|seed| seed.len());
    assert_eq!(borrowed_len, KEY_LEN);
}

#[test]
fn a_borrowed_half_cannot_be_rendered_from_a_debug_impl() {
    // The secret types have no `Debug` at all, so the risk is a container: a
    // bundle or vault that printed its fields would leak the halves anyway.
    let bundle = agent_bundle();
    let signing = bundle.with_signing_secret(|seed| hex(seed));
    let recipient = bundle.with_recipient_secret(|secret| hex(secret));

    let rendered = format!("{bundle:?}");
    assert!(
        !rendered.contains(&signing) && !rendered.contains(&recipient),
        "a bundle rendered key material: {rendered}"
    );
}
