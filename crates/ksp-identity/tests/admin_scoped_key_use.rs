//! The admin's signing half, lent to one closure.
//!
//! # Why the admin is here at all
//!
//! WP16 gave scoped use to the agent and user halves and deliberately left the
//! admin out, on the premise that the admin only signs through S2's typed
//! methods. That premise was wrong: S4's `SignedIntent::sign` takes an
//! `EvidenceSigningKey`, which is built from a 32-byte seed, so issuing a
//! deletion intent needs the admin's seed and the admin is the only authority
//! that may issue one.
//!
//! # What these tests check
//!
//! The same two properties as the agent half: the bytes lent are the *right*
//! half, and the only thing leaving the call is the closure's value. The public
//! key is derived with `ed25519_dalek` directly rather than by calling the
//! accessor under test, so a copy, a re-generation or another key disagrees.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_identity::{AdminKeyBundle, AdminSigningKey, KEY_LEN, KeyId};

/// A message whose signature proves which seed was used.
const PREIMAGE: &[u8] = b"keyspout-admin-scoped-key-use";

/// The Ed25519 public key a 32-byte seed produces.
///
/// Written against the primitive so the test does not merely call the accessor
/// it is checking.
fn signing_public_of(seed: &[u8; KEY_LEN]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

fn admin_bundle() -> AdminKeyBundle {
    AdminKeyBundle::from_key(&AdminSigningKey::generate(), KeyId::new("admin-2026"))
}

// ---------------------------------------------------------------------------
// T091 — the accessor lends the half whose public key it reports
// ---------------------------------------------------------------------------

#[test]
fn the_borrowed_admin_seed_is_the_one_this_key_reports() {
    let key = AdminSigningKey::generate();
    let reported = key.verifying_public().to_bytes();

    let derived = key.with_secret(signing_public_of);
    assert_eq!(
        derived, reported,
        "the lent seed must be the one whose public key this key reports"
    );
}

#[test]
fn an_admin_bundle_forwards_that_same_half() {
    // The failure this catches: a bundle that forwards nothing, or forwards an
    // unrelated key it generated for itself. Both still produce *a* key.
    let bundle = admin_bundle();

    let derived = bundle.with_signing_secret(signing_public_of);
    assert_eq!(
        derived,
        bundle.signing_key().to_bytes(),
        "the bundle must lend the half it reports"
    );
}

// ---------------------------------------------------------------------------
// T092 — the call shape S4 needs
// ---------------------------------------------------------------------------

#[test]
fn a_signature_made_inside_the_closure_verifies_under_the_public_key() {
    // This is the shape `ksp run --consume` needs: S4 signs an intent with an
    // `EvidenceSigningKey`, which is built from a 32-byte seed, so the seed must
    // be usable without being owned.
    let key = AdminSigningKey::generate();
    let verifier = key.verifying_public();

    let signature = key.with_secret(|seed| {
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
fn the_closure_result_is_passed_through_unchanged() {
    let key = AdminSigningKey::generate();

    let outcome: Result<&'static str, &'static str> = key.with_secret(|_| Ok("signed"));
    assert_eq!(outcome, Ok("signed"));

    assert_eq!(key.with_secret(|seed| seed.len()), KEY_LEN);
}

#[test]
fn a_borrowed_half_cannot_be_rendered_from_a_debug_impl() {
    // The risk is the container: a bundle that printed its fields would leak the
    // half even though the key type has no `Debug` at all.
    let bundle = admin_bundle();
    let lent = bundle.with_signing_secret(|seed| {
        seed.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    });

    let rendered = format!("{bundle:?}");
    assert!(
        !rendered.contains(&lent),
        "a bundle rendered key material: {rendered}"
    );
}
