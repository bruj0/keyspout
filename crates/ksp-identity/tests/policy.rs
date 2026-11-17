//! The acceptance criteria for WP05, driven through the public API.
//!
//! Two misfits live here. Misfit H is that a trust anchor taken from the artifact
//! under verification verifies nothing, so the tests attack it from both sides: a
//! policy naming a key this host never pinned, and a policy naming the pinned ID
//! while signing with a different key. Misfit N is that a replayed older policy
//! is validly signed, so the tests walk the checkpoint forward, then try to go
//! back, and check that a rejected policy never moves it.
//!
//! A test reports a failure by panicking, and the panic message is what says why.
//! The production code keeps the strict lints.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use ksp_identity::{
    AdminSigningKey, AgentKeys, EnrollmentRecord, EnrollmentRecordWire, Freshness, KeyId, Policy,
    PolicyBody, PolicyRefusal, PolicyRequest, PolicyVerifier, SigningSecretKey, TrustAnchors,
    TrustStore, TrustedCheckpoint, TrustedEnrolmentKeys, UnsignedEnrolment, VerificationOutcome,
    decode_policy, encode_policy,
};
use ksp_types::{ActorId, AgentId, Level, OpaqueSecretId, RecordVersion, VaultId};

const ADMIN_ID: &str = "admin-1";
const NOT_BEFORE: u64 = 1_000;
const NOT_AFTER: u64 = 2_000;
const DURING: u64 = 1_500;
const MAX_USER_TTL: u64 = 3_600;
const MAX_AGENT_TTL: u64 = 600;

fn agent_seven() -> ksp_types::AgentId {
    ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap()
}

fn agent_eight() -> ksp_types::AgentId {
    ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000008").unwrap()
}

fn agent_nine() -> ksp_types::AgentId {
    ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000009").unwrap()
}

fn agent_level() -> Level {
    Level::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap())
}

fn vault() -> VaultId {
    VaultId::new("vault-1")
}

fn user() -> ksp_types::PrincipalId {
    ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap()
}

fn secret() -> OpaqueSecretId {
    OpaqueSecretId::new("secret-1")
}

/// One fixed enrolment, generated once per process.
///
/// Deterministic on purpose: a fixture that generated fresh keys per call would
/// make two "identical" policies differ, and a digest comparison would then fail
/// for a reason that has nothing to do with the code under test.
fn trusted_keys() -> TrustedEnrolmentKeys {
    static SIGNING: std::sync::OnceLock<ksp_identity::VerifyingPublicKey> =
        std::sync::OnceLock::new();
    TrustedEnrolmentKeys {
        signing_key: *SIGNING.get_or_init(|| SigningSecretKey::generate().verifying_public()),
        recipient_key: ksp_identity::RecipientPublicKey::from_bytes([21u8; 32]),
        signing_key_id: KeyId::new("alice-ed25519-1"),
        recipient_key_id: KeyId::new("alice-x25519-1"),
    }
}

fn body(revision: u64) -> PolicyBody {
    PolicyBody::new(
        revision,
        vault(),
        user(),
        trusted_keys(),
        vec![secret(), OpaqueSecretId::new("secret-2")],
        vec![
            ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap(),
            ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000008").unwrap(),
        ],
        MAX_USER_TTL,
        MAX_AGENT_TTL,
        NOT_BEFORE,
        NOT_AFTER,
    )
}

/// A well-formed request that a matching policy authorises.
fn request() -> PolicyRequest {
    PolicyRequest {
        vault: vault(),
        user: user(),
        source: Level::User,
        target: agent_level(),
        secret: secret(),
        agent: ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap(),
        path: "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-00000000-0000-4000-8000-000000000007/secret-1/1".to_string(),
        scope: agent_level().path_segment(),
        requested_ttl_secs: 300,
        record_version: RecordVersion(1),
    }
}

fn signed(admin: &AdminSigningKey, revision: u64) -> Policy {
    Policy::new(admin, KeyId::new(ADMIN_ID), body(revision)).unwrap()
}

/// A verifier holding the admin's key under the ID a policy names.
fn verifier(admin: &AdminSigningKey, checkpoint: Option<TrustedCheckpoint>) -> PolicyVerifier {
    let mut anchors = TrustAnchors::new();
    anchors.pin(KeyId::new(ADMIN_ID), admin.verifying_public());
    PolicyVerifier::new(anchors, checkpoint)
}

fn assert_refused(outcome: VerificationOutcome) -> PolicyRefusal {
    match outcome {
        VerificationOutcome::Refused(refusal) => refusal,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Criterion 1 — a wrong issuer is rejected
// ---------------------------------------------------------------------------

#[test]
fn a_policy_signed_by_a_key_that_is_not_the_pinned_issuer_is_rejected() {
    let admin = AdminSigningKey::generate();
    let impostor = AdminSigningKey::generate();

    // The impostor signs, but names the pinned ID. The ID is looked up and the
    // pinned key does not verify: the ID alone buys nothing.
    let policy = signed(&impostor, 5);
    let refusal = assert_refused(verifier(&admin, None).verify(&policy, &request(), DURING));
    assert_eq!(
        refusal,
        PolicyRefusal::IssuerSignature {
            issuer: ADMIN_ID.to_string()
        }
    );
}

// ---------------------------------------------------------------------------
// Criteria 2, 3, 4 — the wrong vault, user or agent
// ---------------------------------------------------------------------------

#[test]
fn a_policy_for_a_different_vault_is_rejected() {
    let admin = AdminSigningKey::generate();
    let mut request = request();
    request.vault = VaultId::new("vault-2");

    let refusal =
        assert_refused(verifier(&admin, None).verify(&signed(&admin, 5), &request, DURING));
    assert_eq!(
        refusal,
        PolicyRefusal::Vault {
            expected: "vault-1".to_string(),
            found: "vault-2".to_string()
        }
    );
}

#[test]
fn a_policy_for_a_different_user_is_rejected() {
    let admin = AdminSigningKey::generate();
    let mut request = request();
    request.user = ksp_types::PrincipalId::parse("bad00000-0000-4000-8000-000000000003").unwrap();
    request.path = "p/vault-1/bad00000-0000-4000-8000-000000000003/agent-00000000-0000-4000-8000-000000000007/secret-1/1".to_string();

    let refusal =
        assert_refused(verifier(&admin, None).verify(&signed(&admin, 5), &request, DURING));
    assert_eq!(
        refusal,
        PolicyRefusal::User {
            expected: user().to_string(),
            found: "bad00000-0000-4000-8000-000000000003".to_string()
        }
    );
}

/// Review v1, Issue 1. The grant names an agent; the level the copy is written
/// at must be *that* agent's level.
///
/// This is the direction the first version of the suite missed. Every field is
/// self-consistent — the scope and the path both describe agent-9 — so nothing
/// except a direct comparison between the grant and the target can catch it.
#[test]
fn a_grant_for_one_agent_does_not_authorise_a_copy_at_another_agents_level() {
    let admin = AdminSigningKey::generate();
    let mut request = request();

    // The policy grants exactly agent-7.
    request.agent = ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap();
    // …but the copy is written at agent-9's level, with a scope and a path that
    // agree with that level.
    request.target =
        Level::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000009").unwrap());
    request.scope =
        Level::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000009").unwrap())
            .path_segment();
    request.path = "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-00000000-0000-4000-8000-000000000009/secret-1/1".to_string();

    assert_eq!(
        assert_refused(verifier(&admin, None).verify(&signed(&admin, 5), &request, DURING)),
        PolicyRefusal::TargetLevel {
            granted: agent_seven().to_string(),
            target: agent_nine().to_string()
        }
    );

    // With the grant and the level in agreement the same shape is accepted, so
    // the refusal is about the disagreement and not about agent-9 being unknown.
    let mut agreeing = request;
    agreeing.agent = ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000008").unwrap();
    agreeing.target =
        Level::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000008").unwrap());
    agreeing.scope =
        Level::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000008").unwrap())
            .path_segment();
    agreeing.path = "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-00000000-0000-4000-8000-000000000008/secret-1/1".to_string();
    let policy = Policy::new(
        &admin,
        KeyId::new(ADMIN_ID),
        PolicyBody::new(
            5,
            vault(),
            user(),
            trusted_keys(),
            vec![secret()],
            vec![ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000008").unwrap()],
            MAX_USER_TTL,
            MAX_AGENT_TTL,
            NOT_BEFORE,
            NOT_AFTER,
        ),
    )
    .unwrap();
    assert!(
        verifier(&admin, None)
            .verify(&policy, &agreeing, DURING)
            .is_verified()
    );
}

#[test]
fn a_policy_for_a_different_agent_is_rejected() {
    let admin = AdminSigningKey::generate();
    let mut request = request();
    // agent-9 is enrolled nowhere in this policy.
    request.agent = ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000009").unwrap();
    request.target =
        Level::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap());

    let refusal =
        assert_refused(verifier(&admin, None).verify(&signed(&admin, 5), &request, DURING));
    assert_eq!(
        refusal,
        PolicyRefusal::AgentGrant {
            agent: agent_nine().to_string()
        }
    );
}

// ---------------------------------------------------------------------------
// Criterion 5 — a disallowed level pair
// ---------------------------------------------------------------------------

#[test]
fn a_level_pair_that_is_not_a_share_is_rejected() {
    let admin = AdminSigningKey::generate();
    let policy = signed(&admin, 5);

    // agent -> agent is the sibling read Misfit G describes.
    let mut sibling = request();
    sibling.source =
        Level::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000008").unwrap());
    assert_eq!(
        assert_refused(verifier(&admin, None).verify(&policy, &sibling, DURING)),
        PolicyRefusal::LevelPair {
            from_level: Level::Agent(agent_eight()).path_segment(),
            to_level: Level::Agent(agent_seven()).path_segment()
        }
    );

    // agent -> user is the one-way boundary FR-016 draws.
    let mut upstream = request();
    upstream.source = agent_level();
    upstream.target = Level::User;
    upstream.scope = Level::User.path_segment();
    upstream.path = "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/user/secret-1/1".to_string();
    assert!(matches!(
        assert_refused(verifier(&admin, None).verify(&policy, &upstream, DURING)),
        PolicyRefusal::LevelPair { .. }
    ));
}

// ---------------------------------------------------------------------------
// Criteria 6, 7 — a disallowed secret or agent grant
// ---------------------------------------------------------------------------

#[test]
fn a_secret_that_is_not_shareable_is_rejected() {
    let admin = AdminSigningKey::generate();
    let mut request = request();
    request.secret = OpaqueSecretId::new("secret-3");
    request.path = "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-00000000-0000-4000-8000-000000000007/secret-3/1".to_string();

    assert_eq!(
        assert_refused(verifier(&admin, None).verify(&signed(&admin, 5), &request, DURING)),
        PolicyRefusal::SecretGrant {
            secret: "secret-3".to_string()
        }
    );
}

#[test]
fn an_agent_that_is_not_shareable_is_rejected() {
    let admin = AdminSigningKey::generate();
    let mut request = request();
    request.agent = ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000009").unwrap();
    // The target level still names agent-7, so the *grant* is what fails, not
    // the level pair.
    let policy_body = PolicyBody::new(
        5,
        vault(),
        user(),
        trusted_keys(),
        vec![secret()],
        vec![ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap()],
        MAX_USER_TTL,
        MAX_AGENT_TTL,
        NOT_BEFORE,
        NOT_AFTER,
    );
    let policy = Policy::new(&admin, KeyId::new(ADMIN_ID), policy_body).unwrap();

    assert_eq!(
        assert_refused(verifier(&admin, None).verify(&policy, &request, DURING)),
        PolicyRefusal::AgentGrant {
            agent: agent_nine().to_string()
        }
    );
}

// ---------------------------------------------------------------------------
// Criterion 8 — an expired policy
// ---------------------------------------------------------------------------

#[test]
fn a_policy_outside_its_validity_interval_is_rejected() {
    let admin = AdminSigningKey::generate();
    let policy = signed(&admin, 5);

    assert_eq!(
        assert_refused(verifier(&admin, None).verify(&policy, &request(), NOT_AFTER + 1)),
        PolicyRefusal::Expired {
            at: NOT_AFTER + 1,
            not_after: NOT_AFTER
        }
    );
    assert_eq!(
        assert_refused(verifier(&admin, None).verify(&policy, &request(), NOT_BEFORE - 1)),
        PolicyRefusal::NotYetValid {
            at: NOT_BEFORE - 1,
            not_before: NOT_BEFORE
        }
    );
    // Inside the interval the same policy is accepted, so the refusals above are
    // about the clock and not about the policy being unusable.
    assert!(
        verifier(&admin, None)
            .verify(&policy, &request(), DURING)
            .is_verified()
    );
}

// ---------------------------------------------------------------------------
// Criterion 9 — an excessive TTL, at each level separately
// ---------------------------------------------------------------------------

#[test]
fn a_lease_above_the_agent_maximum_is_rejected() {
    let admin = AdminSigningKey::generate();
    let mut request = request();
    request.requested_ttl_secs = MAX_AGENT_TTL + 1;

    assert_eq!(
        assert_refused(verifier(&admin, None).verify(&signed(&admin, 5), &request, DURING)),
        PolicyRefusal::MaxAgentTtl {
            max: MAX_AGENT_TTL,
            requested: MAX_AGENT_TTL + 1
        }
    );

    // At the boundary exactly, the same request is allowed: the bound is
    // inclusive, and a test that only tried max+1 would not say so.
    request.requested_ttl_secs = MAX_AGENT_TTL;
    assert!(
        verifier(&admin, None)
            .verify(&signed(&admin, 5), &request, DURING)
            .is_verified()
    );
}

#[test]
fn a_lease_above_the_user_maximum_is_rejected() {
    let admin = AdminSigningKey::generate();
    let policy = signed(&admin, 5);

    // A lease written at a non-agent level is bounded by max_user_ttl, which is
    // a separate number from max_agent_ttl.
    assert_eq!(
        policy.check_ttl(&Level::User, MAX_USER_TTL + 1),
        Err(PolicyRefusal::MaxUserTtl {
            max: MAX_USER_TTL,
            requested: MAX_USER_TTL + 1
        })
    );
    assert_eq!(policy.check_ttl(&Level::User, MAX_USER_TTL), Ok(()));
    assert_eq!(policy.max_ttl_for(&Level::Admin), MAX_USER_TTL);
    assert_eq!(policy.max_ttl_for(&agent_level()), MAX_AGENT_TTL);
}

// ---------------------------------------------------------------------------
// Criteria 10, 11, 13 — the checkpoint
// ---------------------------------------------------------------------------

#[test]
fn a_policy_below_the_trusted_checkpoint_is_rejected_as_a_rollback() {
    let admin = AdminSigningKey::generate();
    let mut verifier = verifier(&admin, None);

    // Accept revision 5, which advances the checkpoint.
    let first = verifier.verify_and_accept(&signed(&admin, 5), &request(), DURING);
    assert!(first.is_verified());
    assert_eq!(verifier.checkpoint().unwrap().revision(), 5);

    // Now present revision 4: validly signed, but older. It is a replay.
    let refusal = assert_refused(verifier.verify(&signed(&admin, 4), &request(), DURING));
    assert_eq!(
        refusal,
        PolicyRefusal::Rollback {
            presented: 4,
            checkpoint: 5
        }
    );

    // And the checkpoint did not move down to meet it.
    assert_eq!(verifier.checkpoint().unwrap().revision(), 5);
}

#[test]
fn a_rejected_policy_does_not_advance_the_checkpoint() {
    let admin = AdminSigningKey::generate();
    let mut verifier = verifier(&admin, None);
    assert_eq!(verifier.checkpoint(), None);

    // A newer, well-signed policy that fails a field check.
    let mut wrong_vault = request();
    wrong_vault.vault = VaultId::new("vault-2");
    assert!(matches!(
        verifier.verify_and_accept(&signed(&admin, 9), &wrong_vault, DURING),
        VerificationOutcome::Refused(_)
    ));
    assert_eq!(
        verifier.checkpoint(),
        None,
        "a refused policy must not create a checkpoint"
    );

    // Once a valid policy is accepted, a later refusal still leaves it alone.
    assert!(
        verifier
            .verify_and_accept(&signed(&admin, 5), &request(), DURING)
            .is_verified()
    );
    assert!(matches!(
        verifier.verify_and_accept(&signed(&admin, 9), &wrong_vault, DURING),
        VerificationOutcome::Refused(_)
    ));
    assert_eq!(verifier.checkpoint().unwrap().revision(), 5);
}

#[test]
fn a_valid_newer_policy_advances_the_checkpoint() {
    let admin = AdminSigningKey::generate();
    let mut verifier = verifier(&admin, None);

    assert!(
        verifier
            .verify_and_accept(&signed(&admin, 5), &request(), DURING)
            .is_verified()
    );
    assert_eq!(verifier.checkpoint().unwrap().revision(), 5);

    let outcome = verifier.verify_and_accept(&signed(&admin, 6), &request(), DURING);
    assert_eq!(
        outcome.freshness(),
        Some(Freshness::Checked { checkpoint: 5 }),
        "the outcome must say which checkpoint it was checked against"
    );
    assert_eq!(verifier.checkpoint().unwrap().revision(), 6);

    // The checkpoint names the policy it accepted, not just a number.
    let accepted = signed(&admin, 6);
    assert!(
        verifier
            .checkpoint()
            .unwrap()
            .matches_digest(&accepted.digest().unwrap())
    );
}

// ---------------------------------------------------------------------------
// Criterion 12 — no checkpoint means freshness is unavailable
// ---------------------------------------------------------------------------

#[test]
fn with_no_checkpoint_freshness_is_reported_unavailable_and_not_a_plain_success() {
    let admin = AdminSigningKey::generate();
    let outcome = verifier(&admin, None).verify(&signed(&admin, 5), &request(), DURING);

    // A distinct arm, not a success with a footnote: a caller that handled only
    // `Fresh` and `Refused` would not compile against this.
    match outcome {
        VerificationOutcome::Stale {
            revision,
            freshness,
        } => {
            assert_eq!(revision, 5);
            assert_eq!(freshness, Freshness::Unavailable);
        }
        other => panic!("a host with no checkpoint must report staleness, got {other:?}"),
    }
    assert!(!matches!(
        verifier(&admin, None).verify(&signed(&admin, 5), &request(), DURING),
        VerificationOutcome::Fresh { .. }
    ));
}

// ---------------------------------------------------------------------------
// Criteria 14, 15 — rotation
// ---------------------------------------------------------------------------

/// Resolve the recipient key a mint would seal to: the trusted record's.
///
/// This is the "future minting" the rotation must change, and it deliberately
/// reads the *store*, not the artifact.
fn recipient_for_minting(store: &TrustStore, agent: &AgentId) -> [u8; 32] {
    let identity = ActorId::Agent(*agent);
    store
        .get(&identity)
        .expect("the agent is enrolled")
        .recipient_key()
        .to_bytes()
}

fn enrol_agent(
    admin: &AdminSigningKey,
    store: &mut TrustStore,
    keys: &AgentKeys,
    suffix: &str,
) -> EnrollmentRecord {
    let agent_id = ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap();
    let unsigned = keys
        .enrol(
            agent_id,
            KeyId::new(format!("agent-7-ed25519-{suffix}")),
            KeyId::new(format!("agent-7-x25519-{suffix}")),
        )
        .unwrap();
    let record = admin
        .sign_enrolment(unsigned, KeyId::new(ADMIN_ID))
        .unwrap();
    store
        .import(
            &EnrollmentRecordWire::from_record(&record),
            record.fingerprint(),
        )
        .unwrap();
    record
}

#[test]
fn rotation_changes_what_a_future_mint_seals_to() {
    let admin = AdminSigningKey::generate();
    let mut store = TrustStore::new(admin.verifying_public());
    let agent = ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap();

    let first = enrol_agent(&admin, &mut store, &AgentKeys::generate(), "1");
    let before = recipient_for_minting(&store, &agent);
    assert_eq!(before, first.recipient_key().to_bytes());

    let new_keys = AgentKeys::generate();
    let unsigned = new_keys
        .enrol(
            agent,
            KeyId::new("agent-7-ed25519-2"),
            KeyId::new("agent-7-x25519-2"),
        )
        .unwrap();
    let next = admin
        .sign_enrolment(unsigned, KeyId::new(ADMIN_ID))
        .unwrap();
    let rotation = store.rotate(&next, DURING).unwrap();

    // The fingerprint was recomputed, not carried over.
    assert_ne!(
        rotation.current.fingerprint(),
        rotation.previous.fingerprint()
    );
    assert_eq!(rotation.identity, ActorId::Agent(agent));

    // A mint after the rotation seals to the new verified key.
    let after = recipient_for_minting(&store, &agent);
    assert_eq!(after, next.recipient_key().to_bytes());
    assert_ne!(after, before);
}

#[test]
fn a_rotation_to_the_enrolment_already_trusted_is_refused() {
    let admin = AdminSigningKey::generate();
    let mut store = TrustStore::new(admin.verifying_public());

    let current = enrol_agent(&admin, &mut store, &AgentKeys::generate(), "1");

    // Re-presenting the trusted enrolment is not a rotation: accepting it would
    // push a duplicate into `retired` and report that something changed.
    assert!(matches!(
        store.rotate(&current, DURING).unwrap_err(),
        ksp_identity::EnrolmentError::RotationUnchanged
    ));
    assert!(store.retired(current.identity()).is_empty());

    // Rotating an identity this store has never trusted is refused too, and
    // names the identity rather than a generic failure.
    let mut other = TrustStore::new(admin.verifying_public());
    assert!(matches!(
        other.rotate(&current, DURING).unwrap_err(),
        ksp_identity::EnrolmentError::NotTrusted { .. }
    ));
}

#[test]
fn after_rotation_the_old_key_and_the_old_artifact_still_work() {
    // SC-018, asserted so that a future change to it is a decision and not an
    // accident. The old pair is built here from a secret this test holds, so the
    // agreement can actually be recomputed after the rotation.
    let old_secret = x25519_dalek::StaticSecret::from([7u8; 32]);
    let old_public = x25519_dalek::PublicKey::from(&old_secret);

    let admin = AdminSigningKey::generate();
    let mut store = TrustStore::new(admin.verifying_public());
    let agent = ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap();

    let unsigned = UnsignedEnrolment::bind(
        ActorId::Agent(agent),
        SigningSecretKey::generate().verifying_public(),
        ksp_identity::RecipientPublicKey::from_bytes(old_public.to_bytes()),
        KeyId::new("agent-7-ed25519-1"),
        KeyId::new("agent-7-x25519-1"),
    )
    .unwrap();
    let old_record = admin
        .sign_enrolment(unsigned, KeyId::new(ADMIN_ID))
        .unwrap();
    store
        .import(
            &EnrollmentRecordWire::from_record(&old_record),
            old_record.fingerprint(),
        )
        .unwrap();

    // The artifact: a peer's ephemeral key agrees with the old recipient key.
    let peer = x25519_dalek::StaticSecret::from([11u8; 32]);
    let sealed_to_old = peer.diffie_hellman(&old_public);

    // Rotate to fresh keys.
    let new_keys = AgentKeys::generate();
    let new_unsigned = new_keys
        .enrol(
            agent,
            KeyId::new("agent-7-ed25519-2"),
            KeyId::new("agent-7-x25519-2"),
        )
        .unwrap();
    let next = admin
        .sign_enrolment(new_unsigned, KeyId::new(ADMIN_ID))
        .unwrap();
    store.rotate(&next, DURING).unwrap();

    // The old key still produces the same shared secret: rotation revoked
    // nothing that was already captured.
    let reopened = old_secret.diffie_hellman(&x25519_dalek::PublicKey::from(&peer));
    assert_eq!(reopened.as_bytes(), sealed_to_old.as_bytes());

    // And the new key is a different pair, so "future minting uses the new key"
    // is a real change rather than a relabelling.
    assert_ne!(
        next.recipient_key().to_bytes(),
        old_record.recipient_key().to_bytes()
    );

    // The store keeps the old record, so the old artifact is still attributable.
    assert_eq!(store.retired(&ActorId::Agent(agent)), &[old_record]);
}

// ---------------------------------------------------------------------------
// Criterion 16 — a trust anchor read from the artifact is never used
// ---------------------------------------------------------------------------

#[test]
fn a_self_signed_policy_naming_its_own_key_is_rejected() {
    let admin = AdminSigningKey::generate();
    let attacker = AdminSigningKey::generate();

    // The attacker signs a perfectly valid policy with their own key, and names
    // that key's ID. Internally consistent, and worth nothing here.
    let policy = Policy::new(&attacker, KeyId::new("attacker-1"), body(5)).unwrap();
    assert!(
        policy.verify_issuer(&attacker.verifying_public()),
        "the attacker's signature really is valid over their own policy"
    );

    assert_eq!(
        assert_refused(verifier(&admin, None).verify(&policy, &request(), DURING)),
        PolicyRefusal::IssuerNotPinned {
            presented: "attacker-1".to_string()
        }
    );

    // A host with nothing pinned refuses everything rather than trusting the
    // policy's own key.
    let empty = PolicyVerifier::new(TrustAnchors::new(), None);
    assert!(matches!(
        assert_refused(empty.verify(&policy, &request(), DURING)),
        PolicyRefusal::IssuerNotPinned { .. }
    ));
}

// ---------------------------------------------------------------------------
// Criterion 17 — a fixed-order encoding, pinned by a golden fixture
// ---------------------------------------------------------------------------

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// The body the golden fixture was generated from.
///
/// Every value is fixed and no key material is involved, so the bytes are a
/// function of the struct definition alone.
fn pinned_body() -> PolicyBody {
    PolicyBody::new(
        7,
        VaultId::new("vault-1"),
        ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
        TrustedEnrolmentKeys {
            signing_key: ksp_identity::VerifyingPublicKey::from_bytes([1u8; 32]).unwrap(),
            recipient_key: ksp_identity::RecipientPublicKey::from_bytes([2u8; 32]),
            signing_key_id: KeyId::new("alice-ed25519-1"),
            recipient_key_id: KeyId::new("alice-x25519-1"),
        },
        vec![OpaqueSecretId::new("secret-1")],
        vec![ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap()],
        MAX_USER_TTL,
        MAX_AGENT_TTL,
        NOT_BEFORE,
        NOT_AFTER,
    )
}

#[test]
fn the_policy_body_encoding_is_pinned_by_a_golden_fixture() {
    let encoded = ksp_types::cbor::encode(&pinned_body()).unwrap();
    let expected = std::fs::read(fixture("policy-body.cbor")).unwrap();
    assert_eq!(
        encoded, expected,
        "the policy body encoding changed; if that is deliberate, regenerate \
         tests/fixtures/policy-body.cbor and say why in the commit"
    );

    // A fixed-order struct, not a map: decoding it back gives the same struct,
    // and the bytes start with a map header whose entries are in declaration
    // order, so a reordering of the fields is a different signature preimage.
    let decoded: PolicyBody = ksp_types::cbor::decode(&encoded).unwrap();
    assert_eq!(decoded, pinned_body());
}

/// Regenerate the committed fixture after an intentional encoding change.
#[test]
#[ignore = "regenerates the golden fixture; run deliberately"]
fn regenerate_golden_fixture() {
    std::fs::write(
        fixture("policy-body.cbor"),
        ksp_types::cbor::encode(&pinned_body()).unwrap(),
    )
    .unwrap();
}

#[test]
fn a_policy_round_trips_through_the_store_form() {
    let admin = AdminSigningKey::generate();
    let policy = signed(&admin, 5);
    let bytes = encode_policy(&policy).unwrap();
    let back = decode_policy(&bytes).unwrap();
    assert_eq!(back, policy);
    assert!(back.verify_issuer(&admin.verifying_public()));

    // Bytes that are not a policy are malformed, which is a different outcome
    // from a policy that says the wrong thing.
    assert!(matches!(
        decode_policy(b"not a policy").unwrap_err(),
        PolicyRefusal::Malformed { .. }
    ));
}

// ---------------------------------------------------------------------------
// The checkpoint and the scope/path/version checks
// ---------------------------------------------------------------------------

#[test]
fn a_delivery_that_names_one_scope_and_writes_at_another_is_rejected() {
    let admin = AdminSigningKey::generate();
    let policy = signed(&admin, 5);

    let mut wrong_scope = request();
    wrong_scope.scope = "agent-8".to_string();
    assert_eq!(
        assert_refused(verifier(&admin, None).verify(&policy, &wrong_scope, DURING)),
        PolicyRefusal::Scope {
            expected: Level::Agent(agent_seven()).path_segment(),
            found: "agent-8".to_string()
        }
    );

    let mut wrong_path = request();
    wrong_path.path = "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/user/secret-1/1".to_string();
    assert_eq!(
        assert_refused(verifier(&admin, None).verify(&policy, &wrong_path, DURING)),
        PolicyRefusal::Path {
            expected: "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-00000000-0000-4000-8000-000000000007/secret-1/1".to_string(),
            found: "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/user/secret-1/1".to_string()
        }
    );

    let mut zero_version = request();
    zero_version.record_version = RecordVersion(0);
    zero_version.path = "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-00000000-0000-4000-8000-000000000007/secret-1/0".to_string();
    assert_eq!(
        assert_refused(verifier(&admin, None).verify(&policy, &zero_version, DURING)),
        PolicyRefusal::Version { found: 0 }
    );
}

#[test]
fn an_unrecognised_policy_version_is_rejected_before_its_fields_are_read() {
    let admin = AdminSigningKey::generate();
    let policy = signed(&admin, 5);

    let mut body_value = serde_json::to_value(policy.body()).unwrap();
    body_value["version"] = serde_json::json!(2);
    let mut policy_value = serde_json::to_value(&policy).unwrap();
    policy_value["body"] = body_value;
    let future: Policy = serde_json::from_value(policy_value).unwrap();

    assert!(matches!(
        assert_refused(verifier(&admin, None).verify(&future, &request(), DURING)),
        PolicyRefusal::UnsupportedVersion {
            found: 2,
            expected: 1
        }
    ));
}

// ---------------------------------------------------------------------------
// Review v1, Issues 2 and 4
// ---------------------------------------------------------------------------

/// Issue 2: the policy binds the user's enrolment keys, so it must be able to
/// say whether a record is the one it trusts.
#[test]
fn the_policy_says_which_enrolment_it_trusts() {
    let admin = AdminSigningKey::generate();
    let trusted = trusted_keys();

    let user_vault = ksp_identity::UserVault::generate();
    let identity = ActorId::User(user());
    let unsigned = UnsignedEnrolment::bind(
        identity,
        user_vault.signing_public(),
        user_vault.recipient_public(),
        trusted.signing_key_id.clone(),
        trusted.recipient_key_id.clone(),
    )
    .unwrap();
    let record = admin
        .sign_enrolment(unsigned, KeyId::new(ADMIN_ID))
        .unwrap();

    let policy = Policy::new(
        &admin,
        KeyId::new(ADMIN_ID),
        PolicyBody::new(
            5,
            vault(),
            user(),
            TrustedEnrolmentKeys {
                signing_key: user_vault.signing_public(),
                recipient_key: user_vault.recipient_public(),
                signing_key_id: trusted.signing_key_id.clone(),
                recipient_key_id: trusted.recipient_key_id.clone(),
            },
            vec![secret()],
            vec![ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap()],
            MAX_USER_TTL,
            MAX_AGENT_TTL,
            NOT_BEFORE,
            NOT_AFTER,
        ),
    )
    .unwrap();

    assert!(policy.trusts(&record));

    // A record for the same identity with a substituted recipient key is not the
    // one this policy trusts, even though the same admin signed it.
    let impostor = ksp_identity::UserVault::generate();
    let swapped = UnsignedEnrolment::bind(
        identity,
        user_vault.signing_public(),
        impostor.recipient_public(),
        trusted.signing_key_id,
        trusted.recipient_key_id,
    )
    .unwrap();
    let swapped = admin.sign_enrolment(swapped, KeyId::new(ADMIN_ID)).unwrap();
    assert!(!policy.trusts(&swapped));
}

/// Issue 4: a policy that expires before it starts denies everything at runtime
/// and reads like a clock problem. Refuse it where the mistake was made.
#[test]
fn a_policy_whose_validity_interval_is_inverted_is_refused_at_construction() {
    let admin = AdminSigningKey::generate();

    let inverted = PolicyBody::new(
        5,
        vault(),
        user(),
        trusted_keys(),
        vec![secret()],
        vec![ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap()],
        MAX_USER_TTL,
        MAX_AGENT_TTL,
        NOT_AFTER,
        NOT_BEFORE,
    );
    assert_eq!(
        Policy::new(&admin, KeyId::new(ADMIN_ID), inverted).unwrap_err(),
        PolicyRefusal::ValidityInterval {
            not_before: NOT_AFTER,
            not_after: NOT_BEFORE
        }
    );

    // A zero-length interval contains no instant, so it is refused too.
    let empty = PolicyBody::new(
        5,
        vault(),
        user(),
        trusted_keys(),
        vec![secret()],
        vec![ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap()],
        MAX_USER_TTL,
        MAX_AGENT_TTL,
        NOT_BEFORE,
        NOT_BEFORE,
    );
    assert!(matches!(
        Policy::new(&admin, KeyId::new(ADMIN_ID), empty).unwrap_err(),
        PolicyRefusal::ValidityInterval { .. }
    ));
}

#[test]
fn a_publication_level_is_never_a_delivery_target() {
    // The fourth level exists so a publication does not have to widen `admin/`.
    // It is a read namespace: a delivery *into* it, or *from* it, would make the
    // publication a share target and put the admin's own level back in play.
    let admin = AdminSigningKey::generate();
    let policy = signed(&admin, 5);

    for (source, target) in [
        (Level::User, Level::Granted),
        (Level::Granted, Level::Agent(agent_seven())),
        (Level::Granted, Level::Granted),
    ] {
        let mut refused_request = request();
        refused_request.source = source.clone();
        refused_request.target = target.clone();
        refused_request.scope = target.path_segment();
        refused_request.path = format!(
            "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/{}/secret-1/1",
            target.path_segment()
        );
        let refusal =
            assert_refused(verifier(&admin, None).verify(&policy, &refused_request, DURING));
        let message = refusal.to_string();
        assert!(
            matches!(refusal, PolicyRefusal::LevelPair { .. })
                || matches!(refusal, PolicyRefusal::NotADeliveryTarget { .. }),
            "{source} -> {target} is refused as a level refusal: {message}"
        );
        assert!(
            message.contains("agent-<principal-uuid>"),
            "the refusal names the accepted target: {message}"
        );
    }
}
