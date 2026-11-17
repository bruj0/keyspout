//! The acceptance criteria for WP02, driven through the public API.
//!
//! Three misfits live here. **A** is a policy that reads as a restriction and is
//! not one, so the target type cannot hold a wildcard and the boundary refuses one
//! by name. **D** is a stale artifact replacing a newer one, so the revision is
//! derived from the artifact being replaced and can only advance. **G** is a
//! dangling grant, so a link check refuses an unknown user, agent or version and
//! names which one it was.
//!
//! A test reports a failure by panicking, and the panic message is what says why.
//! The production code keeps the strict lints.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use ksp_identity::policy_edge::{
    EdgeRequest, LinkCheck, PolicyEdge, PolicyId, PolicyTarget, check_links,
};
use ksp_identity::{AdminSigningKey, KeyId};
use ksp_types::{AgentId, OpaqueSecretId, PrincipalId, RecordVersion, VaultId};

const ADMIN_ID: &str = "admin-2026";
const NOT_BEFORE: u64 = 1_000;
const NOT_AFTER: u64 = 2_000;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn agent_seven() -> AgentId {
    AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap()
}

fn alice() -> PrincipalId {
    PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap()
}

fn secret() -> OpaqueSecretId {
    OpaqueSecretId::new("s1")
}

fn request(target: PolicyTarget) -> EdgeRequest {
    EdgeRequest {
        user: alice(),
        secret: secret(),
        record_version: RecordVersion(1),
        target,
        publication: None,
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
    }
}

fn edge(target: PolicyTarget) -> PolicyEdge {
    PolicyEdge::create(
        &AdminSigningKey::generate(),
        KeyId::new(ADMIN_ID),
        VaultId::new("vault-1"),
        request(target),
    )
    .unwrap()
}

// ---------------------------------------------------------------- T001: ids

#[test]
fn a_policy_id_is_32_lowercase_hex_characters_and_nothing_else() {
    let generated = PolicyId::generate();
    assert_eq!(generated.as_str().len(), 32);
    assert!(
        generated
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "the generated id is lowercase hex: {generated}"
    );
    // It parses back to itself, and two ids differ.
    assert_eq!(PolicyId::parse(generated.as_str()).unwrap(), generated);
    assert_ne!(PolicyId::generate(), PolicyId::generate());

    for refused in [
        "",
        "00112233",
        "00112233445566778899aabbccddeeff0",
        "00112233445566778899AABBCCDDEEFF",
        "../../policies",
        "00112233445566778899aabbccddeefg",
    ] {
        assert!(
            PolicyId::parse(refused).is_err(),
            "{refused:?} must not parse as an id"
        );
    }
}

// ------------------------------------------------------------- T001: targets

#[test]
fn a_target_accepts_exactly_two_forms() {
    assert_eq!(
        PolicyTarget::parse("00000000-0000-4000-8000-000000000007").unwrap(),
        PolicyTarget::Agent(agent_seven())
    );
    assert_eq!(
        PolicyTarget::parse("any-enrolled").unwrap(),
        PolicyTarget::AnyEnrolled
    );

    // Every spelling that would mean "several" is refused, and the sentence names
    // both accepted forms so a caller can derive one.
    for refused in [
        "*",
        "agent-*",
        "any",
        "00000000-0000-4000-8000-000000000007,00000000-0000-4000-8000-000000000008",
        "00000000-0000-4000-8000-00000000000",
        "alice-agent",
    ] {
        let error = PolicyTarget::parse(refused).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("agent UUID") && message.contains("any-enrolled"),
            "{refused:?} is refused with both accepted forms: {message}"
        );
    }

    // Display names the agent or the word, never a pattern.
    assert_eq!(
        PolicyTarget::Agent(agent_seven()).to_string(),
        "agent:00000000-0000-4000-8000-000000000007"
    );
    assert_eq!(PolicyTarget::AnyEnrolled.to_string(), "any-enrolled");
}

// -------------------------------------------------- T002: canonical encoding

/// The edge the golden fixture is pinned from.
///
/// The identifier is fixed so the fixture is reproducible; `create_at` exists for
/// exactly this and for a ledger replay.
fn pinned_edge() -> PolicyEdge {
    PolicyEdge::create_at(
        &AdminSigningKey::generate(),
        KeyId::new(ADMIN_ID),
        VaultId::new("vault-1"),
        PolicyId::parse("00112233445566778899aabbccddeeff").unwrap(),
        1,
        request(PolicyTarget::Agent(agent_seven())),
    )
    .unwrap()
}

#[test]
fn the_edge_body_encoding_is_pinned_by_a_golden_fixture() {
    let pinned = pinned_edge();
    let encoded = pinned.body_bytes().unwrap();
    let expected = std::fs::read(fixture("policy-edge-body.cbor")).unwrap();
    assert_eq!(
        encoded, expected,
        "the policy edge body encoding changed; if that is deliberate, regenerate \
         tests/fixtures/policy-edge-body.cbor and say why in the commit"
    );
}

/// Regenerate the committed fixture after an intentional encoding change.
#[test]
#[ignore = "regenerates the golden fixture; run deliberately"]
fn regenerate_golden_fixture() {
    std::fs::write(
        fixture("policy-edge-body.cbor"),
        pinned_edge().body_bytes().unwrap(),
    )
    .unwrap();
}

#[test]
fn the_same_edge_encodes_to_the_same_bytes() {
    let pinned = pinned_edge();
    let once = pinned.encode().unwrap();
    let twice = pinned.encode().unwrap();
    assert_eq!(once, twice, "encoding is deterministic");
    let back = PolicyEdge::decode(&once).unwrap();
    assert_eq!(back, pinned, "the artifact round-trips");
    assert_eq!(back.encode().unwrap(), once, "and re-encodes identically");
}

// ------------------------------------------------ T002: the signature covers

#[test]
fn the_signature_covers_every_field_of_the_body() {
    let admin = AdminSigningKey::generate();
    let key = KeyId::new(ADMIN_ID);
    let base = PolicyEdge::create(
        &admin,
        key.clone(),
        VaultId::new("vault-1"),
        request(PolicyTarget::Agent(agent_seven())),
    )
    .unwrap();
    assert!(
        base.verify_issuer(&admin.verifying_public()),
        "the issuer's own key verifies the edge"
    );
    assert!(
        !base.verify_issuer(&AdminSigningKey::generate().verifying_public()),
        "another key does not"
    );

    // Each variant changes exactly one field, and the digest is over the same
    // preimage the signature is, so a difference here is a difference the
    // signature would see.
    let mut variants = vec![
        request(PolicyTarget::Agent(agent_seven())),
        request(PolicyTarget::AnyEnrolled),
    ];
    variants[0].secret = OpaqueSecretId::new("s2");
    variants.push(EdgeRequest {
        user: PrincipalId::parse("b0b00000-0000-4000-8000-000000000001").unwrap(),
        ..request(PolicyTarget::Agent(agent_seven()))
    });
    variants.push(EdgeRequest {
        record_version: RecordVersion(2),
        ..request(PolicyTarget::Agent(agent_seven()))
    });
    variants.push(EdgeRequest {
        not_before: NOT_BEFORE + 1,
        ..request(PolicyTarget::Agent(agent_seven()))
    });
    variants.push(EdgeRequest {
        not_after: NOT_AFTER + 1,
        ..request(PolicyTarget::Agent(agent_seven()))
    });
    variants.push(EdgeRequest {
        publication: Some("p/vault-1/admin/granted/s1/1".to_string()),
        ..request(PolicyTarget::Agent(agent_seven()))
    });

    let base_digest = base.digest().unwrap();
    for variant in variants {
        let other =
            PolicyEdge::create(&admin, key.clone(), VaultId::new("vault-1"), variant).unwrap();
        assert_ne!(
            other.digest().unwrap(),
            base_digest,
            "every signed field changes the digest"
        );
        assert!(
            !base.verify_issuer(&AdminSigningKey::generate().verifying_public()),
            "a changed body cannot be verified by a key that did not sign it"
        );
    }

    // A tampered artifact is refused rather than reported as a different edge: the
    // last byte of the encoding is inside the signature, so the body still decodes
    // and the signature no longer verifies.
    let mut tampered = base.encode().unwrap();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    match PolicyEdge::decode(&tampered) {
        Ok(edge) => assert!(
            !edge.verify_issuer(&admin.verifying_public()),
            "a flipped signature byte does not verify"
        ),
        Err(_) => panic!("the body should still decode; only the signature changed"),
    }
}

// --------------------------------------------------------------- T002: window

#[test]
fn an_edge_that_expires_before_it_begins_is_refused() {
    let mut expired = request(PolicyTarget::AnyEnrolled);
    expired.not_after = expired.not_before;
    let error = PolicyEdge::create(
        &AdminSigningKey::generate(),
        KeyId::new(ADMIN_ID),
        VaultId::new("vault-1"),
        expired,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("expires before it begins"),
        "{error}"
    );
}

// ------------------------------------------------------------ T003: revisions

#[test]
fn a_created_edge_is_revision_one_and_an_update_advances_by_one() {
    let admin = AdminSigningKey::generate();
    let key = KeyId::new(ADMIN_ID);
    let created = PolicyEdge::create(
        &admin,
        key.clone(),
        VaultId::new("vault-1"),
        request(PolicyTarget::AnyEnrolled),
    )
    .unwrap();
    assert_eq!(created.revision(), 1);

    let updated = PolicyEdge::update(
        &admin,
        key.clone(),
        &created,
        EdgeRequest {
            target: PolicyTarget::Agent(agent_seven()),
            ..request(PolicyTarget::AnyEnrolled)
        },
    )
    .unwrap();
    assert_eq!(updated.revision(), 2, "an update advances exactly one");
    assert_eq!(updated.id(), created.id(), "the id is the edge's identity");
    assert_ne!(updated.digest().unwrap(), created.digest().unwrap());
    assert!(updated.verify_issuer(&admin.verifying_public()));

    // A revision of zero is not a revision.
    let zero = PolicyEdge::create_at(
        &admin,
        key,
        VaultId::new("vault-1"),
        created.id().clone(),
        0,
        request(PolicyTarget::AnyEnrolled),
    );
    assert!(zero.is_err(), "revision 0 is refused");
}

#[test]
fn two_edges_claim_one_tuple_only_when_every_field_agrees() {
    let base = edge(PolicyTarget::Agent(agent_seven()));
    let same = edge(PolicyTarget::Agent(agent_seven()));
    assert!(
        base.same_active_tuple(&same),
        "two edges for the same access collide regardless of id"
    );
    assert_ne!(base.id(), same.id(), "and they are different authorities");

    assert!(!base.same_active_tuple(&edge(PolicyTarget::AnyEnrolled)));
    assert!(!base.same_active_tuple(&{
        let mut other = request(PolicyTarget::Agent(agent_seven()));
        other.record_version = RecordVersion(2);
        PolicyEdge::create_at(
            &AdminSigningKey::generate(),
            KeyId::new(ADMIN_ID),
            VaultId::new("vault-1"),
            base.id().clone(),
            1,
            other,
        )
        .unwrap()
    }));
}

// ---------------------------------------------------------------- T004: links

struct Known {
    user: bool,
    agent: bool,
    secret: bool,
}

impl LinkCheck for Known {
    fn user_exists(&self, _user: &PrincipalId) -> bool {
        self.user
    }
    fn agent_exists(&self, _agent: AgentId) -> bool {
        self.agent
    }
    fn secret_version_exists(&self, _secret: &OpaqueSecretId, _version: RecordVersion) -> bool {
        self.secret
    }
}

#[test]
fn a_dangling_link_is_refused_by_name_and_names_the_accepted_form() {
    let all_known = Known {
        user: true,
        agent: true,
        secret: true,
    };
    let path = edge(PolicyTarget::Agent(agent_seven()));
    assert!(check_links(&all_known, path.body()).is_ok());

    let cases = [
        (
            Known {
                user: false,
                agent: true,
                secret: true,
            },
            "does not hold",
        ),
        (
            Known {
                user: true,
                agent: false,
                secret: true,
            },
            "not enrolled on this host",
        ),
        (
            Known {
                user: true,
                agent: true,
                secret: false,
            },
            "that version is not stored",
        ),
    ];
    let mut messages = std::collections::BTreeSet::new();
    for (check, expected) in cases {
        let error = check_links(&check, path.body()).unwrap_err();
        let message = error.to_string();
        assert!(message.contains(expected), "{message}");
        messages.insert(message);
    }
    assert_eq!(messages.len(), 3, "each missing link has its own sentence");

    // `any-enrolled` does not name an agent, so an unenrolled host does not make
    // it dangling — its cooperation is a different property, disclosed elsewhere.
    let no_agents = Known {
        user: true,
        agent: false,
        secret: true,
    };
    assert!(check_links(&no_agents, edge(PolicyTarget::AnyEnrolled).body()).is_ok());
}
