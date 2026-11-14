//! The capability acceptance record and the audit operation that carries it.
//!
//! Misfit N: the acceptance of an unenforced capability must be **durable**. It
//! reaches the audit log under its own operation, so a later reader — a
//! colleague, an auditor, a future operator — can tell an accepted absence from
//! an unnoticed one (NFR-009).
//!
//! # The record carries no secret, and that is structural
//!
//! FR-046 requires the writers to be *structurally* unable to place a secret
//! in a record. So the capability acceptance is not a free-text blob: it is
//! three typed fields — the capability, the adapter's name, and the guarantee
//! level — and every one of them is a public fact.
//!
//! The adapter name is a name from the closed set. The guarantee level is one
//! of three words. The capability is one of two. There is no field a path or a
//! passphrase could be formatted into.
//!
//! # The operation is a variant on a closed enum, not a string
//!
//! The enum's own documentation says that "adding an operation is a deliberate
//! change here rather than a string at a call site". So the record names
//! `AuditOperation::Capability` — a variant the compiler checks — rather than
//! putting a free-text operation where a secret could hide.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_types::GuaranteeLevel;
use ksp_types::evidence::{
    AuditComponent, AuditOperation, AuditRecord, AuditTarget, CapabilityAcceptance, Outcome,
};
use ksp_types::metadata::PrincipalId;

/// The administrator principal every record in this file names.
const ADMIN: &str = "00000000-0000-4000-8000-000000000001";

/// An adapter name from the closed set.
fn adapter(name: &str) -> ksp_types::AdapterName {
    ksp_types::AdapterName::parse(name).expect("the name is in the closed set")
}

/// A record for an accepted capability.
fn record(acceptance: CapabilityAcceptance) -> AuditRecord {
    AuditRecord {
        actor: PrincipalId::parse(ADMIN).expect("the admin principal parses"),
        signer_key_id: "admin-1".to_string(),
        component: AuditComponent::CommandLine,
        operation: AuditOperation::Capability,
        target: Some(AuditTarget::Deployment),
        outcome: Outcome::Success,
        exit_code: 0,
        observed_at: 1_700_000_000,
        prev_digest: None,
        acceptance: None,
    }
    .with_acceptance(acceptance)
}

// ---------------------------------------------------------------------------
// The record names the capability, the adapter and the guarantee
// ---------------------------------------------------------------------------

/// The acceptance names the capability, the adapter and the guarantee level.
///
/// The three facts are all needed: the capability says *what*, the adapter
/// says *which mechanism*, and the level says *how far to trust it*.
#[test]
fn the_acceptance_names_the_capability_the_adapter_and_the_level() {
    let acceptance = CapabilityAcceptance::new(
        ksp_types::HostCapability::MemoryBarrier,
        adapter("mlock"),
        GuaranteeLevel::None,
    );

    assert_eq!(
        acceptance.capability,
        ksp_types::HostCapability::MemoryBarrier,
        "the acceptance must name the capability"
    );
    assert_eq!(
        acceptance.adapter.as_str(),
        "mlock",
        "the acceptance must name the adapter that ran"
    );
    assert_eq!(
        acceptance.guarantee,
        GuaranteeLevel::None,
        "the acceptance must name the guarantee level"
    );
}

/// The acceptance renders the three facts, and nothing else.
///
/// The rendering is the durable form: it is what a reader of the audit log
/// sees. It must carry the level even when the level is `none` — an accepted
/// absence that reads as an enforced capability is the failure Misfit H and
/// Misfit N are about.
#[test]
fn the_acceptance_renders_its_three_facts() {
    let acceptance = CapabilityAcceptance::new(
        ksp_types::HostCapability::PathConfinement,
        adapter("portable_confinement"),
        GuaranteeLevel::None,
    );

    let text = acceptance.to_string();
    assert!(
        text.contains("path confinement"),
        "the rendering must name the capability; got: {text}"
    );
    assert!(
        text.contains("portable_confinement"),
        "the rendering must name the adapter; got: {text}"
    );
    assert!(
        text.contains("none"),
        "the rendering must name the guarantee level; got: {text}"
    );
}

/// A `none` guarantee renders as `none`, in the same terms as `full`.
///
/// FR-038: the difference must be the level and not the presence of a row.
#[test]
fn a_none_guarantee_renders_in_the_same_terms_as_a_full_one() {
    let none = CapabilityAcceptance::new(
        ksp_types::HostCapability::MemoryBarrier,
        adapter("mlock"),
        GuaranteeLevel::None,
    );
    let full = CapabilityAcceptance::new(
        ksp_types::HostCapability::MemoryBarrier,
        adapter("memfd_secret"),
        GuaranteeLevel::Full,
    );

    let none_text = none.to_string();
    let full_text = full.to_string();

    assert!(none_text.contains("none"), "{none_text}");
    assert!(full_text.contains("full"), "{full_text}");
    // Both name the capability in the same words.
    for text in [&none_text, &full_text] {
        assert!(
            text.contains("memory barrier"),
            "both renderings must name the capability in the same terms; got: {text}"
        );
    }
    assert_ne!(
        none_text, full_text,
        "a `none` acceptance and a `full` one must render differently"
    );
}

// ---------------------------------------------------------------------------
// The boundary — the record carries no secret-bearing field
// ---------------------------------------------------------------------------

/// The acceptance has no field a secret could be put in.
///
/// The type-level assertion: the acceptance is three fields, and each is a
/// public fact. There is no string the operator's passphrase could be
/// formatted into, and no path.
#[test]
fn the_acceptance_carries_no_secret_bearing_field() {
    // The adapter name is a name from the closed set, so it cannot be a
    // passphrase however the caller constructs it.
    let acceptance = CapabilityAcceptance::for_adapter(
        ksp_types::HostCapability::MemoryBarrier,
        "mlock",
        GuaranteeLevel::None,
    )
    .expect("`mlock` is in the closed set");

    assert!(
        ksp_types::AdapterName::ALL.contains(&acceptance.adapter.as_str()),
        "the adapter must be a name from the closed set; got: {}",
        acceptance.adapter
    );

    // And a name outside the closed set is refused rather than recorded, so a
    // secret could not be formatted into the adapter field.
    assert!(
        CapabilityAcceptance::for_adapter(
            ksp_types::HostCapability::MemoryBarrier,
            "correct-horse-battery-staple",
            GuaranteeLevel::Full,
        )
        .is_none(),
        "an adapter name outside the closed set must be refused, or a secret \\
         could be formatted into the record"
    );
}

/// The acceptance's rendering carries no path and no secret.
///
/// The rendered acceptance is what a reader of the audit log sees. The
/// capability's name and the adapter's name are the only identifiers in it — no
/// path, no value.
#[test]
fn the_acceptance_rendering_carries_no_path_and_no_secret() {
    let acceptance = CapabilityAcceptance::for_adapter(
        ksp_types::HostCapability::MemoryBarrier,
        "mlock",
        GuaranteeLevel::None,
    )
    .expect("`mlock` is in the closed set");

    let text = acceptance.to_string();
    assert!(
        !text.contains('/'),
        "the acceptance must carry no path; got: {text}"
    );
    for marker in ["secret", "value", "token", "password", "passphrase", "key"] {
        assert!(
            !text.contains(marker),
            "the acceptance must carry no field that could hold a {marker}; got: {text}"
        );
    }
}

/// The acceptance survives the record's own projection.
///
/// The chain projects a record's fields, and a field whose name announces
/// material is refused. The capability acceptance must not trip that: it
/// carries public facts.
#[test]
fn the_acceptance_is_projected_as_public_facts() {
    let acceptance = CapabilityAcceptance::for_adapter(
        ksp_types::HostCapability::MemoryBarrier,
        "mlock",
        GuaranteeLevel::None,
    )
    .expect("`mlock` is in the closed set");
    let record = record(acceptance);

    // The record carries the acceptance, and the acceptance's fields are the
    // three public facts.
    let carried = record
        .acceptance()
        .expect("the record carries its acceptance");
    assert_eq!(carried.adapter.as_str(), "mlock");
    assert_eq!(carried.guarantee, GuaranteeLevel::None);
    assert_eq!(carried.capability, ksp_types::HostCapability::MemoryBarrier);
}

// ---------------------------------------------------------------------------
// The closure is structural, not a convention
// ---------------------------------------------------------------------------

/// A document naming an adapter outside the closed set is refused.
///
/// The acceptance is decoded from the audit chain, so the decode path is a
/// way in. A `String` field would accept any text there; the closed type
/// refuses a name outside the set at the point it is read.
///
/// This is the test that fails when the field is loosened back to a string.
#[test]
fn a_document_naming_an_adapter_outside_the_closed_set_is_refused() {
    let document = r#"{
      "capability": "memory_barrier",
      "adapter": "correct-horse-battery-staple",
      "guarantee": "full"
    }"#;

    let decoded: Result<CapabilityAcceptance, _> = serde_json::from_str(document);

    assert!(
        decoded.is_err(),
        "a document naming an adapter outside the closed set must be refused, \
         or a secret could be formatted into the record; decoded: {decoded:?}"
    );
}

/// The acceptance's adapter field is the closed type itself.
///
/// The claim that every field is a public fact is a claim about the *type*.
/// The field holds an `AdapterName`, so no value of this type can name an
/// adapter outside the set — not one built by a constructor, and not one
/// decoded from a document.
#[test]
fn the_adapter_field_is_the_closed_type() {
    let acceptance = CapabilityAcceptance::for_adapter(
        ksp_types::HostCapability::MemoryBarrier,
        "mlock",
        GuaranteeLevel::None,
    )
    .expect("`mlock` is in the closed set");

    // The field is an `AdapterName`, so its discriminant is one of the five
    // kinds and its identifier is one of the five names.
    assert_eq!(acceptance.adapter.kind(), ksp_types::AdapterKind::Mlock);
    assert!(
        ksp_types::AdapterName::ALL.contains(&acceptance.adapter.as_str()),
        "the adapter must be a name from the closed set; got: {}",
        acceptance.adapter
    );
}

/// The acceptance round-trips through its own encoding.
///
/// A record decoded from the chain has to carry the same facts the writer
/// encoded, or a reader cannot trust what the chain says.
#[test]
fn the_acceptance_round_trips_through_its_own_encoding() {
    let acceptance = CapabilityAcceptance::for_adapter(
        ksp_types::HostCapability::PathConfinement,
        "landlock",
        GuaranteeLevel::Full,
    )
    .expect("`landlock` is in the closed set");

    let encoded = serde_json::to_string(&acceptance).expect("the acceptance encodes");
    let decoded: CapabilityAcceptance =
        serde_json::from_str(&encoded).expect("the acceptance decodes");

    assert_eq!(decoded, acceptance);
}
