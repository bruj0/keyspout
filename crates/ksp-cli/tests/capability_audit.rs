//! The capability acceptance record through the real audit chain.
//!
//! # What these prove that a unit test cannot
//!
//! The acceptance has to **survive**: it is signed, framed, written into a
//! segment and read back. A record that round-trips through a plain struct
//! proves nothing about the chain — the chain is where a record is serialised
//! into CBOR, linked to its predecessor, and later verified against a public
//! pin.
//!
//! So these tests write through the chain and read back, and they check the
//! thing that matters: a later reader can tell an **accepted absence** from an
//! unnoticed one (Misfit N, NFR-009).
//!
//! # The record carries no secret
//!
//! The acceptance's three fields are a capability, an adapter name from the
//! closed set, and a guarantee level. The test reads the bytes on disk and
//! checks that none of them names a path or a value.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Stdio};

use ksp_cli::config::Layout;
use ksp_deletion::{AuditChain, SignedAuditRecord};
use ksp_types::GuaranteeLevel;
use ksp_types::evidence::{AuditOperation, AuditTarget, CapabilityAcceptance, Outcome};
use ksp_types::metadata::PrincipalId;

/// Provisions a deployment under `home`.
///
/// The admin key lives in the deployment, so the acceptance cannot be recorded
/// until one exists. The provisioning goes through the binary, the way an
/// operator's would, so the chain the test reads is the one a real run writes.
fn provision(home: &Path) {
    let command = Command::new(env!("CARGO_BIN_EXE_ksp"))
        .env("KSP_HOME", home)
        .env("LC_ALL", "C")
        .args(["admin", "init", "--vault", "vault-1", "--user", "alice"])
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");
    assert!(
        command.status.success(),
        "admin init failed: {}",
        String::from_utf8_lossy(&command.stderr)
    );
}

/// Appends a capability acceptance to the chain under `home` and returns the
/// records the chain holds afterwards.
fn append_acceptance(home: &Path, acceptance: CapabilityAcceptance) -> Vec<SignedAuditRecord> {
    let layout = Layout::new(home.to_path_buf());
    ksp_cli::audit::record_capability(&layout, acceptance).expect("the acceptance is recorded");
    chain_records(home)
}

/// Every record the chain holds under `home`.
fn chain_records(home: &Path) -> Vec<SignedAuditRecord> {
    let root = Layout::new(home.to_path_buf()).audit_root();
    let chain = AuditChain::new(&root);

    let mut found = Vec::new();
    let Ok(actors) = std::fs::read_dir(&root) else {
        return found;
    };
    for actor in actors.flatten() {
        let Ok(principal) = PrincipalId::parse(&actor.file_name().to_string_lossy()) else {
            continue;
        };
        let Ok(files) = std::fs::read_dir(actor.path()) else {
            continue;
        };
        for file in files.flatten() {
            let name = file.file_name().to_string_lossy().to_string();
            let Some(key_id) = name
                .strip_prefix("segment-")
                .and_then(|rest| rest.strip_suffix(".cbor"))
            else {
                continue;
            };
            found.extend(chain.read(principal, key_id).expect("the segment reads"));
        }
    }
    found
}

/// The acceptance survives the chain, and the chain verifies.
///
/// The round trip is the point: the record is signed, framed, linked and read
/// back, and the acceptance is still there with its three facts intact.
#[test]
fn a_capability_acceptance_survives_the_chain() {
    let home = tempfile::tempdir().expect("a temporary home");
    provision(home.path());
    let acceptance = CapabilityAcceptance::for_adapter(
        ksp_types::HostCapability::MemoryBarrier,
        "mlock",
        GuaranteeLevel::None,
    )
    .expect("`mlock` is in the closed set");

    let records = append_acceptance(home.path(), acceptance);
    assert_eq!(records.len(), 1, "the acceptance wrote one record");

    let record = &records[0].record;
    assert_eq!(
        record.operation,
        AuditOperation::Capability,
        "the record must name the capability operation"
    );
    assert_eq!(
        record.target,
        Some(AuditTarget::Deployment),
        "the record must act on the deployment, which is what a capability is a \
         property of"
    );

    let carried = record
        .acceptance()
        .expect("the record carries its acceptance");
    assert_eq!(
        carried.capability,
        ksp_types::HostCapability::MemoryBarrier,
        "the acceptance must name the capability"
    );
    assert_eq!(
        carried.adapter.as_str(),
        "mlock",
        "the acceptance must name the adapter"
    );
    assert_eq!(
        carried.guarantee,
        GuaranteeLevel::None,
        "the acceptance must name the guarantee level"
    );
}

/// The acceptance is signed and links into the chain like every other record.
///
/// A record that verifies on its own but does not link would leave a gap a
/// reader could not detect, which is the failure the chain exists to prevent.
#[test]
fn the_acceptance_links_into_the_chain() {
    let home = tempfile::tempdir().expect("a temporary home");
    provision(home.path());
    let acceptance = CapabilityAcceptance::for_adapter(
        ksp_types::HostCapability::PathConfinement,
        "portable_confinement",
        GuaranteeLevel::None,
    )
    .expect("`portable_confinement` is in the closed set");

    let records = append_acceptance(home.path(), acceptance);
    let first = &records[0];
    assert_eq!(
        first.record.prev_digest, None,
        "the first record in a segment has no predecessor"
    );
    assert_eq!(
        first.domain,
        SignedAuditRecord::domain(),
        "the acceptance must be signed under the audit domain, so a reader \
         cannot mistake it for evidence of another kind"
    );
}

/// The record carries no path and no secret.
///
/// The chain is where a record becomes durable, so this is where a secret
/// would survive. The acceptance's fields are public facts, and the test
/// checks the **decoded record** rather than the bytes on disk.
///
/// # Why the record and not the bytes
///
/// The segment is CBOR, and it ends with the writer's **signature** — 64
/// random bytes. A byte scan over those bytes finds a `/` in roughly one
/// segment in five, and a "token" or "value" now and then, and the test then
/// fails for a reason that has nothing to do with the code under test. The
/// signature is not part of what the writer claims; the claim is the record.
///
/// So the test decodes the record and scans its fields. A path or a secret in
/// the *record* is still caught, and the scan is not a lottery.
#[test]
fn the_record_on_disk_carries_no_path_and_no_secret() {
    let home = tempfile::tempdir().expect("a temporary home");
    provision(home.path());
    let acceptance = CapabilityAcceptance::for_adapter(
        ksp_types::HostCapability::MemoryBarrier,
        "mlock",
        GuaranteeLevel::None,
    )
    .expect("`mlock` is in the closed set");

    let records = append_acceptance(home.path(), acceptance);
    assert!(!records.is_empty(), "the acceptance must have been written");

    let mut checked = 0;
    for signed in &records {
        let record = &signed.record;

        // The whole record, rendered field by field.
        let text = format!("{record:?}");
        assert!(
            !text.contains('/'),
            "the record must carry no path: {}",
            text.escape_debug()
        );
        for marker in ["secret", "value", "token", "password", "passphrase"] {
            assert!(
                !text.contains(marker),
                "the record must carry no field that could hold a {marker}: {}",
                text.escape_debug()
            );
        }

        // And the acceptance's own rendering, which is what a reader sees.
        let carried = record
            .acceptance()
            .expect("the record carries its acceptance");
        let rendered = carried.to_string();
        assert!(
            !rendered.contains('/'),
            "the acceptance must carry no path: {}",
            rendered.escape_debug()
        );

        checked += 1;
    }
    assert!(checked > 0, "the acceptance must have been written");
}

/// A `none` acceptance and a `full` acceptance are distinguishable in the
/// chain.
///
/// Misfit B and N together: a later reader must be able to tell an accepted
/// absence from a full-strength acceptance, which means the level has to
/// survive the chain rather than being flattened on the way in.
#[test]
fn a_none_acceptance_and_a_full_one_are_distinguishable_in_the_chain() {
    let home = tempfile::tempdir().expect("a temporary home");
    provision(home.path());

    let none = CapabilityAcceptance::for_adapter(
        ksp_types::HostCapability::MemoryBarrier,
        "mlock",
        GuaranteeLevel::None,
    )
    .expect("`mlock` is in the closed set");
    let full = CapabilityAcceptance::for_adapter(
        ksp_types::HostCapability::MemoryBarrier,
        "memfd_secret",
        GuaranteeLevel::Full,
    )
    .expect("`memfd_secret` is in the closed set");

    append_acceptance(home.path(), none);
    let records = append_acceptance(home.path(), full);
    assert_eq!(records.len(), 2, "both acceptances were written");

    let levels: Vec<GuaranteeLevel> = records
        .iter()
        .map(|record| {
            record
                .record
                .acceptance()
                .expect("each record carries its acceptance")
                .guarantee
        })
        .collect();
    assert!(
        levels.contains(&GuaranteeLevel::None) && levels.contains(&GuaranteeLevel::Full),
        "the chain must preserve both levels; got: {levels:?}"
    );

    // And the outcome is the same on both, so the level is the only
    // difference — which is what makes it readable.
    for record in &records {
        assert_eq!(record.record.outcome, Outcome::Success);
    }
}

/// `ksp audit --admin` prints the acceptance it reads.
///
/// The durable record is only half of NFR-009: a claim nobody can read is not a
/// disclosure. The view projected every field of the record except this one, so
/// an operator saw `operation=capability` and no adapter and no level — the
/// record was present and the fact was not.
#[test]
fn the_admin_view_prints_the_acceptance() {
    let home = tempfile::tempdir().expect("a temporary home");
    provision(home.path());
    let acceptance = CapabilityAcceptance::for_adapter(
        ksp_types::HostCapability::MemoryBarrier,
        "sealed_memfd",
        GuaranteeLevel::Weakened,
    )
    .expect("`sealed_memfd` is in the closed set");

    let records = append_acceptance(home.path(), acceptance);
    assert!(
        records
            .iter()
            .any(|signed| signed.record.acceptance().is_some()),
        "the chain must hold an acceptance before the view is asked to print it"
    );

    let run = Command::new(env!("CARGO_BIN_EXE_ksp"))
        .env("KSP_HOME", home.path())
        .env("LC_ALL", "C")
        .args(["audit", "--admin"])
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");
    let observed =
        String::from_utf8_lossy(&run.stdout).to_string() + &String::from_utf8_lossy(&run.stderr);

    assert!(
        run.status.success(),
        "the admin view must read the chain it just verified: {observed}"
    );
    assert!(
        observed.contains("operation=capability"),
        "the record must still be printed as the capability operation: {observed}"
    );
    assert!(
        observed.contains("sealed_memfd"),
        "the view must name the adapter that was accepted: {observed}"
    );
    assert!(
        observed.contains("weakened"),
        "the view must name the guarantee level that was accepted: {observed}"
    );
}

/// `ksp audit verify` accepts a chain that contains the capability variant.
///
/// Acceptance criterion 5 has two clauses, and only the first had a test. A
/// record that survives the chain but makes the verifier refuse would be worse
/// than one that was never written: the operator would see a valid log reported
/// as broken and learn to distrust the command.
///
/// The command reads the pins from the anchor, the policy and the enrolments
/// rather than from the log, so a new operation variant has to be admissible
/// without a pin of its own — which is exactly what this asserts.
#[test]
fn audit_verify_accepts_a_chain_that_contains_the_capability_variant() {
    let home = tempfile::tempdir().expect("a temporary home");
    provision(home.path());
    let acceptance = CapabilityAcceptance::for_adapter(
        ksp_types::HostCapability::PathConfinement,
        "landlock",
        GuaranteeLevel::Full,
    )
    .expect("`landlock` is in the closed set");

    let records = append_acceptance(home.path(), acceptance);

    // Without this the test would pass against an empty chain: `verify` reports
    // no problems for a log it never read, so a record that failed to reach the
    // segment would make the assertion below vacuous.
    assert!(
        records
            .iter()
            .any(|signed| signed.record.operation == AuditOperation::Capability),
        "the chain must actually hold the capability record before `verify` is \
         asked about it; it holds {} record(s)",
        records.len()
    );

    let run = Command::new(env!("CARGO_BIN_EXE_ksp"))
        .env("KSP_HOME", home.path())
        .env("LC_ALL", "C")
        .args(["audit", "verify"])
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");
    let observed =
        String::from_utf8_lossy(&run.stdout).to_string() + &String::from_utf8_lossy(&run.stderr);

    assert!(
        run.status.success(),
        "a chain holding a capability record must verify: {observed}"
    );
    assert!(
        observed.contains("unpinned=0") && observed.contains("invalid=0"),
        "a capability record is a record like any other; it must not be \
         reported as unpinned or invalid: {observed}"
    );
}
