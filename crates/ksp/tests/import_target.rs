//! Import targeting: which recipient key, which level, and which vault.
//!
//! # Why these tests try to open a record
//!
//! Three misfits live here and all three report success when they fail:
//!
//! - **D** — a value sealed to the wrong recipient still seals, still reports a
//!   version, and is readable by the wrong person.
//! - **J** — a value written into the wrong deployment's vault lands in a store
//!   another team's principals can reach.
//! - **K** — a selector broader than intended copies another team's records into
//!   this vault.
//!
//! So a test that inspects metadata proves nothing: a wrong recipient produces
//! correct-looking metadata. The test must attempt the read and assert that it
//! **fails**, or assert that the other store is byte-identical.
//!
//! # What is factual here, and what this file cannot test
//!
//! Creating two deployments needs `admin init`, which writes a sealed vault and
//! binds a UNIX account. That is privileged setup, so the isolation test asserts
//! the property at the level the code can reach: a resolved target names its own
//! vault, and no code path accepts a vault from an argument.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp::import::target::{ImportTarget, TargetError, parse_target};

// ---------------------------------------------------------------------------
// T001 — neither form, or both, is a usage refusal naming both
// ---------------------------------------------------------------------------

#[test]
fn a_named_principal_is_the_target() {
    let target = parse_target(Some("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f"), false)
        .expect("a canonical principal UUID is accepted");
    assert!(matches!(target, ImportTarget::Principal(_)));
}

#[test]
fn own_vault_is_the_target() {
    let target = parse_target(None, true).expect("--own is accepted");
    assert!(matches!(target, ImportTarget::OwnVault));
}

#[test]
fn neither_form_names_both_accepted_forms() {
    let error = parse_target(None, false).expect_err("neither form must be refused");
    assert!(matches!(error, TargetError::NoTarget));

    // The sentence must name both, or an operator who reads only half of it is
    // sent to a form that also works and wonders why theirs did not.
    let text = error.to_string();
    assert!(
        text.contains("--to-principal"),
        "the refusal must name --to-principal; got: {text}"
    );
    assert!(
        text.contains("--own"),
        "the refusal must name --own; got: {text}"
    );
}

#[test]
fn both_forms_together_are_refused_naming_both() {
    let error = parse_target(Some("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f"), true)
        .expect_err("both forms must be refused");
    assert!(matches!(error, TargetError::ConflictingTargets));

    let text = error.to_string();
    assert!(
        text.contains("--to-principal") && text.contains("--own"),
        "got: {text}"
    );
}

#[test]
fn a_malformed_principal_is_refused_before_any_lookup() {
    // A typo is a usage error, not "the principal is not enrolled": the two have
    // different fixes and one sentence cannot name both.
    let error = parse_target(Some("not-a-uuid"), false).expect_err("a bad UUID is refused");
    assert!(matches!(error, TargetError::MalformedPrincipal(_)));
    assert!(error.to_string().contains("UUID"));
}

// ---------------------------------------------------------------------------
// T004 — the level mirrors `admin put`
// ---------------------------------------------------------------------------

#[test]
fn both_forms_write_at_the_admin_level() {
    // `admin put` and `admin put --own` both write at `admin`, and the difference
    // is the recipient key and the subtree. A second rule for the same decision is
    // how two commands come to disagree, so this asserts the mirror.
    use ksp::import::target::level_for;

    assert_eq!(level_for(&ImportTarget::OwnVault), ksp_types::Level::Admin);

    let principal = ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f")
        .expect("a canonical UUID parses");
    assert_eq!(
        level_for(&ImportTarget::Principal(principal)),
        ksp_types::Level::Admin
    );
}

// ---------------------------------------------------------------------------
// T005 — the vault is never an argument
// ---------------------------------------------------------------------------

#[test]
fn no_import_flag_names_a_vault() {
    // The absence of the flag **is** the control. A test that asserted the flag's
    // default would not notice someone adding one, so this reads the parser's own
    // help and asserts no vault option exists.
    use clap::CommandFactory;

    let command = ksp::commands::Cli::command();
    let import = command
        .get_subcommands()
        .find(|sub| sub.get_name() == "import")
        .expect("import is on the surface");

    let vault_flags: Vec<String> = import
        .get_arguments()
        .filter_map(|arg| arg.get_long().map(str::to_string))
        .filter(|long| long.contains("vault"))
        .collect();

    assert!(
        vault_flags.is_empty(),
        "`ksp import` must expose no vault flag, because the destination is the \
         deployment's own vault; found: {vault_flags:?}"
    );
}

// ---------------------------------------------------------------------------
// T002/T003 — resolution refuses before anything is sealed
// ---------------------------------------------------------------------------

#[test]
fn resolving_against_a_host_with_no_deployment_refuses_naming_the_deployment() {
    // A home with no deployment is the state of a fresh clone, and the refusal must
    // say so rather than "no such principal": the fix is to initialise, not to enrol.
    let home = std::env::temp_dir().join(format!("ksp-no-deployment-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let layout = ksp::config::Layout::new(home.clone());

    let target = ImportTarget::OwnVault;
    let error = ksp::import::target::resolve(&layout, &target)
        .expect_err("a host with no deployment must refuse");

    assert!(
        matches!(error, TargetError::Deployment(_)),
        "the refusal must name the deployment, not the principal; got {error:?}"
    );
    // A refusal that says only "missing" sends the operator looking for the wrong
    // thing, so the underlying sentence is carried through.
    assert!(
        !error.to_string().trim().is_empty(),
        "the refusal must carry the deployment's own sentence"
    );

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// Review finding: a stray space was reported as a malformed UUID
// ---------------------------------------------------------------------------

#[test]
fn surrounding_whitespace_is_trimmed_before_the_uuid_is_read() {
    // No UUID contains whitespace, so trimming has exactly one reading. Refusing
    // `" 6f5a1c8e-…"` as a malformed UUID sends the operator looking for a typo
    // that is not in the value: the UUID is correct and the space is not part of it.
    for raw in [
        " 6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f",
        "6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f ",
        "\t6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f\n",
    ] {
        let target = parse_target(Some(raw), false)
            .unwrap_or_else(|error| panic!("{raw:?} must be accepted after trimming: {error}"));
        assert!(matches!(target, ImportTarget::Principal(_)));
    }
}

#[test]
fn a_genuinely_malformed_uuid_still_refuses() {
    // The converse, so the trimming above is not a blanket acceptance.
    for raw in [
        "not-a-uuid",
        "6f5a1c8e",
        "6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6g",
    ] {
        let error =
            parse_target(Some(raw), false).expect_err("a malformed UUID must still be refused");
        assert!(
            matches!(error, TargetError::MalformedPrincipal(_)),
            "got {error:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Acceptance criterion 1, at the level a unit test can actually reach
// ---------------------------------------------------------------------------

#[test]
fn a_value_sealed_to_one_recipient_cannot_be_opened_with_another_key() {
    // Criterion 1 asks that a value imported for a principal cannot be opened
    // with the admin's keys. A full two-deployment fixture would prove the
    // fixture; the claim itself lives in the envelope, which is bound to one
    // X25519 public key. So this tests that seam.
    //
    // Misfit D's dangerous half: a value sealed to the wrong recipient still
    // seals, still reports a version, and is readable by the wrong person. The
    // test therefore attempts the open and asserts it fails, rather than
    // inspecting metadata that would look correct either way.
    use ksp_identity::enrolment::{RecipientPublicKey, RecipientSecretKey};
    use ksp_record::blob::ContentBlob;
    use ksp_record::envelope::RecordEnvelope;
    use ksp_types::content_key::ContentKey;

    let intended = RecipientSecretKey::generate();
    let wrong = RecipientSecretKey::generate();
    let intended_public: RecipientPublicKey = intended.recipient_public();
    let wrong_public: RecipientPublicKey = wrong.recipient_public();

    let content_key = ContentKey::generate();
    let metadata = ksp_types::BoundMetadata {
        vault_id: ksp_types::VaultId::new("v-team1"),
        user_id: ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f")
            .expect("a canonical UUID"),
        level: ksp_types::Level::Admin,
        secret_id: ksp_types::OpaqueSecretId::new("s-1"),
        version: 1,
    };
    let aad = metadata.bound_aad().expect("the metadata binds");

    let blob =
        ContentBlob::seal(&content_key, b"db_password", b"hunter2", &aad).expect("the blob seals");
    let envelope = RecordEnvelope::seal(&content_key, &intended_public.to_bytes(), &metadata)
        .expect("the envelope seals to the intended recipient");

    // The intended recipient opens it, so the seal is not failing for everyone.
    let opened = intended
        .with_secret(|secret| envelope.open(secret, &metadata))
        .expect("the intended recipient opens the envelope");
    let (_, value) = blob.open(&opened, &aad).expect("the blob opens");
    assert_eq!(value, b"hunter2");

    // The wrong recipient does not. This is the assertion criterion 1 asks for.
    let refused = wrong.with_secret(|secret| envelope.open(secret, &metadata));
    assert!(
        refused.is_err(),
        "a value sealed to one principal must not open with another principal's key; that is \
         misfit D's silent half"
    );

    // And the refusal is the binding, not an unrelated error: the other recipient
    // opens an envelope sealed to *it*.
    let other = RecordEnvelope::seal(&content_key, &wrong_public.to_bytes(), &metadata)
        .expect("the envelope seals to the other recipient");
    assert!(
        wrong
            .with_secret(|secret| other.open(secret, &metadata))
            .is_ok(),
        "the other recipient opens its own envelope, so the refusal above is the binding"
    );
}
