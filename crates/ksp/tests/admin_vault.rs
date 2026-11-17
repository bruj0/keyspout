//! The admin principal's own vault: sealed by `admin::seal_vault`, refused twice.
//!
//! Publication needs the admin's X25519 key to seal a content key to her, which is
//! the only reason this vault exists (CF-018). Two things have to be true for it to
//! be usable: the binding must be reconstructible from the deployment record, and a
//! second seal must be refused, because every entry already published is sealed to
//! the key the first one holds.
//!
//! # Why there is no verb here
//!
//! The design spec's command surface is pinned by a test in `commands.rs`, and only
//! WP07 changes it. So this suite calls the operation the surface will eventually
//! reach, and the two assertions about a *refusal* are made where a caller sees
//! them: on the error a subsequent seal returns.
//!
//! A test reports a failure by panicking, and the panic message is what says why.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use ksp::deployment::Deployment;
use support::admin_and_two_users;

const PASSWORD: &str = "correct horse battery";

#[test]
fn a_fresh_deployment_holds_no_admin_vault() {
    let fixture = admin_and_two_users();
    let layout = fixture.layout(&fixture.admin_home);
    let recorded = Deployment::load(&layout).expect("a deployment record");

    // Absent, and the absence is a state a caller can act on rather than a guess:
    // publication refuses naming the operation that seals it.
    assert!(
        recorded.admin_vault_recipient_key.is_none(),
        "provisioning seals no admin vault"
    );
    assert!(
        !layout.root().join(ksp::vault::ADMIN_VAULT_FILE).exists(),
        "no admin vault file exists yet"
    );
}

#[test]
fn sealing_the_admin_vault_records_keys_a_reader_can_rebuild_the_binding_from() {
    let fixture = admin_and_two_users();
    let layout = fixture.layout(&fixture.admin_home);

    let sealed = ksp::admin::seal_vault(&layout, PASSWORD.as_bytes()).expect("the vault is sealed");
    let recorded = Deployment::load(&layout).expect("a deployment record");
    assert_eq!(sealed.principal, recorded.admin);

    // The binding is derived from the principal rather than minted, so a later
    // reader rebuilds it instead of needing it stored: the binding is the vault's
    // associated data, and a vault whose binding cannot be reconstructed is a vault
    // nobody can open.
    assert_eq!(
        recorded
            .admin_vault_signing_key_id
            .as_ref()
            .expect("the signing key id is recorded")
            .as_str(),
        format!("admin-vault-signing-{}", recorded.admin),
        "the signing key id is reconstructible from the principal"
    );
    assert_eq!(
        recorded
            .admin_vault_recipient_key_id
            .as_ref()
            .expect("the recipient key id is recorded")
            .as_str(),
        format!("admin-vault-recipient-{}", recorded.admin),
        "the recipient key id is reconstructible from the principal"
    );
    assert!(
        recorded.admin_vault_recipient_key.is_some(),
        "the public half is recorded so a publication can seal to it"
    );

    // The file is the admin's alone. The unsealing round trip needs a configured
    // memory barrier, which a deployment has and this fixture does not; the mode is
    // the part a fixture can prove.
    let vault_file = layout.root().join(ksp::vault::ADMIN_VAULT_FILE);
    assert!(vault_file.is_file(), "the vault file is written");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&vault_file).unwrap().permissions().mode() & 0o777,
        0o600,
        "the admin's key material is owner-only"
    );
}

#[test]
fn a_second_seal_is_refused_and_names_what_a_reseal_would_break() {
    let fixture = admin_and_two_users();
    let layout = fixture.layout(&fixture.admin_home);
    let first = ksp::admin::seal_vault(&layout, PASSWORD.as_bytes()).expect("the first seal");
    let before = Deployment::load(&layout)
        .expect("a deployment record")
        .admin_vault_recipient_key
        .expect("recorded");

    let refused = ksp::admin::seal_vault(&layout, PASSWORD.as_bytes())
        .err()
        .expect("a second seal is refused")
        .to_string();
    assert!(
        refused.contains("already has a vault"),
        "the refusal names the state: {refused}"
    );
    assert!(
        refused.contains("withdraw and re-publish"),
        "the refusal names what a reseal would break and the way out: {refused}"
    );

    // And the recorded key is the first vault's, not a new pair: a refused seal
    // changes nothing.
    let after = Deployment::load(&layout)
        .expect("a deployment record")
        .admin_vault_recipient_key
        .expect("still recorded");
    assert_eq!(after.to_bytes(), before.to_bytes(), "the first key stands");
    assert_eq!(first.recipient_key_id.as_str(), {
        let recorded = Deployment::load(&layout).unwrap();
        recorded
            .admin_vault_recipient_key_id
            .unwrap()
            .as_str()
            .to_string()
    });
}
