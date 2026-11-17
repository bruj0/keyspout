//! One store, N principals, one registry: the topology feature 014 builds on.
//!
//! # What this covers
//!
//! The plan's Option B decision (CF-001): each principal keeps its own home, the
//! store is the shared thing, and the canonical principal list lives in the store
//! at `p/<vault>/<admin>/principals.cbor` where every principal can read it.
//!
//! # Why it is end to end
//!
//! Every claim here is about *which account can reach which path*, and a unit test
//! that called the helper directly would prove what the helper does rather than
//! what a command does. The registry's mode, its location under the admin's
//! principal, and the refusal of a layout this build cannot represent are all
//! observable only through the binary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::os::unix::fs::PermissionsExt;

use ksp::exit;
use support::{Deployment, PASSWORD, admin_and_two_users};

/// A deployment with two users over one store records a registry every principal
/// can read, at the path the plan names.
#[test]
fn two_user_homes_share_one_store_and_one_registry() {
    let fixture = admin_and_two_users();

    let registry = fixture.registry();
    assert!(
        registry.exists(),
        "the registry is at {}",
        registry.display()
    );
    assert!(
        registry.ends_with("principals.cbor"),
        "the registry is a file, not a directory: {}",
        registry.display()
    );
    // `p/<vault>/<admin>/principals.cbor`: under the *admin's* principal, so the
    // user's levels are siblings rather than parents of it.
    let path = registry.to_str().unwrap();
    assert!(path.contains("/p/vault-1/"), "{path}");

    let mode = std::fs::metadata(&registry).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644, "every principal reads the registry: {mode:o}");

    let layout = fixture.layout(&fixture.admin_home);
    let stored = ksp::registry::PrincipalRegistry::load(&layout).expect("the registry reads");
    assert_eq!(stored.entries.len(), 3, "one admin and two users");
    assert_eq!(
        stored.admin_entries().count(),
        1,
        "exactly one admin principal"
    );
    assert_eq!(
        stored
            .entries
            .iter()
            .filter(|entry| entry.role == ksp::registry::RegistryRole::User)
            .count(),
        2,
        "both enrolled users are recorded"
    );
    // Each user's public keys are in the registry, which is what lets any
    // principal verify her signature without her password.
    for entry in stored
        .entries
        .iter()
        .filter(|e| e.role == ksp::registry::RegistryRole::User)
    {
        assert!(
            entry.recipient_key.is_some(),
            "{} has a recipient key",
            entry.principal
        );
        assert!(entry.signing_key_id.as_str().starts_with("alice-"));
    }
}

/// The admin's record names **one** user: the first enrolled one. Later users
/// live in the registry, and enrolling them must not overwrite her keys.
#[test]
fn the_admin_record_keeps_the_first_user_when_a_second_is_enrolled() {
    let fixture = admin_and_two_users();
    let layout = fixture.layout(&fixture.admin_home);
    let record = ksp::deployment::Deployment::load(&layout).expect("the admin record reads");
    let registry = ksp::registry::PrincipalRegistry::load(&layout).expect("the registry reads");
    let first_user = registry
        .entries
        .iter()
        .find(|entry| entry.role == ksp::registry::RegistryRole::User)
        .expect("the first user is recorded");

    assert_eq!(
        record.user, first_user.principal,
        "the admin record names the first enrolled user, not the last"
    );
    assert_eq!(
        record.user_signing_key,
        Some(first_user.signing_key),
        "her signing key survives the second enrolment"
    );
    assert_eq!(
        record.user_recipient_key, first_user.recipient_key,
        "her recipient key survives the second enrolment"
    );
    // Bob is in the registry and nowhere in the admin's record.
    assert_eq!(registry.entries.len(), 3, "both users are recorded");
}

/// Re-enrolling a home that already holds a vault names the principal that is
/// there, not one minted for the failed attempt.
#[test]
fn re_enrolling_an_existing_home_names_the_principal_it_already_holds() {
    let fixture = admin_and_two_users();
    let layout = fixture.layout(&fixture.alice_home);
    let alice = ksp::deployment::Deployment::load(&layout)
        .expect("alice's record reads")
        .user;

    let (code, output) = fixture.run(
        &fixture.admin_home,
        &[
            "admin",
            "user",
            "add",
            "--home",
            fixture.alice_home.to_str().unwrap(),
        ],
        Some(PASSWORD),
    );
    assert_ne!(
        code,
        exit::SUCCESS,
        "a second enrolment must refuse: {output}"
    );
    assert!(
        output.contains(&alice.to_string()),
        "the refusal names the principal that holds the vault: {output}"
    );
    assert!(
        output.contains("already holds a sealed vault"),
        "the refusal names the state and the command that replaces a vault: {output}"
    );
}

/// Each user's vault lives in her own home, not in the admin's.
#[test]
fn a_user_vault_is_written_into_the_home_that_was_named() {
    let fixture = admin_and_two_users();

    assert!(
        fixture.alice_home.join("vault.cbor").is_file(),
        "alice's vault is in her own home"
    );
    assert!(
        fixture.bob_home.join("vault.cbor").is_file(),
        "bob's vault is in his own home"
    );
    assert!(
        !fixture.admin_home.join("vault.cbor").exists(),
        "the admin home holds no user vault"
    );
}

/// A second admin principal is refused, and the refusal names the existing one.
#[test]
fn a_second_admin_is_refused_by_principal() {
    let fixture = admin_and_two_users();
    let layout = fixture.layout(&fixture.admin_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("a deployment record");

    let (code, output) = fixture.run(
        &fixture.admin_home,
        &["admin", "init", "--vault", "vault-2", "--user", "alice"],
        None,
    );
    assert_ne!(code, exit::SUCCESS, "a second init must refuse: {output}");
    assert!(
        output.contains(&deployment.admin.to_string()),
        "the refusal must name the admin principal that already holds the key: {output}"
    );
}

/// A configured store root that is absent is refused, and no fallback store is
/// created inside the home.
#[test]
fn an_absent_configured_store_root_is_refused_rather_than_created() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let home = root.path().join("home");
    let missing = root.path().join("not-mounted");
    std::fs::create_dir_all(&home).unwrap();

    let mut command = std::process::Command::new(support::ksp());
    let output = command
        .env("KSP_HOME", &home)
        .env("KSP_STORE", &missing)
        .args(["admin", "init", "--vault", "vault-1", "--user", "alice"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the binary runs");
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code().unwrap_or(-1),
        exit::CAPABILITY_REFUSAL,
        "an absent store root is a capability refusal: {combined}"
    );
    assert!(
        combined.contains("KSP_STORE"),
        "the refusal names the variable to unset: {combined}"
    );
    assert!(
        !home.join("store").exists(),
        "no fallback store is created in the home"
    );
    assert!(
        !missing.exists(),
        "a configured store root is never created by a command"
    );
}

/// A pre-014 home is refused before anything is read, and nothing is modified.
#[test]
fn a_pre_014_home_is_refused_with_nothing_modified() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let home = root.path().join("old-home");
    std::fs::create_dir_all(&home).unwrap();
    // The old layout: a deployment record and a host-local policy, no registry.
    std::fs::write(
        home.join("deployment.cbor"),
        b"not read: the gate runs first",
    )
    .unwrap();
    std::fs::write(home.join("policy.cbor"), b"the old grant list").unwrap();
    let before = tree(&home);

    for args in [
        vec!["status"],
        vec!["admin", "policy", "--show"],
        vec!["secret", "ls"],
        vec!["audit", "verify"],
    ] {
        let mut command = std::process::Command::new(support::ksp());
        let output = command
            .env("KSP_HOME", &home)
            .env_remove("KSP_STORE")
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::null())
            .output()
            .expect("the binary runs");
        let combined = String::from_utf8_lossy(&output.stdout).to_string()
            + &String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code().unwrap_or(-1),
            exit::CAPABILITY_REFUSAL,
            "{args:?} must be refused by the gate: {combined}"
        );
        assert!(
            combined.contains("pre-014"),
            "{args:?} names the layout it found: {combined}"
        );
    }

    assert_eq!(before, tree(&home), "the gate writes nothing");
}

/// The user principal can read her own grants from her own home.
#[test]
fn a_user_home_carries_the_policy_the_admin_signed() {
    let fixture = admin_and_two_users();

    let (code, output) = fixture.run(&fixture.alice_home, &["admin", "policy", "--show"], None);
    assert_eq!(
        code,
        exit::SUCCESS,
        "a user reads the policy in her own home: {output}"
    );
    assert!(
        output.contains("vault-1"),
        "the copy names the vault it governs: {output}"
    );
}

/// Every path under `root`, sorted, as `(relative path, is directory)`.
fn tree(root: &std::path::Path) -> Vec<(String, bool)> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            found.push((relative, path.is_dir()));
            if path.is_dir() {
                stack.push(path);
            }
        }
    }
    found.sort();
    found
}

/// The fixture is the one later work packages use, so it is checked here rather
/// than trusted: a deployment it cannot describe is a deployment they cannot test.
#[test]
fn the_fixture_builds_every_home_the_acceptance_criteria_name() {
    let fixture: Deployment = admin_and_two_users();
    for home in [&fixture.admin_home, &fixture.alice_home, &fixture.bob_home] {
        assert!(
            home.join("deployment.cbor").is_file(),
            "{} holds its own record",
            home.display()
        );
    }
    let layout = fixture.layout(&fixture.alice_home);
    let deployment = ksp::deployment::Deployment::load(&layout).expect("alice's record reads");
    assert!(
        deployment.user_signing_key.is_some(),
        "alice's public keys are recorded in her own home"
    );
    assert_eq!(
        deployment.vault.as_str(),
        "vault-1",
        "one vault id across every home"
    );
    // The agent is enrolled in the user's home, and its public keys are readable
    // there without a password.
    let (code, output) = fixture.run(
        &fixture.alice_home,
        &["agent", "pubkey", "--agent", &fixture.agent],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the agent is enrolable: {output}");
    // The password is the one the fixture enrolled with, so a caller that wants to
    // mint does not have to guess it.
    assert_eq!(PASSWORD, "a long enough password");
}
