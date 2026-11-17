//! The feature's five steps, end to end, through the binary.
//!
//! # What this proves that the work packages could not
//!
//! Each work package was verified against its own subsystem, and several of them
//! reached the operations directly because the command surface was pinned until this
//! work package. This runs the path an operator actually types, in the order the
//! design's use case states it:
//!
//! 1. the admin seals her own vault and writes a secret she can open;
//! 2. the admin transfers a different secret to the user, who may share it;
//! 3. the admin creates a grant for the first secret, and **no copy** of it appears
//!    at the user's or the agent's level;
//! 4. the user exports the admin-issued token without a password, and the agent runs
//!    and receives the value;
//! 5. the admin withdraws, the next run is refused, and the user's own secret is
//!    still hers.
//!
//! A wiring gap between two subsystems can only fail here, where the steps cross
//! process boundaries.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::path::{Path, PathBuf};

use ksp::exit;
use support::{Deployment as Fixture, PASSWORD, admin_and_two_users};

/// The value the admin publishes, and the value she transfers.
const PUBLISHED: &str = "value-the-admin-publishes";
const TRANSFERRED: &str = "value-the-user-owns";

/// Run one command and require it to succeed.
fn ok(fixture: &Fixture, home: &Path, args: &[&str], stdin: Option<&str>) -> String {
    let (code, output) = fixture.run(home, args, stdin);
    assert_eq!(
        code,
        exit::SUCCESS,
        "`ksp {}` failed: {output}",
        args.join(" ")
    );
    output
}

/// The user principal the grant names: the first enrolled user.
fn first_user(fixture: &Fixture) -> String {
    let layout = fixture.layout(&fixture.admin_home);
    let registry = ksp::registry::PrincipalRegistry::load(&layout).expect("the registry reads");
    registry
        .entries
        .iter()
        .find(|entry| entry.role == ksp::registry::RegistryRole::User)
        .expect("a user is enrolled")
        .principal
        .to_string()
}

/// The policy id `admin policy create` printed, from its JSON report.
fn created_id(output: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(
        output
            .lines()
            .find(|line| line.trim_start().starts_with('{'))
            .unwrap_or_else(|| panic!("no JSON report in {output}")),
    )
    .expect("the report is JSON");
    value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("the report names no policy id: {output}"))
        .to_string()
}

/// One level directory under a principal: `p/<vault>/<principal>/<level>/<secret>`.
///
/// Addressed by level rather than scanned for, because the claim these steps make is
/// about a *level*: "no copy appears in the user's or the agent's level" is a
/// statement about two directories that must not exist, and a scan that matched a
/// file name would answer a different question.
fn level_dir(fixture: &Fixture, principal: &str, level: &str, secret: &str) -> PathBuf {
    fixture
        .store
        .join("p")
        .join("vault-1")
        .join(principal)
        .join(level)
        .join(secret)
}

/// A principal's level directory holds at least one version of `secret`.
fn holds(fixture: &Fixture, principal: &str, level: &str, secret: &str) -> bool {
    let directory = level_dir(fixture, principal, level, secret);
    std::fs::read_dir(&directory)
        .map(|entries| entries.flatten().next().is_some())
        .unwrap_or(false)
}

#[test]
fn the_five_design_steps_run_end_to_end_through_the_binary() {
    let fixture = admin_and_two_users();
    let admin = fixture.admin_home.clone();
    let user = first_user(&fixture);

    // ── Step 0: each home selects the strongest capability configuration it can ──
    //
    // `init` writes it, and unsealing a vault reads it: without one, the memory
    // barrier has no adapter and every password command refuses with exit 7. The
    // fixture provisions the topology and leaves the host posture to its operator,
    // which is what a real deployment does too.
    ok(&fixture, &admin, &["init"], None);
    ok(&fixture, &fixture.alice_home, &["init"], None);

    // ── Step 1: the admin seals her own vault and writes a secret she can open ──
    //
    // The vault is what a publication's content key is sealed to, and the `--own`
    // record is the plaintext source: `admin put` without it seals to the user, which
    // is the transfer in step 2 and unreadable by the admin on purpose (CF-102).
    ok(&fixture, &admin, &["admin", "seal-vault"], Some(PASSWORD));
    ok(
        &fixture,
        &admin,
        &["admin", "put", "published", "--name", "published", "--own"],
        Some(PUBLISHED),
    );
    let admin_principal = ksp::deployment::Deployment::load(&fixture.layout(&fixture.admin_home))
        .expect("a deployment record")
        .admin
        .to_string();
    assert!(
        holds(&fixture, &admin_principal, "admin", "published"),
        "the admin's own copy is written at her principal, `admin` level"
    );
    assert!(
        !holds(&fixture, &user, "user", "published"),
        "writing the admin's own copy must not write one for the user"
    );

    // ── Step 2: the admin transfers a different secret to the user ──
    //
    // No `--own`: the record is sealed to the user's recorded recipient key, so she
    // can read it and share it, and the admin cannot open it afterwards.
    ok(
        &fixture,
        &admin,
        &["admin", "put", "transferred", "--name", "transferred"],
        Some(TRANSFERRED),
    );

    // ── Step 3: the admin creates a grant for the admin-vault secret ──
    let output = ok(
        &fixture,
        &admin,
        &[
            "admin",
            "policy",
            "create",
            "--user",
            &user,
            "--secret",
            "published",
            "--version",
            "1",
            "--agent",
            &fixture.agent,
            "--json",
        ],
        Some(PASSWORD),
    );
    let policy = created_id(&output);
    assert!(
        output.contains("\"state\":\"active\""),
        "a new grant is active: {output}"
    );
    assert!(
        output.contains("\"verified\":true"),
        "the grant verifies against the pinned anchor: {output}"
    );

    // The publication exists under the admin's principal, and it is the only copy: a
    // grant delivers a sealed reference, so neither the user's level nor the agent's
    // may hold a record of the secret. This is the assertion that fails if a work
    // package quietly copies instead of publishing.
    assert!(
        holds(&fixture, &admin_principal, "granted", "published"),
        "the grant writes a sealed publication under the admin"
    );
    assert!(
        !holds(&fixture, &user, "user", "published"),
        "a policy-bound secret must not appear at the user's `user` level"
    );
    assert!(
        !holds(
            &fixture,
            &user,
            &format!("agent-{}", fixture.agent),
            "published"
        ),
        "a policy-bound secret must not appear at the agent's level either: the token \
         carries a reference, not a copy"
    );

    // ── Step 4: the user exports the token, keyless, and the agent runs ──
    let token = fixture.root.path().join("policy-token.json");
    ok(
        &fixture,
        &fixture.alice_home,
        &[
            "secret",
            "share",
            "published",
            "--policy",
            &policy,
            "--out",
            token.to_str().unwrap(),
        ],
        // No stdin: an export that read a password would block here rather than fail,
        // and the point of C1 is that there is nothing for the user to unlock.
        None,
    );
    assert!(token.is_file(), "the export wrote the token");

    let (code, output) = fixture.run(
        &fixture.alice_home,
        &[
            "run",
            "--token",
            token.to_str().unwrap(),
            "--env",
            "KSP_POLICY_VALUE",
            "--",
            "printenv",
            "KSP_POLICY_VALUE",
        ],
        None,
    );
    assert_eq!(code, exit::SUCCESS, "the policy delivery failed: {output}");
    assert!(
        output.contains(PUBLISHED),
        "the agent receives the published value: {output}"
    );
    // The delivery is the *user's* fact, not the admin's: the agent acts for her, and
    // her account is the one that can write her chain. A delivery recorded under the
    // admin looks right on a single-account host and is a refusal (exit 7) on a
    // two-account one, where her account cannot write the admin's 0700 chain.
    let pw = fixture.root.path().join("scenario.pw");
    std::fs::write(&pw, PASSWORD).expect("the password file is writable");
    let pw = pw.to_str().expect("the fixture path is UTF-8");
    let log = ok(
        &fixture,
        &fixture.alice_home,
        &["audit", "--limit", "20", "--passphrase-file", pw],
        None,
    );
    let delivered = log
        .lines()
        .find(|line| line.contains("operation=deliver"))
        .unwrap_or_else(|| panic!("the user's view holds the delivery: {log}"));
    assert!(
        delivered.contains(&format!("actor={user}")),
        "the delivery is attributed to the user the grant names: {delivered}"
    );

    // ── Step 5: the admin withdraws, the next run is refused, the user keeps hers ──
    let output = ok(
        &fixture,
        &admin,
        &["admin", "policy", "delete", &policy, "--json"],
        None,
    );
    assert!(
        output.contains("\"state\":\"withdrawn\""),
        "the withdrawal is recorded and rendered: {output}"
    );

    let (code, output) = fixture.run(
        &fixture.alice_home,
        &[
            "run",
            "--token",
            token.to_str().unwrap(),
            "--env",
            "KSP_POLICY_VALUE",
            "--",
            "printenv",
            "KSP_POLICY_VALUE",
        ],
        None,
    );
    assert_ne!(
        code,
        exit::SUCCESS,
        "a withdrawn grant must not deliver: {output}"
    );
    assert!(
        !output.contains(PUBLISHED),
        "the refused run must not print the value: {output}"
    );

    // The transfer in step 2 is untouched by the withdrawal: it is the user's record,
    // at her own level, and a policy decision about another secret does not reach it.
    let (code, output) = fixture.run(
        &fixture.alice_home,
        &["secret", "get", "transferred", "--reveal"],
        Some(PASSWORD),
    );
    assert_eq!(
        code,
        exit::SUCCESS,
        "the user's own record still reads: {output}"
    );
    assert!(
        output.contains(TRANSFERRED),
        "the user's own value is still hers: {output}"
    );
}

#[test]
fn an_expiry_only_update_needs_no_password_and_rewrites_no_publication() {
    let fixture = admin_and_two_users();
    let admin = fixture.admin_home.clone();
    let user = first_user(&fixture);
    ok(&fixture, &admin, &["init"], None);
    ok(&fixture, &fixture.alice_home, &["init"], None);
    ok(&fixture, &admin, &["admin", "seal-vault"], Some(PASSWORD));
    ok(
        &fixture,
        &admin,
        &["admin", "put", "published", "--name", "published", "--own"],
        Some(PUBLISHED),
    );
    let output = ok(
        &fixture,
        &admin,
        &[
            "admin",
            "policy",
            "create",
            "--user",
            &user,
            "--secret",
            "published",
            "--version",
            "1",
            "--agent",
            &fixture.agent,
            "--json",
        ],
        Some(PASSWORD),
    );
    let policy = created_id(&output);

    // Moving the window changes the ledger row and the token, not the sealed entry: the
    // artifact already holds this policy. Reading a password there would ask the admin to
    // decrypt her own secret for a write that produces nothing, and the operator would
    // learn to type it without reading what for.
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs()
        + 3_600;
    let output = ok(
        &fixture,
        &admin,
        &[
            "admin",
            "policy",
            "update",
            &policy,
            "--expires-at",
            &expiry.to_string(),
            "--json",
        ],
        // No stdin: a prompt here would block the command rather than fail it, and the
        // refusal this test exists for is the one `NoPassword` produced before the fix.
        None,
    );
    assert!(
        output.contains(&format!("\"not_after\":{expiry}")),
        "the window moved: {output}"
    );
    assert!(
        output.contains("\"state\":\"active\""),
        "the grant is still active over the same artifact: {output}"
    );

    // A create that has an entry to seal still refuses without the password: the
    // exemption is for the write that has nothing to seal, not for the command.
    ok(
        &fixture,
        &admin,
        &["admin", "put", "second", "--name", "second", "--own"],
        Some(PUBLISHED),
    );
    let (code, output) = fixture.run(
        &admin,
        &[
            "admin",
            "policy",
            "create",
            "--user",
            &user,
            "--secret",
            "second",
            "--version",
            "1",
            "--agent",
            &fixture.agent,
        ],
        None,
    );
    assert_ne!(
        code,
        exit::SUCCESS,
        "a create that must seal an entry cannot run without the password: {output}"
    );
}

#[test]
fn a_policy_delivery_refuses_every_flag_it_cannot_honour() {
    let fixture = admin_and_two_users();
    let admin = fixture.admin_home.clone();
    let user = first_user(&fixture);
    ok(&fixture, &admin, &["init"], None);
    ok(&fixture, &fixture.alice_home, &["init"], None);
    ok(&fixture, &admin, &["admin", "seal-vault"], Some(PASSWORD));
    ok(
        &fixture,
        &admin,
        &["admin", "put", "published", "--name", "published", "--own"],
        Some(PUBLISHED),
    );
    let output = ok(
        &fixture,
        &admin,
        &[
            "admin",
            "policy",
            "create",
            "--user",
            &user,
            "--secret",
            "published",
            "--version",
            "1",
            "--agent",
            &fixture.agent,
            "--json",
        ],
        Some(PASSWORD),
    );
    let policy = created_id(&output);
    let out = fixture.root.path().join("refused-token.json");

    // `--ttl` used to carry a default, so `--policy` could not tell whether the operator
    // typed it and silently minted nothing with a bound the operator believed was set.
    // Every flag here names the accepted form, so the shape can be derived from the set
    // rather than only from the one flag that happens to be refused (CF-038).
    for flag in ["--name", "--uses", "--ttl", "--passphrase-file"] {
        let (code, output) = fixture.run(
            &fixture.alice_home,
            &[
                "secret",
                "share",
                "published",
                "--policy",
                &policy,
                flag,
                "1",
                "--out",
                out.to_str().unwrap(),
            ],
            None,
        );
        assert_eq!(code, exit::USAGE, "`{flag}` must be refused: {output}");
        assert!(
            output.contains(flag),
            "the refusal names the flag that was refused: {output}"
        );
        assert!(
            output.contains("accepted form is"),
            "the refusal prints the accepted form: {output}"
        );
    }
    assert!(
        !out.exists(),
        "a refused export writes no token: the file must not exist"
    );
}
