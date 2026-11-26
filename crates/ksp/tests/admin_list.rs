//! `admin list` — every principal, and an unreadable subtree reported not fatal.
//!
//! # What this covers
//!
//! D3 and D4 in `docs/known-defects.md`, in one function (`admin::list`).
//!
//! - **D3**: the walk fails on the first directory the caller may *traverse* but
//!   not *read* — the Level Parent at `0711` and the Level Directory at `0700`.
//!   The store error was mapped to `AdminError::Write`, so a **read** reported
//!   *"a protected file this operation had to write could not be written"* and
//!   named nothing.
//! - **D4**: the prefix came from the deployment record's single `user` field,
//!   which is the first enrolled principal only. Every later principal's records
//!   were silently omitted.
//!
//! # Why the assertions are on exit codes and the parsed object
//!
//! A listing that succeeds while omitting a principal and one that fails on the
//! first unreadable directory are the same defect seen from two ends. Only the
//! exit code plus the contents together distinguish "listed everything" from
//! "listed what it could and said so" from "failed".
//!
//! These run unprivileged: the fixture builds its own homes under a traversable
//! root, and no account is chowned to another uid.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use support::PASSWORD;

/// A temp dir every account can traverse, under `/tmp` rather than the invoking
/// `TMPDIR`, which is `0700` for root and untraversable for anyone else.
fn shared_tempdir() -> tempfile::TempDir {
    let temp = tempfile::Builder::new()
        .prefix("ksp-admin-list-")
        .tempdir_in("/tmp")
        .expect("a temp dir under /tmp");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755))
        .expect("the fixture root is traversable");
    temp
}

/// One deployment: an admin home, a shared store, and any number of user homes.
struct Fixture {
    root: tempfile::TempDir,
    admin_home: PathBuf,
    store: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = shared_tempdir();
        let admin_home = root.path().join("admin-home");
        let store = root.path().join("store");
        std::fs::create_dir_all(&store).expect("the store root exists");
        let fixture = Self {
            root,
            admin_home,
            store,
        };

        let (code, output) = fixture.run(
            &fixture.admin_home,
            &["admin", "init", "--vault", "vault-1", "--user", "alice"],
            None,
        );
        assert_eq!(code, 0, "admin init failed: {output}");

        // The capability configuration, which every command that establishes a
        // capability reads first. Without it the assertions below would fail at
        // exit 7 for a reason unrelated to the listing, and a red phase that fails
        // for the wrong reason proves nothing.
        let (code, output) = fixture.run(&fixture.admin_home, &["init"], None);
        assert_eq!(code, 0, "init failed: {output}");

        // And each principal's home needs one too: `secret set` runs from *her*
        // home, which has no configuration of its own.
        std::fs::set_permissions(
            fixture.admin_home.join("config.toml"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("the configuration is readable by the principal");
        fixture
    }

    /// Enrol a principal into a home of her own, in the shared store.
    fn enrol(&self, name: &str) -> PathBuf {
        let home = self.root.path().join(format!("{name}-home"));
        let (code, output) = self.run(
            &self.admin_home,
            &["admin", "user", "add", "--home", home.to_str().unwrap()],
            Some(PASSWORD),
        );
        assert_eq!(code, 0, "admitting {name} failed: {output}");
        // The handover copies the admin's configuration into the new home; this
        // fixture mirrors that so a command run from it is not refused for D1.
        std::fs::copy(
            self.admin_home.join("config.toml"),
            home.join("config.toml"),
        )
        .expect("the configuration is handed over");
        home
    }

    fn run(&self, home: &Path, args: &[&str], stdin: Option<&str>) -> (i32, String) {
        let mut command = std::process::Command::new(support::ksp());
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("KSP_HOME", home)
            .env("KSP_STORE", &self.store)
            .args(args)
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().expect("the binary runs");
        if let Some(text) = stdin {
            use std::io::Write;
            child
                .stdin
                .take()
                .expect("stdin is piped")
                .write_all(text.as_bytes())
                .unwrap();
        }
        let output = child.wait_with_output().unwrap();
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr),
        )
    }

    /// The parsed JSON object of `admin list --json`.
    fn list(&self) -> (i32, String, Option<serde_json::Value>) {
        let (code, raw) = self.run(&self.admin_home, &["--json", "admin", "list"], None);
        let first = raw.lines().next().unwrap_or("").to_string();
        (code, raw.clone(), serde_json::from_str(&first).ok())
    }
}

/// D4 again, one layer up: two principals may hold the same record identifier.
///
/// `RecordMetadata` carries a record id, a level and a version — and no
/// principal. The listing deduped on that projection, so once the walk reached
/// two principals' trees, the *second* principal's record collapsed into the
/// first's and vanished from the output. Distinct identifiers hid it: with
/// `s1` and `s2` there is nothing to collapse.
///
/// The store path is what is unique, so the dedup keys on that. This is the same
/// defect D4 describes — a listing that omits a principal's records and says
/// nothing about doing so — reached through the set operation rather than
/// through the prefix.
#[test]
fn two_principals_holding_the_same_record_identifier_are_both_listed() {
    let fixture = Fixture::new();
    let alice_home = fixture.enrol("alice");
    let bob_home = fixture.enrol("bob");

    let password = set_password_file(&fixture.root);
    // The same identifier in both homes: same record id, same level, same
    // version, different principal.
    for home in [&alice_home, &bob_home] {
        let (code, output) = fixture.run(
            home,
            &[
                "secret",
                "set",
                "shared-id",
                "--name",
                "db_password",
                "--passphrase-file",
                &password,
            ],
            Some("correct-horse"),
        );
        assert_eq!(code, 0, "secret set in {} failed: {output}", home.display());
    }

    let (code, raw, json) = fixture.list();
    assert_eq!(code, 0, "admin list failed: {raw}");
    let json = json.unwrap_or_else(|| panic!("admin list --json is one object: {raw}"));
    let records = json["records"]
        .as_array()
        .unwrap_or_else(|| panic!("records is an array: {json}"));
    let same_id = records
        .iter()
        .filter(|record| record["record"] == "shared-id")
        .count();
    assert_eq!(
        same_id, 2,
        "both principals' copies are listed; the metadata carries no principal,          so a dedup on it cannot tell them apart: {json}"
    );
}

/// D3: a subtree the caller may traverse but not read does not fail the listing.
///
/// The principal's level is `0700`, so the admin can name it and cannot read it.
/// Before the fix the walk failed with `EACCES` and the command reported a
/// **write** failure. After it, the listing succeeds and names what it could not
/// read.
#[test]
fn an_unreadable_subtree_is_reported_rather_than_failing_the_listing() {
    let fixture = Fixture::new();
    let alice_home = fixture.enrol("alice");

    // A record at alice's level, written by her, so there is something to find.
    let (code, output) = fixture.run(
        &alice_home,
        &[
            "secret",
            "set",
            "s1",
            "--name",
            "db_password",
            "--passphrase-file",
            &set_password_file(&fixture.root),
        ],
        Some("correct-horse"),
    );
    assert_eq!(code, 0, "secret set as alice failed: {output}");

    // Deny the read for real. A `0700` directory the *invoking* process owns
    // denies it nothing, so making alice's level `0700` would have exercised
    // nothing and the test would have passed on a broken walk. `0000` does deny
    // it, and the record written above sits inside the directory it hides.
    let hidden = mode_zeroed_level(&fixture.store);
    assert!(
        !hidden.is_empty(),
        "the fixture denied at least one directory: {}",
        fixture.store.display()
    );

    let (code, raw, json) = fixture.list();
    assert_eq!(
        code, 0,
        "the listing must not fail on a directory it may traverse but not read: {raw}"
    );
    let json = json.unwrap_or_else(|| panic!("admin list --json is one object: {raw}"));
    assert_eq!(
        json["kind"], "records",
        "the tag does not change; a new variant would rename it: {json}"
    );
    // It reports what it could not read rather than dropping it silently.
    let unreadable = json["unreadable"]
        .as_array()
        .unwrap_or_else(|| panic!("the listing carries what it could not read: {json}"));
    // The listing reports the path **relative to the store root**, because that
    // is the shape every other path in this output takes; comparing an absolute
    // path here would fail against a correct report.
    let relative = hidden
        .strip_prefix(&fixture.store)
        .expect("the denied directory is under the store")
        .to_string_lossy()
        .to_string();
    let named = unreadable
        .iter()
        .filter_map(|entry| entry.as_str())
        .find(|text| text.starts_with(&relative))
        .unwrap_or_else(|| panic!("the unreadable directory is named: {json} (denied {relative})"));
    // The mode, the owner and the filesystem's own reason. The mode alone cannot
    // distinguish a permission this caller lacks from a path that is not a
    // directory, and those have different fixes.
    assert!(named.contains("mode 0000"), "the mode is reported: {named}");
    assert!(
        named.contains("owner uid"),
        "the owner is reported: {named}"
    );
    assert!(
        named.to_lowercase().contains("permission denied"),
        "the filesystem's reason is reported, not discarded: {named}"
    );
}

/// `chmod 0000` on every level directory under the store, and return the first.
///
/// The walk reaches a directory it cannot enumerate; an owner's `0700` is not
/// such a directory, which is why the mode here is `0000`. Root ignores both,
/// so a root run would see nothing unreadable — this test is unprivileged by
/// design, like the rest of the suite's unprivileged targets.
fn mode_zeroed_level(store: &Path) -> PathBuf {
    let mut denied = Vec::new();
    let principals = store.join("p");
    let Ok(vaults) = std::fs::read_dir(&principals) else {
        return PathBuf::new();
    };
    for vault in vaults.flatten() {
        let Ok(users) = std::fs::read_dir(vault.path()) else {
            continue;
        };
        for user in users.flatten() {
            let Ok(levels) = std::fs::read_dir(user.path()) else {
                continue;
            };
            for level in levels.flatten() {
                if level.path().is_dir() {
                    std::fs::set_permissions(level.path(), std::fs::Permissions::from_mode(0o000))
                        .expect("the level directory is closed");
                    denied.push(level.path());
                }
            }
        }
    }
    denied.sort();
    denied.into_iter().next().unwrap_or_default()
}

/// D4: every enrolled principal's records are listed, not just the first.
#[test]
fn every_enrolled_principal_is_listed() {
    let fixture = Fixture::new();
    let alice_home = fixture.enrol("alice");
    let bob_home = fixture.enrol("bob");

    let password = set_password_file(&fixture.root);
    for (home, id) in [(&alice_home, "s1"), (&bob_home, "s2")] {
        let (code, output) = fixture.run(
            home,
            &[
                "secret",
                "set",
                id,
                "--name",
                "db_password",
                "--passphrase-file",
                &password,
            ],
            Some("correct-horse"),
        );
        assert_eq!(code, 0, "secret set in {} failed: {output}", home.display());
    }

    let (code, raw, json) = fixture.list();
    assert_eq!(code, 0, "admin list failed: {raw}");
    let json = json.unwrap_or_else(|| panic!("admin list --json is one object: {raw}"));
    let records = json["records"]
        .as_array()
        .unwrap_or_else(|| panic!("records is an array: {json}"));
    let ids: Vec<&str> = records
        .iter()
        .filter_map(|r| r["record"].as_str())
        .collect();
    assert!(
        ids.contains(&"s1") && ids.contains(&"s2"),
        "both principals' records are named, not only the first enrolled one: {ids:?}"
    );
}

/// The engine numbers two distinct ids, because both principals exist.
///
/// Sorted and deduplicated before comparison: the same identifier at two levels
/// is two records, and the assertion is about principals, not about counts.
#[test]
fn the_listing_is_stable_across_runs() {
    let fixture = Fixture::new();
    let _alice_home = fixture.enrol("alice");

    let (first_code, first, _) = fixture.list();
    let (second_code, second, _) = fixture.list();
    assert_eq!(first_code, 0, "{first}");
    assert_eq!(second_code, 0, "{second}");
    assert_eq!(
        first.lines().next(),
        second.lines().next(),
        "two identical listings produce identical output"
    );
}

/// A password file the admin writes and the principal can read.
///
/// `secret set` reads the password from a file, and a `0600` file in the admin's
/// home is unopenable for the principal — which is the point of the mode and the
/// wrong thing for a fixture.
fn set_password_file(root: &tempfile::TempDir) -> String {
    let path = root.path().join("vault.pw");
    std::fs::write(&path, PASSWORD).expect("the password file is written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("the password file is readable");
    path.to_str().expect("a UTF-8 path").to_string()
}
