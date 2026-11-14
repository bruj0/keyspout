//! What the two probe verbs do to a real filesystem and a real exit code.
//!
//! # Why these run the binary
//!
//! The unit tests call [`ksp_cli::probe::configure`] directly, which proves the
//! probe's decisions but not how `dispatch` reports them. The exit code is part
//! of the CLI's contract — a script branches on it — and the sentence printed
//! beside it is what a reader sees. Both live in `app.rs`'s dispatch arm, so
//! only a run of the real binary exercises them (the WP05 lesson: a probe that
//! calls the adapter proves the adapter stamps, not that production calls the
//! adapter).
//!
//! # The first-run case needs a home that is absent
//!
//! `KSP_HOME` defaults to `.ksp` under the working directory, so the host
//! `ksp init` exists for is one where that directory is absent. A fixture that
//! pre-creates the directory cannot reach the defect these tests were written
//! for, which is how it survived a seventeen-test suite.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

use ksp_cli::config::Layout;
use ksp_cli::layout::HOME_MODE;

/// Run `ksp` with this home and return (code, stdout + stderr).
fn ksp_in(home: &Path, args: &[&str]) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ksp"))
        .env("KSP_HOME", home)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");

    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (
        output.status.code().expect("the binary exited normally"),
        text,
    )
}

/// Criterion 4 and 6: an existing configuration is reported and not modified.
#[test]
fn an_existing_configuration_is_reported_and_left_alone_by_both_verbs() {
    let home = tempfile::tempdir().expect("home");
    let path = Layout::new(home.path()).capability_config_file();
    let theirs = "# hand-written\n[confinement]\nadapters = [\"landlock\"]\n\
                  requirement = \"required\"\n\n[memory_barrier]\nadapters = [\"mlock\"]\n\
                  requirement = \"optional\"\n";
    fs::write(&path, theirs).expect("the operator's file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");

    for args in [vec!["init"], vec!["config", "init"]] {
        let (code, text) = ksp_in(home.path(), &args);
        assert_eq!(code, 0, "{args:?} reports rather than fails: {text}");
        assert!(
            text.contains("already exists"),
            "{args:?} must say a configuration exists: {text}"
        );
        assert_eq!(
            fs::read_to_string(&path).expect("the file is there"),
            theirs,
            "{args:?} must not change one byte of the operator's file"
        );
    }
}

/// FR-021 — `ksp init` is the first run, on a host with no home yet.
///
/// The end-to-end form of the unit test: this is the case that failed, and the
/// fix has to hold through dispatch, not only through `configure`.
#[test]
fn init_creates_the_home_and_the_configuration_on_a_first_run() {
    let parent = tempfile::tempdir().expect("parent");
    let home = parent.path().join(".ksp");
    assert!(!home.exists(), "the fixture must not pre-create the home");

    let (code, text) = ksp_in(&home, &["init"]);

    assert_eq!(code, 0, "a first run succeeds: {text}");
    let path = Layout::new(&home).capability_config_file();
    assert!(path.is_file(), "the configuration is written: {text}");
    assert_eq!(
        fs::metadata(&path).expect("the file exists").mode() & 0o777,
        0o600,
        "criterion 7: the written file is private"
    );
    assert_eq!(
        fs::metadata(&home).expect("the home exists").mode() & 0o777,
        HOME_MODE,
        "the home carries the layout table's mode"
    );
    assert!(text.contains("does not guarantee"), "{text}");
}

/// Misfit J — `--force` replaces, and the replacement is private again.
#[test]
fn force_replaces_the_file_and_keeps_it_private() {
    let home = tempfile::tempdir().expect("home");
    let path = Layout::new(home.path()).capability_config_file();
    fs::write(&path, "not even toml").expect("a file to replace");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("a looser mode");

    let (code, text) = ksp_in(home.path(), &["config", "init", "--force"]);

    assert_eq!(code, 0, "the repair path succeeds: {text}");
    let written = fs::read_to_string(&path).expect("the file is written");
    assert!(
        written.contains("[memory_barrier]"),
        "the probed configuration replaced the old content: {written}"
    );
    assert_eq!(
        fs::metadata(&path).expect("the file exists").mode() & 0o777,
        0o600,
        "replacing a 0644 file must tighten it to 0600"
    );
}

/// A write failure is not a lease refusal.
///
/// The probe used to return the code whose published sentence is "the backend
/// or the host layout cannot admit this lease". The true reason was printed on
/// the line above, so the mismatch was invisible unless the whole output was
/// read — and a script reads only the code and its sentence.
#[test]
fn a_configuration_that_cannot_be_written_is_not_reported_as_a_lease_refusal() {
    let home = tempfile::tempdir().expect("home");
    // Read and traverse, but not write: the probe cannot create the file.
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o500)).expect("a read-only home");

    let (code, text) = ksp_in(home.path(), &["config", "init", "--force"]);

    // Restore the mode first: a failing assertion must not leave a directory the
    // harness cannot clean up.
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).expect("mode restored");

    assert_ne!(
        code, 0,
        "an unwritable configuration is not a success: {text}"
    );
    assert_ne!(code, 7, "code 7 means a lease refusal, not a write failure");
    assert!(
        text.contains("could not be written"),
        "the real reason is printed: {text}"
    );
    assert!(
        !text.contains("lease"),
        "the refusal must not borrow a sentence written for a lease: {text}"
    );
}
