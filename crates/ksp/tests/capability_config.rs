//! Reading `config.toml`: the mode guard, the parser and the refusals.
//!
//! # What these prove that a unit test on the parser cannot
//!
//! The file is the downgrade path (Misfit D). Every command keeps working while
//! its mode permits another principal to write it, so nothing fails until
//! someone changes what the deployment is allowed to establish. The guard is
//! therefore a **check on the filesystem object**, not on the document: these
//! tests write real files with real modes and read them through the real
//! reader.
//!
//! # Two misfits, two kinds of test
//!
//! - **D** is about the file: mode, owner, and the order of the check.
//! - **C** is about the content: a malformed document and an unknown adapter
//!   name are different mistakes with different fixes, so they must be
//!   different refusals.
//!
//! A test that asserted only "an error happened" would pass against a reader
//! that reported every failure with one message, which is the defect T031
//! exists to prevent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ksp::capability_config::{
    ConfigurationRefusal, FILE_NAME, StoredConfiguration, is_private, read,
};
use ksp::config::Layout;
use ksp_types::capability_config::{
    AdapterName, CapabilityConfiguration, GuaranteeLevel, HostCapability, RequirementLevel,
};

/// A home containing a `config.toml` with `contents` and `mode`.
///
/// The mode is set explicitly after the write: `umask` masks the mode a file is
/// *created* with, not the mode it *has*, and these tests are about the mode it
/// has.
fn home_with(contents: &str, mode: u32) -> (tempfile::TempDir, PathBuf) {
    let home = tempfile::tempdir().expect("a temporary home");
    let path = home.path().join(FILE_NAME);
    fs::write(&path, contents).expect("the configuration is written");
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))
        .expect("the mode is set explicitly");
    (home, path)
}

/// A complete document naming `confinement_adapters` and `barrier_adapters`.
fn document(confinement_adapters: &str, barrier_adapters: &str) -> String {
    format!(
        "[confinement]\nadapters = {confinement_adapters}\nrequirement = \"required\"\n\n\
         [memory_barrier]\nadapters = {barrier_adapters}\nrequirement = \"optional\"\n"
    )
}

/// A valid document whose preference order is **not** alphabetical.
///
/// The order matters and a sorted list would silently change it, so the fixture
/// must offer a reader that sorts the chance to be caught: an alphabetical
/// fixture passes against a sorting reader and proves nothing.
fn valid_document() -> String {
    document(r#"["portable_confinement", "landlock"]"#, r#"["mlock"]"#)
}

/// The refusal a read produced, or a panic naming the success it got instead.
fn refusal(layout: &Layout) -> ConfigurationRefusal {
    match read(layout) {
        Ok(Some(config)) => panic!("the reader accepted a file it must refuse: {config:?}"),
        Ok(None) => panic!("the reader reported the file absent"),
        Err(refusal) => refusal,
    }
}

// ---------------------------------------------------------------------------
// Criterion 5 — a missing file is the unconfigured state, not an error
// ---------------------------------------------------------------------------

/// A home with no `config.toml` reads as unconfigured.
///
/// FR-004: a missing file is not an error. It is the state in which every
/// capability is unconfigured and no adapter is selected — which is why the
/// reader answers `None` rather than a document full of empty lists. An empty
/// list is a document the operator wrote; `None` is a document they did not.
#[test]
fn a_missing_file_is_unconfigured_and_selects_no_adapter() {
    let home = tempfile::tempdir().expect("a temporary home");
    let layout = Layout::new(home.path());

    assert!(
        !layout.capability_config_file().exists(),
        "the fixture must not create the file it is testing the absence of"
    );

    let read_back = read(&layout).expect("an absent file is not an error");
    assert_eq!(
        read_back, None,
        "an absent file is the unconfigured state, and no adapter is selected"
    );
}

// ---------------------------------------------------------------------------
// Criterion 1 of T029 — a valid document is read and validated
// ---------------------------------------------------------------------------

/// A private, valid document is read, and the adapter order is preserved.
///
/// The order is the preference (WP04 walks it in order and takes the first
/// adapter the host confirms). A reader that sorted the list, or that stored it
/// in a set, would silently change which mechanism the operator gets — and the
/// document would still look valid.
#[test]
fn a_private_file_is_read_and_its_adapter_order_is_preserved() {
    let (home, _path) = home_with(&valid_document(), 0o600);
    let layout = Layout::new(home.path());

    let configuration = read(&layout)
        .expect("a private, valid file is read")
        .expect("the file is present");

    assert_eq!(
        configuration
            .confinement
            .adapters
            .iter()
            .map(AdapterName::as_str)
            .collect::<Vec<_>>(),
        vec!["portable_confinement", "landlock"],
        "the order the operator wrote is the preference order, so it must survive"
    );
    assert_eq!(
        configuration.memory_barrier.adapters.len(),
        1,
        "the barrier list is read from its own table"
    );
    assert_eq!(
        configuration.confinement.requirement,
        RequirementLevel::Required,
        "the requirement level is read from the document, not defaulted"
    );
    assert_eq!(
        configuration.memory_barrier.requirement,
        RequirementLevel::Optional,
        "each capability carries its own requirement level"
    );
    // The reason the requirement matters: it decides whether a missing
    // mechanism refuses the run or only weakens the posture.
    assert_eq!(RequirementLevel::Required.label(), "required");
    assert_eq!(GuaranteeLevel::None.label(), "none");
}

// ---------------------------------------------------------------------------
// Misfit D / criterion 3 — a file another principal can write is refused
// ---------------------------------------------------------------------------

/// A file writable by another principal is refused, and the mode is named.
///
/// The mode is the finding. An operator who is told only "the configuration is
/// not private" has to guess which of the three write bits is set.
#[test]
fn a_file_writable_by_another_principal_is_refused_with_the_mode_it_found() {
    // `0622` is group-readable and writable by the group and by everyone. Only
    // the group/other **write** bits matter here: the file holds no secret
    // (FR-016), so readability by another principal is not the hazard.
    let (home, _path) = home_with(&valid_document(), 0o622);
    let layout = Layout::new(home.path());

    let refused = refusal(&layout);
    assert!(
        matches!(refused, ConfigurationRefusal::NotPrivate { mode, .. } if mode == 0o622),
        "the refusal must carry the mode it found: {refused:?}"
    );
    assert!(
        refused.to_string().contains("0622"),
        "the refusal must print the mode, not only carry it: {refused}"
    );
    assert!(
        refused.to_string().contains(FILE_NAME),
        "the refusal must name the file: {refused}"
    );
}

/// Criterion 6 — a file refused for its mode is never parsed.
///
/// # Why this test can tell the difference
///
/// The file's content is not a valid document. A reader that parsed first and
/// checked the mode afterwards would answer `Malformed`. A reader that checks
/// first answers `NotPrivate`. So the **variant** is the evidence, and an
/// assertion that "some error happened" would pass either way.
///
/// This is the whole point of the guard: reading a file you are about to refuse
/// is trusting it, and a mode that permits another principal to write means the
/// content cannot be trusted even once.
#[test]
fn a_file_refused_for_its_mode_is_never_parsed() {
    let (home, path) = home_with("this is not = [valid toml", 0o666);
    let layout = Layout::new(home.path());

    assert_eq!(
        path,
        layout.capability_config_file(),
        "the fixture must write the file the reader reads"
    );

    let refused = refusal(&layout);
    assert!(
        matches!(refused, ConfigurationRefusal::NotPrivate { .. }),
        "the mode check must run before the content is parsed, so a file with \
         unparseable content and a bad mode is refused for its mode: {refused:?}"
    );
    assert!(
        !refused.to_string().contains("valid toml"),
        "the refusal must not quote content it never read: {refused}"
    );
}

/// The guard's condition, without needing a second UNIX account.
///
/// The file that carries another owner cannot be produced here: changing a file's
/// owner needs root, and the gate runs unprivileged. The predicate is the same
/// function the reader calls, so testing it here covers the case the file test
/// cannot reach.
#[test]
fn the_guard_accepts_only_a_file_no_other_principal_can_write() {
    // Trusted: only the owner can write it. The group and world bit vary with the
    // deployment — a shared deployment widens the file so a second principal can
    // read it, and that is not a write path.
    assert!(is_private(0o600), "owner-only");
    assert!(
        is_private(0o640),
        "a group-readable file is not a write path: FR-009 refuses writing, and \
         the file carries no secret (FR-016)"
    );
    assert!(
        is_private(0o644),
        "a file a second principal must read is accepted: the admin writes the \
         configuration the agent's process reads to confine its child, and the \
         home owns the question of who can replace the file"
    );
    assert!(is_private(0o400), "a read-only file is the safest kind");

    // Not trusted: another principal can write it.
    assert!(!is_private(0o620), "group-writable");
    assert!(!is_private(0o602), "world-writable");
    assert!(!is_private(0o666), "both");
    assert!(
        !is_private(0o664),
        "a file the group can write decides what the deployment establishes, \
         whatever else it grants"
    );
}

// ---------------------------------------------------------------------------
// Misfit C / criterion 4 — malformed and unknown adapter are different
// ---------------------------------------------------------------------------

/// A malformed file names the file and the parser's reason.
#[test]
fn a_malformed_file_names_the_parser_reason_and_the_file() {
    let (home, _path) = home_with("not = [valid toml", 0o600);
    let layout = Layout::new(home.path());

    let refused = refusal(&layout);
    let text = refused.to_string();
    assert!(
        matches!(refused, ConfigurationRefusal::Malformed { .. }),
        "unparseable content is a malformed document: {refused:?}"
    );
    assert!(
        text.contains(FILE_NAME),
        "the refusal names the file: {text}"
    );
    assert!(
        text.contains("line"),
        "the parser's reason names a line, so the operator can find the mistake: {text}"
    );
}

/// An unknown adapter name names the key and the value.
///
/// Not "an unknown adapter": the operator has to be told **which** entry, or the
/// only way to find it is to read the file again.
#[test]
fn an_unknown_adapter_name_names_the_key_and_the_value() {
    let (home, _path) = home_with(
        &document(r#"["landlock", "selinux"]"#, r#"["mlock"]"#),
        0o600,
    );
    let layout = Layout::new(home.path());

    let refused = refusal(&layout);
    assert_eq!(
        refused,
        ConfigurationRefusal::UnknownAdapter {
            path: layout.capability_config_file(),
            key: "confinement.adapters[1]".to_string(),
            value: "selinux".to_string(),
        },
        "the refusal must name the key and the value"
    );
    let text = refused.to_string();
    assert!(
        text.contains("selinux") && text.contains("confinement.adapters[1]"),
        "the rendered refusal names both: {text}"
    );
    assert!(
        text.contains("landlock"),
        "the refusal must name the adapters the build could have offered (FR-010): {text}"
    );
}

/// Criterion 4 — the two mistakes produce two different refusals.
///
/// This is the criterion stated as a comparison, because either message on its
/// own could be "an error" and satisfy a weaker test. Rendered text that failed
/// to distinguish them would leave the operator with one sentence for two
/// problems with different fixes.
#[test]
fn a_malformed_file_and_an_unknown_adapter_name_are_two_different_refusals() {
    let (malformed_home, _) = home_with("not = [valid toml", 0o600);
    let (unknown_home, _) = home_with(
        &document(r#"["landlock", "selinux"]"#, r#"["mlock"]"#),
        0o600,
    );

    let malformed = refusal(&Layout::new(malformed_home.path()));
    let unknown = refusal(&Layout::new(unknown_home.path()));

    assert_ne!(
        std::mem::discriminant(&malformed),
        std::mem::discriminant(&unknown),
        "a malformed file and an unknown adapter name are different mistakes"
    );
    assert_ne!(
        malformed.to_string(),
        unknown.to_string(),
        "one message for both would serve neither"
    );
    assert!(
        !malformed.to_string().contains("adapter") && unknown.to_string().contains("adapter"),
        "the malformed refusal must not blame an adapter it never found: \
         malformed={malformed} unknown={unknown}"
    );
}

/// An adapter that belongs to the other capability is refused as a value.
///
/// `confinement.adapters = ["mlock"]` is a document the closed set accepts by
/// name and the registry cannot resolve for that capability: `mlock` is a memory
/// barrier. Accepting it would make the reader answer "the host cannot establish
/// path confinement" for a configuration the operator could fix in one word —
/// a false statement about the host (Misfit L).
#[test]
fn an_adapter_from_the_other_capability_is_refused() {
    let (home, _path) = home_with(&document(r#"["memfd_secret"]"#, r#"["mlock"]"#), 0o600);
    let layout = Layout::new(home.path());

    let refused = refusal(&layout);
    assert_eq!(
        refused,
        ConfigurationRefusal::WrongCapability {
            path: layout.capability_config_file(),
            key: "confinement.adapters[0]".to_string(),
            value: "memfd_secret".to_string(),
            capability: HostCapability::PathConfinement,
        },
        "an adapter outside the capability's registry is a value error"
    );
    let text = refused.to_string();
    assert!(
        text.contains("path confinement") && text.contains("memfd_secret"),
        "the refusal names the capability and the value: {text}"
    );
}

// ---------------------------------------------------------------------------
// T031's third kind — an unreadable file
// ---------------------------------------------------------------------------

/// A path that is not a readable regular file is reported as unreadable.
///
/// The path here is a directory with a mode the guard accepts, so the refusal
/// cannot be blamed on the mode. A directory opens without complaint and fails
/// only when read, which is why it reaches the `is_file` check.
#[test]
fn an_unreadable_path_is_reported_as_unreadable() {
    let home = tempfile::tempdir().expect("a temporary home");
    let path = home.path().join(FILE_NAME);
    fs::create_dir(&path).expect("a directory stands in for the file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .expect("the mode is set explicitly");

    let layout = Layout::new(home.path());
    let refused = refusal(&layout);
    assert!(
        matches!(refused, ConfigurationRefusal::Unreadable { .. }),
        "a directory is not a document: {refused:?}"
    );
    assert!(
        refused.to_string().contains(FILE_NAME),
        "the refusal names the file: {refused}"
    );
}

/// A FIFO at the configuration path is refused, and does not hang the command.
///
/// # Why this test uses a timeout
///
/// `open(2)` on a FIFO with no writer **blocks until a writer appears**, so a
/// reader that opens before it checks is not merely wrong: it stops, with no
/// output, and the operator has no way to tell that from a slow command. The
/// assertion is therefore about **returning at all**, which needs a deadline —
/// a test that simply called the reader would hang forever alongside the
/// defect, and a hung test reports nothing either.
///
/// The read runs on its own thread so the deadline can be measured. Reaching
/// the timeout means the reader blocked, which is the failure this pins.
#[test]
fn a_fifo_is_refused_instead_of_hanging_the_command() {
    let home = tempfile::tempdir().expect("a temporary home");
    let path = home.path().join(FILE_NAME);
    let made = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo is available on a POSIX host");
    assert!(made.success(), "the fixture must create a FIFO");

    let layout = Layout::new(home.path());
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // The result is sent, not asserted on: an assertion belongs to the test
        // thread, where a failure is reported against the test rather than
        // against a detached thread nobody joins.
        let _ = sender.send(read(&layout));
    });

    let answer = receiver
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the reader must return rather than block on a FIFO");

    match answer {
        Ok(other) => panic!("a FIFO is not a document, but the reader accepted it: {other:?}"),
        Err(refused) => assert!(
            matches!(refused, ConfigurationRefusal::Unreadable { .. }),
            "a FIFO is refused as unreadable: {refused:?}"
        ),
    }
}

// ---------------------------------------------------------------------------
// Criterion 7 — the reader holds no secret and no vault state
// ---------------------------------------------------------------------------

/// A document cannot smuggle a field the schema does not name.
///
/// FR-016: the configuration holds capability names and requirement levels only.
/// `deny_unknown_fields` is what makes that structural rather than a convention:
/// there is no field a secret could be written into, so `ksp config` cannot
/// become a place an operator keeps a passphrase.
#[test]
fn a_configuration_cannot_carry_a_secret_field() {
    let contents = "[confinement]\nadapters = [\"landlock\"]\nrequirement = \"required\"\n\
                    secret = \"correct-horse-battery-staple\"\n\n\
                    [memory_barrier]\nadapters = [\"mlock\"]\nrequirement = \"optional\"\n";
    let (home, _path) = home_with(contents, 0o600);
    let layout = Layout::new(home.path());

    let refused = refusal(&layout);
    assert!(
        matches!(refused, ConfigurationRefusal::Malformed { .. }),
        "a field the schema does not name is refused: {refused:?}"
    );
    assert!(
        !refused.to_string().contains("correct-horse"),
        "the refusal must not echo the value it refused: {refused}"
    );
}

/// An unknown capability table is refused rather than ignored.
///
/// A silently ignored table would let an operator believe they had configured
/// something. FR-003 asks for every key and value to be validated, and a table
/// the schema does not know is a key it cannot validate.
#[test]
fn an_unknown_capability_table_is_refused() {
    let contents = "[confinement]\nadapters = [\"landlock\"]\nrequirement = \"required\"\n\n\
                    [memory_barrier]\nadapters = [\"mlock\"]\nrequirement = \"optional\"\n\n\
                    [filesystem]\nadapters = [\"zfs\"]\nrequirement = \"required\"\n";
    let (home, _path) = home_with(contents, 0o600);
    let layout = Layout::new(home.path());

    assert!(
        matches!(refusal(&layout), ConfigurationRefusal::Malformed { .. }),
        "a table the schema does not name is a key that cannot be validated"
    );
}

// ---------------------------------------------------------------------------
// The round trip the probe depends on (WP07), and the CF-023 trap
// ---------------------------------------------------------------------------

/// A `StoredConfiguration` the reader's own writer produced is read back.
///
/// WP07's probe writes a `StoredConfiguration` and hands it to this validator
/// before writing, so the two halves have to agree on the spelling of every
/// value. CF-023 is the precedent: a derived `Serialize` that wrote an enum's
/// discriminant while its `Deserialize` read the identifier produced documents
/// nothing could read, and only a round trip noticed.
#[test]
fn a_written_configuration_is_read_back() {
    let (home, path) = home_with(&valid_document(), 0o600);
    let layout = Layout::new(home.path());

    let read_back: CapabilityConfiguration = read(&layout)
        .expect("the document is read")
        .expect("the file is present");

    let stored = StoredConfiguration::from(&read_back);
    let rewritten = toml::to_string_pretty(&stored).expect("the probe can write what it read");

    // The written document is one this reader accepts, byte for byte: that is
    // what lets the probe validate before it writes.
    fs::write(&path, &rewritten).expect("the rewritten file is written");
    let read_again = read(&layout)
        .expect("a document this reader wrote is a document it accepts")
        .expect("the file is present");

    assert_eq!(
        read_again, read_back,
        "the round trip must preserve every value, including the adapter order"
    );
    assert!(
        rewritten.contains("\"landlock\""),
        "the written document spells the adapter name, not its discriminant: {rewritten}"
    );
}

/// A `StoredConfiguration` built by hand validates the same way the file does.
///
/// The probe constructs the value in memory rather than parsing a file, so the
/// validator has to be reachable without one — and it has to give the same
/// refusal, because the probe must not write a document the reader would reject.
#[test]
fn a_stored_configuration_validates_without_a_file() {
    let stored = StoredConfiguration {
        confinement: ksp::capability_config::StoredSetting {
            adapters: vec!["landlock".to_string()],
            requirement: RequirementLevel::Required,
        },
        memory_barrier: ksp::capability_config::StoredSetting {
            adapters: vec!["mlock".to_string()],
            requirement: RequirementLevel::Optional,
        },
    };
    let named = Path::new("/nonexistent/config.toml");

    let validated = stored
        .validated(named)
        .expect("a document naming adapters of the right capability validates");
    assert_eq!(validated.memory_barrier.adapters.len(), 1);

    let refused = StoredConfiguration {
        confinement: ksp::capability_config::StoredSetting {
            adapters: vec!["zfs".to_string()],
            requirement: RequirementLevel::Required,
        },
        ..stored
    }
    .validated(named)
    .expect_err("the same document with an unknown name is refused");
    assert!(
        matches!(refused, ConfigurationRefusal::UnknownAdapter { .. }),
        "the in-memory validator gives the same refusal the file reader gives: {refused:?}"
    );
}
