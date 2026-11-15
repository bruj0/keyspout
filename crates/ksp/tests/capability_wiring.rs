//! The capability configuration, wired into the commands an operator runs.
//!
//! # What these prove that the module tests cannot
//!
//! `capability_config` proves the file is parsed and guarded. `establish` proves
//! the decision is right. Neither proves that a **command** reads the file
//! before it touches a capability, or that a refusal reaches the operator with
//! the file and the key in it — and both of those are the difference between a
//! library and a control (T040, T042).
//!
//! # Why these spawn the binary instead of calling `dispatch`
//!
//! A refused invocation has an exit code and a sentence, and the pair is the
//! contract a script reads. Calling `dispatch` in-process would test the pair
//! without the printing `main` does, which is exactly the layer where WP06's
//! write failure borrowed code 7 and printed a true reason followed by a false
//! one.
//!
//! # Every test here builds its own home and never calls `configure`
//!
//! Unlike the other fixtures, a configuration is this file's subject: half these
//! tests are about a host that has none, so the helper the rest of the suite uses
//! would erase what they assert.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use ksp::config::Layout;
use ksp::exit;
use ksp_posture::adapters::confinement_adapter;
use ksp_posture::capability_of;
use ksp_types::capability_config::{AdapterAvailability, AdapterName, HostCapability};

fn ksp() -> &'static str {
    env!("CARGO_BIN_EXE_ksp")
}

/// Run `ksp` with this home and return (exit code, stdout and stderr).
fn ksp_in(home: &Path, args: &[&str]) -> (i32, String) {
    let output = Command::new(ksp())
        .env("KSP_HOME", home)
        .env("LC_ALL", "C")
        .args(args)
        .output()
        .expect("the binary runs");
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.code().unwrap_or(-1), combined)
}

/// The document `ksp init` writes, spelled here so a test can change one field.
///
/// The requirement is `optional` for both capabilities, so the document is
/// satisfiable on every gate host: a `required` confinement refuses on macOS and
/// a `required` barrier is fine everywhere, and a fixture that depends on which
/// host is running is a fixture that fails for the wrong reason.
const SATISFIABLE: &str = "\
[confinement]
adapters = [\"portable_confinement\"]
requirement = \"optional\"

[memory_barrier]
adapters = [\"mlock\"]
requirement = \"optional\"
";

/// Write `contents` as this home's `config.toml` with `mode`.
fn write_configuration(home: &Path, contents: &str, mode: u32) {
    let path = Layout::new(home).capability_config_file();
    std::fs::write(&path, contents).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// T040: a malformed document refuses the command before any capability is
/// touched, and the refusal names the file.
#[test]
fn a_malformed_configuration_refuses_before_a_capability_is_touched() {
    let home = tempfile::tempdir().unwrap();
    // A syntax error, and a value that is not TOML at all.
    write_configuration(home.path(), "this is not a document", 0o600);

    let (code, output) = ksp_in(home.path(), &["status"]);

    assert_eq!(
        code,
        exit::POLICY_DENIAL,
        "a file the operator wrote wrong is a policy denial: {output}"
    );
    assert!(
        output.contains("config.toml"),
        "the refusal must name the file: {output}"
    );
    // The reader's own reason, which names where to look. It must not echo the
    // document: a passphrase pasted into config.toml would be printed back
    // (FR-016).
    assert!(
        output.contains("line") && output.contains("column"),
        "the refusal must say where: {output}"
    );
    assert!(
        !output.contains("this is not a document"),
        "the refusal must not quote the document: {output}"
    );

    // And nothing was created on the way: a refused command establishes no
    // capability and provisions nothing.
    let layout = Layout::new(home.path());
    assert!(
        !layout.store_root().exists(),
        "a refused command must not create the store"
    );
}

/// FR-008: an adapter name the build does not contain is named with its key, and
/// no default is substituted.
#[test]
fn an_unknown_adapter_name_is_refused_with_its_key_and_value() {
    let home = tempfile::tempdir().unwrap();
    write_configuration(
        home.path(),
        &SATISFIABLE.replace("portable_confinement", "seatbelt"),
        0o600,
    );

    let (code, output) = ksp_in(home.path(), &["status"]);

    assert_eq!(code, exit::POLICY_DENIAL, "{output}");
    assert!(
        output.contains("confinement.adapters[0]"),
        "the refusal must name the key: {output}"
    );
    assert!(
        output.contains("seatbelt"),
        "the refusal must name the value: {output}"
    );
    assert!(
        output.contains("landlock"),
        "and it must name the adapters this build contains: {output}"
    );
}

/// FR-009: a file another principal can write is the boundary, and it exits as a
/// capability refusal rather than as a typo.
///
/// # Why the mode is `0664` and not `0644`
///
/// FR-009 and SC-007 are about a principal who can **write** the file, which is
/// the downgrade path Misfit D describes. `0644` is readable by everyone and
/// writable only by its owner, and the file holds no secret (FR-016), so the
/// reader accepts it. The test uses a group-writable mode, which is the case the
/// requirement names.
#[test]
fn a_configuration_another_principal_can_write_is_refused_with_its_mode() {
    let home = tempfile::tempdir().unwrap();
    write_configuration(home.path(), SATISFIABLE, 0o664);

    let (code, output) = ksp_in(home.path(), &["status"]);

    assert_eq!(
        code,
        exit::CAPABILITY_REFUSAL,
        "the widened file is the boundary, not a mistake in the document: {output}"
    );
    assert!(
        output.contains("0664"),
        "the refusal names the mode: {output}"
    );
    assert!(output.contains("config.toml"), "and the file: {output}");
}

/// The private file the probe writes is read without complaint.
///
/// The other half of FR-009: a configuration owned by the invoking principal and
/// writable only by it is applied. Without this the guard could refuse every file
/// and the tests above would still pass.
#[test]
fn a_private_configuration_is_read_and_applied() {
    let home = tempfile::tempdir().unwrap();
    write_configuration(home.path(), SATISFIABLE, 0o600);

    let (code, output) = ksp_in(home.path(), &["status"]);

    assert_eq!(code, exit::SUCCESS, "{output}");
    assert!(
        !output.contains("is not private"),
        "the guard must accept its own file: {output}"
    );
}

/// T042 and SC-001: a host with no configuration reports both capabilities as
/// unconfigured, names the adapters the build could have offered, points at
/// `ksp init`, and **writes nothing**.
#[test]
fn status_on_a_host_with_no_configuration_reports_both_capabilities_unconfigured() {
    let home = tempfile::tempdir().unwrap();

    let (code, output) = ksp_in(home.path(), &["status"]);

    assert_eq!(
        code,
        exit::SUCCESS,
        "status needs no configuration to describe the host: {output}"
    );

    let lines: Vec<&str> = output
        .lines()
        .filter(|line| line.starts_with("host:"))
        .collect();
    assert_eq!(
        lines.len(),
        HostCapability::ALL.len(),
        "one row per host capability, whether or not it is configured: {output}"
    );
    for capability in HostCapability::ALL {
        let row = lines
            .iter()
            .find(|line| line.contains(capability.label()))
            .unwrap_or_else(|| panic!("no row for {}: {output}", capability.label()));
        assert!(
            row.contains("unconfigured"),
            "an unconfigured capability says so: {row}"
        );
        assert!(
            row.contains("ksp init"),
            "and points at the command that fixes it: {row}"
        );
        // FR-010: the adapters the build could have offered.
        for name in AdapterName::ALL {
            let parsed = AdapterName::parse(name).expect("in the closed set");
            if capability_of(parsed.kind()) == capability {
                assert!(
                    row.contains(name),
                    "the row must name `{name}`, which this build contains for {}: {row}",
                    capability.label()
                );
            }
        }
    }

    // SC-001's other half: it writes nothing. No configuration, no store, no key
    // root — a status command that provisioned would make "unconfigured"
    // unreachable after the first look.
    let layout = Layout::new(home.path());
    assert!(
        !layout.capability_config_file().exists(),
        "status must not write a configuration"
    );
    assert!(
        !layout.store_root().exists(),
        "status must not create the store"
    );
}

/// T042 and FR-014: the status line names the platform, the configured order, the
/// adapter selected and the guarantee.
#[test]
fn status_names_the_platform_the_configured_order_and_the_selected_adapter() {
    let home = tempfile::tempdir().unwrap();
    write_configuration(home.path(), SATISFIABLE, 0o600);

    let (code, output) = ksp_in(home.path(), &["status"]);
    assert_eq!(code, exit::SUCCESS, "{output}");

    // FR-037: the platform, so a reader can tell one host from another without
    // reading the configuration.
    assert!(
        output.contains(&format!("platform:    {}", std::env::consts::OS)),
        "the document names the platform it is running on: {output}"
    );

    let confinement = output
        .lines()
        .filter(|line| line.starts_with("host:"))
        .find(|line| line.contains(HostCapability::PathConfinement.label()))
        .unwrap_or_else(|| panic!("no confinement row: {output}"));
    // The configured order, as the operator wrote it.
    assert!(
        confinement.contains("configured portable_confinement"),
        "the row names the configured order: {confinement}"
    );
    // The adapter that ran, and its guarantee. `portable_confinement` establishes
    // nothing, and the row says so in the same terms as an enforced capability
    // (FR-038).
    assert!(
        confinement.contains("ran portable_confinement (none)"),
        "the row names the adapter that ran and its level: {confinement}"
    );
    assert!(
        !confinement.contains("unconfigured"),
        "a configured capability is not reported as unconfigured: {confinement}"
    );
}

/// FR-030: a fallback reports the fallback's level, never the preferred
/// adapter's.
#[test]
fn a_fallback_reports_the_adapter_that_ran_and_why_the_first_did_not() {
    let home = tempfile::tempdir().unwrap();
    // The first entry is unavailable on a host without Landlock and available on
    // one with it; either way `sealed_memfd` runs only if the host lacks
    // `memfd_secret`. The assertion therefore comes from the adapters, not from a
    // guess about the host.
    write_configuration(
        home.path(),
        "\
[confinement]
adapters = [\"landlock\", \"portable_confinement\"]
requirement = \"optional\"

[memory_barrier]
adapters = [\"memfd_secret\", \"sealed_memfd\", \"mlock\"]
requirement = \"optional\"
",
        0o600,
    );

    let (code, output) = ksp_in(home.path(), &["status"]);
    assert_eq!(code, exit::SUCCESS, "{output}");

    let row = |capability: HostCapability| -> String {
        output
            .lines()
            .filter(|line| line.starts_with("host:"))
            .find(|line| line.contains(capability.label()))
            .unwrap_or_else(|| panic!("no row for {}: {output}", capability.label()))
            .to_string()
    };

    let barrier = row(HostCapability::MemoryBarrier);
    // The order is the preference, and the report follows it: whichever of the
    // three the host confirms is the one named as having run.
    let ran = AdapterName::ALL
        .iter()
        .find(|name| barrier.contains(&format!("ran {name} (")))
        .unwrap_or_else(|| panic!("the row names no adapter as having run: {barrier}"));
    let expected_level =
        ksp_posture::memory_barrier_adapter(&AdapterName::parse(ran).expect("in the closed set"))
            .expect("the registry holds every name in the closed set for its own capability")
            .guarantee();
    assert!(
        barrier.contains(&format!("({})", expected_level.label())),
        "the row must carry the guarantee of the adapter that ran ({ran}): {barrier}"
    );

    // The confinement row: on a host without Landlock the skipped reason is the
    // host's own words, which is what makes the fallback explainable (Misfit B).
    let confinement = row(HostCapability::PathConfinement);
    match confinement_adapter(&AdapterName::parse("landlock").expect("in the closed set"))
        .expect("the registry holds landlock on every target")
        .availability()
    {
        AdapterAvailability::Available => assert!(
            confinement.contains("ran landlock (full)"),
            "a host that enforces Landlock runs it, and says so: {confinement}"
        ),
        AdapterAvailability::Unavailable { reason } => {
            assert!(
                confinement.contains("ran portable_confinement (none)"),
                "the portable adapter is the fallback and guarantees nothing: {confinement}"
            );
            assert!(
                confinement.contains(&reason),
                "the row must give the host's own reason for skipping Landlock: {confinement}"
            );
        }
    }
}

/// FR-014 and NFR-009: the row names the level the operator set, not only the
/// adapters.
///
/// # Why this is not a cosmetic line
///
/// The posture line beside it says `SoftRequirement` or `HardRequirement`, and
/// that word describes the ruleset `status` itself applied while measuring — an
/// optional one, on purpose, so a host that cannot confine is reported instead
/// of refusing. A reader who sees `SoftRequirement` and nothing else concludes
/// the capability is not required, and then the next `ksp run` refuses. The
/// level on this row is the one fact that says which will happen.
#[test]
fn the_status_row_names_the_level_the_operator_set() {
    let home = tempfile::tempdir().unwrap();
    write_configuration(
        home.path(),
        &SATISFIABLE.replace(
            "adapters = [\"portable_confinement\"]\nrequirement = \"optional\"",
            "adapters = [\"portable_confinement\"]\nrequirement = \"required\"",
        ),
        0o600,
    );

    let (code, output) = ksp_in(home.path(), &["status"]);
    assert_eq!(code, exit::SUCCESS, "{output}");

    let row = output
        .lines()
        .filter(|line| line.starts_with("host:"))
        .find(|line| line.contains(HostCapability::PathConfinement.label()))
        .unwrap_or_else(|| panic!("no confinement row: {output}"));
    assert!(
        row.contains("requirement required"),
        "the row must carry the configured level: {row}"
    );

    // The same level, on the other capability, written `optional`: the row must
    // not print one level for both.
    let barrier = output
        .lines()
        .filter(|line| line.starts_with("host:"))
        .find(|line| line.contains(HostCapability::MemoryBarrier.label()))
        .unwrap_or_else(|| panic!("no barrier row: {output}"));
    assert!(
        barrier.contains("requirement optional"),
        "each capability carries its own level: {barrier}"
    );
}

/// T042: a configuration that names no adapter this host provides says which
/// problem it is, and does not send the operator to a command that cannot fix
/// it.
///
/// # The two ways to be unconfigured
///
/// No file at all is fixed by `ksp init`. A file that names only adapters this
/// host lacks is not: SC-009 makes `ksp init` write nothing when a configuration
/// exists, and report that it exists. Telling an operator to run it on the same
/// line that just printed the order it would refuse to replace is an instruction
/// that cannot be followed.
///
/// # Why the fixture names `landlock` only
///
/// `landlock` is unavailable on macOS and available in the VM, so this test
/// branches on the adapter's own answer rather than on the host. On a host that
/// provides it, the row is a fallback-free success and the assertion flips to
/// "an adapter ran"; either way the assertion is derived, not guessed.
#[test]
fn a_configuration_the_host_cannot_satisfy_does_not_point_at_ksp_init() {
    let home = tempfile::tempdir().unwrap();
    write_configuration(
        home.path(),
        "\
[confinement]
adapters = [\"landlock\"]
requirement = \"optional\"

[memory_barrier]
adapters = [\"mlock\"]
requirement = \"optional\"
",
        0o600,
    );

    let (code, output) = ksp_in(home.path(), &["status"]);
    assert_eq!(code, exit::SUCCESS, "{output}");

    let row = output
        .lines()
        .filter(|line| line.starts_with("host:"))
        .find(|line| line.contains(HostCapability::PathConfinement.label()))
        .unwrap_or_else(|| panic!("no confinement row: {output}"));

    let availability =
        confinement_adapter(&AdapterName::parse("landlock").expect("in the closed set"))
            .expect("the registry holds landlock on every target")
            .availability();
    match availability {
        AdapterAvailability::Available => assert!(
            row.contains("ran landlock (full)"),
            "a host that provides the named adapter runs it: {row}"
        ),
        AdapterAvailability::Unavailable { reason } => {
            assert!(
                row.contains("unconfigured"),
                "nothing ran, and the row says so: {row}"
            );
            assert!(
                !row.contains("ksp init"),
                "a configuration exists, so `ksp init` would write nothing (SC-009) and \
                 pointing at it is an instruction that cannot be followed: {row}"
            );
            assert!(
                row.contains(&reason),
                "and the host's own reason is what the operator acts on: {row}"
            );
            assert!(
                row.contains("this build contains"),
                "the row still names what the build could have offered (FR-010): {row}"
            );
        }
    }
}
