//! The Host Probe, the write policy and what the two verbs report.
//!
//! # Why the host is described rather than measured
//!
//! The two gate hosts disagree about every mechanism: the Linux VM provides
//! Landlock and `memfd_secret`, macOS provides neither and has `mlock`. A test
//! that read the running host and asserted "confinement is required" would
//! pass on one and fail on the other while the code was identical. So every
//! assertion about a *decision* supplies the host through [`probe_with`], and
//! the assertions about the *file* supply the outcome through
//! [`configure_with`].
//!
//! The one test that does measure the real host asks a question that has the
//! same answer on both: whatever the probe writes, the reader accepts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use ksp::capability_config::{FILE_NAME, read};
use ksp::config::Layout;
use ksp::layout::HOME_MODE;
use ksp::probe::{
    CapabilityDisclosure, Observation, OverwritePolicy, ProbeError, ProbeOutcome, ProbeReport,
    ProbeSummary, configure, configure_with, probe_with, render,
};
use ksp_types::capability_config::{
    AdapterAvailability, AdapterName, CapabilityConfiguration, CapabilitySetting, GuaranteeLevel,
    HostCapability, RequirementLevel,
};

/// The Linux VM: everything the build has.
fn linux() -> fn(&AdapterName) -> Option<Observation> {
    fn everything(name: &AdapterName) -> Option<Observation> {
        let guarantee = match name.as_str() {
            "portable_confinement" => GuaranteeLevel::None,
            "mlock" | "sealed_memfd" => GuaranteeLevel::Weakened,
            _ => GuaranteeLevel::Full,
        };
        Some(Observation {
            guarantee,
            availability: AdapterAvailability::Available,
        })
    }
    everything
}

/// macOS: no Landlock, no `memfd`, `mlock` works and is weakened.
///
/// The portable confinement adapter is available and establishes nothing, which
/// is what FR-018 promises every host has.
fn macos() -> fn(&AdapterName) -> Option<Observation> {
    lookup_partial
}

/// One described host, chosen by adapter name.
fn lookup_partial(name: &AdapterName) -> Option<Observation> {
    let available = match name.as_str() {
        "portable_confinement" => Some(GuaranteeLevel::None),
        "mlock" => Some(GuaranteeLevel::Weakened),
        _ => None,
    };
    Some(match available {
        Some(guarantee) => Observation {
            guarantee,
            availability: AdapterAvailability::Available,
        },
        None => Observation {
            guarantee: GuaranteeLevel::Full,
            availability: AdapterAvailability::Unavailable {
                reason: "this host does not provide it".to_string(),
            },
        },
    })
}

/// A host whose strengths disagree with the closed set's order.
///
/// `memfd_secret` is declared before `sealed_memfd` in the closed set, so a
/// list that merely followed the declaration order would still look sorted on
/// either gate host — every adapter there is available at the strength the
/// declaration happens to put in the right place. This host reverses two of
/// them, which is the only way the sort can be seen doing anything.
fn reversed(name: &AdapterName) -> Option<Observation> {
    let guarantee = match name.as_str() {
        "memfd_secret" => GuaranteeLevel::Weakened,
        "sealed_memfd" => GuaranteeLevel::Full,
        "mlock" => GuaranteeLevel::None,
        "portable_confinement" => GuaranteeLevel::None,
        _ => GuaranteeLevel::Full,
    };
    Some(Observation {
        guarantee,
        availability: AdapterAvailability::Available,
    })
}

/// A host that provides nothing at all, not even the portable adapter.
///
/// Not a real host — FR-018 forbids it — but the probe has to answer for it,
/// because a capability with no adapter left must still produce a file the
/// reader accepts rather than an empty table.
fn barren(name: &AdapterName) -> Option<Observation> {
    let _ = name;
    Some(Observation {
        guarantee: GuaranteeLevel::None,
        availability: AdapterAvailability::Unavailable {
            reason: "nothing is provided".to_string(),
        },
    })
}

/// The disclosure entry for `capability`.
fn entry_of(outcome: &ProbeOutcome, capability: HostCapability) -> &CapabilityDisclosure {
    outcome
        .disclosure
        .iter()
        .find(|entry| entry.capability == capability)
        .expect("every capability is disclosed")
}

/// A fixed outcome, for the tests about the file rather than about the host.
fn fixed() -> ProbeOutcome {
    ProbeOutcome {
        configuration: CapabilityConfiguration {
            confinement: CapabilitySetting {
                adapters: vec![
                    AdapterName::parse("landlock").expect("a name in the set"),
                    AdapterName::parse("portable_confinement").expect("a name in the set"),
                ],
                requirement: RequirementLevel::Required,
            },
            memory_barrier: CapabilitySetting {
                adapters: vec![AdapterName::parse("mlock").expect("a name in the set")],
                requirement: RequirementLevel::Required,
            },
        },
        disclosure: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Misfit K — the probe decides the level, and says so
// ---------------------------------------------------------------------------

/// A host that cannot enforce a capability gets `optional`, not `required`.
///
/// This is FR-031 and the whole of Misfit K. Writing `required` here produces a
/// configuration that refuses every run on the host that wrote it — the probe
/// would ship a broken host.
#[test]
fn a_capability_nothing_enforces_is_written_optional() {
    let outcome = probe_with(macos());

    assert_eq!(
        outcome.configuration.confinement.requirement,
        RequirementLevel::Optional,
        "no enforcing mechanism on this host, so the level must not refuse every run"
    );
    assert_eq!(
        entry_of(&outcome, HostCapability::PathConfinement).guarantee,
        GuaranteeLevel::None,
        "the portable adapter is available but establishes nothing"
    );
    assert!(
        !entry_of(&outcome, HostCapability::PathConfinement).established(),
        "an adapter that establishes nothing has not established the capability"
    );
}

/// A host that can enforce a capability gets `required`.
///
/// The converse of the test above, and the reason the level cannot be a
/// constant: the same probe on the other gate host must not downgrade what the
/// host can actually do.
#[test]
fn a_capability_the_host_enforces_is_written_required() {
    let outcome = probe_with(linux());

    assert_eq!(
        outcome.configuration.confinement.requirement,
        RequirementLevel::Required
    );
    assert_eq!(
        outcome.configuration.memory_barrier.requirement,
        RequirementLevel::Required
    );
    assert_eq!(
        entry_of(&outcome, HostCapability::MemoryBarrier).guarantee,
        GuaranteeLevel::Full
    );
}

/// A weakened mechanism still counts as enforcement.
///
/// `mlock` buys residency and not secrecy, and it is a real mechanism. Treating
/// it as "nothing" would write `optional` for the one barrier macOS has, which
/// is a downgrade the host does not require.
#[test]
fn a_weakened_mechanism_is_still_an_enforced_capability() {
    let outcome = probe_with(macos());

    assert_eq!(
        outcome.configuration.memory_barrier.requirement,
        RequirementLevel::Required,
        "mlock is available and establishes a smaller guarantee, not none"
    );
    let entry = entry_of(&outcome, HostCapability::MemoryBarrier);
    assert_eq!(entry.guarantee, GuaranteeLevel::Weakened);
    assert_eq!(
        entry.selected.as_ref().map(AdapterName::as_str),
        Some("mlock"),
        "the selected adapter is the one the resolver will actually run"
    );
}

// ---------------------------------------------------------------------------
// NFR-008 — the weaker adapter is a fallback, not the only choice
// ---------------------------------------------------------------------------

/// The list holds every adapter of the capability, strongest first.
///
/// A single-adapter pin is the defect NFR-008 names: an operator who later
/// obtains a stronger mechanism would have no entry to move to. The order is
/// what makes strength win, because the resolver takes the first entry the host
/// provides.
#[test]
fn the_preference_list_is_every_adapter_strongest_first() {
    let outcome = probe_with(linux());

    assert_eq!(
        outcome
            .configuration
            .memory_barrier
            .adapters
            .iter()
            .map(AdapterName::as_str)
            .collect::<Vec<_>>(),
        vec!["memfd_secret", "sealed_memfd", "mlock"],
        "strongest first, and every name present so a weaker one is a fallback"
    );
    assert_eq!(
        outcome
            .configuration
            .confinement
            .adapters
            .iter()
            .map(AdapterName::as_str)
            .collect::<Vec<_>>(),
        vec!["landlock", "portable_confinement"],
        "the enforcing adapter leads the no-op fallback"
    );
}

/// The order follows the guarantee, not the order the closed set declares.
///
/// The gate hosts cannot show this: on both of them the strongest adapter is
/// also the one the closed set declares first, so a list in declaration order
/// would pass every other test in this file. A host whose strengths are
/// reversed is the only fixture where the sort is load-bearing.
#[test]
fn the_order_follows_the_guarantee_not_the_declaration_order() {
    let outcome = probe_with(reversed);

    let barrier: Vec<&str> = outcome
        .configuration
        .memory_barrier
        .adapters
        .iter()
        .map(AdapterName::as_str)
        .collect();
    assert_eq!(
        barrier.first().copied(),
        Some("sealed_memfd"),
        "the full guarantee leads even though memfd_secret is declared first: {barrier:?}"
    );
    assert_eq!(
        barrier.last().copied(),
        Some("mlock"),
        "the weakest is last: {barrier:?}"
    );
    assert_eq!(
        entry_of(&outcome, HostCapability::MemoryBarrier)
            .selected
            .as_ref()
            .map(AdapterName::as_str),
        Some("sealed_memfd"),
        "the resolver selects the first entry, so the strongest must be first"
    );
}

/// A host without `memfd_secret` still gets a list that names `mlock`.
///
/// Acceptance criterion 3, stated as the file content rather than as a sentence
/// about the host: `mlock` is present and it is not the only entry, so it is a
/// fallback in the sense NFR-008 uses.
#[test]
fn a_host_without_memfd_secret_still_lists_mlock() {
    let outcome = probe_with(macos());
    let barrier: Vec<&str> = outcome
        .configuration
        .memory_barrier
        .adapters
        .iter()
        .map(AdapterName::as_str)
        .collect();

    assert!(
        barrier.contains(&"mlock"),
        "the barrier this host can use must be in the list: {barrier:?}"
    );
    assert!(
        barrier.len() > 1,
        "a single entry is a pin, not a preference list: {barrier:?}"
    );
    assert_eq!(
        barrier.first().copied(),
        Some("memfd_secret"),
        "the strongest is offered first so a host that gains it needs no edit: {barrier:?}"
    );
}

// ---------------------------------------------------------------------------
// T034 — the probe holds no availability logic of its own
// ---------------------------------------------------------------------------

/// Every adapter of a capability is asked, and the none-available case is
/// answered rather than skipped.
///
/// A capability whose adapters are all absent must still produce a table, or
/// the reader refuses the document as missing a field. The probe cannot assume
/// FR-018 holds: it has to answer for the host it is given.
#[test]
fn a_host_that_provides_nothing_still_produces_a_readable_table() {
    let outcome = probe_with(barren);

    for entry in &outcome.disclosure {
        assert!(
            !entry.adapters.is_empty(),
            "{} has an empty preference list, which cannot be a document",
            entry.capability.config_key()
        );
        assert_eq!(
            entry.requirement,
            RequirementLevel::Optional,
            "{} enforces nothing here, so it must not be required",
            entry.capability.config_key()
        );
        assert!(
            entry.selected.is_none(),
            "{} selected an adapter on a host that provides none",
            entry.capability.config_key()
        );
    }
}

/// The disclosure names the host's reason for every adapter it cannot provide.
///
/// "Optional" without a reason reads like a choice the operator made. FR-022
/// asks for what the configuration does not guarantee, and the host's own words
/// are the part a reader cannot reconstruct.
#[test]
fn the_disclosure_names_each_unavailable_adapter_and_its_reason() {
    let outcome = probe_with(macos());
    let confinement = entry_of(&outcome, HostCapability::PathConfinement);

    assert_eq!(
        confinement
            .unavailable
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        vec!["landlock"],
        "only the unavailable adapter is listed as unavailable"
    );
    assert!(
        confinement.unavailable[0]
            .1
            .contains("this host does not provide it"),
        "the reason is the host's own words: {:?}",
        confinement.unavailable[0].1
    );
}

// ---------------------------------------------------------------------------
// Misfit I — the command prints what it wrote and what it does not guarantee
// ---------------------------------------------------------------------------

/// The rendered report carries the document **and** the disclosure.
///
/// FR-022 asks for two things, and a report that printed only the file would
/// satisfy the easier half. The `optional` line is the one an operator needs:
/// it says which capability this host cannot enforce and why.
#[test]
fn the_report_prints_the_configuration_and_what_it_gives_up() {
    let outcome = probe_with(macos());
    let report = configure_with(
        &Layout::new(tempfile::tempdir().expect("home").keep()),
        OverwritePolicy::Replace,
        outcome,
    )
    .expect("a described host writes a file");
    let summary = ProbeSummary::of(&report);
    let text = render(&summary);

    assert!(
        text.contains("[confinement]") && text.contains("[memory_barrier]"),
        "the configuration itself is printed: {text}"
    );
    assert!(
        text.contains("what this configuration does not guarantee:"),
        "the disclosure has a heading a reader can find: {text}"
    );
    assert!(
        text.contains("path confinement: not established on this host"),
        "the capability this host cannot enforce is named: {text}"
    );
    assert!(
        text.contains("memory barrier: weakened, established by mlock"),
        "a weakened capability says which adapter weakens it: {text}"
    );
    assert!(
        text.contains("0600"),
        "the mode the file was given is reported: {text}"
    );
}

/// The JSON and the text report the same capabilities.
///
/// Two renderings of one report drift the moment one of them is edited alone,
/// which is how the audit view came to drop a field the record carried.
#[test]
fn the_json_carries_every_capability_the_text_mentions() {
    let outcome = probe_with(linux());
    let report = configure_with(
        &Layout::new(tempfile::tempdir().expect("home").keep()),
        OverwritePolicy::Replace,
        outcome,
    )
    .expect("a described host writes a file");
    let summary = ProbeSummary::of(&report);
    let json = serde_json::to_value(&summary).expect("the summary serialises");
    let capabilities = json["capabilities"]
        .as_array()
        .expect("capabilities is an array");

    assert_eq!(capabilities.len(), 2, "both capabilities are reported");
    let keys: Vec<&str> = capabilities
        .iter()
        .map(|entry| entry["capability"].as_str().expect("a key"))
        .collect();
    assert_eq!(keys, vec!["confinement", "memory_barrier"]);
    assert_eq!(
        capabilities[0]["requirement"].as_str(),
        Some("required"),
        "the JSON reports the level the file carries"
    );
}

// ---------------------------------------------------------------------------
// Misfit J — `ksp init` leaves an existing file alone; `--force` replaces it
// ---------------------------------------------------------------------------

/// An existing configuration is left byte-for-byte unchanged.
///
/// The bytes, not a boolean: a command that "does not overwrite" but rewrites
/// an equivalent file has still discarded the operator's comments and their
/// order, and the operator's file is the one the host is running on.
#[test]
fn an_existing_configuration_is_left_byte_for_byte() {
    let home = tempfile::tempdir().expect("home");
    let layout = Layout::new(home.path());
    let path = layout.capability_config_file();
    let theirs = "# mine, hand-written\n[confinement]\nadapters = [\"landlock\"]\n\
                  requirement = \"required\"\n\n[memory_barrier]\nadapters = [\"mlock\"]\n\
                  requirement = \"optional\"\n";
    fs::write(&path, theirs).expect("the operator's file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");

    let report = configure_with(&layout, OverwritePolicy::IfAbsent, fixed())
        .expect("the policy is not an error");

    assert!(
        matches!(report, ProbeReport::LeftAlone { .. }),
        "the policy reports the file it left alone: {report:?}"
    );
    assert_eq!(
        fs::read_to_string(&path).expect("the file is still there"),
        theirs,
        "not one byte of the operator's file may change"
    );
}

/// The replacing policy does replace.
///
/// The other half of Misfit J: a policy that never wrote would pass the test
/// above and fail its purpose. `--force` is the deliberate repair, so it has to
/// actually repair.
#[test]
fn the_force_policy_replaces_the_file() {
    let home = tempfile::tempdir().expect("home");
    let layout = Layout::new(home.path());
    let path = layout.capability_config_file();
    fs::write(&path, "not even toml").expect("a file to replace");

    let report =
        configure_with(&layout, OverwritePolicy::Replace, fixed()).expect("the write succeeds");

    assert!(matches!(report, ProbeReport::Written { .. }), "{report:?}");
    let written = fs::read_to_string(&path).expect("the file is written");
    assert_ne!(written, "not even toml", "the old content is gone");
    assert!(
        written.contains("[memory_barrier]"),
        "the new content is the probed configuration: {written}"
    );
}

/// A dangling symlink counts as a configuration that already exists.
///
/// `Path::exists` follows the link and answers `false`, so a policy built on it
/// would treat a host with something at the path as unconfigured and write
/// through the link. The file that is *there* is the question.
#[test]
fn a_dangling_symlink_is_treated_as_an_existing_configuration() {
    let home = tempfile::tempdir().expect("home");
    let layout = Layout::new(home.path());
    let path = layout.capability_config_file();
    std::os::unix::fs::symlink(home.path().join("nowhere.toml"), &path).expect("a dangling link");
    assert!(
        !path.exists(),
        "the fixture must be dangling, or it does not test the link"
    );

    let report = configure_with(&layout, OverwritePolicy::IfAbsent, fixed())
        .expect("the policy is not an error");

    assert!(
        matches!(report, ProbeReport::LeftAlone { .. }),
        "something is placed at the path, so the policy leaves it alone: {report:?}"
    );
}

// ---------------------------------------------------------------------------
// Misfit D / NFR-001 — the written file belongs to its reader
// ---------------------------------------------------------------------------

/// The written file is `0600`, and stays `0600` when it replaces a looser one.
///
/// `open(2)`'s mode argument is masked by `umask`, and `truncate` on an
/// existing file keeps the old mode, so both paths need the mode set on the
/// descriptor. A `0644` configuration is the downgrade path the guard exists to
/// refuse: another principal could then decide what this host may establish.
#[test]
fn the_written_file_is_private_even_over_a_looser_file() {
    let home = tempfile::tempdir().expect("home");
    let layout = Layout::new(home.path());
    let path = layout.capability_config_file();

    // The first path: a file this command created.
    configure_with(&layout, OverwritePolicy::Replace, fixed()).expect("the write succeeds");
    let mode = fs::metadata(&path).expect("metadata").mode() & 0o777;
    assert_eq!(mode, 0o600, "a freshly written configuration is 0600");

    // The second path: an existing 0644 file replaced by `--force`. `truncate`
    // keeps the old mode, so a `create(true)` alone would leave it readable.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("a looser mode");
    configure_with(&layout, OverwritePolicy::Replace, fixed()).expect("the write succeeds");
    let mode = fs::metadata(&path).expect("metadata").mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "replacing a looser file must tighten it, not inherit its mode"
    );
}

// ---------------------------------------------------------------------------
// The contract between the probe and the reader
// ---------------------------------------------------------------------------

/// Whatever the real probe writes on this host, the reader accepts.
///
/// The one assertion that holds on both gate hosts: the probe and the reader
/// are two halves of one contract, and a probe that wrote a document its own
/// reader refused would stop every command on the host. The content is
/// deliberately not asserted here — that is what the described-host tests do.
#[test]
fn the_real_probe_writes_a_file_the_reader_accepts() {
    let home = tempfile::tempdir().expect("home");
    let layout = Layout::new(home.path());

    let report = configure(&layout, OverwritePolicy::Replace).expect("this host is probeable");
    assert!(matches!(report, ProbeReport::Written { .. }), "{report:?}");

    let read_back = read(&layout)
        .expect("the reader accepts what the probe wrote")
        .expect("the file is present");

    for capability in [
        HostCapability::PathConfinement,
        HostCapability::MemoryBarrier,
    ] {
        let setting = match capability {
            HostCapability::PathConfinement => &read_back.confinement,
            HostCapability::MemoryBarrier => &read_back.memory_barrier,
        };
        assert!(
            !setting.adapters.is_empty(),
            "{} was written with an empty preference list",
            capability.config_key()
        );
    }
}

/// The probe creates nothing but the configuration.
///
/// FR-026 and NFR-001: the probe reads the host's capability mechanisms and no
/// vault state. A file it created besides the configuration would be state it
/// had no business writing.
#[test]
fn the_probe_writes_no_file_but_the_configuration() {
    let home = tempfile::tempdir().expect("home");
    let layout = Layout::new(home.path());

    configure(&layout, OverwritePolicy::Replace).expect("this host is probeable");

    let mut created: Vec<String> = fs::read_dir(home.path())
        .expect("the home is readable")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect();
    created.sort();
    assert_eq!(
        created,
        vec![FILE_NAME.to_string()],
        "the probe wrote something other than the configuration"
    );
    assert!(
        !layout.vault_file().exists(),
        "the probe must not touch the vault"
    );
}

// ---------------------------------------------------------------------------
// FR-021 — the host with no configuration file is a host with no home
// ---------------------------------------------------------------------------

/// `ksp init` writes into a home that does not exist yet.
///
/// This is the case the command exists for, and every other test here passes a
/// directory that a tempdir already made — which is why the defect this pins
/// survived a seventeen-test suite. The default home is `$HOME/.ksp`, and on a
/// fresh account that directory is absent.
#[test]
fn the_probe_creates_a_home_that_does_not_exist_yet() {
    let parent = tempfile::tempdir().expect("parent");
    let home = parent.path().join(".ksp");
    assert!(!home.exists(), "the fixture must not pre-create the home");
    let layout = Layout::new(&home);

    let report = configure(&layout, OverwritePolicy::Replace)
        .expect("a first run creates the home it writes into");

    assert!(matches!(report, ProbeReport::Written { .. }), "{report:?}");
    assert!(
        layout.capability_config_file().is_file(),
        "the configuration is written into the home just created"
    );
    assert_eq!(
        fs::metadata(&home).expect("the home exists").mode() & 0o777,
        HOME_MODE,
        "the home carries the layout table's mode, set on the directory rather \
         than requested from create_dir, where umask would mask it"
    );
}

/// A home that cannot be created names the **directory**, not the file.
///
/// The operator's fix is to create or permit a directory. A refusal about
/// `config.toml` sends them to a path that is not the problem, and the two
/// refusals are therefore different variants rather than one with a different
/// string.
#[test]
fn a_home_that_cannot_be_created_names_the_directory() {
    let parent = tempfile::tempdir().expect("parent");
    // A regular file where the home should be: `create_dir_all` cannot succeed,
    // and no permission trick is needed to arrange it.
    let home = parent.path().join(".ksp");
    fs::write(&home, "not a directory").expect("a file stands in for the home");
    let layout = Layout::new(&home);

    let refused = configure(&layout, OverwritePolicy::Replace)
        .expect_err("a file cannot become the deployment root");

    assert!(
        matches!(&refused, ProbeError::NoHome { path, .. } if path == &home),
        "the refusal names the directory it could not create: {refused:?}"
    );
    let text = refused.to_string();
    assert!(
        text.contains("deployment root"),
        "the message says which thing could not be created: {text}"
    );
    assert!(
        !text.contains("config.toml"),
        "the message must not blame a file it never reached: {text}"
    );
}

// ---------------------------------------------------------------------------
// T037 — both verbs exist in the tree
// ---------------------------------------------------------------------------

/// The command tree parses the two verbs FR-021 to FR-025 name.
///
/// A wire-up test rather than a handler test: three of the requirements are
/// about which verb does what to an existing file, and a verb that never parses
/// cannot do anything to it.
#[test]
fn the_two_verbs_are_in_the_command_tree() {
    use clap::Parser;
    use ksp::commands::{Cli, Command, ConfigCommand};

    let init = Cli::try_parse_from(["ksp", "init"]).expect("ksp init parses");
    assert!(
        matches!(init.command, Command::Init),
        "ksp init is a top-level verb, beside status"
    );

    let plain = Cli::try_parse_from(["ksp", "config", "init"]).expect("ksp config init parses");
    let Command::Config { command } = plain.command else {
        panic!("expected a config subcommand");
    };
    assert!(
        matches!(command, ConfigCommand::Init { force: false }),
        "without --force the policy is the absent-file one"
    );

    let forced = Cli::try_parse_from(["ksp", "config", "init", "--force"]).expect("--force parses");
    let Command::Config { command } = forced.command else {
        panic!("expected a config subcommand");
    };
    assert!(
        matches!(command, ConfigCommand::Init { force: true }),
        "--force selects the replacing policy"
    );
}
