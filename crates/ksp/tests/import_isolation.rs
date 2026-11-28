//! Vault isolation: an import writes to its own deployment's vault, and nowhere else.
//!
//! # What misfit J actually is
//!
//! Two deployments on one host, `vault-bw-team1` and `vault-bw-team2`. An operator
//! imports team1's items with the wrong `KSP_HOME`, or with a vault name an adapter
//! declaration supplied, and the records land in team2's store. Nothing fails: every
//! record seals correctly, the report is green, and team2 now holds team1's
//! credentials.
//!
//! The second form is worse than the first. A wrong `KSP_HOME` is a typing mistake
//! the operator can see in their own command. A vault name read from a data file is a
//! decision made by data.
//!
//! # What is asserted here, and why not more
//!
//! Creating two deployments needs `admin init`, which seals a vault and binds a UNIX
//! account — privileged setup a unit test cannot do. So this file asserts the two
//! properties that are decidable without it:
//!
//! 1. **No code path accepts a vault from an argument or from data.** The absence of
//!    the flag and the absence of the field are the control, so both are asserted.
//! 2. **The vault comes from the deployment record**, which is resolved from
//!    `KSP_HOME` — so two deployment roots cannot share one vault by accident.
//!
//! The end-to-end two-store comparison belongs in WP07, where a real deployment can
//! be built. Asserting it here against a fixture would prove the fixture.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

/// The layout resolves every path from the root it is given.
///
/// Two roots therefore produce two disjoint stores. This is the property that makes
/// a second vault a second deployment rather than a subdirectory, and the design
/// fixes it at §3.8.1: one deployment holds one vault and N principals.
#[test]
fn two_roots_produce_two_disjoint_stores() {
    let one = ksp::config::Layout::new("/tmp/deployment-team1");
    let two = ksp::config::Layout::new("/tmp/deployment-team2");

    assert_ne!(
        one.store_root(),
        two.store_root(),
        "two deployments must not share a store root"
    );
    assert!(
        !one.store_root().starts_with(two.root()) && !two.store_root().starts_with(one.root()),
        "one deployment's store must not sit inside another's root: {} vs {}",
        one.store_root().display(),
        two.store_root().display()
    );
}

/// A root given to the layout is the root every path is built from.
///
/// If any path were derived from anything else — a global, an environment variable
/// re-read later — two deployments could disagree about which store they meant.
#[test]
fn every_path_is_built_from_the_root_it_was_given() {
    let root = Path::new("/tmp/deployment-team1");
    let layout = ksp::config::Layout::new(root);

    for path in [
        layout.vault_file(),
        layout.store_root(),
        layout.issuance_ledger(),
        layout.admin_key_root(),
    ] {
        assert!(
            path.starts_with(root),
            "{} must be built from the root {}",
            path.display(),
            root.display()
        );
    }
}

/// No `ksp import` flag may name a vault.
///
/// The absence **is** the control: a flag that named a vault would either be
/// redundant with `KSP_HOME` or, worse, silently redirect a write into a store the
/// running deployment does not own. A test that asserted a default would not notice
/// someone adding the flag.
#[test]
fn the_import_surface_exposes_no_vault_selector() {
    use clap::CommandFactory;

    let command = ksp::commands::Cli::command();
    let import = command
        .get_subcommands()
        .find(|sub| sub.get_name() == "import")
        .expect("import is on the command surface");

    let offenders: Vec<String> = import
        .get_arguments()
        .filter_map(|arg| arg.get_long().map(str::to_string))
        .filter(|long| long.contains("vault") || long.contains("store"))
        .collect();

    assert!(
        offenders.is_empty(),
        "`ksp import` must expose no way to choose a destination store; found {offenders:?}"
    );
}

// The data half of misfit J — that an adapter declaration carries no destination —
// is asserted in WP05, where the declaration type exists. Asserting it here would
// compile against a module this work package does not own.
