//! Build-time enforcement of the HPKE provider version floor.

#![allow(clippy::panic)]

#[path = "src/provider_guard.rs"]
mod provider_guard;

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../Cargo.lock");

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("could not locate the workspace root"));
    let lock_path = workspace_root.join("Cargo.lock");
    let lock = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", lock_path.display()));

    match provider_guard::check_locked_version(&lock) {
        Ok((major, minor, patch)) => println!(
            "cargo:warning={} {major}.{minor}.{patch} satisfies the FR-005 floor",
            provider_guard::PROVIDER_PACKAGE
        ),
        Err(failure) => panic!("{failure}"),
    }
}
