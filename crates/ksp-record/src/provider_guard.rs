//! The provider downgrade guard.
//!
//! FR-005 requires the HPKE provider to be pinned at `>= 0.6.0`:
//! RUSTSEC-2026-0072 shipped in `hpke-rs-rust-crypto <= 0.5.0`, and the
//! provider version is what selects the `dh` implementation that performs
//! the all-zero shared-secret check.
//!
//! A `Cargo.toml` version requirement is a *minimum*, not a guarantee: a
//! future `cargo update`, a vendored tree or a patch could move the
//! resolved version. The guard reads the version that was actually
//! resolved and fails the build if it is below the floor, so a downgrade
//! cannot pass silently.
//!
//! The chosen provider is recorded in the committed `Cargo.lock`.
//!
//! The build script includes this exact source module, so the tested guard
//! logic is also the logic that fails the build.

/// The lowest provider version that satisfies FR-005.
pub const MINIMUM_PROVIDER_VERSION: (u64, u64, u64) = (0, 6, 0);

/// The provider package whose version the guard checks.
pub const PROVIDER_PACKAGE: &str = "hpke-rs-rust-crypto";

/// Why the guard refused the resolved provider version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardFailure {
    /// The resolved version is below the floor.
    BelowFloor {
        /// The resolved version.
        resolved: (u64, u64, u64),
        /// The floor that was required.
        minimum: (u64, u64, u64),
    },
    /// The version could not be determined at all.
    ///
    /// An unverified provider is indistinguishable from a downgraded one,
    /// so the guard fails closed.
    Undetermined,
}

impl core::fmt::Display for GuardFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BelowFloor { resolved, minimum } => write!(
                f,
                "{PROVIDER_PACKAGE} {}.{}.{} is below the required minimum {}.{}.{} \
                 (RUSTSEC-2026-0072 affects versions <= 0.5.0). The record envelope depends \
                 on this provider's all-zero shared-secret check.",
                resolved.0, resolved.1, resolved.2, minimum.0, minimum.1, minimum.2,
            ),
            Self::Undetermined => write!(
                f,
                "could not determine the resolved {PROVIDER_PACKAGE} version; the FR-005 \
                 downgrade guard cannot be satisfied.",
            ),
        }
    }
}

/// Check a resolved provider version against the floor.
pub fn check_version(resolved: (u64, u64, u64)) -> Result<(), GuardFailure> {
    if resolved < MINIMUM_PROVIDER_VERSION {
        Err(GuardFailure::BelowFloor {
            resolved,
            minimum: MINIMUM_PROVIDER_VERSION,
        })
    } else {
        Ok(())
    }
}

/// Find the version of a package in a `Cargo.lock` file.
///
/// The lock file is a TOML document, but the package blocks have a simple
/// and stable shape, so a targeted scan avoids adding a TOML dependency to
/// the build.
pub fn parse_lock_version(contents: &str, package: &str) -> Option<(u64, u64, u64)> {
    let mut lines = contents.lines();

    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed != format!("name = \"{package}\"") {
            continue;
        }
        // The version line follows the name line inside the same block.
        for candidate in lines.by_ref() {
            let candidate = candidate.trim();
            if let Some(rest) = candidate.strip_prefix("version = \"") {
                let version = rest.strip_suffix('"')?;
                return parse_semver(version);
            }
            if candidate.starts_with('[') {
                // The block ended without a version.
                return None;
            }
        }
        return None;
    }

    None
}

/// Parse a semantic version into its numeric parts.
pub fn parse_semver(version: &str) -> Option<(u64, u64, u64)> {
    // Strip any pre-release or build metadata.
    let core = version.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

/// Parse and validate the provider version recorded in a lockfile.
pub fn check_locked_version(contents: &str) -> Result<(u64, u64, u64), GuardFailure> {
    let resolved =
        parse_lock_version(contents, PROVIDER_PACKAGE).ok_or(GuardFailure::Undetermined)?;
    check_version(resolved)?;
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is
    // what says why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn parses_a_version_from_a_lock_file() {
        let lock = r#"
[[package]]
name = "hpke-rs-rust-crypto"
version = "0.8.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        assert_eq!(parse_lock_version(lock, PROVIDER_PACKAGE), Some((0, 8, 0)));
    }

    #[test]
    fn parses_a_version_with_prerelease_metadata() {
        let lock = r#"
[[package]]
name = "hpke-rs-rust-crypto"
version = "0.6.0-rc.1"
"#;
        assert_eq!(parse_lock_version(lock, PROVIDER_PACKAGE), Some((0, 6, 0)));
    }

    #[test]
    fn a_missing_package_yields_nothing() {
        let lock = r#"
[[package]]
name = "something-else"
version = "1.0.0"
"#;
        assert_eq!(parse_lock_version(lock, PROVIDER_PACKAGE), None);
    }

    #[test]
    fn the_floor_comparison_is_numeric_not_lexical() {
        // "0.10.0" is greater than "0.6.0" numerically, and less than it
        // lexically. A lexical comparison would let 0.10.0 pass the floor
        // only by luck, and 0.5.0 fail it only by luck.
        assert!(check_version((0, 10, 0)).is_ok());
        assert!(check_version((0, 5, 0)).is_err());
        assert!(check_version((0, 6, 0)).is_ok());
    }

    #[test]
    fn a_downgraded_provider_is_refused() {
        // The exact version RUSTSEC-2026-0072 affects.
        let failure = check_version((0, 5, 0)).expect_err("0.5.0 must be refused");
        assert_eq!(
            failure,
            GuardFailure::BelowFloor {
                resolved: (0, 5, 0),
                minimum: (0, 6, 0),
            }
        );
        assert!(
            failure.to_string().contains("0.5.0"),
            "the failure must name the resolved version"
        );
    }

    #[test]
    fn the_locked_provider_is_checked_by_the_shared_guard() {
        let lock = "[[package]]\nname = \"hpke-rs-rust-crypto\"\nversion = \"0.5.0\"\n";
        assert!(matches!(
            check_locked_version(lock),
            Err(GuardFailure::BelowFloor { .. })
        ));
    }

    #[test]
    fn the_current_provider_version_is_accepted() {
        assert!(check_version((0, 8, 0)).is_ok());
    }
}
