//! The capability vocabulary that the posture subsystem and the configuration
//! subsystem share.
//!
//! A **host capability** is a function of the machine, not of a deployment:
//! the ability to confine a process's paths, or to hold key material in
//! memory the kernel protects. This module names the capabilities, the
//! adapters that establish them, the guarantee each adapter gives, and the
//! configuration that says which adapter the operator wants.
//!
//! It holds no behaviour, no policy and no I/O. The file format lives in
//! `ksp-cli`; this crate holds the types both sides agree on.
//!
//! **Host capability is not lease capability.** A [`LeaseCapability`] says
//! what a *storage backend* is configured to guarantee about a lease's
//! deadline. A `HostCapability` says what the *host* can enforce about a
//! process or about memory. The two never meet, and the design spec uses
//! both words.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A function of the host that Keyspout depends on and must state honestly.
///
/// The two are the ones the workspace currently needs. Each has at least one
/// adapter on every supported target, so that a host which provides none of
/// the platform mechanisms can still run and report its own limitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HostCapability {
    /// Restricting the paths a confined process may reach.
    #[serde(rename = "confinement")]
    PathConfinement,
    /// Holding key material in memory the kernel protects.
    #[serde(rename = "memory_barrier")]
    MemoryBarrier,
}

impl HostCapability {
    /// Every host capability the workspace knows, in the closed set's order.
    ///
    /// A status document renders one row per capability, and the rows are
    /// derived from this list rather than written out at the call site: a
    /// capability added to the enum without a row would then be a build here
    /// rather than a gap a reader discovers.
    pub const ALL: [Self; 2] = [Self::PathConfinement, Self::MemoryBarrier];

    /// The name the configuration file uses for this capability.
    ///
    /// It is the table name in `config.toml` and the key a refusal names.
    pub fn config_key(&self) -> &'static str {
        match self {
            Self::PathConfinement => "confinement",
            Self::MemoryBarrier => "memory_barrier",
        }
    }

    /// The name a view prints for this capability.
    pub fn label(&self) -> &'static str {
        match self {
            Self::PathConfinement => "path confinement",
            Self::MemoryBarrier => "memory barrier",
        }
    }
}

/// What an adapter establishes for its capability.
///
/// The ordering runs `Full` > `Weakened` > `None` so that a requirement check
/// can compare two levels without a hand-written match. The levels are
/// relative to a capability, not to each other: `None` for a portable
/// confinement adapter is not "the lowest of the barrier levels".
///
/// The ordering is written out rather than derived from the declaration
/// order, because a reader who reorders the variants would otherwise
/// silently invert every comparison that depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GuaranteeLevel {
    /// The capability's own guarantee, in full.
    #[serde(rename = "full")]
    Full,
    /// A real mechanism with a stated, smaller guarantee.
    #[serde(rename = "weakened")]
    Weakened,
    /// No mechanism at all. The capability is not established.
    #[serde(rename = "none")]
    None,
}

impl GuaranteeLevel {
    /// The name a view prints for this level.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Weakened => "weakened",
            Self::None => "none",
        }
    }

    /// The strength of this level, as a number. Higher is stronger.
    fn strength(self) -> u8 {
        match self {
            Self::Full => 2,
            Self::Weakened => 1,
            Self::None => 0,
        }
    }
}

impl PartialOrd for GuaranteeLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GuaranteeLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.strength().cmp(&other.strength())
    }
}

/// Whether a run refuses when the capability cannot be established.
///
/// The level is the operator's, and it is read from the configuration file
/// rather than fixed in a code path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequirementLevel {
    /// The run refuses without the capability.
    Required,
    /// The run continues with a weakened posture, and says so.
    Optional,
}

impl RequirementLevel {
    /// The name a view prints for this level.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
        }
    }
}

/// The discriminant of an adapter name.
///
/// One variant per adapter in the closed set. A registry downstream matches
/// on this value rather than on the name string, so the compiler proves the
/// match exhaustive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AdapterKind {
    /// The Landlock ruleset over `O_PATH` descriptors.
    Landlock,
    /// The adapter that establishes no kernel restriction at all.
    PortableConfinement,
    /// `memfd_secret(2)`, pages absent from the kernel direct map.
    MemfdSecret,
    /// A sealed `memfd` with `MADV_DONTDUMP`.
    SealedMemfd,
    /// `mlock(2)` residency plus zeroization on release.
    Mlock,
}

/// The stable identifier of one adapter.
///
/// The set is closed. An adapter name outside it is a configuration error,
/// refused before it reaches the registry, so that a name no build contains
/// can never be resolved by a runtime lookup.
///
/// The set is the five adapters this feature defines. It lives here rather
/// than in the registry so that the *configuration* side can refuse a name
/// it will never be able to resolve: `ksp-cli` parses a file without
/// reaching into `ksp-posture`, and the refusal it reports is the same one
/// the posture side would give.
///
/// The name is backed by a fieldless enum rather than by a string, so that a
/// registry downstream can `match` on it and have the compiler prove the
/// match exhaustive. A name added here without a registry arm then breaks
/// the downstream build instead of being discovered at runtime.
///
/// # The name serializes as the identifier, not as the discriminant
///
/// The derived `Serialize` would write the *discriminant* — `"Mlock"` — while
/// the derived `Deserialize` reads the *identifier* — `"mlock"`. The two
/// disagree, so a document this type wrote could not be read back, and
/// `ksp init` would write a `config.toml` that no later command would parse.
///
/// Both halves are therefore written out here: `Serialize` writes
/// [`as_str`](Self::as_str), and `Deserialize` reads through the same
/// checked [`parse`](Self::parse) the rest of the crate uses. The two halves
/// now agree on one spelling — the identifier — which is also the spelling
/// the operator writes in `config.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AdapterName(AdapterKind);

impl Serialize for AdapterName {
    /// Writes the adapter's identifier.
    ///
    /// The identifier, not the discriminant: a document this type wrote has to
    /// be readable by this type.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AdapterName {
    /// Reads an adapter's identifier, refusing a name outside the closed set.
    ///
    /// The refusal is the same one [`parse`](Self::parse) gives, so a document
    /// naming an adapter this build does not contain is refused at the point it
    /// is read rather than at the point it is resolved.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Self::parse(&name).map_err(serde::de::Error::custom)
    }
}

impl AdapterName {
    /// The five adapter names, in the order the configuration file lists
    /// them: the strongest first for each capability.
    pub const ALL: [&'static str; 5] = [
        "landlock",
        "portable_confinement",
        "memfd_secret",
        "sealed_memfd",
        "mlock",
    ];

    /// Parse an adapter identifier.
    ///
    /// An identifier outside the closed set is refused here, with the
    /// offending value named, so that it never reaches the registry.
    pub fn parse(name: &str) -> Result<Self, AdapterNameError> {
        match name {
            "landlock" => Ok(Self(AdapterKind::Landlock)),
            "portable_confinement" => Ok(Self(AdapterKind::PortableConfinement)),
            "memfd_secret" => Ok(Self(AdapterKind::MemfdSecret)),
            "sealed_memfd" => Ok(Self(AdapterKind::SealedMemfd)),
            "mlock" => Ok(Self(AdapterKind::Mlock)),
            _ => Err(AdapterNameError::Unknown(name.to_string())),
        }
    }

    /// The discriminant, for a registry that matches on the name.
    ///
    /// A downstream `match` over this value is compiler-checked, so adding
    /// an adapter here without a registry arm fails the downstream build.
    pub fn kind(&self) -> AdapterKind {
        self.0
    }

    /// The identifier as a string slice.
    pub fn as_str(&self) -> &'static str {
        match self.0 {
            AdapterKind::Landlock => "landlock",
            AdapterKind::PortableConfinement => "portable_confinement",
            AdapterKind::MemfdSecret => "memfd_secret",
            AdapterKind::SealedMemfd => "sealed_memfd",
            AdapterKind::Mlock => "mlock",
        }
    }
}

/// Why an adapter name was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdapterNameError {
    /// The name is not one of the closed set.
    #[error("unknown adapter name: {0}")]
    Unknown(String),
}

/// Deserialize an adapter name through its checked parse, so that a document
/// naming an adapter outside the closed set is refused at the point it is
/// read rather than at the point it is resolved.
impl TryFrom<String> for AdapterName {
    type Error = AdapterNameError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        Self::parse(&name)
    }
}

impl fmt::Display for AdapterName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one capability is configured to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetting {
    /// The adapters to try, in the operator's order of preference.
    ///
    /// The order is the preference. The resolver walks it in order and takes
    /// the first adapter the host confirms.
    pub adapters: Vec<AdapterName>,
    /// Whether the run refuses when the capability cannot be established.
    pub requirement: RequirementLevel,
}

/// The capability configuration, as the operator wrote it.
///
/// One setting per host capability. Pure data: no I/O, and no knowledge of
/// the file format it is parsed from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityConfiguration {
    /// The path confinement setting.
    pub confinement: CapabilitySetting,
    /// The memory barrier setting.
    pub memory_barrier: CapabilitySetting,
}

impl CapabilityConfiguration {
    /// The setting for one capability.
    pub fn setting(&self, capability: HostCapability) -> &CapabilitySetting {
        match capability {
            HostCapability::PathConfinement => &self.confinement,
            HostCapability::MemoryBarrier => &self.memory_barrier,
        }
    }
}

/// What the host says about one adapter.
///
/// `Unavailable` carries the **host's** reason, not a generic "not
/// supported". The reason is what a refusal and a disclosure quote, so it
/// has to survive all the way to the surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterAvailability {
    /// The host provides the adapter's mechanism.
    Available,
    /// The host does not provide it, and says why.
    Unavailable {
        /// The host's own reason, in text a refusal can quote.
        reason: String,
    },
}

impl AdapterAvailability {
    /// Whether the host provides the adapter's mechanism.
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }

    /// The host's reason, when there is one.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Available => None,
            Self::Unavailable { reason } => Some(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what
    // says why. The production library keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_closed_set_is_exactly_the_five_adapters() {
        assert_eq!(AdapterName::ALL.len(), 5);
        for name in AdapterName::ALL {
            assert!(AdapterName::parse(name).is_ok(), "{name} must parse");
        }
    }

    #[test]
    fn an_unknown_name_is_refused_and_names_the_value() {
        let error = AdapterName::parse("secreter").expect_err("a name outside the set is refused");
        assert!(error.to_string().contains("secreter"));
    }

    #[test]
    fn the_name_is_case_sensitive() {
        // `Landlock` is not `landlock`. A name that only differs in case is a
        // different name, and admitting it would make the closed set depend
        // on how the operator typed it.
        assert!(AdapterName::parse("Landlock").is_err());
    }

    #[test]
    fn the_empty_name_is_refused() {
        assert!(AdapterName::parse("").is_err());
    }

    #[test]
    fn a_name_round_trips_through_its_string_form() {
        let name = AdapterName::parse("memfd_secret").expect("a known name parses");
        assert_eq!(name.as_str(), "memfd_secret");
        assert_eq!(name.to_string(), "memfd_secret");
    }

    #[test]
    fn the_guarantee_ordering_is_by_strength() {
        assert!(GuaranteeLevel::Full > GuaranteeLevel::Weakened);
        assert!(GuaranteeLevel::Weakened > GuaranteeLevel::None);
        assert!(GuaranteeLevel::Full > GuaranteeLevel::None);
        assert!(GuaranteeLevel::None < GuaranteeLevel::Weakened);
    }

    #[test]
    fn the_capability_config_keys_match_the_configuration_tables() {
        assert_eq!(HostCapability::PathConfinement.config_key(), "confinement");
        assert_eq!(HostCapability::MemoryBarrier.config_key(), "memory_barrier");
    }

    #[test]
    fn the_config_key_is_the_key_the_reader_accepts() {
        // The key a refusal names must be the key the reader parses, so the
        // test builds the document from the method rather than from a second
        // copy of the literal. Renaming either one now fails here.
        for (capability, adapters, other) in [
            (
                HostCapability::PathConfinement,
                "landlock",
                HostCapability::MemoryBarrier,
            ),
            (
                HostCapability::MemoryBarrier,
                "mlock",
                HostCapability::PathConfinement,
            ),
        ] {
            // Both tables are present, because the configuration holds one
            // setting per capability and a missing table is refused.
            let document = format!(
                "[{key}]\nadapters = [\"{adapter}\"]\nrequirement = \"required\"\n\n[{other_key}]\nadapters = [\"mlock\"]\nrequirement = \"optional\"\n",
                key = capability.config_key(),
                adapter = adapters,
                other_key = other.config_key(),
            );
            let configuration: CapabilityConfiguration = toml::from_str(&document)
                .expect("the config key must be the key the reader accepts");
            assert_eq!(
                configuration.setting(capability).requirement,
                RequirementLevel::Required,
            );
        }
    }

    #[test]
    fn the_parsed_name_and_its_discriminant_agree() {
        for name in AdapterName::ALL {
            let parsed = AdapterName::parse(name).expect("a known name parses");
            assert_eq!(parsed.as_str(), name);
        }
    }

    #[test]
    fn the_whole_name_set_is_reachable_through_its_discriminant() {
        // A registry downstream matches on the discriminant. Every name in the
        // set must have a discriminant, so the two cannot drift apart.
        let kinds: Vec<AdapterKind> = AdapterName::ALL
            .iter()
            .map(|name| {
                AdapterName::parse(name)
                    .expect("a known name parses")
                    .kind()
            })
            .collect();
        let mut unique = kinds.clone();
        unique.sort_by_key(|kind| format!("{kind:?}"));
        unique.dedup();
        assert_eq!(
            unique.len(),
            AdapterName::ALL.len(),
            "each name must have its own discriminant"
        );
    }

    #[test]
    fn an_unavailable_adapter_carries_the_hosts_reason() {
        let availability = AdapterAvailability::Unavailable {
            reason: "memfd_secret(2) is not available on this host".to_string(),
        };
        assert!(!availability.is_available());
        assert_eq!(
            availability.reason(),
            Some("memfd_secret(2) is not available on this host"),
        );
    }

    #[test]
    fn an_available_adapter_has_no_reason() {
        let availability = AdapterAvailability::Available;
        assert!(availability.is_available());
        assert_eq!(availability.reason(), None);
    }
}
