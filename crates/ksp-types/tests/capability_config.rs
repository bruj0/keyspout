//! The capability configuration's contract with the file format.
//!
//! These tests are the *only* place the `toml` crate touches this crate,
//! and it is a dev-dependency for exactly that reason: the published crate
//! holds types, not a parser. What these tests pin is that the types are
//! shaped so that a real `config.toml` document parses into them, and so
//! that a document with a typo is refused rather than half-read.

// A test reports a failure by panicking, and the panic message is
// what says why. The production library keeps the strict settings.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_types::{
    AdapterName, CapabilityConfiguration, CapabilitySetting, GuaranteeLevel, HostCapability,
    RequirementLevel,
};

/// A document that matches the shape the design spec's `config.toml` uses.
const VALID_DOCUMENT: &str = r#"
[confinement]
adapters = ["landlock", "portable_confinement"]
requirement = "required"

[memory_barrier]
adapters = ["memfd_secret", "sealed_memfd", "mlock"]
requirement = "optional"
"#;

#[test]
fn a_valid_document_parses_into_the_configuration() {
    let configuration: CapabilityConfiguration =
        toml::from_str(VALID_DOCUMENT).expect("a document with both capability tables must parse");

    let confinement = configuration.setting(HostCapability::PathConfinement);
    assert_eq!(
        confinement.adapters,
        vec![
            AdapterName::parse("landlock").unwrap(),
            AdapterName::parse("portable_confinement").unwrap(),
        ],
        "the configured order is the preference order and must survive the parse",
    );
    assert_eq!(confinement.requirement, RequirementLevel::Required);

    let barrier = configuration.setting(HostCapability::MemoryBarrier);
    assert_eq!(barrier.adapters.len(), 3);
    assert_eq!(barrier.requirement, RequirementLevel::Optional);
}

#[test]
fn an_unknown_adapter_name_is_refused_by_the_name_type() {
    let error =
        AdapterName::parse("secreter").expect_err("a name outside the closed set is refused");
    assert!(
        error.to_string().contains("secreter"),
        "the refusal must name the offending value; got: {error}",
    );
}

#[test]
fn an_unknown_adapter_name_in_a_document_is_refused() {
    let document = r#"
[confinement]
adapters = ["secreter"]
requirement = "required"
"#;
    let error = toml::from_str::<CapabilityConfiguration>(document)
        .expect_err("a document naming an adapter outside the closed set must be refused");
    assert!(
        error.to_string().contains("secreter"),
        "the refusal must name the offending value; got: {error}",
    );
}

#[test]
fn an_unknown_key_is_refused_rather_than_ignored() {
    // A typo in a key name must not become a silently missing preference.
    let document = r#"
[confinement]
adapters = ["landlock"]
requirement = "required"
requiremnt = "optional"
"#;
    let error = toml::from_str::<CapabilityConfiguration>(document)
        .expect_err("an unknown key must be refused");
    assert!(
        error.to_string().contains("requiremnt"),
        "the refusal must name the offending key; got: {error}",
    );
}

#[test]
fn an_unknown_capability_table_is_refused() {
    let document = r#"
[confinement]
adapters = ["landlock"]
requirement = "required"

[memory_barier]
adapters = ["mlock"]
requirement = "optional"
"#;
    let error = toml::from_str::<CapabilityConfiguration>(document)
        .expect_err("a misspelled capability table must be refused");
    assert!(
        error.to_string().contains("memory_barier"),
        "the refusal must name the offending table; got: {error}",
    );
}

#[test]
fn an_unknown_requirement_level_is_refused() {
    let document = r#"
[confinement]
adapters = ["landlock"]
requirement = "maybe"
"#;
    let error = toml::from_str::<CapabilityConfiguration>(document)
        .expect_err("a requirement level outside the closed set must be refused");
    assert!(
        error.to_string().contains("maybe"),
        "the refusal must name the offending value; got: {error}",
    );
}

#[test]
fn a_missing_capability_table_is_refused() {
    let document = r#"
[confinement]
adapters = ["landlock"]
requirement = "required"
"#;
    let error = toml::from_str::<CapabilityConfiguration>(document)
        .expect_err("a configuration that names only one capability must be refused");
    assert!(
        error.to_string().contains("memory_barrier"),
        "the refusal must name the missing capability; got: {error}",
    );
}

#[test]
fn the_guarantee_levels_are_ordered_from_full_to_none() {
    assert!(GuaranteeLevel::Full > GuaranteeLevel::Weakened);
    assert!(GuaranteeLevel::Weakened > GuaranteeLevel::None);
    assert!(GuaranteeLevel::Full > GuaranteeLevel::None);
}

#[test]
fn the_three_guarantee_levels_are_distinct() {
    // A `None` guarantee must be distinguishable from a `Weakened` one, so
    // that a portable adapter can never be read as a weaker real mechanism.
    assert_ne!(GuaranteeLevel::None, GuaranteeLevel::Weakened);
    assert_ne!(GuaranteeLevel::None, GuaranteeLevel::Full);
}

#[test]
fn the_closed_adapter_set_is_exactly_the_five_named_adapters() {
    for name in [
        "landlock",
        "portable_confinement",
        "memfd_secret",
        "sealed_memfd",
        "mlock",
    ] {
        assert!(
            AdapterName::parse(name).is_ok(),
            "{name} is one of the five adapters and must parse",
        );
    }
}

/// The name writes the identifier, and the identifier reads back.
///
/// The derived `Serialize` wrote the *discriminant* — `"Mlock"` — while the
/// derived `Deserialize` read the *identifier* — `"mlock"`. The two halves
/// disagreed, so a document this type wrote could not be read back, and
/// `ksp init` would write a `config.toml` that no later command would parse.
///
/// This is the test that fails when the name's serialization is derived from
/// the discriminant again.
#[test]
fn the_adapter_name_round_trips_through_its_own_encoding() {
    for name in AdapterName::ALL {
        let parsed = AdapterName::parse(name).expect("the name is in the closed set");

        // The encoding is the identifier, not the discriminant: the derived
        // `Serialize` would have written `"Mlock"`.
        let encoded = serde_json::to_string(&parsed).expect("the name encodes");
        assert_eq!(
            encoded,
            format!("\"{name}\""),
            "the encoding must be the identifier {name}; got: {encoded}",
        );

        let decoded: AdapterName = serde_json::from_str(&encoded).expect("the name decodes");
        assert_eq!(decoded, parsed, "{name} must survive its own encoding");
    }
}

/// A configuration this crate writes is a configuration this crate reads.
///
/// The document the probe writes and the document the CLI writes are read
/// back by the same parser, so the round trip has to hold for the whole
/// configuration and not only for one name.
#[test]
fn a_written_configuration_is_read_back() {
    let configuration = CapabilityConfiguration {
        confinement: CapabilitySetting {
            adapters: vec![
                AdapterName::parse("landlock").expect("in the closed set"),
                AdapterName::parse("portable_confinement").expect("in the closed set"),
            ],
            requirement: RequirementLevel::Required,
        },
        memory_barrier: CapabilitySetting {
            adapters: vec![
                AdapterName::parse("memfd_secret").expect("in the closed set"),
                AdapterName::parse("sealed_memfd").expect("in the closed set"),
                AdapterName::parse("mlock").expect("in the closed set"),
            ],
            requirement: RequirementLevel::Optional,
        },
    };

    let document = toml::to_string_pretty(&configuration).expect("the configuration encodes");
    let decoded: CapabilityConfiguration =
        toml::from_str(&document).expect("the configuration decodes");

    assert_eq!(decoded, configuration);
}
