//! The adapter traits and the registry.
//!
//! These tests pin the contract between the two registries and the closed
//! name set. The registry's property is that it is **closed**: a name the
//! build does not contain yields `None`, and never a default adapter.
//!
//! The two registries are disjoint. A confinement name asked of the barrier
//! registry yields `None`, and the reverse. A default here would silently
//! confine the run, or silently hold key material, by a mechanism the
//! operator never named — which is Misfit C reached through the registry
//! instead of through the file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_posture::ConfinementRefusal;
use ksp_posture::adapters::{
    ConfinementAdapter, LandlockConfinement, MemfdSecretBarrier, MemoryBarrierAdapter,
    MlockBarrier, PortableConfinement, SealedMemfdBarrier, capability_of, confinement_adapter,
    memory_barrier_adapter,
};
use ksp_types::{AdapterKind, AdapterName, GuaranteeLevel, HostCapability};

/// The name, as the configuration file spells it.
fn name(value: &str) -> AdapterName {
    AdapterName::parse(value).expect("a name in the closed set parses")
}

#[test]
fn the_registry_hands_out_the_portable_confinement_adapter() {
    let adapter = confinement_adapter(&name("portable_confinement"))
        .expect("the portable confinement adapter is in this build");
    assert_eq!(adapter.name(), "portable_confinement");
}

#[test]
fn a_barrier_name_is_not_a_confinement_adapter() {
    // The registry must not fall back to a default. A confinement adapter
    // returned here would confine the run by a mechanism the operator never
    // named.
    for barrier in ["memfd_secret", "sealed_memfd", "mlock"] {
        assert!(
            confinement_adapter(&name(barrier)).is_none(),
            "{barrier} is a memory barrier adapter, not a confinement one"
        );
    }
}

#[test]
fn a_confinement_name_is_not_a_memory_barrier_adapter() {
    for confinement in ["landlock", "portable_confinement"] {
        assert!(
            memory_barrier_adapter(&name(confinement)).is_none(),
            "{confinement} is a path confinement adapter, not a barrier one"
        );
    }
}

#[test]
fn an_adapter_this_build_does_not_contain_yields_none() {
    // Every name in the closed set now has an adapter in this build, on every
    // target. This test used to assert the opposite — that the Landlock and
    // the barrier adapters were absent — because they had not been written
    // yet. It now pins the property that replaced it.
    //
    // The property is **not** that the registry always answers. It is that the
    // registry answers for the names that belong to a capability, and answers
    // `None` only for the names that belong to the other one. A registry that
    // hid an adapter on a host with no mechanism would make "this build has no
    // Landlock adapter" indistinguishable from "this host has no Landlock",
    // and the operator would be told the wrong thing (FR-017, NFR-003).
    for value in AdapterName::ALL {
        let adapter_name = name(value);
        match capability_of(adapter_name.kind()) {
            HostCapability::PathConfinement => {
                assert!(
                    confinement_adapter(&adapter_name).is_some(),
                    "{value} is a path-confinement adapter and must be in this build"
                );
            }
            HostCapability::MemoryBarrier => {
                assert!(
                    memory_barrier_adapter(&adapter_name).is_some(),
                    "{value} is a memory-barrier adapter and must be in this build"
                );
            }
        }
    }
}

#[test]
fn a_host_mechanism_that_is_absent_is_reported_as_unavailable_not_as_missing() {
    // The distinction the registry and the availability answer separately.
    //
    // On a host with no Landlock the adapter is still in the build, and the
    // *adapter* says the mechanism is absent. A registry that answered `None`
    // would report "this build has no Landlock adapter", which is a different
    // fact with a different fix.
    let adapter = confinement_adapter(&name("landlock"))
        .expect("the landlock adapter is in this build on every target");

    // The availability is the kernel's own answer, so the test asserts the
    // *consistency* of the two rather than a constant: where Landlock is
    // present the adapter is available, and where it is not the adapter says
    // so with a reason.
    let available = adapter.availability().is_available();
    let abi = ksp_posture::ConfinementSpec::required(Vec::new())
        .refusal_for(None)
        .is_some();
    assert!(
        abi,
        "a kernel with no Landlock must refuse a required spec — the oracle the \
         availability check is compared against"
    );

    // Both answers must agree about this host. The refusal path asks the
    // kernel through the same query the adapter uses.
    let refusal = ksp_posture::ConfinementSpec::required(Vec::new()).refusal();
    if let Some(refusal) = refusal {
        assert!(
            !available,
            "the kernel reports no Landlock, so the adapter must not claim to \
             be available"
        );
        assert_eq!(
            refusal.mechanism(),
            "landlock",
            "the refusal must name the mechanism that is missing"
        );
    } else {
        assert!(
            available,
            "the kernel provides Landlock, so the adapter must report itself \
             as available"
        );
    }
}

#[test]
fn no_registry_ever_returns_a_default_adapter() {
    // Every name in the closed set is asked of both registries. A name that
    // the wrong registry answers would be a default adapter, and the test
    // fails wherever one is returned.
    for value in AdapterName::ALL {
        let adapter_name = name(value);
        let kind = adapter_name.kind();
        let confinement = confinement_adapter(&adapter_name);
        let barrier = memory_barrier_adapter(&adapter_name);

        match capability_of(kind) {
            HostCapability::PathConfinement => {
                assert!(
                    barrier.is_none(),
                    "{value} must not be answered by the barrier registry"
                );
            }
            HostCapability::MemoryBarrier => {
                assert!(
                    confinement.is_none(),
                    "{value} must not be answered by the confinement registry"
                );
            }
        }
    }
}

#[test]
fn each_name_belongs_to_exactly_one_capability() {
    // The two registries derive their answers from this one fact, so they
    // cannot disagree about which capability owns a name. The check is that
    // the fact is one of the two capabilities and that the *other* registry
    // withholds the name: a name claimed by both registries would belong to
    // two capabilities, which is the failure this test exists to catch.
    for value in AdapterName::ALL {
        let adapter_name = name(value);
        let kind = adapter_name.kind();
        let capability = capability_of(kind);

        let confinement = confinement_adapter(&adapter_name);
        let barrier = memory_barrier_adapter(&adapter_name);

        match capability {
            HostCapability::PathConfinement => {
                // A confinement name may be in this build, but it must never
                // also be a barrier adapter.
                if barrier.is_some() {
                    panic!("{value} is claimed by both registries");
                }
            }
            HostCapability::MemoryBarrier => {
                if confinement.is_some() {
                    panic!("{value} is claimed by both registries");
                }
            }
        }
    }
}

#[test]
fn the_portable_confinement_adapter_establishes_nothing() {
    // It is available — it can be selected — and it guarantees nothing. The
    // two facts are separate, and the guarantee is the one that says the
    // child is not confined.
    let adapter = PortableConfinement;
    assert_eq!(adapter.guarantee(), GuaranteeLevel::None);
    assert!(
        adapter.availability().is_available(),
        "the portable adapter needs nothing from the host, so it can always be selected"
    );
}

#[test]
fn the_portable_confinement_adapter_refuses_to_confine() {
    // It must never hand back a confined child that is not confined.
    let spec = ksp_posture::ConfinementSpec::required(Vec::new());
    let error = PortableConfinement
        .establish(&spec)
        .expect_err("the portable adapter establishes nothing, so it refuses");
    assert!(
        error.to_string().contains("not confined"),
        "the refusal must say the child is not confined; got: {error}"
    );
}

#[test]
fn the_portable_confinement_refusal_names_no_kernel_mechanism() {
    // The portable adapter never calls the kernel, so a refusal that names
    // Landlock sends the operator to inspect a kernel the run never asked.
    // The refusal must name the adapter and must not name Landlock.
    let spec = ksp_posture::ConfinementSpec::required(Vec::new());
    let error = PortableConfinement
        .establish(&spec)
        .expect_err("the portable adapter establishes nothing, so it refuses");
    let rendered = error.to_string();
    assert!(
        !rendered.to_lowercase().contains("landlock"),
        "the refusal must not name a kernel mechanism the adapter never used; got: {rendered}"
    );
    assert!(
        rendered.contains("portable_confinement"),
        "the refusal must name the adapter that refused; got: {rendered}"
    );
}

#[test]
fn the_portable_confinement_refusal_reports_no_abi_and_no_missing_right() {
    // The refusal is built for a run that never asked the kernel for
    // anything, so it carries no ABI and no missing right. Reporting either
    // would describe a kernel exchange that did not happen.
    let spec = ksp_posture::ConfinementSpec::required(Vec::new());
    let error = PortableConfinement
        .establish(&spec)
        .expect_err("the portable adapter establishes nothing, so it refuses");
    let refusal = ConfinementRefusal::of(&spec, error);

    assert_eq!(refusal.mechanism(), "portable_confinement");
    assert_eq!(refusal.abi(), None);
    assert!(
        refusal.missing_rights().is_empty(),
        "no right is missing: the kernel was never asked; got: {:?}",
        refusal.missing_rights()
    );

    let rendered = refusal.to_string();
    assert!(
        !rendered.contains("ABI"),
        "a refusal with no kernel in it must not report an ABI; got: {rendered}"
    );
    assert!(
        rendered.contains("portable_confinement"),
        "the refusal must name the adapter that refused; got: {rendered}"
    );
}

#[test]
fn the_adapter_name_is_the_name_the_closed_set_spells() {
    // The identifier every adapter reports is the one the operator writes in
    // the configuration file. If any two drifted, that adapter would be
    // unreachable by the name that selects it — and a posture would print a
    // name nobody could configure.
    //
    // All five are pinned, not just one: a single-adapter assertion is what let
    // four of the five go unverified.
    let names = [
        PortableConfinement.name(),
        LandlockConfinement.name(),
        MemfdSecretBarrier.name(),
        SealedMemfdBarrier.name(),
        MlockBarrier.name(),
    ];
    for name in names {
        assert!(
            AdapterName::ALL.contains(&name),
            "the adapter identifier {name} must be in the closed name set"
        );
    }

    // The registry hands each one out under the same name it reports, so the
    // registry and the adapter cannot disagree about the spelling. The two
    // registries hold different traits, so each name is asked of the one that
    // owns its capability.
    for spell in AdapterName::ALL {
        let parsed = name(spell);
        let reported = match capability_of(parsed.kind()) {
            HostCapability::PathConfinement => confinement_adapter(&parsed)
                .unwrap_or_else(|| panic!("{spell} must have a confinement adapter"))
                .name(),
            HostCapability::MemoryBarrier => memory_barrier_adapter(&parsed)
                .unwrap_or_else(|| panic!("{spell} must have a barrier adapter"))
                .name(),
        };
        assert_eq!(
            reported, spell,
            "the registry must hand out {spell} under its own name"
        );
    }
}

#[test]
fn the_registry_hands_out_the_same_adapter_every_time() {
    // The registry holds statics, so two lookups must be the same value. A
    // resolver that asked twice must not see two different adapters.
    let first = confinement_adapter(&name("portable_confinement"));
    let second = confinement_adapter(&name("portable_confinement"));
    assert!(first.is_some());
    assert!(second.is_some());
    assert!(
        std::ptr::eq(first.unwrap(), second.unwrap()),
        "the registry must hand out one adapter, not a fresh one per lookup"
    );
}

#[test]
fn every_adapter_kind_belongs_to_a_capability() {
    // The match over the closed name set is exhaustive, so this test is the
    // compiler's statement that every kind has a home.
    assert_eq!(
        capability_of(AdapterKind::Landlock),
        HostCapability::PathConfinement
    );
    assert_eq!(
        capability_of(AdapterKind::PortableConfinement),
        HostCapability::PathConfinement
    );
    assert_eq!(
        capability_of(AdapterKind::MemfdSecret),
        HostCapability::MemoryBarrier
    );
    assert_eq!(
        capability_of(AdapterKind::SealedMemfd),
        HostCapability::MemoryBarrier
    );
    assert_eq!(
        capability_of(AdapterKind::Mlock),
        HostCapability::MemoryBarrier
    );
}
