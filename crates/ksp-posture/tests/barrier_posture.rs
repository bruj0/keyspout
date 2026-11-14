//! The barrier posture, produced by the adapters that establish it.
//!
//! # Why this file exists
//!
//! `BarrierPosture::of` used to hard-code `adapter: None` and
//! `guarantee: GuaranteeLevel::None`, with no parameter that could override
//! either. Every real `ksp status` therefore printed `no adapter` on a host that
//! had a barrier, while the posture tests — which assembled the struct by hand
//! and passed a name they had chosen — stayed green.
//!
//! The tests here allocate a **real** region through an adapter and build the
//! posture from what came back. Nothing in this file names an adapter in the
//! value under test: the name is whatever the code produced, and the assertions
//! compare it against the adapter's own identifier.
//!
//! `mlock` is the mechanism a test can allocate without depending on the kernel
//! command line, and it is available on every target this crate builds for.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_posture::BarrierKind;
use ksp_posture::adapters::{MemoryBarrierAdapter, MlockBarrier};
use ksp_posture::posture::BarrierPosture;

/// Allocates a real region through the `mlock` adapter.
fn region() -> ksp_posture::BarrieredRegion {
    MlockBarrier
        .allocate(32)
        .expect("the mlock adapter must allocate on this host")
}

/// The posture a real allocation produces names the adapter that allocated it.
#[test]
fn the_posture_names_the_adapter_that_allocated_the_region() {
    let region = region();
    let posture = BarrierPosture::of(region.kind(), region.observed_memlock());

    assert_eq!(
        posture.adapter,
        Some(MlockBarrier.name()),
        "the posture must name the adapter that ran, not a name the caller chose"
    );
    assert!(
        posture.adapter.is_some(),
        "a posture for a region that exists must never render `no adapter`"
    );
}

/// The posture carries the adapter's own guarantee.
///
/// The level is the adapter's claim about what it establishes, so it must equal
/// the adapter's own answer rather than a constant this test knows.
#[test]
fn the_posture_carries_the_adapters_own_guarantee() {
    let region = region();
    let posture = BarrierPosture::of(region.kind(), region.observed_memlock());

    assert_eq!(
        posture.guarantee,
        MlockBarrier.guarantee(),
        "the posture must report the guarantee the adapter establishes"
    );
}

/// Every kind maps to the adapter that establishes it.
///
/// The mapping is what lets `BarrierPosture::of` derive the name from the kind
/// instead of restating it. A kind left without an adapter would be a region no
/// status line could attribute, so the match is exhaustive and this test pins
/// the answer for each.
#[test]
fn every_barrier_kind_maps_to_the_adapter_that_establishes_it() {
    for (kind, expected) in [
        (BarrierKind::MemfdSecret, "memfd_secret"),
        (BarrierKind::SealedMemfd, "sealed_memfd"),
        (BarrierKind::Mlock, "mlock"),
    ] {
        let adapter = ksp_posture::adapters::barrier::adapter_for_kind(kind);
        assert_eq!(
            adapter.name(),
            expected,
            "{kind} must map to the adapter that establishes it"
        );

        // And the posture built from that kind reports the same name.
        let posture = BarrierPosture::of(
            kind,
            ksp_posture::MemlockObservation {
                soft_bytes: None,
                hard_bytes: None,
            },
        );
        assert_eq!(
            posture.adapter,
            Some(expected),
            "the posture for {kind} must name {expected}"
        );
    }
}

/// A run with no barrier is the only posture that reports no adapter.
#[test]
fn only_a_run_with_no_barrier_reports_no_adapter() {
    let none = BarrierPosture::unavailable(ksp_posture::MemlockObservation {
        soft_bytes: None,
        hard_bytes: None,
    });
    assert_eq!(none.adapter, None);
    assert_eq!(none.kind, None);
}
