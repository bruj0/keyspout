//! The domain strings that scope every signature and every HPKE sealing.
//!
//! Domain separation is load-bearing: a signature produced in one context
//! must never verify in another. Each artifact has its own versioned
//! prefix, and no two prefixes share a value.

/// Domain for the admin's signature over an enrolment record.
///
/// Added by WP04: the enrolment record is the trust anchor an agent verifies
/// against, so its signature needs its own domain. It lives here rather than in
/// `ksp-identity` because every signature domain is defined once, in this file,
/// so two subsystems cannot invent different prefixes for the same purpose.
pub const DOMAIN_ENROLMENT: &[u8] = b"keyspout-enrolment-v1";

/// Domain for a sealed user vault's associated data.
///
/// The vault's identity and key IDs are authenticated as AEAD associated data.
/// They get their own prefix rather than reusing the fingerprint's, so that a
/// future change to the fingerprint preimage cannot make the two structures
/// byte-compatible.
pub const DOMAIN_VAULT_AAD: &[u8] = b"keyspout-vault-aad-v1";

/// Domain for the admin's signature over a policy.
///
/// A policy authorises a grant; a token authorises one delivery. If the two
/// shared a prefix, a policy signature could be presented where a token
/// signature is expected.
pub const DOMAIN_POLICY: &[u8] = b"keyspout-policy-v1";

/// Domain for the issuer's signature over a delivery token.
pub const DOMAIN_TOKEN: &[u8] = b"keyspout-token-v1";

/// Domain for a proof-of-possession signature.
pub const DOMAIN_POP: &[u8] = b"keyspout-pop-v1";

/// Domain for a deletion intent signature.
pub const DOMAIN_DELETE_INTENT: &[u8] = b"keyspout-delete-intent-v1";

/// Domain for a deletion report signature.
pub const DOMAIN_DELETE_REPORT: &[u8] = b"keyspout-delete-report-v1";

/// Domain for an absence observation signature.
pub const DOMAIN_ABSENCE_OBSERVATION: &[u8] = b"keyspout-absence-observation-v1";

/// Domain for an audit record signature.
///
/// The audit domain is separate from every deletion domain for the reason the
/// whole file exists: an audit record that verified as a deletion report would let
/// a component's log entry be presented as evidence about a version. The plan
/// calls this `ksp.audit.v1`; the value here follows the registry's rule instead —
/// one `keyspout-<kind>-v1` prefix per artifact, enforced by the test in this file.
pub const DOMAIN_AUDIT_RECORD: &[u8] = b"keyspout-audit-record-v1";

/// Domain for a sweeper arming signature.
///
/// The arming is configuration, not evidence: it says a schedule was recorded, and
/// the sweep proof says a run happened. Separate domains keep one from being
/// presented as the other.
pub const DOMAIN_SWEEPER_ARMING: &[u8] = b"keyspout-sweeper-arming-v1";

/// Domain for a sweep proof signature.
///
/// A proof says a run happened and what it counted. It is not a deletion receipt for a
/// version (misfit Y), and a separate domain keeps that distinction in the bytes.
pub const DOMAIN_SWEEP_PROOF: &[u8] = b"keyspout-sweep-proof-v1";

/// The HPKE `info` label for sealing a content key into a record envelope.
pub const HPKE_INFO_RECORD: &[u8] = b"keyspout-record-v1";

/// The HPKE `info` label for sealing a content-key map into a delivery.
pub const HPKE_INFO_DELIVERY: &[u8] = b"keyspout-delivery-v1";

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is
    // what says why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_domain_is_distinct() {
        let domains: HashSet<&[u8]> = [
            DOMAIN_ENROLMENT,
            DOMAIN_VAULT_AAD,
            DOMAIN_POLICY,
            DOMAIN_TOKEN,
            DOMAIN_POP,
            DOMAIN_DELETE_INTENT,
            DOMAIN_DELETE_REPORT,
            DOMAIN_ABSENCE_OBSERVATION,
            DOMAIN_AUDIT_RECORD,
            DOMAIN_SWEEPER_ARMING,
            DOMAIN_SWEEP_PROOF,
            HPKE_INFO_RECORD,
            HPKE_INFO_DELIVERY,
        ]
        .into_iter()
        .collect();

        assert_eq!(domains.len(), 13, "a domain string was reused");
    }

    #[test]
    fn domains_are_versioned() {
        for domain in [
            DOMAIN_ENROLMENT,
            DOMAIN_VAULT_AAD,
            DOMAIN_POLICY,
            DOMAIN_TOKEN,
            DOMAIN_POP,
            DOMAIN_DELETE_INTENT,
            DOMAIN_DELETE_REPORT,
            DOMAIN_ABSENCE_OBSERVATION,
            DOMAIN_AUDIT_RECORD,
            DOMAIN_SWEEPER_ARMING,
            DOMAIN_SWEEP_PROOF,
            HPKE_INFO_RECORD,
            HPKE_INFO_DELIVERY,
        ] {
            assert!(
                domain.ends_with(b"-v1"),
                "a domain string is not versioned: {}",
                String::from_utf8_lossy(domain)
            );
        }
    }
}
