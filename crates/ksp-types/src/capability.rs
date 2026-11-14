//! What a storage backend is configured to be able to do about a lease.
//!
//! A capability is a property of *configuration*, not of the store's
//! behaviour, and it is declared by exactly one of three values. A missing
//! mechanism is `None` — never an optimistic guess.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// What a backend is configured to guarantee about a lease's deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseCapability {
    /// The backend has no mechanism that can enforce a deadline. The lease
    /// outlives every client, and cleanup depends on a configured sweeper.
    None,
    /// The backend enforces the deadline itself, under the durability and
    /// configuration gates the backend must acknowledge.
    NativeExpiry,
    /// The backend cleans up on a cadence. The interval is the cadence the admitted
    /// mechanism is **known to run at**: proven when a sweep proof exists, declared when
    /// only an arming does. It is not a maximum lag and not a promise of erasure.
    Scheduled {
        /// The cadence the admitted mechanism is known to run at.
        interval: Duration,
    },
}

impl LeaseCapability {
    /// The declared cleanup cadence, if the backend declares one.
    pub fn interval(&self) -> Option<Duration> {
        match self {
            Self::Scheduled { interval } => Some(*interval),
            Self::None | Self::NativeExpiry => None,
        }
    }
}

/// The admission decision for a requested lease duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionDecision {
    /// The requested duration is admitted under this capability.
    Admitted,
    /// The requested duration is refused, and the reason is stated.
    Refused(AdmissionRefusal),
}

/// Why a requested duration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionRefusal {
    /// The backend has no deadline mechanism at all.
    NoMechanism,
    /// The requested duration is shorter than the configured floor.
    BelowFloor {
        /// The requested duration.
        requested: Duration,
        /// The floor that was applied.
        floor: Duration,
    },
}

/// The conservative MVP admission policy.
///
/// This is **not** a timing theorem. It is the rule that at least one full
/// cleanup pass must be scheduled after the deadline, so that a blob cannot
/// outlive its own lease with no sweep ever scheduled for it. It is applied
/// to a *declared* cadence, so it bounds the configuration, not the store's
/// actual behaviour.
///
/// - `None` admits nothing.
/// - `NativeExpiry` admits any duration: the backend enforces the deadline
///   itself.
/// - `Scheduled` admits a duration of at least `2 × interval`.
pub fn admits(capability: &LeaseCapability, requested: Duration) -> bool {
    admit_decision(capability, requested) == AdmissionDecision::Admitted
}

/// The full admission decision, including the reason for a refusal.
pub fn admit_decision(capability: &LeaseCapability, requested: Duration) -> AdmissionDecision {
    match capability {
        LeaseCapability::None => AdmissionDecision::Refused(AdmissionRefusal::NoMechanism),
        LeaseCapability::NativeExpiry => AdmissionDecision::Admitted,
        LeaseCapability::Scheduled { interval } => {
            // The floor is computed with checked arithmetic: an absurdly
            // large declared interval must not wrap around into a small
            // floor that would admit a short lease.
            match interval.checked_mul(2) {
                Some(floor) if requested >= floor => AdmissionDecision::Admitted,
                Some(floor) => {
                    AdmissionDecision::Refused(AdmissionRefusal::BelowFloor { requested, floor })
                }
                None => AdmissionDecision::Refused(AdmissionRefusal::BelowFloor {
                    requested,
                    floor: Duration::MAX,
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);
    const DAY: Duration = Duration::from_secs(86_400);

    #[test]
    fn none_admits_nothing() {
        assert!(!admits(&LeaseCapability::None, Duration::from_secs(1)));
        assert!(!admits(&LeaseCapability::None, Duration::MAX));
    }

    #[test]
    fn native_expiry_admits_any_duration() {
        assert!(admits(
            &LeaseCapability::NativeExpiry,
            Duration::from_secs(1)
        ));
        assert!(admits(&LeaseCapability::NativeExpiry, HOUR));
    }

    #[test]
    fn scheduled_applies_the_two_times_floor_at_the_boundary() {
        let capability = LeaseCapability::Scheduled { interval: DAY };
        let floor = DAY * 2;

        // 2x - 1 second is refused.
        assert!(!admits(&capability, floor - Duration::from_secs(1)));
        // Exactly 2x is admitted.
        assert!(admits(&capability, floor));
        // 2x + 1 second is admitted.
        assert!(admits(&capability, floor + Duration::from_secs(1)));
    }

    #[test]
    fn a_refusal_states_the_floor() {
        let capability = LeaseCapability::Scheduled { interval: DAY };
        let decision = admit_decision(&capability, HOUR);
        assert_eq!(
            decision,
            AdmissionDecision::Refused(AdmissionRefusal::BelowFloor {
                requested: HOUR,
                floor: DAY * 2,
            })
        );
    }

    #[test]
    fn an_unrepresentable_floor_refuses_rather_than_wrapping() {
        let capability = LeaseCapability::Scheduled {
            interval: Duration::MAX,
        };
        assert!(!admits(&capability, Duration::MAX));
    }
}
