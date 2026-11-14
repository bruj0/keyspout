//! The shared contract types.
//!
//! This crate holds the identifiers, encodings, domain strings and evidence
//! structures that more than one subsystem must agree on *byte for byte*. It
//! holds no behaviour, no policy and no I/O.
//!
//! If two subsystems disagree about an identifier, a domain string or an
//! encoding, they disagree here, in one place, and nowhere else.

pub mod capability;
pub mod capability_config;
pub mod cbor;
pub mod content_key;
pub mod domains;
pub mod evidence;
pub mod metadata;
pub mod shamir;

pub use capability::{
    AdmissionDecision, AdmissionRefusal, LeaseCapability, admit_decision, admits,
};
pub use capability_config::{
    AdapterAvailability, AdapterKind, AdapterName, AdapterNameError, CapabilityConfiguration,
    CapabilitySetting, GuaranteeLevel, HostCapability, RequirementLevel,
};
pub use content_key::{CONTENT_KEY_LEN, ContentKey};

#[cfg(any(test, feature = "test-observer"))]
pub use content_key::{Erasure, last_erasure, take_erasure};
pub use domains::{
    DOMAIN_ABSENCE_OBSERVATION, DOMAIN_DELETE_INTENT, DOMAIN_DELETE_REPORT, DOMAIN_ENROLMENT,
    DOMAIN_POLICY, DOMAIN_POP, DOMAIN_TOKEN, DOMAIN_VAULT_AAD, HPKE_INFO_DELIVERY,
    HPKE_INFO_RECORD,
};
pub use evidence::{AbsenceObservation, DeletionIntent, DeletionReport, Outcome};
pub use metadata::{
    ActorId, AgentId, BoundMetadata, Level, LevelError, OpaqueSecretId, PrincipalId,
    PrincipalIdError, RecordVersion, VaultId,
};
pub use shamir::{SealedBundle, ShamirError, Share, ShareCount, Threshold};
