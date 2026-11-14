//! Evidence-based blob storage, lease admission, and durable arming.

pub mod admission;
pub mod arming;
pub mod file;
pub mod proof;
pub mod s3;
pub mod status;
pub mod store;
pub mod sweep;
pub mod sweeper;
pub mod usebound;
pub mod valkey;

pub use admission::{
    AdmissionError, Classification, FileEvidence, S3Configuration, S3Evidence, ValkeyConfiguration,
    classify_file, classify_s3, classify_valkey,
};
pub use arming::{ArmError, ArmRecord, ArmingAcknowledgement, ArmingStore, Durability, arm_intent};
pub use store::{BlobStore, StoreError, validate_path, validate_prefix};
pub use sweep::{
    FailureStage, SweepBound, SweepError, SweepFailure, SweepReport, SweepStore, sweep,
};
pub use sweeper::{
    ArmingError, ArmingKind, ArmingQuery, CredentialBinding, Grant, MeasuredUnitState, Right,
    ScopeLevel, SignedArming, SweepScope, SweeperArming, arming_id,
};
