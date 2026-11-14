//! Record cryptography and version integrity.

pub mod blob;
pub mod envelope;
pub mod kem;
pub mod path;
pub mod provider_guard;
pub mod version;

pub use blob::ContentBlob;
pub use envelope::{Record, RecordEnvelope};
pub use kem::{KemError, open_from, seal_to};
pub use path::{RecordPath, RecordPathError};
pub use provider_guard::{GuardFailure, MINIMUM_PROVIDER_VERSION, PROVIDER_PACKAGE};
pub use version::{
    BlobStore, PublishOutcome, RecordError, StoreError, commit_version, decode_record,
    encode_record,
};
