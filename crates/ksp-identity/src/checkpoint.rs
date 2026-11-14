//! The trusted checkpoint and rollback detection.
//!
//! # The misfit this resolves
//!
//! Misfit N: a malicious or unavailable store deletes, denies or replays. A
//! policy is admin-signed, so a *fabricated* policy is impossible — but an
//! **older, genuinely signed** policy can be replayed, and its signature will
//! verify perfectly. Signature validity says nothing about recency.
//!
//! # The rule
//!
//! The host keeps a checkpoint: the highest policy revision it has already
//! accepted. A policy whose revision is **below** the checkpoint is a
//! [`Rollback`](crate::policy::PolicyRefusal::Rollback) — a replay, not a valid
//! policy — and is refused. The checkpoint advances **only after** a valid newer
//! policy is accepted, so a refused policy can never move it.
//!
//! # What a fresh host cannot do
//!
//! With no checkpoint there is nothing to compare against, so a replayed older
//! policy is undetectable. That is reported as
//! [`Freshness::Unavailable`](crate::policy::Freshness), a first-class outcome
//! rather than a note attached to a success, because a caller must decide what
//! to do about it rather than silently inherit it.
//!
//! # What the checkpoint does not defend
//!
//! It defends a *store* that replays. It does not defend a host an attacker
//! already controls: anyone who can rewrite the checkpoint can lower it, and no
//! key here would stop that. The digest below catches an accidental corruption
//! or a checkpoint that no longer matches the policy it names — not a targeted
//! rewrite. Host integrity is S5's problem, and claiming more here would be the
//! kind of unearned guarantee the rest of the design refuses.

use ksp_types::cbor;

/// The revision and the policy digest a host has already accepted.
///
/// Deliberately not a bare `u64`: a checkpoint that carries the digest of the
/// policy it accepted can be checked against that policy, so a checkpoint from a
/// different lineage is detectable instead of merely comparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustedCheckpoint {
    revision: u64,
    policy_digest: [u8; 32],
}

impl TrustedCheckpoint {
    /// A checkpoint naming the revision and digest it accepted.
    pub fn new(revision: u64, policy_digest: [u8; 32]) -> Self {
        Self {
            revision,
            policy_digest,
        }
    }

    /// The highest revision accepted so far.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// The digest of the policy that was accepted at that revision.
    pub fn policy_digest(&self) -> &[u8; 32] {
        &self.policy_digest
    }

    /// Whether this checkpoint names exactly this policy digest.
    pub fn matches_digest(&self, digest: &[u8; 32]) -> bool {
        self.policy_digest == *digest
    }
}

/// Why a checkpoint could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    /// The stored bytes could not be decoded.
    #[error("the trusted checkpoint could not be decoded: {cause}")]
    Decode {
        /// The decoder's reason.
        cause: String,
    },
    /// The checkpoint could not be encoded.
    #[error("the trusted checkpoint could not be encoded: {cause}")]
    Encode {
        /// The encoder's reason.
        cause: String,
    },
    /// The host-local store refused the write.
    #[error("the trusted checkpoint could not be stored: {cause}")]
    Store {
        /// The store's reason.
        cause: String,
    },
}

impl TrustedCheckpoint {
    /// The canonical encoding a host-local store persists.
    ///
    /// A fixed-order struct: the two fields in declaration order, so the bytes
    /// a host wrote are the bytes a host reads back.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CheckpointError> {
        cbor::encode(self).map_err(|err| CheckpointError::Encode {
            cause: err.to_string(),
        })
    }

    /// Read a checkpoint written by [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CheckpointError> {
        cbor::decode(bytes).map_err(|err| CheckpointError::Decode {
            cause: err.to_string(),
        })
    }
}

/// Where a host keeps its trusted checkpoint.
///
/// A trait rather than a concrete file so the verifier does not decide *how* the
/// host stores it, and so a caller with no persistent store can say so by
/// passing `None` rather than by silently getting an in-memory one.
pub trait CheckpointStore {
    /// The checkpoint this host already holds, if any.
    ///
    /// `Ok(None)` means "no checkpoint", which is what makes freshness
    /// unavailable. It does not mean "loading failed".
    fn load(&self) -> Result<Option<TrustedCheckpoint>, CheckpointError>;

    /// Persist a newly accepted checkpoint.
    fn save(&mut self, checkpoint: &TrustedCheckpoint) -> Result<(), CheckpointError>;
}

/// A checkpoint store that keeps the value in memory.
///
/// Useful for a single process and for tests. It is **not** a persistent store:
/// a process that restarts with this store has no checkpoint, and therefore no
/// rollback detection, which is exactly the state the verifier reports as
/// freshness unavailable.
#[derive(Debug, Default, Clone)]
pub struct MemoryCheckpointStore {
    held: Option<TrustedCheckpoint>,
}

impl MemoryCheckpointStore {
    /// An empty store: no checkpoint, so no rollback detection.
    pub fn new() -> Self {
        Self::default()
    }

    /// A store that already holds a checkpoint.
    pub fn with(checkpoint: TrustedCheckpoint) -> Self {
        Self {
            held: Some(checkpoint),
        }
    }

    /// The checkpoint held, if any.
    pub fn held(&self) -> Option<TrustedCheckpoint> {
        self.held
    }
}

impl CheckpointStore for MemoryCheckpointStore {
    fn load(&self) -> Result<Option<TrustedCheckpoint>, CheckpointError> {
        Ok(self.held)
    }

    fn save(&mut self, checkpoint: &TrustedCheckpoint) -> Result<(), CheckpointError> {
        self.held = Some(*checkpoint);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_checkpoint_round_trips_through_its_stored_bytes() {
        let checkpoint = TrustedCheckpoint::new(7, [3u8; 32]);
        let bytes = checkpoint.to_bytes().unwrap();
        assert_eq!(TrustedCheckpoint::from_bytes(&bytes).unwrap(), checkpoint);
    }

    #[test]
    fn a_truncated_digest_is_refused_rather_than_padded() {
        let checkpoint = TrustedCheckpoint::new(7, [3u8; 32]);
        let mut bytes = checkpoint.to_bytes().unwrap();
        bytes.pop();
        assert!(TrustedCheckpoint::from_bytes(&bytes).is_err());
    }

    #[test]
    fn an_empty_store_reports_no_checkpoint_rather_than_an_error() {
        let store = MemoryCheckpointStore::new();
        assert_eq!(store.load().unwrap(), None);
    }

    #[test]
    fn a_saved_checkpoint_is_loaded_back() {
        let mut store = MemoryCheckpointStore::new();
        let checkpoint = TrustedCheckpoint::new(4, [1u8; 32]);
        store.save(&checkpoint).unwrap();
        assert_eq!(store.load().unwrap(), Some(checkpoint));
    }
}
