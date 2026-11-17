//! The order a withdrawal happens in.
//!
//! # Why an order and not three calls
//!
//! A withdrawal is one decision and three effects: the ledger entry that records it,
//! the artifact that stops existing, and the publication reference that stops keeping
//! a content key alive. Any order that writes an effect before the record turns the
//! ledger into an audit log — it describes what happened and prevents nothing.
//!
//! So the order is fixed here, in one place: **ledger, artifact, publication**. A crash
//! anywhere in it leaves a state the next run completes, because every step asks what
//! is already true before it acts:
//!
//! - the append is idempotent, so a retry lands on the recorded decision;
//! - removing an absent artifact succeeds, because the aim is its absence;
//! - releasing a reference that is already released writes nothing.
//!
//! # What this deliberately does not do
//!
//! It does not remove a publication when its last reference goes. `publication::release`
//! says so in its own doc, and the reason is the same one this module exists for: an
//! artifact that vanishes before its entry is written is a change nobody can account
//! for. Removing it is a separate decision with its own record, not a side effect of a
//! reference count reaching zero.

use ksp_identity::IssuanceLedger;
use ksp_identity::policy_edge::RevisionRefusal;
use ksp_identity::policy_edge::{PolicyAction, PolicyEdge, PolicyId, PolicyLedgerEntry};

use crate::config::Layout;
use crate::edges::{EdgeStore, EdgeStoreError};
use crate::publication::{PublicationError, PublicationPath};

/// Why a withdrawal did not finish.
#[derive(Debug, thiserror::Error)]
pub enum WithdrawalError {
    /// The edge model refused the decision.
    #[error(transparent)]
    Edge(#[from] EdgeStoreError),
    /// The edge model refused the entry's fields.
    #[error(transparent)]
    RefusedEdge(#[from] ksp_identity::policy_edge::EdgeRefusal),
    /// The decision is not later than the revision in force.
    #[error(transparent)]
    Refused(#[from] RevisionRefusal),
    /// The ledger could not record the decision, so nothing was changed.
    #[error(
        "the policy ledger at {path} could not record the withdrawal, so nothing was changed: {cause}"
    )]
    Ledger {
        /// The file that refused the append.
        path: String,
        /// Why it refused.
        cause: String,
    },
    /// The publication could not be read or written.
    #[error(transparent)]
    Publication(#[from] PublicationError),
}

/// What a completed withdrawal did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalOutcome {
    /// The decision that was recorded, or the one already in force.
    pub entry: PolicyLedgerEntry,
    /// Whether this run removed the artifact. `false` means it was already gone.
    pub artifact_removed: bool,
    /// The policies that still reference the publication.
    pub survivors: Vec<String>,
}

/// One withdrawal, performed in the order that makes it a control.
pub struct Withdrawal<'a> {
    layout: &'a Layout,
    store: &'a EdgeStore<'a>,
    ledger: &'a IssuanceLedger,
}

impl<'a> Withdrawal<'a> {
    /// A withdrawal against one store and one ledger.
    pub fn new(layout: &'a Layout, store: &'a EdgeStore, ledger: &'a IssuanceLedger) -> Self {
        Self {
            layout,
            store,
            ledger,
        }
    }

    /// Step one: record the decision. Nothing else changes if this fails.
    pub fn record(
        &self,
        edge: &PolicyEdge,
        actor: ksp_types::PrincipalId,
        at: i64,
    ) -> Result<PolicyLedgerEntry, WithdrawalError> {
        let entry = PolicyLedgerEntry::for_edge(edge, PolicyAction::Withdrawn, actor, at)?;
        // The head is read before the append so a retry can tell "already decided" from
        // "a later revision exists". Reading after the append would make every retry
        // look like a regression against its own entry.
        let head = self
            .ledger
            .policy_head(edge.id())
            .map_err(|error| WithdrawalError::Ledger {
                path: self.ledger.policy_events_path().display().to_string(),
                cause: error.to_string(),
            })?;
        // A refusal propagates; both accepted outcomes then append through
        // `record_policy`, which returns the recorded entry instead of a second one
        // when the decision is already there. Which of the two it was matters to a
        // caller that wants to report "already withdrawn" — and `record_policy`
        // answers that by returning the entry that was already in force.
        ksp_identity::policy_edge::guard(head.as_ref(), &entry)?;
        self.ledger
            .record_policy(&entry)
            .map_err(|error| WithdrawalError::Ledger {
                path: self.ledger.policy_events_path().display().to_string(),
                cause: error.to_string(),
            })
    }

    /// Step two: remove the artifact.
    ///
    /// `Ok(false)` means it was already absent. An absent artifact is the aim, not a
    /// failure: a retry after a crash must not stop because the previous attempt got
    /// further than it reported.
    pub fn remove_artifact(&self, id: &PolicyId) -> Result<bool, WithdrawalError> {
        match std::fs::remove_file(self.store.path(id)) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(WithdrawalError::Edge(EdgeStoreError::Unreadable {
                path: format!("{}: {error}", self.store.path(id).display()),
            })),
        }
    }

    /// Step three: release the publication reference, if the decision named one.
    pub fn release(&self, entry: &PolicyLedgerEntry) -> Result<Vec<String>, WithdrawalError> {
        let Some(publication) = entry.publication.as_deref() else {
            return Ok(Vec::new());
        };
        let path = PublicationPath::parse(publication).map_err(PublicationError::Path)?;
        Ok(crate::publication::release(
            self.layout,
            &path,
            entry.policy.as_str(),
        )?)
    }

    /// All three steps, in order.
    pub fn complete(
        &self,
        edge: &PolicyEdge,
        actor: ksp_types::PrincipalId,
        at: i64,
    ) -> Result<WithdrawalOutcome, WithdrawalError> {
        let entry = self.record(edge, actor, at)?;
        let artifact_removed = self.remove_artifact(&entry.policy)?;
        let survivors = self.release(&entry)?;
        Ok(WithdrawalOutcome {
            entry,
            artifact_removed,
            survivors,
        })
    }
}
