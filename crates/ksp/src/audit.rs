//! Appending an audit record before an effect is reported.
//!
//! # The order this module exists to enforce
//!
//! Every command that touches a secret path writes a record and only then reports
//! what it did (FR-044). The two failure directions are not symmetric, and the
//! asymmetry is the whole design:
//!
//! - A **record that cannot be written refuses the operation**. Best-effort logging
//!   would record intentions, and a log that may be skipped answers "what was
//!   attempted" instead of "what happened" (T022).
//! - A **refusal or a failure is recorded too**. The refusals that prove a control
//!   fired are precisely the entries a successes-only log omits (Misfit U), so the
//!   failed path appends with its exit class before it exits.
//!
//! # What a record is not
//!
//! It is the writer's claim at the time it wrote, and an absent record is not
//! evidence that an operation did not happen (FR-045): a process killed between its
//! effect and its append leaves an effect nobody recorded. Nothing here pretends
//! otherwise, and no message in this module says a deletion was observed.
//!
//! # Whose key signs
//!
//! The actor's own key (FR-047): the admin's for administration and sweep runs, the
//! tenant's for a user operation, the agent's for a delivery. Appending never asks
//! for a password the command did not already hold and never opens a record
//! (NFR-008) — this module only receives keys the command already loaded.

use ksp_deletion::{AuditChain, ChainError, EvidenceSigningKey};
use ksp_identity::AgentKeyBundle;
use ksp_types::PrincipalId;
use ksp_types::evidence::{
    AuditComponent, AuditOperation, AuditRecord, AuditTarget, CapabilityAcceptance, Outcome,
};

use crate::config::Layout;
use crate::exit;

/// Why an audit record could not be written.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// The audit root is a protected root and could not be created by the layout
    /// table.
    #[error("the audit root could not be created: {0}")]
    Root(String),
    /// The deployment could not be read, so the actor's identity is unknown.
    #[error("the deployment could not be read, so the record names no actor")]
    Deployment,
    /// The actor's signing key could not be loaded.
    #[error("the actor's signing key could not be loaded")]
    Keys,
    /// The record could not be appended to the chain.
    #[error(transparent)]
    Chain(#[from] ChainError),
}

impl AuditError {
    /// The exit class a failed append produces.
    ///
    /// Capability (`7`), not policy: the operation was permitted and the host could
    /// not make its record durable. NFR-005 asks a refusal to name the mechanism,
    /// and every message above does.
    pub fn exit_code(&self) -> i32 {
        exit::CAPABILITY_REFUSAL
    }
}

/// What one append says.
pub struct Event<'a> {
    /// The principal the record names and whose chain it joins.
    pub actor: PrincipalId,
    /// The key ID of the signer, which names the segment inside the actor's
    /// directory.
    pub signer_key_id: &'a str,
    /// The component writing.
    pub component: AuditComponent,
    /// What it was doing.
    pub operation: AuditOperation,
    /// What it acted on, when the operation names one.
    pub target: Option<AuditTarget>,
    /// Whether the operation completed, failed or was refused.
    pub outcome: Outcome,
    /// The exit class it produced.
    pub exit_code: i32,
    /// The capability this event accepted, when it accepted one.
    ///
    /// `None` for every other operation. The field is a typed value, so it
    /// cannot carry a secret (FR-046).
    pub acceptance: Option<CapabilityAcceptance>,
}

/// Append one record, creating the audit root through the layout table first.
///
/// The root is created here rather than by the writer's first append because a
/// `umask` would otherwise decide its mode; the table records the owner and mode a
/// later `ksp status` measures against (FR-013).
pub fn append(
    layout: &Layout,
    writer: &EvidenceSigningKey,
    writer_principal: PrincipalId,
    event: &Event<'_>,
) -> Result<(), AuditError> {
    crate::layout::ensure_row(layout.root(), &layout.audit_root())
        .map_err(|error| AuditError::Root(error.to_string()))?;

    let record = AuditRecord {
        actor: event.actor,
        signer_key_id: event.signer_key_id.to_string(),
        component: event.component,
        operation: event.operation,
        target: event.target.clone(),
        outcome: event.outcome,
        exit_code: event.exit_code,
        observed_at: i64::try_from(crate::run::now_seconds()).unwrap_or(i64::MAX),
        // Filled from the segment's tail by the chain: a caller cannot append a
        // stale link.
        prev_digest: None,
        acceptance: event.acceptance.clone(),
    };

    AuditChain::new(layout.audit_root())
        .append_for(
            writer,
            writer_principal,
            event.actor,
            event.signer_key_id,
            record,
        )
        .map(|_digest| ())
        .map_err(AuditError::from)
}

/// Append as the admin, for an administration operation or a sweep run.
///
/// The admin key file is read without a password, which is what lets a mutating
/// command log itself without acquiring a secret it did not need (NFR-008).
pub fn record_admin(
    layout: &Layout,
    component: AuditComponent,
    operation: AuditOperation,
    target: Option<AuditTarget>,
    outcome: Outcome,
    exit_code: i32,
) -> Result<(), AuditError> {
    let (recorded, anchor) =
        crate::deployment::require(layout).map_err(|_| AuditError::Deployment)?;
    let admin = crate::admin::load_admin(layout, &anchor).map_err(|_| AuditError::Keys)?;
    // The seed is borrowed for one append; no second copy outlives this call.
    admin.with_secret(|seed| {
        let writer = EvidenceSigningKey::from_seed(*seed);
        append(
            layout,
            &writer,
            // The admin's own chain: she can read its tail, the tenant cannot read
            // hers, and the record still names the tenant as the actor.
            recorded.admin,
            &Event {
                actor: recorded.user,
                signer_key_id: anchor.key_id.as_str(),
                component,
                operation,
                target,
                outcome,
                exit_code,
                acceptance: None,
            },
        )
    })
}

/// Append the acceptance of a host capability.
///
/// The record is written against [`AuditTarget::Deployment`], because a
/// capability is a property of the deployment rather than of one record, and
/// it carries the [`CapabilityAcceptance`] — the capability, the adapter that
/// ran and the guarantee it established.
///
/// The acceptance is **durable**: it is what a later reader consults to tell
/// an accepted absence from an unnoticed one (Misfit N, NFR-009).
///
/// # The record carries no secret
///
/// The acceptance's three fields are a capability, an adapter name from the
/// closed set, and a guarantee level. There is no field a path or a passphrase
/// could be formatted into, which is what FR-046 requires of every writer.
pub fn record_capability(
    layout: &Layout,
    acceptance: CapabilityAcceptance,
) -> Result<(), AuditError> {
    let (recorded, anchor) =
        crate::deployment::require(layout).map_err(|_| AuditError::Deployment)?;
    let admin = crate::admin::load_admin(layout, &anchor).map_err(|_| AuditError::Keys)?;
    // The seed is borrowed for one append; no second copy outlives this call.
    admin.with_secret(|seed| {
        let writer = EvidenceSigningKey::from_seed(*seed);
        append(
            layout,
            &writer,
            // The admin's own chain: the deployment is the admin's, and the
            // record names the deployment as its subject.
            recorded.admin,
            &Event {
                actor: recorded.admin,
                signer_key_id: anchor.key_id.as_str(),
                component: AuditComponent::CommandLine,
                operation: AuditOperation::Capability,
                target: Some(AuditTarget::Deployment),
                outcome: Outcome::Success,
                exit_code: 0,
                acceptance: Some(acceptance),
            },
        )
    })
}

/// Append as the tenant, for a user operation.
pub fn record_user(
    layout: &Layout,
    unsealed: &crate::secret::Unsealed,
    operation: AuditOperation,
    target: Option<AuditTarget>,
    outcome: Outcome,
    exit_code: i32,
) -> Result<(), AuditError> {
    let key_id = crate::deployment::require(layout)
        .map_err(|_| AuditError::Deployment)?
        .0
        .user_signing_key_id
        .ok_or(AuditError::Keys)?;
    unsealed.vault.with_signing_secret(|seed| {
        let writer = EvidenceSigningKey::from_seed(*seed);
        append(
            layout,
            &writer,
            unsealed.user,
            &Event {
                actor: unsealed.user,
                signer_key_id: key_id.as_str(),
                component: AuditComponent::CommandLine,
                operation,
                target,
                outcome,
                exit_code,
                acceptance: None,
            },
        )
    })
}

/// The parts of an agent append an [`Event`] does not already carry.
pub struct AgentRecord<'a> {
    /// The principal whose secret the delivery carried.
    pub actor: PrincipalId,
    /// The agent key ID, which names the segment.
    pub signer_key_id: &'a str,
    /// What the agent was doing.
    pub operation: AuditOperation,
    /// What it acted on.
    pub target: Option<AuditTarget>,
    /// Whether the delivery completed.
    pub outcome: Outcome,
    /// The exit class it produced.
    pub exit_code: i32,
    /// The capability this event accepted, when it accepted one.
    ///
    /// `None` for every other operation. The field is a typed value, so it
    /// cannot carry a secret (FR-046).
    pub acceptance: Option<CapabilityAcceptance>,
}

/// Append as an agent, for a delivery or a consume.
///
/// # The acceptance is forwarded, not dropped
///
/// [`AgentRecord::acceptance`] exists because a delivery is the moment an
/// operator's `optional` capability is *accepted*: the child ran without the
/// mechanism, and a later reader has to be able to tell that from an oversight
/// (Misfit N, NFR-009). The field used to be discarded here — the caller set it
/// and this function wrote `None` — so the acceptance was recorded by nobody and
/// the only trace of the decision was the status line.
pub fn record_agent(
    layout: &Layout,
    bundle: &AgentKeyBundle,
    record: &AgentRecord<'_>,
) -> Result<(), AuditError> {
    bundle.with_signing_secret(|seed| {
        let writer = EvidenceSigningKey::from_seed(*seed);
        append(
            layout,
            &writer,
            // An agent acts for the principal whose secret it delivers, and on
            // the `file` backend it is that principal's account, so its chain is theirs.
            record.actor,
            &Event {
                actor: record.actor,
                signer_key_id: record.signer_key_id,
                component: AuditComponent::Agent,
                operation: record.operation,
                target: record.target.clone(),
                outcome: record.outcome,
                exit_code: record.exit_code,
                acceptance: record.acceptance.clone(),
            },
        )
    })
}
