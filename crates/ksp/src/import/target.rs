//! Which recipient key, which level, and which vault an import writes to.
//!
//! # Three decisions, two of which are silent when wrong
//!
//! - **The target** names whom the value is sealed to: the admin's own vault, or a
//!   named principal. A wrong choice still seals, still reports a version, and is
//!   readable by the wrong person (misfit D).
//! - **The vault** is the deployment's own, resolved from `KSP_HOME`. It is never a
//!   flag and never a field in an adapter declaration, because a destination that
//!   can come from an argument or from data can be redirected into a store the
//!   running deployment does not own (misfit J).
//!
//! # The level mirrors `admin put`, on purpose
//!
//! [`level_for`] returns `Level::Admin` for both forms. `admin put` and
//! `admin put --own` differ in the **recipient key** and the **subtree**, not the
//! level: the `admin` level is the record's provenance, saying the admin wrote the
//! value and delegated it, which is what makes a later delivery of it require a
//! policy. A second rule for the same decision is how two commands come to
//! disagree, so this module copies the existing one rather than inventing another.

use ksp_types::{Level, PrincipalId};

/// Where an imported value goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportTarget {
    /// The admin's own sealed vault, at the admin's own principal.
    OwnVault,
    /// A named principal, sealed to that principal's recipient key.
    Principal(PrincipalId),
}

/// Why a target could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetError {
    /// Neither `--to-principal` nor `--own` was given.
    #[error(
        "an import names where the value goes: pass `--to-principal <UUID>` to seal it to a \
         principal, or `--own` to seal it into the admin's own vault"
    )]
    NoTarget,

    /// Both `--to-principal` and `--own` were given.
    #[error(
        "an import names exactly one destination: `--to-principal <UUID>` and `--own` are \
         mutually exclusive, so pass one of them"
    )]
    ConflictingTargets,

    /// The principal was not a canonical UUID.
    ///
    /// Distinct from an unenrolled principal because the fixes differ: a typo is
    /// corrected, and an unenrolled principal has to be added. One sentence cannot
    /// name both fixes.
    #[error(
        "`{0}` is not a principal UUID: pass the canonical lowercase v4 UUID (8-4-4-4-12) that \
         `ksp admin list` prints"
    )]
    MalformedPrincipal(String),

    /// The deployment or its registry could not be read.
    #[error("{0}")]
    Deployment(String),

    /// The principal is not enrolled in this deployment.
    #[error(
        "principal {0} is not enrolled in this deployment: `ksp admin list` names the enrolled \
         principals, and `ksp admin user add` enrols a new one"
    )]
    NotEnrolled(String),

    /// The target principal has no recipient key yet.
    ///
    /// A registry entry is written before the principal's vault exists, so its
    /// recipient key can be absent. Sealing to nothing would produce a record
    /// nobody can open, which looks exactly like a successful import.
    #[error(
        "principal {0} has no recipient key, so no value can be sealed to it yet: its vault is \
         created by `ksp admin user add`, which enrols the recipient key"
    )]
    NoRecipientKey(String),

    /// The admin has no own vault, so `--own` has nothing to seal to.
    #[error(
        "this host holds no admin vault, so there is nothing to seal an admin-owned value to: \
         create one with `ksp admin seal-vault`, then re-run this command"
    )]
    NoAdminVault,
}

/// Resolve the two flags into exactly one destination.
///
/// The parse is separated from the lookup so a typo is caught before any store is
/// opened, and so the refusal for a malformed UUID is distinguishable from the
/// refusal for an unenrolled principal.
pub fn parse_target(to_principal: Option<&str>, own: bool) -> Result<ImportTarget, TargetError> {
    match (to_principal, own) {
        (Some(_), true) => Err(TargetError::ConflictingTargets),
        (None, false) => Err(TargetError::NoTarget),
        (None, true) => Ok(ImportTarget::OwnVault),
        (Some(text), false) => {
            // Trimmed before it is read. No UUID contains whitespace, so trimming
            // has one reading, and refusing `" 6f5a…"` as malformed would send the
            // operator looking for a typo that is not in the value. An empty value
            // after trimming is still a typo: `--to-principal ""` names nothing.
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return Err(TargetError::MalformedPrincipal(text.to_string()));
            }
            let principal = PrincipalId::parse(trimmed)
                .map_err(|_| TargetError::MalformedPrincipal(trimmed.to_string()))?;
            Ok(ImportTarget::Principal(principal))
        }
    }
}

/// The level an import writes at.
///
/// Always [`Level::Admin`], for both forms, because that mirrors `admin put` and
/// `admin put --own` exactly. The comment says so at the single place the decision
/// is made, so a future change has one thing to reconsider rather than two.
pub fn level_for(_target: &ImportTarget) -> Level {
    Level::Admin
}

/// A resolved destination: which principal owns the record, which key seals it.
///
/// The three fields are decided together because a record sealed to one principal's
/// key and written at another principal's path is misfit D: it looks correct and is
/// readable by the wrong person.
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    /// The principal whose subtree the record lives in.
    pub principal: PrincipalId,
    /// The X25519 public key the content key is sealed to.
    pub recipient: [u8; 32],
}

/// Resolve a target against this host's deployment and registry.
///
/// Nothing is sealed until this returns: an unenrolled principal or a missing
/// recipient key refuses here, before the first byte reaches the store.
pub fn resolve(
    layout: &crate::config::Layout,
    target: &ImportTarget,
) -> Result<ResolvedTarget, TargetError> {
    let (recorded, _anchor) = crate::deployment::require(layout)
        .map_err(|error| TargetError::Deployment(error.to_string()))?;

    match target {
        ImportTarget::OwnVault => {
            // The admin's own vault is where a value she keeps goes. Sealing to
            // anything else would let her write a record she cannot open, which is
            // the failure this branch exists to avoid.
            let recipient = recorded
                .admin_vault_recipient_key
                .ok_or(TargetError::NoAdminVault)?
                .to_bytes();
            Ok(ResolvedTarget {
                principal: recorded.admin,
                recipient,
            })
        }
        ImportTarget::Principal(id) => {
            let registry = crate::registry::PrincipalRegistry::load(layout)
                .map_err(|error| TargetError::Deployment(error.to_string()))?;
            let entry = registry.entry(*id).ok_or_else(|| {
                // The registry is authoritative: a principal absent from it has no
                // vault, so a value sealed to its key could never be opened.
                TargetError::NotEnrolled(id.to_string())
            })?;
            let recipient = entry
                .recipient_key
                .as_ref()
                .ok_or_else(|| TargetError::NoRecipientKey(id.to_string()))?
                .to_bytes();
            Ok(ResolvedTarget {
                principal: *id,
                recipient,
            })
        }
    }
}
