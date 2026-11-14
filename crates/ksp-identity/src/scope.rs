//! Which audit records a caller may read, decided from the pin that proved them.
//!
//! # Misfit S — the audit view crosses the split
//!
//! "Any operation by any part of the system" taken literally makes the audit view
//! the confidentiality leak the principal split exists to prevent: a tenant reads
//! the admin's provisioning, an agent reads a sibling's deliveries. The decision
//! therefore belongs to the identity context and not to the renderer — a scope
//! applied only to `--json` would leave the human view the weaker path.
//!
//! # The pin decides, never the request
//!
//! A caller's principal comes from the credential that was proved for this
//! invocation: the admin's pinned anchor, or the tenant's vault binding. A
//! requested principal selects a *subject*; it can narrow a view and it can never
//! widen one. This is what keeps a `--principal` flag from being an authorization
//! mechanism, and it is why [`resolve`] takes the [caller](Caller) and the
//! [request](Request) as separate arguments.
//!
//! # Why this decision lives here and not beside the chain
//!
//! The obvious home for "which records may a caller read" is next to [`Scope`]'s
//! input, `AuditChain`, in `ksp-deletion`. It cannot go there: `ksp-deletion` already
//! depends on this crate for the signed evidence envelope, so a dependency back would
//! be a cycle. This module therefore decides over the `AuditRecord` payload, which is
//! all the decision needs, and the CLI — the only place that holds both crates and the
//! layout — reads the segments and applies the predicate. The authorization decision
//! stays in S1; only the I/O moves. The test below fails if that dependency ever goes
//! away, because the reason for this placement would have gone with it.
//!
//! # What is deliberately absent
//!
//! There is no lookup here, so a refusal cannot disclose whether a UUID exists:
//! the answer for a real sibling and for a random UUID is the same refusal with
//! the same wording. [`ScopeRefusal`] carries the requested UUID — naming what was
//! asked for is required — and nothing else about it.

use ksp_types::evidence::{AuditRecord, AuditTarget};
use ksp_types::{Level, PrincipalId};

use crate::fingerprint::KeyId;

/// How the caller's identity was established for this invocation.
///
/// Each variant names the pinned key that was proved, because the scope follows
/// the pin: a caller that cannot prove one of these keys is not a caller at all
/// and is refused with the class's own code before a scope is resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// The holder of the pinned admin signing key.
    Admin {
        /// The key ID the anchor pins.
        key_id: KeyId,
        /// The tenant's principal UUID, as the deployment recorded it.
        ///
        /// `Level::User` is a bare word and names no UUID, so a subject filter can only
        /// match a user level if it knows which principal that level belongs to. The
        /// deployment record is a pinned fact — not a name looked up in a registry, which
        /// FR-037 forbids — so it can answer that without inventing an identity.
        tenant: PrincipalId,
    },
    /// The tenant, proved by opening its vault with the password it alone holds.
    Tenant {
        /// The tenant's principal UUID, as the deployment recorded it.
        principal: PrincipalId,
        /// The key ID the vault binding and the deployment pin.
        key_id: KeyId,
    },
}

impl Caller {
    /// The pinned key ID that was proved.
    pub fn key_id(&self) -> &KeyId {
        match self {
            Self::Admin { key_id, .. } | Self::Tenant { key_id, .. } => key_id,
        }
    }

    /// The principal UUID the caller acts as, when it has one.
    ///
    /// The admin has one since 002 (`deployment.admin`), but it is not the subject of
    /// the records it reads: an administrative write names the tenant it was
    /// performed for, so the admin's scope is `Complete` and needs no principal here.
    pub fn principal(&self) -> Option<PrincipalId> {
        match self {
            Self::Admin { .. } => None,
            Self::Tenant { principal, .. } => Some(*principal),
        }
    }
}

/// What the caller asked to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Everything the caller's scope holds.
    All,
    /// One principal's records, named on the command line.
    Subject(PrincipalId),
}

/// Which records a caller may read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Every chain: the admin's view.
    Complete,
    /// One principal's records, selected by the admin as a subject.
    Subject {
        /// The principal whose records were asked for.
        principal: PrincipalId,
        /// The level that belongs to that principal, when this build can name one.
        ///
        /// `Level::Agent` carries its UUID in every record, so an agent subject needs
        /// nothing here. A user level is the bare word `user`, so a user subject matches
        /// on level only when the caller can say which principal that level is — the
        /// admin can, from the deployment record.
        level: Option<Level>,
    },
    /// The caller's own operations, plus the operations that name its own level.
    Own {
        /// The principal the caller acts as.
        principal: PrincipalId,
        /// The level that counts as this principal's own.
        level: Level,
    },
}

impl Scope {
    /// Whether one record is inside this scope.
    ///
    /// Two ways in, and no third: the caller authored the record, or the record's
    /// target is the caller's own level. Both are read from the *signed payload*,
    /// never from the directory the record was found in — a path is not a
    /// signature, and a file moved into another actor's directory would otherwise
    /// widen a view.
    pub fn permits(&self, record: &AuditRecord) -> bool {
        match self {
            Self::Complete => true,
            // A subject filter answers for one principal without a lookup: the record
            // names it as the actor, or names its agent level, which carries the UUID
            // in its path segment. A user's own level does **not** carry a UUID, so a
            // subject that is a user is matched on authorship only — deriving the rest
            // would be the lookup this module refuses to invent (FR-037).
            Self::Subject { principal, level } => {
                record.actor == *principal
                    || matches!(
                        &record.target,
                        Some(AuditTarget::Record { level: Level::Agent(agent), .. })
                            if agent.principal() == *principal
                    )
                    || matches!(
                        (&record.target, level),
                        (Some(AuditTarget::Record { level: target, .. }), Some(level))
                            if target == level
                    )
            }
            Self::Own { principal, level } => {
                record.actor == *principal
                    || matches!(
                        &record.target,
                        Some(AuditTarget::Record { level: target, .. }) if target == level
                    )
            }
        }
    }

    /// The one-line description a view prints so the reader knows what it saw.
    pub fn label(&self) -> String {
        match self {
            Self::Complete => "complete".to_string(),
            Self::Subject { principal, .. } => format!("subject={principal}"),
            Self::Own { principal, level } => {
                format!("principal={principal} level={}", level.path_segment())
            }
        }
    }
}

/// Why a request was outside the caller's scope.
///
/// The wording names the mechanism, because "permission denied" tells an operator
/// neither what decided nor how to ask again correctly.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeRefusal {
    /// The caller asked for another principal's records.
    #[error(
        "the audit view is scoped to the principal whose pinned key signs the invocation: \
         {caller} may not read the records of {requested}; ask as that principal, or as the admin"
    )]
    OutOfScope {
        /// The principal the caller acts as.
        caller: PrincipalId,
        /// The principal that was asked for.
        requested: PrincipalId,
    },
}

/// Decide what one caller may read.
pub fn resolve(caller: &Caller, request: Request) -> Result<Scope, ScopeRefusal> {
    match caller {
        // A subject narrows the admin's view. It needs no permission — the complete
        // view already holds every record it could select — but it must not be
        // ignored: a caller that asked for less and received everything has been
        // told its request did not matter.
        Caller::Admin { tenant, .. } => Ok(match request {
            Request::All => Scope::Complete,
            Request::Subject(principal) => Scope::Subject {
                principal,
                level: (principal == *tenant).then_some(Level::User),
            },
        }),
        Caller::Tenant { principal, .. } => match request {
            Request::All => Ok(Scope::Own {
                principal: *principal,
                level: Level::User,
            }),
            Request::Subject(requested) if requested == *principal => Ok(Scope::Own {
                principal: *principal,
                level: Level::User,
            }),
            Request::Subject(requested) => Err(ScopeRefusal::OutOfScope {
                caller: *principal,
                requested,
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use ksp_types::evidence::{AuditComponent, AuditOperation, Outcome};
    use ksp_types::{OpaqueSecretId, VaultId};

    /// A canonical version-4 UUID that differs in its last byte.
    fn principal(last: u8) -> PrincipalId {
        PrincipalId::parse(&format!("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e{last:02x}")).unwrap()
    }

    fn tenant() -> Caller {
        Caller::Tenant {
            principal: principal(1),
            key_id: KeyId::new("user-2026"),
        }
    }

    fn admin() -> Caller {
        Caller::Admin {
            key_id: KeyId::new("admin-2026"),
            tenant: principal(1),
        }
    }

    fn record(actor: PrincipalId, target: Option<AuditTarget>) -> AuditRecord {
        AuditRecord {
            actor,
            signer_key_id: "admin-2026".to_string(),
            component: AuditComponent::CommandLine,
            operation: AuditOperation::Put,
            target,
            outcome: Outcome::Success,
            exit_code: 0,
            observed_at: 1_700_000_000,
            prev_digest: None,
            acceptance: None,
        }
    }

    fn at(level: Level) -> Option<AuditTarget> {
        Some(AuditTarget::Record {
            vault: VaultId::new("vault-1"),
            level,
            secret: OpaqueSecretId::new("db-password"),
            version: 1,
        })
    }

    #[test]
    fn the_admin_reads_every_record() {
        let scope = resolve(&admin(), Request::All).unwrap();
        assert_eq!(scope, Scope::Complete);
        assert!(scope.permits(&record(principal(9), None)));
        assert!(scope.permits(&record(principal(2), at(Level::User))));
    }

    /// A subject narrows the admin's view instead of being ignored: a caller that asked
    /// for one principal and received every principal has been told its request did not
    /// matter.
    #[test]
    fn the_admin_asking_for_a_subject_gets_that_subject() {
        let asked = principal(2);
        let scope = resolve(&admin(), Request::Subject(asked)).unwrap();
        assert_eq!(
            scope,
            Scope::Subject {
                principal: asked,
                level: None
            }
        );

        assert!(
            scope.permits(&record(asked, None)),
            "authored by the subject"
        );
        assert!(
            scope.permits(&record(
                principal(9),
                at(Level::Agent(ksp_types::AgentId::new(asked)))
            )),
            "another actor's operation on the subject's own agent level"
        );
        assert!(
            !scope.permits(&record(principal(9), None)),
            "a different actor"
        );
        assert!(
            !scope.permits(&record(principal(9), at(Level::User))),
            "a user level belongs to the tenant, not to an agent subject"
        );
    }

    /// The tenant is the one principal whose level is a bare word, so matching it takes
    /// the deployment's own record rather than a guess.
    #[test]
    fn the_admin_asking_for_the_tenant_matches_the_user_level() {
        let tenant = principal(1);
        let scope = resolve(&admin(), Request::Subject(tenant)).unwrap();
        assert_eq!(
            scope,
            Scope::Subject {
                principal: tenant,
                level: Some(Level::User)
            }
        );
        assert!(
            scope.permits(&record(principal(9), at(Level::User))),
            "an operation on the tenant's level is the tenant's record"
        );
        assert!(!scope.permits(&record(
            principal(9),
            at(Level::Agent(ksp_types::AgentId::new(principal(2))))
        )));
    }

    #[test]
    fn a_tenant_sees_what_it_authored_and_what_names_its_own_level() {
        let scope = resolve(&tenant(), Request::All).unwrap();
        assert!(scope.permits(&record(principal(1), None)));
        // An agent's delivery of the tenant's record names the tenant's level.
        assert!(scope.permits(&record(principal(2), at(Level::User))));
        // Another principal's operation, and one that names another level, are out.
        assert!(!scope.permits(&record(principal(2), None)));
        assert!(!scope.permits(&record(
            principal(2),
            at(Level::Agent(ksp_types::AgentId::new(principal(2))))
        )));
    }

    #[test]
    fn a_deployment_wide_record_belongs_to_the_admin_view() {
        let scope = resolve(&tenant(), Request::All).unwrap();
        assert!(!scope.permits(&record(principal(9), Some(AuditTarget::Deployment))));
    }

    #[test]
    fn asking_for_another_principal_is_refused_and_the_request_does_not_widen_anything() {
        let refused = resolve(&tenant(), Request::Subject(principal(2)));
        assert!(matches!(
            refused,
            Err(ScopeRefusal::OutOfScope { requested, .. }) if requested == principal(2)
        ));
        // Asking for your own UUID is not a widening: it is the same view.
        assert_eq!(
            resolve(&tenant(), Request::Subject(principal(1))).unwrap(),
            resolve(&tenant(), Request::All).unwrap()
        );
    }

    /// A real sibling and a UUID nobody holds get the same answer, so the command
    /// cannot be used to enumerate principals.
    #[test]
    fn an_absent_uuid_is_refused_exactly_like_a_forbidden_one() {
        let sibling = resolve(&tenant(), Request::Subject(principal(2))).unwrap_err();
        let absent = resolve(&tenant(), Request::Subject(principal(200))).unwrap_err();
        assert_eq!(
            std::mem::discriminant(&sibling),
            std::mem::discriminant(&absent)
        );
        let wording = |refusal: &ScopeRefusal, asked: PrincipalId| {
            refusal.to_string().replace(&asked.to_string(), "<asked>")
        };
        assert_eq!(
            wording(&sibling, principal(2)),
            wording(&absent, principal(200)),
            "the two refusals must not differ in anything but the UUID asked for"
        );
    }

    /// The dependency this module's placement rests on.
    ///
    /// The decision is here rather than beside `AuditChain` because `ksp-deletion` already
    /// depends on this crate, and a dependency back would be a cycle. If that ever stops
    /// being true, the reason for this placement stops being true with it — and a note that
    /// quietly outlives its cause is worse than no note, because the next reader trusts it.
    /// The manifest is embedded at compile time, so this costs no I/O and cannot pass over
    /// a manifest it did not read.
    #[test]
    fn the_crate_that_makes_this_the_right_home_still_depends_on_us() {
        let deletion = include_str!("../../ksp-deletion/Cargo.toml");
        assert!(
            deletion.contains("ksp-identity"),
            concat!(
                "ksp-deletion no longer depends on ksp-identity, so the reason the audit scope ",
                "decides over the AuditRecord payload instead of living beside AuditChain has ",
                "expired: revisit the placement (plan.md) and this note"
            )
        );
    }

    #[test]
    fn the_refusal_names_the_mechanism_not_permission_denied() {
        let text = resolve(&tenant(), Request::Subject(principal(2)))
            .unwrap_err()
            .to_string();
        assert!(
            text.contains("scoped to the principal whose pinned key signs the invocation"),
            "a refusal must say what decided it: {text}"
        );
        assert!(!text.contains("permission denied"), "{text}");
        assert!(
            text.contains(&principal(2).to_string()),
            "the requested principal must be named: {text}"
        );
    }
}
