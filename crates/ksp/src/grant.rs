//! The policy lifecycle: create one grant, revise it, withdraw it.
//!
//! # The order is the control
//!
//! Every write here lands in one order — **ledger, then artifact, then
//! publication** — and each step exists to make the previous one survivable:
//!
//! - the ledger records the decision, so a crash after it leaves a grant a local
//!   client honours and a tree a retry can complete (FR-029, FR-030);
//! - the artifact is the authority a `run` verifies, and the ledger entry names
//!   its digest, so an artifact edited afterwards is detectable;
//! - the publication is written **after** the artifact because its entry is keyed
//!   by the policy id, and a publication written before the grant cannot know the
//!   id the grant will carry.
//!
//! # What the admin needs, and what she must not need
//!
//! Signing needs no password: the admin key is her enrolled signing key and the
//! grant is public material. Writing a publication *does* need one, because the
//! plaintext comes from the admin's own `--own` record and the artifact's content
//! key is sealed to her admin vault (CF-102). A cooperative grant writes no
//! publication, so it needs no password at all — and the surface says so rather
//! than reading a password it will not use.

use ksp_identity::policy_edge::{EdgeRequest, PolicyEdge, PolicyId, PolicyTarget};
use ksp_types::{OpaqueSecretId, PrincipalId, RecordVersion};

use crate::config::Layout;
use crate::deployment::Deployment;
use crate::exit;

/// The window a grant gets when the operator names none.
///
/// Thirty days, and named here rather than in a call site so the report and the
/// help text cannot state different numbers. It is a *default*, not a bound: a
/// delivery token's only lease is the grant's own `not_after` (CF-020), so a grant
/// that never expires would be a delivery that never expires either.
pub const DEFAULT_GRANT_WINDOW_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Why a policy lifecycle operation failed.
#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    /// This host has no deployment.
    #[error("this host is not provisioned for a policy")]
    NotProvisioned,
    /// The edge store refused the write.
    #[error(transparent)]
    Edge(#[from] crate::edges::EdgeStoreError),
    /// The publication could not be written or read.
    #[error(transparent)]
    Publication(#[from] crate::publication::PublicationError),
    /// The delivery token could not be issued.
    #[error(transparent)]
    Token(#[from] crate::token::TokenError),
    /// The admin's own copy of the value could not be opened.
    #[error(transparent)]
    Admin(#[from] crate::admin::AdminError),
    /// The withdrawal was refused.
    #[error(transparent)]
    Withdrawal(#[from] crate::lifecycle::WithdrawalError),
    /// A cooperative grant was asked for a delivery it cannot authorise.
    ///
    /// `AnyEnrolled` names no agent, so its publication is sealed to the user and no
    /// token exists to issue. Raised as a refusal rather than an internal error: the
    /// operator asked for a delivery the design does not describe.
    #[error(
        "policy {policy} is cooperative: it names no agent, so no delivery token can be \
         issued for it"
    )]
    CooperativeDelivery {
        /// The policy identifier.
        policy: String,
    },
    /// The requested window is not in the future.
    ///
    /// Refused before anything is signed: a grant whose `not_after` has passed is
    /// authority a `run` refuses, and writing it would put a row in the ledger for a
    /// decision that never takes effect.
    #[error(
        "the grant would expire at {not_after}, which is not after now ({now}): name a later \
         --expires-at, or leave it out for the {DEFAULT_GRANT_WINDOW_SECONDS}-second default"
    )]
    WindowPast {
        /// The instant the caller asked for.
        not_after: u64,
        /// The instant this command ran.
        now: u64,
    },
    /// The target was neither a named agent nor `--any`.
    #[error(
        "a grant needs a target: name one agent with --agent <uuid>, or --any for any enrolled \
         agent"
    )]
    NoTarget,
    /// A grant with a named agent was asked for without the password its
    /// publication needs.
    #[error(
        "this grant publishes a value, so it needs the admin vault password: supply it on \
         stdin, or name a file with --passphrase-file"
    )]
    NoPassword,
    /// The grant names an agent but this deployment has not published that agent's
    /// keys where the admin can read them.
    ///
    /// The admin cannot enter the user's `0700` home, so the index entry the user
    /// publishes is the only material she can seal to (CF-011). Naming the fix here
    /// matters: "the publication was refused" sent an operator looking for a
    /// permissions bug rather than for the missing publication step.
    #[error(
        "agent {agent} has published no keys in this deployment, so a publication cannot be \
         sealed to it: the user publishes that agent's keys first"
    )]
    AgentNotPublished {
        /// The agent the grant names.
        agent: String,
    },
}

impl GrantError {
    /// The exit code this failure maps to.
    pub fn exit_code(&self) -> i32 {
        match self {
            // A host with no deployment has no grant to write; every other surface
            // reports missing key material for that state, and this one matches.
            Self::NotProvisioned | Self::AgentNotPublished { .. } => exit::MISSING_KEY,
            Self::Admin(error) => error.exit_code(),
            Self::Token(error) => error.exit_code(),
            // A refusal is a decision, not a fault. Everything else is a file this
            // host could not read or write, which re-running will not fix.
            Self::Edge(
                crate::edges::EdgeStoreError::Refused(_)
                | crate::edges::EdgeStoreError::RecordedNotPublished { .. },
            ) => exit::POLICY_DENIAL,
            Self::Withdrawal(
                crate::lifecycle::WithdrawalError::Refused(_)
                | crate::lifecycle::WithdrawalError::RefusedEdge(_)
                | crate::lifecycle::WithdrawalError::Edge(_),
            ) => exit::POLICY_DENIAL,
            Self::Publication(_) | Self::Withdrawal(_) | Self::Edge(_) => exit::INTERNAL,
            Self::CooperativeDelivery { .. } => exit::POLICY_DENIAL,
            Self::WindowPast { .. } | Self::NoTarget | Self::NoPassword => exit::USAGE,
        }
    }
}

/// What one lifecycle operation produced.
pub struct GrantWritten {
    /// The joined view: the artifact, its tokens, its agent and its decision record.
    pub view: crate::policy_view::PolicyView,
    /// Where the delivery token was written, when the grant issued one.
    pub token: Option<std::path::PathBuf>,
}

/// Sign, record, publish and tokenise one grant.
///
/// `password` is `Some` only when the caller supplied one; it is required exactly
/// when the target is a named agent, because that is the case that writes a
/// publication.
#[allow(clippy::too_many_arguments)]
pub fn create(
    layout: &Layout,
    password: Option<&[u8]>,
    user: PrincipalId,
    secret: &OpaqueSecretId,
    version: RecordVersion,
    target: PolicyTarget,
    expires_at: Option<i64>,
) -> Result<GrantWritten, GrantError> {
    let (recorded, anchor) =
        crate::deployment::require(layout).map_err(|_| GrantError::NotProvisioned)?;
    let admin = crate::admin::load_admin(layout, &anchor)?;
    let ledger = crate::ledgers::LedgerPaths::for_deployment(layout, &recorded).as_ledger();

    let now = crate::run::now_seconds();
    let not_after = match expires_at {
        Some(at) => u64::try_from(at).unwrap_or(0),
        None => now.saturating_add(DEFAULT_GRANT_WINDOW_SECONDS),
    };
    if not_after <= now {
        return Err(GrantError::WindowPast { not_after, now });
    }

    // The publication path is derived, never supplied: it is the one path a reader
    // recomputes from the record's metadata, so an operator-chosen one would name an
    // artifact nobody looks for.
    let publication = match &target {
        PolicyTarget::Agent(_) => Some(crate::publication::PublicationPath::derive(
            recorded.vault.clone(),
            recorded.admin,
            secret.clone(),
            version,
        )),
        PolicyTarget::AnyEnrolled => None,
    };

    let request = EdgeRequest {
        user,
        secret: secret.clone(),
        record_version: version,
        // `PolicyTarget` is `Copy`, so naming it here does not consume the value the
        // publication match above borrowed.
        target,
        publication: publication.as_ref().map(|path| path.canonical()),
        not_before: now,
        not_after,
    };
    let store = crate::edges::EdgeStore::new(layout, &recorded);
    let edge = store.create(&admin, anchor.key_id.clone(), request, &ledger)?;

    let token = match publication {
        Some(path) => Some(publish_and_token(
            layout, password, &recorded, &admin, &edge, &path,
        )?),
        // A cooperative grant is an artifact and a ledger row and nothing else: the
        // publication would be sealed to the user, whom this command has no key for,
        // and issuing a token would claim a restriction the policy does not make
        // (FR-035).
        None => None,
    };

    let view = view_of(layout, &edge)?;
    Ok(GrantWritten { view, token })
}

/// Re-sign one grant at the next revision.
///
/// A target change re-publishes, because the entry is sealed to the agent's key: the
/// old entry names an agent that must no longer open it. The content key, the name
/// and the value are carried over — the artifact is not regenerated, because every
/// entry already made would stop opening.
pub fn update(
    layout: &Layout,
    password: Option<&[u8]>,
    id: &PolicyId,
    target: Option<PolicyTarget>,
    expires_at: Option<i64>,
) -> Result<GrantWritten, GrantError> {
    let (recorded, anchor) =
        crate::deployment::require(layout).map_err(|_| GrantError::NotProvisioned)?;
    let admin = crate::admin::load_admin(layout, &anchor)?;
    let ledger = crate::ledgers::LedgerPaths::for_deployment(layout, &recorded).as_ledger();
    let store = crate::edges::EdgeStore::new(layout, &recorded);
    let current = store.load(id)?;

    let now = crate::run::now_seconds();
    let not_after = match expires_at {
        Some(at) => u64::try_from(at).unwrap_or(0),
        None => current.body().not_after(),
    };
    if not_after <= now {
        return Err(GrantError::WindowPast { not_after, now });
    }
    let target = target.unwrap_or_else(|| current.target());

    // The path follows the record the grant names, so it does not move when only the
    // target does. A cooperative grant names none, by construction.
    let publication = match &target {
        PolicyTarget::Agent(_) => Some(
            current
                .body()
                .publication()
                .and_then(|named| crate::publication::PublicationPath::parse(named).ok())
                .unwrap_or_else(|| {
                    crate::publication::PublicationPath::derive(
                        recorded.vault.clone(),
                        recorded.admin,
                        current.secret().clone(),
                        current.record_version(),
                    )
                }),
        ),
        PolicyTarget::AnyEnrolled => None,
    };

    // The old entry is released **before** the new revision is recorded. A revision
    // in force must not be accompanied by an entry the previous revision left behind:
    // the reverse order leaves a window in which both are live.
    if let (PolicyTarget::AnyEnrolled, Some(named)) = (&target, current.body().publication()) {
        let path = crate::publication::PublicationPath::parse(named)
            .map_err(crate::publication::PublicationError::Path)?;
        crate::publication::release(layout, &path, id.as_str())?;
    }

    let request = EdgeRequest {
        user: *current.user(),
        secret: current.secret().clone(),
        record_version: current.record_version(),
        target,
        publication: publication.as_ref().map(|path| path.canonical()),
        not_before: current.body().not_before(),
        not_after,
    };
    let edge = store.update(&admin, anchor.key_id.clone(), id, request, &ledger)?;

    let token = match publication {
        Some(path) => Some(publish_and_token(
            layout, password, &recorded, &admin, &edge, &path,
        )?),
        None => None,
    };

    let view = view_of(layout, &edge)?;
    Ok(GrantWritten { view, token })
}

/// Withdraw one grant: record the decision, remove the artifact, release the entry.
///
/// `Withdrawal::complete` owns the order — it records first, so a decision that is
/// not on record cannot remove the artifact a verifier still names.
///
/// The result is the same joined view the other two verbs return, read **after** the
/// withdrawal. It is read by id rather than through an edge because the artifact is
/// gone: the ledger entry is now the only witness, and `PolicyReader` renders that as
/// `withdrawn` with the decision row attached instead of reporting no such policy.
pub fn withdraw(
    layout: &Layout,
    id: &PolicyId,
    actor: PrincipalId,
) -> Result<crate::policy_view::PolicyView, GrantError> {
    let (recorded, _anchor) =
        crate::deployment::require(layout).map_err(|_| GrantError::NotProvisioned)?;
    let store = crate::edges::EdgeStore::new(layout, &recorded);
    // Read without a trust decision: refusing to *remove* an artifact this host
    // cannot verify would leave the grant in force in every tree that can read it.
    let edge = store.load_unsigned(id)?;
    let ledger = crate::ledgers::LedgerPaths::for_deployment(layout, &recorded).as_ledger();
    let withdrawal = crate::lifecycle::Withdrawal::new(layout, &store, &ledger);
    withdrawal.complete(&edge, actor, crate::run::now_seconds() as i64)?;
    reader_show(layout, id.as_str())
}

/// Write the publication and issue the token the grant authorises.
fn publish_and_token(
    layout: &Layout,
    password: Option<&[u8]>,
    recorded: &Deployment,
    admin: &ksp_identity::AdminSigningKey,
    edge: &PolicyEdge,
    path: &crate::publication::PublicationPath,
) -> Result<std::path::PathBuf, GrantError> {
    let PolicyTarget::Agent(agent) = edge.target() else {
        // Unreachable through the two callers above, which only reach here with a
        // published target. Refused rather than panicking: a cooperative grant that
        // acquired a publication would be a delivery the design does not describe.
        return Err(GrantError::CooperativeDelivery {
            policy: edge.id().to_string(),
        });
    };
    // An update that moves only the window, or a create that repeats an identity, finds
    // the entry already sealed: `publish` returns the artifact untouched, so opening the
    // vault would ask the admin to decrypt a secret in order to write nothing. The token
    // is still minted, and `issue_policy_token` loads the publication and refuses when it
    // is absent — so the password is required exactly when an entry has to be sealed, and
    // an expiry-only update needs none.
    let already_sealed = path.file(layout).is_file()
        && crate::publication::load(layout, path)?.holds(edge.id().as_str());
    if !already_sealed {
        let password = password.ok_or(GrantError::NoPassword)?;
        let stored = crate::agent_index::load(layout, edge.vault(), *edge.user(), &agent).map_err(
            |error| match error {
                crate::keys::PinError::Absent => GrantError::AgentNotPublished {
                    agent: agent.to_string(),
                },
                // A published index this host cannot read is a file problem, not a missing
                // publication: the operator cannot fix it from the user's side.
                _ => GrantError::Admin(crate::admin::AdminError::Write),
            },
        )?;
        let admin_recipient = recorded
            .admin_vault_recipient_key
            .ok_or(crate::admin::AdminError::NoAdminVault)?;

        // The plaintext is opened **before** the publication is touched, so a missing
        // `--own` record refuses with the command that writes it instead of failing
        // half-way through a publish whose artifact was just rewritten.
        let vault = crate::admin::open_admin_vault(layout, password)?;
        let (name, value) = crate::admin::open_own_with(
            layout,
            &vault,
            edge.secret(),
            edge.record_version().get(),
        )?;

        crate::publication::publish(
            layout,
            path,
            crate::publication::PublishRequest {
                policy: edge.id().as_str(),
                cooperative: false,
                target: stored.recipient_key.to_bytes(),
                admin_recipient: admin_recipient.to_bytes(),
            },
            || Ok((name, value)),
            |publication| vault.with_recipient_secret(|sk| publication.open_with_admin(sk)),
        )?;
    }

    // One revision, one token: the identifier is derived from the policy and the
    // revision it authorises, so a retried create cannot mint a second token for the
    // same authority.
    let jti = format!("{}-{}", edge.id(), edge.revision());
    let issued = crate::token::issue_policy_token(layout, admin, edge, jti)?;
    Ok(issued.path)
}

/// The joined view of one edge, as every read surface renders it.
///
/// Read back through the same `PolicyReader` the listing uses rather than assembled
/// here: a write that described its own result could disagree with what the reader
/// prints, and the reader is the surface an operator checks it against.
fn view_of(
    layout: &Layout,
    edge: &PolicyEdge,
) -> Result<crate::policy_view::PolicyView, GrantError> {
    reader_show(layout, edge.id().as_str())
}

/// One policy, as the deployment-wide reader renders it.
fn reader_show(layout: &Layout, id: &str) -> Result<crate::policy_view::PolicyView, GrantError> {
    let reader = crate::policy_view::PolicyReader::open(layout, crate::run::now_seconds() as i64)
        .map_err(|_| GrantError::NotProvisioned)?;
    reader.show(id, None).map_err(|error| {
        GrantError::Edge(crate::edges::EdgeStoreError::Absent {
            path: error.to_string(),
        })
    })
}
