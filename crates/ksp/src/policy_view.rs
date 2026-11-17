//! The joined read projection over the policy edges.
//!
//! # What this module is for
//!
//! A signed edge is only half the answer. "Which policies does this deployment
//! hold, are they still in force, and what did they authorise" is a join across
//! five things that are deliberately separate:
//!
//! - `policies/<id>.cbor` — the signed artifact, and the only place a label may
//!   come from;
//! - `policy-events.jsonl` — the decisions, in the order they were made;
//! - the user's published agent index — the agent's identity, key ids and
//!   fingerprint;
//! - the publication the edge names — the sealed copy a delivery opens;
//! - `policies/<id>.token` — the token the grant issued, when one was issued.
//!
//! # What this module refuses to do
//!
//! It never omits a policy it cannot fully resolve. A missing agent, a withdrawn
//! secret version or an artifact whose signature does not verify all render as a
//! **state** with a reason, because the reader's question is "why is this not
//! working", and a row that disappeared answers it with silence (FR-032).
//!
//! The mode label is `PolicyTarget::mode` and nothing else: a view that spelled
//! `cooperative` out of a format string would be a second place a label is
//! decided, and the first one to fall behind a new target.
//!
//! # The token join, and its limit
//!
//! The token a grant issued lives at `policies/<id>.token` and names its policy
//! in its header, so it is the authority for "which token does this policy have".
//! `issuance.jsonl` rows are **not** part of this join: they record a policy
//! *revision* and no identifier, so a row cannot be attributed to one policy
//! among several. When the ledger holds such rows the listing says how many could
//! not be attributed rather than guessing or staying silent (CF-090).

use ksp_identity::delivery::DeliveryArtifact;
use ksp_identity::issuance::IssuanceLedger;
use ksp_identity::policy_edge::{PolicyAction, PolicyEdge, PolicyId};
use ksp_types::{AgentId, OpaqueSecretId, PrincipalId, VaultId};

use crate::config::Layout;
use crate::edges::{DeploymentLinks, EdgeStore, EdgeStoreError};
use crate::ledgers::LedgerPaths;
use crate::output::AgentListing;
use crate::registry::{PrincipalError, PrincipalRegistry};

/// The state one policy is in, as a read surface prints it.
///
/// One of five, and the order of precedence is the order of the variants: an
/// artifact this host cannot attribute is `unverified` whatever else is true of
/// it, because a state computed from bytes nobody signed is not evidence. A
/// withdrawal outranks a dangling link: the decision was made, and it stands even
/// if the thing it named has since been deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyState {
    /// Verified, recorded and in force.
    Active,
    /// The ledger records a revision that grants nothing further.
    Withdrawn,
    /// The edge names a user, agent or secret version that is not there.
    Dangling,
    /// The validity window has passed.
    Expired,
    /// The signature does not verify against the pinned anchor.
    Unverified,
}

impl PolicyState {
    /// The word a read surface prints.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Withdrawn => "withdrawn",
            Self::Dangling => "dangling",
            Self::Expired => "expired",
            Self::Unverified => "unverified",
        }
    }

    /// Parse one of the five words a `--state` filter accepts.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "withdrawn" => Some(Self::Withdrawn),
            "dangling" => Some(Self::Dangling),
            "expired" => Some(Self::Expired),
            "unverified" => Some(Self::Unverified),
            _ => None,
        }
    }

    /// The five accepted words, for a refusal that has to name them.
    pub const ALL: [&'static str; 5] = ["active", "withdrawn", "dangling", "expired", "unverified"];
}

/// One token a grant issued, as the read surface reports it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TokenRow {
    /// The token's identifier — the `jti` its header carries.
    pub jti: String,
    /// The instant the header's claims expire.
    pub expires_at: u64,
    /// `live`, `expired` or `revoked`.
    pub state: String,
    /// How many deliveries the arm still permits, when a bound was set.
    pub remaining_uses: Option<u32>,
}

/// One policy decision, as the withdrawal column reports it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WithdrawalRow {
    /// The revision the withdrawal produced.
    pub revision: u64,
    /// The principal that decided.
    pub actor: String,
    /// When it was recorded, in Unix seconds.
    pub at: i64,
}

/// One policy, joined to everything a reader needs to judge it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PolicyView {
    /// The edge's identifier, which is also the artifact's file name.
    pub id: String,
    /// The revision in force.
    pub revision: u64,
    /// The principal the policy grants to.
    pub user: String,
    /// The secret it names.
    pub secret: String,
    /// The record version it names.
    pub version: u32,
    /// The target, as `agent:<uuid>` or `any-enrolled`.
    pub target: String,
    /// `cryptographic` or `cooperative`, from `PolicyTarget::mode`.
    ///
    /// `unknown` for a policy the ledger knows and the tree does not: the decision
    /// record does not carry the target, so a withdrawn row cannot pretend to know
    /// which kind it was.
    pub mode: String,
    /// One of the five states.
    pub state: &'static str,
    /// Why the state is not `active`, when it is not.
    pub state_reason: Option<String>,
    /// The earliest instant the edge is valid.
    pub not_before: u64,
    /// The instant it stops being valid.
    pub not_after: u64,
    /// Whether the issuer verified against the pinned anchor.
    pub verified: bool,
    /// The publication the edge names, when it names one.
    pub publication: Option<String>,
    /// The tokens the grant issued, oldest decision first.
    pub tokens: Vec<TokenRow>,
    /// The agents the target names, with the keys and the fingerprint.
    ///
    /// Absent only for `cooperative`, which names no agent: an empty list there is
    /// the target's own statement, not a failed lookup.
    pub agents: Vec<AgentListing>,
    /// The withdrawal that ended the grant, when the ledger records one.
    pub withdrawal: Option<WithdrawalRow>,
    /// When the last decision about this policy was recorded.
    ///
    /// [Absent by decision] FR-024 also asks for the policy's *last use*. Nothing
    /// records a per-policy use: a consumption is a child process reading a
    /// publication, and the ledger records the mint and the withdrawal, not the read.
    /// The field is therefore the last recorded decision, named for what it is, rather
    /// than a "last use" computed from the nearest timestamp available.
    pub last_decision_at: Option<i64>,
}

/// What one listing answered, including what it did not print.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PolicyListing {
    /// The records this listing prints, in the documented order.
    pub records: Vec<PolicyView>,
    /// How many records the filter matched, printed or not.
    pub total: usize,
    /// The bound that was applied.
    pub limit: usize,
    /// How many issuance rows could not be attributed to a policy.
    ///
    /// Named rather than dropped: a reader comparing a policy's token count with
    /// the ledger needs to know that the ledger cannot answer the question.
    pub unattributed_issuances: usize,
}

/// Which records a listing prints.
#[derive(Debug, Clone, Default)]
pub struct PolicyFilter {
    /// Only policies naming this user.
    pub user: Option<PrincipalId>,
    /// Only policies naming this secret.
    pub secret: Option<OpaqueSecretId>,
    /// Only policies in this state.
    pub state: Option<PolicyState>,
    /// The caller's own scope: a user principal sees only her policies.
    pub scope: Option<PrincipalId>,
    /// The most records to print.
    pub limit: usize,
}

/// Why a read surface could not answer.
#[derive(Debug, thiserror::Error)]
pub enum PolicyReadError {
    /// This host holds no deployment to read.
    #[error("this host holds no deployment, so it holds no policy to read")]
    NotProvisioned,
    /// There is no policy with that identifier in this deployment.
    ///
    /// Reported for a policy that exists under a *different* user as well, so the
    /// surface does not confirm the existence of another principal's edge
    /// (FR-026).
    #[error("this deployment holds no policy {id}")]
    Absent {
        /// The identifier that was asked for.
        id: String,
    },
    /// The identifier is not one this deployment could have issued.
    #[error(
        "{value} is not a policy identifier: a policy identifier is 32 lowercase hex characters"
    )]
    MalformedId {
        /// The value that was refused.
        value: String,
    },
    /// The edge store refused to answer.
    #[error(transparent)]
    Store(#[from] EdgeStoreError),
    /// The ledger refused to answer.
    #[error("the policy ledger could not be read: {0}")]
    Ledger(String),
    /// The registry could not name the deployment's principals.
    #[error(transparent)]
    Registry(#[from] PrincipalError),
    /// The anchor is absent or unreadable, so no artifact can be verified.
    #[error("the admin anchor could not be read, so no policy can be verified")]
    Anchor,
}

impl PolicyReadError {
    /// The exit code this refusal carries.
    pub fn exit_code(&self) -> i32 {
        match self {
            // A policy id that does not exist is a command given an argument the
            // deployment cannot satisfy, which is the usage class — not a denial,
            // and deliberately not distinguishable from another user's policy.
            Self::Absent { .. } | Self::MalformedId { .. } => crate::exit::USAGE,
            Self::NotProvisioned | Self::Anchor => crate::exit::MISSING_KEY,
            Self::Store(error) => match error {
                EdgeStoreError::Absent { .. } => crate::exit::USAGE,
                _ => crate::exit::INTERNAL,
            },
            Self::Ledger(_) | Self::Registry(_) => crate::exit::INTERNAL,
        }
    }
}

/// Everything one deployment-wide read needs, opened once.
pub struct PolicyReader<'a> {
    layout: &'a Layout,
    store: EdgeStore<'a>,
    ledger: IssuanceLedger,
    anchor: ksp_identity::VerifyingPublicKey,
    registry: PrincipalRegistry,
    vault: VaultId,
    now: i64,
}

impl<'a> PolicyReader<'a> {
    /// Open the reader for one deployment.
    ///
    /// No password and no admin key: every input is public material with group
    /// read, which is what lets a user principal run the same join (FR-027).
    pub fn open(layout: &'a Layout, now: i64) -> Result<Self, PolicyReadError> {
        // The resolved pin, not a second read of the file it came from: `require`
        // opened the anchor to answer, and reading it again would be a second answer
        // to the same question — the trap that put an empty path in a plist.
        let (deployment, anchor) =
            crate::deployment::require(layout).map_err(|_| PolicyReadError::NotProvisioned)?;
        let registry = PrincipalRegistry::load_at(&PrincipalRegistry::path_of(
            layout,
            &deployment.vault,
            deployment.admin,
        ))
        .map_err(|_| PolicyReadError::Anchor)?;
        let ledger = LedgerPaths::for_deployment(layout, &deployment).as_ledger();
        let store = EdgeStore::new(layout, &deployment);
        Ok(Self {
            layout,
            store,
            ledger,
            anchor: anchor.key,
            registry,
            vault: deployment.vault.clone(),
            now,
        })
    }

    /// The vault these policies live in.
    pub fn vault(&self) -> &VaultId {
        &self.vault
    }

    /// Every policy the filter selects, in the documented order.
    ///
    /// The order is the tuple the stores are keyed by — user, secret, version, id —
    /// so two runs over one tree print the same rows in the same places, and a
    /// limit cuts a prefix of that order rather than a filesystem's whim.
    pub fn list(&self, filter: &PolicyFilter) -> Result<PolicyListing, PolicyReadError> {
        let entries = self
            .ledger
            .policy_entries()
            .map_err(|error| PolicyReadError::Ledger(error.to_string()))?;
        let mut records: Vec<PolicyView> = self
            .store
            .list_unsigned()?
            .iter()
            .map(|edge| self.view(edge.id(), Some(edge), &entries))
            .collect::<Result<_, _>>()?;
        // A policy the ledger decided and the tree no longer holds is *not* omitted:
        // a withdrawal removes the artifact, and a listing that showed only what is
        // on disk would report a withdrawn grant as never having existed.
        let present: std::collections::BTreeSet<String> =
            records.iter().map(|record| record.id.clone()).collect();
        let orphans: Vec<PolicyId> = entries
            .iter()
            .filter(|entry| !present.contains(entry.policy.as_str()))
            .map(|entry| entry.policy.clone())
            .collect();
        for id in orphans {
            if present.contains(id.as_str()) {
                continue;
            }
            if records.iter().any(|record| record.id == id.as_str()) {
                continue;
            }
            records.push(self.view(&id, None, &entries)?);
        }
        let unattributed_issuances = self.unattributed_issuance_count()?;

        if let Some(user) = filter.user.or(filter.scope) {
            records.retain(|record| record.user == user.to_string());
        }
        if let Some(secret) = &filter.secret {
            records.retain(|record| record.secret == secret.to_string());
        }
        if let Some(state) = filter.state {
            records.retain(|record| record.state == state.as_str());
        }
        records.sort_by(|left, right| {
            (&left.user, &left.secret, left.version, &left.id).cmp(&(
                &right.user,
                &right.secret,
                right.version,
                &right.id,
            ))
        });
        let total = records.len();
        let limit = filter.limit.max(1);
        records.truncate(limit);
        Ok(PolicyListing {
            records,
            total,
            limit,
            unattributed_issuances,
        })
    }

    /// One policy, with the whole join.
    ///
    /// `scope` is the caller's own principal when a user runs the command: an edge
    /// belonging to someone else is reported as absent rather than forbidden, so
    /// the answer does not confirm that another principal holds anything.
    pub fn show(
        &self,
        id: &str,
        scope: Option<PrincipalId>,
    ) -> Result<PolicyView, PolicyReadError> {
        let id = PolicyId::parse(id).map_err(|_| PolicyReadError::MalformedId {
            value: id.to_string(),
        })?;
        let entries = self
            .ledger
            .policy_entries()
            .map_err(|error| PolicyReadError::Ledger(error.to_string()))?;
        let edge = match self.store.load_unsigned(&id) {
            Ok(edge) => Some(edge),
            // The ledger knows this policy and the tree does not: a withdrawal
            // removes the artifact, and reporting that as "no such policy" would
            // erase the decision from the only surface that can show it.
            Err(EdgeStoreError::Absent { .. })
                if entries.iter().any(|entry| entry.policy == id) =>
            {
                None
            }
            Err(EdgeStoreError::Absent { .. }) => {
                return Err(PolicyReadError::Absent { id: id.to_string() });
            }
            Err(error) => return Err(PolicyReadError::Store(error)),
        };
        if let Some(caller) = scope {
            let owner = edge.as_ref().map(|edge| *edge.user()).or_else(|| {
                entries
                    .iter()
                    .find(|entry| entry.policy == id)
                    .map(|entry| entry.user)
            });
            if owner != Some(caller) {
                return Err(PolicyReadError::Absent { id: id.to_string() });
            }
        }
        self.view(&id, edge.as_ref(), &entries)
    }

    /// The one join, shared by `list` and `show` so they cannot disagree.
    ///
    /// `edge` is `None` for a policy only the ledger knows: the state then comes from
    /// the decisions alone, and every field the artifact would have supplied is
    /// reported as unknown rather than reconstructed.
    fn view(
        &self,
        id: &PolicyId,
        edge: Option<&PolicyEdge>,
        entries: &[ksp_identity::policy_edge::PolicyLedgerEntry],
    ) -> Result<PolicyView, PolicyReadError> {
        let last = entries
            .iter()
            .filter(|entry| entry.policy == *id)
            .max_by_key(|entry| entry.revision);
        let withdrawn = last.is_some_and(|entry| entry.action == PolicyAction::Withdrawn);
        let withdrawal = last
            .filter(|entry| entry.action == PolicyAction::Withdrawn)
            .map(|entry| WithdrawalRow {
                revision: entry.revision,
                actor: entry.actor.to_string(),
                at: entry.at,
            });
        let last_decision_at = last.map(|entry| entry.at);

        let Some(edge) = edge else {
            let entry = last.ok_or_else(|| PolicyReadError::Absent { id: id.to_string() })?;
            return Ok(PolicyView {
                id: id.to_string(),
                revision: entry.revision,
                user: entry.user.to_string(),
                secret: entry.secret.to_string(),
                version: entry.record_version.get(),
                target: "unknown".to_string(),
                mode: "unknown".to_string(),
                state: PolicyState::Withdrawn.as_str(),
                state_reason: Some(
                    "the ledger records this withdrawal and the artifact is gone, which is what a withdrawal leaves behind: the decision stands, and the target it named is not in the record"
                        .to_string(),
                ),
                not_before: 0,
                not_after: 0,
                verified: false,
                publication: entry.publication.clone(),
                tokens: Vec::new(),
                agents: Vec::new(),
                withdrawal,
                last_decision_at,
            });
        };

        let verified = edge.verify_issuer(&self.anchor);
        let missing = self.missing_link(edge);
        let expired = edge.body().not_after() <= self.now as u64;
        // The ledger and the artifact name one another by digest, so a revision that
        // is recorded with different bytes is a rewritten artifact even when the
        // signature over those bytes verifies: the admin signed *something*, and it
        // is not what the ledger decided.
        let rewritten = last.is_some_and(|entry| {
            entry.revision == edge.revision()
                && edge
                    .digest()
                    .map(|digest| digest != entry.digest)
                    .unwrap_or(true)
        });

        let (state, reason) = if !verified {
            (
                PolicyState::Unverified,
                Some(
                    "the signature does not verify against the pinned admin anchor, so nothing this edge says is evidence"
                        .to_string(),
                ),
            )
        } else if rewritten {
            (
                PolicyState::Unverified,
                Some(
                    "the artifact's digest is not the one the ledger recorded for this revision, so the bytes on disk are not the decision that was made"
                        .to_string(),
                ),
            )
        } else if withdrawn {
            (
                PolicyState::Withdrawn,
                Some(format!(
                    "revision {} grants nothing further, per the policy ledger",
                    last.map(|entry| entry.revision).unwrap_or_default()
                )),
            )
        } else if let Some(reason) = missing {
            (PolicyState::Dangling, Some(reason))
        } else if expired {
            (
                PolicyState::Expired,
                Some(format!(
                    "the validity window ended at {}",
                    edge.body().not_after()
                )),
            )
        } else {
            (PolicyState::Active, None)
        };

        Ok(PolicyView {
            id: edge.id().to_string(),
            revision: edge.revision(),
            user: edge.user().to_string(),
            secret: edge.secret().to_string(),
            version: edge.record_version().get(),
            target: edge.target().to_string(),
            mode: edge.target().mode().to_string(),
            state: state.as_str(),
            state_reason: reason,
            not_before: edge.body().not_before(),
            not_after: edge.body().not_after(),
            verified,
            publication: edge.body().publication().map(str::to_string),
            tokens: self.tokens(edge)?,
            agents: self.agents(edge),
            withdrawal,
            last_decision_at,
        })
    }

    /// The tokens this grant issued.
    ///
    /// The artifact at `policies/<id>.token` names its policy in its own header, so
    /// it is the authority. An artifact for another policy, an artifact that does
    /// not verify, or one that will not decode is reported as a row the reader can
    /// see is wrong — never as an empty list, which would read as "no token".
    fn tokens(&self, edge: &PolicyEdge) -> Result<Vec<TokenRow>, PolicyReadError> {
        let path = self.store.token_path(edge.id());
        if !path.exists() {
            return Ok(Vec::new());
        }
        let row = match std::fs::read(&path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                DeliveryArtifact::from_bytes(&bytes).map_err(|error| error.to_string())
            }) {
            Ok(artifact) => {
                let header = artifact.header();
                let named = header
                    .records()
                    .first()
                    .and_then(|record| record.policy.clone());
                if named.as_ref() != Some(edge.id()) {
                    TokenRow {
                        jti: header.jti().to_string(),
                        expires_at: header.expires_at(),
                        state: "another_policy".to_string(),
                        remaining_uses: None,
                    }
                } else {
                    let revoked = self
                        .ledger
                        .standing(header.jti())
                        .map(|standing| standing.refuses_run())
                        .unwrap_or(false);
                    let state = if revoked {
                        "revoked"
                    } else if header.expires_at() <= self.now as u64 {
                        "expired"
                    } else {
                        "live"
                    };
                    TokenRow {
                        jti: header.jti().to_string(),
                        expires_at: header.expires_at(),
                        state: state.to_string(),
                        remaining_uses: ksp_backend::usebound::remaining(
                            &self.layout.store_root(),
                            header.jti(),
                        ),
                    }
                }
            }
            // A file that will not read is still a token this policy issued, and a
            // reader who sees `unreadable` knows to replace it. An empty list would
            // say the grant issued nothing.
            Err(reason) => TokenRow {
                jti: String::new(),
                expires_at: 0,
                state: format!("unreadable: {reason}"),
                remaining_uses: None,
            },
        };
        Ok(vec![row])
    }

    /// The agents the target names, with the keys and the fingerprint.
    fn agents(&self, edge: &PolicyEdge) -> Vec<AgentListing> {
        let Some(agent) = edge.target().agent() else {
            return Vec::new();
        };
        self.agent_listing(edge, agent).into_iter().collect()
    }

    /// One agent's published identity, or nothing when it is not there.
    fn agent_listing(&self, edge: &PolicyEdge, agent: AgentId) -> Option<AgentListing> {
        let stored =
            crate::agent_index::load(self.layout, &self.vault, *edge.user(), &agent).ok()?;
        Some(AgentListing {
            identity: stored.identity.to_string(),
            display_name: stored.display_name.clone(),
            signing_key_id: stored.signing_key_id.to_string(),
            recipient_key_id: stored.recipient_key_id.to_string(),
            fingerprint: stored.fingerprint.to_hex(),
        })
    }

    /// The first link this edge names that is not there.
    ///
    /// The same three questions admission asks, asked through the same trait, so a
    /// policy that was admitted cannot read as `dangling` for any other reason than
    /// the one it would have been refused for.
    fn missing_link(&self, edge: &PolicyEdge) -> Option<String> {
        let links = DeploymentLinks::new(
            self.layout,
            &self.registry,
            self.vault.clone(),
            *edge.user(),
        );
        use ksp_identity::policy_edge::LinkCheck;
        if !links.user_exists(edge.user()) {
            return Some(format!(
                "user {} is not in this deployment's registry",
                edge.user()
            ));
        }
        if let Some(agent) = edge
            .target()
            .agent()
            .filter(|agent| !links.agent_exists(*agent))
        {
            return Some(format!(
                "agent {agent} is not published by this user, so the grant has no one to deliver to"
            ));
        }
        if !links.secret_version_exists(edge.secret(), edge.record_version()) {
            // A link that could not be *looked at* is not a link that is missing.
            // The state stays whatever the other facts say, and the sentence says
            // which fact is unknown rather than accusing the tree.
            if let Some(backend) = links.unavailable() {
                return Some(format!(
                    "the {backend} backend cannot be consulted without a live client, so the secret version was not checked"
                ));
            }
            // The version may live at the user's level or in the admin's own record —
            // UC1 has the admin create the secret on her vault — so the sentence names
            // both places the check looked rather than one of them (CF-103).
            return Some(format!(
                "secret {} version {} is stored at neither the user's level nor the admin's",
                edge.secret(),
                edge.record_version().get()
            ));
        }
        // The publication is a link the grant names, and it is the one that carries the
        // ciphertext: a grant whose artifact names it and whose file is not there cannot
        // deliver to anyone. Only a specific-agent grant names one; a cooperative grant
        // has none by construction, and its absence is not a broken link (FR-035).
        if let Some(named) = edge.body().publication() {
            let present = crate::publication::PublicationPath::parse(named)
                .ok()
                .is_some_and(|path| path.file(self.layout).is_file());
            if !present {
                return Some(format!(
                    "the publication {named} is not on this host, and it is what the grant delivers from"
                ));
            }
        }
        None
    }

    /// How many issuance rows name a policy revision but no policy.
    ///
    /// A count, not a list: the rows belong to the legacy mint path and cannot be
    /// attributed to one edge, so printing them under a policy would be a claim the
    /// ledger cannot support (CF-090).
    fn unattributed_issuance_count(&self) -> Result<usize, PolicyReadError> {
        let listing = self
            .ledger
            .listing()
            .map_err(|error| PolicyReadError::Ledger(error.to_string()))?;
        Ok(listing.entries.len())
    }
}
