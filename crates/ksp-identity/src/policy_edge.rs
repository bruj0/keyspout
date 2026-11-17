//! One policy is one signed access edge.
//!
//! # What this replaces
//!
//! The old `Policy` held two lists and granted their **product**: a secret in
//! `shareable_secrets` and an agent in `shareable_agents` together authorised that
//! agent to read that secret. Two lists cannot say "this agent, this secret" — they
//! can only say "any of these, any of those" — and that is misfit A: a reader saw
//! "shareable" and heard a restriction the artifact did not make.
//!
//! An edge says one thing: this user's secret at this version may go to this
//! target. There is one target, never a list.
//!
//! # Targets cannot be patterns
//!
//! [`PolicyTarget`] has two forms, `Agent(uuid)` and `AnyEnrolled`. There is no
//! string form inside the model, so a wildcard, a prefix or a list is not a value
//! the model can hold — it is a **refusal at the boundary**, in [`PolicyTarget::parse`],
//! which names both accepted forms. A model that stored a pattern and checked it
//! later would be one forgotten check away from authorising everything.
//!
//! # The body is a fixed-order struct
//!
//! `ksp_types::cbor` documents that a map has no guaranteed byte representation,
//! and the signature is over exactly these bytes. The field order below is the
//! wire order, pinned by `crates/ksp-identity/tests/fixtures/policy-edge-body.cbor`.
//!
//! # The revision is monotonic and carries no history
//!
//! Creation is revision 1. An update signs `N+1` with the same id. The artifact is
//! replaced, and the *history* lives in the withdrawal ledger (WP04) — a policy
//! file that kept its own revisions would be a second, unauthenticated copy of the
//! ledger.

use std::fmt;

use ksp_types::{
    AgentId, DOMAIN_POLICY_EDGE, OpaqueSecretId, PrincipalId, RecordVersion, VaultId, cbor,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::enrolment::{AdminSigningKey, EnrolmentSignature, VerifyingPublicKey};
use crate::fingerprint::KeyId;

/// The wire version of a policy edge.
pub const POLICY_EDGE_VERSION: u16 = 1;

/// The revision a newly created edge carries.
pub const FIRST_REVISION: u64 = 1;

/// The identifier of one policy edge.
///
/// 128 random bits as lowercase hex. Random rather than derived from the tuple, so
/// a withdrawn grant that is issued again is a **new** authority with a new id: a
/// token minted under the old id cannot come back into force by re-creating the
/// same tuple.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyId(String);

impl PolicyId {
    /// Mint a new identifier.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::fill(&mut bytes);
        let mut id = String::with_capacity(32);
        for byte in bytes {
            use fmt::Write;
            let _ = write!(id, "{byte:02x}");
        }
        Self(id)
    }

    /// Parse a canonical identifier.
    ///
    /// Canonical means exactly 32 lowercase hex characters. A hazard here is a
    /// caller that accepts a longer string: an id is a path segment, and a
    /// length-tolerant parser would let `../../policies` name a directory.
    ///
    /// [`PolicyEdge::decode`] applies this same rule to an artifact's own id. It has
    /// to: `PolicyId`'s `Deserialize` is derived from the `String`, so decoding does
    /// not call this function.
    pub fn parse(value: &str) -> Result<Self, EdgeRefusal> {
        let canonical = value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !canonical {
            return Err(EdgeRefusal::IdNotCanonical {
                value: value.to_string(),
            });
        }
        Ok(Self(value.to_string()))
    }

    /// The identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where one policy-bound record's plaintext lives.
///
/// A reference, not a key: the user who mints the token cannot open the
/// publication, so a policy-bound record's sealed map carries this instead of a
/// content key (FR-018). `publication` is kept as its canonical string because this
/// crate must not depend on the layout crate that parses it; the reader parses it
/// with the same parser that derives it, and a path that parser refuses is refused
/// by the reader (FR-036).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRecordRef {
    /// The policy whose entry the agent opens.
    pub policy_id: PolicyId,
    /// The publication path, as `PublicationPath::canonical` renders it.
    pub publication: String,
}

impl PolicyRecordRef {
    /// The policy id, re-parsed so a decoded id is held to the same canonical rule
    /// as a created one.
    ///
    /// `PolicyId`'s `Deserialize` is derived from its `String`, so a decoded
    /// reference could carry an id no writer would produce. The id is not a path
    /// segment here, but it selects the policy artifact, and a length-tolerant id
    /// would let one reference select another edge.
    pub fn policy(&self) -> Result<PolicyId, EdgeRefusal> {
        PolicyId::parse(self.policy_id.as_str())
    }
}

/// What an edge authorises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyTarget {
    /// Exactly one enrolled agent.
    Agent(AgentId),
    /// Any agent the user has enrolled.
    ///
    /// Cooperative by construction: the record is sealed to the user, so she can
    /// re-target it. The label says so in every read surface (FR-007).
    AnyEnrolled,
}

impl PolicyTarget {
    /// Parse one of the two accepted forms.
    ///
    /// The only accepted strings are an agent UUID and `any-enrolled`. Everything
    /// else — `*`, `agent-*`, `any`, a comma-separated list — is refused with a
    /// sentence that names both accepted forms, because a refusal that says only
    /// "invalid target" leaves the caller unable to derive one.
    pub fn parse(value: &str) -> Result<Self, EdgeRefusal> {
        if value == "any-enrolled" {
            return Ok(Self::AnyEnrolled);
        }
        if value == "any" || value == "*" || value.contains('*') || value.contains(',') {
            return Err(EdgeRefusal::TargetPattern {
                value: value.to_string(),
            });
        }
        AgentId::parse(value)
            .map(Self::Agent)
            .map_err(|_| EdgeRefusal::TargetPattern {
                value: value.to_string(),
            })
    }

    /// Whether this target names exactly one agent.
    pub fn agent(&self) -> Option<AgentId> {
        match self {
            Self::Agent(agent) => Some(*agent),
            Self::AnyEnrolled => None,
        }
    }

    /// The word a read surface prints for the mode.
    pub fn mode(&self) -> &'static str {
        match self {
            Self::Agent(_) => "cryptographic",
            Self::AnyEnrolled => "cooperative",
        }
    }
}

impl fmt::Display for PolicyTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Agent(agent) => write!(f, "agent:{agent}"),
            Self::AnyEnrolled => f.write_str("any-enrolled"),
        }
    }
}

/// The signed part of one edge.
///
/// Private fields and one constructor per lifecycle step: a caller cannot build a
/// body whose signature covers something other than what is checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEdgeBody {
    version: u16,
    id: PolicyId,
    revision: u64,
    vault: VaultId,
    user: PrincipalId,
    secret: OpaqueSecretId,
    record_version: RecordVersion,
    target: PolicyTarget,
    publication: Option<String>,
    not_before: u64,
    not_after: u64,
}

impl PolicyEdgeBody {
    /// The signed bytes.
    fn signing_preimage(&self) -> Result<Vec<u8>, EdgeRefusal> {
        let encoded = cbor::encode(self).map_err(|error| EdgeRefusal::Malformed {
            cause: error.to_string(),
        })?;
        let mut preimage = Vec::with_capacity(DOMAIN_POLICY_EDGE.len() + encoded.len());
        preimage.extend_from_slice(DOMAIN_POLICY_EDGE);
        preimage.extend_from_slice(&encoded);
        Ok(preimage)
    }

    /// The digest of the signed bytes, without the signature.
    fn digest(&self) -> Result<[u8; 32], EdgeRefusal> {
        let encoded = cbor::encode(self).map_err(|error| EdgeRefusal::Malformed {
            cause: error.to_string(),
        })?;
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_POLICY_EDGE);
        hasher.update(&encoded);
        Ok(hasher.finalize().into())
    }

    /// The edge identifier.
    pub fn id(&self) -> &PolicyId {
        &self.id
    }

    /// The revision.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// The vault.
    pub fn vault(&self) -> &VaultId {
        &self.vault
    }

    /// The user whose authority the edge carries.
    pub fn user(&self) -> &PrincipalId {
        &self.user
    }

    /// The secret identifier.
    pub fn secret(&self) -> &OpaqueSecretId {
        &self.secret
    }

    /// The record version the edge authorises.
    pub fn record_version(&self) -> RecordVersion {
        self.record_version
    }

    /// What the edge authorises.
    pub fn target(&self) -> PolicyTarget {
        self.target
    }

    /// The store path of the sealed publication, when there is one.
    pub fn publication(&self) -> Option<&str> {
        self.publication.as_deref()
    }

    /// When the edge starts to authorise.
    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    /// When it stops.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
}

/// One signed access edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEdge {
    body: PolicyEdgeBody,
    issuer_key_id: KeyId,
    issuer_signature: EnrolmentSignature,
}

/// The fields a caller supplies to create or update an edge.
///
/// One bundle rather than eight positional arguments: two adjacent `u64`s or two
/// `OpaqueSecretId`s swapped at a call site would compile, and a policy that names
/// the wrong version verifies perfectly.
#[derive(Debug, Clone)]
pub struct EdgeRequest {
    /// The user principal.
    pub user: PrincipalId,
    /// The secret identifier.
    pub secret: OpaqueSecretId,
    /// The record version.
    pub record_version: RecordVersion,
    /// The target.
    pub target: PolicyTarget,
    /// The publication path, once one exists.
    pub publication: Option<String>,
    /// Start of the validity window.
    pub not_before: u64,
    /// End of the validity window.
    pub not_after: u64,
}

impl PolicyEdge {
    /// Create an edge at revision 1 with a fresh id.
    pub fn create(
        admin: &AdminSigningKey,
        issuer_key_id: KeyId,
        vault: VaultId,
        request: EdgeRequest,
    ) -> Result<Self, EdgeRefusal> {
        Self::sign(
            admin,
            issuer_key_id,
            vault,
            PolicyId::generate(),
            FIRST_REVISION,
            request,
        )
    }

    /// Create an artifact under an identifier that already exists.
    ///
    /// Only two callers have one: the golden-fixture generator in the tests, and a
    /// ledger replay that re-issues an artifact from its recorded digest. A
    /// *re-grant* after a withdrawal must mint a new id, because a token minted
    /// under the old one would otherwise come back into force.
    #[doc(hidden)]
    pub fn create_at(
        admin: &AdminSigningKey,
        issuer_key_id: KeyId,
        vault: VaultId,
        id: PolicyId,
        revision: u64,
        request: EdgeRequest,
    ) -> Result<Self, EdgeRefusal> {
        Self::sign(admin, issuer_key_id, vault, id, revision, request)
    }

    /// Update an edge, signing `N+1` under the same id.
    ///
    /// The caller cannot choose the revision: it is derived from the artifact being
    /// replaced. An update that took the revision as an argument could be replayed
    /// backwards, which is misfit D.
    pub fn update(
        admin: &AdminSigningKey,
        issuer_key_id: KeyId,
        replaced: &PolicyEdge,
        request: EdgeRequest,
    ) -> Result<Self, EdgeRefusal> {
        let next = replaced
            .body
            .revision
            .checked_add(1)
            .ok_or(EdgeRefusal::RevisionOverflow {
                revision: replaced.body.revision,
            })?;
        // The vault and the id come from the artifact being replaced, never from the
        // caller: an update that could change either would make one identifier name
        // two authorities.
        Self::sign(
            admin,
            issuer_key_id,
            replaced.body.vault.clone(),
            replaced.body.id.clone(),
            next,
            request,
        )
    }

    fn sign(
        admin: &AdminSigningKey,
        issuer_key_id: KeyId,
        vault: VaultId,
        id: PolicyId,
        revision: u64,
        request: EdgeRequest,
    ) -> Result<Self, EdgeRefusal> {
        if revision == 0 {
            return Err(EdgeRefusal::RevisionNotPositive);
        }
        if request.not_after <= request.not_before {
            return Err(EdgeRefusal::ValidityInterval {
                not_before: request.not_before,
                not_after: request.not_after,
            });
        }
        let body = PolicyEdgeBody {
            version: POLICY_EDGE_VERSION,
            id,
            revision,
            vault,
            user: request.user,
            secret: request.secret,
            record_version: request.record_version,
            target: request.target,
            publication: request.publication,
            not_before: request.not_before,
            not_after: request.not_after,
        };
        let signature = admin.sign_bytes(&body.signing_preimage()?);
        Ok(Self {
            body,
            issuer_key_id,
            issuer_signature: signature,
        })
    }

    /// The signed body.
    pub fn body(&self) -> &PolicyEdgeBody {
        &self.body
    }

    /// The identifier.
    pub fn id(&self) -> &PolicyId {
        self.body.id()
    }

    /// The revision.
    pub fn revision(&self) -> u64 {
        self.body.revision()
    }

    /// The vault the edge governs.
    pub fn vault(&self) -> &VaultId {
        self.body.vault()
    }

    /// The user.
    pub fn user(&self) -> &PrincipalId {
        self.body.user()
    }

    /// The secret.
    pub fn secret(&self) -> &OpaqueSecretId {
        self.body.secret()
    }

    /// The record version.
    pub fn record_version(&self) -> RecordVersion {
        self.body.record_version()
    }

    /// The target.
    pub fn target(&self) -> PolicyTarget {
        self.body.target()
    }

    /// The ID of the key that signed the edge.
    pub fn issuer_key_id(&self) -> &KeyId {
        &self.issuer_key_id
    }

    /// The issuer's signature.
    pub fn issuer_signature(&self) -> &EnrolmentSignature {
        &self.issuer_signature
    }

    /// Whether the signature verifies against `anchor`.
    pub fn verify_issuer(&self, anchor: &VerifyingPublicKey) -> bool {
        let Ok(preimage) = self.body.signing_preimage() else {
            return false;
        };
        anchor.verify(&preimage, &self.issuer_signature.to_bytes())
    }

    /// The digest the ledger records beside the revision.
    pub fn digest(&self) -> Result<[u8; 32], EdgeRefusal> {
        self.body.digest()
    }

    /// Whether two edges claim the same active tuple.
    ///
    /// The tuple is `(user, secret, record version, target)`. Two active edges for
    /// one tuple are two authorities for one access, and withdrawing one of them
    /// would read as a withdrawal of the access while the other still granted it
    /// (misfit B).
    pub fn same_active_tuple(&self, other: &Self) -> bool {
        self.body.user == other.body.user
            && self.body.secret == other.body.secret
            && self.body.record_version == other.body.record_version
            && self.body.target == other.body.target
    }

    /// The canonical bytes of the signed body.
    ///
    /// The ledger records the digest of these bytes, and the golden fixture pins
    /// them; exposing them keeps both from re-encoding the body a different way.
    pub fn body_bytes(&self) -> Result<Vec<u8>, EdgeRefusal> {
        cbor::encode(&self.body).map_err(|error| EdgeRefusal::Malformed {
            cause: error.to_string(),
        })
    }

    /// Encode the artifact for the store.
    pub fn encode(&self) -> Result<Vec<u8>, EdgeRefusal> {
        cbor::encode(self).map_err(|error| EdgeRefusal::Malformed {
            cause: error.to_string(),
        })
    }

    /// Decode an artifact, refusing bytes that are not one.
    pub fn decode(bytes: &[u8]) -> Result<Self, EdgeRefusal> {
        let edge: Self = cbor::decode(bytes).map_err(|error| EdgeRefusal::Malformed {
            cause: error.to_string(),
        })?;
        if edge.body.version != POLICY_EDGE_VERSION {
            return Err(EdgeRefusal::UnknownVersion {
                version: edge.body.version,
            });
        }
        // The derived `Deserialize` bypasses `PolicyId::parse`, and this identifier
        // names a file that `EdgeStore::publish` builds from the body. An artifact
        // that decoded an unchecked id would let a re-sign write outside the policy
        // directory.
        if PolicyId::parse(edge.body.id.as_str()).is_err() {
            return Err(EdgeRefusal::IdNotCanonical {
                value: edge.body.id.as_str().to_string(),
            });
        }
        Ok(edge)
    }
}

/// Resolving the links an edge names.
///
/// A trait rather than three closures because the three checks fail differently and
/// each has its own sentence; bundling them keeps "who exists" in one place, which
/// is what makes a dangling edge impossible rather than merely discouraged
/// (misfit G).
pub trait LinkCheck {
    /// Whether the user principal belongs to this deployment.
    fn user_exists(&self, user: &PrincipalId) -> bool;
    /// Whether the agent principal is enrolled.
    fn agent_exists(&self, agent: AgentId) -> bool;
    /// Whether the secret has this version stored.
    fn secret_version_exists(&self, secret: &OpaqueSecretId, version: RecordVersion) -> bool;
}

/// Refuse an edge whose links do not resolve.
///
/// The refusal names **which** link is missing and the accepted form of the value
/// that would satisfy it, because "unknown link" leaves an operator guessing which
/// of three values was wrong.
pub fn check_links<C: LinkCheck>(check: &C, body: &PolicyEdgeBody) -> Result<(), EdgeRefusal> {
    if !check.user_exists(&body.user) {
        return Err(EdgeRefusal::DanglingUser {
            principal: body.user,
        });
    }
    if let Some(agent) = body.target.agent()
        && !check.agent_exists(agent)
    {
        return Err(EdgeRefusal::DanglingAgent { agent });
    }
    if !check.secret_version_exists(&body.secret, body.record_version) {
        return Err(EdgeRefusal::DanglingSecretVersion {
            secret: body.secret.clone(),
            version: body.record_version,
        });
    }
    Ok(())
}

/// Why an edge could not be built, signed or accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EdgeRefusal {
    /// The bytes are not an edge this build wrote.
    #[error("the policy edge could not be encoded or decoded: {cause}")]
    Malformed {
        /// The encoder's or decoder's own words.
        cause: String,
    },
    /// The artifact carries a version this build does not produce.
    #[error("the policy edge names format version {version}, which this build does not know")]
    UnknownVersion {
        /// The version in the artifact.
        version: u16,
    },
    /// An identifier that is not 32 lowercase hex characters.
    #[error(
        "the policy identifier {value} is not canonical: it is exactly 32 lowercase hexadecimal characters, and anything else is refused because an identifier names a path"
    )]
    IdNotCanonical {
        /// The value that was given.
        value: String,
    },
    /// A target that is a pattern, a list or a spelling that does not exist.
    #[error(
        "the target {value} is not a target: the two accepted forms are a single agent UUID, or any-enrolled; there is no wildcard, prefix or list because a target that names several agents grants more than the admin chose"
    )]
    TargetPattern {
        /// The value that was given.
        value: String,
    },
    /// A zero revision, or an update that does not advance.
    #[error("a policy edge revision starts at 1 and only ever advances; 0 is not a revision")]
    RevisionNotPositive,
    /// An update that would wrap the revision counter.
    #[error("the revision {revision} cannot be advanced: the counter is at its limit")]
    RevisionOverflow {
        /// The revision that could not be advanced.
        revision: u64,
    },
    /// A validity window that ends before it starts.
    #[error(
        "the validity window ends at {not_after} and starts at {not_before}: an edge that expires before it begins authorises nothing, which reads as a clock problem"
    )]
    ValidityInterval {
        /// Start.
        not_before: u64,
        /// End.
        not_after: u64,
    },
    /// The user is not a member of the deployment.
    #[error(
        "the policy edge names user {principal}, which this deployment does not hold: enrol her first, and the accepted form is a principal UUID from the registry"
    )]
    DanglingUser {
        /// The principal that was named.
        principal: PrincipalId,
    },
    /// The agent is not enrolled.
    #[error(
        "the policy edge names agent {agent}, which is not enrolled on this host: enrol it first, and the accepted form is the agent's principal UUID"
    )]
    DanglingAgent {
        /// The agent that was named.
        agent: AgentId,
    },
    /// The secret version is absent.
    #[error(
        "the policy edge names secret {secret} at version {version}, and that version is not stored: store it first, and the accepted form is an existing version number"
    )]
    DanglingSecretVersion {
        /// The secret identifier.
        secret: OpaqueSecretId,
        /// The version that was named.
        version: RecordVersion,
    },
    /// Another active edge already holds this tuple.
    #[error(
        "the tuple is already granted by policy {existing}: withdraw that edge before granting the same access again, and a re-grant after withdrawal mints a new identifier"
    )]
    SecondActive {
        /// The edge that already holds the tuple.
        existing: PolicyId,
    },
}

// ---------------------------------------------------------------------------
// The lifecycle record: what the admin did, and the swap that guards a revision
// ---------------------------------------------------------------------------

/// What a lifecycle entry records having happened.
///
/// Three actions, one file: a `create`, an `update` and a `withdrawal` are the same
/// kind of fact — a signed revision that changed who may read what — so they share a
/// shape and one writer. A separate file per action would be three files to keep in
/// step and three writes that can disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyAction {
    /// A policy gained its first revision.
    Created,
    /// A policy gained a narrower revision.
    Updated,
    /// A policy was replaced by a revision that grants nothing further.
    Withdrawn,
}

impl PolicyAction {
    /// The action as it appears in the ledger and in a report.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Updated => "updated",
            Self::Withdrawn => "withdrawn",
        }
    }
}

/// One policy decision, recorded before it is acted on.
///
/// The fields are the signed edge's own facts plus who decided and when — nothing is
/// re-derived here, because a second derivation is a second answer. `digest` is the
/// digest of the **signed bytes**, so an entry can only be built from an edge that
/// carries a signature over exactly those bytes: the ledger and the artifact name one
/// another, and a reader holding one can tell whether the other is the same decision.
///
/// There is no signature field. The signature lives on the edge, and this record
/// binds to it by digest rather than duplicating it: two signatures over one decision
/// would be two things to verify and one of them would be optional.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyLedgerEntry {
    /// The policy this decision is about.
    pub policy: PolicyId,
    /// The revision the decision produced.
    pub revision: u64,
    /// The digest of the revision's signed bytes.
    pub digest: [u8; 32],
    /// What happened.
    pub action: PolicyAction,
    /// The principal that decided. The admin, for every action.
    pub actor: PrincipalId,
    /// When it was recorded, in Unix seconds.
    pub at: i64,
    /// The vault the policy belongs to.
    pub vault: VaultId,
    /// The principal the policy grants to.
    pub user: PrincipalId,
    /// The secret the policy names.
    pub secret: OpaqueSecretId,
    /// The record version the policy names.
    pub record_version: RecordVersion,
    /// The publication the policy sends a recipient to, when it has one.
    pub publication: Option<String>,
}

impl PolicyLedgerEntry {
    /// The entry for one signed edge.
    ///
    /// Takes the signed edge rather than its fields: a caller that could assemble an
    /// entry from loose values could record a digest over bytes no signature covers,
    /// and the ledger would then attest to a decision nobody made.
    pub fn for_edge(
        edge: &PolicyEdge,
        action: PolicyAction,
        actor: PrincipalId,
        at: i64,
    ) -> Result<Self, EdgeRefusal> {
        let body = edge.body();
        Ok(Self {
            policy: body.id().clone(),
            revision: body.revision(),
            digest: edge.digest()?,
            action,
            actor,
            at,
            vault: body.vault().clone(),
            user: *body.user(),
            secret: body.secret().clone(),
            record_version: body.record_version(),
            publication: body.publication().map(str::to_string),
        })
    }

    /// Whether two entries record the same decision.
    ///
    /// The second the clock reports is not part of the decision: a retry after a crash
    /// produces the same policy, revision and action, and only the timestamp moved.
    pub fn same_decision(&self, other: &Self) -> bool {
        self.policy == other.policy
            && self.revision == other.revision
            && self.action == other.action
            && self.digest == other.digest
    }
}

/// The recorded head of one policy: the revision in force and its digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevisionHead {
    /// The highest revision recorded for the policy.
    pub revision: u64,
    /// The digest recorded with it.
    pub digest: [u8; 32],
}

/// What the guard decided about a candidate entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevisionDecision {
    /// The candidate is a new, later revision: append it.
    Apply,
    /// The identical decision is already recorded: change nothing.
    AlreadyRecorded,
}

/// Why a candidate revision may not be written.
///
/// Each variant names the recorded value, because the caller's next question is what
/// the ledger says, not what it refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RevisionRefusal {
    /// The candidate is not strictly greater than the revision in force.
    #[error("policy revision {candidate} is not later than the recorded revision {recorded}")]
    Stale {
        /// The revision in force.
        recorded: u64,
        /// The revision the caller tried to write.
        candidate: u64,
    },
    /// The candidate reuses the recorded revision with different bytes.
    #[error(
        "policy revision {revision} is already recorded with a different digest; a recorded revision cannot be rewritten"
    )]
    DigestMismatch {
        /// The revision both the record and the candidate name.
        revision: u64,
    },
}

/// Compare a candidate entry with the recorded head, and decide.
///
/// The rule is one sentence: a write is accepted only when its revision is strictly
/// greater than the revision in force. Everything else is a refusal with the recorded
/// value in it — a regression, a rewrite of a signed revision, or a replay.
///
/// An identical decision is not a refusal but a no-op: a retried withdrawal after a
/// crash has to complete without a second entry, and calling that a conflict would
/// make the retry path refuse the very case it exists for.
pub fn guard(
    recorded: Option<&RevisionHead>,
    candidate: &PolicyLedgerEntry,
) -> Result<RevisionDecision, RevisionRefusal> {
    let Some(recorded) = recorded else {
        return Ok(RevisionDecision::Apply);
    };
    if candidate.revision > recorded.revision {
        return Ok(RevisionDecision::Apply);
    }
    if candidate.revision == recorded.revision {
        return if candidate.digest == recorded.digest {
            Ok(RevisionDecision::AlreadyRecorded)
        } else {
            Err(RevisionRefusal::DigestMismatch {
                revision: candidate.revision,
            })
        };
    }
    Err(RevisionRefusal::Stale {
        recorded: recorded.revision,
        candidate: candidate.revision,
    })
}
