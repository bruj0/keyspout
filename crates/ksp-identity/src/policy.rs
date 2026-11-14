//! The policy, its verification, and the outcomes a caller must handle.
//!
//! # The misfit this resolves
//!
//! Misfit H: a key that appears inside the artifact under verification is
//! **data, never an anchor**. A verifier that reads "the issuer's public key"
//! out of the thing it is verifying has verified nothing — an attacker signs
//! with their own key and names it in the artifact.
//!
//! The fix is structural. [`TrustAnchors`] is a host-local map from key ID to
//! public key, filled at provisioning. A policy supplies only an
//! `issuer_key_id`; that ID is *looked up* in the pinned map. There is no
//! function anywhere in this module that accepts a verifying key taken from a
//! policy, a token or a store.
//!
//! Misfit N is the checkpoint's: a replayed older policy is validly signed, so
//! only a [`TrustedCheckpoint`] can refuse
//! it, and with no checkpoint the outcome says freshness is unavailable.
//!
//! # Every field is checked
//!
//! FR-046 lists eleven things a policy can be wrong about. Each one has its own
//! [`PolicyRefusal`] variant naming the field, because a refusal that says only
//! "invalid policy" leaves an operator unable to tell a clock skew from a
//! substituted vault.
//!
//! A *malformed* policy is a different outcome from a *rejected* one:
//! [`PolicyRefusal::Malformed`] means the bytes were not a policy, while the
//! named variants mean they were a well-formed policy that this host will not
//! act on.

use std::collections::BTreeMap;
use std::fmt;

use ksp_types::{
    ActorId, AgentId, BoundMetadata, Level, OpaqueSecretId, PrincipalId, RecordVersion, VaultId,
    cbor,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::checkpoint::{CheckpointStore, TrustedCheckpoint};
use crate::enrolment::{
    AdminSigningKey, EnrolmentSignature, RecipientPublicKey, VerifyingPublicKey,
};
use crate::fingerprint::KeyId;

/// The wire format version of a policy.
pub const POLICY_VERSION: u16 = 1;

/// The version of the policy *body* that the fingerprint and the signature cover.
///
/// Separate from [`POLICY_VERSION`] only in name: both move together when the
/// body's field set changes, and the value is inside the signed bytes so an old
/// and a new policy are never silently comparable.
const POLICY_BODY_VERSION: u16 = 1;

/// The keys a policy trusts for one user's enrolment.
///
/// Both public keys and both key IDs, because the fingerprint binds all four and
/// a policy that pinned only the keys would leave the IDs free to be swapped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedEnrolmentKeys {
    /// The user's Ed25519 signing public key.
    pub signing_key: VerifyingPublicKey,
    /// The user's X25519 recipient public key.
    pub recipient_key: RecipientPublicKey,
    /// The ID naming the signing key.
    pub signing_key_id: KeyId,
    /// The ID naming the recipient key.
    pub recipient_key_id: KeyId,
}

/// A user's authority to share, as signed by the admin.
///
/// The fields are private and the only constructor is [`Policy::new`], which
/// computes the revision-carrying body itself, so a caller cannot build a policy
/// whose signature covers something other than what is checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    body: PolicyBody,
    issuer_key_id: KeyId,
    issuer_signature: EnrolmentSignature,
}

/// The signed part of a policy.
///
/// A fixed-order struct, never a map: `ksp_types::cbor` documents that a map has
/// no guaranteed byte representation, and the signature is over exactly these
/// bytes. The order below is the wire order, and `tests/fixtures/policy-body.cbor`
/// pins it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBody {
    version: u16,
    revision: u64,
    vault: VaultId,
    user: PrincipalId,
    trusted: TrustedEnrolmentKeys,
    shareable_secrets: Vec<OpaqueSecretId>,
    shareable_agents: Vec<AgentId>,
    max_user_ttl_secs: u64,
    max_agent_ttl_secs: u64,
    not_before: u64,
    not_after: u64,
}

impl PolicyBody {
    /// Collect the signed fields of a policy.
    ///
    /// The version is set here, not by the caller: a body whose version a caller
    /// chose could claim a format this build does not produce.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        revision: u64,
        vault: VaultId,
        user: PrincipalId,
        trusted: TrustedEnrolmentKeys,
        shareable_secrets: Vec<OpaqueSecretId>,
        shareable_agents: Vec<AgentId>,
        max_user_ttl_secs: u64,
        max_agent_ttl_secs: u64,
        not_before: u64,
        not_after: u64,
    ) -> Self {
        Self {
            version: POLICY_BODY_VERSION,
            revision,
            vault,
            user,
            trusted,
            shareable_secrets,
            shareable_agents,
            max_user_ttl_secs,
            max_agent_ttl_secs,
            not_before,
            not_after,
        }
    }

    /// The format version the body was built at.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// The monotonic revision.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// When the policy becomes valid.
    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    /// When the policy expires.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// The canonical bytes the admin signs.
    fn signing_preimage(&self) -> Result<Vec<u8>, PolicyRefusal> {
        let encoded = cbor::encode(self).map_err(|err| PolicyRefusal::Malformed {
            cause: err.to_string(),
        })?;
        let mut preimage = Vec::with_capacity(ksp_types::DOMAIN_POLICY.len() + encoded.len());
        preimage.extend_from_slice(ksp_types::DOMAIN_POLICY);
        preimage.extend_from_slice(&encoded);
        Ok(preimage)
    }

    /// The digest a `TrustedCheckpoint` records alongside the revision.
    ///
    /// Over the body only, so the digest does not change when the same body is
    /// re-signed by the same issuer.
    fn digest(&self) -> Result<[u8; 32], PolicyRefusal> {
        let encoded = cbor::encode(self).map_err(|err| PolicyRefusal::Malformed {
            cause: err.to_string(),
        })?;
        let mut hasher = Sha256::new();
        hasher.update(ksp_types::DOMAIN_POLICY);
        hasher.update(&encoded);
        Ok(hasher.finalize().into())
    }
}

impl Policy {
    /// Build and sign a policy.
    ///
    /// The admin signs; nothing here can be signed by the user the policy is
    /// about, because an authority that can be widened by its subject is not an
    /// authority.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admin: &crate::enrolment::AdminSigningKey,
        issuer_key_id: KeyId,
        body: PolicyBody,
    ) -> Result<Self, PolicyRefusal> {
        // A policy that expires before it starts denies everything at runtime
        // and reads like a clock problem. Refuse it where the mistake was made,
        // before it is signed and distributed.
        if body.not_after <= body.not_before {
            return Err(PolicyRefusal::ValidityInterval {
                not_before: body.not_before,
                not_after: body.not_after,
            });
        }

        let signature = admin.sign_bytes(&body.signing_preimage()?);
        Ok(Self {
            body,
            issuer_key_id,
            issuer_signature: signature,
        })
    }

    /// The signed body.
    pub fn body(&self) -> &PolicyBody {
        &self.body
    }

    /// The ID of the admin key that signed this policy.
    ///
    /// An ID, never a key: this is the only thing a policy is allowed to say
    /// about its issuer, and it is looked up in [`TrustAnchors`].
    pub fn issuer_key_id(&self) -> &KeyId {
        &self.issuer_key_id
    }

    /// The admin's signature over the body.
    pub fn issuer_signature(&self) -> &EnrolmentSignature {
        &self.issuer_signature
    }

    /// The monotonic revision.
    pub fn revision(&self) -> u64 {
        self.body.revision
    }

    /// The vault this policy governs.
    pub fn vault(&self) -> &VaultId {
        &self.body.vault
    }

    /// The user this policy is about.
    pub fn user(&self) -> &PrincipalId {
        &self.body.user
    }

    /// The enrolment keys the policy trusts.
    pub fn trusted(&self) -> &TrustedEnrolmentKeys {
        &self.body.trusted
    }

    /// The `user`-level secrets that may be shared.
    pub fn shareable_secrets(&self) -> &[OpaqueSecretId] {
        &self.body.shareable_secrets
    }

    /// The agents a `user`-level secret may be shared with.
    pub fn shareable_agents(&self) -> &[AgentId] {
        &self.body.shareable_agents
    }

    /// Whether this policy trusts exactly this enrolment for its user.
    ///
    /// The policy binds the user's enrolment keys; this is the one place that
    /// compares them against an actual record. Without a reader the field would
    /// be a claim the struct makes and the code never keeps, and a mint that
    /// sealed to whatever recipient key the store happened to hold would look
    /// authorised when nothing had checked it.
    pub fn trusts(&self, record: &crate::enrolment::EnrollmentRecord) -> bool {
        let identity = ActorId::User(self.body.user);
        record.identity() == &identity
            && record.signing_key() == &self.body.trusted.signing_key
            && record.recipient_key() == &self.body.trusted.recipient_key
            && record.enrolment().signing_key_id() == &self.body.trusted.signing_key_id
            && record.enrolment().recipient_key_id() == &self.body.trusted.recipient_key_id
    }

    /// Whether the issuer's signature verifies against `anchor`.
    pub fn verify_issuer(&self, anchor: &VerifyingPublicKey) -> bool {
        let Ok(preimage) = self.body.signing_preimage() else {
            return false;
        };
        anchor.verify(&preimage, &self.issuer_signature.to_bytes())
    }

    /// The digest a checkpoint records alongside the revision.
    pub fn digest(&self) -> Result<[u8; 32], PolicyRefusal> {
        self.body.digest()
    }

    /// Whether this policy grants `secret` to `agent`.
    ///
    /// The same two membership checks [`PolicyVerifier`] makes, exposed for a
    /// caller that has no [`PolicyRequest`]: a run holds a delivery token, not a
    /// mint request, so it cannot build one. Both must be present — a policy that
    /// lists the secret but not the agent grants nothing, and the reverse is the
    /// same.
    pub fn grants(&self, secret: &OpaqueSecretId, agent: &AgentId) -> bool {
        self.body.shareable_secrets.contains(secret) && self.body.shareable_agents.contains(agent)
    }

    /// The bound on a lease written at `target`.
    ///
    /// `max_agent_ttl` bounds a copy at an agent level; `max_user_ttl` bounds
    /// everything else, which is the user's own level and the admin level. The
    /// two numbers are separate because an agent's lease is the one an
    /// unattended process holds, and a host may want that shorter.
    pub fn max_ttl_for(&self, target: &Level) -> u64 {
        match target {
            Level::Agent(_) => self.body.max_agent_ttl_secs,
            Level::Admin | Level::User => self.body.max_user_ttl_secs,
        }
    }

    /// Refuse a lease longer than the policy allows for `target`.
    pub fn check_ttl(&self, target: &Level, requested_secs: u64) -> Result<(), PolicyRefusal> {
        let bound = self.max_ttl_for(target);
        if requested_secs > bound {
            return Err(match target {
                Level::Agent(_) => PolicyRefusal::MaxAgentTtl {
                    max: bound,
                    requested: requested_secs,
                },
                Level::Admin | Level::User => PolicyRefusal::MaxUserTtl {
                    max: bound,
                    requested: requested_secs,
                },
            });
        }
        Ok(())
    }

    /// Whether this policy's validity interval contains `at`.
    pub fn check_validity(&self, at: u64) -> Result<(), PolicyRefusal> {
        if at < self.body.not_before {
            return Err(PolicyRefusal::NotYetValid {
                at,
                not_before: self.body.not_before,
            });
        }
        if at > self.body.not_after {
            return Err(PolicyRefusal::Expired {
                at,
                not_after: self.body.not_after,
            });
        }
        Ok(())
    }

    /// The next revision, with one grant removed and the same admin's signature.
    ///
    /// The revision is built from *this* policy's own fields rather than from
    /// anything a caller supplies: the caller chooses one grant to remove, and a
    /// hostile or careless caller cannot use a withdrawal to widen anything —
    /// there is no argument that could add a grant, raise a TTL or move the
    /// validity window.
    pub fn withdraw(
        &self,
        admin: &AdminSigningKey,
        withdrawal: &Withdrawal,
    ) -> Result<Self, PolicyRefusal> {
        let revision = self
            .body
            .revision
            .checked_add(1)
            .ok_or(PolicyRefusal::RevisionExhausted)?;

        let mut secrets = self.body.shareable_secrets.clone();
        let mut agents = self.body.shareable_agents.clone();
        match withdrawal {
            Withdrawal::Secret(secret) => {
                let granted = secrets.iter().any(|held| held == secret);
                if !granted {
                    return Err(PolicyRefusal::GrantNotPresent {
                        grant: withdrawal.to_string(),
                    });
                }
                secrets.retain(|held| held != secret);
            }
            Withdrawal::Agent(agent) => {
                let granted = agents.iter().any(|held| held == agent);
                if !granted {
                    return Err(PolicyRefusal::GrantNotPresent {
                        grant: withdrawal.to_string(),
                    });
                }
                agents.retain(|held| held != agent);
            }
        }

        let body = PolicyBody::new(
            revision,
            self.body.vault.clone(),
            self.body.user,
            self.body.trusted.clone(),
            secrets,
            agents,
            self.body.max_user_ttl_secs,
            self.body.max_agent_ttl_secs,
            self.body.not_before,
            self.body.not_after,
        );
        Self::new(admin, self.issuer_key_id.clone(), body)
    }
}

/// What one mint or delivery is asking the policy to authorise.
///
/// It names the vault, the user, the level pair, the secret, the agent, the
/// record path the delivery will be written at, the scope the delivery claims,
/// the lease it wants and the record version it will publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRequest {
    /// The vault the record lives in.
    pub vault: VaultId,
    /// The user whose authority is being exercised.
    pub user: PrincipalId,
    /// The level the copy is read from.
    pub source: Level,
    /// The level the copy is written at.
    pub target: Level,
    /// The `user`-level secret being shared.
    pub secret: OpaqueSecretId,
    /// The agent receiving the copy.
    pub agent: AgentId,
    /// The path the delivery will be published at.
    pub path: String,
    /// The scope the delivery names.
    ///
    /// For a share it is the target level's path segment; it is checked against
    /// `target` so a delivery cannot state one scope and write at another.
    pub scope: String,
    /// The lease the caller wants, in seconds.
    pub requested_ttl_secs: u64,
    /// The record version the caller intends to publish.
    ///
    /// A version of 0 does not exist: `RecordVersion::FIRST` is 1, so a zero
    /// here is a caller that never picked a version.
    pub record_version: RecordVersion,
}

impl PolicyRequest {
    /// The canonical record path for this request.
    ///
    /// `p/<vault>/<user>/<level>/<opaque-secret-id>/<version>`, the layout
    /// FR-013 fixes. Built here rather than accepted from the caller, so the
    /// path check compares the request against the layout rather than against
    /// itself.
    pub fn expected_path(&self) -> String {
        ksp_record::RecordPath::of(&BoundMetadata {
            vault_id: self.vault.clone(),
            user_id: self.user,
            level: self.target.clone(),
            secret_id: self.secret.clone(),
            version: self.record_version.get(),
        })
        .to_string()
    }
}

/// The keys this host will accept a policy from.
///
/// Filled at provisioning from a channel that is not the store, and keyed by the
/// ID a policy names. This is the whole of Misfit H's fix: the policy supplies an
/// ID, the host supplies the key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustAnchors {
    anchors: BTreeMap<KeyId, VerifyingPublicKey>,
}

impl TrustAnchors {
    /// No anchors: every policy is refused, because nothing can be verified.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin an admin key under the ID a policy will name.
    pub fn pin(&mut self, key_id: KeyId, key: VerifyingPublicKey) {
        self.anchors.insert(key_id, key);
    }

    /// The pinned key for an ID, if this host pinned one.
    pub fn get(&self, key_id: &KeyId) -> Option<&VerifyingPublicKey> {
        self.anchors.get(key_id)
    }

    /// How many anchors are pinned.
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether nothing is pinned.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

/// Why a policy was not acted on.
///
/// Every variant except [`Malformed`](Self::Malformed) names the field that
/// disagreed, because an operator reading "invalid policy" cannot tell a
/// substituted vault from a clock skew.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyRefusal {
    /// The bytes were not a policy at all.
    #[error("the policy could not be decoded: {cause}")]
    Malformed {
        /// The decoder's reason.
        cause: String,
    },
    /// The policy is a format version this build does not understand.
    #[error("the policy is format version {found}, this build understands {expected}")]
    UnsupportedVersion {
        /// The version the policy declares.
        found: u16,
        /// The version this build understands.
        expected: u16,
    },
    /// The policy names an issuer key this host never pinned.
    #[error("the policy names issuer {presented}, which this host has not pinned")]
    IssuerNotPinned {
        /// The ID the policy named.
        presented: String,
    },
    /// The pinned issuer's key did not verify the signature.
    #[error("the policy signature did not verify against the pinned issuer {issuer}")]
    IssuerSignature {
        /// The ID whose key was tried.
        issuer: String,
    },
    /// The revision is below the trusted checkpoint.
    #[error("policy revision {presented} is below the trusted checkpoint {checkpoint}: a rollback")]
    Rollback {
        /// The revision the policy claims.
        presented: u64,
        /// The highest revision already accepted.
        checkpoint: u64,
    },
    /// The policy governs a different vault.
    #[error("the policy governs vault {expected}, the request names {found}")]
    Vault {
        /// What the policy says.
        expected: String,
        /// What the request says.
        found: String,
    },
    /// The policy is about a different user.
    #[error("the policy is for user {expected}, the request names {found}")]
    User {
        /// What the policy says.
        expected: String,
        /// What the request says.
        found: String,
    },
    /// The source/target level pair is not a share this system performs.
    #[error("the level pair {from_level} -> {to_level} is not an allowed share")]
    LevelPair {
        /// The level the copy would be read from.
        from_level: String,
        /// The level the copy would be written at.
        to_level: String,
    },
    /// The secret is not in the policy's shareable set.
    #[error("secret {secret} is not shareable under this policy")]
    SecretGrant {
        /// The secret the request named.
        secret: String,
    },
    /// The agent is not in the policy's shareable set.
    #[error("agent {agent} is not an allowed recipient under this policy")]
    AgentGrant {
        /// The agent the request named.
        agent: String,
    },
    /// The delivery is written at a level that is not the granted agent's.
    ///
    /// A grant names an agent; the level a copy is written at must be that same
    /// agent's. Otherwise a grant for one agent would authorise a delivery to
    /// another, because the level pair check only asks whether the target is
    /// *some* agent level.
    #[error("the delivery is written at agent-{target} but the grant names agent-{granted}")]
    TargetLevel {
        /// The agent the grant names.
        granted: String,
        /// The agent whose level the copy would be written at.
        target: String,
    },
    /// The request is for a scope that is not the target level.
    #[error("the delivery names scope {found}, the target level is {expected}")]
    Scope {
        /// The scope the target level implies.
        expected: String,
        /// The scope the request named.
        found: String,
    },
    /// The request would publish at a path the layout does not produce.
    #[error(
        "the delivery names path {found}, the request's own level, secret and version give {expected}"
    )]
    Path {
        /// The path the layout produces.
        expected: String,
        /// The path the request named.
        found: String,
    },
    /// The validity interval does not contain any instant.
    #[error("the policy's validity interval ends at {not_after} but starts at {not_before}")]
    ValidityInterval {
        /// When the policy would become valid.
        not_before: u64,
        /// When the policy would expire.
        not_after: u64,
    },
    /// The record version is not a version this system produces.
    #[error("record version {found} is not a version this system publishes")]
    Version {
        /// The version the request named.
        found: u32,
    },
    /// The policy is not valid yet.
    #[error("the policy is not valid until {not_before}, the check was at {at}")]
    NotYetValid {
        /// When the check happened.
        at: u64,
        /// When the policy becomes valid.
        not_before: u64,
    },
    /// The policy has expired.
    #[error("the policy expired at {not_after}, the check was at {at}")]
    Expired {
        /// When the check happened.
        at: u64,
        /// When the policy expired.
        not_after: u64,
    },
    /// The requested lease is longer than the policy allows at `user`.
    #[error("a lease of {requested}s exceeds the user maximum of {max}s")]
    MaxUserTtl {
        /// The policy's bound.
        max: u64,
        /// The lease the request asked for.
        requested: u64,
    },
    /// The requested lease is longer than the policy allows at an agent level.
    #[error("a lease of {requested}s exceeds the agent maximum of {max}s")]
    MaxAgentTtl {
        /// The policy's bound.
        max: u64,
        /// The lease the request asked for.
        requested: u64,
    },
    /// The withdrawal names a grant this policy does not make.
    ///
    /// Refused rather than folded into a no-op revision: a revision number that
    /// advances while the grant set does not would tell every host holding it
    /// that something changed when nothing did.
    #[error("this policy does not grant {grant}, so there is nothing to withdraw")]
    GrantNotPresent {
        /// The grant the withdrawal named.
        grant: String,
    },
    /// The revision cannot advance.
    #[error("the policy is already at the highest revision")]
    RevisionExhausted,
}

/// One grant an admin can remove from a policy.
///
/// The same two shapes the policy grants: which `user`-level secrets may be
/// shared, and with which agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Withdrawal {
    /// This `user`-level secret may no longer be shared with any agent.
    Secret(OpaqueSecretId),
    /// No `user`-level secret may be shared with this agent.
    Agent(AgentId),
}

impl fmt::Display for Withdrawal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secret(secret) => write!(f, "secret {secret}"),
            Self::Agent(agent) => write!(f, "agent {agent}"),
        }
    }
}

/// How much rollback protection the answer actually has.
///
/// A separate type rather than a `bool` on a success value, because "verified,
/// but a replay would not have been detected" is a different operational fact
/// from "verified, and a replay would have been refused".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// The policy was checked against this checkpoint and is at or above it.
    Checked {
        /// The revision this host had already accepted.
        checkpoint: u64,
    },
    /// This host holds no checkpoint, so a replayed older policy could not have
    /// been detected. It is not implied that freshness was satisfied.
    Unavailable,
}

/// The result of verifying a policy.
///
/// [`Fresh][Self::Fresh]` and [`Stale][Self::Stale`] are separate arms on
/// purpose: a caller that matches only on `Fresh`/`Refused` fails to compile, so
/// the no-checkpoint case cannot be inherited by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationOutcome {
    /// Verified, and rollback detection was in force.
    Fresh {
        /// The revision that was accepted.
        revision: u64,
        /// What the checkpoint knew.
        freshness: Freshness,
    },
    /// Verified, but this host holds no checkpoint: a replayed older policy
    /// would also have verified.
    Stale {
        /// The revision that was accepted.
        revision: u64,
        /// Always [`Freshness::Unavailable`], named so the caller reads it.
        freshness: Freshness,
    },
    /// Not acted on.
    Refused(PolicyRefusal),
}

impl VerificationOutcome {
    /// Whether the policy was verified, whatever its freshness.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Fresh { .. } | Self::Stale { .. })
    }

    /// The freshness the outcome carries, if it verified.
    pub fn freshness(&self) -> Option<Freshness> {
        match self {
            Self::Fresh { freshness, .. } | Self::Stale { freshness, .. } => Some(*freshness),
            Self::Refused(_) => None,
        }
    }
}

/// Verifies policies against a pinned anchor and a host's trusted checkpoint.
///
/// The anchor set is fixed at construction. There is no setter, and no method
/// takes a verifying key from a policy, so an attacker who controls the store
/// cannot introduce an anchor.
pub struct PolicyVerifier {
    anchors: TrustAnchors,
    checkpoint: Option<TrustedCheckpoint>,
}

impl PolicyVerifier {
    /// A verifier with the host's pinned anchors and its current checkpoint.
    ///
    /// `None` for the checkpoint is a real state, not an error: it is a host
    /// that has never accepted a policy, and every verification will report
    /// [`Stale`](VerificationOutcome::Stale).
    pub fn new(anchors: TrustAnchors, checkpoint: Option<TrustedCheckpoint>) -> Self {
        Self {
            anchors,
            checkpoint,
        }
    }

    /// The checkpoint this verifier holds.
    pub fn checkpoint(&self) -> Option<TrustedCheckpoint> {
        self.checkpoint
    }

    /// Check a policy without advancing the checkpoint.
    ///
    /// This is the read-only half: a caller that wants to authorise one
    /// operation without adopting the policy uses this, and a rejected policy
    /// cannot move the host's state through it at all.
    pub fn verify(&self, policy: &Policy, request: &PolicyRequest, at: u64) -> VerificationOutcome {
        match self.check(policy, request, at) {
            Ok(freshness) => match freshness {
                Freshness::Checked { checkpoint } => VerificationOutcome::Fresh {
                    revision: policy.revision(),
                    freshness: Freshness::Checked { checkpoint },
                },
                Freshness::Unavailable => VerificationOutcome::Stale {
                    revision: policy.revision(),
                    freshness: Freshness::Unavailable,
                },
            },
            Err(refusal) => VerificationOutcome::Refused(refusal),
        }
    }

    /// Check a policy and, if it is valid and newer, adopt it.
    ///
    /// The checkpoint advances **only** on success, and only to a strictly
    /// higher revision — an equal revision is a re-presentation, not progress,
    /// and accepting it would let a store pin the host to one revision.
    pub fn verify_and_accept(
        &mut self,
        policy: &Policy,
        request: &PolicyRequest,
        at: u64,
    ) -> VerificationOutcome {
        match self.check(policy, request, at) {
            Ok(freshness) => {
                if let Ok(digest) = policy.digest() {
                    let advanced = TrustedCheckpoint::new(policy.revision(), digest);
                    if self
                        .checkpoint
                        .is_none_or(|held| held.revision() < advanced.revision())
                    {
                        self.checkpoint = Some(advanced);
                    }
                }
                match freshness {
                    Freshness::Checked { checkpoint } => VerificationOutcome::Fresh {
                        revision: policy.revision(),
                        freshness: Freshness::Checked { checkpoint },
                    },
                    Freshness::Unavailable => VerificationOutcome::Stale {
                        revision: policy.revision(),
                        freshness: Freshness::Unavailable,
                    },
                }
            }
            Err(refusal) => VerificationOutcome::Refused(refusal),
        }
    }

    /// Persist an accepted checkpoint through a host store.
    pub fn persist_checkpoint<S: CheckpointStore>(
        &self,
        store: &mut S,
    ) -> Result<(), crate::checkpoint::CheckpointError> {
        match self.checkpoint {
            Some(checkpoint) => store.save(&checkpoint),
            None => Ok(()),
        }
    }

    /// The full check sequence, in a fixed order.
    ///
    /// The order is deliberate and is the order a reader would audit: the
    /// artifact is decodable terms first (version), then *who signed it* (a
    /// pinned anchor), then *what it says* against the request, and only then
    /// *whether it is current* (the checkpoint). The signature is checked before
    /// any field comparison so that an unsigned policy never gets to have its
    /// fields reported back as if they were authoritative.
    fn check(
        &self,
        policy: &Policy,
        request: &PolicyRequest,
        at: u64,
    ) -> Result<Freshness, PolicyRefusal> {
        if policy.body.version != POLICY_VERSION {
            return Err(PolicyRefusal::UnsupportedVersion {
                found: policy.body.version,
                expected: POLICY_VERSION,
            });
        }

        // Misfit H: the policy names an ID; the host supplies the key.
        let anchor = self.anchors.get(&policy.issuer_key_id).ok_or_else(|| {
            PolicyRefusal::IssuerNotPinned {
                presented: policy.issuer_key_id.as_str().to_string(),
            }
        })?;
        if !policy.verify_issuer(anchor) {
            return Err(PolicyRefusal::IssuerSignature {
                issuer: policy.issuer_key_id.as_str().to_string(),
            });
        }

        // The expiry check comes before the field comparison: an expired policy
        // authorises nothing, so reporting a field mismatch first would invite an
        // operator to "fix" a field on a policy that is dead anyway.
        policy.check_validity(at)?;

        if policy.body.vault != request.vault {
            return Err(PolicyRefusal::Vault {
                expected: policy.body.vault.as_str().to_string(),
                found: request.vault.as_str().to_string(),
            });
        }
        if policy.body.user != request.user {
            return Err(PolicyRefusal::User {
                expected: policy.body.user.to_string(),
                found: request.user.to_string(),
            });
        }

        check_level_pair(&request.source, &request.target)?;

        if !policy.body.shareable_secrets.contains(&request.secret) {
            return Err(PolicyRefusal::SecretGrant {
                secret: request.secret.as_str().to_string(),
            });
        }
        if !policy.body.shareable_agents.contains(&request.agent) {
            return Err(PolicyRefusal::AgentGrant {
                agent: request.agent.to_string(),
            });
        }

        // The grant names an agent; the copy must land at *that* agent's level.
        // Without this, a grant for agent-7 authorises a delivery written at
        // agent-9's level, because scope and path are both derived from the
        // target and so agree with whichever level was named.
        match &request.target {
            Level::Agent(target_agent) if *target_agent == request.agent => {}
            Level::Agent(target_agent) => {
                return Err(PolicyRefusal::TargetLevel {
                    granted: request.agent.to_string(),
                    target: target_agent.to_string(),
                });
            }
            Level::Admin | Level::User => {
                return Err(PolicyRefusal::LevelPair {
                    from_level: request.source.path_segment(),
                    to_level: request.target.path_segment(),
                });
            }
        }

        if request.scope != request.target.path_segment() {
            return Err(PolicyRefusal::Scope {
                expected: request.target.path_segment(),
                found: request.scope.clone(),
            });
        }

        let expected_path = request.expected_path();
        if request.path != expected_path {
            return Err(PolicyRefusal::Path {
                expected: expected_path,
                found: request.path.clone(),
            });
        }

        if request.record_version.get() == 0 {
            return Err(PolicyRefusal::Version {
                found: request.record_version.get(),
            });
        }

        policy.check_ttl(&request.target, request.requested_ttl_secs)?;

        // Misfit N, last: everything above is about *what* the policy says; this
        // is about *how old it is*.
        match self.checkpoint {
            Some(checkpoint) => {
                if policy.revision() < checkpoint.revision() {
                    return Err(PolicyRefusal::Rollback {
                        presented: policy.revision(),
                        checkpoint: checkpoint.revision(),
                    });
                }
                Ok(Freshness::Checked {
                    checkpoint: checkpoint.revision(),
                })
            }
            None => Ok(Freshness::Unavailable),
        }
    }
}

/// The only share this system performs: a `user`-level record to one agent.
///
/// `admin` -> `user` is not a share and `agent` -> anything is the one-way
/// boundary FR-016 draws, so both are refused here rather than left to the
/// caller. A `user` -> `user` pair is not a share either: it would be a lease on
/// the user's own record, which is the `admin`/`user` path, not this one.
fn check_level_pair(source: &Level, target: &Level) -> Result<(), PolicyRefusal> {
    // Two sources are shareable: the user's own value (`user`) and a value the
    // admin wrote and delegated (`admin`). Both land at an agent level. A
    // delivery from an agent level to another agent level is not a share — it is
    // a re-share, which the design does not permit.
    let allowed = matches!(source, Level::User | Level::Admin) && matches!(target, Level::Agent(_));
    if !allowed {
        return Err(PolicyRefusal::LevelPair {
            from_level: source.path_segment(),
            to_level: target.path_segment(),
        });
    }
    Ok(())
}

/// Decode a policy from the bytes a store handed over.
///
/// A decode failure becomes [`PolicyRefusal::Malformed`], which is deliberately
/// distinguishable from every named field refusal: bytes that are not a policy
/// are a different kind of event from a policy that says the wrong thing.
pub fn decode_policy(bytes: &[u8]) -> Result<Policy, PolicyRefusal> {
    cbor::decode(bytes).map_err(|err| PolicyRefusal::Malformed {
        cause: err.to_string(),
    })
}

/// Encode a policy for a store.
pub fn encode_policy(policy: &Policy) -> Result<Vec<u8>, PolicyRefusal> {
    cbor::encode(policy).map_err(|err| PolicyRefusal::Malformed {
        cause: err.to_string(),
    })
}
