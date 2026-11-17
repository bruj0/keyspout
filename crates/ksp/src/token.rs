//! The `ksp token` group: mint a delivery and the intent that authorises its removal.
//!
//! # Why one command does two things
//!
//! A token names an *exact version* of an `agent`-level record, and the content
//! key that version is sealed under is fresh per copy (FR-015). The only party
//! that can produce that key is the one that creates the copy, which is this
//! command: it reads the user's own record, re-seals the value at the agent's
//! level under a new content key, and puts that key inside the token. Splitting
//! the copy into a separate command would leave the fresh key at rest somewhere
//! between the two.
//!
//! # Order
//!
//! The record is written and the artifact sealed **inside** WP08's `publish`
//! closure, which is only called after a durable arming acknowledgement. A
//! failure to arm therefore publishes nothing: no record, no token.
//!
//! # The intent
//!
//! The delete authorisation is signed here, **by the record's owner**, and written
//! beside the token. It is data the run path presents to S4; it is not authority by
//! itself, because S4 verifies it against the user's pinned key before acting. The
//! admin's key takes no part in a mint: she signed the policy that grants the
//! share, and that is the whole of her contribution to a lease (spec §3.7).

use ksp_identity::delivery::{self, VerifiedRecipientKey};
use ksp_identity::policy_edge::{PolicyEdge, PolicyId, PolicyRecordRef, PolicyTarget};
use ksp_identity::{
    DeliveredKey, DeliveryArtifact, DeliveryHeader, MintBinding, MintRefusal, MintRequest, Policy,
    PolicyRequest, PolicyVerifier, SelectedContentKeys, TrustAnchors, UnsignedEnrolment,
    decode_policy, mint,
};
use ksp_record::{ContentBlob, Record, RecordEnvelope, commit_version};
use ksp_types::{
    ActorId, AgentId, BoundMetadata, ContentKey, DeletionIntent, LeaseCapability, Level,
    OpaqueSecretId, RecordVersion,
};

use crate::admission::Admission;
use crate::config::{self, Layout};
use crate::deployment::{self, Deployment};
use crate::edges::EdgeStore;
use crate::exit::{self, Outcome};
use crate::keys::StoredEnrolment;
use crate::publication::PublicationPath;
use crate::secret;

/// Why a mint stopped.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// This host has no deployment, policy or agent enrolment.
    #[error("this host is not provisioned for a mint")]
    NotProvisioned,
    /// The policy names a key this host does not pin.
    #[error("the policy was not signed by the pinned admin key")]
    PolicyIssuer,
    /// The policy refused the request.
    #[error("the policy refused the mint: {0}")]
    Policy(#[from] ksp_identity::PolicyRefusal),
    /// The mint sequence refused.
    #[error("the mint was refused: {0}")]
    Mint(#[from] MintRefusal),
    /// The account the deployment binds no longer resolves.
    ///
    /// The binding is keyed by the actor's UUID and names a host identity; an
    /// identity that is gone leaves the files behind, so "the record is still
    /// readable" is not evidence the principal is (FR-023, FR-024).
    #[error(
        "the principal binding is unverified: {0} no longer resolves to an account on this host"
    )]
    Binding(String),
    /// The backend does not admit this lease.
    #[error("the backend does not admit a lease of that length")]
    Inadmissible,
    /// The backend has no deadline mechanism this host can prove.
    ///
    /// The message is the gate's own sentence, which names what was observed: no
    /// proof, an unverifiable proof, a stale proof with its age and bound, or a
    /// backend that states no mechanism at all.
    #[error("{0}")]
    NoMechanism(String),
    /// The record could not be sealed into an artifact.
    ///
    /// The reason travels: "the delivery could not be produced" left an operator
    /// with nothing to look at when the cause was a header or a recipient key.
    #[error("the delivery could not be sealed: {0}")]
    Seal(String),
    /// The record could not be read or written.
    #[error("the delivery could not be produced")]
    Delivery,
    /// The token file could not be written.
    #[error("the token could not be written")]
    Write,
    /// The user's vault could not be opened, for the vault's own reason.
    #[error("{0}")]
    Vault(crate::vault::VaultError),
    /// The ledger does not name this identifier, so there is nothing to revoke.
    #[error("{0}")]
    UnknownToken(String),
    /// The ledger could not be read, written, or is not safe to use as it is.
    #[error("{0}")]
    Ledger(String),
    /// The token at a policy's path does not verify, so it is not exported.
    #[error("the token at {path} does not verify as policy {policy}'s delivery: {reason}")]
    UnverifiableToken {
        /// The policy it is filed under.
        policy: String,
        /// The file that failed.
        path: String,
        /// What the verifier said.
        reason: String,
    },
    /// A policy names no publication, so there is nothing to deliver.
    #[error("policy {policy} names no publication, so it authorises no delivery")]
    NoPublication {
        /// The policy that names none.
        policy: String,
    },
    /// A policy names a path that is not the derived publication path.
    ///
    /// The refusal names the accepted path rather than the segment that differed,
    /// so an operator can write the right one instead of guessing (FR-036).
    #[error("policy {policy} names {found}, but a publication is only readable at {accepted}")]
    PublicationNotDerived {
        /// The policy that names it.
        policy: String,
        /// The derived path this build accepts.
        accepted: String,
        /// The path the policy records.
        found: String,
    },
    /// The publication a policy names could not be read, for its own reason.
    #[error("the publication policy {policy} names could not be read: {reason}")]
    PublicationUnreadable {
        /// The policy naming it.
        policy: String,
        /// What the reader said.
        reason: String,
    },
    /// The policy is cooperative, so no cryptographic delivery exists to issue.
    ///
    /// `AnyEnrolled` seals the publication entry to the user, who opens it with her
    /// own key and passes the value on. Calling that a restricted delivery would
    /// claim a control the grant does not make (FR-035).
    #[error(
        "policy {policy} names any enrolled agent, so it is cooperative: the user opens it and \
         passes the value on, and there is no per-agent delivery to issue"
    )]
    Cooperative {
        /// The cooperative policy.
        policy: String,
    },
    /// The agent a policy names has published no keys this host can read.
    #[error("agent {agent} has published no enrolment, so a token for it cannot be built")]
    AgentNotPublished {
        /// The agent whose index entry is absent.
        agent: String,
    },
    /// The export named an agent the policy does not name.
    #[error("policy {policy} names agent {names}, not {requested}")]
    NotThisAgent {
        /// The policy.
        policy: String,
        /// The agent the policy names.
        names: String,
        /// The agent the export asked for.
        requested: String,
    },
    /// The export named a secret the policy does not deliver.
    ///
    /// A policy token is only ever for the secret its grant was signed for, so
    /// exporting it under another secret's name would hand an agent a credential the
    /// operator did not mean to send. The two names are printed so the operator can
    /// see which grant they actually signed.
    #[error("policy {policy} delivers {names}, not {requested}")]
    NotThisSecret {
        /// The policy.
        policy: String,
        /// The secret the policy delivers.
        names: String,
        /// The secret the export named.
        requested: String,
    },
    /// The policy has no issued token on this host.
    #[error("no delivery token was issued for policy {policy}; expected it at {path}")]
    TokenAbsent {
        /// The policy.
        policy: String,
        /// Where the token would be.
        path: String,
    },
    /// The file at the policy's token path is a different policy's token.
    #[error("the token at {path} is not the one policy {policy} issued")]
    TokenIsAnotherPolicys {
        /// The policy.
        policy: String,
        /// The file that disagreed.
        path: String,
    },
}

impl TokenError {
    /// The exit code this failure maps to.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::NotProvisioned => exit::MISSING_KEY,
            Self::Vault(error) => error.exit_code(),
            Self::PolicyIssuer | Self::Policy(_) => exit::POLICY_DENIAL,
            Self::Mint(MintRefusal::Inadmissible { .. })
            | Self::Inadmissible
            | Self::Binding(_)
            | Self::NoMechanism(_) => exit::CAPABILITY_REFUSAL,
            // The mint owns the classification of its own refusals; this module
            // does not restate it.
            Self::Mint(refusal) => refusal.exit_code() as i32,
            Self::Delivery | Self::Seal(_) | Self::Write => exit::INTERNAL,
            // "This host has no record of that token" is a refusal, not a bug:
            // the command asked for something the host cannot do, and saying so
            // is not the same as failing unexpectedly.
            Self::UnknownToken(_) => exit::POLICY_DENIAL,
            // A policy that cannot authorise the delivery asked of it is a policy
            // denial, not a failure: the operator asked for something this grant
            // does not provide, and the sentence says which.
            Self::NoPublication { .. }
            | Self::PublicationNotDerived { .. }
            | Self::Cooperative { .. }
            | Self::NotThisAgent { .. }
            | Self::NotThisSecret { .. }
            | Self::TokenAbsent { .. }
            | Self::AgentNotPublished { .. } => exit::POLICY_DENIAL,
            Self::PublicationUnreadable { .. }
            | Self::TokenIsAnotherPolicys { .. }
            | Self::UnverifiableToken { .. } => exit::INTERNAL,
            // A ledger that cannot be read, is torn, or is readable by others is
            // an operator problem this command cannot fix, and it must not
            // pretend otherwise.
            Self::Ledger(_) => exit::INTERNAL,
        }
    }
}

/// What a successful mint produced.
pub struct Minted {
    /// Where the delivery artifact was written.
    pub token: std::path::PathBuf,
    /// Where the signed delete authorisation was written.
    pub intent: std::path::PathBuf,
    /// The version the delivery names.
    pub version: u32,
}

/// Mint a delivery for `agent`, copied from the user's record `secret`.
///
/// `admission` is passed in rather than read from the layout so a caller can be
/// explicit about which backend is being asked to hold the lease. The binary passes
/// the configured one, whose `file` capability comes from a verified sweep proof and
/// therefore refuses on a host that has never proven a run — a refusal, not a silent
/// success.
#[allow(clippy::too_many_arguments)]
pub fn mint_lease(
    layout: &Layout,
    admission: &Admission,
    password: &[u8],
    agent: &AgentId,
    secret_id: &OpaqueSecretId,
    record_name: &[u8],
    ttl_secs: u64,
    remaining_uses: Option<u32>,
    out: &std::path::Path,
) -> Result<Minted, TokenError> {
    // The gate comes first: a backend with no proven deadline mechanism cannot hold
    // a lease at all, and reading the user's record to discover that would be work
    // done to reach a refusal that never depended on the value.
    let (recorded, anchor) = deployment::require(layout).map_err(|_| TokenError::NotProvisioned)?;
    // FR-023/FR-024: the lease is requested *by* the bound principal, so a binding
    // whose account no longer resolves is a capability refusal rather than a share
    // that succeeds because the files it needs still sit under a bare uid. Checked
    // before the capability gate: the reason this cannot proceed is who is asking,
    // not how long the lease would be.
    if let Some(account) = recorded.user_account.as_deref()
        && !deployment::account_resolves(account)
    {
        return Err(TokenError::Binding(account.to_string()));
    }

    let classification = &admission.classification;
    if matches!(classification.capability, LeaseCapability::None) {
        let reason = admission
            .refusal
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| {
                "this backend has no deadline mechanism, so no lease can be held on it".to_string()
            });
        return Err(TokenError::NoMechanism(reason));
    }

    // The policy is the admin's contribution, and it is public material verified
    // against the pinned anchor. The admin's *private* key is not part of a
    // lease: she has already said, by signing this policy, which agent may
    // receive which record, for how long (spec §3.7, FR-020).
    let policy = read_policy(layout)?;
    if !policy.verify_issuer(&anchor.key) {
        return Err(TokenError::PolicyIssuer);
    }

    let stored = StoredEnrolment::load(&layout.enrolment_file(&agent.to_string()))
        .map_err(|_| TokenError::NotProvisioned)?;
    if stored.identity != *agent {
        return Err(TokenError::NotProvisioned);
    }

    // The recipient is the agent's confirmed key, taken from the pin this host
    // holds. Alice confirms its fingerprint through a channel independent of the
    // store; the pin recomputes its own fingerprint from its own claims, so a
    // substituted recipient key does not match (misfit Q).
    let pin = UnsignedEnrolment::bind(
        ActorId::Agent(*agent),
        stored.signing_key,
        stored.recipient_key,
        stored.signing_key_id.clone(),
        stored.recipient_key_id.clone(),
    )
    .map_err(|_| TokenError::NotProvisioned)?;
    let confirmed = *pin.fingerprint();
    let recipient = VerifiedRecipientKey::confirm_pin(&pin, &confirmed)
        .map_err(|_| TokenError::NotProvisioned)?;

    // From here every signature is the user's: the intent that authorises the
    // delete, the arm record that binds it to one version, and the artifact the
    // agent receives. Her key is lent to this closure for the whole sequence, so
    // no copy of it outlives the call.
    let unsealed = secret::unseal(layout, password).map_err(vault_refusal)?;
    unsealed.vault.with_signing_key(|signer| {
        // Alice opens her own record: the value has to be re-sealed at the agent's
        // level, which means this process holds it briefly.
        let (name, value, source_level) = read_user_record(layout, password, secret_id)?;

        let at = crate::run::now_seconds();
        let deadline = i64::try_from(at.saturating_add(ttl_secs)).unwrap_or(i64::MAX);
        let version = RecordVersion(1);
        let agent_metadata = BoundMetadata {
            vault_id: recorded.vault.clone(),
            user_id: recorded.user,
            level: Level::Agent(*agent),
            secret_id: secret_id.clone(),
            version: version.get(),
        };

        let policy_request = PolicyRequest {
            vault: recorded.vault.clone(),
            user: recorded.user,
            source: source_level.clone(),
            target: Level::Agent(*agent),
            secret: secret_id.clone(),
            agent: *agent,
            path: ksp_record::RecordPath::of(&agent_metadata).to_string(),
            scope: Level::Agent(*agent).path_segment(),
            requested_ttl_secs: ttl_secs,
            record_version: version,
        };

        let intent = DeletionIntent {
            intent_id: format!(
                "{}-{}-{}",
                secret_id.as_str(),
                agent,
                agent_metadata.version
            ),
            vault_id: recorded.vault.clone(),
            user_id: recorded.user,
            level: Level::Agent(*agent),
            secret_id: secret_id.clone(),
            version: agent_metadata.version,
            deadline,
            // The agent may remove its own copy on consume; the admin's sweep may
            // remove it when the lease deadline passes (FR-015). The user is added
            // when she bounded the copy herself: her own `secret gc` is what
            // enforces a use count, and an intent that did not name her would make
            // her sweep fail on the one deletion it exists to make.
            authorized_deleters: {
                let mut deleters = vec![ActorId::Agent(*agent), ActorId::Admin(recorded.admin)];
                if remaining_uses.is_some() {
                    deleters.push(ActorId::User(recorded.user));
                }
                deleters
            },
        };

        let intent_id = intent.intent_id.clone();

        // Signed before the arm, so the authorisation exists for the version the
        // token will name. An intent for a version that is never published expires
        // unused; that is the harmless direction.
        let signed_intent = sign_intent(layout, password, intent.clone())?;
        let intent_unsigned = intent;

        let binding = MintBinding {
            identity: ActorId::Agent(*agent),
            signing_key: stored.signing_key,
            recipient_key: stored.recipient_key,
            signing_key_id: stored.signing_key_id.clone(),
            recipient_key_id: stored.recipient_key_id.clone(),
            confirmed_fingerprint: confirmed,
        };

        let mut anchors = TrustAnchors::new();
        anchors.pin(anchor.key_id.clone(), anchor.key);
        let verifier = PolicyVerifier::new(anchors, None);

        // The agent level is created by the table before any bytes are armed: the
        // level's mode is what lets the admin's sweep delete the lease, and the
        // store's own `create_dir_all` would take the caller's umask instead.
        crate::layout::ensure_level(
            layout.root(),
            &recorded.vault,
            recorded.user,
            &Level::Agent(*agent),
        )
        .map_err(|error| TokenError::Seal(format!("the agent level: {error}")))?;
        let store = config::open_file_store(layout)
            .map_err(|error| TokenError::Seal(format!("the store: {error}")))?;
        // The record states the bound; this file holds how much of it is left.
        // Seeded before publication, so a token that exists always has a counter
        // to spend.
        if let Some(uses) = remaining_uses {
            let store = config::open_file_store(layout).map_err(|_| TokenError::Delivery)?;
            ksp_backend::usebound::seed(store.root(), &intent_id, uses)
                .map_err(|_| TokenError::Delivery)?;
        }

        let request = MintRequest {
            remaining_uses,
            binding,
            policy_request,
            intended_recipient: stored.recipient_key,
            intent: intent_unsigned,
            // The intent's own ID is the idempotency key, and the ledger records
            // under that same ID. A second mint for the same version is refused
            // as an identity that already names different bytes; that refusal,
            // not a dedupe in the ledger, is what keeps one row per lease.
            operation_identity: intent_id.clone(),
        };

        // The ledger entry names what the artifact will carry, and both are built
        // from the same values: the identifier is the intent's own id, which is
        // also the header's `jti`, and the deadline is the one the intent arms.
        // Recording anything else would be a row about a different token.
        let issuance = ksp_identity::issuance::Issuance {
            token_id: intent_id.clone(),
            agent: *agent,
            secret: secret_id.clone(),
            version,
            deadline: i64::try_from(at.saturating_add(ttl_secs)).unwrap_or(i64::MAX),
            policy_revision: policy.revision(),
        };
        // The registry that names the admin is authenticated against the pinned anchor:
        // a registry another principal planted would name her own directory, and the
        // issuance record would land in a ledger no reader consults.
        let anchor = crate::keys::Anchor::load(&layout.admin_anchor_file())
            .map_err(|_| TokenError::NotProvisioned)?;
        let ledger =
            crate::ledgers::LedgerPaths::discover(layout, policy.vault(), *policy.user(), &anchor)
                .map_err(|error| TokenError::Ledger(error.to_string()))?
                .as_ledger();

        let outcome = mint(
            &store,
            &ledger,
            signer,
            &verifier,
            &policy,
            classification,
            // Seconds, not hours: the floor is a duration the caller chose, and rounding
            // it up to the next hour would admit a 599 s lease under a 600 s floor.
            ttl_secs,
            at,
            request,
            issuance,
            |_authority| -> Result<Vec<u8>, TokenError> {
                // Everything below runs only after a durable acknowledgement.
                let content_key = ContentKey::generate();
                let aad = agent_metadata
                    .bound_aad()
                    .map_err(|_| TokenError::Delivery)?;
                let blob = ContentBlob::seal(&content_key, record_name, &value, &aad)
                    .map_err(|error| TokenError::Seal(format!("the record blob: {error}")))?;
                let envelope =
                    RecordEnvelope::seal(&content_key, recipient.as_bytes(), &agent_metadata)
                        .map_err(|error| {
                            TokenError::Seal(format!("the record envelope: {error}"))
                        })?;
                let sealed_record = Record {
                    metadata: agent_metadata.clone(),
                    blob,
                    envelope,
                };
                commit_version(&store, &agent_metadata, &sealed_record)
                    .map_err(|error| TokenError::Seal(format!("the record: {error}")))?;

                let selected = ksp_identity::SelectedRecord {
                    secret: secret_id.clone(),
                    version,
                    policy: None,
                };
                // The header names the key that signs it, and that is hers: the
                // artifact's `issuer` is the principal's enrolled key, verified
                // against the same pin (spec §3.7). Naming the admin here would
                // put a signed claim in the artifact that the signature
                // contradicts — `run` would still verify, and every human reading
                // `token inspect` would be told the wrong issuer.
                let issuer_key_id = recorded
                    .user_signing_key_id
                    .clone()
                    .ok_or(TokenError::NotProvisioned)?;
                let header = DeliveryHeader::new(
                    recorded.vault.clone(),
                    recorded.user,
                    issuer_key_id,
                    *agent,
                    stored.signing_key,
                    stored.recipient_key,
                    stored.signing_key_id.clone(),
                    stored.recipient_key_id.clone(),
                    Level::Agent(*agent),
                    source_level,
                    Level::Agent(*agent).path_segment(),
                    vec![selected.clone()],
                    at.saturating_add(ttl_secs),
                    intent_id.clone(),
                )
                .map_err(|error| TokenError::Seal(format!("the header: {error}")))?;
                let keys = SelectedContentKeys::new(
                    &header,
                    vec![(selected, DeliveredKey::Content(content_key))],
                )
                .map_err(|error| TokenError::Seal(error.to_string()))?;
                let artifact = delivery::seal(signer, &header, &keys, &recipient)
                    .map_err(|error| TokenError::Seal(error.to_string()))?;
                artifact
                    .to_bytes()
                    .map_err(|error| TokenError::Seal(error.to_string()))
            },
        )?;

        // `mint` returns the publish closure's own value, which here is the artifact
        // bytes: the token cannot exist without the acknowledgement.
        // `mint` returns the publish closure's own value, which here is the artifact
        // bytes: the token cannot exist without the acknowledgement.
        let token_bytes = outcome.token?;
        std::fs::write(out, &token_bytes).map_err(|_| TokenError::Write)?;
        let intent_path = out.with_extension("intent");
        let intent_bytes =
            ksp_types::cbor::encode(&signed_intent).map_err(|_| TokenError::Write)?;
        std::fs::write(&intent_path, &intent_bytes).map_err(|_| TokenError::Write)?;

        let _ = name;
        Ok(Minted {
            token: out.to_path_buf(),
            intent: intent_path,
            version: version.get(),
        })
    })
}

/// The vault's own reason, carried into this command's error type.
fn vault_refusal(error: crate::secret::SecretError) -> TokenError {
    match error {
        // A wrong password or a vault owned by another account keeps its sentence:
        // 'the vault could not be opened' told an operator nothing (FR-024).
        crate::secret::SecretError::Vault(vault) => TokenError::Vault(vault),
        _ => TokenError::Vault(crate::vault::VaultError::Absent),
    }
}

/// Sign the delete authorisation with the record owner's key.
///
/// The intent is the user's statement that the copy may be removed at the
/// deadline: she is the one leasing it, and the sweep and the agent both act on
/// her authorisation. It is signed with her enrolled signing key and verified
/// against the public half the deployment recorded, so the admin's key takes no
/// part in a delivery (spec §3.7 step 2).
fn sign_intent(
    layout: &Layout,
    password: &[u8],
    intent: DeletionIntent,
) -> Result<ksp_deletion::SignedIntent, TokenError> {
    let unsealed = secret::unseal(layout, password).map_err(vault_refusal)?;
    let key_id = deployment::require(layout)
        .map_err(|_| TokenError::NotProvisioned)?
        .0
        .user_signing_key_id
        .ok_or(TokenError::NotProvisioned)?;
    unsealed
        .vault
        .with_signing_secret(|seed| {
            let key = ksp_deletion::EvidenceSigningKey::from_seed(*seed);
            ksp_deletion::SignedIntent::sign(&key, key_id.as_str(), intent)
        })
        .map_err(|_| TokenError::Delivery)
}

fn read_policy(layout: &Layout) -> Result<Policy, TokenError> {
    let bytes = std::fs::read(layout.policy_file()).map_err(|_| TokenError::NotProvisioned)?;
    decode_policy(&bytes).map_err(|_| TokenError::NotProvisioned)
}

fn read_user_record(
    layout: &Layout,
    password: &[u8],
    secret: &OpaqueSecretId,
) -> Result<(Vec<u8>, Vec<u8>, Level), TokenError> {
    let unsealed = secret::unseal(layout, password).map_err(vault_refusal)?;
    let store = config::open_file_store(layout).map_err(|_| TokenError::Delivery)?;
    // The level is the record's provenance, and the mint has to know it: an
    // `admin`-level value is a delegation and needs a policy, a `user`-level
    // value is the user's own and does not.
    let (level, version) = secret::source_level(&store, &unsealed.vault_id, &unsealed.user, secret)
        .map_err(|_| TokenError::Vault(crate::vault::VaultError::Absent))?
        .ok_or(TokenError::Vault(crate::vault::VaultError::Absent))?;
    let (name, value) =
        secret::get_at(layout, password, level.clone(), secret, version).map_err(vault_refusal)?;
    Ok((name, value, level))
}

/// A `token` subcommand that is not wired yet.
/// What one token says about itself: scope, issuer and expiry, and no key.
///
/// The artifact is verified against the pinned anchor first, so an inspection of
/// a token this host cannot trust says so rather than printing the claims of
/// whatever file was handed to it. Nothing here opens the envelope: an inspection
/// needs no private half, which is what makes it safe to run on any host.
pub fn inspect(
    layout: &Layout,
    path: &std::path::Path,
) -> Result<crate::output::TokenInspection, TokenError> {
    let bytes = std::fs::read(path).map_err(|_| TokenError::NotProvisioned)?;
    let artifact =
        delivery::DeliveryArtifact::from_bytes(&bytes).map_err(|_| TokenError::NotProvisioned)?;

    // Signed by the principal who minted it, so her enrolled key is the pin.
    let signer =
        crate::deployment::user_verifying_key(layout).map_err(|_| TokenError::NotProvisioned)?;
    let verified = delivery::verify(&artifact, &signer).map_err(|_| TokenError::PolicyIssuer)?;
    let header = verified.header();

    let records = header
        .records()
        .iter()
        .map(|selected| crate::output::RecordMetadata {
            record: selected.secret.as_str().to_string(),
            // The level is the header's, not the record's: one delivery names one
            // level for every record it selects.
            level: header.level().path_segment().to_string(),
            version: selected.version.get(),
        })
        .collect();

    Ok(crate::output::TokenInspection {
        jti: header.jti().to_string(),
        agent: header.agent().to_string(),
        level: header.level().path_segment().to_string(),
        vault: header.vault().as_str().to_string(),
        user: header.user().to_string(),
        issuer_key_id: header.issuer_key_id().as_str().to_string(),
        agent_signing_key_id: header.agent_signing_key_id().as_str().to_string(),
        agent_recipient_key_id: header.agent_recipient_key_id().as_str().to_string(),
        expires_at: header.expires_at(),
        records,
    })
}

/// What a ledger row's `standing` says, given what the store reported.
///
/// Split out so the decision is testable without a deployment, a store or a
/// ledger. The integration case needs all three; the *rule* is these few lines,
/// and the rule is what the defect was about.
///
/// # The rule
///
/// A revocation wins over presence: a token this host marked is not live even if
/// the record is still on disk, because the mark is a decision and the bytes are
/// an accident of timing.
///
/// With no revocation, the store's answer decides. `Present` is `live`.
/// `Absent` is `consumed` — the copy can no longer be fetched, which is the
/// question the column answers. `Unreadable` is `unknown`, because an error is
/// not evidence of absence and claiming `consumed` for an unreadable record would
/// assert a deletion nobody established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    /// The record is at the path the ledger names.
    Present,
    /// The store says there is nothing there.
    Absent,
    /// The store could not answer.
    Unreadable,
    /// The deployment or the store could not be opened at all.
    Unreachable,
}

fn standing_for(revoked: Option<&str>, presence: Presence) -> String {
    if let Some(reason) = revoked {
        return format!("revoked: {reason}");
    }
    match presence {
        Presence::Present => "live".to_string(),
        Presence::Absent => "consumed".to_string(),
        Presence::Unreadable => "unknown: the record could not be read".to_string(),
        Presence::Unreachable => "unknown: the deployment or store could not be opened".to_string(),
    }
}

/// What `token list` prints: this host's ledger and its honest scope.
///
/// # Why the ledger alone is not enough
///
/// The ledger knows about revocation and nothing else. A `--consume` run deletes
/// the sealed record and reports it, but it does not revoke the token: the lease
/// is not withdrawn, its copy is gone. So a row that consulted only the ledger
/// said `live` for a token whose bytes no longer existed, while `ksp run` refused
/// the same token with exit 6. Measured: after a consume, `token list` reported
/// `standing: live` with a deadline 118 minutes in the future.
///
/// The row therefore also asks the store whether the record it names is still
/// there. That is the same question `ksp run` asks — same store, same path — so
/// the two cannot disagree.
///
/// # What this can and cannot see
///
/// Presence is checked at the path the ledger names. A store that reports an
/// absent record as an error rather than as `None` yields `unknown`, not
/// `consumed`: this host cannot tell a deleted record from an unreadable one, and
/// saying `consumed` for both would claim an absence nobody established.
pub fn listing(layout: &Layout) -> Result<crate::output::TokenLedger, TokenError> {
    // The ledgers live under the principals in the store, and their two paths are not
    // derivable from one another, so a provisioned host resolves them from its record.
    // A host with no record can only be reading a ledger written before the move —
    // the home-local file — and that is what it lists: the alternative is reporting a
    // history this command cannot see as no history at all.
    let deployment = crate::deployment::require(layout).ok();
    let ledger = match &deployment {
        Some((recorded, _anchor)) => {
            crate::ledgers::LedgerPaths::for_deployment(layout, recorded).as_ledger()
        }
        None => ksp_identity::IssuanceLedger::at(layout.issuance_ledger()),
    };
    let listing = ledger
        .listing()
        .map_err(|error| TokenError::Ledger(error.to_string()))?;

    // The deployment names the vault and the user the records live under; the
    // ledger row names the level, the secret and the version. Together they are
    // the record path, built the same way `ksp run` builds it.
    //
    // A host with no deployment has no records to look for, so every row is
    // `unknown` rather than `consumed` — an absent deployment is not an absent
    // record.
    let deployment = deployment.map(|(recorded, _anchor)| recorded);
    let store = crate::config::open_file_store(layout).ok();

    let rows = listing
        .entries
        .iter()
        .map(|entry| {
            let presence = match (&deployment, &store) {
                (Some(deployment), Some(store)) => {
                    let metadata = ksp_types::BoundMetadata {
                        vault_id: deployment.vault.clone(),
                        user_id: deployment.user,
                        level: ksp_types::Level::Agent(entry.issuance.agent),
                        secret_id: entry.issuance.secret.clone(),
                        version: entry.issuance.version.0,
                    };
                    let path = ksp_record::RecordPath::of(&metadata);
                    match ksp_record::version::BlobStore::get(store, path.as_str()) {
                        Ok(Some(_)) => Presence::Present,
                        Ok(None) => Presence::Absent,
                        Err(_) => Presence::Unreadable,
                    }
                }
                _ => Presence::Unreachable,
            };
            crate::output::LedgerRow {
                token_id: entry.issuance.token_id.clone(),
                agent: entry.issuance.agent.to_string(),
                secret: entry.issuance.secret.as_str().to_string(),
                version: entry.issuance.version.0,
                deadline: entry.issuance.deadline,
                policy_revision: entry.issuance.policy_revision,
                standing: standing_for(
                    entry
                        .reason
                        .as_ref()
                        .map(|reason| reason.to_string())
                        .as_deref(),
                    presence,
                ),
            }
        })
        .collect();

    let mut scope = listing.scope();
    if listing.torn_tail {
        scope.push_str(
            "; the last entry was cut short by a crash and is not listed, so this host cannot \
             say what it was",
        );
    }
    Ok(crate::output::TokenLedger { rows, scope })
}

/// Mark one token identifier this host minted.
///
/// Refuses an identifier the ledger does not name: this host has nothing to
/// revoke, and writing a mark for a token it never minted would make a local
/// file into an accusation about someone else's token.
pub fn revoke(
    layout: &Layout,
    token_id: &str,
    at: i64,
) -> Result<crate::output::Revocation, TokenError> {
    // The mark goes where `run` reads it, which is the same resolution `listing` uses:
    // the store ledger on a provisioned host, and the pre-move home file on a host with
    // no record — a host whose `run` finds no store ledger either, so the pair cannot
    // disagree about which file they are talking about.
    let ledger = match crate::deployment::require(layout) {
        Ok((deployment, _anchor)) => {
            crate::ledgers::LedgerPaths::for_deployment(layout, &deployment).as_ledger()
        }
        Err(_) => ksp_identity::IssuanceLedger::at(layout.issuance_ledger()),
    };
    let mark = ledger.revoke(token_id, at).map_err(|error| match error {
        ksp_identity::LedgerError::UnknownToken { token_id } => TokenError::UnknownToken(format!(
            "this host has no record of token {token_id}, so there is nothing to revoke; \
                     a token minted elsewhere is unknown here, not invalid"
        )),
        other => TokenError::Ledger(other.to_string()),
    })?;
    Ok(crate::output::Revocation {
        token_id: mark.token_id,
        revoked_at: mark.at,
        reach: ksp_identity::REVOCATION_REACH.to_string(),
    })
}

/// Run one `token` subcommand that needs no private half.
pub fn run<W: std::io::Write>(
    command: &crate::commands::TokenCommand,
    layout: &Layout,
    emitter: &mut crate::output::Emitter<W>,
) -> Outcome {
    match command {
        crate::commands::TokenCommand::Inspect { token } => match inspect(layout, token) {
            Ok(inspection) => match emitter.report(&crate::output::Report::Token(inspection)) {
                Ok(()) => Outcome::Success,
                Err(_) => Outcome::Failed(exit::INTERNAL),
            },
            Err(error) => Outcome::Failed(error.exit_code()),
        },
        crate::commands::TokenCommand::Lease => {
            // A lease over an existing agent-level version cannot be built here,
            // and the reason is structural rather than missing code: opening that
            // record needs the content key its envelope sealed to the agent's
            // recipient key. Unwrapping it on this host would be key escrow, and
            // escrow is what makes the levels worth separating.
            let _ = emitter.refusal(
                "a lease must be built from the source: an existing agent-level record is \
                 sealed to the agent's key, and unwrapping it here would hold that key on \
                 the agent's behalf (NFR-001). Use `token mint` or `secret share`",
            );
            Outcome::Failed(exit::CAPABILITY_REFUSAL)
        }
        crate::commands::TokenCommand::List => match listing(layout) {
            Ok(ledger) => match emitter.report(&crate::output::Report::Tokens(ledger)) {
                Ok(()) => Outcome::Success,
                Err(_) => Outcome::Failed(exit::INTERNAL),
            },
            Err(error) => {
                let _ = emitter.refusal(&error.to_string());
                Outcome::Failed(error.exit_code())
            }
        },
        crate::commands::TokenCommand::Revoke { token_id } => {
            match revoke(layout, token_id, crate::run::now_seconds() as i64) {
                Ok(revocation) => match emitter.report(&crate::output::Report::Revoked(revocation))
                {
                    Ok(()) => Outcome::Success,
                    Err(_) => Outcome::Failed(exit::INTERNAL),
                },
                Err(error) => {
                    let _ = emitter.refusal(&error.to_string());
                    Outcome::Failed(error.exit_code())
                }
            }
        }
        _ => Outcome::Failed(exit::INTERNAL),
    }
}

/// What issuing one policy's delivery token produced.
#[derive(Debug)]
pub struct IssuedToken {
    /// Where the token was written, beside its policy.
    pub path: std::path::PathBuf,
    /// The policy it authorises.
    pub policy: PolicyId,
    /// The publication path it names.
    pub publication: String,
}

/// When a policy-bound delivery stops being authorised.
///
/// The policy's own `not_after` is the only lease such a delivery has (CF-020): a
/// per-token TTL would need a fresh signature for every delivery, and the key that
/// could sign it belongs to the admin, not to the user exporting it. Two
/// consequences are deliberate — withdrawing the policy ends access at the source,
/// and an unwithdrawn policy keeps its window whatever the user exports.
fn policy_delivery_window(edge: &PolicyEdge) -> u64 {
    edge.body().not_after()
}

/// The publication path this edge must name, refusing one that is not it.
///
/// Derived here rather than trusted from the artifact, because the artifact's
/// string is written by an earlier command and the path is the address the agent
/// will read: a path that is not the derived one is a publication somewhere else
/// (FR-036).
fn derived_publication(
    layout: &Layout,
    edge: &PolicyEdge,
) -> Result<(PublicationPath, Deployment), TokenError> {
    let (recorded, _) = deployment::require(layout).map_err(|_| TokenError::NotProvisioned)?;
    let derived = PublicationPath::derive(
        edge.vault().clone(),
        recorded.admin,
        edge.secret().clone(),
        edge.record_version(),
    );
    match edge.body().publication() {
        None => Err(TokenError::NoPublication {
            policy: edge.id().to_string(),
        }),
        Some(found) if found != derived.canonical() => Err(TokenError::PublicationNotDerived {
            policy: edge.id().to_string(),
            accepted: derived.canonical(),
            found: found.to_string(),
        }),
        Some(_) => Ok((derived, recorded)),
    }
}

/// Issue the delivery token one specific-agent policy authorises (FR-018, CF-020).
///
/// This runs when the policy is created, with the admin's own password, and it is
/// the only place a policy-bound token is ever signed: the signature is the
/// admin's, so the user who later exports the token has nothing to sign and needs
/// no key. `run` verifies the token against the admin anchor, then the policy,
/// then opens the publication entry sealed to that agent.
///
/// The token names the policy and the publication and carries **no content key**:
/// the user cannot open the publication, so a key in her token would be a key she
/// never had authority to obtain (C1).
pub fn issue_policy_token(
    layout: &Layout,
    admin: &ksp_identity::AdminSigningKey,
    edge: &PolicyEdge,
    jti: String,
) -> Result<IssuedToken, TokenError> {
    let (recorded, anchor) = deployment::require(layout).map_err(|_| TokenError::NotProvisioned)?;
    // The grant is the authority, so it has to be the pinned admin's grant. Nothing
    // below may run for an edge this host cannot attribute.
    if !edge.verify_issuer(&anchor.key) {
        return Err(TokenError::PolicyIssuer);
    }
    // A cooperative grant names any agent, so its publication entry is sealed to the
    // *user* and she opens it with her own key. There is no cryptographic delivery to
    // issue, and issuing one would claim a restriction the policy does not make
    // (FR-035).
    let PolicyTarget::Agent(agent) = edge.target() else {
        return Err(TokenError::Cooperative {
            policy: edge.id().to_string(),
        });
    };
    let (publication_path, _) = derived_publication(layout, edge)?;
    // The artifact must already be there: a token that names a publication nobody
    // wrote is a run that fails at the agent, far from the command that could have
    // refused it.
    let publication = crate::publication::load(layout, &publication_path).map_err(|error| {
        TokenError::PublicationUnreadable {
            policy: edge.id().to_string(),
            reason: error.to_string(),
        }
    })?;
    publication
        .verify_binding(&publication_path)
        .map_err(|error| TokenError::PublicationUnreadable {
            policy: edge.id().to_string(),
            reason: error.to_string(),
        })?;

    // The agent's public material comes from the index its owner publishes, which is
    // readable without her home: the admin cannot traverse a `0700` agent directory
    // and does not need to (CF-011).
    let stored =
        crate::agent_index::load(layout, edge.vault(), *edge.user(), &agent).map_err(|error| {
            match error {
                crate::keys::PinError::Absent => TokenError::AgentNotPublished {
                    agent: agent.to_string(),
                },
                other => TokenError::Seal(other.to_string()),
            }
        })?;
    if stored.identity != agent {
        return Err(TokenError::AgentNotPublished {
            agent: agent.to_string(),
        });
    }

    let not_after = policy_delivery_window(edge);
    // The admin has no out-of-band fingerprint for another principal's agent, so the
    // published index is what she reads: it is the user's signed publication of her
    // own agent's keys (CF-011), and the alternative would be traversing a `0700`
    // home she cannot enter.
    // The pin recomputes its fingerprint from its own claims, so this confirms the
    // record is internally consistent rather than that the key is the agent's. The
    // authority for the latter is the user's own publication of that entry (CF-011),
    // which is the only material the admin can reach without entering her home.
    let pin = UnsignedEnrolment::bind(
        ActorId::Agent(agent),
        stored.signing_key,
        stored.recipient_key,
        stored.signing_key_id.clone(),
        stored.recipient_key_id.clone(),
    )
    .map_err(|error| TokenError::Seal(error.to_string()))?;
    let confirmed = *pin.fingerprint();
    let recipient = VerifiedRecipientKey::confirm_pin(&pin, &confirmed)
        .map_err(|error| TokenError::Seal(error.to_string()))?;
    let selected = ksp_identity::SelectedRecord {
        secret: edge.secret().clone(),
        version: edge.record_version(),
        policy: Some(edge.id().clone()),
    };

    let artifact = admin.with_signing_key(|signer| {
        let header = DeliveryHeader::new(
            edge.vault().clone(),
            // The publication's owning principal, which is also the issuer: a
            // policy-bound record is read where the admin published it, not under
            // the user who owns the secret.
            recorded.admin,
            recorded.admin_key_id.clone(),
            agent,
            stored.signing_key,
            stored.recipient_key,
            stored.signing_key_id.clone(),
            stored.recipient_key_id.clone(),
            Level::Granted,
            Level::Admin,
            Level::Granted.path_segment(),
            vec![selected.clone()],
            not_after,
            jti,
        )
        .map_err(|error| TokenError::Seal(format!("the header: {error}")))?;
        let keys = SelectedContentKeys::new(
            &header,
            vec![(
                selected,
                DeliveredKey::Policy(PolicyRecordRef {
                    policy_id: edge.id().clone(),
                    publication: publication_path.canonical(),
                }),
            )],
        )
        .map_err(|error| TokenError::Seal(error.to_string()))?;
        delivery::seal(signer, &header, &keys, &recipient)
            .map_err(|error| TokenError::Seal(error.to_string()))
    })?;

    let store = EdgeStore::new(layout, &recorded);
    let path = store.token_path(edge.id());
    write_token(
        &path,
        &artifact.to_bytes().map_err(|_| TokenError::Delivery)?,
    )?;
    Ok(IssuedToken {
        path,
        policy: edge.id().clone(),
        publication: publication_path.canonical(),
    })
}

/// The mode a token is written with, beside the publication's own modes.
///
/// `0640`: the admin writes it and her group reads it. The assumption is the store's
/// one group — the same assumption `PUBLICATION_FILE_MODE`'s `0740` and
/// `PUBLICATIONS_DIR_MODE`'s `0750` rest on — because the user who must *export* this
/// token is a different principal from the admin who wrote it (FR-018). A deployment
/// whose principals stop sharing that group breaks the export before it breaks
/// anything else.
pub const POLICY_TOKEN_MODE: u32 = 0o640;

/// Write a token where an operator and the agent can read it.
///
/// Renamed over the target, so a crash cannot leave a half-written artifact that
/// `run` would parse as a different token.
fn write_token(path: &std::path::Path, bytes: &[u8]) -> Result<(), TokenError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut temporary = path.to_path_buf();
    temporary.set_extension("token.tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(POLICY_TOKEN_MODE)
        .open(&temporary)
        .map_err(|_| TokenError::Write)?;
    file.write_all(bytes).map_err(|_| TokenError::Write)?;
    file.sync_all().map_err(|_| TokenError::Write)?;
    std::fs::set_permissions(
        &temporary,
        std::fs::Permissions::from_mode(POLICY_TOKEN_MODE),
    )
    .map_err(|_| TokenError::Write)?;
    std::fs::rename(&temporary, path).map_err(|_| TokenError::Write)
}

/// Export a policy's issued token, reading no password (FR-018).
///
/// The bytes are the admin's signed artifact, so the export is a copy rather than a
/// mint: nothing is signed here and nothing secret is read. The refusals exist
/// because an export is where an operator learns that a policy names a different
/// agent than the one they asked for.
pub fn export_policy_token(
    layout: &Layout,
    edge: &PolicyEdge,
    agent: &AgentId,
    out: &std::path::Path,
) -> Result<(), TokenError> {
    let (recorded, anchor) = deployment::require(layout).map_err(|_| TokenError::NotProvisioned)?;
    if !edge.verify_issuer(&anchor.key) {
        return Err(TokenError::PolicyIssuer);
    }
    match edge.target() {
        PolicyTarget::Agent(named) if named == *agent => {}
        PolicyTarget::Agent(named) => {
            return Err(TokenError::NotThisAgent {
                policy: edge.id().to_string(),
                names: named.to_string(),
                requested: agent.to_string(),
            });
        }
        PolicyTarget::AnyEnrolled => {
            return Err(TokenError::Cooperative {
                policy: edge.id().to_string(),
            });
        }
    }
    let store = EdgeStore::new(layout, &recorded);
    let issued = store.token_path(edge.id());
    let bytes = std::fs::read(&issued).map_err(|_| TokenError::TokenAbsent {
        policy: edge.id().to_string(),
        path: issued.display().to_string(),
    })?;
    // The export checks what it can prove, and no less. The anchor is already in
    // hand, so a tampered or truncated file is refused *here* rather than shipped to
    // an agent that discovers it at `run` — a refusal an operator can act on is worth
    // one signature check. The policy's standing is still `run`'s to judge: this is a
    // copy, and a copy does not become authority by being exported.
    let artifact = DeliveryArtifact::from_bytes(&bytes).map_err(|_| TokenError::Delivery)?;
    delivery::verify(&artifact, &anchor.key).map_err(|error| TokenError::UnverifiableToken {
        policy: edge.id().to_string(),
        path: issued.display().to_string(),
        reason: error.to_string(),
    })?;
    let header = artifact.header();
    let named = header
        .records()
        .first()
        .and_then(|record| record.policy.clone())
        .ok_or(TokenError::Delivery)?;
    if &named != edge.id() || header.issuer_key_id() != edge.issuer_key_id() {
        return Err(TokenError::TokenIsAnotherPolicys {
            policy: edge.id().to_string(),
            path: issued.display().to_string(),
        });
    }
    write_token(out, &bytes)
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use ksp_backend::admission::Classification;
    use ksp_identity::KeyId;
    use ksp_types::{LeaseCapability, VaultId};
    use std::time::Duration;

    const PASSWORD: &[u8] = b"a long enough password";

    /// The `file` backend with no proof: nothing this host can prove about a run.
    fn unproven_file() -> Admission {
        Admission {
            classification: config::BackendSelection::File {
                root: std::path::PathBuf::from("/tmp/ksp"),
            }
            .classification()
            .unwrap(),
            refusal: Some(ksp_backend::proof::GateRefusal::NoProof),
        }
    }

    /// A classification that admits, for the paths that need a lease.
    ///
    /// No MVP backend on a test host admits: `file` needs a proof this fixture does
    /// not have, and valkey needs a live server. This double says so out loud rather
    /// than pretending the file store has one - the point of the test is the
    /// *sequence*, and the real refusal is asserted separately below.
    fn admitting() -> Admission {
        Admission {
            classification: Classification {
                capability: LeaseCapability::NativeExpiry,
                mechanism: "test double",
                declared_cadence: None,
                proven_cadence: None,
                proof_age: None,
                cleanup_lag: None,
                retention: Some(Duration::from_secs(86_400)),
                state: None,
            },
            refusal: None,
        }
    }

    /// Give this home the capability configuration a real host has.
    ///
    /// The probe is the production path: it writes the strongest configuration
    /// this host can satisfy, and it never overwrites one that exists. Without a
    /// configuration the memory barrier has no adapter, and every unseal refuses
    /// — which is the product's intended first-run behaviour, and therefore
    /// something a fixture that means to exercise an *unseal* has to provide.
    fn configure(layout: &Layout) {
        crate::probe::configure(layout, crate::probe::OverwritePolicy::Replace)
            .expect("the host probe writes a configuration");
    }
    fn provisioned() -> (tempfile::TempDir, Layout, AgentId) {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        configure(&layout);
        crate::admin::init(
            &layout,
            VaultId::new("vault-1"),
            "alice".to_string(),
            KeyId::new("admin-2026"),
        )
        .unwrap();
        crate::admin::user_add(
            &layout,
            PASSWORD,
            KeyId::new("alice-ed25519-1"),
            KeyId::new("alice-x25519-1"),
            None,
            None,
        )
        .unwrap();
        // The agent enrols on its own host; the pin is what Alice's machine reads.
        // The UUID is issued here, once, and the name is metadata.
        let agent = crate::agent::enroll("deploy-bot", &layout)
            .unwrap()
            .enrolment
            .identity;
        // Alice grants this agent this secret, which is what authorises a mint.
        // `false` merges: this is the first grant on a fresh host, so the merge
        // has nothing to union with and the result is the same as a replace.
        crate::admin::policy(
            &layout,
            vec![agent],
            vec![OpaqueSecretId::new("s3cr3t-id-1")],
            false,
        )
        .unwrap();
        crate::secret::set(
            &layout,
            PASSWORD,
            &OpaqueSecretId::new("s3cr3t-id-1"),
            b"db_password",
            b"correct-horse",
        )
        .unwrap();
        (dir, layout, agent)
    }

    #[test]
    fn a_file_backend_refuses_the_lease_with_seven() {
        // Contract: a capability or admission refusal is exit 7. The `file`
        // backend has no deletion mechanism, so it cannot hold a lease, and the
        // refusal must not be reported as a successful mint.
        let (_dir, layout, agent) = provisioned();
        let out = layout.root().join("deploy-bot.token");

        let error = match mint_lease(
            &layout,
            &unproven_file(),
            PASSWORD,
            &agent,
            &OpaqueSecretId::new("s3cr3t-id-1"),
            b"db_password",
            900,
            None,
            &out,
        ) {
            Ok(_) => panic!("a file backend must not hold a lease"),
            Err(error) => error,
        };

        assert_eq!(error.exit_code(), exit::CAPABILITY_REFUSAL);
        assert!(!out.exists(), "a refused mint wrote a token file");
    }

    #[test]
    fn a_mint_writes_the_artifact_and_the_intent_that_authorises_removal() {
        let (_dir, layout, agent) = provisioned();
        let out = layout.root().join("deploy-bot.token");

        let minted = mint_lease(
            &layout,
            &admitting(),
            PASSWORD,
            &agent,
            &OpaqueSecretId::new("s3cr3t-id-1"),
            b"db_password",
            900,
            None,
            &out,
        )
        .unwrap();

        assert!(minted.token.exists(), "no artifact was written");
        assert!(
            minted.intent.exists(),
            "no delete authorisation was written"
        );

        // The artifact decodes and names the exact version it was minted for.
        let bytes = std::fs::read(&minted.token).unwrap();
        let artifact = ksp_identity::DeliveryArtifact::from_bytes(&bytes).unwrap();
        assert_eq!(artifact.header().records().len(), 1);
        assert_eq!(artifact.header().records()[0].version.get(), 1);
        assert_eq!(artifact.header().agent(), &agent);

        // The intent verifies under the *user's* key and names the version the
        // token names: an intent for another version would be refused by S4 as not
        // covering this one. The admin's key would not verify it, which is the
        // point — a lease is the owner's authorisation (spec §3.7 step 2).
        let intent_bytes = std::fs::read(&minted.intent).unwrap();
        let signed: ksp_deletion::SignedIntent = ksp_types::cbor::decode(&intent_bytes).unwrap();
        let unsealed = crate::secret::unseal(&layout, PASSWORD).unwrap();

        // The owner's public half comes out of the same vault the signature used,
        // so the two are checked against each other rather than against a value
        // the test made up.
        let verifier = unsealed.vault.with_signing_secret(|seed| {
            ksp_deletion::EvidenceSigningKey::from_seed(*seed).verifying_key()
        });
        assert!(
            signed.verify(&verifier).is_ok(),
            "the intent must verify under the owner's key"
        );
        assert_eq!(signed.intent.version, 1);
        assert_eq!(signed.intent.level, Level::Agent(agent));

        // A foreign key must not verify it: that is what makes the intent
        // attributable rather than merely present.
        let foreign = ksp_deletion::EvidenceSigningKey::from_seed([9u8; 32]).verifying_key();
        assert!(signed.verify(&foreign).is_err());
    }

    #[test]
    fn a_secret_the_policy_does_not_grant_is_refused_before_anything_is_written() {
        // The policy is the authorisation. A secret it does not name must be
        // refused as a policy denial, and no token may exist afterwards.
        let (_dir, layout, agent) = provisioned();
        let out = layout.root().join("other.token");

        // The secret exists; what is missing is the grant. Storing it first is
        // what makes this a policy refusal rather than a missing record.
        crate::secret::set(
            &layout,
            PASSWORD,
            &OpaqueSecretId::new("not-granted-id"),
            b"db_password",
            b"correct-horse",
        )
        .unwrap();

        let error = match mint_lease(
            &layout,
            &admitting(),
            PASSWORD,
            &agent,
            &OpaqueSecretId::new("not-granted-id"),
            b"db_password",
            900,
            None,
            &out,
        ) {
            Ok(_) => panic!("an ungranted secret must not be minted"),
            Err(error) => error,
        };

        assert_eq!(error.exit_code(), exit::POLICY_DENIAL);
        assert!(!out.exists());
    }

    /// A consumed lease must not be listed as live.
    ///
    /// The ledger knows about revocation and nothing else, so a row that
    /// consulted only the ledger said `live` for a token whose sealed record a
    /// `--consume` run had deleted — while `ksp run` refused the same token with
    /// exit 6. Measured on a real deployment: after a consume, `token list`
    /// reported `standing: live` with a deadline 118 minutes in the future.
    ///
    /// The rule is what this test pins, because the rule is what was wrong. The
    /// integration case needs a deployment, a store and a ledger; the decision
    /// does not.
    #[test]
    fn a_consumed_lease_is_not_listed_as_live() {
        // Absent from the store, no revocation: the copy cannot be fetched, so
        // the listing must not offer it as usable.
        assert_eq!(standing_for(None, Presence::Absent), "consumed");

        // Present and unrevoked is the only `live`.
        assert_eq!(standing_for(None, Presence::Present), "live");
    }

    /// An unreadable record is not evidence of a deletion.
    ///
    /// The tempting shorthand is `Ok(None) => consumed, Err(_) => consumed`,
    /// because both mean "no bytes came back". They are different claims: an
    /// error says this host could not look, and `consumed` says it looked and
    /// found nothing. Reporting the second for the first asserts an absence
    /// nobody established.
    #[test]
    fn an_unreadable_record_is_unknown_not_consumed() {
        let unreadable = standing_for(None, Presence::Unreadable);
        assert!(
            unreadable.starts_with("unknown"),
            "an unreadable record is not a consumed one: {unreadable}"
        );
        assert!(
            !unreadable.contains("consumed"),
            "the listing must not claim a deletion it could not observe: {unreadable}"
        );

        let unreachable = standing_for(None, Presence::Unreachable);
        assert!(
            unreachable.starts_with("unknown"),
            "a store that cannot be opened is not an absent record: {unreachable}"
        );
    }

    /// A revocation wins over presence.
    ///
    /// A token this host marked is not live even when the record is still on
    /// disk: the mark is a decision, and the bytes are an accident of timing.
    /// Ordering the other way would let a revoked token read as `live` for as
    /// long as the sweep had not run.
    #[test]
    fn a_revocation_outranks_presence() {
        let standing = standing_for(Some("token marked"), Presence::Present);
        assert!(
            standing.starts_with("revoked"),
            "a marked token is not live whatever the store holds: {standing}"
        );
    }
}
