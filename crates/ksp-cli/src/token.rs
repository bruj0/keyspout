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
use ksp_identity::{
    DeliveryHeader, MintBinding, MintRefusal, MintRequest, Policy, PolicyRequest, PolicyVerifier,
    SelectedContentKeys, TrustAnchors, UnsignedEnrolment, decode_policy, mint,
};
use ksp_record::{ContentBlob, Record, RecordEnvelope, commit_version};
use ksp_types::{
    ActorId, AgentId, BoundMetadata, ContentKey, DeletionIntent, LeaseCapability, Level,
    OpaqueSecretId, RecordVersion,
};

use crate::admission::Admission;
use crate::config::{self, Layout};
use crate::deployment;
use crate::exit::{self, Outcome};
use crate::keys::StoredEnrolment;
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
        let ledger = ksp_identity::IssuanceLedger::at(layout.issuance_ledger());

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
                let keys = SelectedContentKeys::new(&header, vec![(selected, content_key)])
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

/// What `token list` prints: this host's ledger and its honest scope.
pub fn listing(layout: &Layout) -> Result<crate::output::TokenLedger, TokenError> {
    let ledger = ksp_identity::IssuanceLedger::at(layout.issuance_ledger());
    let listing = ledger
        .listing()
        .map_err(|error| TokenError::Ledger(error.to_string()))?;

    let rows = listing
        .entries
        .iter()
        .map(|entry| crate::output::LedgerRow {
            token_id: entry.issuance.token_id.clone(),
            agent: entry.issuance.agent.to_string(),
            secret: entry.issuance.secret.as_str().to_string(),
            version: entry.issuance.version.0,
            deadline: entry.issuance.deadline,
            policy_revision: entry.issuance.policy_revision,
            standing: match &entry.reason {
                Some(reason) => format!("revoked: {reason}"),
                None => "live".to_string(),
            },
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
    let ledger = ksp_identity::IssuanceLedger::at(layout.issuance_ledger());
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
        )
        .unwrap();
        // The agent enrols on its own host; the pin is what Alice's machine reads.
        // The UUID is issued here, once, and the name is metadata.
        let agent = crate::agent::enroll("deploy-bot", &layout)
            .unwrap()
            .enrolment
            .identity;
        // Alice grants this agent this secret, which is what authorises a mint.
        crate::admin::policy(
            &layout,
            vec![agent],
            vec![OpaqueSecretId::new("s3cr3t-id-1")],
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
}
