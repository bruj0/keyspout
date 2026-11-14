//! `ksp run`: reload a pinned agent, verify, open, confine, deliver.
//!
//! # The order, and who enforces it
//!
//! [`crate::run_gate::gate`] verifies the proof of possession before anything is
//! confined or launched, and applies confinement before the child exists. This
//! module's job is everything *before* that gate: reload the agent's authority
//! from its protected file, verify the issuer's signature on the artifact, and
//! unwrap the delivery.
//!
//! # The private half is borrowed, never owned
//!
//! `delivery::open` takes a raw `&[u8; 32]`, and this is the only place the CLI
//! reaches one. It does so inside [`AgentKeyBundle::with_recipient_secret`], so
//! the bytes are lent to the call and the closure returns only the content keys.
//! There is no route here to a second copy.
//!
//! # There is no second record parser
//!
//! The stored version is decoded by WP13's `decode_record`, which lives beside
//! the encoder. A CLI-side parser would be a second definition of the wire form,
//! which is how a record gets read as something it is not.

use ksp_identity::AgentKeyBundle;
use ksp_identity::delivery::{self, DeliveryArtifact, VerifiedDelivery};
use ksp_identity::pop::{PopPreimage, bucket_start, sign_pop};
use ksp_identity::run::{HostKeys, PresentedProof, RunRequest};
use ksp_key_lifecycle::{KeyRoot, KeyStore};
use ksp_posture::ConfinementSpec;
use ksp_posture::confinement::ConfinementRule;
use ksp_record::decode_record;
use ksp_types::BoundMetadata;

use crate::commands::RunArgs;
use crate::config::{self, Layout};
use crate::exit::{self, Outcome};
use crate::keys::{PinError, StoredEnrolment};
use crate::process::ConfinedProcess;
use crate::run_gate::{Delivery, RunGate, gate};

/// Whether this delivery needs a policy, and whether the one on disk authorises it.
///
/// Runs before the record is opened, so a refused run never touches the plaintext
/// (NFR-002). It reads public material only — the policy and the pinned anchor —
/// so it needs no password (NFR-001).
fn check_policy(layout: &Layout, header: &ksp_identity::DeliveryHeader) -> Result<(), RunError> {
    use ksp_types::Level;

    // Only a delegated value needs an authority above the user.
    if !matches!(header.source_level(), Level::Admin) {
        return Ok(());
    }

    let bytes = std::fs::read(layout.policy_file()).map_err(|_| RunError::PolicyAbsent)?;
    let policy = ksp_identity::decode_policy(&bytes).map_err(|_| RunError::PolicyMalformed)?;

    // The anchor is pinned on this host, never taken from the policy: a key
    // inside the artifact is data, and a policy that supplied its own anchor
    // would verify itself.
    let anchor =
        crate::keys::Anchor::load(&layout.admin_anchor_file()).map_err(|_| RunError::Anchor)?;
    if !policy.verify_issuer(&anchor.key) {
        return Err(RunError::PolicyIssuer);
    }

    policy
        .check_validity(crate::run::now_seconds())
        .map_err(|refusal| match refusal {
            ksp_identity::PolicyRefusal::Expired { not_after, .. } => {
                RunError::PolicyExpired { not_after }
            }
            ksp_identity::PolicyRefusal::NotYetValid { not_before, .. } => {
                RunError::PolicyNotYetValid { not_before }
            }
            // Any other validity refusal is a policy this build cannot read, which
            // is the same remedy as a malformed file: replace it.
            _ => RunError::PolicyMalformed,
        })?;

    // Every record the token names must be granted to this agent. A token that
    // names two records and is granted one is not authorised for the other.
    for record in header.records() {
        if !policy.grants(&record.secret, header.agent()) {
            return Err(RunError::PolicyGrant {
                secret: record.secret.as_str().to_string(),
                agent: header.agent().to_string(),
            });
        }
    }
    Ok(())
}

/// Why a run could not reach the child.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunError {
    /// A protected root drifted, so nothing here will be read.
    ///
    /// Measured before the token, the anchor, the ledger or a key file is
    /// opened: a widened `admin/` is a directory another principal can write,
    /// and a key read from it is not the key this host pinned.
    #[error("no record will be delivered through a drifted layout: {0}")]
    Layout(#[from] crate::layout::LayoutRefusal),
    /// The token file could not be read.
    #[error("the token file could not be read")]
    Token,
    /// The token bytes are not a delivery artifact.
    #[error("the token file is not a delivery artifact")]
    TokenFormat,
    /// The token names a level no delivery is minted at, so there is no level
    /// directory this run could confine the child to.
    #[error("the token names a level no delivery is minted at")]
    Level,
    /// The pinned anchor is missing or unreadable.
    #[error("the pinned admin key could not be read")]
    Anchor,
    /// The artifact was not signed by the pinned admin key.
    #[error("the delivery was not signed by the pinned admin key")]
    Issuer,
    /// The agent's key file is missing, tampered with or does not match the pin.
    #[error("the agent's protected key file is not usable")]
    Keys,
    /// The delivery would not open with this agent's key.
    #[error("the delivery could not be opened with this agent's key")]
    Open,
    /// The record the token names is not in the store.
    #[error("the record the token names is not present in the store")]
    Record,
    /// The proof could not be built for this invocation.
    #[error("the proof of possession could not be built")]
    Proof,
    /// There is no enrolment pin for that agent on this host.
    #[error("no enrolment pin exists for that agent")]
    NotEnrolled,
    /// The selected backend could not be opened.
    #[error("the selected backend could not be opened")]
    Store,
    /// This host minted the token and has since been told to stop honouring it.
    #[error("the token was revoked on this host")]
    Revoked,
    /// The ledger exists but could not be read, so this host cannot say whether
    /// the token is still live.
    #[error("the issuance ledger could not be read")]
    Ledger,
    /// The value came from an admin-written record, and this host holds no policy
    /// to authorise the delivery.
    ///
    /// A delegation that cannot be re-checked is not a delegation: it is a
    /// one-time permission that survives the withdrawal of the authority that
    /// granted it.
    #[error(
        "this delivery came from an admin-written record, and this host holds no policy to \
         authorise it"
    )]
    PolicyAbsent,
    /// The policy on this host could not be decoded.
    #[error("the policy on this host could not be decoded")]
    PolicyMalformed,
    /// The policy was not signed by the pinned admin key.
    #[error("the policy was not signed by the pinned admin key")]
    PolicyIssuer,
    /// The policy is outside its validity window, so it authorises nothing.
    #[error("the policy expired at {not_after}, so it authorises nothing")]
    PolicyExpired {
        /// The instant the policy stopped being valid.
        not_after: u64,
    },
    /// The policy is dated in the future, so it authorises nothing yet.
    ///
    /// Distinct from [`PolicyExpired`](Self::PolicyExpired) and from
    /// [`PolicyMalformed`](Self::PolicyMalformed): the file is a valid policy, and
    /// the remedy is to wait or to correct a clock, not to restore a file.
    #[error("the policy is not valid until {not_before}, so it authorises nothing yet")]
    PolicyNotYetValid {
        /// The instant the policy becomes valid.
        not_before: u64,
    },
    /// The policy does not grant this secret to this agent.
    #[error("the policy does not grant {secret} to agent {agent}")]
    PolicyGrant {
        /// The secret the delivery names.
        secret: String,
        /// The agent the delivery names.
        agent: String,
    },
}

impl RunError {
    /// The exit code this failure maps to.
    pub fn exit_code(&self) -> i32 {
        match self {
            // Everything that means "this host cannot produce the bytes" is the
            // named missing-key-material code.
            Self::Token
            | Self::TokenFormat
            | Self::Anchor
            | Self::Keys
            | Self::Open
            | Self::Record
            | Self::NotEnrolled
            | Self::Store => exit::MISSING_KEY,
            // An artifact not signed by the pinned key claims an authority this
            // host does not grant; a token this host was told to stop honouring
            // is a policy decision, not missing material.
            // A token claiming a level the policy never mints at asks for an
            // authority this host does not grant, which is the same class as a
            // token signed by the wrong key.
            Self::Issuer
            | Self::Revoked
            | Self::Level
            | Self::PolicyAbsent
            | Self::PolicyMalformed
            | Self::PolicyIssuer
            | Self::PolicyExpired { .. }
            | Self::PolicyNotYetValid { .. }
            | Self::PolicyGrant { .. } => exit::POLICY_DENIAL,
            // A ledger that cannot be read is this host's problem, not the
            // token's: no verdict is available, so the run stops as internal.
            Self::Ledger => exit::INTERNAL,
            Self::Proof => exit::UNPROVEN,
            Self::Layout(_) => exit::CAPABILITY_REFUSAL,
        }
    }
}

/// Everything the run path read before the gate.
///
/// `content_key` and the identity fields are here for the consume path, which
/// never uses `plaintext`: S4 delivers through its own `Child` port, in another
/// process, after this one has finished reading.
pub(crate) struct Loaded {
    pub(crate) verified: VerifiedDelivery,
    pub(crate) request: RunRequest,
    pub(crate) preimage: PopPreimage,
    pub(crate) bundle: AgentKeyBundle,
    pub(crate) plaintext: Option<Vec<u8>>,
    pub(crate) content_key: ksp_types::ContentKey,
    pub(crate) agent: ksp_types::AgentId,
    /// The bound metadata of the version this run carried.
    ///
    /// Kept rather than re-derived from the request string: the audit record names
    /// the same vault, level, secret and version the record was opened under, and a
    /// second derivation would be a second answer.
    pub(crate) metadata: BoundMetadata,
    /// The principal on whose authority this lease was minted.
    ///
    /// The audit record names the actor as a principal — an agent is identified by
    /// its enrolment, but the record is about what was done to *whose* secret.
    pub(crate) user: ksp_types::PrincipalId,
    pub(crate) signing_key_id: ksp_identity::KeyId,
    /// Set when this host holds no ledger, so the run cannot tell whether the
    /// token was revoked. Carried rather than swallowed: a silent run would look
    /// like a check that passed.
    pub(crate) standing_note: Option<String>,
    /// The level directory this record lives in, as an absolute path.
    ///
    /// It is derived from the bound metadata, not parsed back out of the request
    /// string, so the path the ruleset grants and the path the record was read
    /// from cannot disagree. The confined child gets this one directory and
    /// neither the store root nor the key root above it.
    pub(crate) level_directory: std::path::PathBuf,
}

/// Reload, verify, open, read the record. Nothing is delivered here.
pub(crate) fn load(args: &RunArgs, layout: &Layout) -> Result<Loaded, RunError> {
    // Before the token file, the anchor, the ledger and the key bundle: every
    // one of them lives under a protected root, and reading from a widened root
    // is reading material this host cannot vouch for.
    if let Some(refusal) = crate::layout::refusal(layout.root()) {
        return Err(RunError::Layout(refusal));
    }
    let token_path = args.token.as_deref().ok_or(RunError::Token)?;
    let bytes = std::fs::read(token_path).map_err(|_| RunError::Token)?;
    let artifact = DeliveryArtifact::from_bytes(&bytes).map_err(|_| RunError::TokenFormat)?;

    // The key is pinned on this host, not taken from the artifact. A key inside
    // the token is data, never an anchor — and the pin is the *user's* enrolled
    // key, because she signed this lease (spec §3.7).
    let signer = crate::deployment::user_verifying_key(layout).map_err(|_| RunError::Anchor)?;
    let verified = delivery::verify(&artifact, &signer).map_err(|_| RunError::Issuer)?;

    let header = verified.header().clone();

    // The ledger this host holds decides whether the token may still be used.
    // Checked before the record is read or the key is used, so a revoked token
    // stops here rather than after it has produced a plaintext.
    let standing = ksp_identity::IssuanceLedger::at(layout.issuance_ledger())
        .standing(header.jti())
        .map_err(|_| RunError::Ledger)?;
    if standing.refuses_run() {
        return Err(RunError::Revoked);
    }
    // A token this host never minted is not an accusation, and a host with no
    // ledger cannot judge one. Both continue, and both say so.
    let standing_note = (!standing.can_judge()).then(|| {
        format!(
            "token {} is not in this host's ledger, so this run cannot tell whether it was revoked",
            header.jti()
        )
    });

    // The policy is checked before the record is opened, and only for a value the
    // admin wrote: an `admin`-level record is a delegation, and a delegation that
    // cannot be re-checked is a one-time permission. A `user`-level record is the
    // user's own, and her signature over this artifact is its authority — reading
    // the policy for it would make her own secrets depend on a file they do not
    // need (FR-003).
    check_policy(layout, &header)?;

    let agent = *header.agent();
    let stored =
        StoredEnrolment::load(&layout.enrolment_file(&agent.to_string())).map_err(|error| {
            match error {
                PinError::Absent => RunError::NotEnrolled,
                _ => RunError::Keys,
            }
        })?;
    if stored.identity != agent {
        return Err(RunError::Keys);
    }

    let store = KeyStore::new(KeyRoot::open(layout.agent_key_root()).map_err(|_| RunError::Keys)?);
    let bundle = store
        .load_agent(&stored.pin())
        .map_err(|_| RunError::Keys)?;

    // The only place this process touches a private half. The closure returns
    // the content keys; the borrowed bytes end with the call.
    let content = bundle
        .with_recipient_secret(|secret| delivery::open(&verified, secret))
        .map_err(|_| RunError::Open)?;

    let selected = header.records().first().ok_or(RunError::TokenFormat)?;
    let metadata = BoundMetadata {
        vault_id: header.vault().clone(),
        user_id: *header.user(),
        level: header.level().clone(),
        secret_id: selected.secret.clone(),
        version: selected.version.get(),
    };
    // Owned, because the consume path needs it after this function returns; the
    // selection itself ends here.
    let content_key = content
        .get(&selected.secret, selected.version)
        .cloned()
        .ok_or(RunError::TokenFormat)?;

    // One decoder, beside the encoder.
    let backend = config::open_file_store(layout).map_err(|_| RunError::Store)?;
    let stored_bytes = ksp_record::version::BlobStore::get(
        &backend,
        ksp_record::RecordPath::of(&metadata).as_str(),
    )
    .map_err(|_| RunError::Record)?
    .ok_or(RunError::Record)?;
    let record = decode_record(&stored_bytes).map_err(|_| RunError::Record)?;

    // The AAD is the bound metadata this run names, so a stored record that
    // describes a different level or version fails to open rather than opening
    // under the wrong description.
    let aad = metadata.bound_aad().map_err(|_| RunError::Record)?;
    let (_name, value) = record
        .blob
        .open(&content_key, &aad)
        .map_err(|_| RunError::Record)?;

    let request = RunRequest {
        jti: header.jti().to_string(),
        record_version: selected.version,
        record_path: ksp_record::RecordPath::of(&metadata).to_string(),
        argv: args
            .child
            .iter()
            .map(|argument| argument.as_bytes().to_vec())
            .collect(),
        now: now_seconds(),
    };
    let preimage = PopPreimage::new(
        request.jti.clone(),
        request.record_version,
        request.record_path.clone(),
        &request.argv,
        bucket_start(request.now),
    )
    .map_err(|_| RunError::Proof)?;

    // `--env-all` delivers the whole record; `--env NAME` names one variable.
    // With neither, nothing is delivered and the child runs for its exit code.
    let level_directory = agent_level_directory(layout, &metadata)?;

    let plaintext = match args.env.as_deref() {
        Some(_) => Some(value),
        None if args.env_all => Some(value),
        None => None,
    };

    Ok(Loaded {
        verified,
        request,
        preimage,
        bundle,
        plaintext,
        content_key,
        agent: *header.agent(),
        metadata: metadata.clone(),
        user: *header.user(),
        signing_key_id: header.agent_signing_key_id().clone(),
        standing_note,
        level_directory,
    })
}

/// Run one `ksp run` invocation.
pub fn run(args: &RunArgs, layout: &Layout) -> Outcome {
    // The capability configuration is read before anything else (T040, FR-003).
    // A malformed or unsafe file refuses here — before the token is opened,
    // before the record is decrypted, before any capability is touched — so the
    // operator is sent to the file rather than to a confinement failure it
    // caused.
    let configuration = match crate::establish::load(layout) {
        Ok(configuration) => configuration,
        Err(refusal) => {
            let _ =
                crate::output::Emitter::new(false, std::io::stderr()).refusal(&refusal.to_string());
            return Outcome::Failed(refusal.exit_code());
        }
    };

    // Consuming is a different sequence, not a flag on the same one: it delivers
    // from another process and then deletes, journals and reports here.
    if args.consume {
        return crate::consume::run(args, layout, configuration.as_ref());
    }

    let loaded = match load(args, layout) {
        Ok(loaded) => loaded,
        Err(error) => return refuse(&error),
    };

    if let Some(note) = &loaded.standing_note {
        let _ = crate::output::Emitter::new(false, std::io::stderr()).refusal(note);
    }

    // The compliant client signs its own proof. The gate checks that the request
    // and the proof agree; it is a check on the request, not a claim about this
    // process's honesty.
    let signature = match sign_pop(loaded.bundle.signing_secret(), &loaded.preimage) {
        Ok(signature) => signature,
        Err(_) => return Outcome::Failed(RunError::Proof.exit_code()),
    };

    let signing_public = loaded.bundle.signing_public();
    let recipient_public = loaded.bundle.recipient_public();
    let keys = HostKeys {
        signing_public: Some(&signing_public),
        recipient_public: Some(&recipient_public),
    };

    // Spend one permitted delivery when the sharer bounded the copy. A plain run
    // leaves the version in place, so this is the counter's only consumer: the
    // bound is what makes a delivery finite, and a delivery that was not counted
    // would let a bound be exceeded by simply not consuming.
    //
    // An unbounded arm has no counter and spending it is a no-op, so a
    // time-bounded lease behaves exactly as it did before.
    if let Ok(store) = config::open_file_store(layout)
        && let Err(_spend) =
            ksp_backend::usebound::spend(store.root(), loaded.verified.header().jti())
    {
        // The counter could not be written. Refusing is the safe direction: a
        // delivery that cannot be counted would spend a use the user never
        // authorised, or leave the bound unenforced.
        return Outcome::Failed(RunError::Store.exit_code());
    }

    let name = args.env.clone().unwrap_or_else(|| "KSP_SECRET".to_string());
    let delivery = loaded.plaintext.map(|value| Delivery::new(name, value));

    // What this host establishes for path confinement, from the configuration
    // the operator wrote (T041). A required capability the host cannot establish
    // refuses here, naming the adapter and the host's reason (FR-028, NFR-004);
    // an optional one proceeds and the absence is stated below.
    let grant = match crate::establish::granted(
        configuration.as_ref(),
        ksp_types::HostCapability::PathConfinement,
    ) {
        Ok(grant) => grant,
        Err(refusal) => {
            let _ =
                crate::output::Emitter::new(false, std::io::stderr()).refusal(&refusal.to_string());
            return Outcome::Failed(refusal.exit_code());
        }
    };
    // An adapter that guarantees nothing is not an adapter that confines: the
    // run proceeds unconfined and says so (FR-036). Calling `establish` on it
    // would refuse instead, and a refusal is the wrong answer for a capability
    // the operator marked `optional` on a host with no mechanism.
    let adapter = if grant.established() {
        crate::establish::confinement(&grant)
    } else {
        None
    };
    let confinement = confinement_for(&loaded.level_directory, grant.requirement());

    let gate_input = RunGate {
        request: &loaded.request,
        proof: Some(PresentedProof {
            preimage: &loaded.preimage,
            signature: &signature,
        }),
        keys,
        confinement: &confinement,
        delivery,
    };

    // The delivery is recorded **before** the gate confines this process, and
    // before the child exists.
    //
    // Confinement is irreversible, and the ruleset grants the child's level and the
    // system paths — not the audit root. A record appended afterwards would need a
    // write the process no longer has, and the delivery would be unrecorded. So the
    // record is durable first, which is also the order FR-044 asks for: no effect
    // without a record.
    //
    // What the record claims is bounded: the delivery passed every check and was
    // authorized at `observed_at`. The child's own exit status is the child's, and
    // this process cannot write it; a caller that needs it has the process status.
    // A refusal after this point (a failed proof, a host that cannot confine) is not
    // silently absorbed either — the gate still refuses, and the exit code says so.
    let target = ksp_types::evidence::AuditTarget::Record {
        vault: loaded.metadata.vault_id.clone(),
        level: loaded.metadata.level.clone(),
        secret: loaded.metadata.secret_id.clone(),
        version: loaded.metadata.version,
    };
    // The acceptance of an unenforced capability rides on the delivery record.
    // It is signed by the actor who accepted it — this agent, with the key it
    // already holds — rather than by the admin, whose private key the agent's
    // account cannot read and must not be able to. The delivery record is
    // written before the gate confines this process, so the acceptance is
    // durable before the effect it describes (FR-044, Misfit N, NFR-009).
    let acceptance = grant.acceptance();

    if let Err(refusal) = crate::audit::record_agent(
        layout,
        &loaded.bundle,
        &crate::audit::AgentRecord {
            actor: loaded.user,
            signer_key_id: loaded.signing_key_id.as_str(),
            operation: ksp_types::evidence::AuditOperation::Deliver,
            target: Some(target),
            outcome: ksp_types::evidence::Outcome::Success,
            exit_code: exit::SUCCESS,
            acceptance: acceptance.clone(),
        },
    ) {
        // No record, no delivery (FR-044). The refusal is named, not generic.
        let _ = crate::output::Emitter::new(false, std::io::stderr()).refusal(&refusal.to_string());
        return Outcome::Failed(refusal.exit_code());
    }

    // NFR-010: a delivery that proceeds with no path confinement says so, in its
    // own output, before the child exists. Leaving it to `ksp status` would mean
    // an operator can launch a delivery without ever seeing it.
    let process = match adapter {
        Some(adapter) => ConfinedProcess::new(adapter),
        None => {
            let _ = crate::output::Emitter::new(false, std::io::stderr()).refusal(&format!(
                "no path confinement is enforced on this host: the {} capability is \
                 `{}` and nothing could be established, so the child runs unconfined",
                ksp_types::HostCapability::PathConfinement.label(),
                // From the grant, not from a literal: the level is the
                // operator's and a hard-coded word here would keep saying
                // `optional` after the configuration said otherwise.
                grant.requirement().label(),
            ));
            ConfinedProcess::unconfined()
        }
    };
    let outcome = gate(gate_input, &process, &process, &args.child);

    // A refusal is recorded **after** the gate, which is possible precisely because
    // a refusal means no ruleset is in force: the proof failed, or the host could
    // not confine, and in both cases this process still has the filesystem rights
    // to write the log. A child that simply exited non-zero is *not* re-recorded —
    // that path is confined, and the child's status is the caller's fact, not a
    // Keyspout operation.
    let code = outcome.code();
    if matches!(
        code,
        exit::POLICY_DENIAL | exit::MISSING_KEY | exit::CAPABILITY_REFUSAL | exit::UNPROVEN
    ) {
        let _ = crate::audit::record_agent(
            layout,
            &loaded.bundle,
            &crate::audit::AgentRecord {
                actor: loaded.user,
                signer_key_id: loaded.signing_key_id.as_str(),
                operation: ksp_types::evidence::AuditOperation::Deliver,
                target: Some(ksp_types::evidence::AuditTarget::Record {
                    vault: loaded.metadata.vault_id.clone(),
                    level: loaded.metadata.level.clone(),
                    secret: loaded.metadata.secret_id.clone(),
                    version: loaded.metadata.version,
                }),
                outcome: ksp_types::evidence::Outcome::Failure,
                exit_code: code,
                acceptance: None,
            },
        );
    }
    let _ = loaded.verified;
    outcome
}

/// Turn a load refusal into an outcome, printing the one that carries a
/// measurement.
///
/// `main` prints the code's generic sentence and nothing else, which is the right
/// rule for a refusal that could carry a value. A drifted layout is not that: it
/// names a path, a mode and an owner, and FR-014 requires the refusal itself to
/// carry them.
pub(crate) fn refuse(error: &RunError) -> Outcome {
    // The rule is "print only what carries no value": `main` prints the code's
    // generic sentence, which is right for a refusal whose typed message could
    // echo a path or an identifier. A drifted layout names a path, a mode and an
    // owner, and FR-014 requires that; a revoked token's sentence is fixed text
    // that names nothing, and FR-009 requires *the revocation* to be what the
    // operator reads.
    match error {
        RunError::Layout(refusal) => {
            let mut stderr = crate::output::Emitter::new(false, std::io::stderr());
            let _ = stderr.refusal(&refusal.to_string());
        }
        RunError::Revoked => {
            let mut stderr = crate::output::Emitter::new(false, std::io::stderr());
            let _ = stderr.refusal(&error.to_string());
        }
        // The policy refusals name a condition and no value: an absent policy, an
        // expiry instant, a secret identifier and an agent identifier. The
        // operator has to read *which* one failed, because the remedy differs —
        // restore the policy, re-sign it, or re-grant the pair.
        RunError::PolicyAbsent
        | RunError::PolicyMalformed
        | RunError::PolicyIssuer
        | RunError::PolicyExpired { .. }
        | RunError::PolicyNotYetValid { .. }
        | RunError::PolicyGrant { .. } => {
            let mut stderr = crate::output::Emitter::new(false, std::io::stderr());
            let _ = stderr.refusal(&error.to_string());
        }
        _ => {}
    }
    Outcome::Failed(error.exit_code())
}

/// The one directory a delivery may reach: the agent level the record lives in.
///
/// # Why the level is checked here rather than trusted
///
/// The ruleset grants whatever directory this returns, so the grant must not
/// depend on an invariant enforced in another subsystem. S2's policy mints only
/// `source = user` → `target = agent-<id>` grants today, and this check is what
/// makes that a property of the *confinement* rather than of the mint path: a
/// header naming `user/` would otherwise hand the child every user record in the
/// vault, because a rule beneath a level directory grants the whole level.
pub(crate) fn agent_level_directory(
    layout: &Layout,
    metadata: &BoundMetadata,
) -> Result<std::path::PathBuf, RunError> {
    if !crate::consume::is_agent_level(&metadata.level) {
        return Err(RunError::Level);
    }
    Ok(layout.store_root().join(ksp_record::RecordPath::directory(
        &metadata.vault_id,
        metadata.user_id,
        Some(&metadata.level),
    )))
}

/// The confinement the run applies before launching, at the level the operator
/// configured.
///
/// # Why system paths are in the ruleset
///
/// Landlock denies by default once any right is handled. A confined child that
/// cannot read `/usr/bin/printenv` or the shared libraries behind it does not
/// run at all, so the loader paths are granted read-only. That grants the child
/// nothing it did not already have: what the ruleset *withholds* is the rest —
/// the user's home, other application data, and every write.
///
/// # Why the store root and the key root are *not* in the ruleset
///
/// They were, and that was the misfit this package exists to fix. A rule beneath
/// the store root grants the whole subtree, so a child confined to it could read
/// `vault.cbor`, every `user` record and every *sibling* agent's level — that is
/// a naming convention with a ruleset over it, not confinement (FR-010/FR-011).
///
/// The child gets the one level directory the record it received lives in, and
/// nothing above it. It does not need the record file: the plaintext arrives in
/// its environment. The key root is never granted: no child has a reason to read
/// a private half, its own or anyone else's.
///
/// That level rule is **read-only**, which is narrower than the design's
/// "read/write there" (§3.8). The narrowing is deliberate: the delete a consume
/// makes runs in the parent process, never in the confined child, so no delivered
/// command has a reason to write the store — and a child that could remove a
/// record could delete the evidence a lease reports on. Recorded rather than
/// silently applied; widening it is a decision, not a default.
///
/// # Why the level is a parameter
///
/// It used to be `required` unconditionally, which is exactly the "level fixed
/// in the code path" FR-027 removes. The level now comes from the configuration
/// and this function takes it as an argument, so no caller can reintroduce a
/// hard-coded answer: the type system forces the decision to be made where the
/// file is read.
///
/// A `required` level still refuses rather than producing an unconfined child
/// that looks like a successful one. What changed is who decides: the operator,
/// in `config.toml`, instead of this function.
pub(crate) fn confinement_for(
    level_directory: &std::path::Path,
    requirement: ksp_types::capability_config::RequirementLevel,
) -> ConfinementSpec {
    let mut rules = Vec::new();
    // The loader and the command the operator named. `read_only` refuses a path
    // that does not exist, so each is checked rather than assumed: a host
    // without `/lib64` is ordinary.
    for system in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"] {
        let path = std::path::Path::new(system);
        if path.is_dir() {
            rules.push(ConfinementRule::read_only(path));
        }
    }
    rules.push(ConfinementRule::read_only(level_directory));
    match requirement {
        ksp_types::capability_config::RequirementLevel::Required => {
            ConfinementSpec::required(rules)
        }
        ksp_types::capability_config::RequirementLevel::Optional => {
            ConfinementSpec::optional(rules)
        }
    }
}

pub(crate) fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::path::Path;

    /// FR-010: a delivery is confined to an *agent* level, so a token naming any
    /// other level is refused before a ruleset can grant it.
    ///
    /// A rule beneath a level directory grants the whole level. `user/` holds
    /// every secret the owner stored, so a header naming it would hand the child
    /// the vault — the widest reading of the misfit this package fixes.
    #[test]
    fn a_token_naming_a_non_agent_level_is_refused_rather_than_granted() {
        let home = tempfile::tempdir().unwrap();
        let layout = Layout::new(home.path());
        let principal =
            ksp_types::PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap();

        for level in [ksp_types::Level::User, ksp_types::Level::Admin] {
            let metadata = BoundMetadata {
                vault_id: ksp_types::VaultId::new("vault-1"),
                user_id: principal,
                level: level.clone(),
                secret_id: ksp_types::OpaqueSecretId::new("s3cr3t-id-1"),
                version: 1,
            };
            assert_eq!(
                agent_level_directory(&layout, &metadata).err(),
                Some(RunError::Level),
                "{level:?} must be refused, not granted"
            );
            assert_eq!(RunError::Level.exit_code(), exit::POLICY_DENIAL);
        }
    }

    /// Misfit A: the ruleset must name the record's own level and nothing above
    /// it.
    ///
    /// A rule beneath the store root grants every subtree, which is how a child
    /// confined "to the store" could still read `vault.cbor` and a sibling
    /// agent's level. The assertion is therefore about absence: the two paths that
    /// used to be granted must not appear at all.
    #[test]
    fn the_ruleset_grants_the_own_level_and_neither_the_store_nor_the_key_root() {
        let home = tempfile::tempdir().unwrap();
        let layout = Layout::new(home.path());
        let level = layout
            .store_root()
            .join("p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-7");

        let spec = confinement_for(
            &level,
            ksp_types::capability_config::RequirementLevel::Required,
        );
        let paths: Vec<&Path> = spec
            .rules()
            .iter()
            .map(|rule| rule.path.as_path())
            .collect();

        assert!(
            paths.contains(&level.as_path()),
            "the record's own level must be reachable: {paths:?}"
        );
        assert!(
            !paths.contains(&layout.store_root().as_path()),
            "the store root grants siblings, the vault and every user record: {paths:?}"
        );
        assert!(
            !paths.contains(&layout.agent_key_root().as_path()),
            "no child has a reason to read a private half: {paths:?}"
        );
        assert!(spec.is_required(), "a delivery cannot be optional");
        assert!(
            spec.rules().iter().all(|rule| !rule.writable),
            "a delivered child gets no write right to any path"
        );
    }
}
