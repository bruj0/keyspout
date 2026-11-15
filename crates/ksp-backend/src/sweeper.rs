//! **Sweeper Arming**: the configuration that says a scheduled sweep exists.
//!
//! # Configuration, not evidence
//!
//! This record says the admin declared a schedule. It does **not** say the job runs,
//! and it authorises nothing: what admits a lease is the signed sweep proof a run
//! writes (misfit C — declared but not installed; misfit M — a declaration the host
//! cannot check). Every reader of this module will be tempted to treat the record as
//! evidence, so every type here says what it is.
//!
//! # Two arms, one word
//!
//! [`crate::arming::ArmRecord`] is **Durable Arming**: a key-free deletion intent
//! written before a token is published. This module is the other act — a schedule the
//! operator installs — and the two share no type, no file and no domain.
//!
//! # What the guards are for
//!
//! - **Scope** (misfits O): a rule broader than the deployment deletes another
//!   principal's leases; one that names no agent level deletes nothing. Both verify as
//!   "the rule exists", so existence is not checked — the *width* is.
//! - **Credential** (misfit Q): the sweep needs delete and list on the agent levels and
//!   write on the journal. Anything wider turns a schedule into a standing privilege,
//!   so a wider credential is refused and the excess right is named.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ksp_types::domains::DOMAIN_SWEEPER_ARMING;
use ksp_types::{PrincipalId, VaultId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The user the installed unit runs as.
///
/// The plan's decision, not a guess: the unit is a system unit owned by the operator
/// and the job runs as this unprivileged account.
pub const SWEEPER_UNIT_USER: &str = "ksp-admin";

/// The binary path a *printed* template carries.
///
/// A template is a proposal the operator may edit: `ksp` must not guess the path
/// of a file it is not running from, so the printed artifact names a conventional
/// location and says it is a placeholder.
///
/// It is **not** what an installed job carries. `--install` writes a job and
/// loads it, which is a claim that the job will run, so the path must be the
/// binary that is actually executing. Naming this constant in an installed
/// artifact produced a plist pointing at `/usr/local/bin/ksp` on a host where
/// Homebrew had installed to `/opt/homebrew/bin/ksp`; the job failed with
/// `ENOENT` on its first firing, and `installed:` had already read as success.
pub const SWEEPER_BINARY_PLACEHOLDER: &str = "/usr/local/bin/ksp";

/// What a printed template says about its binary path.
pub const SWEEPER_BINARY_PLACEHOLDER_NOTE: &str =
    "the binary path above is a placeholder: replace it with the absolute path of your ksp";

/// The operating system whose scheduler the arming names.
///
/// A parameter rather than a `cfg` read inside the mapping: the host gate runs on
/// macOS and the VM gate runs on Linux, so a compile-time branch would leave one
/// of the two mappings untested in either run. Passing the platform makes both
/// mappings a pure function of two inputs that tests can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPlatform {
    /// `systemd`, `crontab`.
    Linux,
    /// `launchd`.
    Darwin,
}

impl HostPlatform {
    /// The platform this build is running on.
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::Darwin
        } else {
            Self::Linux
        }
    }
}

/// Escape the five XML metacharacters.
///
/// The property list is the only XML this build writes. A `KSP_HOME` with an `&`
/// or a `<` in it would otherwise produce a file `launchd` refuses to parse, and
/// the refusal would name a line in a template the operator did not write.
fn xml_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// The form the selected backend provides for a periodic job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArmingKind {
    /// A systemd service plus timer, on a local `file` store.
    Systemd,
    /// A `launchd` property list, on a local `file` store on macOS.
    ///
    /// Darwin has no systemd, so an artifact that named it described a job nobody
    /// could install while the cadence it declares is what admits a lease.
    Launchd,
    /// A crontab entry, on an `sftp` host.
    Crontab,
    /// A provider lifecycle rule, on an object store that offers one.
    ProviderLifecycle,
    /// A job the operator runs from somewhere this host cannot see.
    ExternalJob,
}

impl ArmingKind {
    /// The name a report prints.
    pub fn label(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::Launchd => "launchd",
            Self::Crontab => "crontab",
            Self::ProviderLifecycle => "provider-lifecycle",
            Self::ExternalJob => "external-job",
        }
    }

    /// The kind FR-003 assigns to a backend on a platform, when this build knows
    /// the backend.
    ///
    /// `file` is the one row the platform decides: a local store on Linux is swept
    /// by a systemd timer, and on Darwin by a `launchd` job. The other rows name a
    /// remote mechanism and do not move with the host.
    ///
    /// This is the default, not the only accepted kind: see
    /// [`accepted_for_backend`](Self::accepted_for_backend).
    pub fn for_backend(backend: &str, platform: HostPlatform) -> Option<Self> {
        match (backend, platform) {
            ("file", HostPlatform::Linux) => Some(Self::Systemd),
            // Darwin has no systemd: the same backend is swept by a launchd job.
            ("file", HostPlatform::Darwin) => Some(Self::Launchd),
            ("sftp", _) => Some(Self::Crontab),
            ("s3", _) => Some(Self::ProviderLifecycle),
            ("valkey", _) => Some(Self::ExternalJob),
            _ => None,
        }
    }

    /// Whether this backend can carry this kind, on any platform.
    ///
    /// Deliberately not "equals the backend's default". The default moves with the
    /// host, and FR-005 keeps both local schedulers accepted for `file`
    /// everywhere: an operator on a Mac may still ask for a systemd unit to
    /// install on a Linux box, and a Linux operator may ask for a plist. What is
    /// refused is a kind the backend cannot use at all, such as `crontab` on a
    /// local store.
    pub fn accepted_for_backend(self, backend: &str) -> bool {
        matches!(
            (backend, self),
            ("file", Self::Systemd | Self::Launchd)
                | ("sftp", Self::Crontab)
                | ("s3", Self::ProviderLifecycle)
                | ("valkey", Self::ExternalJob)
        )
    }

    /// Whether this kind can be measured from this host at all.
    pub fn is_measurable(self) -> bool {
        matches!(self, Self::Systemd)
    }
}

/// One permission a credential carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Right {
    /// Removing a version's path.
    Delete,
    /// Naming the versions a sweep would remove.
    List,
    /// Writing the deletion journal.
    Write,
    /// Reading a stored record. The sweep never needs it (NFR-003).
    Read,
    /// Changing the store's configuration or access policy.
    Admin,
    /// Owning the store: every right, including granting others.
    Owner,
}

impl Right {
    /// The name a report and a refusal print.
    pub fn label(self) -> &'static str {
        match self {
            Self::Delete => "delete",
            Self::List => "list",
            Self::Write => "write",
            Self::Read => "read",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }
}

/// One grant: a right and what it reaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// The right the credential carries.
    pub right: Right,
    /// The path prefix, journal name or principal the right reaches.
    pub scope: String,
}

/// The identity the armed job authenticates as, and what that identity may do.
///
/// Declared, not discovered: this build has no way to read an SFTP ACL or an IAM
/// policy, so the admin states the binding and the guards check its *shape*. A
/// declaration that is wrong is refused on the next fact that contradicts it — the
/// sweep fails and writes a failure proof — rather than being trusted because it was
/// recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialBinding {
    /// The account, principal or role the job runs as.
    pub identity: String,
    /// What that identity may do, as declared.
    pub grants: Vec<Grant>,
}

/// Why an arming could not be recorded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArmingError {
    /// The interval is zero, or the text is not an interval.
    #[error("an arming interval must be at least one second; got '{0}'")]
    Interval(String),
    /// The scope is not a prefix of this deployment's store.
    #[error(
        "the scope '{scope}' is outside this deployment (p/{vault}): a sweep there would act on \
         records this deployment does not own"
    )]
    ScopeOutsideDeployment {
        /// The scope as written.
        scope: String,
        /// The vault this deployment owns.
        vault: String,
    },
    /// The scope covers levels a sweep must not touch.
    #[error("the scope '{scope}' is broader than a sweep may act on: {reason}")]
    ScopeTooBroad {
        /// The scope as written.
        scope: String,
        /// Which levels it would have reached.
        reason: String,
    },
    /// The scope parses but is not the shape admission compares against.
    ///
    /// Authority-neutral on purpose: the accepted shape is the same for both
    /// signing authorities, and the caller renders the message because what an
    /// operator should do next differs between an admin arming and a user
    /// arming. Carrying `accepted` here keeps one definition of the shape
    /// instead of letting each renderer reconstruct it.
    #[error(
        "the scope '{scope}' is not the shape admission reads; this deployment admits \
         '{accepted}', and a scope that parses but is not that shape reaches no lease"
    )]
    ScopeAdmissionUnreadable {
        /// The scope as written.
        scope: String,
        /// The shape this deployment admits.
        accepted: String,
    },
    /// The credential carries a right the sweep does not need, or reaches too far.
    #[error("the credential '{identity}' is wider than a sweep needs: {excess}")]
    CredentialTooWide {
        /// The declared identity.
        identity: String,
        /// The right and range that makes it too wide.
        excess: String,
    },
    /// The binding names nothing, which enforces nothing (misfit K).
    #[error("the credential binding names no identity, so it enforces nothing")]
    CredentialNamesNothing,
    /// No rights were declared, so the binding's width is unknown.
    #[error("the credential binding declares no rights; state them so the width can be checked")]
    CredentialUnstated,
    /// The kind does not belong to the selected backend.
    #[error("the {kind} kind does not belong to a {backend} backend")]
    KindMismatch {
        /// The recorded kind.
        kind: &'static str,
        /// The selected backend.
        backend: String,
    },
    /// The record is missing a field it needs to mean anything.
    #[error("the arming record is incomplete: {0}")]
    Incomplete(&'static str),
    /// A path an installed job would carry is not absolute.
    ///
    /// A scheduled job runs with a working directory this build does not choose:
    /// `launchd` uses `/`. A relative path in the artifact therefore names a
    /// different file than it names here, and the job fails on its first firing
    /// with nothing on screen to say why. Refusing is the only honest answer,
    /// because the alternative is an artifact that reads as installed and runs
    /// nothing.
    #[error(
        "an installed job cannot carry the relative path '{value}' as its {field}: a scheduled \
         job runs with a working directory ksp does not choose, so a relative path names a \
         different file than it does here. Pass an absolute path, or set {variable}"
    )]
    RelativePath {
        /// Which field the path came from.
        field: &'static str,
        /// The environment variable that would make it absolute.
        variable: &'static str,
        /// The value that was refused.
        value: String,
    },
    /// Encoding or decoding failed.
    #[error("the arming record could not be encoded")]
    Encoding,
}

/// A sweep scope, parsed: whose namespace, which level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepScope {
    /// The vault segment the scope names.
    pub vault: String,
    /// The principal whose namespace the scope is inside.
    pub principal: PrincipalId,
    /// Whether the scope covers every agent level or one named agent.
    pub level: ScopeLevel,
    /// The scope exactly as the admin wrote it, so a report echoes the input.
    pub text: String,
}

/// Which agent level a scope reaches.
///
/// There is one admissible shape, `agent-*`, and it reaches every agent level
/// under the principal. A scope naming one agent is refused by
/// [`admits_file_admission`] rather than narrowed to, so no narrower level is
/// representable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeLevel {
    /// Every agent level under the principal.
    EveryAgent,
}

/// The scope a deployment of `vault` and `principal` admits.
///
/// This is the **Canonical Admission Scope**: the one string `file` admission
/// compares a recorded arming against. It is written here and nowhere else, so
/// the parser and the admission check cannot disagree about the shape.
pub fn canonical_admission_scope(vault: &str, principal: &PrincipalId) -> String {
    format!("p/{vault}/{principal}/agent-*")
}

/// Whether `scope` is the shape this deployment admits, or `Err` naming it.
///
/// The predicate **refuses**; it never rewrites. Normalising `agent-<uuid>` to
/// `agent-*` would make the command succeed while silently widening what a
/// sweep may delete (misfit B), so the caller is told what was accepted and
/// decides what to do about it.
///
/// A scope deeper than the canonical shape is accepted: `agent-*/db-password`
/// is narrower than `agent-*`, and narrowing is what an operator may do.
///
/// The deployment is a parameter so the `Err` can name *this* deployment's
/// accepted shape. A predicate that could only return a generic template would
/// leave every caller to build the concrete one, which is how two definitions
/// of the shape appear in the first place.
pub fn admits_file_admission(
    scope: &str,
    vault: &str,
    principal: &PrincipalId,
) -> Result<(), String> {
    let accepted = canonical_admission_scope(vault, principal);
    let trimmed = scope.trim_end_matches('/');
    // The canonical scope is the definition, so the comparison is against it
    // rather than against a second copy of the shape. A scope equal to it, or
    // deeper than it, is admissible; anything else is refused with the shape.
    if trimmed == accepted || trimmed.starts_with(&format!("{accepted}/")) {
        Ok(())
    } else {
        Err(accepted)
    }
}

impl SweepScope {
    /// Parse `<p>/<vault>/<principal-uuid>/<agent-*>`, and nothing deeper.
    ///
    /// The rules are the misfit O guards: the scope must be inside this
    /// deployment's store, must name this deployment's principal, and must name an
    /// agent level — a broader scope deletes another principal's leases, and
    /// anything above the agent levels deletes the levels a sweep does not own.
    ///
    /// # The scope is a level, never a particular secret
    ///
    /// A sweep deletes versions inside a level; it is not told which record to
    /// delete. A scope with a segment after the level therefore names something the
    /// sweep cannot act on, and an earlier version of this function accepted it: it
    /// inspected the level segment and never checked the arity, so
    /// `agent-*/db-password` parsed to [`ScopeLevel::EveryAgent`] and the trailing
    /// segment was silently dropped. The command armed, exited `0`, and the
    /// capability never moved — `gc` then reported that no armed record was read
    /// while one existed.
    ///
    /// The guard sits here rather than inside the level match because the rule is
    /// about the arity, not about which level was named: any suffix is refused, and
    /// it is refused before the level is interpreted.
    pub fn parse(text: &str, vault: &VaultId, owner: PrincipalId) -> Result<Self, ArmingError> {
        let trimmed = text.trim_end_matches('/');
        let segments: Vec<&str> = trimmed.split('/').collect();
        if segments.first() != Some(&"p") || segments.get(1) != Some(&vault.as_str()) {
            return Err(ArmingError::ScopeOutsideDeployment {
                scope: text.to_string(),
                vault: vault.as_str().to_string(),
            });
        }
        match segments.get(2) {
            Some(principal) if *principal == owner.to_string() => {}
            Some(_) => {
                return Err(ArmingError::ScopeOutsideDeployment {
                    scope: text.to_string(),
                    vault: vault.as_str().to_string(),
                });
            }
            None => {
                return Err(ArmingError::ScopeTooBroad {
                    scope: text.to_string(),
                    reason: "it stops at the vault, so it would sweep every level including the \
                             user's and the admin's"
                        .to_string(),
                });
            }
        }
        let Some(level) = segments.get(3) else {
            return Err(ArmingError::ScopeTooBroad {
                scope: text.to_string(),
                reason: "it stops at the principal, so it would sweep the user and admin levels"
                    .to_string(),
            });
        };
        let level = match *level {
            "agent-*" => ScopeLevel::EveryAgent,
            other => match other.strip_prefix("agent-") {
                Some(_uuid) => {
                    // Misfit A: it parses, and it reaches no lease. The operator
                    // is told the shape admission reads instead of being left
                    // with a refusal about a sweep proof that never appears.
                    //
                    // The shape is not restated here: the predicate returns it,
                    // so this refusal and the admission comparison share one
                    // definition and cannot drift apart.
                    let Err(accepted) = admits_file_admission(text, vault.as_str(), &owner) else {
                        // Unreachable: a scope that reached this arm is not the
                        // canonical shape, so the predicate refuses it. Reported
                        // as a defect in the pair rather than silently accepted.
                        return Err(ArmingError::ScopeAdmissionUnreadable {
                            scope: text.to_string(),
                            accepted: canonical_admission_scope(vault.as_str(), &owner),
                        });
                    };
                    return Err(ArmingError::ScopeAdmissionUnreadable {
                        scope: text.to_string(),
                        accepted,
                    });
                }
                None => {
                    return Err(ArmingError::ScopeTooBroad {
                        scope: text.to_string(),
                        reason: format!("'{other}' is not an agent level"),
                    });
                }
            },
        };
        // The arity guard, after the level is interpreted rather than before it.
        //
        // Order matters: a specific agent level returns above with its own
        // refusal (`ScopeAdmissionUnreadable`, naming `agent-*`), and that reason
        // is the more useful one — it tells the operator the shape admission
        // reads. Checking the arity first would have replaced it with a refusal
        // about the suffix, which is true and less actionable. Only a scope that
        // *is* an accepted level and still carries a suffix reaches here.
        if segments.len() > 4 {
            return Err(ArmingError::ScopeTooBroad {
                scope: text.to_string(),
                reason: format!(
                    "a sweep scope is a level, not a record: the accepted scope is '{}', and \
                     '{}' names something inside the level",
                    canonical_admission_scope(vault.as_str(), &owner),
                    segments[4..].join("/")
                ),
            });
        }
        Ok(Self {
            vault: vault.as_str().to_string(),
            principal: owner,
            level,
            text: trimmed.to_string(),
        })
    }
}

impl CredentialBinding {
    /// Check the binding's width against the scope the arming names.
    ///
    /// The permitted set is exactly what a sweep does: delete and list inside the
    /// arming's own scope, and write on the journal. Everything else is refused, and
    /// the refusal names the right rather than the rule.
    pub fn check(&self, scope: &SweepScope) -> Result<(), ArmingError> {
        if self.identity.trim().is_empty() {
            return Err(ArmingError::CredentialNamesNothing);
        }
        // A root or owner identity is refused before its grants are read: an
        // identity that can become anything is wider than any grant list.
        let identity = self.identity.trim().to_ascii_lowercase();
        if matches!(
            identity.as_str(),
            "root" | "0" | "admin" | "administrator" | "owner" | "superuser"
        ) {
            return Err(ArmingError::CredentialTooWide {
                identity: self.identity.clone(),
                excess:
                    "the identity owns the store, which carries every right the sweep never needs"
                        .to_string(),
            });
        }
        if self.grants.is_empty() {
            return Err(ArmingError::CredentialUnstated);
        }
        for grant in &self.grants {
            match grant.right {
                Right::Delete | Right::List => {
                    // The grant may be equal to the armed scope or narrower than it. A
                    // grant *above* it is the dangerous direction: delete at the vault
                    // reaches the user and admin levels the sweep must not touch.
                    let reach = grant.scope.trim_end_matches('/');
                    if !within(reach, &scope.text) {
                        return Err(ArmingError::CredentialTooWide {
                            identity: self.identity.clone(),
                            excess: format!(
                                "{} reaches '{}', beyond the armed scope '{}'",
                                grant.right.label(),
                                grant.scope,
                                scope.text
                            ),
                        });
                    }
                }
                Right::Write => {
                    if grant.scope.trim_end_matches('/') != "journal" {
                        return Err(ArmingError::CredentialTooWide {
                            identity: self.identity.clone(),
                            excess: format!(
                                "write reaches '{}'; a sweep writes only the journal",
                                grant.scope
                            ),
                        });
                    }
                }
                wider => {
                    return Err(ArmingError::CredentialTooWide {
                        identity: self.identity.clone(),
                        excess: format!(
                            "it carries '{}', which the sweep does not need: it opens no record's \
                             plaintext and changes no configuration",
                            wider.label()
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Whether `reach` is the same as `armed` or deeper than it.
///
/// A trailing `*` in the armed scope matches one segment with that prefix, because
/// `agent-*` is the prefix the operator arms and `agent-<uuid>` is the level it covers:
/// a literal prefix comparison would refuse the least-privilege binding the spec asks
/// for, which is the refusal that teaches an operator to declare something wider.
fn within(reach: &str, armed: &str) -> bool {
    let mut reach = reach.split('/');
    for segment in armed.split('/') {
        let Some(next) = reach.next() else {
            return false;
        };
        let matches = match segment.strip_suffix('*') {
            Some(prefix) => next.starts_with(prefix),
            None => next == segment,
        };
        if !matches {
            return false;
        }
    }
    // Every armed segment consumed. The grant must stop here: a grant with
    // segments left over names something *inside* the armed level, and the sweep
    // deletes versions inside a level rather than a record the grant points at.
    // Accepting the leftover made a grant of `agent-*/db-password` "within"
    // `agent-*`, which taught the operator that a narrower binding was honoured
    // when it was not.
    reach.next().is_none()
}

/// The deterministic identity of one backend-plus-scope arming.
///
/// Deterministic because FR-030 replaces under *one* identity: two armings for one
/// scope must collide here rather than race as two jobs.
pub fn arming_id(backend: &str, scope: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(backend.as_bytes());
    digest.update([0u8]);
    digest.update(scope.trim_end_matches('/').as_bytes());
    let bytes = digest.finalize();
    bytes[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Everything one arming record is built from.
///
/// A struct rather than ten parameters: the fields travel together in every caller, and
/// a positional list of two strings, a vault, a kind and two numbers is one transposition
/// away from recording the wrong thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmingSpec<'a> {
    /// The backend the schedule serves.
    pub backend: &'a str,
    /// The vault this deployment owns.
    pub vault: &'a VaultId,
    /// The form of schedule.
    pub kind: ArmingKind,
    /// The unit or job name the operator installs under.
    pub identifier: &'a str,
    /// How often the job is declared to run.
    pub interval_secs: u64,
    /// The prefix the job sweeps.
    pub scope: &'a str,
    /// The credential the job runs under.
    pub credential: CredentialBinding,
    /// The principal the arming is recorded for.
    pub principal: PrincipalId,
    /// The writer's clock when it was recorded.
    pub recorded_at: i64,
    /// The key ID that signed it.
    pub signer_key_id: &'a str,
    /// Whether the user signed it, rather than the admin.
    pub user_signed: bool,
}

/// One recorded sweeper arming: configuration, signed by the admin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweeperArming {
    /// The deterministic identity: `(backend, scope)`.
    pub arming_id: String,
    /// The backend this schedule serves.
    pub backend: String,
    /// The form of schedule.
    pub kind: ArmingKind,
    /// The unit name, crontab user or job identifier the operator installs under.
    pub identifier: String,
    /// How often the job is declared to run.
    pub interval_secs: u64,
    /// The prefix the job sweeps.
    pub scope: String,
    /// The credential the job runs under.
    pub credential: CredentialBinding,
    /// The principal the arming is recorded for.
    ///
    /// In this build that is the tenant, not the admin who signed it: the deployment
    /// records a principal for each role, and `signer_key_id` is what says who wrote
    /// the record.
    pub principal: PrincipalId,
    /// The writer's clock when it was recorded.
    pub recorded_at: i64,
    /// The key ID that signed it.
    pub signer_key_id: String,
    /// Whether the user signed this arming, rather than the admin.
    ///
    /// The artifact a user installs runs her own sweep, which signs as her and
    /// needs no admin key. A job that ran the admin command would fail on a host
    /// where she cannot read `admin/`, or attribute her deletions to the admin.
    ///
    /// `#[serde(default)]` so an arming written before this field decodes as an
    /// admin arming, which is what every earlier record was.
    #[serde(default)]
    pub user_signed: bool,
}

impl SweeperArming {
    /// Build and validate one arming.
    pub fn new(spec: ArmingSpec<'_>) -> Result<Self, ArmingError> {
        let ArmingSpec {
            backend,
            vault,
            kind,
            identifier,
            interval_secs,
            scope,
            credential,
            principal,
            recorded_at,
            signer_key_id,
            user_signed,
        } = spec;
        if interval_secs == 0 {
            return Err(ArmingError::Interval(interval_secs.to_string()));
        }
        if identifier.trim().is_empty() {
            return Err(ArmingError::Incomplete(
                "the identifier the job installs under",
            ));
        }
        if signer_key_id.trim().is_empty() {
            return Err(ArmingError::Incomplete("the signing key ID"));
        }
        if !kind.accepted_for_backend(backend) {
            return Err(ArmingError::KindMismatch {
                kind: kind.label(),
                backend: backend.to_string(),
            });
        }
        let parsed = SweepScope::parse(scope, vault, principal)?;
        credential.check(&parsed)?;
        Ok(Self {
            arming_id: arming_id(backend, &parsed.text),
            backend: backend.to_string(),
            kind,
            identifier: identifier.to_string(),
            interval_secs,
            scope: parsed.text,
            credential,
            principal,
            recorded_at,
            signer_key_id: signer_key_id.to_string(),
            user_signed,
        })
    }

    /// Whether this arming's schedule can be measured from this host.
    pub fn measurable(&self) -> bool {
        self.kind.is_measurable()
    }

    /// The artifact an install writes, with both paths checked.
    ///
    /// This is the only constructor an install may use. [`launchd_plist`] and
    /// [`systemd_unit`] render whatever they are given, because a *printed*
    /// template is a proposal the operator edits. An install is a claim that the
    /// job will run, so a relative path is refused here rather than written into
    /// a file that `launchd` or `systemd` will fail to execute with no message.
    ///
    /// # Errors
    ///
    /// [`ArmingError::RelativePath`] when `binary` or `home` is not absolute. The
    /// error names the field and the variable that would make it absolute, so the
    /// caller is told what to change rather than that something was wrong.
    ///
    /// [`ArmingError::KindMismatch`] is not returned here: a kind this host does
    /// not install yields `None`, and the caller refuses with its own message
    /// because only the caller knows which platform it is on.
    ///
    /// [`launchd_plist`]: Self::launchd_plist
    /// [`systemd_unit`]: Self::systemd_unit
    pub fn installed_artifact(
        &self,
        binary: &str,
        home: &str,
    ) -> Result<Option<String>, ArmingError> {
        // Absolute, not merely non-empty: an empty path is also refused, and the
        // message is the same one, because both name a file the job cannot find.
        if !std::path::Path::new(binary).is_absolute() {
            return Err(ArmingError::RelativePath {
                field: "binary",
                variable: "PATH",
                value: binary.to_string(),
            });
        }
        if !std::path::Path::new(home).is_absolute() {
            return Err(ArmingError::RelativePath {
                field: "KSP_HOME",
                variable: "KSP_HOME",
                value: home.to_string(),
            });
        }
        Ok(self
            .launchd_plist(binary, home)
            .or_else(|| self.systemd_unit(binary, home)))
    }

    /// The `launchd` property list this arming installs.
    ///
    /// `ksp backend arm-sweep --install` writes it under the operator's own home
    /// and loads it. The content is the same whether ksp writes it or an operator
    /// copies it by hand.
    ///
    /// `binary` and `home` are both supplied by the caller, and both must be
    /// absolute. A template is a proposal, so a printed artifact may carry
    /// [`SWEEPER_BINARY_PLACEHOLDER`]; an installed artifact may not, because
    /// `--install` claims the job will run. `home` is the `KSP_HOME` the job must
    /// carry: a relative `KSP_HOME` resolves against launchd's working directory,
    /// which is `/`, so `.ksp` would name `/.ksp` and the job would sweep nothing.
    pub fn launchd_plist(&self, binary: &str, home: &str) -> Option<String> {
        if self.kind != ArmingKind::Launchd {
            return None;
        }
        Some(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!--
  Keyspout sweep — configuration, not evidence.
  The signed sweep proof a run writes is what admits a lease; this job only says
  the admin recorded a schedule ({backend}, {kind}).
  KSP_HOME must name this host's home as an absolute path: ksp does not guess a
  path it was not given, and launchd runs this job with `/` as its working
  directory, so a relative value would name a directory that does not exist.
  launchd skips a firing while the machine is asleep or while the previous run is
  still going, so one missing run is not evidence that the schedule is broken.
  There is no user key here: a LaunchAgent runs as the account that loads it and a
  LaunchDaemon runs as root, so install it under the account that owns KSP_HOME.
  `ksp backend arm-sweep --install` writes this file under the operator's own
  home and loads it with `launchctl bootstrap`. An install is a declaration, not
  evidence: the capability stays None until a run writes a signed sweep proof.
-->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{identifier}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{binary}</string>
    <string>secret</string>
    <string>gc</string>{user_args}
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>KSP_HOME</key>
    <string>{home}</string>
  </dict>
  <key>StartInterval</key>
  <integer>{interval}</integer>
</dict>
</plist>
"#,
            backend = xml_escape(&self.backend),
            kind = self.kind.label(),
            identifier = xml_escape(&self.identifier),
            binary = xml_escape(binary),
            home = xml_escape(home),
            interval = self.interval_secs,
            user_args = self.user_program_arguments_xml(home),
        ))
    }

    /// The `User=` line a unit carries.
    ///
    /// A user arming's job runs as the account that owns the home, and this build
    /// does not know that account's name, so it names none: `systemd --user` and a
    /// unit installed under the user's own account both inherit it. An admin
    /// arming keeps the fixed sweep account.
    fn unit_user_line(&self) -> String {
        if self.user_signed {
            // No `User=`: a user unit runs as the account that installs it, and
            // naming a fixed account here would run her sweep as someone else.
            "# This job runs as the account that installs it: it is the user's own sweep."
                .to_string()
        } else {
            format!("User={SWEEPER_UNIT_USER}")
        }
    }

    /// The extra argv a user arming's job needs, as a shell fragment.
    ///
    /// `--user-arming` is what makes the run sign as the user instead of the
    /// admin, and `--passphrase-file` is what lets it run with no terminal. The
    /// path is derived from the home the operator installs under, so the artifact
    /// carries a value they can see and change rather than a guess.
    fn user_exec_arguments(&self, home: &str) -> String {
        if self.user_signed {
            format!(" --user-arming --passphrase-file {home}/sweep.passphrase")
        } else {
            String::new()
        }
    }

    /// The same extra argv, as plist `<string>` elements.
    fn user_program_arguments_xml(&self, home: &str) -> String {
        if self.user_signed {
            format!(
                "\n    <string>--user-arming</string>\n    <string>--passphrase-file</string>\n    <string>{}</string>",
                xml_escape(&format!("{home}/sweep.passphrase"))
            )
        } else {
            String::new()
        }
    }

    /// The unit template this arming installs.
    ///
    /// `binary` and `home` are supplied by the caller, for the same reason the
    /// plist takes them: a printed template may name a placeholder, and an
    /// installed artifact must name the binary that is actually running and an
    /// absolute `KSP_HOME`.
    pub fn systemd_unit(&self, binary: &str, home: &str) -> Option<String> {
        if self.kind != ArmingKind::Systemd {
            return None;
        }
        Some(format!(
            "# Keyspout sweep — configuration, not evidence.\n\
             # The signed sweep proof a run writes is what admits a lease; this unit only\n\
             # says the admin recorded a schedule.\n\
             # KSP_HOME must name this host's home as an absolute path: ksp does not guess\n\
             # a path it was not given.\n\
             # Install as root, once:  systemctl link {unit}  &&  systemctl enable --now {unit}\n\
             [Unit]\n\
             Description=Keyspout lease sweep ({backend}, {identifier})\n\
             After=network.target\n\
             \n\
             [Service]\n\
             Type=oneshot\n\
             {user_line}\n\
             # The armed job uses only this credential (FR-034): {credential}\n\
             ExecStart={binary} secret gc{user_args}\n\
             \n\
             [Timer]\n\
             OnUnitActiveSec={interval}s\n\
             # systemd defaults timer accuracy to 1 min, which would consume the measurement\n\
             # grace; the proof's freshness bound is computed from a run that must land close\n\
             # to its interval.\n\
             AccuracySec=1s\n\
             \n\
             [Install]\n\
             WantedBy=timers.target\n",
            unit = self.identifier,
            backend = self.backend,
            identifier = self.identifier,
            user_line = self.unit_user_line(),
            credential = self.credential.identity,
            binary = binary,
            interval = self.interval_secs,
            user_args = self.user_exec_arguments(home),
        ))
    }
}

/// One arming with its admin signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedArming {
    /// The record.
    pub arming: SweeperArming,
    /// The admin's signature over the domain and the record's canonical bytes.
    pub signature: Vec<u8>,
}

impl SignedArming {
    /// Sign an arming. The signature covers the record and the domain, not itself.
    pub fn sign(arming: SweeperArming, signer: &SigningKey) -> Result<Self, ArmingError> {
        let preimage = Self::preimage(&arming)?;
        Ok(Self {
            arming,
            signature: signer.sign(&preimage).to_bytes().to_vec(),
        })
    }

    /// Whether the signature is the admin's over these bytes.
    pub fn verify(&self, key: &VerifyingKey) -> bool {
        let Ok(preimage) = Self::preimage(&self.arming) else {
            return false;
        };
        let Ok(signature) = <[u8; 64]>::try_from(self.signature.as_slice()) else {
            return false;
        };
        key.verify_strict(&preimage, &Signature::from_bytes(&signature))
            .is_ok()
    }

    /// The canonical bytes this host writes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ArmingError> {
        ksp_types::cbor::encode(self).map_err(|_| ArmingError::Encoding)
    }

    /// Read a record this host wrote. Decoded, not trusted: verification is the caller's.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArmingError> {
        ksp_types::cbor::decode(bytes).map_err(|_| ArmingError::Encoding)
    }

    fn preimage(arming: &SweeperArming) -> Result<Vec<u8>, ArmingError> {
        let mut preimage = Vec::from(DOMAIN_SWEEPER_ARMING);
        preimage.extend(ksp_types::cbor::encode(arming).map_err(|_| ArmingError::Encoding)?);
        Ok(preimage)
    }
}

/// What a host could measure about one installed schedule.
///
/// Disclosure only: this is the answer to "does the declaration match the host", not
/// the answer to "may this lease be admitted". The glossary's rename says why — a query
/// that gated admission would answer a question about configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeasuredUnitState {
    /// The host answered, and this is what it said.
    Reported {
        /// Whether the schedule is active as declared.
        active: bool,
        /// What the host said, in its own words.
        detail: String,
        /// When the schedule is next expected to elapse, in the host's own words.
        ///
        /// `None` when the host did not report it. A next elapse is when the manager
        /// intends to start the job, never when a copy stops existing.
        next_elapse: Option<String>,
        /// When the manager last started it, in the host's own words.
        ///
        /// `None` when the host did not report it, which is a fact to print rather
        /// than an absence to fill in. A trigger is not a completed sweep (FR-006).
        last_trigger: Option<String>,
    },
    /// This host cannot answer, and this is why.
    Unknown {
        /// The reason, never a generic "error".
        reason: String,
    },
}

/// The query that describes a schedule, without deciding anything.
pub struct ArmingQuery;

impl ArmingQuery {
    /// The sentence every output carries.
    pub const DISCLOSURE: &'static str = "this describes configuration; it decides nothing about \
                                          whether a lease may be admitted — the signed sweep proof \
                                          does";

    /// The argv that asks systemd about one unit. Built here, run by the operator.
    ///
    /// This package does not spawn it: the CLI records and reports, and installing or
    /// interrogating a delay is the operator's privilege, not a command's.
    pub fn systemd_command(unit: &str) -> (&'static str, Vec<String>) {
        (
            "systemctl",
            vec![
                "show".to_string(),
                unit.to_string(),
                "--property=ActiveState,UnitFileState,NextElapseUSecRealtime,LastTriggerUSec"
                    .to_string(),
                "--no-pager".to_string(),
            ],
        )
    }

    /// Interpret `systemctl show` output. Pure: no process, no clock, no store.
    pub fn interpret_systemd(stdout: &str) -> MeasuredUnitState {
        let field = |name: &str| {
            stdout
                .lines()
                .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
                .map(str::trim)
        };
        let (Some(state), Some(file_state)) = (field("ActiveState"), field("UnitFileState")) else {
            return MeasuredUnitState::Unknown {
                reason: "the output named no ActiveState and UnitFileState".to_string(),
            };
        };
        // systemd prints `n/a` for a property a unit does not carry, which is not a
        // timestamp and must not be printed as one.
        let stamp = |name: &str| {
            field(name)
                .filter(|value| !value.is_empty() && *value != "n/a")
                .map(str::to_string)
        };
        if file_state == "masked" {
            return MeasuredUnitState::Reported {
                active: false,
                detail: "the unit is masked, so the timer cannot start".to_string(),
                next_elapse: stamp("NextElapseUSecRealtime"),
                last_trigger: stamp("LastTriggerUSec"),
            };
        }
        MeasuredUnitState::Reported {
            active: state == "active",
            detail: format!("ActiveState={state} UnitFileState={file_state}"),
            next_elapse: stamp("NextElapseUSecRealtime"),
            last_trigger: stamp("LastTriggerUSec"),
        }
    }

    /// What can be measured for a kind, given that nothing is spawned here.
    pub fn for_kind(kind: ArmingKind) -> MeasuredUnitState {
        match kind {
            ArmingKind::Systemd | ArmingKind::Launchd => MeasuredUnitState::Unknown {
                reason: "this build records the query and the operator runs it; no schedule was \
                         interrogated"
                    .to_string(),
            },
            other => MeasuredUnitState::Unknown {
                reason: format!(
                    "a {} schedule runs somewhere this host cannot see",
                    other.label()
                ),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says why.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const VAULT: &str = "vault-1";
    const SCOPE: &str = "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-*";

    fn owner() -> PrincipalId {
        PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap()
    }

    fn narrow() -> CredentialBinding {
        CredentialBinding {
            identity: "unix:ksp-sweeper".to_string(),
            grants: vec![
                Grant {
                    right: Right::Delete,
                    scope: SCOPE.to_string(),
                },
                Grant {
                    right: Right::List,
                    scope: SCOPE.to_string(),
                },
                Grant {
                    right: Right::Write,
                    scope: "journal".to_string(),
                },
            ],
        }
    }

    fn arming() -> SweeperArming {
        SweeperArming::new(ArmingSpec {
            backend: "file",
            vault: &VaultId::new(VAULT),
            kind: ArmingKind::Systemd,
            identifier: "ksp-sweep.service",
            interval_secs: 3600,
            scope: SCOPE,
            credential: narrow(),
            principal: owner(),
            recorded_at: 1_700_000_000,
            signer_key_id: "admin-2026",
            user_signed: false,
        })
        .unwrap()
    }

    fn scope() -> SweepScope {
        SweepScope::parse(SCOPE, &VaultId::new(VAULT), owner()).unwrap()
    }

    /// The scope is a level, never a particular secret.
    ///
    /// `SweepScope::parse` inspected `segments[3]` and never checked the arity,
    /// so `agent-*/db-password` resolved to `EveryAgent` and `db-password` was
    /// silently dropped. The command armed, exited `0`, and the capability never
    /// moved: `gc` then reported that no armed record was read while one existed.
    ///
    /// Every suffix is refused, not just the one in the report, because the rule
    /// is about the arity rather than about that particular word.
    #[test]
    fn a_scope_deeper_than_the_agent_level_is_refused() {
        for suffix in ["db-password", "agent-*/db-password", "anything"] {
            let text = format!("{SCOPE}/{suffix}");
            let error = SweepScope::parse(&text, &VaultId::new(VAULT), owner())
                .expect_err("a scope deeper than the level must be refused");
            assert!(
                matches!(error, ArmingError::ScopeTooBroad { .. }),
                "{text} must be refused as too broad, got {error:?}"
            );
        }
    }

    /// The refusal names the level the sweep owns, so a reader can derive the
    /// accepted shape from it.
    #[test]
    fn the_arity_refusal_names_the_accepted_level() {
        let text = format!("{SCOPE}/db-password");
        let error = SweepScope::parse(&text, &VaultId::new(VAULT), owner()).unwrap_err();
        let sentence = error.to_string();
        assert!(
            sentence.contains(SCOPE),
            "the refusal must name the accepted level ({SCOPE}): {sentence}"
        );
        assert!(
            sentence.contains("level"),
            "the refusal must say a scope is a level: {sentence}"
        );
    }

    /// The accepted shape still parses, and it parses to the agent level.
    ///
    /// This is the shape every other test in this module builds on, asserted
    /// directly so a guard that refused everything would fail here rather than
    /// somewhere downstream.
    #[test]
    fn the_canonical_scope_still_parses() {
        let parsed = SweepScope::parse(SCOPE, &VaultId::new(VAULT), owner()).unwrap();
        assert_eq!(parsed.level, ScopeLevel::EveryAgent);
        assert_eq!(parsed.text, SCOPE);
    }

    /// A trailing slash is the same scope, and is still accepted.
    ///
    /// The parser trims trailing slashes before splitting, so a scope copied from
    /// a directory listing must not be refused for the slash the copy carried.
    #[test]
    fn a_trailing_slash_is_still_the_canonical_scope() {
        let text = format!("{SCOPE}/");
        let parsed = SweepScope::parse(&text, &VaultId::new(VAULT), owner())
            .expect("a trailing slash is not a deeper scope");
        assert_eq!(parsed.level, ScopeLevel::EveryAgent);
    }

    /// Every shape refused today is still refused, with its own reason.
    ///
    /// Enumerated rather than inferred: the arity guard must not swallow a
    /// refusal that already existed, and each of these names a different fix.
    #[test]
    fn every_shape_refused_today_keeps_its_own_reason() {
        // Above the agent level: too broad, and the reason says where it stopped.
        // `p` on its own is refused as outside the deployment rather than too
        // broad, because it does not name the vault at all — both are refusals,
        // and the existing test in this module accepts either.
        for text in [
            "p",
            "p/vault-1",
            "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f",
        ] {
            let error = SweepScope::parse(text, &VaultId::new(VAULT), owner()).unwrap_err();
            assert!(
                matches!(
                    error,
                    ArmingError::ScopeTooBroad { .. } | ArmingError::ScopeOutsideDeployment { .. }
                ),
                "{text} must be refused, got {error:?}"
            );
        }

        // A level that is not an agent level.
        let text = "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/user";
        let error = SweepScope::parse(text, &VaultId::new(VAULT), owner()).unwrap_err();
        assert!(
            matches!(error, ArmingError::ScopeTooBroad { .. }),
            "the user level must be refused as not an agent level, got {error:?}"
        );

        // A specific agent level: admission reads `agent-*` only.
        let text = "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-11111111-2222-4333-8444-555555555555";
        let error = SweepScope::parse(text, &VaultId::new(VAULT), owner()).unwrap_err();
        assert!(
            matches!(error, ArmingError::ScopeAdmissionUnreadable { .. }),
            "a specific agent level must name the accepted shape, got {error:?}"
        );

        // Another deployment's vault.
        let error = SweepScope::parse(SCOPE, &VaultId::new("other-vault"), owner()).unwrap_err();
        assert!(
            matches!(error, ArmingError::ScopeOutsideDeployment { .. }),
            "another vault must be refused as outside the deployment, got {error:?}"
        );
    }

    /// A grant naming a record is refused, the same way the armed scope is.
    ///
    /// `within` consumes every armed segment and returns `true` whatever the
    /// grant has left over, so a grant of `agent-*/db-password` was "within"
    /// `agent-*` and passed. The sweep acts on a level, so a grant that names a
    /// record grants nothing the sweep can use, and accepting it taught the
    /// operator that a narrower binding was honoured when it was not.
    #[test]
    fn a_grant_naming_a_record_is_refused() {
        let deeper = format!("{SCOPE}/db-password");
        let binding = CredentialBinding {
            identity: "unix:ksp-sweeper".to_string(),
            grants: vec![
                Grant {
                    right: Right::Delete,
                    scope: deeper.clone(),
                },
                Grant {
                    right: Right::List,
                    scope: deeper,
                },
                Grant {
                    right: Right::Write,
                    scope: "journal".to_string(),
                },
            ],
        };
        let error = binding
            .check(&scope())
            .expect_err("a grant that names a record must be refused");
        assert!(
            matches!(error, ArmingError::CredentialTooWide { .. }),
            "the refusal must say the grant is wider than the sweep, got {error:?}"
        );
    }

    /// A deeper scope on a specific agent level keeps that level's own refusal.
    ///
    /// The arity guard runs after the level is interpreted, not before it. A
    /// specific agent level is refused as `ScopeAdmissionUnreadable` — which names
    /// `agent-*`, the shape admission reads — and that reason is more useful than
    /// a refusal about the suffix. Checking the arity first replaced it with
    /// `ScopeTooBroad`, which is true and less actionable, and would have broken
    /// the guarantee that every shape refused today keeps its own reason.
    #[test]
    fn a_deeper_specific_agent_scope_keeps_its_admission_refusal() {
        let text = "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-11111111-2222-4333-8444-555555555555/db-password";
        let error = SweepScope::parse(text, &VaultId::new(VAULT), owner()).unwrap_err();
        assert!(
            matches!(error, ArmingError::ScopeAdmissionUnreadable { .. }),
            "a specific agent level keeps its own reason even with a suffix, got {error:?}"
        );
        assert!(
            error.to_string().contains("agent-*"),
            "the refusal must name the accepted shape: {error}"
        );
    }

    /// Misfit O: a scope above the deployment root deletes someone else's leases.
    #[test]
    fn a_scope_at_or_above_the_vault_is_refused() {
        for text in [
            "p",
            "p/vault-1",
            "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f",
        ] {
            let error = SweepScope::parse(text, &VaultId::new(VAULT), owner()).unwrap_err();
            assert!(
                matches!(
                    error,
                    ArmingError::ScopeTooBroad { .. } | ArmingError::ScopeOutsideDeployment { .. }
                ),
                "{text} must be refused, got {error:?}"
            );
        }
        // Another principal's namespace is outside this deployment, not merely broad.
        let other = "p/vault-1/1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f/agent-*";
        assert!(matches!(
            SweepScope::parse(other, &VaultId::new(VAULT), owner()),
            Err(ArmingError::ScopeOutsideDeployment { .. })
        ));
        // A user level is not a sweep's to touch.
        let user = "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/user";
        assert!(matches!(
            SweepScope::parse(user, &VaultId::new(VAULT), owner()),
            Err(ArmingError::ScopeTooBroad { .. })
        ));
    }

    /// A scope with a record name after the level is refused, not narrowed.
    ///
    /// This test replaces one called `a_narrower_scope_is_accepted`, which built
    /// `{SCOPE}/db-password` and asserted it parsed to `EveryAgent`. That was the
    /// defect written down as a requirement: the trailing segment was dropped, the
    /// command armed and exited `0`, and the capability never moved. A sweep acts
    /// on a level; it is never told which record to delete, so a scope naming one
    /// is refused rather than quietly widened back to the level.
    #[test]
    fn a_scope_naming_a_record_is_refused_rather_than_narrowed() {
        let narrow = format!("{SCOPE}/db-password");
        let error = SweepScope::parse(&narrow, &VaultId::new(VAULT), owner())
            .expect_err("a scope that names a record must be refused");
        assert!(
            matches!(error, ArmingError::ScopeTooBroad { .. }),
            "the refusal must say the scope is too broad, got {error:?}"
        );
    }

    /// Misfit A: an operator who arms `agent-<uuid>` is told the accepted shape.
    ///
    /// `agent-<uuid>` parses as one agent level, which reaches no lease the
    /// deployment arms: the canonical scope is `agent-*` and admission compares
    /// against that. Before this refusal the operator was told about a missing
    /// sweep proof, which is true and useless.
    #[test]
    fn an_agent_uuid_scope_is_refused_and_names_the_accepted_shape() {
        let one = "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f";
        let error = SweepScope::parse(one, &VaultId::new(VAULT), owner()).unwrap_err();
        let ArmingError::ScopeAdmissionUnreadable { scope, accepted } = &error else {
            panic!("expected ScopeAdmissionUnreadable, got {error:?}");
        };
        assert_eq!(scope, one, "the refusal echoes what was written");
        assert_eq!(
            accepted, SCOPE,
            "the refusal names the accepted shape for this deployment"
        );
        let rendered = error.to_string();
        assert!(
            rendered.contains(SCOPE),
            "the rendered refusal must name the accepted shape, got: {rendered}"
        );
    }

    /// Misfit B: the predicate refuses, it never rewrites.
    ///
    /// A fix that normalised `agent-<uuid>` to `agent-*` would make the command
    /// succeed while widening what a sweep may delete. The scope the operator
    /// wrote must not appear as an accepted scope anywhere.
    #[test]
    fn a_refused_scope_is_never_normalised_into_an_accepted_one() {
        let one = "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f";
        assert!(SweepScope::parse(one, &VaultId::new(VAULT), owner()).is_err());
        // The accepted shape is still accepted, and still parses as every agent.
        let ok = SweepScope::parse(SCOPE, &VaultId::new(VAULT), owner()).unwrap();
        assert_eq!(ok.level, ScopeLevel::EveryAgent);
        assert_eq!(ok.text, SCOPE);
    }

    /// The canonical shape has exactly one definition.
    #[test]
    fn the_canonical_scope_is_the_accepted_shape() {
        let canonical = canonical_admission_scope(VAULT, &owner());
        assert_eq!(canonical, SCOPE);
        assert!(admits_file_admission(&canonical, VAULT, &owner()).is_ok());
        assert!(admits_file_admission(
            "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
            VAULT,
            &owner()
        )
        .is_err());
        // Another deployment's canonical scope is not this deployment's.
        assert!(
            admits_file_admission(
                "p/vault-2/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-*",
                VAULT,
                &owner()
            )
            .is_err()
        );
    }

    /// The parser takes the accepted shape from the predicate.
    ///
    /// This is the test that fails when the predicate is dead code. The
    /// expectation is the `SCOPE` **literal**, not a second call to the
    /// predicate: comparing the refusal against the predicate's own answer would
    /// pass under any mutation of the predicate, because both sides would move
    /// together. A literal cannot move, so a parser that stopped asking the
    /// predicate leaves the refusal stale and this assertion fails.
    #[test]
    fn the_parser_refusal_carries_the_predicates_own_answer() {
        let one = "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f";
        let error = SweepScope::parse(one, &VaultId::new(VAULT), owner()).unwrap_err();
        let ArmingError::ScopeAdmissionUnreadable { accepted, .. } = &error else {
            panic!("expected ScopeAdmissionUnreadable, got {error:?}");
        };
        assert_eq!(
            accepted.as_str(),
            SCOPE,
            "the refusal must carry the shape the predicate hands back, not a string \
             the parser built for itself"
        );
    }

    /// Misfit Q: a wider credential turns a schedule into a standing privilege.
    #[test]
    fn a_credential_wider_than_the_sweep_needs_is_refused_and_names_the_excess() {
        let scope = scope();
        let cases = [
            (
                CredentialBinding {
                    identity: "root".to_string(),
                    grants: narrow().grants,
                },
                "owns the store",
            ),
            (
                CredentialBinding {
                    identity: "unix:ksp-sweeper".to_string(),
                    grants: vec![Grant {
                        right: Right::Read,
                        scope: SCOPE.to_string(),
                    }],
                },
                "read",
            ),
            (
                CredentialBinding {
                    identity: "unix:ksp-sweeper".to_string(),
                    grants: vec![Grant {
                        right: Right::Delete,
                        scope: "p/vault-1".to_string(),
                    }],
                },
                "beyond the armed scope",
            ),
            (
                CredentialBinding {
                    identity: "unix:ksp-sweeper".to_string(),
                    grants: vec![Grant {
                        right: Right::Write,
                        scope: "p/vault-1".to_string(),
                    }],
                },
                "writes only the journal",
            ),
        ];
        for (binding, expected) in cases {
            let error = binding.check(&scope).unwrap_err();
            let text = error.to_string();
            assert!(
                matches!(error, ArmingError::CredentialTooWide { .. }),
                "{text}"
            );
            assert!(text.contains(expected), "the excess must be named: {text}");
        }
    }

    /// A wildcard armed scope must accept a grant that names one real level under it.
    ///
    /// `agent-*` is a prefix, not a segment: a literal comparison would refuse the
    /// narrowest useful credential and push the operator towards a wider one.
    #[test]
    fn a_grant_for_one_agent_is_inside_an_every_agent_scope() {
        assert!(within(
            "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
            SCOPE
        ));
        assert!(within(SCOPE, SCOPE));
        // A grant that names a record inside the level is *not* within it. This
        // line asserted `true` before the arity guard existed, which is the same
        // defect as the parser accepting `agent-*/db-password`: the sweep acts on
        // a level, and a grant pointing at one record grants nothing it can use.
        assert!(!within(&format!("{SCOPE}/db-password"), SCOPE));
        // Above the scope, a sibling, and a different prefix are all outside.
        assert!(!within("p/vault-1", SCOPE));
        assert!(!within(
            "p/vault-2/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-*",
            SCOPE
        ));
        assert!(!within(
            "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/user",
            SCOPE
        ));
        assert!(!within(
            "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agentx",
            SCOPE
        ));

        // And the check itself accepts a per-agent credential under that arming.
        let scope = scope();
        let narrow = CredentialBinding {
            identity: "unix:ksp-sweeper".to_string(),
            grants: vec![Grant {
                right: Right::Delete,
                scope: "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f"
                    .to_string(),
            }],
        };
        assert_eq!(narrow.check(&scope), Ok(()));
    }

    /// A binding that names nothing enforces nothing (misfit K).
    #[test]
    fn a_binding_that_names_nothing_is_refused() {
        let scope = scope();
        assert!(matches!(
            CredentialBinding {
                identity: "  ".to_string(),
                grants: narrow().grants
            }
            .check(&scope),
            Err(ArmingError::CredentialNamesNothing)
        ));
        assert!(matches!(
            CredentialBinding {
                identity: "unix:ksp-sweeper".to_string(),
                grants: Vec::new()
            }
            .check(&scope),
            Err(ArmingError::CredentialUnstated)
        ));
    }

    #[test]
    fn a_zero_interval_and_a_mismatched_kind_are_refused() {
        assert!(matches!(
            SweeperArming::new(ArmingSpec {
                backend: "file",
                vault: &VaultId::new(VAULT),
                kind: ArmingKind::Systemd,
                identifier: "ksp-sweep.service",
                interval_secs: 0,
                scope: SCOPE,
                credential: narrow(),
                principal: owner(),
                recorded_at: 1,
                signer_key_id: "admin-2026",
                user_signed: false,
            }),
            Err(ArmingError::Interval(_))
        ));
        assert!(matches!(
            SweeperArming::new(ArmingSpec {
                backend: "file",
                vault: &VaultId::new(VAULT),
                kind: ArmingKind::Crontab,
                identifier: "ksp-sweep.service",
                interval_secs: 60,
                scope: SCOPE,
                credential: narrow(),
                principal: owner(),
                recorded_at: 1,
                signer_key_id: "admin-2026",
                user_signed: false,
            }),
            Err(ArmingError::KindMismatch { .. })
        ));
    }

    /// FR-030: one deterministic identity per backend and scope, so two armings collide.
    #[test]
    fn the_arming_identity_is_the_backend_and_the_scope() {
        assert_eq!(
            arming_id("file", SCOPE),
            arming_id("file", &format!("{SCOPE}/"))
        );
        assert_ne!(arming_id("file", SCOPE), arming_id("valkey", SCOPE));
        assert_eq!(arming().arming_id, arming_id("file", SCOPE));
    }

    #[test]
    fn a_tampered_record_does_not_verify() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let signed = SignedArming::sign(arming(), &signer).unwrap();
        assert!(signed.verify(&signer.verifying_key()));

        let mut edited = signed.clone();
        edited.arming.interval_secs = 60;
        assert!(!edited.verify(&signer.verifying_key()));

        let mut moved = signed.clone();
        moved.arming.scope = format!("{SCOPE}/x");
        assert!(!moved.verify(&signer.verifying_key()));

        let round_tripped = SignedArming::from_bytes(&signed.to_bytes().unwrap()).unwrap();
        assert!(round_tripped.verify(&signer.verifying_key()));
    }

    /// Acceptance 5: the template carries the accuracy pin and the user, and installs
    /// nothing.
    #[test]
    fn the_unit_template_pins_accuracy_and_names_the_user() {
        let unit = arming().systemd_unit("/usr/local/bin/ksp", "/tmp").unwrap();
        assert!(unit.contains("AccuracySec=1s"), "{unit}");
        assert!(unit.contains("User=ksp-admin"), "{unit}");
        assert!(unit.contains("Type=oneshot"), "{unit}");
        assert!(unit.contains("OnUnitActiveSec=3600s"), "{unit}");
        assert!(!unit.contains("RandomizedDelaySec"), "{unit}");
        assert!(
            unit.contains("Install as root"),
            "the operator installs it, not ksp: {unit}"
        );
    }

    /// Misfit C: a declaration cannot be read as an installation.
    #[test]
    fn the_template_says_it_is_configuration_and_not_evidence() {
        let unit = arming().systemd_unit("/usr/local/bin/ksp", "/tmp").unwrap();
        assert!(unit.contains("configuration, not evidence"), "{unit}");
        // A non-systemd kind has no template at all rather than an empty one.
        let external = SweeperArming::new(ArmingSpec {
            backend: "valkey",
            vault: &VaultId::new(VAULT),
            kind: ArmingKind::ExternalJob,
            identifier: "nightly-cleanup",
            interval_secs: 3600,
            scope: SCOPE,
            credential: narrow(),
            principal: owner(),
            recorded_at: 1,
            signer_key_id: "admin-2026",
            user_signed: false,
        })
        .unwrap();
        assert!(
            external
                .systemd_unit("/usr/local/bin/ksp", "/tmp")
                .is_none()
        );
    }

    #[test]
    fn the_query_interprets_a_masked_unit_and_admits_when_it_cannot_tell() {
        let masked = "ActiveState=inactive\nUnitFileState=masked\n";
        match ArmingQuery::interpret_systemd(masked) {
            MeasuredUnitState::Reported {
                active,
                detail,
                next_elapse,
                last_trigger,
            } => {
                assert!(!active);
                assert!(detail.contains("masked"), "{detail}");
                // A property systemd does not carry is absent, not a timestamp.
                assert_eq!(next_elapse, None);
                assert_eq!(last_trigger, None);
            }
            other => panic!("expected a reported state, got {other:?}"),
        }
        assert!(matches!(
            ArmingQuery::interpret_systemd("garbage"),
            MeasuredUnitState::Unknown { .. }
        ));
        assert!(ArmingQuery::DISCLOSURE.contains("decides nothing"));
    }

    /// FR-005: the elapse and the trigger are reported when the host names them, and
    /// neither is invented when it does not.
    #[test]
    fn the_query_reports_the_elapse_and_the_trigger_the_host_named() {
        let answered = "ActiveState=active\nUnitFileState=enabled\n\
                        NextElapseUSecRealtime=Sat 2026-10-24 22:00:00 CEST\n\
                        LastTriggerUSec=Fri 2026-10-24 21:00:00 CEST\n";
        match ArmingQuery::interpret_systemd(answered) {
            MeasuredUnitState::Reported {
                next_elapse,
                last_trigger,
                ..
            } => {
                assert_eq!(next_elapse.as_deref(), Some("Sat 2026-10-24 22:00:00 CEST"));
                assert_eq!(
                    last_trigger.as_deref(),
                    Some("Fri 2026-10-24 21:00:00 CEST")
                );
            }
            other => panic!("expected a reported state, got {other:?}"),
        }

        // The property is `n/a` on a service with no timer, and that is not a time.
        let absent = "ActiveState=inactive\nUnitFileState=static\n\
                      NextElapseUSecRealtime=n/a\nLastTriggerUSec=n/a\n";
        match ArmingQuery::interpret_systemd(absent) {
            MeasuredUnitState::Reported {
                next_elapse,
                last_trigger,
                ..
            } => {
                assert_eq!(next_elapse, None);
                assert_eq!(last_trigger, None);
            }
            other => panic!("expected a reported state, got {other:?}"),
        }
    }

    /// T034: the query must not gate admission. The assertion is on the sources that
    /// The local backend follows the host's scheduler; the remote rows do not.
    ///
    /// `file` is the only row a platform decides. A Mac with a local store was
    /// told to install a systemd unit, so the declaration described a job nobody
    /// could run while the cadence it names is what admits a lease.
    #[test]
    fn the_local_backend_uses_the_platform_s_scheduler() {
        assert_eq!(
            ArmingKind::for_backend("file", HostPlatform::Darwin),
            Some(ArmingKind::Launchd)
        );
        assert_eq!(
            ArmingKind::for_backend("file", HostPlatform::Linux),
            Some(ArmingKind::Systemd)
        );
        for platform in [HostPlatform::Linux, HostPlatform::Darwin] {
            assert_eq!(
                ArmingKind::for_backend("sftp", platform),
                Some(ArmingKind::Crontab),
                "a remote row must not move with the host"
            );
            assert_eq!(
                ArmingKind::for_backend("s3", platform),
                Some(ArmingKind::ProviderLifecycle)
            );
            assert_eq!(
                ArmingKind::for_backend("valkey", platform),
                Some(ArmingKind::ExternalJob)
            );
            assert_eq!(ArmingKind::for_backend("no-such-backend", platform), None);
        }
    }

    fn launchd_arming() -> SweeperArming {
        SweeperArming::new(ArmingSpec {
            backend: "file",
            vault: &VaultId::new(VAULT),
            kind: ArmingKind::Launchd,
            identifier: "com.keyspout.sweep",
            interval_secs: 3600,
            scope: SCOPE,
            credential: narrow(),
            principal: owner(),
            recorded_at: 1,
            signer_key_id: "admin-2026",
            user_signed: false,
        })
        .expect("a local store accepts a launchd job")
    }

    fn user_launchd_arming() -> SweeperArming {
        SweeperArming::new(ArmingSpec {
            backend: "file",
            vault: &VaultId::new(VAULT),
            kind: ArmingKind::Launchd,
            identifier: "com.keyspout.user-sweep",
            interval_secs: 3600,
            scope: SCOPE,
            credential: narrow(),
            principal: owner(),
            recorded_at: 1,
            signer_key_id: "alice-ed25519-1",
            user_signed: true,
        })
        .expect("a local store accepts a launchd job")
    }

    fn user_systemd_arming() -> SweeperArming {
        SweeperArming::new(ArmingSpec {
            backend: "file",
            vault: &VaultId::new(VAULT),
            kind: ArmingKind::Systemd,
            identifier: "ksp-user-sweep.service",
            interval_secs: 3600,
            scope: SCOPE,
            credential: narrow(),
            principal: owner(),
            recorded_at: 1,
            signer_key_id: "alice-ed25519-1",
            user_signed: true,
        })
        .expect("a local store accepts a systemd job")
    }

    /// A user arming's artifact must run the user's sweep.
    ///
    /// The admin's job runs `secret gc`, which signs as the admin and needs the
    /// admin key. A user's job that ran the same command would either fail on a
    /// host where she cannot read `admin/`, or — worse — succeed by attributing
    /// her deletions to the admin. It has to name `--user-arming` and a password
    /// file, because a scheduled job has no terminal to prompt on.
    #[test]
    fn a_user_armings_artifact_runs_the_user_sweep() {
        let plist = user_launchd_arming()
            .launchd_plist("/usr/local/bin/ksp", "/Users/alice/.ksp")
            .expect("a launchd arming has a plist");
        assert!(
            plist.contains("<string>--user-arming</string>"),
            "the job must run the user sweep, not the admin one: {plist}"
        );
        assert!(
            plist.contains("<string>--passphrase-file</string>"),
            "a scheduled job has no terminal to prompt on: {plist}"
        );

        // And the admin's artifact must not gain the flag.
        let admin = launchd_arming()
            .launchd_plist("/usr/local/bin/ksp", "/tmp")
            .expect("a launchd arming has a plist");
        assert!(
            !admin.contains("--user-arming"),
            "an admin arming's job is the admin sweep: {admin}"
        );
    }

    /// The systemd unit follows the same rule, and names the user as `User=`.
    #[test]
    fn a_user_armings_unit_runs_the_user_sweep() {
        let unit = user_systemd_arming()
            .systemd_unit("/usr/local/bin/ksp", "/Users/alice/.ksp")
            .expect("a systemd arming has a unit");
        assert!(
            unit.contains("--user-arming") && unit.contains("--passphrase-file"),
            "the unit must run the user sweep with a password file: {unit}"
        );
        assert!(
            !unit.contains("User=ksp-admin"),
            "a user's job does not run as the admin account: {unit}"
        );
    }

    /// The plist has to carry the interval, the home and the label the job runs
    /// under, or `launchd` loads a job that does the wrong thing quietly.
    #[test]
    fn the_plist_carries_the_interval_the_home_and_the_label() {
        let plist = launchd_arming()
            .launchd_plist("/usr/local/bin/ksp", "/Users/alice/.config/ksp")
            .expect("a launchd arming has a plist");
        assert!(plist.contains("<key>StartInterval</key>"), "{plist}");
        assert!(plist.contains("<integer>3600</integer>"), "{plist}");
        assert!(plist.contains("<key>KSP_HOME</key>"), "{plist}");
        assert!(
            plist.contains("<string>/Users/alice/.config/ksp</string>"),
            "{plist}"
        );
        assert!(
            plist.contains("<string>com.keyspout.sweep</string>"),
            "the Label is what launchctl unload names: {plist}"
        );
        assert!(plist.contains(SWEEPER_BINARY_PLACEHOLDER), "{plist}");
        assert!(
            plist.contains("<string>secret</string>") && plist.contains("<string>gc</string>"),
            "the job runs `secret gc`: {plist}"
        );
        assert!(
            !plist.contains("systemd"),
            "a plist must not name the other host's scheduler: {plist}"
        );
    }

    /// A home with an XML metacharacter must not produce a plist launchd rejects.
    ///
    /// The plist is the only XML this build writes, and a path is the one value in
    /// it that comes from the operator rather than from a constant.
    #[test]
    fn a_home_with_xml_metacharacters_is_escaped() {
        let plist = launchd_arming()
            .launchd_plist("/usr/local/bin/ksp", "/Users/a&b/<ksp>")
            .expect("a launchd arming has a plist");
        assert!(
            plist.contains("<string>/Users/a&amp;b/&lt;ksp&gt;</string>"),
            "{plist}"
        );
        assert!(
            !plist.contains("a&b"),
            "an unescaped ampersand makes the file unparseable: {plist}"
        );
    }

    /// A plist is configuration, and only the arm is evidence.
    #[test]
    fn a_plist_says_it_is_configuration_and_a_systemd_arming_has_none() {
        assert!(
            arming()
                .launchd_plist("/usr/local/bin/ksp", "/tmp")
                .is_none(),
            "only a launchd arming renders a plist"
        );
        let plist = launchd_arming()
            .launchd_plist("/usr/local/bin/ksp", "/tmp")
            .unwrap();
        assert!(
            plist.contains("configuration, not evidence"),
            "the artifact must say the proof is the evidence: {plist}"
        );
    }

    /// An installed job must name the binary that is running, not a constant.
    ///
    /// The defect this covers: `--install` wrote `/usr/local/bin/ksp` on a host
    /// whose Homebrew prefix is `/opt/homebrew`, and the job failed with `ENOENT`
    /// on its first firing after `installed:` had already read as success. The
    /// test supplies a path that is not the placeholder, so a builder that still
    /// read the constant would render the constant and fail here.
    #[test]
    fn an_installed_job_names_the_binary_it_is_given() {
        let running = "/opt/homebrew/Cellar/ksp-cli/1.0.0/bin/ksp";
        let plist = launchd_arming()
            .installed_artifact(running, "/Users/alice/.ksp")
            .expect("an absolute binary and home are admitted")
            .expect("a launchd arming has a plist");
        assert!(
            plist.contains(&format!("<string>{running}</string>")),
            "the job must run the binary that is running: {plist}"
        );
        assert!(
            !plist.contains(SWEEPER_BINARY_PLACEHOLDER),
            "an install must not carry the printed template's placeholder: {plist}"
        );
    }

    /// An installed job must carry an absolute `KSP_HOME`.
    ///
    /// `launchd` runs a job with `/` as its working directory, so the default
    /// `.ksp` would name `/.ksp`. The refusal names the field and the variable,
    /// because a reader who is told only "a path was wrong" has to guess which.
    #[test]
    fn an_installed_job_refuses_a_relative_home() {
        let error = launchd_arming()
            .installed_artifact("/usr/local/bin/ksp", ".ksp")
            .expect_err("a relative KSP_HOME cannot be installed");
        let rendered = error.to_string();
        assert!(
            rendered.contains("KSP_HOME"),
            "the refusal must name the variable that fixes it: {rendered}"
        );
        assert!(
            rendered.contains(".ksp"),
            "the refusal must name the value it refused: {rendered}"
        );
    }

    /// The same refusal covers a relative binary path.
    ///
    /// A relative binary is the other half of the same defect: a job that names
    /// `./ksp` resolves it against `/` and finds nothing.
    #[test]
    fn an_installed_job_refuses_a_relative_binary() {
        let error = launchd_arming()
            .installed_artifact("ksp", "/Users/alice/.ksp")
            .expect_err("a relative binary cannot be installed");
        assert!(
            error.to_string().contains("binary"),
            "the refusal must name the field: {error}"
        );
    }

    /// The systemd unit follows the same rule as the plist.
    #[test]
    fn an_installed_unit_names_the_binary_it_is_given() {
        let running = "/home/alice/.local/bin/ksp";
        let unit = arming()
            .installed_artifact(running, "/home/alice/.ksp")
            .expect("an absolute binary and home are admitted")
            .expect("a systemd arming has a unit");
        assert!(
            unit.contains(&format!("ExecStart={running} secret gc")),
            "the unit must run the binary that is running: {unit}"
        );
        assert!(
            !unit.contains(SWEEPER_BINARY_PLACEHOLDER),
            "an install must not carry the printed template's placeholder: {unit}"
        );
    }

    /// Both local schedulers stay accepted for a local store, on either host.
    ///
    /// FR-005. The default moves with the platform, and the accepted set does not:
    /// a Mac operator may still record a systemd unit to install elsewhere, and a
    /// Linux operator may still record a plist. `crontab` on `file` stays refused.
    #[test]
    fn a_local_store_accepts_both_local_schedulers_and_not_a_crontab() {
        for kind in [ArmingKind::Systemd, ArmingKind::Launchd] {
            assert!(
                kind.accepted_for_backend("file"),
                "{} is a local scheduler and a local store can use it",
                kind.label()
            );
        }
        assert!(!ArmingKind::Crontab.accepted_for_backend("file"));
        assert!(ArmingKind::Crontab.accepted_for_backend("sftp"));
        assert!(!ArmingKind::Launchd.accepted_for_backend("sftp"));
        assert!(!ArmingKind::Launchd.accepted_for_backend("no-such-backend"));
    }

    /// would call it, because a comment cannot enforce a module boundary.
    #[test]
    fn no_admission_path_references_the_query() {
        for source in [
            include_str!("admission.rs"),
            include_str!("status.rs"),
            include_str!("store.rs"),
        ] {
            assert!(
                !source.contains("ArmingQuery"),
                "an admission path must not consult the arming query"
            );
        }
    }
}
