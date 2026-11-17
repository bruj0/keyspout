//! Where a policy edge lives, and the links it must resolve before it is signed.
//!
//! # One file per edge, under the admin principal
//!
//! `p/<vault>/<admin>/policies/<policy-id>.cbor`. The location is the plan's; the
//! reason it is under the *admin* is that the admin signed it, and a path under the
//! user would say the user authored her own authority.
//!
//! The artifact is public material: `0644`, and the directory `0755` so a read
//! surface can enumerate it. `0744` in the plan's table would make the file
//! unreadable to every principal but its owner, which contradicts the sentence
//! beside it — "signed public material" — and would leave `policy list` unable to
//! list. The mode is a `file` fact; on `s3` and `valkey` the deployment credential
//! is the read boundary.
//!
//! # Uniqueness is a property of the set, not of a file
//!
//! Two active edges for one `(user, secret, version, target)` are two authorities
//! for one access: withdrawing either would read as a withdrawal while the other
//! still granted it (misfit B). So `create` refuses when any artifact in the
//! directory already claims the tuple. A withdrawn edge has no artifact — withdrawal
//! deletes it — so a re-grant is not blocked, and it mints a new id.
//!
//! # Links are resolved before the signature exists
//!
//! A signed edge naming a user, agent or version this deployment does not hold
//! verifies perfectly and can never be used (misfit G). The checks run before
//! `sign`, so no artifact exists for a refusal to clean up.

use std::path::PathBuf;

use ksp_identity::IssuanceLedger;
use ksp_identity::policy_edge::{
    EdgeRefusal, EdgeRequest, LinkCheck, PolicyAction, PolicyEdge, PolicyId, PolicyLedgerEntry,
    RevisionDecision, check_links, guard,
};
use ksp_identity::{AdminSigningKey, KeyId};
use ksp_types::{BoundMetadata, Level, OpaqueSecretId, PrincipalId, RecordVersion, VaultId};

use crate::config::Layout;
use crate::deployment::Deployment;
use crate::registry::PrincipalRegistry;
use crate::run::now_seconds;

/// The directory mode: readable and traversable, so a list surface can enumerate.
pub const POLICIES_DIR_MODE: u32 = 0o755;

/// The artifact mode: public material, like the registry beside it.
pub const POLICY_EDGE_MODE: u32 = 0o644;

/// The edge directory of one deployment.
#[derive(Debug, Clone)]
pub struct EdgeStore<'a> {
    layout: &'a Layout,
    vault: VaultId,
    admin: PrincipalId,
    admin_key_id: KeyId,
}

impl<'a> EdgeStore<'a> {
    /// The store a deployment's edges live in.
    pub fn new(layout: &'a Layout, deployment: &Deployment) -> Self {
        Self::at(
            layout,
            deployment.vault.clone(),
            deployment.admin,
            deployment.admin_key_id.clone(),
        )
    }

    /// A store located by three values a reader already holds.
    ///
    /// The run path uses this: an agent reading a policy-bound delivery has the
    /// vault, the admin principal and the issuer key id inside the token it was
    /// given, and it has no deployment record of its own to consult. Reading the
    /// grant from the same values the token names is also what makes the check
    /// meaningful — the store it reads is the one the grant claims to live in.
    pub fn at(layout: &'a Layout, vault: VaultId, admin: PrincipalId, admin_key_id: KeyId) -> Self {
        Self {
            layout,
            vault,
            admin,
            admin_key_id,
        }
    }

    /// The vault the edges govern.
    pub fn vault(&self) -> &VaultId {
        &self.vault
    }

    /// The admin principal that signs them.
    pub fn admin(&self) -> PrincipalId {
        self.admin
    }

    /// `p/<vault>/<admin>/policies/`.
    pub fn dir(&self) -> PathBuf {
        self.layout
            .store_root()
            .join("p")
            .join(self.vault.as_str())
            .join(self.admin.to_string())
            .join("policies")
    }

    /// `p/<vault>/<admin>/policies/<id>.cbor`.
    pub fn path(&self, id: &PolicyId) -> PathBuf {
        self.dir().join(format!("{id}.cbor"))
    }

    /// `p/<vault>/<admin>/policies/<id>.token`.
    ///
    /// Beside the edge the token was issued for, so the two cannot disagree about
    /// which policy it belongs to: a token in a directory named by its own policy
    /// id is a token an operator can find from the grant (FR-018, CF-020).
    pub fn token_path(&self, id: &PolicyId) -> PathBuf {
        self.dir().join(format!("{id}.token"))
    }

    /// Write the artifact's bytes beside it, and leave them there.
    ///
    /// Returns the staging path. Nothing is visible to a reader: the name carries no
    /// `cbor` extension, so `list` ignores it and a crash leaves an invisible file
    /// rather than a corrupt grant. The bytes are `sync`ed and carry the artifact's
    /// final mode before this returns, so a commit is a rename and nothing else.
    ///
    /// A process that dies between this call and the ledger append leaves that invisible
    /// file behind, and nothing reclaims it: no reader sees it, no command reports it.
    /// For an `update` the next attempt overwrites it, because the identifier is the
    /// one being updated; for a `create` the identifier was minted for the attempt that
    /// died, so its staging file stays until someone removes it by hand. That is the
    /// residue of choosing an invisible name over a visible half-written grant.
    fn stage(&self, edge: &PolicyEdge) -> Result<PathBuf, EdgeStoreError> {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        // The principal directory is the layout's: `0711`, so a sibling traverses and
        // does not list. `policies/` is created here because it is the one place the
        // plan widens, and it is created through the explicit mode rather than a
        // caller's `umask`.
        crate::layout::ensure_principal_root(self.layout, &self.vault, self.admin).map_err(
            |_| EdgeStoreError::Write {
                path: self.dir().display().to_string(),
            },
        )?;
        std::fs::create_dir_all(self.dir()).map_err(|_| EdgeStoreError::Write {
            path: self.dir().display().to_string(),
        })?;
        std::fs::set_permissions(
            self.dir(),
            std::fs::Permissions::from_mode(POLICIES_DIR_MODE),
        )
        .map_err(|_| EdgeStoreError::Write {
            path: self.dir().display().to_string(),
        })?;

        let bytes = edge.encode().map_err(EdgeStoreError::Refused)?;
        let staged = self.staged_path(edge.id());
        let written = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(POLICY_EDGE_MODE)
                .open(&staged)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            // `open(2)`'s mode is masked by `umask`; the explicit call is what makes
            // the mode a fact rather than an intention. It runs here rather than after
            // the rename, so the artifact never appears with the wrong one.
            std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(POLICY_EDGE_MODE))
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&staged);
            return Err(EdgeStoreError::Write {
                path: self.path(edge.id()).display().to_string(),
            });
        }
        Ok(staged)
    }

    /// Rename the staged bytes onto the artifact path.
    fn commit(
        &self,
        edge: &PolicyEdge,
        staged: &std::path::Path,
    ) -> Result<PathBuf, EdgeStoreError> {
        let path = self.path(edge.id());
        std::fs::rename(staged, &path).map_err(|_| EdgeStoreError::RecordedNotPublished {
            policy: edge.id().to_string(),
            revision: edge.revision(),
            cause: format!(
                "the artifact at {} could not be renamed into place",
                path.display()
            ),
            pending: Some(staged.display().to_string()),
        })?;
        Ok(path)
    }

    /// The staging path for one artifact: `policies/.<id>.tmp`.
    fn staged_path(&self, id: &PolicyId) -> PathBuf {
        self.dir().join(format!(".{id}.tmp"))
    }

    /// Read one edge.
    ///
    /// The artifact is checked, not merely parsed: it must be the artifact this path
    /// names, in this vault, and signed by the pinned admin key. `policies/` is
    /// `0755` on purpose, so every principal can read it — which is exactly why the
    /// mode cannot be what makes a file authority. The signature is.
    pub fn load(&self, id: &PolicyId) -> Result<PolicyEdge, EdgeStoreError> {
        let path = self.path(id);
        let bytes = std::fs::read(&path).map_err(|_| EdgeStoreError::Absent {
            path: path.display().to_string(),
        })?;
        let edge = PolicyEdge::decode(&bytes).map_err(|_| EdgeStoreError::Unreadable {
            path: path.display().to_string(),
        })?;
        self.trust(id, &edge, &path)?;
        Ok(edge)
    }

    /// Read one edge **without** deciding whether it is authority.
    ///
    /// A consumer must refuse an artifact it cannot attribute, which is what `load`
    /// does. A *read surface* must not: its job is to say `unverified` beside the
    /// policy, and a refusal would replace the row with silence — the exact failure
    /// the dangling/unverified states exist to prevent. The checks that are about
    /// identity rather than trust still run, because an artifact under another
    /// identifier is not a policy in this set at all.
    ///
    /// Never call this to decide what a grant may do.
    pub fn load_unsigned(&self, id: &PolicyId) -> Result<PolicyEdge, EdgeStoreError> {
        let path = self.path(id);
        let bytes = std::fs::read(&path).map_err(|_| EdgeStoreError::Absent {
            path: path.display().to_string(),
        })?;
        let edge = PolicyEdge::decode(&bytes).map_err(|_| EdgeStoreError::Unreadable {
            path: path.display().to_string(),
        })?;
        if edge.id() != id {
            return Err(EdgeStoreError::Misidentified {
                path: path.display().to_string(),
                named: edge.id().to_string(),
            });
        }
        // The vault is identity, not trust: an artifact naming another vault is not a
        // policy of this one, and a read surface must not list it as if it were.
        if edge.vault() != &self.vault {
            return Err(EdgeStoreError::ForeignVault {
                path: path.display().to_string(),
                vault: edge.vault().to_string(),
            });
        }
        Ok(edge)
    }

    /// Every edge in the directory, decoded but not judged.
    ///
    /// The same enumeration `list` performs, with the trust decision left to the
    /// caller: a read surface reports an unattributable artifact as `unverified`,
    /// and a consumer uses `list`.
    pub fn list_unsigned(&self) -> Result<Vec<PolicyEdge>, EdgeStoreError> {
        let directory = self.dir();
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => {
                return Err(EdgeStoreError::Unlistable {
                    path: directory.display().to_string(),
                });
            }
        };
        let mut edges = Vec::new();
        for entry in entries {
            let path = entry
                .map_err(|_| EdgeStoreError::Unlistable {
                    path: directory.display().to_string(),
                })?
                .path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("cbor") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| PolicyId::parse(stem).ok())
                .ok_or_else(|| EdgeStoreError::Unreadable {
                    path: path.display().to_string(),
                })?;
            edges.push(self.load_unsigned(&id)?);
        }
        edges.sort_by(|left, right| left.id().cmp(right.id()));
        Ok(edges)
    }

    /// The facts that make a decoded artifact authority.
    fn trust(
        &self,
        id: &PolicyId,
        edge: &PolicyEdge,
        path: &std::path::Path,
    ) -> Result<(), EdgeStoreError> {
        let shown = path.display().to_string();
        if edge.id() != id {
            return Err(EdgeStoreError::Misidentified {
                path: shown,
                named: edge.id().to_string(),
            });
        }
        if edge.vault() != &self.vault {
            return Err(EdgeStoreError::ForeignVault {
                path: shown,
                vault: edge.vault().to_string(),
            });
        }
        if edge.issuer_key_id() != &self.admin_key_id {
            return Err(EdgeStoreError::ForeignIssuer {
                path: shown,
                issuer: edge.issuer_key_id().as_str().to_string(),
                expected: self.admin_key_id.as_str().to_string(),
            });
        }
        let anchor = Deployment::anchor(self.layout).map_err(|cause| EdgeStoreError::Anchor {
            cause: cause.to_string(),
        })?;
        if !edge.verify_issuer(&anchor.key) {
            return Err(EdgeStoreError::Unverified { path: shown });
        }
        Ok(())
    }

    /// Every edge in the directory.
    ///
    /// A directory that does not exist yet is an empty set, not an error: a
    /// deployment that has never granted anything has no `policies/`, and reporting
    /// that as a failure would make the first grant fail. Every other read failure
    /// is an error. The difference matters: `create` refuses a duplicate by reading
    /// this set, so a `list` that answered "empty" to `EACCES` would admit a second
    /// active edge for one tuple.
    pub fn list(&self) -> Result<Vec<PolicyEdge>, EdgeStoreError> {
        let directory = self.dir();
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => {
                return Err(EdgeStoreError::Unlistable {
                    path: directory.display().to_string(),
                });
            }
        };
        let mut edges = Vec::new();
        for entry in entries {
            let path = entry
                .map_err(|_| EdgeStoreError::Unlistable {
                    path: directory.display().to_string(),
                })?
                .path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("cbor") {
                continue;
            }
            // The file name is the identifier, so a name this build cannot parse is
            // not an artifact it wrote, and the set is not one it can vouch for.
            let id = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| PolicyId::parse(stem).ok())
                .ok_or_else(|| EdgeStoreError::Unreadable {
                    path: path.display().to_string(),
                })?;
            edges.push(self.load(&id)?);
        }
        edges.sort_by(|left, right| left.id().cmp(right.id()));
        Ok(edges)
    }

    /// The edge that already claims `candidate`'s tuple, if one exists.
    ///
    /// A present artifact counts as active: withdrawal deletes it, so there is no
    /// withdrawn-but-present state for this check to reason about. Expiry is a
    /// different question and is answered at verification against a clock, not here
    /// — an edge whose window has passed still holds its tuple until it is withdrawn
    /// or expires, and silently re-granting beside it would make one tuple name two
    /// authorities.
    pub fn active_conflict(
        &self,
        candidate: &PolicyEdge,
    ) -> Result<Option<PolicyId>, EdgeStoreError> {
        for edge in self.list()? {
            if edge.id() != candidate.id() && edge.same_active_tuple(candidate) {
                return Ok(Some(edge.id().clone()));
            }
        }
        Ok(None)
    }

    /// Sign, record and publish a new edge, or refuse.
    ///
    /// The ledger is a parameter rather than a field because a publish without a
    /// ledger is exactly the defect this work package removes: making the ledger
    /// required in the type means no call site can write a policy without naming the
    /// file that records it (misfit A).
    pub fn create(
        &self,
        admin: &AdminSigningKey,
        issuer_key_id: KeyId,
        request: EdgeRequest,
        ledger: &IssuanceLedger,
    ) -> Result<PolicyEdge, EdgeStoreError> {
        let edge = PolicyEdge::create(admin, issuer_key_id, self.vault.clone(), request)?;
        self.admit(&edge)?;
        self.commit_recorded(&edge, PolicyAction::Created, ledger)?;
        Ok(edge)
    }

    /// Sign, record and publish `N+1` of an existing edge.
    ///
    /// # Why the recorded head is consulted
    ///
    /// The artifact is not the only witness to a revision. A crash between the ledger
    /// append and the publish leaves the ledger one revision ahead of the directory,
    /// and signing `N+1` from the artifact would then write a second decision for a
    /// revision already recorded. Three outcomes, and each is a different action:
    ///
    /// - nothing recorded, or a strictly greater revision: record, then publish;
    /// - the identical decision recorded: publish only, which is how an interrupted
    ///   attempt is completed (Ed25519 is deterministic, so the retry's body and
    ///   digest are the same decision);
    /// - a later revision recorded, or the same revision with different bytes: refuse
    ///   and name the recorded revision. That is the compare-and-swap.
    pub fn update(
        &self,
        admin: &AdminSigningKey,
        issuer_key_id: KeyId,
        id: &PolicyId,
        request: EdgeRequest,
        ledger: &IssuanceLedger,
    ) -> Result<PolicyEdge, EdgeStoreError> {
        let replaced = self.load(id)?;
        let edge = PolicyEdge::update(admin, issuer_key_id, &replaced, request)?;
        self.admit(&edge)?;
        self.commit_recorded(&edge, PolicyAction::Updated, ledger)?;
        Ok(edge)
    }

    /// Stage the artifact, record the decision, then publish it.
    ///
    /// The order is the control and the staging is what makes it completable:
    ///
    /// - a failure to **stage** records nothing, so the ledger and the tree agree;
    /// - a failure to **record** removes the staged bytes, so nothing is left behind;
    /// - a failure to **commit** keeps them and names their path, because the decision
    ///   is on record and the bytes that make it real are still on disk. A retry of an
    ///   update re-signs the same revision and completes it; for a create the staged
    ///   file is the completion, so the refusal says where it is.
    fn commit_recorded(
        &self,
        edge: &PolicyEdge,
        action: PolicyAction,
        ledger: &IssuanceLedger,
    ) -> Result<(), EdgeStoreError> {
        let staged = self.stage(edge)?;
        if let Err(error) = self.record(edge, action, ledger) {
            let _ = std::fs::remove_file(&staged);
            return Err(error);
        }
        self.commit(edge, &staged).map(|_| ())
    }

    /// Append the decision, once, before anything is written.
    fn record(
        &self,
        edge: &PolicyEdge,
        action: PolicyAction,
        ledger: &IssuanceLedger,
    ) -> Result<RevisionDecision, EdgeStoreError> {
        let entry = PolicyLedgerEntry::for_edge(edge, action, self.admin, now_seconds() as i64)?;
        let head = ledger
            .policy_head(edge.id())
            .map_err(|error| EdgeStoreError::Ledger {
                path: ledger.policy_events_path().display().to_string(),
                cause: error.to_string(),
            })?;
        let decision = guard(head.as_ref(), &entry)?;
        if decision == RevisionDecision::AlreadyRecorded {
            return Ok(decision);
        }
        ledger
            .record_policy(&entry)
            .map_err(|error| EdgeStoreError::Ledger {
                path: ledger.policy_events_path().display().to_string(),
                cause: error.to_string(),
            })?;
        Ok(decision)
    }

    /// The checks that must pass before an artifact exists.
    fn admit(&self, edge: &PolicyEdge) -> Result<(), EdgeStoreError> {
        let registry = PrincipalRegistry::load(self.layout)?;
        let links = DeploymentLinks::new(self.layout, &registry, self.vault.clone(), *edge.user());
        let result = check_links(&links, edge.body());
        if let Some(backend) = links.unavailable() {
            return Err(EdgeStoreError::LinkCheckUnavailable { backend });
        }
        result?;
        if let Some(existing) = self.active_conflict(edge)? {
            return Err(EdgeStoreError::Refused(EdgeRefusal::SecondActive {
                existing,
            }));
        }
        Ok(())
    }
}

/// The links an edge names, resolved against this deployment.
///
/// The user set comes from the **registry**, never from `deployment.cbor`: that
/// record names one user, and an edge for the second user would be refused as
/// dangling by a check that read it (CF-008).
pub struct DeploymentLinks<'a> {
    layout: &'a Layout,
    registry: &'a PrincipalRegistry,
    vault: VaultId,
    user: PrincipalId,
    /// The backend whose store could not be consulted, when there was one.
    ///
    /// A boolean trait method cannot say "I could not check"; answering `false`
    /// would refuse a valid grant and report it as a dangling secret. So the reason
    /// is recorded here and raised by the caller that admits the edge.
    unavailable: std::cell::Cell<Option<&'static str>>,
}

impl<'a> DeploymentLinks<'a> {
    /// The link check for one deployment, for a reader that must report `dangling`.
    ///
    /// The same three questions admission asks, asked of the same places: a read
    /// surface that decided `dangling` another way would be a second answer to "does
    /// this edge name something that exists".
    pub fn new(
        layout: &'a Layout,
        registry: &'a PrincipalRegistry,
        vault: VaultId,
        user: PrincipalId,
    ) -> Self {
        Self {
            layout,
            registry,
            vault,
            user,
            unavailable: std::cell::Cell::new(None),
        }
    }

    /// The backend that could not be consulted, if any link could not be resolved.
    pub fn unavailable(&self) -> Option<&'static str> {
        self.unavailable.get()
    }
}

impl LinkCheck for DeploymentLinks<'_> {
    fn user_exists(&self, user: &PrincipalId) -> bool {
        self.registry.entry(*user).is_some()
    }

    fn agent_exists(&self, agent: ksp_types::AgentId) -> bool {
        // The owner's published index, not her home-local pin: the admin cannot read
        // another account's `0700` home, which is why the index exists (CF-011).
        crate::agent_index::exists(self.layout, &self.vault, self.user, &agent)
    }

    fn secret_version_exists(&self, secret: &OpaqueSecretId, version: RecordVersion) -> bool {
        // Only the `file` backend can be opened without a live connection. On the
        // other two the caller already holds a client, so this check reports that it
        // could not run rather than answering `false` — a false here would refuse a
        // valid grant for the wrong reason.
        let backend = match crate::config::read_backend(self.layout) {
            Ok(selection) => selection.name(),
            Err(_) => {
                self.unavailable.set(Some("the configured"));
                return false;
            }
        };
        if backend != "file" {
            self.unavailable.set(Some(backend));
            return false;
        }
        let Ok(store) = crate::config::open_file_store(self.layout) else {
            self.unavailable.set(Some(backend));
            return false;
        };
        use ksp_record::version::BlobStore;
        let stored_at = |owner: PrincipalId, level: Level| {
            let metadata = BoundMetadata {
                vault_id: self.vault.clone(),
                user_id: owner,
                level,
                secret_id: secret.clone(),
                version: version.get(),
            };
            store
                .get(ksp_record::RecordPath::of(&metadata).as_str())
                .ok()
                .flatten()
                .is_some()
        };
        // The version may live in either place, and both are legitimate. UC1 has the
        // admin create the secret on **her own vault** and publish it, so the record
        // the grant names is the admin's `admin`-level one at her principal; UC7 has
        // her transfer a copy, which is the user's `user`-level one at the user's.
        //
        // Checking only the user's level was a defect this work package found: it
        // refused every policy-only secret with "that version is not stored", which is
        // the exact case the feature exists for — a user who never holds the value.
        // The question FR-010 and FR-031 ask is whether the named version exists in
        // this deployment, not which principal wrote it.
        if stored_at(self.user, Level::User) {
            return true;
        }
        self.registry
            .admin_entries()
            .any(|admin| stored_at(admin.principal, Level::Admin))
    }
}

/// Why an edge could not be published, read or admitted.
#[derive(Debug, thiserror::Error)]
pub enum EdgeStoreError {
    /// The edge was refused by the model.
    #[error(transparent)]
    Refused(#[from] EdgeRefusal),
    /// The ledger refused the revision: a regression, or a rewrite of a signed one.
    #[error(transparent)]
    Revision(#[from] ksp_identity::policy_edge::RevisionRefusal),
    /// The decision was recorded and the artifact was not written.
    ///
    /// The ledger is the authority and it already holds this revision, so the change is
    /// on record and the artifact is not. A `create` cannot be retried into completion —
    /// its identifier was generated for this attempt — and an `update` can: the same
    /// request re-signs the same revision, the guard reports it as already recorded, and
    /// the publish is what completes it.
    #[error(
        "policy {policy} revision {revision} was recorded, but its artifact could not be published: {cause}; the ledger holds a decision the tree does not show, and the signed bytes are staged at {}",
        pending.as_deref().unwrap_or("(no staging file)")
    )]
    RecordedNotPublished {
        /// The policy the decision names.
        policy: String,
        /// The revision the decision recorded.
        revision: u64,
        /// Why the artifact could not be published.
        cause: String,
        /// The staged bytes that complete it, when they survived.
        pending: Option<String>,
    },
    /// The decision could not be recorded, so nothing was written.
    ///
    /// Names the ledger, not the policy: the policy is fine and the file that has to
    /// witness the change is the thing that is not.
    #[error(
        "the policy ledger at {path} could not record the decision, so nothing was changed: {cause}"
    )]
    Ledger {
        /// The file that refused the append.
        path: String,
        /// Why it refused.
        cause: String,
    },
    /// The registry could not be read.
    #[error(transparent)]
    Registry(#[from] crate::registry::RegistryError),
    /// No artifact exists at the expected path.
    #[error("this deployment holds no policy edge at {path}")]
    Absent {
        /// The path that was read.
        path: String,
    },
    /// An artifact exists and is not one this build wrote.
    #[error("the policy edge at {path} is not readable by this build")]
    Unreadable {
        /// The path that was read.
        path: String,
    },
    /// The edge directory could not be read.
    ///
    /// An empty directory and an unreadable one are different facts, and only one of
    /// them means "this deployment grants nothing". The uniqueness check reads this
    /// set, so a list that answered "empty" when it could not look would admit a
    /// second active edge for one tuple.
    #[error(
        "the policy directory at {path} could not be read: a grant list that cannot be read is not an empty grant list, so nothing was granted or withdrawn"
    )]
    Unlistable {
        /// The directory that was read.
        path: String,
    },
    /// The artifact carries an identifier other than the one its path names.
    #[error(
        "the policy edge at {path} names identifier {named} in its body: an identifier is the authority it names, and re-signing this artifact would write over an edge that was never loaded"
    )]
    Misidentified {
        /// The path the artifact sits at.
        path: String,
        /// The identifier the body carries.
        named: String,
    },
    /// The artifact belongs to another vault.
    #[error(
        "the policy edge at {path} names vault {vault}, and this store holds one vault: an edge admitted across vaults would authorise a secret it does not govern"
    )]
    ForeignVault {
        /// The path the artifact sits at.
        path: String,
        /// The vault the body names.
        vault: String,
    },
    /// The artifact names a key other than the pinned admin key.
    #[error(
        "the policy edge at {path} was signed by {issuer}, and this deployment's admin key is {expected}: an edge is authority only under the key that signed it, so a signature under another key establishes nothing"
    )]
    ForeignIssuer {
        /// The path the artifact sits at.
        path: String,
        /// The key ID the artifact claims.
        issuer: String,
        /// The pinned admin key ID.
        expected: String,
    },
    /// The artifact claims the admin key and does not verify under it.
    #[error(
        "the policy edge at {path} does not verify against the pinned admin anchor: the body and the signature disagree, so this artifact is not an edge this deployment issued"
    )]
    Unverified {
        /// The path the artifact sits at.
        path: String,
    },
    /// The pinned anchor could not be read, so no artifact can be trusted.
    #[error("the admin anchor could not be read, so a policy edge cannot be verified: {cause}")]
    Anchor {
        /// The pin reader's own words.
        cause: String,
    },
    /// An artifact or its directory could not be written.
    #[error("the policy edge at {path} could not be written")]
    Write {
        /// The path that was written.
        path: String,
    },
    /// The secret version could not be checked, so the edge is not refused as
    /// dangling and not admitted either.
    #[error(
        "the secret version could not be checked on the {backend} store: a command can open only a `file` store, so an edge for any other backend is issued from the lifecycle path, which holds a live client — this edge was not signed"
    )]
    LinkCheckUnavailable {
        /// The backend that could not be consulted.
        backend: &'static str,
    },
}
