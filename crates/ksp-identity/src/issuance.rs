//! The issuance ledger: what *this* host minted, and which of it it no longer
//! honours.
//!
//! An agent holds a token as a file. Nothing about that file records where it
//! came from, so a foreground process that exits leaves no way to answer "what
//! did this machine issue, and is it still good?" (Misfit R). This module is the
//! minting host's own record — appended inside the mint's publication closure so
//! an entry exists only for a token that was actually sealed.
//!
//! # What a revocation is, and what it is not
//!
//! A mark here is **trust state**, never a claim about a copied artifact. It
//! stops future mints (when the grant is also withdrawn from the policy) and it
//! is honoured by any client that holds this ledger. It does not recall a token
//! an agent already copied: those bytes are sealed to a recipient key this host
//! never had, and no local file can reach them. [`REVOCATION_REACH`] states both
//! halves, and `tests/issuance.rs` opens a pre-revocation artifact with the
//! agent's own key after the mark is written, so the second half is demonstrated
//! rather than asserted.
//!
//! # Three states, not two
//!
//! A ledger that does not name a token is [`TokenStanding::Unknown`], never
//! "invalid": a token presented on a host that never minted it is unremarkable,
//! and a host with no ledger at all cannot judge one. Refusing a token because
//! this host has no record of it would be a false accusation, and it would break
//! every deployment where the mint and the run are different machines.
//!
//! # Why a local file, and why owner-only
//!
//! There is no registry service here: no listening socket, no replication, no
//! publishing command. The ledger is a file beside the deployment, readable by
//! the commands on this host and by nothing else. It is opened `0600` and an
//! existing ledger whose mode has widened is refused rather than appended to.
//! Entries carry identifiers and deadlines only — no key, no content key, no
//! value — so the check is about the trust state staying local, not about
//! protecting a plaintext that was never there. The file is opened `O_NOFOLLOW`
//! and a directory created for it is `0700`, so the claim covers the path and
//! the name, not only the mode of the file the path resolves to.
//!
//! # A crash can cut the tail, and nothing else
//!
//! One short append is one write, so the only damage a crash can do is to cut
//! the final line. Reading reports that and keeps the complete entries; appending
//! **refuses** until the file is repaired by its owner, because gluing a new
//! decision onto a fragment produces a line the reader classifies as torn and
//! drops — a revocation that reports success and does not survive.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use ksp_types::{AgentId, OpaqueSecretId, RecordVersion};
use serde::{Deserialize, Serialize};

use crate::enrolment::AdminSigningKey;
pub use crate::policy::Withdrawal;
use crate::policy::{Policy, PolicyRefusal};

/// What a revocation reaches, in the words the command prints.
///
/// Both halves are in one sentence on purpose: an operator who reads only
/// "revoked" will assume the copy in the agent's directory stopped working.
pub const REVOCATION_REACH: &str = "revocation stops future mints and is honoured by every client that holds this ledger; \
     it does not recall a copy taken earlier, which still opens with the agent's own key";

/// One token this host minted.
///
/// Identifiers, a version, a deadline and the policy revision that authorised
/// it. There is deliberately no field that could hold a secret, a content key or
/// a value: the ledger is trust state, and a type that cannot carry a key cannot
/// leak one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuance {
    /// The token's opaque identifier — the `jti` its header carries, never a name.
    pub token_id: String,
    /// The agent the delivery was sealed to.
    pub agent: AgentId,
    /// The `user`-level secret the copy was taken from.
    pub secret: OpaqueSecretId,
    /// The exact record version that was shared.
    pub version: RecordVersion,
    /// The armed deadline, in Unix seconds.
    pub deadline: i64,
    /// The policy revision that authorised the mint.
    pub policy_revision: u64,
}

/// A decision that one token identifier is no longer honoured here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationMark {
    /// The identifier that was marked.
    pub token_id: String,
    /// When the mark was written, in Unix seconds.
    pub at: i64,
}

/// A decision that one grant is withdrawn, recorded so a client sees it without
/// re-verifying a whole policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantWithdrawal {
    /// Which grant was removed, in the same form the policy named it.
    pub withdrawal: Withdrawal,
    /// The narrower policy revision the admin signed.
    pub policy_revision: u64,
    /// When the withdrawal was recorded, in Unix seconds.
    pub at: i64,
}

impl GrantWithdrawal {
    /// The record of a policy revision that removed `withdrawal`.
    pub fn new(withdrawal: &Withdrawal, policy_revision: u64, at: i64) -> Self {
        Self {
            withdrawal: withdrawal.clone(),
            policy_revision,
            at,
        }
    }

    /// Whether two records describe the same decision.
    ///
    /// The second a retry observed is not part of the decision: a crash that lost
    /// the policy write leaves the same grant and the same revision, and only the
    /// clock has moved.
    pub fn same_decision(&self, other: &Self) -> bool {
        self.withdrawal == other.withdrawal && self.policy_revision == other.policy_revision
    }

    /// Whether this withdrawal covers a token minted for `issuance`.
    ///
    /// A withdrawal reaches every token minted under the grant *up to and
    /// including* its own revision. A token minted later under a revision that
    /// re-granted the same pair is not covered: a re-grant is a new trust state,
    /// and pretending the old withdrawal still bites would make a legitimate
    /// grant unusable for the life of the vault.
    pub fn covers(&self, issuance: &Issuance) -> bool {
        let grant_removed = match &self.withdrawal {
            Withdrawal::Secret(secret) => secret == &issuance.secret,
            Withdrawal::Agent(agent) => agent == &issuance.agent,
        };
        grant_removed && self.policy_revision >= issuance.policy_revision
    }
}

/// Why a client holding this ledger no longer honours a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationReason {
    /// `token revoke` marked this identifier directly.
    TokenMarked,
    /// `admin revoke` withdrew the grant the token was minted under, and the
    /// narrower policy revision names it.
    GrantWithdrawn {
        /// The revision of the policy that removed the grant.
        policy_revision: u64,
    },
}

impl fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TokenMarked => f.write_str("the token identifier was marked revoked"),
            Self::GrantWithdrawn { policy_revision } => write!(
                f,
                "the grant was withdrawn by policy revision {policy_revision}"
            ),
        }
    }
}

/// What this host can say about one token identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenStanding {
    /// The ledger names the token and holds no mark against it.
    Live(Issuance),
    /// The ledger names the token and something marks it.
    Revoked {
        /// What this host minted.
        issuance: Issuance,
        /// The decision that no longer honours it.
        reason: RevocationReason,
        /// When that decision was recorded.
        at: i64,
    },
    /// The ledger does not name the token.
    Unknown {
        /// Distinguishes "this host holds a ledger without this entry" from
        /// "this host holds no ledger at all". Only the second cannot judge.
        ledger_present: bool,
    },
}

impl TokenStanding {
    /// Whether a local run must refuse this token.
    ///
    /// Only a mark refuses. Unknown never does: this host not having minted a
    /// token says nothing about the token.
    pub fn refuses_run(&self) -> bool {
        matches!(self, Self::Revoked { .. })
    }

    /// Whether this host has enough state to judge the identifier at all.
    pub fn can_judge(&self) -> bool {
        !matches!(
            self,
            Self::Unknown {
                ledger_present: false
            }
        )
    }

    /// The decision behind a refusal, if there is one.
    pub fn reason(&self) -> Option<&RevocationReason> {
        match self {
            Self::Revoked { reason, .. } => Some(reason),
            Self::Live(_) | Self::Unknown { .. } => None,
        }
    }

    /// What to print beside the standing, in words that state the reach honestly.
    pub fn note(&self) -> &'static str {
        match self {
            Self::Live(_) => {
                "this host minted this token and holds no revocation against it; \
                 that is not a promise that it will be honoured anywhere else"
            }
            Self::Revoked { .. } => REVOCATION_REACH,
            Self::Unknown {
                ledger_present: true,
            } => {
                "this host has no record of this token: it is unknown here, \
                 which is not a judgement about the token"
            }
            Self::Unknown {
                ledger_present: false,
            } => {
                "there is no issuance ledger on this host, so it cannot judge \
                 whether this token was revoked"
            }
        }
    }
}

/// Whether this host holds a ledger at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerState {
    /// No ledger file: this host has recorded nothing, and can judge nothing.
    Absent,
    /// A ledger file exists, whether or not it has entries.
    Present,
}

/// One recorded issuance and whatever this host holds against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    /// What was minted.
    pub issuance: Issuance,
    /// The mark that no longer honours it, if any.
    pub reason: Option<RevocationReason>,
    /// When that mark was written, if any.
    pub revoked_at: Option<i64>,
}

/// What `token list` reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerListing {
    /// Whether the host holds a ledger at all.
    pub state: LedgerState,
    /// One entry per token this host minted, in the order it minted them.
    pub entries: Vec<LedgerEntry>,
    /// A final line that was cut short by a crash mid-append.
    ///
    /// It is reported rather than raised: a torn tail cannot name a token that
    /// reached an agent, because the entry is written before the artifact leaves
    /// the publish closure, so the honest response is to say the file was cut
    /// and keep the complete entries. Appending to a file in this state is
    /// refused — see [`LedgerError::TornTail`].
    pub torn_tail: bool,
}

impl LedgerListing {
    /// The honest scope of this listing.
    ///
    /// A claim about this host, never about tokens in general: an empty ledger
    /// means this host minted nothing, not that no token exists.
    pub fn scope(&self) -> String {
        ledger_scope(self.state, self.entries.len())
    }
}

/// The scope sentence for a state and a count.
pub fn ledger_scope(state: LedgerState, count: usize) -> String {
    match state {
        LedgerState::Absent => {
            "no issuance ledger on this host: it has no record of any token minted here, \
             and a token minted elsewhere is unknown here"
                .to_string()
        }
        LedgerState::Present => format!(
            "{count} token(s) minted on this host; a token minted elsewhere is unknown here"
        ),
    }
}

/// Why a revocation could not be recorded.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// The ledger could not be read or written.
    #[error("the issuance ledger at {path} could not be used: {cause}")]
    Io {
        /// The ledger path.
        path: PathBuf,
        /// What the filesystem or the encoder said.
        cause: String,
    },
    /// A line inside the ledger is not one this build understands.
    #[error("line {line} of the issuance ledger is not a record this build understands")]
    Corrupt {
        /// The one-based line number.
        line: usize,
    },
    /// The ledger is readable by someone other than its owner.
    #[error("the issuance ledger has mode {mode:o}: it must not be readable by anyone else")]
    InsecurePermissions {
        /// The mode that was found.
        mode: u32,
    },
    /// The file does not end at a line boundary, so appending would glue a new
    /// decision onto a fragment a crash left behind.
    ///
    /// Refused rather than repaired: rewriting the file to drop the fragment
    /// would discard whatever that fragment was, and appending would produce a
    /// line that the reader classifies as torn and drops — a revocation that
    /// reports success and does not survive.
    #[error(
        "the issuance ledger at {path} does not end at a line boundary: a crash cut its last entry, and appending would lose this decision. Inspect the file and repair or remove it as its owner"
    )]
    TornTail {
        /// The ledger path.
        path: PathBuf,
    },
    /// The ledger names no such token.
    #[error("this host has no record of token {token_id}, so there is nothing to revoke")]
    UnknownToken {
        /// The identifier that was offered.
        token_id: String,
    },
}

/// Why an admin revocation was refused.
#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    /// The policy refused the withdrawal, so nothing was signed and nothing marked.
    #[error(transparent)]
    Policy(#[from] PolicyRefusal),
    /// The narrower revision was signed but the ledger refused to record it.
    ///
    /// The narrower policy is **not** handed back: a revision that this host
    /// cannot see in its own ledger would stop future mints here while leaving
    /// local clients believing the token is still live.
    #[error("the withdrawal was not recorded: {0}")]
    Ledger(#[from] LedgerError),
}

/// What `admin revoke` produced: a narrower signed policy, and the ledger record
/// of the same decision.
#[derive(Debug, Clone)]
pub struct AdminRevocation {
    /// The next revision, with the grant removed and the admin's signature over it.
    pub policy: Policy,
    /// The ledger record a local client reads without verifying a policy.
    pub withdrawal: GrantWithdrawal,
}

/// Why a publication stopped.
#[derive(Debug)]
pub enum PublishError<E> {
    /// The seal failed, so nothing was published and nothing was recorded.
    Seal(E),
    /// The seal succeeded and the ledger refused the entry, so the artifact was
    /// dropped rather than handed to the caller.
    Ledger(LedgerError),
}

impl<E: fmt::Display> fmt::Display for PublishError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seal(cause) => write!(f, "the delivery could not be sealed: {cause}"),
            Self::Ledger(cause) => write!(f, "the delivery was sealed but not recorded: {cause}"),
        }
    }
}

/// One event in the append-only ledger file.
///
/// The file is a log, not a mutable document: a revocation appends a decision
/// rather than rewriting an entry, so a crash can only ever cut the tail, never
/// half-rewrite a token that was already recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum LedgerEvent {
    Issued { issuance: Issuance },
    TokenRevoked { mark: RevocationMark },
    GrantWithdrawn { withdrawal: GrantWithdrawal },
}

/// The ledger file this host writes beside its deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceLedger {
    path: PathBuf,
}

impl IssuanceLedger {
    /// A ledger at `path`. No file is created until the first entry.
    pub fn at(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// The path this ledger reads and writes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Seal first, record second, and only then hand the artifact back.
    ///
    /// This is the body a mint's publication closure runs, and the order is the
    /// whole point:
    ///
    /// - a seal that fails records nothing, so an entry never names an artifact
    ///   that was never made;
    /// - a ledger that refuses the entry drops the artifact instead of returning
    ///   it, so a token cannot reach an agent with no record behind it.
    ///
    /// A mint that is refused before its arm never reaches this call at all,
    /// which is why an armed-but-unpublished mint leaves the ledger empty.
    ///
    /// The asymmetry is deliberate: the caller's own output step can still fail
    /// after this returns, which leaves an entry naming a token no agent holds.
    /// That direction is benign — a record of something that did not reach an
    /// agent — while the reverse, a token that reached an agent with no record,
    /// is the one this order makes impossible.
    pub fn publish_recorded<T, E>(
        &self,
        issuance: Issuance,
        seal: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, PublishError<E>> {
        let published = seal().map_err(PublishError::Seal)?;
        self.append(&LedgerEvent::Issued { issuance })
            .map_err(PublishError::Ledger)?;
        Ok(published)
    }

    /// Mark one token identifier as no longer honoured here.
    ///
    /// Refuses an identifier the ledger does not name — there is nothing to
    /// revoke, and writing a mark for a token this host never minted would turn
    /// a local file into an accusation about someone else's token. Marking twice
    /// is a no-op that returns the earlier mark, so a retried command cannot
    /// produce two decisions where one was made.
    pub fn revoke(&self, token_id: &str, at: i64) -> Result<RevocationMark, LedgerError> {
        let contents = self.read()?;
        if contents.issued(token_id).is_none() {
            return Err(LedgerError::UnknownToken {
                token_id: token_id.to_string(),
            });
        }
        if let Some(mark) = contents.mark_for(token_id) {
            return Ok(mark.clone());
        }
        let mark = RevocationMark {
            token_id: token_id.to_string(),
            at,
        };
        self.append(&LedgerEvent::TokenRevoked { mark: mark.clone() })?;
        Ok(mark)
    }

    /// Record that one grant was withdrawn at a signed policy revision.
    ///
    /// Idempotent on the *decision*, not on the timestamp: a retry at a later
    /// second reports the record that is already in force instead of appending a
    /// second one. That is what makes a retried `admin revoke` safe after a crash
    /// between the mark and the caller's policy write.
    pub fn withdraw_grant(
        &self,
        withdrawal: &GrantWithdrawal,
    ) -> Result<GrantWithdrawal, LedgerError> {
        let contents = self.read()?;
        if let Some(existing) = contents
            .withdrawals
            .iter()
            .find(|seen| seen.same_decision(withdrawal))
        {
            return Ok(existing.clone());
        }
        self.append(&LedgerEvent::GrantWithdrawn {
            withdrawal: withdrawal.clone(),
        })?;
        Ok(withdrawal.clone())
    }

    /// The grant withdrawals this ledger holds, in the order they were written.
    ///
    /// Read-only and public because verification needs it: a record signed by an
    /// agent whose grant was withdrawn is reported with the policy revision and time
    /// that withdrew it (FR-052), and the current policy cannot say when. An absent
    /// ledger yields an empty list — this host recorded no withdrawal, which is a
    /// fact about this host and not about grants in general.
    pub fn withdrawals(&self) -> Result<Vec<GrantWithdrawal>, LedgerError> {
        let contents = self.read()?;
        // A cut last line may have been a withdrawal. Reading through it would
        // report an agent as current on the strength of a decision this file
        // cannot show, so the caller is told the list is not whole.
        if contents.torn_tail {
            return Err(LedgerError::TornTail {
                path: self.path().to_path_buf(),
            });
        }
        Ok(contents.withdrawals)
    }

    /// Everything this host minted, with the marks it holds against each.
    pub fn listing(&self) -> Result<LedgerListing, LedgerError> {
        let contents = self.read()?;
        let mut entries = Vec::with_capacity(contents.issuances.len());
        for issuance in &contents.issuances {
            let standing = contents.standing_for(issuance);
            let (reason, revoked_at) = match standing {
                TokenStanding::Revoked { reason, at, .. } => (Some(reason), Some(at)),
                TokenStanding::Live(_) | TokenStanding::Unknown { .. } => (None, None),
            };
            entries.push(LedgerEntry {
                issuance: issuance.clone(),
                reason,
                revoked_at,
            });
        }
        Ok(LedgerListing {
            state: contents.state(),
            entries,
            torn_tail: contents.torn_tail,
        })
    }

    /// What this host can say about one identifier.
    pub fn standing(&self, token_id: &str) -> Result<TokenStanding, LedgerError> {
        let contents = self.read()?;
        Ok(match contents.issued(token_id) {
            Some(issuance) => contents.standing_for(issuance),
            None => TokenStanding::Unknown {
                ledger_present: contents.present,
            },
        })
    }

    fn read(&self) -> Result<Contents, LedgerError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(Contents {
                    present: false,
                    torn_tail: false,
                    issuances: Vec::new(),
                    marks: Vec::new(),
                    withdrawals: Vec::new(),
                });
            }
            Err(error) => return Err(self.io(&error)),
        };
        let text = String::from_utf8(bytes).map_err(|_| LedgerError::Io {
            path: self.path.clone(),
            cause: "the file is not text".to_string(),
        })?;

        let lines: Vec<&str> = text.lines().collect();
        let mut contents = Contents {
            present: true,
            torn_tail: false,
            issuances: Vec::new(),
            marks: Vec::new(),
            withdrawals: Vec::new(),
        };
        for (index, line) in lines.iter().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<LedgerEvent>(line) {
                Ok(LedgerEvent::Issued { issuance }) => contents.issuances.push(issuance),
                Ok(LedgerEvent::TokenRevoked { mark }) => contents.marks.push(mark),
                Ok(LedgerEvent::GrantWithdrawn { withdrawal }) => {
                    contents.withdrawals.push(withdrawal);
                }
                // Only the final line may be truncated: earlier lines were
                // followed by a complete append, so a damaged one is corruption.
                Err(_) if index + 1 == lines.len() => contents.torn_tail = true,
                Err(_) => {
                    return Err(LedgerError::Corrupt { line: index + 1 });
                }
            }
        }
        Ok(contents)
    }

    fn append(&self, event: &LedgerEvent) -> Result<(), LedgerError> {
        self.refuse_a_torn_tail()?;

        let mut line = serde_json::to_string(event).map_err(|error| LedgerError::Io {
            path: self.path.clone(),
            cause: error.to_string(),
        })?;
        line.push('\n');

        // Whether this append is also the file's creation decides whether the
        // parent directory needs syncing: a new file whose directory entry has
        // not reached the disk can vanish in a power loss, which would be a token
        // without the record this module promises precedes it.
        let existed = self.path.exists();

        let mut file = self.open_for_append()?;
        // One write of one short line: the smallest window a crash can tear, and
        // the reason a torn tail is the only damage this file can suffer.
        file.write_all(line.as_bytes())
            .map_err(|error| self.io(&error))?;
        file.sync_all().map_err(|error| self.io(&error))?;
        if !existed {
            self.sync_parent_directory()?;
        }
        Ok(())
    }

    /// Refuse to append onto a file that does not end at a line boundary.
    ///
    /// Reads the last byte rather than trusting the parse: a complete line that
    /// lost its newline parses fine and still cannot be appended to.
    fn refuse_a_torn_tail(&self) -> Result<(), LedgerError> {
        match fs::read(&self.path) {
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(self.io(&error)),
            Ok(bytes) if bytes.is_empty() => Ok(()),
            Ok(bytes) if bytes.last().is_some_and(|byte| *byte != b'\n') => {
                Err(LedgerError::TornTail {
                    path: self.path.clone(),
                })
            }
            Ok(_) => Ok(()),
        }
    }

    fn open_for_append(&self) -> Result<File, LedgerError> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            self.create_owner_only_directory(parent)?;
        }

        let mut options = OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // `O_NOFOLLOW`: the ledger is a file this host chose, never whatever a
            // symlink at that path points at.
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(&self.path).map_err(|error| self.io(&error))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = file
                .metadata()
                .map_err(|error| self.io(&error))?
                .permissions()
                .mode()
                & 0o777;
            if mode & 0o077 != 0 {
                return Err(LedgerError::InsecurePermissions { mode });
            }
        }
        Ok(file)
    }

    /// Make the new file's directory entry as durable as its contents.
    #[cfg(unix)]
    fn sync_parent_directory(&self) -> Result<(), LedgerError> {
        let Some(parent) = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        else {
            return Ok(());
        };
        let directory = File::open(parent).map_err(|error| self.io(&error))?;
        directory.sync_all().map_err(|error| self.io(&error))
    }

    #[cfg(not(unix))]
    fn sync_parent_directory(&self) -> Result<(), LedgerError> {
        Ok(())
    }

    #[cfg(unix)]
    fn create_owner_only_directory(&self, parent: &Path) -> Result<(), LedgerError> {
        use std::os::unix::fs::DirBuilderExt;

        // `0700` for the directory as well as `0600` for the file: a `0755`
        // directory would publish the ledger's name even though its contents
        // stay private.
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|error| self.io(&error))
    }

    #[cfg(not(unix))]
    fn create_owner_only_directory(&self, parent: &Path) -> Result<(), LedgerError> {
        fs::create_dir_all(parent).map_err(|error| self.io(&error))
    }

    fn io(&self, error: &std::io::Error) -> LedgerError {
        LedgerError::Io {
            path: self.path.clone(),
            cause: error.to_string(),
        }
    }
}

/// The folded contents of the ledger file.
struct Contents {
    present: bool,
    torn_tail: bool,
    issuances: Vec<Issuance>,
    marks: Vec<RevocationMark>,
    withdrawals: Vec<GrantWithdrawal>,
}

impl Contents {
    fn state(&self) -> LedgerState {
        if self.present {
            LedgerState::Present
        } else {
            LedgerState::Absent
        }
    }

    fn issued(&self, token_id: &str) -> Option<&Issuance> {
        self.issuances
            .iter()
            .find(|issuance| issuance.token_id == token_id)
    }

    fn mark_for(&self, token_id: &str) -> Option<&RevocationMark> {
        self.marks.iter().find(|mark| mark.token_id == token_id)
    }

    fn standing_for(&self, issuance: &Issuance) -> TokenStanding {
        if let Some(mark) = self.mark_for(&issuance.token_id) {
            return TokenStanding::Revoked {
                issuance: issuance.clone(),
                reason: RevocationReason::TokenMarked,
                at: mark.at,
            };
        }
        if let Some(withdrawal) = self
            .withdrawals
            .iter()
            .find(|withdrawal| withdrawal.covers(issuance))
        {
            return TokenStanding::Revoked {
                issuance: issuance.clone(),
                reason: RevocationReason::GrantWithdrawn {
                    policy_revision: withdrawal.policy_revision,
                },
                at: withdrawal.at,
            };
        }
        TokenStanding::Live(issuance.clone())
    }
}

/// Withdraw one grant: sign the narrower revision, then record the decision.
///
/// The order is the contract with a local client. The narrower policy is built
/// and signed first, so a withdrawal that withdraws nothing is refused before
/// anything is written; the ledger record is written second, and if it cannot be
/// the narrower policy is dropped rather than returned. What is never produced is
/// the third combination: a signed revision in the caller's hands that this
/// host's own ledger does not know about, where the next mint refuses for a
/// reason no local command can show.
///
/// The residual is the other direction: a crash between the mark and the
/// caller's policy write leaves a record naming a revision no file contains, so a
/// local client refuses a token the still-current policy grants. That is the
/// direction this order chose — a false refusal, healed by running the command
/// again, rather than a token left live locally against a grant the next mint
/// already refuses. The retry is safe: the second call signs the same revision
/// from the same policy and [`IssuanceLedger::withdraw_grant`] reports the record
/// already in force instead of appending a second one.
pub fn admin_revoke(
    ledger: &IssuanceLedger,
    admin: &AdminSigningKey,
    policy: &Policy,
    withdrawal: Withdrawal,
    at: i64,
) -> Result<AdminRevocation, RevocationError> {
    let policy = policy.withdraw(admin, &withdrawal)?;
    let record = GrantWithdrawal::new(&withdrawal, policy.revision(), at);
    let withdrawal = ledger.withdraw_grant(&record)?;
    Ok(AdminRevocation { policy, withdrawal })
}
