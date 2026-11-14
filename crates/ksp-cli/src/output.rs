//! The single point where the binary produces output.
//!
//! # Redaction is structural here, not a filter
//!
//! FR-044 and FR-051 say the system never logs a secret value and never accepts
//! plaintext secret input in argv or inherited environment. A redaction pass that
//! *removes* secrets is a filter with a hole in it: it is only as good as the
//! pattern list, and the day a value has an unexpected shape it is printed.
//!
//! So nothing that reaches this module can hold a value. [`AuditEvent`] has a
//! closed field set — an opaque record identifier, a version, an actor and an
//! outcome — and there is no constructor parameter anywhere in this file that
//! takes secret material. [`Report`] carries the two shapes a command may print:
//! a status disclosure and a metadata line, both of which are built from the
//! structures the subsystems already publish, none of which contain a value.
//!
//! The one declared exception is `ksp run --env`, which deliberately hands
//! plaintext to a child. It does so through the child's environment, never
//! through this module.

use std::io::Write;

use ksp_backend::status::StatusReport;
use serde::Serialize;

/// What an audit event records about one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AuditOutcome {
    /// The operation completed.
    Success,
    /// The operation was refused.
    Refused,
    /// The operation failed.
    Failed,
}

/// One audit event.
///
/// The field set is the redaction rule: there is nowhere to put a value, a key, a
/// raw token or proof material. An identifier is opaque on purpose — it names a
/// record the store already knows, not its contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    /// The operation, as the command surface names it.
    pub operation: String,
    /// The opaque record identifier, when the operation had one.
    pub record: Option<String>,
    /// The record version, when the operation had one.
    pub version: Option<u32>,
    /// The actor that performed the operation.
    pub actor: String,
    /// What happened.
    pub outcome: AuditOutcome,
    /// The exit code the operation produced.
    pub code: i32,
}

impl AuditEvent {
    /// Build an event. Every argument is an identifier or an outcome; none is a
    /// value.
    pub fn new(
        operation: impl Into<String>,
        actor: impl Into<String>,
        outcome: AuditOutcome,
        code: i32,
    ) -> Self {
        Self {
            operation: operation.into(),
            record: None,
            version: None,
            actor: actor.into(),
            outcome,
            code,
        }
    }

    /// Attach the opaque record identifier and version this event is about.
    pub fn about(mut self, record: impl Into<String>, version: u32) -> Self {
        self.record = Some(record.into());
        self.version = Some(version);
        self
    }
}

/// Metadata about one record, which is all a listing may print.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordMetadata {
    /// The opaque record identifier.
    pub record: String,
    /// The level the record lives at.
    pub level: String,
    /// The current version.
    pub version: u32,
}

/// An identity's public halves, and the fingerprint that binds them.
///
/// Every field here is public by construction: a fingerprint is a digest and a
/// public key is a public key. Nothing that could be a private half has a route
/// into this structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicIdentity {
    /// The identity, as `<kind>:<value>`.
    pub identity: String,
    /// The Ed25519 public key, hex.
    pub signing_key: String,
    /// The X25519 public key, hex.
    pub recipient_key: String,
    /// The ID naming the signing key.
    pub signing_key_id: String,
    /// The ID naming the recipient key.
    pub recipient_key_id: String,
    /// The binding fingerprint, hex.
    pub fingerprint: String,
}

/// The pinned admin anchor: one public key and the ID it is pinned under.
///
/// Deliberately not [`PublicIdentity`] with two empty fields: an admin key has
/// no recipient half at all, and printing an empty one reads like a key that
/// failed to generate rather than a key that does not exist by design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PinnedAnchor {
    /// The key ID the anchor names.
    pub key_id: String,
    /// The Ed25519 public key, hex.
    pub signing_key: String,
    /// The admin principal UUID this deployment issued, canonical form.
    pub principal: String,
    /// The user principal UUID this deployment issued, canonical form.
    pub user: String,
}

/// What a token says about itself, and nothing it could be used to do.
///
/// No key, no content key and no sealed key map appears here: an inspection is
/// the metadata a caller can already see in the clear, named so it is not
/// mistaken for one the caller had to be trusted with. The expiry is the token's
/// own claim, which a compliant client checks and a cleanup sweep targets; it
/// does not bound the ciphertext's existence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TokenInspection {
    /// The token's identifier, which a retry reuses.
    pub jti: String,
    /// The agent the delivery names.
    pub agent: String,
    /// The level the delivery is scoped to.
    pub level: String,
    /// The vault the records live in.
    pub vault: String,
    /// The user who owns the records.
    pub user: String,
    /// The key ID of the issuer whose signature verified.
    pub issuer_key_id: String,
    /// The key ID of the agent signing key the token binds.
    pub agent_signing_key_id: String,
    /// The key ID of the agent recipient key the key map is sealed to.
    pub agent_recipient_key_id: String,
    /// When the claims expire, as the token's own claim.
    pub expires_at: u64,
    /// The records the delivery selects: identifiers and versions only.
    pub records: Vec<RecordMetadata>,
}

/// What a backend says about itself, and what one lease asks of it.
///
/// `cleanup_lag` is deliberately absent: the system cannot measure how long after
/// a delete a copy stops existing anywhere, so there is no field for it to be
/// unknowingly wrong in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackendReport {
    /// The backend the configuration selects, or the one being described.
    pub backend: String,
    /// Its lease capability, as the classification names it.
    pub capability: String,
    /// The mechanism that capability rests on.
    pub mechanism: String,
    /// The declared cleanup cadence, if the backend declares one.
    pub declared_cadence_secs: Option<u64>,
    /// The retention window the classification states, if any.
    pub retention_secs: Option<u64>,
    /// The lease the test asked about, if this was a test.
    pub requested_ttl_secs: Option<u64>,
    /// Whether that lease is admissible. `None` for a description that asked.
    pub admitted: Option<bool>,
    /// One sentence naming what the operator has to know.
    pub detail: String,
}

/// A grant this host withdrew, as the admin decision left it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GrantWithdrawn {
    /// The grant that was removed, in the form the policy named it.
    pub grant: String,
    /// The narrower policy revision the admin signed.
    pub policy_revision: u64,
    /// When the decision was recorded, in Unix seconds.
    pub withdrawn_at: i64,
    /// What the withdrawal does and does not reach.
    pub reach: String,
}

/// One sweep, as the command prints it.
///
/// The counts are this store's own. The note is the report's own sentence, not
/// one written here: a caveat kept in the renderer would drift away from the
/// report that governs what may be claimed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SweepSummary {
    /// The capability the backend was classified with.
    pub capability: String,
    /// Due records the sweep selected.
    pub selected: usize,
    /// Versions this invocation removed.
    pub removed: usize,
    /// Due records naming a version that was already gone.
    pub already_absent: usize,
    /// Armed records whose deadline has not passed.
    pub not_yet_due: usize,
    /// How many records did not finish, and why.
    pub failures: Vec<String>,
    /// Whether the bound stopped this invocation early.
    pub bound_reached: bool,
    /// Due versions the next run must still remove.
    pub backlog: usize,
    /// The report's own sentence about what the counts mean.
    pub note: String,
}

impl SweepSummary {
    /// Read a backend report into the shape a caller sees.
    pub fn from_report(report: &ksp_backend::SweepReport) -> Self {
        Self {
            // Same rendering `backend list` uses, so the two agree on the word
            // for a capability without a second mapping to keep in step.
            capability: format!("{:?}", report.capability),
            selected: report.selected,
            removed: report.removed,
            already_absent: report.already_absent,
            not_yet_due: report.not_yet_due,
            failures: report
                .failures
                .iter()
                .map(|failure| failure.reason.clone())
                .collect(),
            bound_reached: report.bound_reached,
            backlog: report.backlog,
            note: report.note(),
        }
    }
}

/// One line of the audit view: an acknowledgement or a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditLine {
    /// `acknowledgement` or `report`.
    pub kind: String,
    /// The intent the entry answers.
    pub intent: String,
    /// Who performed or claimed it.
    pub actor: String,
    /// The version it names.
    pub version: u32,
    /// The time the entry states, in the sense its `claim` field gives.
    pub at: i64,
    /// What the time means, so a report is never read as a deletion time.
    pub claim: String,
    /// Whether a signature verified. Absent for a journal entry, which has none.
    pub verified: Option<bool>,
}

/// The journal and reports this host holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditView {
    /// Every entry, journal first, in file order.
    pub lines: Vec<AuditLine>,
    /// Entries that could not be read or verified.
    pub unreadable: usize,
}

/// One record as a scoped `ksp audit` view prints it.
///
/// Every field is a projection of the signed record: the identifiers the payload
/// carries, its closed enums rendered through their own labels, and the exit class
/// the writer recorded. There is no free-form field, so there is nowhere for a
/// value to be formatted into a view (FR-046).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogEntry {
    /// The actor the record names.
    pub actor: String,
    /// The key that signed it, as the record itself states.
    pub signer_key_id: String,
    /// The component that wrote it.
    pub component: String,
    /// What it was doing.
    pub operation: String,
    /// What it acted on, or `None` when the operation names nothing.
    pub target: Option<String>,
    /// Whether it completed or not.
    pub outcome: String,
    /// The exit class the writer recorded.
    pub exit_code: i32,
    /// The writer's clock at the time it wrote.
    pub observed_at: i64,
    /// The capability acceptance the record carries, rendered.
    ///
    /// `None` for a record that did not establish a capability — which is most
    /// of them. When present, the rendering names the capability, the adapter
    /// that established it and the level that adapter guarantees, in the terms
    /// [`ksp_types::CapabilityAcceptance`] itself uses. A record that claims an
    /// acceptance the view cannot print is a durable claim nobody can read
    /// (NFR-009).
    pub acceptance: Option<String>,
    /// The segment it was read from, relative to the home.
    pub segment: String,
    /// Its position in that segment, from zero.
    pub index: usize,
}

/// One record as `ksp audit` prints it.
///
/// Three shapes so nothing is dropped: a record this build decodes, a record whose
/// kind it does not know — printed as its kind and its fields (FR-040) — and a frame
/// that is not a record at all, printed as a finding (FR-042). The tag is the `kind`
/// field FR-041's consumer reads, and it is the only field the three share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind")]
pub enum LogRecord {
    /// A record this build decodes.
    #[serde(rename = "audit-record")]
    Known(Box<LogEntry>),
    /// A record whose kind this build does not know.
    #[serde(rename = "unknown-record")]
    Unknown(UnknownLogRecord),
    /// A frame that is not a record.
    #[serde(rename = "malformed")]
    Malformed(MalformedRecord),
}

/// A record of a kind this build does not know, with the fields it carries.
///
/// The projection is made where the record format lives, so an unknown payload cannot
/// smuggle bytes into a rendering: a byte string is reported by length and a field whose
/// name announces material is redacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnknownLogRecord {
    /// The domain the writer named, which is the kind this build does not know.
    ///
    /// Named `domain` and not `kind`: the enclosing enum already writes `kind`, and two
    /// fields with that name would collide in the object a consumer parses.
    pub domain: String,
    /// The segment it was read from, relative to the home.
    pub segment: String,
    /// Its position in that segment, from zero.
    pub index: usize,
    /// The payload's fields, as the record format may project them.
    pub fields: Vec<ksp_deletion::RawField>,
}

/// A frame that could not be read as a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MalformedRecord {
    /// The segment it was read from, relative to the home.
    pub segment: String,
    /// Its position in that segment, from zero.
    pub index: usize,
    /// Why it could not be read, in the reader's own words.
    pub reason: String,
}

/// What `ksp audit` read, and whose view it is.
///
/// Distinct from [`AuditView`], which is `ksp admin audit`'s report on the deletion
/// acknowledgement journal. They answer different questions and are deliberately
/// not one type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogView {
    /// The scope that decided what is here, as the identity context labelled it.
    pub scope: String,
    /// How many chains were read. Two or more means the order between them is a
    /// claim, which [`LogView::notes`] says out loud.
    pub segments: usize,
    /// How many records the scope holds. The records themselves are emitted one by
    /// one through [`Emitter::records`], so `--json` is one object per record (FR-041)
    /// instead of one array a consumer has to unwrap.
    pub records: usize,
    /// Entries that could not be read at all, counted rather than dropped (FR-042).
    pub unreadable: usize,
    /// Records of a kind this build does not know, printed from their own fields.
    pub unknown: usize,
    /// Frames that are not records, printed as findings.
    pub malformed: usize,
    /// Unknown records withheld because this view cannot establish whose they are.
    pub withheld: usize,
    /// The entries behind that count, by path, so an operator can act on one.
    pub trouble: Vec<String>,
    /// What this view cannot claim. Printed after the records, never before them.
    pub notes: Vec<String>,
}

/// One head digest, and the chain it ends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeadView {
    /// The actor and segment the head belongs to.
    pub chain: String,
    /// Lowercase hex of the digest.
    pub digest: String,
}

/// The first record a finding class was seen at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FirstView {
    /// The class: `invalid`, `unpinned`, `mismatch` or `revoked`.
    pub class: String,
    /// The chain the record belongs to.
    pub chain: String,
    /// Zero-based index of the record in its segment.
    pub index: usize,
}

/// What `ksp audit verify` found.
///
/// Counts, never a verdict about coverage: `completeness` is a sentence because
/// the only honest answer depends on whether a head digest came from outside the
/// log (FR-051).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyView {
    /// How many segments were read.
    pub segments: usize,
    /// How many records were read.
    pub records: usize,
    /// Records that verify under a current pin.
    pub valid: usize,
    /// Records that verify under a key whose grant was withdrawn.
    pub revoked: usize,
    /// Records whose named signer no pin holds.
    pub unpinned: usize,
    /// Records signed by a pinned key that may not sign them.
    pub mismatch: usize,
    /// Records whose named key is pinned and whose bytes do not verify.
    pub invalid: usize,
    /// The first chain break, named.
    pub broken: Option<String>,
    /// The index of a torn trailing frame, when there is one.
    pub torn_tail: Option<usize>,
    /// Entries that could not be read at all.
    pub unreadable: usize,
    /// The entries behind that count, by path.
    pub trouble: Vec<String>,
    /// Every verified chain's head, in actor and segment order.
    pub heads: Vec<HeadView>,
    /// How many head digests the caller supplied.
    pub heads_supplied: usize,
    /// The supplied heads that a chain actually ends at.
    pub matched_heads: Vec<HeadView>,
    /// The first record of each finding class, so an operator has something to
    /// look at without the verifier holding every finding.
    pub first: Vec<FirstView>,
    /// What this run can and cannot say about coverage.
    pub completeness: String,
    /// What the counts do not mean.
    pub notes: Vec<String>,
}

/// One recorded sweeper arming, as the command reports it.
///
/// What `--install` wrote, and what its load established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstalledView {
    /// The file that was written.
    pub path: String,
    /// What the load established, in one sentence.
    ///
    /// Two sentences, not a bool: "the load succeeded" and "a proof exists" are
    /// different claims, and only the second admits a lease.
    pub note: String,
}

/// Every field is what the record says. `unit_template` is the proposal an operator
/// installs; it is printed, never written anywhere a service manager reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArmingView {
    /// The backend the schedule serves.
    pub backend: String,
    /// The form of schedule.
    pub kind: String,
    /// The unit or job name the operator installs under.
    pub identifier: String,
    /// The declared interval, in seconds.
    pub interval_secs: u64,
    /// The prefix the job sweeps.
    pub scope: String,
    /// The identity the job runs as.
    pub credential: String,
    /// The rights declared for that identity.
    pub rights: Vec<String>,
    /// The principal the arming is recorded for.
    pub principal: String,
    /// The writer's clock, in seconds since the epoch.
    pub recorded_at: i64,
    /// The deterministic identity of this backend-plus-scope arming.
    pub arming_id: String,
    /// What an existing record said, when this arming replaced one.
    pub replaced: Option<String>,
    /// The artifact to install, in whatever form the kind provides.
    ///
    /// A systemd unit for `systemd`, a `launchd` property list for `launchd`, and
    /// nothing for a kind whose job runs somewhere this host cannot see. The field
    /// name is kept for the published JSON: renaming a key a consumer reads is a
    /// contract change, and this work package has no authorization for one.
    pub unit_template: Option<String>,
    /// What `--install` wrote and what its load established, when it ran.
    ///
    /// `None` when no install was requested. `loaded` distinguishes a verified
    /// load from a declaration, so a reader cannot mistake one for the other.
    pub installed: Option<InstalledView>,
    /// What this host could measure, when `--query` asked.
    pub query: Option<String>,
}

/// A recovery phrase, with the split it names.
///
/// The phrase is the deliverable of `vault rekey`: the operator writes it down
/// and that is the only copy. It is printed only after the vault file it
/// recovers was written, so a printed phrase always opens something.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryView {
    /// The rendered phrase.
    pub phrase: String,
    /// How many shares it needs.
    pub threshold: usize,
    /// How many it states.
    pub shares: usize,
}

/// What a command may print.
///
/// Two shapes, both built from structures the subsystems publish. A plaintext
/// value has no route into either.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Report {
    /// A status disclosure.
    Status(Box<StatusReport>),
    /// What a sealed vault file states without a password.
    SealedVault(SealedVaultView),
    /// A record's metadata.
    Record(RecordMetadata),
    /// An identity's public halves.
    Identity(PublicIdentity),
    /// The admin anchor this host pinned.
    Anchor(PinnedAnchor),
    /// A list of records' metadata.
    ///
    /// A struct variant rather than a newtype: `Report` is internally tagged, and
    /// serde cannot tag a newtype variant that wraps a sequence. The failure was
    /// silent — `to_value` returned `Err` and the emitter substituted a string —
    /// so `secret ls --json` emitted `"unserializable"` and every caller read it
    /// as an empty listing.
    Records {
        /// The records this listing names, in the order the store returned them.
        records: Vec<RecordMetadata>,
    },
    /// What one token says about itself.
    Token(TokenInspection),
    /// What this host minted, and what it holds against each.
    Tokens(TokenLedger),
    /// What one revocation decided, and how far it reaches.
    Revoked(Revocation),
    /// What one grant withdrawal removed, and what it does not reach.
    Withdrawn(GrantWithdrawn),
    /// What one sweep did, and what it could not do.
    Sweep(SweepSummary),
    /// What this host journaled, and what actors reported.
    Audit(AuditView),
    /// The audit log one caller is entitled to read.
    Log(LogView),
    /// What verification found in the audit log.
    Verify(VerifyView),
    /// A recovery phrase this command just produced.
    RecoveryPhrase(RecoveryView),
    /// What a backend says about itself.
    Backend(BackendReport),
    /// One recorded sweeper arming.
    Arming(ArmingView),
    /// An enrolment that reports the principal UUID it issued or confirmed.
    ///
    /// The UUID is the identity; a display name printed beside it is metadata.
    PrincipalIssued {
        /// The operation that completed.
        operation: String,
        /// The principal UUID, canonical form.
        principal: String,
    },
    /// A confirmation with no payload beyond its own name.
    Confirmation {
        /// The operation that completed.
        operation: String,
    },
}

/// What a sealed vault file states without a password.
///
/// The version and nothing else: a command that printed a salt, a ciphertext length
/// or a binding would narrow an offline attack without answering a question the
/// operator asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SealedVaultView {
    /// The format version the sealed file records.
    pub version: u16,
}

/// One row of the issuance ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LedgerRow {
    /// The token's opaque identifier.
    pub token_id: String,
    /// The agent the delivery was sealed to.
    pub agent: String,
    /// The `user`-level secret the copy came from.
    pub secret: String,
    /// The exact version that was shared.
    pub version: u32,
    /// The armed deadline.
    pub deadline: i64,
    /// The policy revision that authorised the mint.
    pub policy_revision: u64,
    /// `live`, `revoked`, or `unknown` with what this host could tell.
    pub standing: String,
}

/// What `token list` prints.
///
/// The scope sentence is not decoration: the rows are what *this host* minted,
/// and a token minted elsewhere is unknown here. A listing that printed only
/// rows would let an empty output read as "no token exists anywhere".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TokenLedger {
    /// One row per token this host minted.
    pub rows: Vec<LedgerRow>,
    /// The claim the rows support, and the one they do not.
    pub scope: String,
}

/// What `token revoke` decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Revocation {
    /// The identifier that was marked.
    pub token_id: String,
    /// When the mark was written.
    pub revoked_at: i64,
    /// What the mark does and does not reach.
    pub reach: String,
}

/// Where output goes.
pub struct Emitter<W: Write> {
    json: bool,
    sink: W,
}

impl<W: Write> Emitter<W> {
    /// An emitter writing to `sink`, in JSON or in text.
    pub fn new(json: bool, sink: W) -> Self {
        Self { json, sink }
    }

    /// Print a report.
    ///
    /// A report that will not serialize is a defect in this tool, and this
    /// returns the error rather than printing a substitute. The previous
    /// fallback wrote the string `"unserializable"`, which a caller parsed as a
    /// successful answer with no fields — the most dangerous shape a defect can
    /// take, because nothing anywhere reported it.
    pub fn report(&mut self, report: &Report) -> std::io::Result<()> {
        if self.json {
            let value = serde_json::to_value(report)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            writeln!(self.sink, "{value}")?;
        } else {
            writeln!(self.sink, "{}", render(report))?;
        }
        Ok(())
    }

    /// Print an audit event.
    pub fn audit(&mut self, event: &AuditEvent) -> std::io::Result<()> {
        if self.json {
            let value = serde_json::to_value(event)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            writeln!(self.sink, "{value}")?;
        } else {
            writeln!(self.sink, "{}", render_audit(event))?;
        }
        Ok(())
    }

    /// Print one record per call's worth: a JSON object each, or one rendered line each.
    ///
    /// FR-041 asks for one object per record rather than an array, so a consumer reads a
    /// record at a time and no projection has to decide what to group. The text branch
    /// uses the same per-record rendering the view's own lines use, so the two cannot
    /// drift into different field sets.
    pub fn records(&mut self, records: &[LogRecord]) -> std::io::Result<()> {
        for record in records {
            if self.json {
                let value = serde_json::to_value(record)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
                writeln!(self.sink, "{value}")?;
            } else {
                writeln!(self.sink, "{}", render_log_record(record))?;
            }
        }
        Ok(())
    }

    /// Print a refusal.
    ///
    /// Takes the message the subsystem produced. Those messages are written not
    /// to carry secrets, and the subsystems that could see a value have no way to
    /// put one in a message — but a caller must still pass a message it built,
    /// never a formatted error from an unexpected path.
    pub fn refusal(&mut self, message: &str) -> std::io::Result<()> {
        writeln!(self.sink, "ksp: {message}")
    }

    /// Print the outcome of the capability probe.
    ///
    /// One rendering function serves both branches, so the JSON and the text
    /// cannot drift into different field sets.
    pub fn probe(&mut self, summary: &crate::probe::ProbeSummary) -> std::io::Result<()> {
        if self.json {
            let value = serde_json::to_value(summary)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            writeln!(self.sink, "{value}")
        } else {
            writeln!(self.sink, "{}", crate::probe::render(summary))
        }
    }
}

/// One record as a line, whichever of the three shapes it is.
fn render_log_record(record: &LogRecord) -> String {
    match record {
        LogRecord::Known(entry) => {
            let target = match &entry.target {
                Some(target) => format!("  target={target}"),
                None => String::new(),
            };
            // Only a record that established a capability prints an acceptance.
            // The row is omitted rather than rendered empty for every other
            // record, so a reader can tell "no capability was established" from
            // "a capability was established and the view did not say what".
            let acceptance = match &entry.acceptance {
                Some(acceptance) => format!("  acceptance={acceptance}"),
                None => String::new(),
            };
            format!(
                "record: actor={}  signer={}  component={}  operation={}{target}  outcome={}  code={}  at={}{acceptance}  segment={}  index={}",
                entry.actor,
                entry.signer_key_id,
                entry.component,
                entry.operation,
                entry.outcome,
                entry.exit_code,
                entry.observed_at,
                entry.segment,
                entry.index
            )
        }
        // A kind this build does not know is printed as itself, with the fields it
        // carries, so it is visible rather than dropped (FR-040). The kind and the field
        // names come from a writer this build does not know, so they are escaped: a name
        // holding a newline would otherwise end this line and forge the next record.
        LogRecord::Unknown(unknown) => {
            let fields = unknown
                .fields
                .iter()
                .map(|field| {
                    format!(
                        "{}={}",
                        printable(&field.name),
                        render_raw_value(&field.value)
                    )
                })
                .collect::<Vec<_>>()
                .join("  ");
            format!(
                "record: kind={}  segment={}  index={}  {}",
                printable(&unknown.domain),
                printable(&unknown.segment),
                unknown.index,
                fields
            )
        }
        LogRecord::Malformed(malformed) => format!(
            "malformed: segment={}  index={}  {}",
            printable(&malformed.segment),
            malformed.index,
            printable(&malformed.reason)
        ),
    }
}

/// Text as it may appear inside one line.
///
/// Most of what this renderer prints is a value this build produced: a UUID, a domain
/// string, a count. Two things are not — a record's kind and its field names — and those
/// come from a writer that need not be this build. A file name can hold a control
/// character for the same reason. Escaping them keeps one record on one line, so a
/// crafted name cannot print a second, richer record underneath this one.
fn printable(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            other if other.is_control() => format!("\\u{{{:x}}}", u32::from(other)),
            other => other.to_string(),
        })
        .collect()
}

/// What may be printed for one field of a record this build cannot type.
fn render_raw_value(value: &ksp_deletion::RawFieldValue) -> String {
    use ksp_deletion::RawFieldValue;
    match value {
        // Not the text: a writer this build does not know has not agreed to keep
        // material out of a record, so only the length is reported (FR-046).
        RawFieldValue::Text { chars } => format!("<text of {chars} chars>"),
        RawFieldValue::Integer(number) => number.to_string(),
        RawFieldValue::Flag(flag) => flag.to_string(),
        RawFieldValue::Bytes(len) => format!("<{len} bytes>"),
        RawFieldValue::Nested { kind, len } => format!("<{kind} of {len}>"),
        RawFieldValue::Other(kind) => format!("<{kind}>"),
        RawFieldValue::Redacted => "[redacted]".to_string(),
    }
}

/// Render a report as text.
fn render(report: &Report) -> String {
    match report {
        Report::Status(status) => render_status(status),
        Report::SealedVault(vault) => format!(
            "vault:       sealed, version {} (the file is ciphertext; reading it needs the password)",
            vault.version
        ),
        Report::Anchor(anchor) => format!(
            "admin  key_id={}  signing_key={}  principal={}  user={}",
            anchor.key_id, anchor.signing_key, anchor.principal, anchor.user
        ),
        // The key IDs are printed beside the keys because they are what a policy
        // and a pin name: an operator comparing two terminals needs the ID, and a
        // rotation that changed only the key would leave the ID looking unchanged.
        Report::Identity(identity) => format!(
            "{}  signing_key_id={}  signing_key={}  recipient_key_id={}  recipient_key={}  fingerprint={}",
            identity.identity,
            identity.signing_key_id,
            identity.signing_key,
            identity.recipient_key_id,
            identity.recipient_key,
            identity.fingerprint
        ),
        Report::Record(record) => format!(
            "{}  level={}  version={}",
            record.record, record.level, record.version
        ),
        Report::Records { records } => records
            .iter()
            .map(|record| {
                format!(
                    "{}  level={}  version={}",
                    record.record, record.level, record.version
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Report::Token(token) => {
            let records = token
                .records
                .iter()
                .map(|record| {
                    format!(
                        "{}  level={}  version={}",
                        record.record, record.level, record.version
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                "jti={}  agent={}  level={}  expires_at={}\nissuer={}  agent_signing_key={}  agent_recipient_key={}\n{records}",
                token.jti,
                token.agent,
                token.level,
                token.expires_at,
                token.issuer_key_id,
                token.agent_signing_key_id,
                token.agent_recipient_key_id
            )
        }
        Report::Tokens(ledger) => {
            let rows = ledger
                .rows
                .iter()
                .map(|row| {
                    format!(
                        "{}  agent={}  secret={}  version={}  deadline={}  policy_rev={}  {}",
                        row.token_id,
                        row.agent,
                        row.secret,
                        row.version,
                        row.deadline,
                        row.policy_revision,
                        row.standing
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            if rows.is_empty() {
                ledger.scope.clone()
            } else {
                format!("{rows}\n{}", ledger.scope)
            }
        }
        Report::Revoked(revocation) => format!(
            "token={}  revoked_at={}\n{}",
            revocation.token_id, revocation.revoked_at, revocation.reach
        ),
        Report::Withdrawn(withdrawn) => format!(
            "grant={}  policy_revision={}  withdrawn_at={}\n{}",
            withdrawn.grant, withdrawn.policy_revision, withdrawn.withdrawn_at, withdrawn.reach
        ),
        Report::Sweep(sweep) => format!(
            "capability={}  selected={}  removed={}  already_absent={}  not_yet_due={}  bound_reached={}  backlog={}\n{}",
            sweep.capability,
            sweep.selected,
            sweep.removed,
            sweep.already_absent,
            sweep.not_yet_due,
            sweep.bound_reached,
            sweep.backlog,
            sweep.note
        ),
        Report::Audit(audit) => {
            let mut out = audit
                .lines
                .iter()
                .map(|line| {
                    let verified = match line.verified {
                        Some(true) => "  verified=true",
                        Some(false) => "  verified=false",
                        None => "",
                    };
                    format!(
                        "{}  intent={}  actor={}  version={}  at={}{verified}\n  {}",
                        line.kind, line.intent, line.actor, line.version, line.at, line.claim
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&format!(
                "{} entry/entries, {} unreadable or unverified; a report's time is the actor's claim, \
                 not a deletion this host observed",
                audit.lines.len(),
                audit.unreadable
            ));
            out
        }
        Report::Log(log) => {
            // The header and the notes only: the records are printed one per line by
            // `Emitter::records`, so this report never holds them and cannot summarise
            // them into something that disagrees with the record itself (FR-039).
            // Every kind of thing the walk met is counted, so a reader can tell a log
            // this build understands from one it only partly understands.
            let mut out = format!(
                "audit: scope={}  segments={}  records={}  unknown={}  malformed={}  unreadable={}  withheld={}",
                log.scope,
                log.segments,
                log.records,
                log.unknown,
                log.malformed,
                log.unreadable,
                log.withheld
            );
            for path in &log.trouble {
                out.push_str(&format!("\nnote: could not read {}", printable(path)));
            }
            for note in &log.notes {
                out.push_str(&format!("\nnote: {note}"));
            }
            out
        }
        Report::Verify(verify) => {
            let broken = match &verify.broken {
                Some(broken) => format!("chain=broken ({broken})"),
                None => "chain=unbroken".to_string(),
            };
            let mut out = format!(
                "audit verify: segments={}  records={}  valid={}  revoked={}  unpinned={}  \
                 mismatch={}  invalid={}  unreadable={}  {broken}",
                verify.segments,
                verify.records,
                verify.valid,
                verify.revoked,
                verify.unpinned,
                verify.mismatch,
                verify.invalid,
                verify.unreadable
            );
            if let Some(index) = verify.torn_tail {
                out.push_str(&format!("\ntorn tail: a partial frame at index {index}"));
            }
            for head in &verify.heads {
                out.push_str(&format!("\nhead {}={}", head.chain, head.digest));
            }
            for first in &verify.first {
                out.push_str(&format!(
                    "\nfirst {}: {} at index {}",
                    first.class, first.chain, first.index
                ));
            }
            for path in &verify.trouble {
                out.push_str(&format!("\nnote: could not read {path}"));
            }
            for note in &verify.notes {
                out.push_str(&format!("\nnote: {note}"));
            }
            out
        }
        Report::Arming(arming) => {
            let mut out = format!(
                "arming: backend={}  kind={}  identifier={}  interval={}s  scope={}  \
                 credential={}  rights={}  principal={}  recorded_at={}  id={}",
                arming.backend,
                arming.kind,
                arming.identifier,
                arming.interval_secs,
                arming.scope,
                arming.credential,
                arming.rights.join(","),
                arming.principal,
                arming.recorded_at,
                arming.arming_id
            );
            if let Some(replaced) = &arming.replaced {
                out.push_str(&format!("\nreplaced: {replaced}"));
            }
            // The interval is a schedule, not a deadline, on every kind alike (FR-035),
            // and the record is configuration until a proof confirms a run (FR-032).
            out.push_str(
                "\nnote: this records a schedule; it is configuration until a signed sweep proof \
                 confirms a run. The interval says how often the job is declared to run, never how \
                 long a lease lives.",
            );
            match &arming.installed {
                Some(installed) => {
                    out.push_str(&format!(
                        "\ninstalled: {path}\nnote: {loaded}",
                        path = installed.path,
                        loaded = installed.note
                    ));
                }
                None => out.push_str(
                    "\nnote: nothing was installed. ksp wrote no unit, no property list, no \
                     crontab entry and ran no privileged helper.",
                ),
            }
            if let Some(template) = &arming.unit_template {
                out.push('\n');
                out.push_str(template);
            }
            if let Some(query) = &arming.query {
                out.push_str(&format!(
                    "\nquery: {query}\nnote: {disclosure}",
                    disclosure = ksp_backend::sweeper::ArmingQuery::DISCLOSURE
                ));
            }
            out
        }
        // The warning comes first and the phrase last, so what an operator copies
        // is the phrase itself and not a line that happens to follow it.
        Report::RecoveryPhrase(recovery) => format!(
            "threshold={}  shares={}\nwrite this down now: it is the only copy, and the \
             previous phrase no longer recovers this vault\n{}",
            recovery.threshold, recovery.shares, recovery.phrase
        ),
        Report::Backend(backend) => {
            let cadence = match backend.declared_cadence_secs {
                Some(secs) => format!("{secs}s"),
                None => "none".to_string(),
            };
            let retention = match backend.retention_secs {
                Some(secs) => format!("{secs}s"),
                None => "unknown".to_string(),
            };
            let verdict = match (backend.requested_ttl_secs, backend.admitted) {
                (Some(ttl), Some(true)) => format!("  ttl={ttl}s admitted=true"),
                (Some(ttl), Some(false)) => format!("  ttl={ttl}s admitted=false"),
                (Some(ttl), None) => format!("  ttl={ttl}s admitted=unknown"),
                (None, _) => String::new(),
            };
            format!(
                "backend={}  capability={}  mechanism={}  cadence={cadence}  retention={retention}{verdict}\n{}",
                backend.backend, backend.capability, backend.mechanism, backend.detail
            )
        }
        Report::PrincipalIssued {
            operation,
            principal,
        } => format!("{operation}: principal={principal}"),
        Report::Confirmation { operation } => format!("{operation}: ok"),
    }
}

/// Render the status disclosure, keeping every unknown labelled as unknown.
fn render_status(status: &StatusReport) -> String {
    let backend = &status.backend;
    let mut lines = vec![
        format!("capability:  {:?}", backend.capability),
        format!("mechanism:   {}", backend.mechanism),
        format!("evidence:    {}", backend.evidence),
    ];
    lines.push(match backend.declared_cadence_secs {
        Some(secs) => format!("cadence:     {secs}s (declared)"),
        None => "cadence:     not declared".to_owned(),
    });
    // The one step the classifier says will change this state. It is printed
    // only when the classifier named one, so a proven schedule says nothing
    // rather than inventing advice.
    if let Some(action) = &backend.next_action {
        lines.push(format!("next:        {action}"));
    }
    // Declared and proven are printed on separate lines, so a disagreement is
    // visible instead of being averaged into one number (FR-057).
    lines.push(
        match (backend.proven_cadence_secs, backend.proof_age_secs) {
            (Some(secs), Some(age)) => format!("proven:      {secs}s (proof age {age}s)"),
            (Some(secs), None) => format!("proven:      {secs}s"),
            (None, _) => "proven:      none".to_owned(),
        },
    );
    // Naming both is not enough: the reader has to be told which one admission used.
    if let (Some(declared), Some(proven)) =
        (backend.declared_cadence_secs, backend.proven_cadence_secs)
        && declared != proven
    {
        lines.push(format!(
            "disagreement: the arming declares {declared}s and the newest proof establishes \
             {proven}s, so admission uses {proven}s"
        ));
    }
    // An absent floor is printed as absent, and as absent *for the right reason*.
    // Printing `0` would tell a reader that a zero-second lease is admissible, and
    // "this backend admits no lease" would be false on a store that enforces the
    // deadline itself: there the floor does not apply because nothing has to sweep.
    lines.push(match (backend.admission_minimum_secs, backend.capability) {
        (Some(secs), _) => format!(
            "minimum:     {secs}s (2 x the proven interval; MVP admission policy, not a timing \
             promise)"
        ),
        (None, ksp_types::LeaseCapability::None) => {
            "minimum:     none — this backend admits no lease".to_owned()
        }
        (None, _) => {
            "minimum:     none — the backend enforces the deadline itself, so no sweep floor \
             applies"
                .to_owned()
        }
    });
    lines.push(format!("cleanup lag: {}", backend.cleanup_lag));
    lines.push(format!("retention:   {}", render_retention(backend)));
    lines.extend(render_arming(status));
    lines.extend(render_proof(status));
    lines.push(format!("schedule:    {}", status.schedule_note));
    lines.push(format!("confinement: {}", status.posture.confinement));
    lines.push(format!("barrier:     {}", status.posture.barrier));
    lines.extend(render_dump_controls(&status.posture.undumpable));
    lines.push(format!("platform:    {}", status.platform));
    lines.extend(render_capabilities(status));
    lines.push(format!("freshness:   {}", render_freshness(status)));
    lines.extend(render_permissions(&status.permissions));
    lines.push(render_binding(&status.binding));
    if let Some(canary) = &status.canary {
        lines.push(format!(
            "canary:      version {} {} at {} (one lookup, not a conclusion)",
            canary.version,
            if canary.found { "found" } else { "not found" },
            canary.observed_at
        ));
    }
    lines.extend(render_audit_head(status));
    lines.push(format!("passphrase:  {}", status.passphrase));
    lines.join("\n")
}

/// Render the two controls that decide whether this process can be dumped.
///
/// Before this, the barrier line said `weakened` and that was the whole answer:
/// a reader learned that something was weaker and not *what* (Misfit D). Each
/// control now gets its own line, and the line carries the mechanism, so
/// `excluded` is a claim about `RLIMIT_CORE` rather than about a call the reader
/// has to guess. A control that did not apply carries the kernel's own reason —
/// the same sentence the syscall produced, which is the only one that names the
/// cause.
fn render_dump_controls(posture: &ksp_posture::UndumpablePosture) -> Vec<String> {
    let core = match &posture.core_limit {
        ksp_posture::ControlOutcome::Applied => {
            format!("excluded ({} = 0)", ksp_posture::CORE_DUMP_MECHANISM)
        }
        ksp_posture::ControlOutcome::Unavailable { reason } => format!("not excluded ({reason})"),
    };
    let ptrace = match &posture.ptrace {
        ksp_posture::ControlOutcome::Applied => {
            format!("refused with {}", ksp_posture::ptrace_mechanism())
        }
        ksp_posture::ControlOutcome::Unavailable { reason } => format!("not refused ({reason})"),
    };
    vec![
        format!("core dumps:  {core}"),
        format!("ptrace:      {ptrace}"),
    ]
}

/// Render one line per host capability: the platform, the order the
/// configuration named, the level the operator set, the adapter that ran and
/// what it guarantees.
///
/// # Why an unconfigured capability prints extra words and an enforced one does
/// not
///
/// FR-010 asks an unconfigured capability to name the adapters the build could
/// have offered and to point at `ksp init`. The alternative — printing the same
/// shape and leaving the reader to notice that every field is empty — is the
/// "absence nobody notices" this feature exists to close (Misfit L).
///
/// # The two ways to be unconfigured have different fixes
///
/// A capability with no adapter selected is unconfigured either because there is
/// no `config.toml` or because the file names adapters this host does not
/// provide. The first is fixed by `ksp init`; the second is not, because
/// `ksp init` writes nothing when a configuration exists (SC-009) and the
/// operator has already written the file it would refuse to replace. Printing
/// the `ksp init` sentence in both cases told an operator to run a command that
/// would refuse to do anything, on the same line that had just reported the
/// order it refused to replace.
///
/// # The hint comes from the build, not from this module
///
/// The adapter names are read from the same closed set the registry matches on,
/// so a hint can never name an adapter the capability would refuse. A hint that
/// sends an operator to a value the reader rejects is worse than no hint.
fn render_capabilities(status: &StatusReport) -> Vec<String> {
    status
        .capabilities
        .iter()
        .map(|disclosure| {
            let mut text = disclosure.to_string();
            if !disclosure.is_configured() {
                let adapters = crate::establish::adapters_for(disclosure.capability);
                let listed = adapters.join(", ");
                if disclosure.requirement.is_some() {
                    text.push_str(&format!(
                        "; this build contains {listed}; this host provides none of the adapters \
                         the configuration names, so nothing can be established — name one of \
                         them there, or accept the absence"
                    ));
                } else {
                    text.push_str(&format!(
                        "; this build contains {listed}; run `ksp init` to write the strongest \
                         configuration this host can satisfy"
                    ));
                }
            }
            format!("host:        {text}")
        })
        .collect()
}

/// Render the recorded schedule and what the host could measure about it.
///
/// The unit, the next elapse and the last trigger are three separate lines because
/// they answer three questions, and each prints `unknown` with its own reason when the
/// host cannot answer. A single "unit: ok" would conflate them.
fn render_arming(status: &StatusReport) -> Vec<String> {
    use ksp_backend::status::ArmingDisclosure;

    let (kind, identifier, declared, recorded_at, signer, unit) = match &status.arming {
        ArmingDisclosure::None { reason } => return vec![format!("arming:      none ({reason})")],
        ArmingDisclosure::Unknown { reason } => {
            return vec![format!("arming:      unknown ({reason})")];
        }
        ArmingDisclosure::Recorded {
            kind,
            identifier,
            declared_interval_secs,
            recorded_at,
            signer_key_id,
            unit,
        } => (
            kind,
            identifier,
            declared_interval_secs,
            recorded_at,
            signer_key_id,
            unit,
        ),
    };
    let mut lines = vec![format!(
        "arming:      {kind} {identifier}, declared {declared}s, recorded at {recorded_at} by \
         {signer}"
    )];
    lines.extend(render_unit(unit));
    lines.push(format!("trigger note: {}", status.last_trigger_note));
    lines
}

/// What the service manager reported, or why it could not answer.
fn render_unit(unit: &ksp_backend::sweeper::MeasuredUnitState) -> Vec<String> {
    use ksp_backend::sweeper::MeasuredUnitState;

    match unit {
        MeasuredUnitState::Reported {
            active,
            detail,
            next_elapse,
            last_trigger,
        } => {
            let stamp = |value: &Option<String>, what: &str| match value {
                Some(value) => value.clone(),
                None => format!("unknown (the manager reported no {what})"),
            };
            vec![
                format!("unit:        reported active={active} ({detail})"),
                format!("next elapse: {}", stamp(next_elapse, "next elapse")),
                format!("last trigger: {}", stamp(last_trigger, "last trigger")),
            ]
        }
        MeasuredUnitState::Unknown { reason } => vec![
            format!("unit:        unknown ({reason})"),
            format!("next elapse: unknown ({reason})"),
            format!("last trigger: unknown ({reason})"),
        ],
    }
}

/// Render the newest proof of each outcome, and what neither says.
fn render_proof(status: &StatusReport) -> Vec<String> {
    use ksp_backend::proof::ProofFreshness;

    let proof = &status.proof;
    let mut lines = Vec::new();
    match &proof.newest_success {
        Some(record) => {
            lines.push(format!(
                "run window:  {}..{} ({}s run, {} removed, {} already absent, {} not yet due{})",
                record.run_start,
                record.run_end,
                (record.run_end - record.run_start).max(0),
                record.removed,
                record.already_absent,
                record.not_yet_due,
                if record.bound_reached {
                    ", stopped at its bound"
                } else {
                    ""
                }
            ));
            lines.push(match proof.freshness {
                Some(ProofFreshness::Fresh) => format!(
                    "proof state: fresh (age {}s, signed by {})",
                    record.age_secs, record.signer_key_id
                ),
                Some(ProofFreshness::Stale) => format!(
                    "proof state: stale (age {}s; later than its interval plus measured grace, \
                     which is lateness and not a copy that lasted longer)",
                    record.age_secs
                ),
                Some(ProofFreshness::FutureSkew) => format!(
                    "proof state: unknown (the run is dated {}s in the future, so freshness \
                     cannot be decided on this clock)",
                    -record.age_secs
                ),
                None => format!("proof state: unknown (age {}s)", record.age_secs),
            });
        }
        None => {
            let reason = proof
                .absent_reason
                .as_deref()
                .unwrap_or("no sweep proof was read");
            lines.push(format!("proof:       none ({reason})"));
        }
    }
    match &proof.newest_failure {
        Some(ksp_backend::status::Observed::Known(record)) => {
            let codes = record
                .error_codes
                .iter()
                .map(i32::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!(
                "newest failure: run {}..{}, codes [{codes}]; a failed run does not change the \
                 admitted interval",
                record.run_start, record.run_end
            ));
        }
        Some(ksp_backend::status::Observed::Unknown { reason }) => {
            lines.push(format!("newest failure: unknown ({reason})"));
        }
        None => lines.push(
            "newest failure: none (no failed run for this deployment is recorded)".to_owned(),
        ),
    }
    if proof.malformed > 0 {
        lines.push(format!(
            "proof files:  {} could not be decoded and were skipped",
            proof.malformed
        ));
    }
    lines
}

/// Render where the audit log ends, and that a head is not an external checkpoint.
///
/// Three states, and they are different: a walk that could not run says why, a walk
/// that broke says where and shows no head, and a walk that reached heads prints them.
fn render_audit_head(status: &StatusReport) -> Vec<String> {
    let audit = &status.audit;
    let mut lines = Vec::new();
    match (&audit.absent_reason, &audit.broken) {
        (Some(reason), _) => lines.push(format!("audit:       unknown ({reason})")),
        (None, Some(broken)) => lines.push(format!(
            "audit:       unknown ({} records in {} segment(s) were walked, but {broken})",
            audit.records, audit.segments
        )),
        (None, None) if audit.chains.is_empty() => {
            lines.push("audit:       no records yet, so no chain has a head to report".to_owned())
        }
        (None, None) => {
            lines.push(format!(
                "audit:       {} records in {} segment(s), {} chain(s)",
                audit.records,
                audit.segments,
                audit.chains.len()
            ));
            lines.extend(
                audit
                    .chains
                    .iter()
                    .map(|head| format!("  chain:     {} head {}", head.chain, head.digest)),
            );
        }
    }
    if audit.unreadable > 0 {
        lines.push(format!(
            "  unreadable: {} entr(ies) could not be read, so this head covers part of the log",
            audit.unreadable
        ));
    }
    if audit.unattributed > 0 {
        lines.push(format!(
            "  unattributed: {} record(s) verified against no pinned key, so the head ends a \
             chain this host cannot fully attribute",
            audit.unattributed
        ));
    }
    lines.push(
        "audit head:  a head is not an external checkpoint: a tail removed before it was \
         recorded would still match, so completeness stays unknown"
            .to_owned(),
    );
    lines
}

/// Render the layout measurement.
///
/// A clean measurement is one line: eleven `match` rows would train the reader to
/// skip the section, and the section is the point. Every drifted root gets its own
/// line with the path, the measured mode and the expected owner, because that is
/// what FR-014 requires a refusal to name and status is where the operator looks
/// after one.
/// Say whether the recorded account still resolves, and never guess.
///
/// Printed next to the ownership findings because it is the sentence that makes
/// them actionable: a drifted root names a uid, and this line says whether that uid
/// is still the account the operator meant.
fn render_binding(binding: &ksp_backend::status::BindingDisclosure) -> String {
    use ksp_backend::status::BindingDisclosure;

    match binding {
        BindingDisclosure::None => {
            "binding:     none — the vault belongs to whoever created it".to_owned()
        }
        BindingDisclosure::Verified { account, uid } => {
            format!("binding:     {account} (uid {uid})")
        }
        BindingDisclosure::Unverified { account, reason } => format!(
            "binding:     {account} — unverified: {reason}, so a rebuild may bind a different \
             account"
        ),
    }
}

fn render_permissions(permissions: &ksp_backend::status::PermissionDisclosure) -> Vec<String> {
    let total = permissions.findings.len();
    let missing = permissions
        .findings
        .iter()
        .filter(|finding| finding.verdict == ksp_posture::Verdict::Missing)
        .count();
    let measured = total - missing;
    let drifted: Vec<&ksp_posture::PermissionFinding> = permissions.drifted().collect();

    if drifted.is_empty() {
        // A home that does not exist yet has nothing to match. "11 protected
        // roots match" would be a measurement nobody made, and the reader would
        // take it as evidence the layout was checked.
        if measured == 0 {
            return vec![format!(
                "permissions: no protected roots exist here yet ({total} expected)"
            )];
        }
        return vec![if missing == 0 {
            format!("permissions: {measured} protected roots match the layout")
        } else {
            format!(
                "permissions: {measured} protected roots match the layout, {missing} not created yet"
            )
        }];
    }

    let mut lines = vec![format!(
        "permissions: {} of {total} protected roots drifted",
        drifted.len()
    )];
    lines.extend(
        drifted
            .into_iter()
            .map(|finding| format!("  drift:     {}", finding.describe())),
    );
    if missing > 0 {
        lines.push(format!(
            "  missing:   {missing} protected roots are not created yet"
        ));
    }
    lines
}

fn render_retention(backend: &ksp_backend::status::StatusDisclosure) -> String {
    use ksp_backend::status::Retention;
    match &backend.retention {
        Retention::Known {
            window_secs,
            reason,
        } => format!("{window_secs}s ({reason})"),
        Retention::Unknown { reason } => format!("unknown ({reason})"),
    }
}

fn render_freshness(status: &StatusReport) -> String {
    use ksp_backend::status::Freshness;
    match &status.freshness {
        Freshness::Available { revision } => {
            format!("rollback detection in force at revision {revision}")
        }
        Freshness::RollbackDetectionUnavailable => {
            "rollback detection unavailable (no trusted checkpoint)".to_owned()
        }
    }
}

fn render_audit(event: &AuditEvent) -> String {
    let record = match (&event.record, event.version) {
        (Some(record), Some(version)) => format!(" record={record} version={version}"),
        _ => String::new(),
    };
    format!(
        "audit: operation={} actor={} outcome={:?} code={}{record}",
        event.operation, event.actor, event.outcome, event.code
    )
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// A control that did not apply is never rendered as though it had.
    ///
    /// The rendering is where the honest answer can be lost: the posture can be
    /// correct and the document still print `excluded` for an absent control.
    /// This asserts the negative form for both lines, with the reason the kernel
    /// gave, because that reason is the only part an operator can act on.
    #[test]
    fn an_unapplied_dump_control_is_rendered_as_absent() {
        let posture = ksp_posture::UndumpablePosture {
            core_limit: ksp_posture::ControlOutcome::Unavailable {
                reason: "setrlimit(RLIMIT_CORE): Operation not permitted".to_owned(),
            },
            ptrace: ksp_posture::ControlOutcome::Applied,
        };
        let lines = render_dump_controls(&posture);
        assert_eq!(lines.len(), 2, "one line per control: {lines:?}");
        assert!(
            lines[0].starts_with("core dumps:"),
            "the core-dump line keeps its key: {lines:?}"
        );
        assert!(
            lines[0].contains("not excluded"),
            "an absent control reads as absent: {lines:?}"
        );
        assert!(
            lines[0].contains("Operation not permitted"),
            "the kernel's own reason is kept: {lines:?}"
        );
        assert!(
            !lines[1].contains("not refused"),
            "the control that applied is not reported as absent: {lines:?}"
        );
        assert!(
            lines[1].contains("refused with"),
            "the applied control names its mechanism: {lines:?}"
        );
    }

    /// A writer-controlled name cannot forge a second record on its own line.
    #[test]
    fn a_field_name_with_a_newline_stays_on_its_own_line() {
        let record = LogRecord::Unknown(UnknownLogRecord {
            domain: "future\nrecord".to_string(),
            segment: "audit/x/segment-0.cbor".to_string(),
            index: 0,
            fields: vec![ksp_deletion::RawField {
                name: "a=1  outcome=success\nrecord: actor=admin".to_string(),
                value: ksp_deletion::RawFieldValue::Integer(1),
            }],
        });
        let line = render_log_record(&record);
        assert!(!line.contains('\n'), "one projection is one line: {line:?}");
        assert!(line.contains("kind=future\\nrecord"), "{line}");
        assert!(
            line.contains("outcome=success\\nrecord"),
            "the forged record is escaped, not interpreted: {line}"
        );
    }

    fn emitted(event: &AuditEvent, json: bool) -> String {
        let mut buffer = Vec::new();
        Emitter::new(json, &mut buffer).audit(event).unwrap();
        String::from_utf8(buffer).unwrap()
    }

    #[test]
    fn an_audit_event_has_no_field_a_value_could_travel_in() {
        // Structural: the field set is operation, record, version, actor, outcome
        // and code. Serializing it cannot print a secret because there is no
        // place to put one.
        let event = AuditEvent::new("secret.set", "user:alice", AuditOutcome::Success, 0)
            .about("record-1", 3);
        let json = emitted(&event, true);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["actor", "code", "operation", "outcome", "record", "version"],
            "an unexpected field is a place a value could hide"
        );
    }

    #[test]
    fn an_audit_event_names_the_record_and_version_but_not_its_contents() {
        let event = AuditEvent::new("secret.set", "agent:7", AuditOutcome::Success, 0)
            .about("opaque-record-id", 4);
        let text = emitted(&event, false);
        assert!(text.contains("opaque-record-id"));
        assert!(text.contains("version=4"));
        assert!(text.contains("operation=secret.set"));
    }

    #[test]
    fn a_report_renders_as_json_when_asked() {
        let mut buffer = Vec::new();
        Emitter::new(true, &mut buffer)
            .report(&Report::Confirmation {
                operation: "vault.init".to_owned(),
            })
            .unwrap();
        let json = String::from_utf8(buffer).unwrap();
        assert!(json.contains("\"kind\":\"confirmation\""));
        assert!(json.contains("vault.init"));
    }

    #[test]
    fn a_record_listing_prints_only_metadata() {
        let record = RecordMetadata {
            record: "record-1".to_owned(),
            level: "agent:7".to_owned(),
            version: 2,
        };
        let mut buffer = Vec::new();
        Emitter::new(false, &mut buffer)
            .report(&Report::Records {
                records: vec![record],
            })
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("record-1"));
        assert!(text.contains("level=agent:7"));
        assert!(text.contains("version=2"));
    }

    #[test]
    fn status_reports_a_drifted_root_with_its_mode_and_expected_owner() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ksp");
        ksp_cli_layout_ensure(&root);
        std::fs::set_permissions(root.join("admin"), std::fs::Permissions::from_mode(0o775))
            .unwrap();

        let permissions =
            ksp_backend::status::PermissionDisclosure::new(crate::layout::audit(&root));
        let findings = render_permissions(&permissions).join("\n");
        assert!(findings.contains("drifted"), "{findings}");
        assert!(findings.contains("admin"), "{findings}");
        assert!(findings.contains("0775"), "{findings}");
        assert!(findings.contains("0700"), "{findings}");

        // Clean measurement: one line, no per-root noise.
        let clean = temp.path().join("clean");
        ksp_cli_layout_ensure(&clean);
        let permissions =
            ksp_backend::status::PermissionDisclosure::new(crate::layout::audit(&clean));
        let findings = render_permissions(&permissions).join("\n");
        assert!(findings.contains("match the layout"), "{findings}");
        assert!(!findings.contains("drift"), "{findings}");

        // Nothing exists: the line must say so rather than claim a match for
        // roots that were never created.
        let absent = temp.path().join("never-provisioned");
        let permissions =
            ksp_backend::status::PermissionDisclosure::new(crate::layout::audit(&absent));
        let findings = render_permissions(&permissions).join("\n");
        assert!(
            findings.contains("no protected roots exist here yet"),
            "{findings}"
        );
        assert!(!findings.contains("match the layout"), "{findings}");
    }

    fn ksp_cli_layout_ensure(root: &std::path::Path) {
        crate::layout::ensure(root).unwrap();
    }

    /// A document with one fact of each kind, for the renderer tests below.
    fn document(
        declared: Option<std::time::Duration>,
        proven: Option<std::time::Duration>,
        audit: ksp_backend::status::AuditDisclosure,
    ) -> StatusReport {
        use ksp_backend::admission::Classification;
        use ksp_types::LeaseCapability;

        let classification = Classification {
            capability: proven
                .map(|interval| LeaseCapability::Scheduled { interval })
                .unwrap_or(LeaseCapability::None),
            mechanism: "a signed sweep proof from the recorded schedule",
            declared_cadence: declared,
            proven_cadence: proven,
            proof_age: proven.map(|_| 4),
            cleanup_lag: None,
            retention: None,
            state: None,
        };
        ksp_backend::status::report(
            &classification,
            ksp_backend::status::StatusFacts {
                arming: ksp_backend::status::ArmingDisclosure::None {
                    reason: "no verified arming record names this deployment".to_string(),
                },
                proof: ksp_backend::status::ProofDisclosure {
                    newest_success: None,
                    freshness: None,
                    absent_reason: Some("no sweep proof exists".to_string()),
                    newest_failure: None,
                    malformed: 0,
                },
                audit,
                posture: ksp_backend::status::PostureDisclosure {
                    confinement: ksp_posture::ConfinementPosture {
                        state: ksp_posture::ConfinementState::Unavailable,
                        landlock: ksp_posture::LandlockObservation::NotEnabled,
                        required: false,

                        adapter: None,
                        guarantee: ksp_types::GuaranteeLevel::None,
                    },
                    barrier: ksp_posture::BarrierPosture::unavailable(
                        ksp_posture::MemlockObservation {
                            soft_bytes: None,
                            hard_bytes: None,
                        },
                    ),
                    undumpable: ksp_posture::UndumpablePosture {
                        core_limit: ksp_posture::ControlOutcome::Applied,
                        ptrace: ksp_posture::ControlOutcome::Applied,
                    },
                },
                capabilities: Vec::new(),
                freshness: ksp_backend::status::Freshness::RollbackDetectionUnavailable,
                canary: None,
                permissions: ksp_backend::status::PermissionDisclosure::new(Vec::new()),
                binding: ksp_backend::status::BindingDisclosure::None,
            },
        )
    }

    fn empty_audit() -> ksp_backend::status::AuditDisclosure {
        ksp_backend::status::AuditDisclosure {
            chains: Vec::new(),
            records: 0,
            segments: 0,
            unreadable: 0,
            unattributed: 0,
            broken: None,
            absent_reason: Some("no audit log exists here".to_string()),
        }
    }

    /// FR-023: three states, and "I could not check" is never printed as "fine".
    #[test]
    fn the_binding_line_separates_unbound_from_unverifiable() {
        use ksp_backend::status::BindingDisclosure;

        assert_eq!(
            render_binding(&BindingDisclosure::None),
            "binding:     none — the vault belongs to whoever created it"
        );
        assert_eq!(
            render_binding(&BindingDisclosure::Verified {
                account: "deploy".to_string(),
                uid: 1001,
            }),
            "binding:     deploy (uid 1001)"
        );
        // The refusal reason travels verbatim, and the consequence is named: a
        // reader who sees a uid in a drifted-root line has to know the binding
        // cannot be trusted to mean that account.
        let unverified = render_binding(&BindingDisclosure::Unverified {
            account: "deploy".to_string(),
            reason: "no such UNIX account".to_string(),
        });
        assert!(
            unverified.starts_with("binding:     deploy — unverified: "),
            "{unverified}"
        );
        assert!(unverified.contains("no such UNIX account"), "{unverified}");
        assert!(unverified.contains("different account"), "{unverified}");
        // `none` must not be spelled in a way that reads as verified.
        assert!(
            !render_binding(&BindingDisclosure::None).contains("uid"),
            ""
        );
    }

    /// FR-057: naming both intervals is not enough; the reader needs the decision.
    #[test]
    fn a_disagreement_names_both_intervals_and_the_one_admission_used() {
        let text = render_status(&document(
            Some(std::time::Duration::from_secs(300)),
            Some(std::time::Duration::from_secs(60)),
            empty_audit(),
        ));
        assert!(
            text.contains(
                "disagreement: the arming declares 300s and the newest proof establishes 60s, so \
                 admission uses 60s"
            ),
            "{text}"
        );
        // Agreement prints no line: a warning on every healthy host is noise.
        let agreeing = render_status(&document(
            Some(std::time::Duration::from_secs(60)),
            Some(std::time::Duration::from_secs(60)),
            empty_audit(),
        ));
        assert!(!agreeing.contains("disagreement:"), "{agreeing}");
    }

    /// A native-expiry backend has no sweep floor, and that is not the same as
    /// admitting nothing.
    #[test]
    fn a_native_expiry_backend_is_not_described_as_admitting_nothing() {
        use ksp_backend::admission::Classification;

        let classification = Classification {
            capability: ksp_types::LeaseCapability::NativeExpiry,
            mechanism: "the store enforces the deadline",
            declared_cadence: None,
            proven_cadence: None,
            proof_age: None,
            cleanup_lag: None,
            retention: None,
            state: None,
        };
        let mut report = document(None, None, empty_audit());
        report.backend = ksp_backend::status::StatusDisclosure::from(&classification);
        let text = render_status(&report);
        assert!(
            text.contains("the backend enforces the deadline itself"),
            "{text}"
        );
        assert!(
            !text.contains("this backend admits no lease"),
            "a native-expiry backend admits leases: {text}"
        );
    }

    /// The `next:` line comes from the classifier, and is absent when it names
    /// no step.
    ///
    /// Misfit F: a line maintained beside the classifier drifts from it. This
    /// asserts the printed line is the classifier's own sentence, and that a
    /// proven schedule prints no advice at all rather than inventing some.
    #[test]
    fn the_next_line_is_the_classifiers_own_sentence() {
        use ksp_backend::admission::{CapabilityState, Classification};
        use std::time::Duration;

        let declared = Classification {
            capability: ksp_types::LeaseCapability::None,
            mechanism: "a schedule is recorded, but no run has proven it",
            declared_cadence: Some(Duration::from_secs(3_600)),
            proven_cadence: None,
            proof_age: None,
            cleanup_lag: None,
            retention: None,
            state: Some(CapabilityState::DeclaredNoProof),
        };
        let mut report = document(None, None, empty_audit());
        report.backend = ksp_backend::status::StatusDisclosure::from(&declared);
        let text = render_status(&report);
        assert!(
            text.contains("next:"),
            "a state with a step prints it: {text}"
        );
        assert!(
            text.contains("first firing"),
            "the step is the classifier's own sentence: {text}"
        );

        let proven = Classification {
            capability: ksp_types::LeaseCapability::Scheduled {
                interval: Duration::from_secs(3_600),
            },
            mechanism: "a signed sweep proof from the recorded schedule",
            declared_cadence: Some(Duration::from_secs(3_600)),
            proven_cadence: Some(Duration::from_secs(3_600)),
            proof_age: Some(0),
            cleanup_lag: None,
            retention: None,
            state: Some(CapabilityState::Proven),
        };
        report.backend = ksp_backend::status::StatusDisclosure::from(&proven);
        let text = render_status(&report);
        assert!(
            !text.contains("next:"),
            "a proven schedule needs no next step: {text}"
        );
    }

    /// A chain that does not reach a head has no head to print, and says why.
    #[test]
    fn a_broken_audit_chain_prints_no_head_and_names_the_break() {
        let text = render_status(&document(
            None,
            None,
            ksp_backend::status::AuditDisclosure {
                chains: Vec::new(),
                records: 3,
                segments: 1,
                unreadable: 0,
                unattributed: 0,
                broken: Some("admin/6f5a: the chain breaks at index 2".to_string()),
                absent_reason: None,
            },
        ));
        assert!(text.contains("audit:       unknown ("), "{text}");
        assert!(text.contains("the chain breaks at index 2"), "{text}");
        assert!(
            text.contains("a head is not an external checkpoint"),
            "the absence is explained, not just printed: {text}"
        );
        assert!(
            !text.contains("  chain:"),
            "a broken chain has no head line to show: {text}"
        );
    }

    #[test]
    fn a_missing_admission_floor_prints_as_absent_not_as_zero() {
        use ksp_backend::admission::Classification;
        use ksp_backend::status::StatusDisclosure;
        use ksp_types::LeaseCapability;

        let classification = Classification {
            capability: LeaseCapability::None,
            mechanism: "no configured lease mechanism",
            declared_cadence: None,
            proven_cadence: None,
            proof_age: None,
            cleanup_lag: None,
            retention: None,
            state: None,
        };
        let disclosure = StatusDisclosure::from(&classification);
        let text = render_status(&ksp_backend::status::report(
            &classification,
            ksp_backend::status::StatusFacts {
                arming: ksp_backend::status::ArmingDisclosure::None {
                    reason: "no verified arming record names this deployment".to_string(),
                },
                proof: ksp_backend::status::ProofDisclosure {
                    newest_success: None,
                    freshness: None,
                    absent_reason: Some("no sweep proof exists".to_string()),
                    newest_failure: None,
                    malformed: 0,
                },
                audit: ksp_backend::status::AuditDisclosure {
                    chains: Vec::new(),
                    records: 0,
                    segments: 0,
                    unreadable: 0,
                    unattributed: 0,
                    broken: None,
                    absent_reason: Some("no audit log exists here".to_string()),
                },
                posture: ksp_backend::status::PostureDisclosure {
                    confinement: ksp_posture::ConfinementPosture {
                        state: ksp_posture::ConfinementState::Unavailable,
                        landlock: ksp_posture::LandlockObservation::NotEnabled,
                        required: false,

                        adapter: None,
                        guarantee: ksp_types::GuaranteeLevel::None,
                    },
                    barrier: ksp_posture::BarrierPosture::unavailable(
                        ksp_posture::MemlockObservation {
                            soft_bytes: None,
                            hard_bytes: None,
                        },
                    ),
                    undumpable: ksp_posture::UndumpablePosture {
                        core_limit: ksp_posture::ControlOutcome::Applied,
                        ptrace: ksp_posture::ControlOutcome::Applied,
                    },
                },
                capabilities: Vec::new(),
                freshness: ksp_backend::status::Freshness::RollbackDetectionUnavailable,
                canary: None,
                permissions: ksp_backend::status::PermissionDisclosure::new(Vec::new()),
                binding: ksp_backend::status::BindingDisclosure::None,
            },
        ));

        assert_eq!(disclosure.admission_minimum_secs, None);
        assert!(
            text.contains("admits no lease"),
            "an absent floor must not print as a number: {text}"
        );
        assert!(!text.contains("minimum:     0s"));
    }
}
