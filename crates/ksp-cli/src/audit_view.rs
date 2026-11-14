//! `ksp audit`: the records this caller is entitled to read.
//!
//! # Two acts, two commands
//!
//! `ksp admin audit` reports on the deletion acknowledgement journal. This command
//! reads the audit log — the signed, chained records `ksp` appends before it
//! reports an effect. They answer different questions and share no storage, so
//! they share no type either.
//!
//! # Where the scope is decided
//!
//! The decision is [`ksp_identity::scope`]'s, and it is asked here before a single
//! record is read, so a refused request never opens a segment. This module supplies
//! three things the identity context cannot know: which credential proved the
//! caller, where the chains live, and how a record is rendered.
//!
//! # What this view does not do
//!
//! It does not verify signatures or links, and it does not decode a record kind it
//! does not know: `ksp audit verify` answers the first, and the projection that
//! keeps an unknown kind visible is a later package. What it does do is count what
//! it could not read instead of dropping it (FR-042).

use std::io::Write;
use std::path::Path;

use ksp_deletion::{AUDIT_DOMAIN, AuditChain, Frame, RawRecord, SignedAuditRecord, frames};
use ksp_identity::scope::{self, Caller, Request, Scope};
use ksp_types::PrincipalId;
use ksp_types::evidence::Outcome;

use crate::config::Layout;
use crate::exit::{self, Outcome as ExitOutcome};
use crate::output::{
    Emitter, LogEntry, LogRecord, LogView, MalformedRecord, Report, UnknownLogRecord,
};

/// What this view cannot claim, whenever it reads more than one chain.
///
/// Stated rather than implied: the chains are per writer, so this build can prove
/// the order *inside* one chain and only the writers' clocks between chains.
const ORDER_CAVEAT: &str = "records are grouped by chain (writer); the order between chains is each \
                            writer's timestamp claim, not a sequence this host can prove";

/// Said on every view, because a reader will assume otherwise.
///
/// FR-042 wants an unverifiable record reported as unverified and counted; that is
/// `ksp audit verify`'s job. Until it runs, a line that looks like evidence must not be
/// read as evidence, and the cheapest honest thing this command can do is say so.
const NOT_VERIFIED: &str =
    "this view has not checked signatures or chain links; `ksp audit verify` checks them";

/// Said when a record of an unknown kind was withheld from a narrowed view.
///
/// A record this build cannot decode cannot be attributed to an actor either, so a
/// tenant's or a subject's view counts it and does not print it. Printing it would show
/// one principal's record to another on the strength of a directory name.
const WITHHELD: &str = "record(s) of a kind this build does not know were counted and withheld: their actor \
     cannot be established, so they cannot be shown to this view";

/// How many record lines a view emits when the caller names no bound.
///
/// A bound is the default because the log grows without limit and a consumer
/// asking "what happened recently" should not have to decode a year of records to
/// answer. `--limit 0` reads without a bound for a caller that wants everything.
pub const DEFAULT_LIMIT: usize = 200;

/// What the caller asked to see, beyond the scope.
///
/// The scope decides which records are *eligible*; this decides which of those are
/// *emitted*. They are separate because a bound must never be mistaken for a
/// narrower scope: the header reports both counts, so a caller can tell a
/// truncated view from a complete one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Filter {
    /// The most record lines to emit. `0` means no bound.
    pub limit: usize,
    /// Emit only records whose `observed_at` is at or after this instant.
    pub since: Option<i64>,
}

impl Filter {
    /// No bound and no window: what a caller that named neither gets.
    pub fn unbounded() -> Self {
        Self {
            limit: 0,
            since: None,
        }
    }

    /// Whether this record is inside the window.
    ///
    /// Only a decoded record carries a timestamp, so an unknown or malformed
    /// record is never filtered out: excluding a finding because its time could
    /// not be read would hide the very thing the view exists to report.
    fn admits(&self, observed_at: Option<i64>) -> bool {
        match (self.since, observed_at) {
            (Some(since), Some(at)) => at >= since,
            _ => true,
        }
    }

    /// Whether the emitted count has reached the bound.
    fn is_full(&self, emitted: usize) -> bool {
        self.limit != 0 && emitted >= self.limit
    }
}

/// Parse a `--since` duration: `<n><s|m|h|d>`.
///
/// A bad value is the caller's mistake and names the accepted forms, because a
/// duration that silently defaulted would answer a question the caller did not
/// ask.
pub fn parse_since(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let (digits, unit) = text.split_at(text.len().saturating_sub(1));
    let scale = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        _ => {
            return Err(format!(
                "'{text}' is not a duration; use <n><s|m|h|d>, for example 30m, 1h or 7d"
            ));
        }
    };
    let count: u64 = digits.parse().map_err(|_| {
        format!("'{text}' is not a duration; use <n><s|m|h|d>, for example 30m, 1h or 7d")
    })?;
    Ok(count.saturating_mul(scale))
}

/// What the caller asked for on the command line.
pub struct View<'a> {
    /// Read the complete view, as the holder of the admin key.
    pub as_admin: bool,
    /// The principal whose records to show, by UUID.
    pub principal: Option<&'a str>,
    /// Where the vault password is read, when it is read from a file.
    pub passphrase_file: Option<&'a Path>,
    /// The bound and the window.
    pub filter: Filter,
}

/// Why a view could not be produced at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ViewError {
    /// This host has no deployment to read.
    #[error("this host has no deployment")]
    NotProvisioned,
    /// The credential the caller named could not be proved.
    ///
    /// The sentence names the password and the flag that supplies it, because the
    /// common cause is a caller with no terminal: it cannot type, and a refusal
    /// that said only "the credential could not be proved" left it with nothing
    /// to do. A caller that *did* supply a password and got this message has a
    /// wrong password or an unreadable key, and the sentence still fits.
    #[error(
        "the credential for this view could not be proved: this view needs the vault \
         password, read from a terminal, or from the file named by --passphrase-file"
    )]
    Keys,
    /// The request names something that is not a principal UUID.
    #[error("{0} is not a principal UUID; a principal is named by its canonical UUID")]
    NotAPrincipal(String),
}

impl ViewError {
    /// The exit code this failure maps to.
    pub fn exit_code(&self) -> i32 {
        match self {
            // Nothing that could authorise the request was proved: the same class
            // as a vault that will not open, and not the scope refusal's code.
            Self::NotProvisioned | Self::Keys => exit::MISSING_KEY,
            // A request that cannot be authorised as asked, which is what the
            // policy-denial class means.
            Self::NotAPrincipal(_) => exit::POLICY_DENIAL,
        }
    }
}

/// Read the log, scope it, and report it.
pub fn run<W: Write>(layout: &Layout, view: View, emitter: &mut Emitter<W>) -> ExitOutcome {
    let request = match view.principal {
        None => Request::All,
        Some(text) => match PrincipalId::parse(text) {
            Ok(principal) => Request::Subject(principal),
            Err(_) => {
                let error = ViewError::NotAPrincipal(text.to_string());
                let _ = emitter.refusal(&error.to_string());
                return ExitOutcome::Failed(error.exit_code());
            }
        },
    };

    let caller = match caller(layout, &view) {
        Ok(caller) => caller,
        Err(error) => {
            let _ = emitter.refusal(&error.to_string());
            return ExitOutcome::Failed(error.exit_code());
        }
    };

    // Asked before any segment is opened: a refused request reads nothing.
    let scope = match scope::resolve(&caller, request) {
        Ok(scope) => scope,
        Err(refusal) => {
            let _ = emitter.refusal(&refusal.to_string());
            return ExitOutcome::Failed(exit::POLICY_DENIAL);
        }
    };

    let read = read(layout, &scope, &view.filter);
    let mut notes = vec![NOT_VERIFIED.to_string()];
    if read.segments > 1 {
        notes.push(ORDER_CAVEAT.to_string());
    }
    if read.withheld > 0 {
        notes.push(format!("{} {}", read.withheld, WITHHELD));
    }
    // A bounded view must say so, in the same place it says what it counted: a
    // reader that saw only the emitted count would take a truncation for the whole
    // answer. The note names the filter that actually truncated — the window or
    // the bound — because naming the wrong one sends the caller to a flag that
    // changes nothing.
    if view.filter.limit != 0 && read.total > read.records.len() {
        notes.push(format!(
            "this view emitted {} of {} record(s) the window admits: raise --limit, or pass \
             --limit 0 to read without a bound",
            read.records.len(),
            read.total
        ));
    }
    if read.windowed_out > 0 {
        notes.push(format!(
            "{} record(s) are older than the --since window and were not emitted: widen the \
             window, or omit --since to read every record",
            read.windowed_out
        ));
    }
    let report = Report::Log(LogView {
        scope: scope.label(),
        segments: read.segments,
        records: read
            .records
            .iter()
            .filter(|r| matches!(r, LogRecord::Known(_)))
            .count(),
        total: read.total,
        limit: (view.filter.limit != 0).then_some(view.filter.limit),
        unreadable: read.unreadable,
        unknown: read.unknown,
        malformed: read.malformed,
        withheld: read.withheld,
        trouble: read.trouble,
        notes,
    });
    // The summary first, then one record at a time: the header says what the view is and
    // what it cannot claim, and each record is printed from its own payload (FR-039,
    // FR-041).
    let written = emitter
        .report(&report)
        .and_then(|()| emitter.records(&read.records));
    match written {
        Ok(()) => ExitOutcome::Success,
        Err(_) => ExitOutcome::Failed(exit::INTERNAL),
    }
}

/// Prove the caller's identity from the credential it presented.
///
/// The principal is never read from the command line: the admin path checks the
/// loaded key against the pinned anchor, and the tenant path needs the vault
/// password and the binding the deployment pinned.
fn caller(layout: &Layout, view: &View) -> Result<Caller, ViewError> {
    let (deployment, anchor) =
        crate::deployment::require(layout).map_err(|_| ViewError::NotProvisioned)?;
    if view.as_admin {
        // `load_admin` refuses a key whose public half is not the pinned one, so a
        // key file alone is not the admin — the pin is.
        crate::admin::load_admin(layout, &anchor).map_err(|_| ViewError::Keys)?;
        return Ok(Caller::Admin {
            key_id: anchor.key_id,
            tenant: deployment.user,
        });
    }
    let password = crate::app::password(view.passphrase_file).map_err(|_| ViewError::Keys)?;
    let unsealed = crate::secret::unseal(layout, &password).map_err(|_| ViewError::Keys)?;
    let key_id = deployment
        .user_signing_key_id
        .clone()
        .ok_or(ViewError::Keys)?;
    Ok(Caller::Tenant {
        principal: unsealed.user,
        key_id,
    })
}

/// The records inside the scope, plus what could not be read.
struct Read {
    segments: usize,
    records: Vec<LogRecord>,
    /// How many records the window admits, before any bound was applied.
    total: usize,
    /// How many records the scope permits but the window excluded.
    ///
    /// Counted so the view can name the filter that actually emptied it: a note
    /// that said "raise --limit" when the bound is 200 and the window is what
    /// excluded everything sends the caller to the wrong knob.
    windowed_out: usize,
    unreadable: usize,
    unknown: usize,
    malformed: usize,
    withheld: usize,
    trouble: Vec<String>,
}

/// Walk the chains the scope reaches, keep what it permits, and count what it could
/// not read.
///
/// A tenant's scope reaches one directory — its own. Descending into another
/// principal's would leak what Misfit S is about: even a *count* of entries that could
/// not be opened says that something is there, and roughly how much. So the traversal
/// follows the scope and not only the predicate.
///
/// Inside the directories it is entitled to read, a directory that is not a principal
/// UUID and a segment that will not parse are counted rather than skipped: an entry
/// silently dropped is how a log with a hole starts reading like a complete one.
fn read(layout: &Layout, scope: &Scope, filter: &Filter) -> Read {
    let chain = AuditChain::new(layout.audit_root());
    let mut read = Read {
        segments: 0,
        records: Vec::new(),
        total: 0,
        windowed_out: 0,
        unreadable: 0,
        unknown: 0,
        malformed: 0,
        withheld: 0,
        trouble: Vec::new(),
    };

    match scope {
        Scope::Own { principal, .. } => {
            let own = chain.writer_root(*principal);
            // A tenant that has never appended has no directory: an empty view, not a
            // failure, and not something to count.
            read_actor(layout, &own, scope, filter, &mut read);
        }
        Scope::Complete | Scope::Subject { .. } => {
            // The audit root is `0711`: every principal traverses it and none may
            // list it, so a complete view cannot be built from a directory
            // listing. Two sources, and neither may be silent:
            //
            // - the listing, when this caller *can* list (a single-account home);
            // - the principals the deployment names, whose own directories it is
            //   entitled to traverse. A directory it cannot open is counted, not
            //   skipped: "another writer's chain exists and I cannot read it" is
            //   the disclosure, and an empty view would be a lie of omission.
            let mut actors = match std::fs::read_dir(layout.audit_root()) {
                Ok(entries) => entries
                    .flatten()
                    .map(|entry| entry.path())
                    .collect::<Vec<_>>(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(_) => {
                    unreadable(layout, &mut read, &layout.audit_root());
                    Vec::new()
                }
            };
            for principal in known_principals(layout) {
                let directory = chain.writer_root(principal);
                if !actors.contains(&directory) {
                    actors.push(directory);
                }
            }
            actors.sort();
            for directory in actors {
                // A directory that is not a principal UUID is not a writer's chain; it
                // is counted and named rather than silently skipped.
                let is_actor = directory
                    .file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| PrincipalId::parse(name).ok())
                    .is_some();
                if !is_actor {
                    unreadable(layout, &mut read, &directory);
                    continue;
                }
                read_actor(layout, &directory, scope, filter, &mut read);
            }
        }
    }
    read
}

/// Read every segment in one principal's directory, keeping what the scope permits.
fn read_actor(layout: &Layout, directory: &Path, scope: &Scope, filter: &Filter, read: &mut Read) {
    let Ok(files) = std::fs::read_dir(directory) else {
        // Absent is a writer who has never appended, and the view states that as
        // zero records. Anything else — including "I am not allowed to find out" —
        // is counted: `Path::exists` answers `false` for `EACCES`, which would
        // turn a chain this caller may not read into a chain that is not there.
        match std::fs::symlink_metadata(directory) {
            Ok(_) => unreadable(layout, read, directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => unreadable(layout, read, directory),
        }
        return;
    };
    let mut files = files
        .flatten()
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    files.sort();

    for file in files {
        let is_segment = file
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.starts_with("segment-") && name.ends_with(".cbor"))
            .unwrap_or(false);
        if !is_segment {
            // A writer's directory holds segments and nothing else. An entry that is not
            // one is counted and named: skipping it silently is how a renamed or
            // half-written segment turns into a view that looks whole.
            unreadable(layout, read, &file);
            continue;
        }
        read.segments += 1;
        // The file, not the chain: a frame that does not decode must be printed as a
        // finding and the walk must continue, which a chain read cannot do because a
        // record it cannot see might be the one the next link names (FR-042).
        let bytes = match std::fs::read(&file) {
            Ok(bytes) => bytes,
            Err(_) => {
                unreadable(layout, read, &file);
                continue;
            }
        };
        let segment = relative(layout, &file);
        for (index, frame) in frames(&bytes).into_iter().enumerate() {
            match frame {
                Frame::Body(body) => record(body, &segment, index, scope, filter, read),
                Frame::Torn { index, cause } => {
                    read.malformed += 1;
                    read.records.push(LogRecord::Malformed(MalformedRecord {
                        segment: segment.clone(),
                        index,
                        reason: cause.reason().to_string(),
                    }));
                }
            }
        }
    }
}

/// One framed body: a record this build decodes, a kind it does not know, or a finding.
fn record(
    body: &[u8],
    segment: &str,
    index: usize,
    scope: &Scope,
    filter: &Filter,
    read: &mut Read,
) {
    if let Ok(signed) = SignedAuditRecord::from_bytes(body)
        && signed.domain == AUDIT_DOMAIN
    {
        if scope.permits(&signed.record) {
            // The total counts what the *window* admits, before the bound. It is
            // incremented after `admits` and not before, because a bound and a
            // window are both filters and only the bound may truncate: a total
            // that counted records the window excluded would tell a consumer it
            // saw more than it did, which is the opposite of what the field is
            // for.
            if filter.admits(Some(signed.record.observed_at)) {
                read.total += 1;
                if !filter.is_full(read.records.len()) {
                    read.records.push(LogRecord::Known(Box::new(entry(
                        &signed.record,
                        segment,
                        index,
                    ))));
                }
            } else {
                read.windowed_out += 1;
            }
        }
        return;
    }
    // Either the envelope named a domain this build does not know, or its payload is a
    // shape this build cannot type. Both are projected the same way; a body that is not
    // even a CBOR map is a finding.
    match RawRecord::project(body) {
        Some(raw) => {
            read.unknown += 1;
            // Only the complete view may print one: an unknown record cannot be
            // attributed, so a narrowed view cannot know it belongs there.
            if matches!(scope, Scope::Complete) {
                // An unknown record carries no timestamp this build can read, so
                // the window cannot exclude it: a finding is never filtered out.
                read.total += 1;
                if !filter.is_full(read.records.len()) {
                    read.records.push(LogRecord::Unknown(UnknownLogRecord {
                        domain: raw.domain,
                        segment: segment.to_string(),
                        index,
                        fields: raw.fields,
                    }));
                }
            } else {
                read.withheld += 1;
            }
        }
        None => {
            read.malformed += 1;
            if !filter.is_full(read.records.len()) {
                read.records.push(LogRecord::Malformed(MalformedRecord {
                    segment: segment.to_string(),
                    index,
                    reason: "the frame does not decode as a record".to_string(),
                }));
            }
        }
    }
}

/// The principals this deployment names, in a stable order.
///
/// The deployment is public material: the admin and user UUIDs are in it, so
/// naming them leaks nothing a peer could not read. It is also the only source a
/// caller that cannot list the audit root has, and a view that gave up there
/// would report an empty log on a home that has two chains.
pub(crate) fn known_principals(layout: &Layout) -> Vec<PrincipalId> {
    match crate::deployment::require(layout) {
        Ok((deployment, _)) => {
            let mut principals = vec![deployment.admin];
            if deployment.user != deployment.admin {
                principals.push(deployment.user);
            }
            principals
        }
        // An unprovisioned home has no chains under a named principal.
        Err(_) => Vec::new(),
    }
}

/// A path relative to the home, so one host's view is comparable with another's.
fn relative(layout: &Layout, path: &Path) -> String {
    path.strip_prefix(layout.root())
        .unwrap_or(path)
        .display()
        .to_string()
}

/// Count one entry that could not be read, and name it.
///
/// The count alone tells an operator that something is wrong; the path tells them what.
/// Paths are shown relative to the home so one host's view is comparable with another's.
fn unreadable(layout: &Layout, read: &mut Read, path: &Path) {
    read.unreadable += 1;
    read.trouble.push(relative(layout, path));
}

/// Project one record into the view.
fn entry(record: &ksp_types::evidence::AuditRecord, segment: &str, index: usize) -> LogEntry {
    LogEntry {
        actor: record.actor.to_string(),
        signer_key_id: record.signer_key_id.clone(),
        component: record.component.label().to_string(),
        operation: record.operation.label().to_string(),
        target: record
            .target
            .as_ref()
            .map(ksp_types::evidence::AuditTarget::label),
        outcome: match record.outcome {
            Outcome::Success => "success".to_string(),
            Outcome::Failure => "failure".to_string(),
        },
        exit_code: record.exit_code,
        observed_at: record.observed_at,
        // Rendered through the type's own `Display`, so the view and the record
        // cannot describe the same acceptance two different ways. Dropping this
        // field — as this projection did — left the durable record readable in
        // CBOR and unreadable in the only view an operator has (NFR-009).
        acceptance: record.acceptance.as_ref().map(ToString::to_string),
        segment: segment.to_string(),
        index,
    }
}
