//! Provenance, reconciliation, and the disposition of every imported key.
//!
//! # What this module decides, and why it decides it in one place
//!
//! An import writes values. The question an operator asks next is a different
//! one: *what did the last import of this source write, and how does this one
//! differ?* Answering it needs three facts that no single record holds — which
//! source a key came from, what value it had last time, and whether the record
//! is still in the store — so they are reconciled here rather than inferred at
//! each surface.
//!
//! # Misfit G: the two ways a re-import destroys state
//!
//! - **Deleting on absence.** A key missing from a *partial* copy of a file
//!   looks identical to a key the operator deliberately removed. Keyspout cannot
//!   tell them apart, so it reports and never deletes ([`never_delete`]).
//! - **Overwriting with a stale value.** A second import of an older copy
//!   silently replaces a newer value. The digest in the ledger is what makes
//!   "unchanged" distinguishable from "changed" at all: the sealed blob uses a
//!   random nonce, so equal plaintext never produces equal ciphertext and the
//!   record's stored bytes cannot answer the question (CF-133).
//!
//! # Misfit I: the copy is invisible
//!
//! An imported value exists in two places. Without a record of the import, a
//! later rotation in the manager leaves the Keyspout copy silently behind, and
//! nothing says the value was imported rather than typed. The ledger is that
//! record.
//!
//! # Why the ledger is not part of the record
//!
//! [`ksp_types::BoundMetadata`] is the AEAD and HPKE associated data and a fixed
//! five-tuple; `ContentBlob`'s plaintext is `[u32 name_len][name][value]`; a
//! `Record` has no sidecar. Adding provenance to any of them re-seals every
//! record, so the ledger follows `issuance.jsonl` and `policy-events.jsonl`
//! instead (plan KDD-1). The accepted cost is that provenance is not
//! tamper-evident with the value: a local edit to the ledger changes what a
//! later import calls absent. The file is `0600` and one writer owns it.
//!
//! # Ordering
//!
//! [`record_import`] runs **after** the sealed write succeeds. A row written
//! first would name a record that does not exist, and the next import would
//! decide `unchanged` against a version nobody can open.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The domain separator prefixed to every digest.
///
/// Length-delimited from the value so a domain that happens to be a prefix of
/// another cannot collide with it, following the fingerprint's construction.
const DIGEST_DOMAIN: &[u8] = b"ksp.import.value.v1";

/// The mode the ledger is created with, and measured against.
///
/// Owner-only, unlike the two principal ledgers' `0640`: an import is the
/// admin's own act, and this file names which of her keys came from which file.
/// Nobody else needs it, so it grants nobody else access.
pub const IMPORTS_LEDGER_MODE: u32 = 0o600;

/// The filename, relative to the deployment home.
pub const IMPORTS_LEDGER_FILE: &str = "imports.jsonl";

// ---------------------------------------------------------------------------
// The digest
// ---------------------------------------------------------------------------

/// SHA-256 over the imported plaintext, under a fixed domain prefix.
///
/// This is what makes [`Disposition::Unchanged`] computable. The two accepted
/// costs are named where the decision was made (plan KDD-1 and the
/// `ImportLedgerEntry` entity): a reader of the ledger can confirm a *guess* at
/// an imported value offline, and the digest is not tamper-evident with the
/// value.
///
/// It is rendered lowercase hex so a row is readable with `jq` and comparable
/// across runs without a decoder.
pub fn value_digest(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update((DIGEST_DOMAIN.len() as u64).to_be_bytes());
    hasher.update(value);
    let digest = hasher.finalize();
    // Hex by hand: the workspace already renders digests this way, and a
    // one-line loop does not justify a dependency.
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// The ledger row
// ---------------------------------------------------------------------------

/// One line of `imports.jsonl`: what one import of one source wrote.
///
/// `version` and `secret_id` are what the next import joins on, and
/// `value_digest` is what it compares. A row that carried only `version` could
/// not tell a changed value from an unchanged one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportLedgerEntry {
    /// The canonical source identifier: a file path or `adapter:<name>:<selector>`.
    pub source_id: String,
    /// The key name as it appeared in the source.
    pub key: String,
    /// The opaque identifier the record was written under.
    pub secret_id: String,
    /// The version this import wrote.
    pub version: u32,
    /// SHA-256 of the value, lowercase hex. See [`value_digest`].
    pub value_digest: String,
    /// Whole seconds since the Unix epoch, matching every other ledger here.
    pub imported_at: i64,
}

// ---------------------------------------------------------------------------
// Source identity
// ---------------------------------------------------------------------------

/// Why a source identifier could not be produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceIdError {
    /// The file could not be canonicalised.
    ///
    /// A missing file and an unreadable one are one error here because the
    /// caller's next step is the same — check the path — and the operating
    /// system's own sentence names which it was.
    #[error(
        "the import source `{path}` could not be resolved: {cause}. Pass a file that exists \
         and is readable, or an adapter selector with `--from <adapter>`"
    )]
    Unresolvable {
        /// The path as it was given.
        path: String,
        /// The operating system's sentence.
        cause: String,
    },
}

/// The canonical identifier of a file source.
///
/// Canonicalised, so the same file named two ways is one source. Without it
/// every import would look like a first import, `absent` would never fire, and
/// Misfit G would be unreachable — a `cd`, a `./`, or a `..` is enough to mint a
/// second lineage.
///
/// The file need not be a regular file: a symlink to one canonicalises to its
/// target, which is the same source read through a different name.
pub fn source_id_for_file(path: &Path) -> Result<String, SourceIdError> {
    let canonical = std::fs::canonicalize(path).map_err(|error| SourceIdError::Unresolvable {
        path: path.display().to_string(),
        cause: error.to_string(),
    })?;
    Ok(format!("file:{}", canonical.display()))
}

/// The identifier of an adapter source.
///
/// Not canonicalised, because an adapter selector is a manager-side coordinate
/// rather than a filesystem path, and normalising one would guess at a
/// manager's own semantics.
pub fn source_id_for_adapter(name: &str, selector: &str) -> String {
    format!("adapter:{name}:{selector}")
}

// ---------------------------------------------------------------------------
// Reading the ledger
// ---------------------------------------------------------------------------

/// The last import of one source, as the reconciler needs it.
///
/// A map rather than a list because the reconciler's only question is per key.
/// The digest and version are kept together: a key can be present with a
/// matching digest and a missing record, and only both halves answer what to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportLedger {
    rows: BTreeMap<String, ImportLedgerEntry>,
}

impl ImportLedger {
    /// Build a ledger from rows already in hand.
    ///
    /// The last row for a key wins, matching [`last_import`]: within one source
    /// the newest import is the one the next reconcile is against.
    pub fn from_entries(entries: &[ImportLedgerEntry]) -> Self {
        let mut rows = BTreeMap::new();
        for entry in entries {
            rows.insert(entry.key.clone(), entry.clone());
        }
        Self { rows }
    }

    /// Whether this source has no recorded import at all.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The keys the last import of this source wrote, sorted.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.rows.keys().map(String::as_str)
    }

    /// The version the last import wrote for `key`.
    pub fn version_of(&self, key: &str) -> Option<u32> {
        self.rows.get(key).map(|row| row.version)
    }

    /// The whole row the last import wrote for `key`.
    pub fn row(&self, key: &str) -> Option<&ImportLedgerEntry> {
        self.rows.get(key)
    }
}

/// Why the ledger could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    /// The ledger exists and could not be read, or a row in it is not JSON.
    ///
    /// Distinguishable from absence on purpose: a corrupt ledger that read as an
    /// empty one would report every key as `new` and bump every version.
    #[error(
        "the import ledger at {path} could not be read: {cause}. It records which keys came \
         from which source; repair or remove it before importing again, because reading it as \
         empty would treat every key as new"
    )]
    Unreadable {
        /// The file that was read.
        path: String,
        /// Why it refused.
        cause: String,
    },

    /// The ledger could not be created or appended to.
    #[error(
        "the import ledger at {path} could not be written: {cause}. An import that cannot record \
         what it wrote cannot be reconciled later, so nothing was imported"
    )]
    Unwritable {
        /// The file that was written.
        path: String,
        /// Why it refused.
        cause: String,
    },
}

/// Read every row for one source, keeping the last import of each key.
///
/// A source that was never imported reads as an empty ledger rather than an
/// error: that is the first import of every source, and failing on it would make
/// the command unusable the first time it ran.
///
/// A ledger that exists but cannot be parsed is an **error**, not an empty
/// answer. The two are different facts — "nothing recorded" and "the record is
/// unreadable" — and conflating them reports every key as new and re-versions
/// the whole store.
pub fn last_import(
    layout: &crate::config::Layout,
    source_id: &str,
) -> Result<ImportLedger, LedgerError> {
    let path = layout.imports_ledger();
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        // Only absence is an empty lineage. Any other read failure means the
        // file is there and unreadable, which is evidence rather than absence.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ImportLedger::default());
        }
        Err(error) => {
            return Err(LedgerError::Unreadable {
                path: path.display().to_string(),
                cause: error.to_string(),
            });
        }
    };

    let mut rows = BTreeMap::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let entry: ImportLedgerEntry =
            serde_json::from_str(line).map_err(|error| LedgerError::Unreadable {
                path: path.display().to_string(),
                cause: error.to_string(),
            })?;
        if entry.source_id == source_id {
            rows.insert(entry.key.clone(), entry);
        }
    }
    Ok(ImportLedger { rows })
}

// ---------------------------------------------------------------------------
// Writing the ledger
// ---------------------------------------------------------------------------

/// Append one row per key this import wrote.
///
/// Called **after** the sealed write succeeds. An empty slice writes nothing and
/// still succeeds: an import that wrote no key has nothing to record, and
/// creating an empty file would make "never imported" indistinguishable from
/// "imported nothing".
pub fn record_import(
    layout: &crate::config::Layout,
    entries: &[ImportLedgerEntry],
) -> Result<(), LedgerError> {
    if entries.is_empty() {
        return Ok(());
    }

    let path: PathBuf = layout.imports_ledger();
    let mut rendered = String::new();
    for entry in entries {
        let line = serde_json::to_string(entry).map_err(|error| LedgerError::Unwritable {
            path: path.display().to_string(),
            cause: error.to_string(),
        })?;
        rendered.push_str(&line);
        rendered.push('\n');
    }

    // `open(2)`'s mode applies **only at creation**, and even then it is masked by
    // the caller's `umask`. Two facts follow, and both are why the mode is set
    // again below rather than trusted here:
    //
    // 1. A ledger that already exists keeps whatever mode it has. A file left at
    //    `0644` by an older build, or created by hand, would stay readable by
    //    every account for the life of the deployment while `ksp status` reported
    //    the row as matching, because the row only measures drift.
    // 2. At creation, `0600 & ~umask` is `0600` for any ordinary umask, but
    //    `umask 0777` strips every bit and yields `0000` — a ledger its own owner
    //    cannot read. This was probed rather than reasoned about.
    //
    // So `set_permissions` below states the final mode unconditionally, and this
    // open's `mode` is a best-effort narrowing for the window before it runs.
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(IMPORTS_LEDGER_MODE)
        .open(&path)
        .map_err(|error| LedgerError::Unwritable {
            path: path.display().to_string(),
            cause: error.to_string(),
        })?;

    // An append is one write, so a row is never half-written by a concurrent
    // reader: the file is opened `O_APPEND` and the buffer is one `write_all`.
    file.write_all(rendered.as_bytes())
        .map_err(|error| LedgerError::Unwritable {
            path: path.display().to_string(),
            cause: error.to_string(),
        })?;

    // Unconditional, and an error rather than `let _ =`. A ledger whose mode
    // could not be narrowed is a ledger whose rows are readable by accounts the
    // import did not intend to inform, and silently discarding that would make
    // the failure look like a success.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(IMPORTS_LEDGER_MODE)).map_err(
        |error| LedgerError::Unwritable {
            path: path.display().to_string(),
            cause: error.to_string(),
        },
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------

/// What became of one key.
///
/// The two `Absent` arms are separate because the repairs differ, which is the
/// whole point of the distinction: one sends the operator to the source file,
/// the other to the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Disposition {
    /// The key is in this source and in no earlier import of it.
    New,
    /// The key is in this source with a value that differs from the last import.
    Changed,
    /// The key is in this source with the same value as the last import.
    Unchanged,
    /// The ledger names the key and the source no longer does.
    ///
    /// The file dropped it. The record stays: Keyspout cannot distinguish a
    /// deliberate removal from a partial copy (Misfit G).
    AbsentNotInSource,
    /// The source still names the key and the store no longer holds the record.
    ///
    /// A sweep removed a record the source still names. Re-importing restores it,
    /// which is why this is not the same sentence as the arm above — and why it
    /// **writes**. Probed at implement time: an earlier version reported this arm
    /// and wrote nothing, so its own documentation ("re-importing restores it")
    /// was false and a swept record could never come back.
    AbsentRemoved,
}

impl Disposition {
    /// The word the report and `--json` carry.
    ///
    /// The two absent arms render differently **and** both read as absent, so a
    /// surface that matches on a prefix still groups them and a human reading one
    /// line still sees which repair applies.
    pub fn as_str(self) -> &'static str {
        match self {
            Disposition::New => "new",
            Disposition::Changed => "changed",
            Disposition::Unchanged => "unchanged",
            Disposition::AbsentNotInSource => "absent (not in source)",
            Disposition::AbsentRemoved => "absent (removed)",
        }
    }

    /// Whether this disposition writes a new version.
    ///
    /// `New`, `Changed` and `AbsentRemoved` do. The first two because the value
    /// is new or differs; `AbsentRemoved` because the store lost a record the
    /// source still names, and this import is the only thing that will put it
    /// back. Reporting it and writing nothing — which an earlier version did —
    /// leaves the record missing however many times the operator re-runs, and
    /// contradicts this arm's own documentation.
    ///
    /// `Unchanged` and `AbsentNotInSource` write nothing. `AbsentNotInSource` in
    /// particular is the half of Misfit G that must never touch the store: a key
    /// missing from a partial copy of a file is indistinguishable from one the
    /// operator removed, so it is reported and left alone.
    pub fn writes(self) -> bool {
        matches!(
            self,
            Disposition::New | Disposition::Changed | Disposition::AbsentRemoved
        )
    }
}

impl std::fmt::Display for Disposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One key's outcome, with the value to write when there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The key name.
    pub key: String,
    /// What became of it.
    pub disposition: Disposition,
    /// The value to write, when [`Disposition::writes`] is true.
    ///
    /// `None` on `Unchanged` and `AbsentNotInSource`, so a caller that iterates
    /// decisions and writes what it finds cannot blank a record the file merely
    /// stopped naming. `AbsentRemoved` carries the source's value, which is what
    /// restores the record a sweep took.
    pub writes: Option<String>,
}

/// Compare this import against the last one of the same source.
///
/// `source` is this import's pairs. `present` is what the **store** currently
/// holds, as a map from key to its latest version — the second half of the
/// `absent` distinction, and the reason this takes the store's answer rather
/// than trusting the ledger alone.
///
/// The order of the returned vector is the source's own order (`BTreeMap`, so
/// sorted), with the absent keys appended in ledger order, so two runs of the
/// same inputs produce byte-identical reports.
pub fn reconcile(
    source: &BTreeMap<String, String>,
    present: &BTreeMap<String, u32>,
    previous: &ImportLedger,
) -> Vec<Decision> {
    let mut decisions = Vec::with_capacity(source.len());

    for (key, value) in source {
        let disposition = match previous.row(key) {
            // Never imported from this source. Being in the store does not make
            // it unchanged: a value the admin typed by hand is a different fact
            // from one this source wrote, and overwriting it is the change the
            // operator asked for by importing.
            None => Disposition::New,
            Some(row) => {
                if present.get(key).is_none() {
                    // The source names it and the store lost it. A sweep, most
                    // likely, and the fix is to re-import — not to edit the file.
                    Disposition::AbsentRemoved
                } else if row.value_digest == value_digest(value.as_bytes()) {
                    Disposition::Unchanged
                } else {
                    Disposition::Changed
                }
            }
        };

        decisions.push(Decision {
            key: key.clone(),
            disposition,
            writes: disposition.writes().then(|| value.clone()),
        });
    }

    // The ledger's keys this source no longer names. Sorted, because the ledger's
    // own map is.
    for key in previous.keys() {
        if !source.contains_key(key) {
            decisions.push(Decision {
                key: key.to_string(),
                disposition: Disposition::AbsentNotInSource,
                writes: None,
            });
        }
    }

    decisions
}

/// An absent key is reported and nothing else happens.
///
/// This is a doc-only marker rather than a function because the property is
/// negative: the guarantee is that no code path turns
/// [`Disposition::AbsentNotInSource`] into a delete, and a function would have
/// nothing to do. It is named here so a reviewer can find where the decision
/// lives, and [`Disposition::writes`] is the type-level half of it.
pub mod never_delete {}
