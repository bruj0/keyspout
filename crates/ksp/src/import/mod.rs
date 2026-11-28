//! Reading secrets out of a file or an external manager, and sealing them here.
//!
//! # Ingest only
//!
//! This module copies a value **into** the sealed store. It never hands one out.
//! Team, group and organisation management stays in the external manager, and
//! `ksp run` reaches none of this: a forbidden-dependency test holds that absence
//! rather than a comment (`crates/ksp/tests/import_guards.rs`).
//!
//! # One command, two ways to acquire
//!
//! A `.env` or JSON file and an external manager differ in exactly one place —
//! where the bytes come from. The parse, the target, the vault binding, the
//! provenance and the report are identical, so they exist once.

pub mod adapter;
pub mod parse;
pub mod provenance;
pub mod target;

use std::collections::BTreeMap;
use std::path::PathBuf;

use ksp_types::Level;

/// What an import was asked to do.
#[derive(Debug, Clone)]
pub enum Source {
    /// Read a file, through the named subset of its format.
    File {
        /// The path the operator named.
        path: PathBuf,
        /// The format to read it as.
        format: parse::FileFormat,
    },
    /// Read through a declaration in `<KSP_HOME>/integrations/`.
    Adapter {
        /// The declaration's name, as `--from` selected it.
        name: String,
        /// What the declaration should read: a search term, a path, a collection.
        selector: String,
    },
}

/// Why an import stopped.
///
/// Every arm is a refusal the operator can act on, and every sentence names the
/// accepted form. Each maps to exit `13`, because each is a well-formed
/// invocation of something this binary will not do.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    /// The target could not be resolved.
    #[error("{0}")]
    Target(#[from] target::TargetError),

    /// The deployment could not be read.
    #[error("{0}")]
    Deployment(String),

    /// The source file could not be read.
    #[error(
        "`{path}` could not be read: {cause}. An import reads a file that already exists; write \
         the values into it first, or pass `--from <adapter>` to read a manager instead"
    )]
    Unreadable {
        /// The path as the operator wrote it.
        path: String,
        /// The operating system's sentence.
        cause: String,
    },

    /// The source was refused, in whole.
    ///
    /// Every refused construct is listed rather than only the first, so one pass
    /// fixes them all. Nothing is written: the parse is all-or-nothing, which is
    /// what makes "no record for any key in that file" true.
    #[error("{}", refused_lines(.0))]
    Parse(Vec<parse::Refusal>),

    /// No declaration by that name exists on this host.
    #[error(
        "no adapter named `{name}` is declared in {directory}. `ksp import --list-adapters` prints \
         the adapters this host has, and a new one is a TOML file in that directory; \
         `ksp import --schema` prints the contract one must satisfy"
    )]
    NoSuchAdapter {
        /// The name that was asked for.
        name: String,
        /// The directory that was searched.
        directory: String,
    },

    /// An adapter operation could not be performed.
    #[error("{0}")]
    Exec(String),

    /// The manager's answer was not the shape the declaration names.
    #[error("{0}")]
    Shape(String),

    /// A value could not be found in a manager's answer.
    #[error("{0}")]
    Extract(String),

    /// The provenance ledger could not be read or written.
    #[error("{0}")]
    Ledger(String),

    /// A value could not be sealed.
    ///
    /// # Why this carries what it already wrote
    ///
    /// The loop stops on the first seal failure, and by then earlier keys are
    /// already in the store. They **must** reach the ledger before this returns,
    /// or the next import sees a store holding values it has no record of, calls
    /// them `new`, and writes a second version of every one of them. That was
    /// measured: with two sealed versions and no ledger row, a re-import reports
    /// both keys `new` at v2.
    ///
    /// So the promise is not "nothing was written" — that would be false — but
    /// "what was written is recorded, so a re-run reports those keys `unchanged`".
    /// A refusal that says an answer is partial obliges the code to state the
    /// part it has.
    #[error(
        "`{key}` could not be sealed into this deployment: {cause}. {written} key(s) were written \
         before it and are recorded, so re-running the import reports them `unchanged` and adds \
         only the rest"
    )]
    Seal {
        /// The key that failed.
        key: String,
        /// What the store said.
        cause: String,
        /// How many keys were sealed and recorded before the failure.
        written: usize,
    },
}

/// Render refused constructs as one line each.
///
/// A function rather than an inline expression so `Display` stays readable and
/// the message's shape is asserted in one place.
fn refused_lines(refusals: &[parse::Refusal]) -> String {
    let mut out = String::from(
        "the source was refused, so no key was imported. Every refused construct is listed, and \
         each names the form that would work:",
    );
    for refusal in refusals {
        out.push_str("\n  - ");
        out.push_str(&refusal.to_string());
    }
    out
}

/// What an import did, for the report.
#[derive(Debug)]
pub struct Imported {
    /// The vault the records were written into.
    pub vault: String,
    /// The canonical source identifier.
    pub source_id: String,
    /// The selector, or the file path when the source was a file.
    pub selector: String,
    /// One row per key, in the source's own order.
    pub rows: Vec<ImportedRow>,
    /// How many records this run wrote.
    pub records: usize,
}

/// One key's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedRow {
    /// The key, as the source wrote it.
    pub key: String,
    /// What became of it.
    pub disposition: provenance::Disposition,
    /// The version written, when one was.
    pub version: Option<u32>,
}

/// Run one import.
///
/// # The order is the guarantee
///
/// `acquire -> parse -> resolve target -> bind vault -> seal -> record -> report`,
/// and the first four write nothing. That ordering is what makes "a refusal
/// writes no record" true rather than hopeful: a parse refusal, an unenrolled
/// principal or a missing recipient key all happen before the first `seal`, so
/// no path leaves a half-import behind.
///
/// The ledger is written **last**, after every sealed write succeeded. A ledger
/// row for a record that was never written would make the next import report a
/// key `unchanged` when the store does not hold it.
pub fn run(
    layout: &crate::config::Layout,
    source: &Source,
    destination: &target::ImportTarget,
) -> Result<Imported, ImportError> {
    // 1. Acquire, then 2. parse. Both are read-only.
    let (pairs, source_id, selector) = acquire(layout, source)?;

    // 3. Resolve the target. Nothing is sealed until this returns.
    let resolved = target::resolve(layout, destination)?;

    // 4. Bind the vault: the deployment's own, never a flag and never a field in
    //    a declaration (misfit J).
    let (recorded, _anchor) = crate::deployment::require(layout)
        .map_err(|error| ImportError::Deployment(error.to_string()))?;

    let level = target::level_for(destination);
    let previous = provenance::last_import(layout, &source_id)
        .map_err(|error| ImportError::Ledger(error.to_string()))?;

    // What the store already holds for these keys, so a key the source still
    // names but a sweep removed is `absent (removed)` rather than `new`.
    let store = crate::config::open_file_store(layout)
        .map_err(|error| ImportError::Deployment(error.to_string()))?;
    let mut present: BTreeMap<String, u32> = BTreeMap::new();
    for key in pairs.keys() {
        let secret = ksp_types::OpaqueSecretId::new(key.clone());
        let next = crate::secret::next_version_at(
            &store,
            &recorded.vault,
            &resolved.principal,
            level.clone(),
            &secret,
        )
        .map_err(|_| ImportError::Seal {
            key: key.clone(),
            cause: "the store could not be read to find the next version".to_string(),
            written: 0,
        })?;
        // `next_version_at` returns 1 for an absent record, so anything above 1
        // means the store holds one and its highest version is one below.
        if next > 1 {
            present.insert(key.clone(), next - 1);
        }
    }

    let decisions = provenance::reconcile(&pairs, &present, &previous);

    // 5. Seal, and record. The sealing half is a function of the store, so the
    //    mid-loop failure path is reachable from a test with a store that fails
    //    on demand rather than only from a full disk.
    let sealed = seal_decisions(
        layout, &store, &recorded, &resolved, &level, &source_id, &decisions,
    )?;

    Ok(Imported {
        vault: recorded.vault.to_string(),
        source_id,
        selector,
        rows: sealed.rows,
        records: sealed.records,
    })
}

/// What a seal pass produced.
#[derive(Debug)]
struct Sealed {
    /// One row per decision, in the source's own order.
    rows: Vec<ImportedRow>,
    /// How many records were written.
    records: usize,
}

/// Seal every decision that writes, recording each before the next.
///
/// # Why the ledger write lives in here
///
/// The store is a parameter so this can be driven by a store that fails at a
/// chosen point. That matters because the property this function carries is only
/// interesting when a seal fails **midway**: the keys already sealed are durable,
/// so they must reach the ledger before the refusal returns. A store holding
/// values with no ledger row makes the next import report them `new` and write a
/// second version of each — measured, not theorised.
#[allow(clippy::too_many_arguments)]
fn seal_decisions(
    layout: &crate::config::Layout,
    store: &dyn ksp_record::version::BlobStore,
    recorded: &crate::deployment::Deployment,
    resolved: &target::ResolvedTarget,
    level: &Level,
    source_id: &str,
    decisions: &[provenance::Decision],
) -> Result<Sealed, ImportError> {
    let mut rows = Vec::with_capacity(decisions.len());
    let mut ledger = Vec::new();
    let mut records = 0usize;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);

    for decision in decisions {
        // `writes` is `None` for `unchanged` and for a key the source stopped
        // naming, so a caller that writes what it finds cannot blank a record
        // the file merely omitted.
        let Some(value) = decision.writes.as_ref() else {
            rows.push(ImportedRow {
                key: decision.key.clone(),
                disposition: decision.disposition,
                version: None,
            });
            continue;
        };

        let secret = ksp_types::OpaqueSecretId::new(decision.key.clone());
        let by = crate::secret::seal_record_by(
            store,
            recorded,
            resolved.principal,
            level.clone(),
            &secret,
            decision.key.as_bytes(),
            value.as_bytes(),
            resolved.recipient,
        );

        // A failure stops the pass, but the keys sealed before it are already
        // durable. They are recorded before the refusal returns.
        let version = match by {
            Ok(version) => version,
            Err(error) => {
                provenance::record_import(layout, &ledger)
                    .map_err(|error| ImportError::Ledger(error.to_string()))?;
                return Err(ImportError::Seal {
                    key: decision.key.clone(),
                    cause: error.to_string(),
                    written: ledger.len(),
                });
            }
        };

        ledger.push(provenance::ImportLedgerEntry {
            source_id: source_id.to_string(),
            key: decision.key.clone(),
            secret_id: decision.key.clone(),
            version,
            value_digest: provenance::value_digest(value.as_bytes()),
            imported_at: now,
        });

        rows.push(ImportedRow {
            key: decision.key.clone(),
            disposition: decision.disposition,
            version: Some(version),
        });
        records += 1;
    }

    provenance::record_import(layout, &ledger)
        .map_err(|error| ImportError::Ledger(error.to_string()))?;

    Ok(Sealed { rows, records })
}

/// Read the source into pairs, and name it canonically.
///
/// Returns the pairs, the source identifier the ledger joins on, and the word to
/// print after `source:`. Every branch ends in a `BTreeMap`, so two runs over the
/// same input produce byte-identical reports and ledger rows.
fn acquire(
    layout: &crate::config::Layout,
    source: &Source,
) -> Result<(BTreeMap<String, String>, String, String), ImportError> {
    match source {
        Source::File { path, format } => {
            let bytes = std::fs::read(path).map_err(|error| ImportError::Unreadable {
                path: path.display().to_string(),
                cause: error.to_string(),
            })?;
            let pairs = match parse::parse(&bytes, *format) {
                parse::ParseOutcome::Accepted(pairs) => pairs,
                parse::ParseOutcome::Refused(refusals) => {
                    return Err(ImportError::Parse(refusals));
                }
            };
            let source_id =
                provenance::source_id_for_file(path).map_err(|error| ImportError::Unreadable {
                    path: path.display().to_string(),
                    cause: error.to_string(),
                })?;
            Ok((pairs, source_id, path.display().to_string()))
        }
        Source::Adapter { name, selector } => {
            let directory = layout.integrations();
            let loaded = adapter::load_dir(&directory);
            let declaration = loaded
                .adapters
                .iter()
                .find(|declaration| &declaration.name == name)
                .ok_or_else(|| ImportError::NoSuchAdapter {
                    name: name.clone(),
                    directory: directory.display().to_string(),
                })?;

            let pairs = read_through_adapter(declaration, selector)?;
            Ok((
                pairs,
                provenance::source_id_for_adapter(name, selector),
                selector.clone(),
            ))
        }
    }
}

/// Run an adapter's `list` and turn its answer into pairs.
///
/// # Where a value comes from
///
/// A list enumerates what the selector matches, and an import needs a value for
/// each match. Two shapes cover the managers this feature was built for, and
/// which applies is decided by the declaration rather than guessed:
///
/// - **The listing carries the value.** The declaration names no `read`, so each
///   listed item is itself the record, and the value is read from the `extract`
///   path `[ops.list]` declares, or from `value` when it declares none.
/// - **The listing carries only identifiers.** The declaration names a `read`, so
///   each listed item is fetched by its own id and the value is read from
///   `[ops.read].extract`. This is the Bitwarden shape: `bw list items` returns
///   the item without its password, and `bw get item <id>` returns it.
///
/// The key is the item's `id` when it has one and its `key` otherwise. A key
/// invented from a list position would be stable only until the listing order
/// changed, which is the one property no vendor promises.
fn read_through_adapter(
    declaration: &adapter::AdapterDeclaration,
    selector: &str,
) -> Result<BTreeMap<String, String>, ImportError> {
    let listing = declaration
        .exec_operation("list", Some(selector), None)
        .map_err(|error| ImportError::Exec(error.to_string()))?;

    let listing = adapter::validate_shape(shape_of(declaration, "list"), listing.as_bytes())
        .map_err(|error| ImportError::Shape(error.to_string()))?;

    // An array is the list itself; an object is a wrapper around it, and the
    // managers that wrap use `items`.
    let items = match listing {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Object(mut map) => match map.remove("items") {
            Some(serde_json::Value::Array(items)) => items,
            _ => {
                return Err(ImportError::Shape(format!(
                    "adapter `{}` declared its `list` shape as an object, and an object wrapper is \
                     read through its `items` member, which it does not have as an array. Declare \
                     `shape = \"json_array\"` on `[ops.list]` when the endpoint answers with an array",
                    declaration.name
                )));
            }
        },
        _ => {
            return Err(ImportError::Shape(format!(
                "adapter `{}` answered its `list` with something that is neither an array nor an \
                 object carrying one in `items`",
                declaration.name
            )));
        }
    };

    // The record the value is read from, and the path inside it.
    let per_item_read = declaration.ops.read.is_some();
    let extract_path = if per_item_read {
        declaration
            .ops
            .read
            .as_ref()
            .and_then(|operation| operation.extract.as_deref())
    } else {
        declaration
            .ops
            .list
            .as_ref()
            .and_then(|operation| operation.extract.as_deref())
    };

    let mut pairs = BTreeMap::new();
    for item in items {
        let id = item_id(&item).ok_or_else(|| {
            ImportError::Extract(format!(
                "adapter `{}` listed an item with neither an `id` nor a `key` field, so there is no \
                 stable name to import it under: a listing is joined to the store by that name, and \
                 a position in the list is not stable",
                declaration.name
            ))
        })?;

        let record = if per_item_read {
            let fetched = declaration
                .exec_operation("read", None, Some(&id))
                .map_err(|error| ImportError::Exec(error.to_string()))?;
            adapter::validate_shape(shape_of(declaration, "read"), fetched.as_bytes())
                .map_err(|error| ImportError::Shape(error.to_string()))?
        } else {
            item.clone()
        };

        // `value` is the default because that is what a listing of pairs uses.
        // A manager that names it otherwise declares an `extract` path, and the
        // refusal for a missing path names that fix.
        let path = extract_path.unwrap_or("value");
        let value = adapter::extract(&record, path, &id)
            .map_err(|error| ImportError::Extract(error.to_string()))?;
        pairs.insert(id, value);
    }

    Ok(pairs)
}

/// The output shape a declaration names for one operation.
///
/// The file-level name and the checker's type are deliberately separate (see
/// `declaration.rs`), so this is the one place they are joined. It exists rather
/// than being inlined twice so a third file-level spelling is added here once.
fn shape_of(declaration: &adapter::AdapterDeclaration, operation: &str) -> adapter::OutputShape {
    let declared = match operation {
        "list" => declaration.ops.list.as_ref(),
        _ => declaration.ops.read.as_ref(),
    };
    match declared
        .map(|operation| operation.shape)
        .unwrap_or_default()
    {
        adapter::declaration::OutputShapeName::Json => adapter::OutputShape::Json,
        adapter::declaration::OutputShapeName::JsonArray => adapter::OutputShape::JsonArray,
    }
}

/// The stable name of a listed item.
///
/// `id` first because that is what every manager's API documents, and `key`
/// second because a key-value store lists pairs that way. A number is accepted
/// where a string is expected: an id that is an integer in the vendor's JSON is
/// still an id.
fn item_id(item: &serde_json::Value) -> Option<String> {
    for field in ["id", "key"] {
        match item.get(field) {
            Some(serde_json::Value::String(text)) if !text.trim().is_empty() => {
                return Some(text.clone());
            }
            Some(serde_json::Value::Number(number)) => return Some(number.to_string()),
            _ => continue,
        }
    }
    None
}

/// The level an import writes at, for a caller that needs it without a target.
///
/// Re-exported rather than restated so `app.rs` and this module cannot disagree
/// about the level an import uses.
pub fn level_for(destination: &target::ImportTarget) -> Level {
    target::level_for(destination)
}

#[cfg(test)]
mod tests {
    //! The mid-loop failure path, which no `.env` file can reach.
    //!
    //! A key is constrained to `[A-Za-z_][A-Za-z0-9_]*`, so the store cannot be
    //! made to refuse one through the command; and the present-map probe reads
    //! every key before the first seal, so a store that fails to *read* fails
    //! before anything is written. The only production trigger is a write that
    //! fails partway — a full disk is the realistic one — so the property is
    //! proven here, against a store that fails at a chosen point. The claim is
    //! not reachable another way, and a claim about a partial result is worth a
    //! test rather than a comment.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use ksp_record::version::{BlobStore, StoreError};
    use ksp_types::Level;

    use super::*;

    /// A store that keeps everything in memory and fails a chosen write.
    ///
    /// `fails_after` counts **record** writes; the arm journal and the metadata
    /// head are written by the same commit, so the counter moves on the path that
    /// carries a sealed version rather than on every `put_if_absent`.
    struct FailingStore {
        bytes: RefCell<BTreeMap<String, Vec<u8>>>,
        writes: RefCell<usize>,
        fails_after: usize,
    }

    impl FailingStore {
        fn new(fails_after: usize) -> Self {
            Self {
                bytes: RefCell::new(BTreeMap::new()),
                writes: RefCell::new(0),
                fails_after,
            }
        }
    }

    impl BlobStore for FailingStore {
        fn get(&self, path: &str) -> Result<Option<Vec<u8>>, StoreError> {
            Ok(self.bytes.borrow().get(path).cloned())
        }

        fn put_if_absent(&self, path: &str, bytes: &[u8]) -> Result<bool, StoreError> {
            // A record path is `p/<vault>/<principal>/<level>/<secret>/<version>`.
            let is_record = path.matches('/').count() == 5;
            if is_record {
                let mut writes = self.writes.borrow_mut();
                if *writes >= self.fails_after {
                    return Err(StoreError::Backend("the disk is full".to_string()));
                }
                *writes += 1;
            }
            let mut map = self.bytes.borrow_mut();
            if map.contains_key(path) {
                return Ok(false);
            }
            map.insert(path.to_string(), bytes.to_vec());
            Ok(true)
        }

        fn compare_and_set(
            &self,
            _path: &str,
            _expected: Option<&[u8]>,
            _replacement: &[u8],
        ) -> Result<bool, StoreError> {
            // The head is not what this test is about, and a head that fails
            // would stop the pass before a second record could be attempted.
            Ok(true)
        }

        fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
            Ok(self
                .bytes
                .borrow()
                .keys()
                .filter(|path| path.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    /// Two keys, so the second seal is the one that can fail.
    fn two_decisions() -> Vec<provenance::Decision> {
        ["A", "B"]
            .into_iter()
            .map(|key| provenance::Decision {
                key: key.to_string(),
                disposition: provenance::Disposition::New,
                writes: Some("value".to_string()),
            })
            .collect()
    }

    /// The failure path records what it sealed before it refuses.
    ///
    /// Without this, the store holds `A` with no ledger row, the next import
    /// reconciles `A` as `new`, and a second version is written — a duplicate of
    /// a value that never changed.
    #[test]
    fn a_midway_failure_records_the_keys_it_already_sealed() {
        let home = tempfile::tempdir().unwrap();
        let layout = crate::config::Layout::new(home.path());

        // A deployment record the metadata can be bound to, without a vault:
        // `seal_record_by` reads only the vault id, and this test is about the
        // ledger, not about anything the keys would open.
        let recorded = crate::deployment::Deployment {
            vault: ksp_types::VaultId::new("vault-1"),
            admin: ksp_types::PrincipalId::generate(),
            user: ksp_types::PrincipalId::generate(),
            user_name: None,
            user_account: None,
            admin_key_id: ksp_identity::KeyId::new("test-admin"),
            admin_vault_signing_key_id: None,
            admin_vault_recipient_key_id: None,
            admin_vault_recipient_key: None,
            user_signing_key_id: None,
            user_signing_key: None,
            user_recipient_key_id: None,
            user_recipient_key: None,
        };
        let resolved = target::ResolvedTarget {
            principal: recorded.admin,
            recipient: [7u8; 32],
        };

        // Fail the second record write, so the first is sealed and recorded.
        let store = FailingStore::new(1);
        let error = seal_decisions(
            &layout,
            &store,
            &recorded,
            &resolved,
            &Level::Admin,
            "file:/tmp/two.env",
            &two_decisions(),
        )
        .expect_err("the second seal fails");

        match &error {
            ImportError::Seal { key, written, .. } => {
                assert_eq!(key, "B", "the key that failed is named");
                assert_eq!(*written, 1, "one key was sealed before the failure");
            }
            other => panic!("expected a Seal refusal, got {other:?}"),
        }

        // The ledger is the assertion that matters: it must already hold `A`.
        let ledger = std::fs::read_to_string(layout.imports_ledger())
            .expect("the ledger was written before the refusal returned");
        assert!(
            ledger.contains("\"key\":\"A\""),
            "the sealed key must be recorded; got: {ledger}"
        );
        assert!(
            !ledger.contains("\"key\":\"B\""),
            "the failed key must not be recorded as written; got: {ledger}"
        );
    }
}
