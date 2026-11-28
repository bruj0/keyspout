//! Loading, validating and probing a declaration.
//!
//! # Why the destination check runs on the raw document
//!
//! `deny_unknown_fields` already refuses an unknown key, so a `vault = "..."`
//! line fails to parse either way. The refusal differs in what it says: serde
//! reports `unknown field` with no reason, and an operator who wrote `vault`
//! because the adapter looked like it should select one needs to be told that a
//! destination may never come from data. So the raw document is scanned first, and
//! a destination-shaped key refuses with its reason.
//!
//! That ordering is also what makes T008 honest: `--schema` prints the refused
//! keys, and it prints the same list this module refuses on, so the document and
//! the check cannot disagree.

use std::path::{Path, PathBuf};

use super::declaration::{AdapterDeclaration, Kind};

/// A key that would select where a record lands, and why it is refused.
///
/// A destination must be the deployment's own vault, resolved from `KSP_HOME`
/// (misfit J). A declaration that could name one would let a file decide where a
/// record goes, and the operator running an import under `vault-bw-team1` would
/// write into `vault-bw-team2` because a `.toml` said so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusedKey {
    /// The key as it would appear in the file.
    pub name: &'static str,
    /// Why it is refused, in a sentence an operator can act on.
    pub reason: &'static str,
}

/// The destination-shaped keys, with reasons.
///
/// `--schema` prints these, and [`refuse_destination_keys`] refuses on them. One
/// list, so a key cannot be refused without being documented or documented
/// without being refused.
pub fn refused_destination_keys() -> &'static [RefusedKey] {
    &[
        RefusedKey {
            name: "vault",
            reason: "the vault is the deployment's own, resolved from KSP_HOME; a vault named \
                     in a file would let data decide where a record lands",
        },
        RefusedKey {
            name: "vault_id",
            reason: "the vault is the deployment's own, resolved from KSP_HOME; a declaration \
                     cannot redirect a write into a store the running deployment does not own",
        },
        RefusedKey {
            name: "level",
            reason: "the level is the record's provenance and is derived from the command \
                     (`admin put` writes at `admin`); a declaration has no business naming one",
        },
        RefusedKey {
            name: "destination",
            reason: "there is no destination field: the deployment's own vault is the only \
                     destination, and it is never an argument or a file value",
        },
        RefusedKey {
            name: "principal",
            reason: "the target principal is chosen on the command line with --to-principal; a \
                     file naming one would decide who can read the value",
        },
    ]
}

/// Why a declaration could not be loaded or validated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeclarationError {
    /// The file is not readable.
    #[error("the adapter declaration at {path} could not be read: {cause}")]
    Unreadable {
        /// The file that was read.
        path: String,
        /// Why it refused.
        cause: String,
    },

    /// The file parsed into something this type will not accept.
    #[error("{}", .0)]
    Malformed(#[from] Malformed),

    /// The declaration is syntactically fine and describes nothing usable.
    #[error("{}", .0)]
    Invalid(#[from] Invalid),

    /// The declared binary is not on `PATH`.
    #[error("{}", .0)]
    BinaryAbsent(#[from] BinaryAbsent),
}

/// A declaration that parses and is refused on its content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Malformed {
    /// A destination-shaped key appeared in the file.
    #[error(
        "the adapter declaration at {path} carries `{key}`, which is refused: {reason}. \
         Remove the key; the vault, the level and the principal are chosen by the deployment \
         and the command, never by a declaration"
    )]
    DestinationKey {
        /// The file.
        path: String,
        /// The key.
        key: String,
        /// Why it is refused.
        reason: &'static str,
    },

    /// The text is not TOML, or has an unknown key.
    #[error(
        "the adapter declaration at {path} is not a valid declaration: {cause}. The accepted \
         shape is printed by `ksp import --schema`"
    )]
    Parse {
        /// The file.
        path: String,
        /// serde's or toml's own sentence.
        cause: String,
    },

    /// `kind = "cli"` with no `binary`.
    #[error(
        "the adapter declaration at {path} declares `kind = \"cli\"` and no `binary`. The \
         accepted shape names the executable to run, for example `binary = \"bw\"`"
    )]
    MissingBinary {
        /// The file.
        path: String,
    },

    /// `kind = "http"` with no `base_url`.
    #[error(
        "the adapter declaration at {path} declares `kind = \"http\"` and no `base_url`. The \
         accepted shape names the endpoint to call, for example `base_url = \"https://...\"`"
    )]
    MissingBaseUrl {
        /// The file.
        path: String,
    },

    /// Both `binary` and `base_url`, which `kind` cannot disambiguate.
    #[error(
        "the adapter declaration at {path} names both `binary` and `base_url`. `kind` selects \
         which one is used, so the accepted shape names exactly the one its `kind` needs: \
         `kind = \"cli\"` with `binary`, or `kind = \"http\"` with `base_url`"
    )]
    BothEndpoints {
        /// The file.
        path: String,
    },

    /// A `kind` outside the closed set.
    #[error(
        "the adapter declaration at {path} names a `kind` this binary does not implement. The \
         accepted values are `cli` and `http`; a manager whose authentication is \
         challenge-response or OAuth needs a new Rust arm rather than a new file"
    )]
    UnknownKind {
        /// The file.
        path: String,
    },
}

/// A declaration that parses and implements nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Invalid {
    /// No operation at all.
    #[error(
        "adapter `{adapter}` declares no operation, so it can supply no key. The accepted \
         shape declares at least `[ops.list]`, which is what an import enumerates with"
    )]
    NoOperations {
        /// The adapter's own name.
        adapter: String,
    },
}

/// A declared binary that is not on `PATH`, or is there and not runnable.
///
/// Misfit H: a `Command::new` on a missing binary produces the shell's own
/// `command not found`, which names neither the adapter nor the file and arrives
/// as a process error. This refusal is the program's own and names both.
///
/// A file that exists and is not executable is the same defect with a different
/// cause, and it is **not** "the binary is absent": a sentence that said so would
/// send the operator to install a binary that is already there. Probed at review
/// time: `is_file()` accepted a `0644` file, `probe_binary` returned `Ok`, and the
/// eventual `exec` failed with `EACCES` under a sentence claiming the binary
/// existed. So the two states are one error with two sentences.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BinaryAbsent {
    /// Nothing of that name is on `PATH`.
    #[error(
        "adapter `{adapter}` names the binary `{binary}`, which is not on PATH. Install it, or \
         correct `binary` in the declaration; the import refuses here rather than running a \
         command that does not exist"
    )]
    NotFound {
        /// The adapter that named it.
        adapter: String,
        /// The binary, as the declaration spelled it.
        binary: String,
    },

    /// The file is there and the process may not execute it.
    #[error(
        "adapter `{adapter}` names the binary `{binary}`, which exists at {path} and is not \
         executable. Make it executable, or correct `binary`; a file the import cannot run \
         refuses here rather than failing when it is first used"
    )]
    NotExecutable {
        /// The adapter that named it.
        adapter: String,
        /// The binary, as the declaration spelled it.
        binary: String,
        /// Where it was found.
        path: String,
    },
}

/// The declarations a directory holds, and the files that failed.
///
/// One malformed file does not refuse the others: refusing the whole directory
/// would make one typo look like "no adapters are configured".
#[derive(Debug, Default)]
pub struct LoadedDeclarations {
    /// The declarations that loaded, ordered by name.
    pub adapters: Vec<AdapterDeclaration>,
    /// The files that did not, with the reason. Reported, never fatal.
    pub failures: Vec<(PathBuf, DeclarationError)>,
}

/// Load every `.toml` in a directory.
pub fn load_dir(dir: &Path) -> LoadedDeclarations {
    let mut loaded = LoadedDeclarations::default();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        // A directory that does not exist holds no adapters, which is the state of
        // a deployment that has configured none. It is not an error: the caller
        // reports "no adapters configured", which is the truth.
        Err(_) => return loaded,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        match load_at(&path) {
            Ok(declaration) => loaded.adapters.push(declaration),
            Err(error) => loaded.failures.push((path, error)),
        }
    }
    loaded.adapters.sort_by(|a, b| a.name.cmp(&b.name));
    loaded
}

/// Load one declaration from a path.
pub fn load_at(path: &Path) -> Result<AdapterDeclaration, DeclarationError> {
    let text = std::fs::read_to_string(path).map_err(|error| DeclarationError::Unreadable {
        path: path.display().to_string(),
        cause: error.to_string(),
    })?;
    parse(&text, path)
}

/// Parse one declaration from text.
///
/// The destination keys are checked **first**, on the raw document, so the refusal
/// names the key and the reason rather than serde's `unknown field`.
pub fn parse(text: &str, path: &Path) -> Result<AdapterDeclaration, DeclarationError> {
    let at = || path.display().to_string();

    // The raw scan. `toml::Value` accepts any key, so a destination-shaped one is
    // visible here even though the typed parse would reject it anonymously.
    //
    // `toml::from_str` rather than `str::parse::<Value>()`: in `toml` 1.x the
    // `FromStr` impl on `Value` parses a **value**, not a document, and rejects a
    // table with "unexpected content, expected nothing" (probed). The free
    // function is the document parser.
    let raw: toml::Value = toml::from_str(text).map_err(|error: toml::de::Error| {
        DeclarationError::Malformed(Malformed::Parse {
            path: at(),
            cause: error.to_string(),
        })
    })?;

    // Every level, not only the top: an operator who writes `vault` inside
    // `[ops.read]` has made the same mistake, and serde's `unknown field` would
    // name the key without saying why it is refused.
    if let Some((key, reason)) = find_destination_key(&raw) {
        return Err(DeclarationError::Malformed(Malformed::DestinationKey {
            path: at(),
            key: key.to_string(),
            reason,
        }));
    }

    // `deny_unknown_fields` catches everything else.
    let declaration: AdapterDeclaration = toml::from_str(text).map_err(|error| {
        DeclarationError::Malformed(Malformed::Parse {
            path: at(),
            cause: error.to_string(),
        })
    })?;

    // `kind` selects which endpoint is meaningful, and exactly one is accepted.
    match (declaration.kind, &declaration.binary, &declaration.base_url) {
        (Kind::Cli, None, _) => {
            return Err(DeclarationError::Malformed(Malformed::MissingBinary {
                path: at(),
            }));
        }
        (Kind::Http, _, None) => {
            return Err(DeclarationError::Malformed(Malformed::MissingBaseUrl {
                path: at(),
            }));
        }
        _ => {}
    }
    if declaration.binary.is_some() && declaration.base_url.is_some() {
        return Err(DeclarationError::Malformed(Malformed::BothEndpoints {
            path: at(),
        }));
    }

    Ok(declaration)
}

/// Check a declaration's content, once it has parsed.
///
/// Separate from [`parse`] because "the file is not TOML" and "the file describes
/// nothing usable" send an operator to different places: the first to their
/// editor, the second to `--schema`.
pub fn validate(declaration: &AdapterDeclaration) -> Result<(), DeclarationError> {
    let caps = declaration.capabilities();
    if !caps.list && !caps.read {
        return Err(DeclarationError::Invalid(Invalid::NoOperations {
            adapter: declaration.name.clone(),
        }));
    }
    Ok(())
}

impl AdapterDeclaration {
    /// Refuse if the declared binary cannot be executed.
    ///
    /// Resolved before any invocation, so a missing binary is a sentence naming
    /// the adapter and the binary rather than the operating system's
    /// `command not found` arriving as a subprocess error — and so a binary that
    /// is present but not executable refuses with **that** sentence rather than
    /// surfacing as an `EACCES` from the first real invocation.
    pub fn probe_binary(&self) -> Result<(), BinaryAbsent> {
        let Some(binary) = self.binary.as_deref() else {
            // A `http` declaration has no binary to probe; `parse` already
            // required the endpoint its `kind` needs.
            return Ok(());
        };
        match resolve_on_path(binary) {
            Some(path) if is_executable(&path) => Ok(()),
            Some(path) => Err(BinaryAbsent::NotExecutable {
                adapter: self.name.clone(),
                binary: binary.to_string(),
                path: path.display().to_string(),
            }),
            None => Err(BinaryAbsent::NotFound {
                adapter: self.name.clone(),
                binary: binary.to_string(),
            }),
        }
    }
}

/// Whether the process may execute this file.
///
/// Not `is_file()`: a file with no execute bit is present and unrunnable, and the
/// two have different repairs. This mirrors what `execve` will decide for this
/// uid, which is the question a probe exists to answer ahead of time.
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Where a binary lives, if it is on `PATH`.
/// A binary spelled with a separator is checked directly rather than searched.
pub fn resolve_on_path(binary: &str) -> Option<PathBuf> {
    if binary.contains('/') {
        let path = PathBuf::from(binary);
        return path.is_file().then_some(path);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}

/// Find a destination-shaped key at any depth.
///
/// Returns the key and its reason. Depth matters because `[ops.read]` is a table,
/// and an operator who wrote a destination inside one has made the same mistake as
/// one who wrote it at the top.
fn find_destination_key(value: &toml::Value) -> Option<(&'static str, &'static str)> {
    match value {
        toml::Value::Table(table) => {
            for refused in refused_destination_keys() {
                if table.contains_key(refused.name) {
                    return Some((refused.name, refused.reason));
                }
            }
            table.values().find_map(find_destination_key)
        }
        toml::Value::Array(items) => items.iter().find_map(find_destination_key),
        _ => None,
    }
}
