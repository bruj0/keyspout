//! What an adapter declaration is, and what it refuses to be.
//!
//! # A declaration is data, and data here is a capability
//!
//! The file names a binary and an argv, so writing one is as good as running the
//! command as the operator (misfit E). Three consequences run through this type:
//!
//! 1. It is **validated on every use**, never trusted from a previous run.
//! 2. It can express **no destination** — no vault, no level — because a
//!    destination read from a file is a decision made by data rather than by the
//!    operator (misfit J's data half). [`super::validate`] refuses one.
//! 3. It carries a credential **variable name**, never a value. A file that held a
//!    session token would be a secret in a file the operator edits by hand, which
//!    is exactly what this product exists to avoid.
//!
//! # `kind` is a closed set of two
//!
//! `cli` and `http`, and the HTTP arm models exactly one auth shape: a credential
//! in a header, named by `credential_env`. A manager with no parity CLI and a
//! challenge-response or OAuth flow needs a new arm in Rust rather than a new
//! file — that boundary is auth shape, not provider identity, and the plan states
//! it so an operator does not expect `--list-adapters` to grow a third without a
//! code change.
//!
//! # `file` is deliberately absent
//!
//! A `.env` or JSON file goes through [`crate::import::parse`], which invokes
//! nothing. Making it a `kind` would force this type to tolerate a declaration
//! naming no executable, which would weaken the exactness that closes misfits E
//! and H.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How a declaration acquires its bytes.
///
/// Closed at two. See the module docs for why a third arm is a code change and
/// why `file` is not one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// An executable on `PATH`, invoked with an argv and no shell.
    Cli,
    /// An HTTP endpoint, called with a credential in a header.
    Http,
}

impl Kind {
    /// The values this set accepts, in the order the schema prints them.
    ///
    /// A `--schema` reader needs the accepted set as data, not as a sentence, so
    /// it comes from here rather than from a document that can go stale.
    pub const ACCEPTED: &'static [&'static str] = &["cli", "http"];
}

/// One operation a declaration implements: what to run, and what comes back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    /// The argv for `kind = "cli"`. Placeholders `{selector}` and `{key}` are
    /// substituted into exactly one argument each.
    ///
    /// Absent for `kind = "http"`, where the operation is performed by a request
    /// whose path and query the runner builds from the selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,

    /// The path a `kind = "http"` request is sent to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// The shape the output must have before the parser is allowed to read it
    /// (misfit H's changed-output half).
    ///
    /// Defaults to `json` and is omitted when it is the default, so a declaration
    /// that needs no unusual shape does not repeat it. The default is not a
    /// weakening: `json` is the only value in the set today, so a declaration that
    /// omits it gets exactly the check a declaration that names it gets.
    #[serde(default, skip_serializing_if = "OutputShapeName::is_default")]
    pub shape: OutputShapeName,

    /// Where the value sits inside the parsed output, as a dotted path.
    ///
    /// `read` only. A `list` operation yields many items and has no single value,
    /// and a `list` that carried an `extract` would describe a shape the runner
    /// cannot honour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extract: Option<String>,
}

/// The output shape a declaration names, as it appears in the file.
///
/// A separate name from [`super::shape::OutputShape`] on purpose: this is what a
/// **file** says, and the runner's type is what the **check** uses. Keeping them
/// apart means a new file-level spelling is a serde rename rather than a change to
/// the checker's vocabulary.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OutputShapeName {
    /// A JSON object. What a single-record read returns.
    #[default]
    Json,
    /// A JSON array. What a list operation returns.
    ///
    /// Separate from `Json` rather than a permissive default: a shape that
    /// accepted both would stop a `read` from refusing an array, and a vendor
    /// that started wrapping its object in a list would pass unnoticed. Measured
    /// against `bw 2026.10.0`: `bw list items --raw` is an array and
    /// `bw get item <id>` is an object.
    JsonArray,
}

impl OutputShapeName {
    /// The values this set accepts.
    pub const ACCEPTED: &'static [&'static str] = &["json", "json_array"];

    /// Whether this is the default, which the serialiser omits.
    ///
    /// A `skip_serializing_if` predicate rather than a manual `is_json`, because
    /// the default and the predicate must agree: if they drifted, the canonical
    /// example's round trip would fail in one direction only.
    fn is_default(&self) -> bool {
        *self == OutputShapeName::default()
    }
}

/// The operations a declaration implements.
///
/// An omitted operation means **unsupported**, and `--list-adapters` says so,
/// which is what lets an operator learn before an import that a manager cannot
/// supply a per-key read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ops {
    /// Enumerate what the selector matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list: Option<Operation>,
    /// Read one value by key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<Operation>,
    /// Write one value by key.
    ///
    /// Declared so a future write path has somewhere to live, and reported by
    /// `--list-adapters` so its absence is visible. Import does not use it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<Operation>,
}

/// One adapter, as the file describes it.
///
/// `deny_unknown_fields` is the control rather than a convenience: a misspelled
/// key that parsed would leave the adapter running a different command than the
/// operator wrote, and the file would look correct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdapterDeclaration {
    /// The name `--from` selects.
    pub name: String,

    /// Which arm this declaration uses.
    pub kind: Kind,

    /// The executable, for `kind = "cli"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,

    /// The endpoint, for `kind = "http"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,

    /// The **name** of the environment variable holding the credential.
    ///
    /// Never a value. An import reads it from the operator's own environment, so
    /// the token is not in the file, not in argv, and not in this process's log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_env: Option<String>,

    /// The operations this adapter implements.
    ///
    /// Defaulted so that a file that names none parses, and [`super::validate`]
    /// refuses it with a sentence naming the operations that would work. Without
    /// the default, serde says `missing field ops`, which tells the operator the
    /// file is malformed rather than telling them what to add.
    #[serde(default)]
    pub ops: Ops,

    /// Everything the file said that this type does not model.
    ///
    /// Empty in practice: `deny_unknown_fields` refuses an unknown key before it
    /// reaches here. The field exists so [`super::validate`] can report a
    /// destination-shaped key from the **raw** document, where a refusal can name
    /// it and its reason; a serde error for an unknown field would name the key
    /// but not why it is refused.
    #[serde(skip)]
    pub raw: BTreeMap<String, String>,
}

/// Which operations a declaration implements, for `--list-adapters`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// The declaration names a `list` operation.
    pub list: bool,
    /// The declaration names a `read` operation.
    pub read: bool,
    /// The declaration names a `write` operation.
    pub write: bool,
}

impl AdapterDeclaration {
    /// What this declaration can do.
    pub fn capabilities(&self) -> Capabilities {
        Capabilities {
            list: self.ops.list.is_some(),
            read: self.ops.read.is_some(),
            write: self.ops.write.is_some(),
        }
    }

    /// The binary or endpoint, for the `--list-adapters` line.
    pub fn target(&self) -> &str {
        match self.kind {
            Kind::Cli => self.binary.as_deref().unwrap_or(""),
            Kind::Http => self.base_url.as_deref().unwrap_or(""),
        }
    }

    /// Why this declaration cannot authenticate unattended, when it cannot.
    ///
    /// Misfit F, and the plan names `auth_requirement` as an S2 component: an
    /// import that prompts turns a foreground command into a password-capturing
    /// one, and a blocked import in a script looks like a hang. So a declaration
    /// that names `credential_env` is asking the caller to have exported that
    /// variable, and the caller needs the manager's own command to do it.
    ///
    /// `Ok(())` means the declaration expects no credential: a manager whose CLI
    /// already holds a session needs nothing here.
    ///
    /// Found by review: this method did not exist. [`AuthRequirement`] was
    /// reachable only from a test, so nothing a declaration did could produce the
    /// refusal criterion 5 describes.
    pub fn auth_requirement(&self) -> Result<(), AuthRequirement> {
        if self.credential_env.is_some() {
            return Err(AuthRequirement::for_manager(&self.name));
        }
        Ok(())
    }
}

/// How a manager expects to be given a session, and what the refusal says.
///
/// Misfit F: an import that prompts turns a foreground command into a
/// password-capturing one, and one that blocks in a script looks like a hang. So
/// this type never prompts and never accepts a password — it names the command the
/// manager's own CLI provides and returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequirement {
    /// The adapter this refusal is about.
    pub adapter: String,
    /// The command or variable that produces a session.
    pub instruction: String,
}

impl AuthRequirement {
    /// The refusal for a manager this binary has heard of.
    ///
    /// The table is deliberately small and each entry is a command the manager
    /// documents. An unrecognised manager falls back to the environment variable a
    /// declaration configures, which is the one thing this program can truthfully
    /// say about an adapter it does not know.
    pub fn for_manager(manager: &str) -> Self {
        let instruction = match manager {
            "bitwarden" | "vaultwarden" => {
                "run `bw unlock`, then export BW_SESSION to the session it prints \
                 (or set BWS_ACCESS_TOKEN for Secrets Manager)"
            }
            "1password" | "onepassword" => {
                "run `op signin`, or create a service-account token and export it as \
                 OP_SERVICE_ACCOUNT_TOKEN"
            }
            // Not a dead end, and not a guess. This program cannot know an unlisted
            // manager's command, and inventing one would send the operator to a
            // command that does not exist. What is true for every adapter is the
            // variable the declaration itself names, so the sentence points there and
            // gives a concrete example of the two shapes that exist.
            _ => {
                "authenticate that manager with its own CLI, then export the variable the \
                 declaration names in `credential_env` — for example `BWS_ACCESS_TOKEN` for \
                 Bitwarden Secrets Manager — and import reads it from your environment; it \
                 never prompts for a password"
            }
        };
        Self {
            adapter: manager.to_string(),
            instruction: instruction.to_string(),
        }
    }
}

impl std::fmt::Display for AuthRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // CF-120: the emitter prepends its own label, so the sentence states the
        // fact first.
        write!(
            f,
            "adapter `{}` needs a session in `credential_env`: {}. Import never prompts for a \
             password and never stores one, so it stops here rather than blocking on a \
             terminal",
            self.adapter, self.instruction
        )
    }
}
