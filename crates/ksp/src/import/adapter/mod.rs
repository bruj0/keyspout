//! Adapter declarations: what a manager file may say, and how it is run.
//!
//! # One file per manager, and no shell
//!
//! A declaration is TOML in `<KSP_HOME>/integrations/`. Adding a manager means
//! writing one file — no Rust change, no recompile — which is the property the
//! feature exists to provide. The boundary is **auth shape**, not provider
//! identity: a manager whose CLI handles its own session needs only a file, and
//! one with a challenge-response flow needs one new Rust arm.
//!
//! # The four things a declaration may never do
//!
//! - **Name a destination.** No vault, no level, no principal. Those are the
//!   deployment's and the command's, never a file's (misfit J's data half).
//! - **Carry a secret.** `credential_env` is a variable *name*; the value stays in
//!   the operator's environment and is never written into argv or a log (misfit F).
//! - **Reach a shell.** [`runner`] passes an argv vector to
//!   [`std::process::Command`], so `;` and `$()` are bytes rather than syntax
//!   (misfit E).
//! - **Be trusted for existing.** It is validated and its binary probed on every
//!   use, because a file that names a command is a capability (misfit E again).

pub mod declaration;
pub mod extract;
pub mod http;
pub mod runner;
pub mod schema;
pub mod shape;
pub mod validate;

pub use declaration::{AdapterDeclaration, AuthRequirement, Capabilities, Kind};
pub use extract::{ExtractError, extract, extract_or_item};
pub use runner::ExecError;
pub use schema::{EmittedSchema, canonical_example, emit_schema};
pub use shape::{OutputShape, ShapeError, validate_shape};
pub use validate::{
    BinaryAbsent, DeclarationError, Invalid, LoadedDeclarations, Malformed, load_at, load_dir,
    refused_destination_keys, validate,
};

/// The directory under `KSP_HOME` that holds adapter declarations.
///
/// Named here rather than spelled at each use, so the layout table, the loader
/// and any refusal that names the directory cannot disagree about it.
pub const INTEGRATIONS_DIR: &str = "integrations";
