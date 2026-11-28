//! Running a declared command, with no shell anywhere in the path.
//!
//! # The two ways a value becomes a command
//!
//! A selector is operator input that reaches an adapter. If it is interpolated
//! into a shell string, `;`, `$()` or a backtick ends the declaration's command and
//! starts one of the selector's author's choosing (misfit E's second form). Two
//! things prevent that here, and both are structural rather than careful:
//!
//! 1. [`std::process::Command`] is given an **argv vector**. There is no string
//!    for a shell to parse, so there is nothing to interpret.
//! 2. A placeholder is replaced **inside one argument element**. A selector
//!    containing a space therefore fills one argv slot rather than splitting into
//!    two, so the child cannot be given a different command by a value.
//!
//! The child's environment carries no secret beyond what the operator already
//! exported: the declaration names a variable, and this module never writes one.

use std::process::{Command, Stdio};

use super::declaration::AdapterDeclaration;

/// Why a declared command could not be run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecError {
    /// The operation cannot be executed by this declaration's `kind`.
    ///
    /// A `kind = "cli"` operation with no `argv` describes nothing to run; an
    /// `http` operation has no invocation arm at all yet (CF-138). The refusal
    /// names the operation, the `kind`, and the option **that kind** accepts,
    /// because a single message naming `argv` would send an `http` reader to a key
    /// `parse` refuses alongside `base_url`.
    #[error(
        "adapter `{adapter}` cannot execute its `{operation}` operation: it is `kind = \
         \"{kind}\"` and that operation declares no {option}. {accepted}"
    )]
    NoArgv {
        /// The adapter.
        adapter: String,
        /// The operation.
        operation: String,
        /// The `kind`, so the refusal names the option that kind accepts.
        kind: String,
        /// The option this `kind` needs.
        option: &'static str,
        /// What an operator should write instead.
        accepted: &'static str,
    },

    /// The child could not be spawned.
    #[error(
        "adapter `{adapter}` could not run `{binary}`: {cause}. The declaration named it, so \
         the binary existing was the one thing this refusal is not about"
    )]
    Spawn {
        /// The adapter.
        adapter: String,
        /// The binary.
        binary: String,
        /// The operating system's sentence.
        cause: String,
    },

    /// The child ran and exited non-zero.
    ///
    /// The child's own stderr is carried, because it is the manager's sentence and
    /// the operator needs it. It is **not** presented as this program's refusal: a
    /// wrapper that reprinted `bw`'s error as its own would take the blame for a
    /// credential the manager rejected.
    #[error(
        "adapter `{adapter}` ran `{binary}` and it exited {status}: {stderr}. That sentence is \
         the manager's own, so it names the fault better than this program can"
    )]
    Exited {
        /// The adapter.
        adapter: String,
        /// The binary.
        binary: String,
        /// The exit status.
        status: String,
        /// The child's stderr, trimmed.
        stderr: String,
    },

    /// The child's stdout was not UTF-8.
    #[error(
        "adapter `{adapter}` produced output that is not valid UTF-8, so it is not the JSON \
         shape it declares"
    )]
    NotUtf8 {
        /// The adapter.
        adapter: String,
    },

    /// The request for an `http` operation failed.
    ///
    /// Carried as the transport's own sentence rather than restated: the reason
    /// a request failed (an unreachable host, a 403, a body that is not UTF-8)
    /// each needs a different repair, and a single sentence invented here would
    /// name one fix for all of them.
    #[error("{refusal}")]
    Http {
        /// The adapter.
        adapter: String,
        /// The transport's sentence, which already names the adapter and the URL.
        refusal: String,
    },
}

impl AdapterDeclaration {
    /// Run one declared operation.
    ///
    /// `argv` is the declaration's own vector; `selector` and `key` fill the
    /// `{selector}` and `{key}` placeholders. Substitution happens inside one
    /// element, so a value never becomes two arguments.
    ///
    /// Returns the child's stdout. Shape checking is the caller's next step
    /// ([`super::shape::validate_shape`]), kept separate so this function has one
    /// job and can be tested with `/bin/echo`.
    ///
    /// The argv is `&[S]` rather than `&[String]` so a caller holding a literal
    /// test vector and a caller holding a declaration's owned vector both work
    /// without either converting.
    pub fn exec<S: AsRef<str>>(
        &self,
        argv: &[S],
        selector: Option<&str>,
        key: Option<&str>,
    ) -> Result<String, ExecError> {
        let binary = self.binary.as_deref().unwrap_or_default();
        let resolved: Vec<String> = argv
            .iter()
            .map(|element| substitute(element.as_ref(), selector, key))
            .collect();

        // No `.shell()`, no `sh -c`, no string concatenation: the operating system
        // receives the vector. This is the whole of misfit E's second form.
        let output = Command::new(binary)
            .args(&resolved)
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .map_err(|error| ExecError::Spawn {
                adapter: self.name.clone(),
                binary: binary.to_string(),
                cause: error.to_string(),
            })?;

        if !output.status.success() {
            let status = match output.status.code() {
                Some(code) => code.to_string(),
                None => "on a signal".to_string(),
            };
            return Err(ExecError::Exited {
                adapter: self.name.clone(),
                binary: binary.to_string(),
                status,
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }

        String::from_utf8(output.stdout).map_err(|_| ExecError::NotUtf8 {
            adapter: self.name.clone(),
        })
    }

    /// Run a named operation from the declaration.
    ///
    /// Two arms, because the declaration has two kinds. A `cli` operation is
    /// executed as an argv vector; an `http` operation is executed as a request.
    /// They differ only in how the bytes are acquired, so both return the raw
    /// text and the caller checks its shape either way
    /// ([`super::shape::validate_shape`]).
    ///
    /// CF-138 recorded that the `http` arm had no invocation, which made an
    /// `http` declaration validate and then refuse. [`super::http`] is the
    /// missing half.
    pub fn exec_operation(
        &self,
        operation: &str,
        selector: Option<&str>,
        key: Option<&str>,
    ) -> Result<String, ExecError> {
        let declared = match operation {
            "list" => self.ops.list.as_ref(),
            "read" => self.ops.read.as_ref(),
            _ => self.ops.write.as_ref(),
        };

        if self.kind == super::declaration::Kind::Http {
            return self.exec_http(declared, operation, selector, key);
        }

        let (option, accepted) = (
            "`argv`",
            "The accepted shape names the command, for example `argv = [\"list\", \"items\"]`",
        );
        let Some(operation_spec) = declared else {
            return Err(ExecError::NoArgv {
                adapter: self.name.clone(),
                operation: operation.to_string(),
                kind: format!("{:?}", self.kind).to_lowercase(),
                option,
                accepted,
            });
        };
        let Some(argv) = operation_spec.argv.as_ref() else {
            return Err(ExecError::NoArgv {
                adapter: self.name.clone(),
                operation: operation.to_string(),
                kind: format!("{:?}", self.kind).to_lowercase(),
                option,
                accepted,
            });
        };
        self.exec(argv, selector, key)
    }

    /// Perform one `http` operation.
    ///
    /// The path is substituted through the same `{selector}` / `{key}`
    /// vocabulary the `cli` arm uses, so a manager whose read is keyed by path
    /// (`/items/{key}`) needs no field the contract does not already have, and a
    /// manager whose list is filtered by query gets the selector appended when
    /// the path does not place it.
    ///
    /// The credential is read from **this process's** environment by the name
    /// the declaration gives. It is never written to the declaration, to argv, or
    /// to the report.
    fn exec_http(
        &self,
        declared: Option<&super::declaration::Operation>,
        operation: &str,
        selector: Option<&str>,
        key: Option<&str>,
    ) -> Result<String, ExecError> {
        let Some(spec) = declared else {
            return Err(ExecError::NoArgv {
                adapter: self.name.clone(),
                operation: operation.to_string(),
                kind: "http".to_string(),
                option: "`path`",
                accepted: "The accepted shape names the request path, for example \
                           `path = \"/items\"`",
            });
        };
        let Some(path) = spec.path.as_deref() else {
            return Err(ExecError::NoArgv {
                adapter: self.name.clone(),
                operation: operation.to_string(),
                kind: "http".to_string(),
                option: "`path`",
                accepted: "The accepted shape names the request path, for example \
                           `path = \"/items\"`",
            });
        };
        let Some(base_url) = self.base_url.as_deref() else {
            return Err(ExecError::NoArgv {
                adapter: self.name.clone(),
                operation: operation.to_string(),
                kind: "http".to_string(),
                option: "`base_url`",
                accepted: "The accepted shape names the host, for example \
                           `base_url = \"https://vault.example\"`",
            });
        };

        let substituted = key
            .map(|key| path.replace("{key}", key))
            .unwrap_or_else(|| path.to_string());
        let mut url = super::http::join(base_url, &substituted);
        // A path that places the placeholder already carries the selector's
        // value; appending it again would send it twice and let the vendor decide
        // which one wins.
        if !path.contains("{selector}") {
            url = super::http::with_selector(&url, "search", selector);
        } else if let Some(selector) = selector {
            url = url.replace("{selector}", &super::http::encode(selector));
        }

        let credential = self
            .credential_env
            .as_deref()
            .and_then(|name| std::env::var(name).ok());

        super::http::get(&self.name, &url, credential.as_deref()).map_err(|error| ExecError::Http {
            adapter: self.name.clone(),
            refusal: error.to_string(),
        })
    }
}

/// Replace placeholders inside one argument element.
///
/// Deliberately not a global replace across a joined string: joining and splitting
/// is how a value becomes two arguments.
fn substitute(element: &str, selector: Option<&str>, key: Option<&str>) -> String {
    let mut out = element.to_string();
    if let Some(selector) = selector {
        out = out.replace("{selector}", selector);
    }
    if let Some(key) = key {
        out = out.replace("{key}", key);
    }
    out
}
