//! The `kind = "http"` invocation arm.
//!
//! # Why this module exists at all (CF-138)
//!
//! Feature 018 shipped `kind = "http"` as a declarable arm and validated it, and
//! then had no way to invoke it: `exec` is an argv chain and nothing in this
//! workspace opened an outbound connection. The arm therefore validated and
//! refused, which made acceptance criterion 2 unreachable. This is the missing
//! half.
//!
//! # What it may and may not do
//!
//! A declaration names a `path` and, optionally, a `credential_env`. That is the
//! whole of it:
//!
//! - **It cannot name a destination.** No vault, no level, no principal, for the
//!   same reason the CLI arm cannot (misfit J).
//! - **It carries no credential value.** `credential_env` is a variable *name*.
//!   The value is read from this process's environment at call time and placed
//!   in a request header. It never enters the declaration, argv, a log, or the
//!   report (misfit F).
//! - **It reaches no shell.** The URL is built from the declared base and path
//!   and handed to an HTTP client, so `;` and `$()` in a selector are bytes.
//!
//! # A redirect is refused, not followed
//!
//! The declared `base_url` is where the operator pointed this adapter. A
//! redirect would move the **credential header** to a host the declaration never
//! named, which is a destination chosen by data — the same defect misfit J exists
//! to close, arriving through the transport instead of through a file.

use std::time::Duration;

/// Why an `http` operation could not be performed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    /// The declaration names no `path` for this operation.
    ///
    /// An `http` declaration is executed by building a request, so a missing
    /// `path` leaves nothing to request. Naming `argv` here would send the
    /// operator to a key this kind of declaration cannot carry.
    #[error(
        "adapter `{adapter}` declares `{operation}` without a `path`, and a `kind = \"http\"` \
         operation is performed by a request rather than by an argv: add `path = \"/...\"` to \
         `[ops.{operation}]`, for example `path = \"/items\"`"
    )]
    NoPath {
        /// The declaration's name.
        adapter: String,
        /// The operation that has no path.
        operation: String,
    },

    /// The declaration names no `base_url`, so there is no host to request.
    ///
    /// `validate` refuses such a declaration, so this arm is the run path
    /// declining to build a request from an empty string rather than trusting a
    /// check made somewhere else. An empty base URL would otherwise become a
    /// request to a relative path, and the client's error would name the
    /// transport instead of the declaration.
    #[error(
        "adapter `{adapter}` declares `kind = \"http\"` with no `base_url`, so there is no host to \
         request: add `base_url = \"https://...\"` beside `kind`"
    )]
    NoBaseUrl {
        /// The declaration's name.
        adapter: String,
    },

    /// The endpoint redirected, and this build refuses to follow one.
    ///
    /// A redirect would move the credential header to a host the declaration
    /// never named, so it is refused rather than followed (see the module docs).
    /// The status is named because the alternative — letting the empty 3xx body
    /// reach the shape check — reports "the adapter produced no output", which
    /// sends the operator to look for a broken declaration instead of a redirect.
    #[error(
        "adapter `{adapter}` answered `{url}` with HTTP {status}, a redirect. This build does not \
         follow one: doing so would carry the credential header to a host the declaration does \
         not name. Point `base_url` at the endpoint the redirect leads to, or at the manager's \
         API host, and re-run the import"
    )]
    Redirected {
        /// The declaration's name.
        adapter: String,
        /// The URL that redirected.
        url: String,
        /// The 3xx status.
        status: u16,
    },

    /// The request did not complete.
    #[error(
        "adapter `{adapter}` could not reach `{url}`: {cause}. The declaration's `base_url` names \
         the endpoint, and `ksp import --list-adapters` prints what this host has declared"
    )]
    Unreachable {
        /// The declaration's name.
        adapter: String,
        /// The URL that was attempted.
        url: String,
        /// The transport's own description.
        cause: String,
    },

    /// The endpoint answered with a status that is not a success.
    ///
    /// The status is reported rather than the body: a manager's error body can
    /// echo the request, and the request can carry a credential header.
    #[error(
        "adapter `{adapter}` was refused by `{url}` with HTTP {status}. A 401 or 403 usually means \
         the credential named by `credential_env` is missing, expired or lacks scope; \
         `ksp import --list-adapters` names the variable this declaration reads"
    )]
    Status {
        /// The declaration's name.
        adapter: String,
        /// The URL that was refused.
        url: String,
        /// The status code.
        status: u16,
    },

    /// The response was not text this process can read.
    #[error(
        "adapter `{adapter}` answered with a body that is not valid UTF-8, so no declared shape can \
         be checked against it"
    )]
    NotUtf8 {
        /// The declaration's name.
        adapter: String,
    },
}

/// Perform one `GET` for a declaration.
///
/// `base_url` and `path` are joined by the caller so the joining rule lives in
/// one place. `credential` is the value of the variable `credential_env` names,
/// already read from the environment; `None` sends no header at all rather than
/// an empty one, because a manager that receives `Authorization:` with nothing
/// after it reports a malformed request instead of a missing credential.
///
/// The timeout is stated here rather than defaulted by the client: a hung
/// manager would otherwise hold an import open indefinitely, and an operator
/// would be left with a command that neither succeeds nor fails.
pub fn get(adapter: &str, url: &str, credential: Option<&str>) -> Result<String, HttpError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        // A redirect would carry the credential header to a host the
        // declaration never named. See the module docs.
        .max_redirects(0)
        .build()
        .into();

    let mut request = agent.get(url);
    if let Some(credential) = credential {
        // Sent as a bearer token because that is the shape every manager's API
        // documented here accepts. A manager needing a different header needs a
        // new field in the declaration rather than a guess made at this line.
        request = request.header("Authorization", &format!("Bearer {credential}"));
    }

    let mut response = match request.call() {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(status)) => {
            return Err(HttpError::Status {
                adapter: adapter.to_string(),
                url: url.to_string(),
                status,
            });
        }
        Err(error) => {
            return Err(HttpError::Unreachable {
                adapter: adapter.to_string(),
                url: url.to_string(),
                cause: error.to_string(),
            });
        }
    };

    // A 3xx reaches here as a **successful** response when redirects are
    // disabled: the client is told "do not follow", not "refuse". Without this
    // check the empty 3xx body falls through to the shape check, which reports
    // "the adapter produced no output" — a sentence that sends the operator to
    // look for a broken declaration rather than a redirect.
    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        return Err(HttpError::Redirected {
            adapter: adapter.to_string(),
            url: url.to_string(),
            status,
        });
    }

    // Read as bytes and decode here, so a non-UTF-8 body is a typed refusal that
    // names the adapter rather than a panic or a lossy conversion that would
    // silently change a value before it is sealed.
    let body = response
        .body_mut()
        .read_to_vec()
        .map_err(|error| HttpError::Unreachable {
            adapter: adapter.to_string(),
            url: url.to_string(),
            cause: error.to_string(),
        })?;

    String::from_utf8(body).map_err(|_| HttpError::NotUtf8 {
        adapter: adapter.to_string(),
    })
}

/// Join a declaration's `base_url` and an operation's `path`.
///
/// Exactly one `/` between them, whatever the operator wrote. A doubled slash is
/// not a URL error: most servers accept it, and the ones that do not answer 404,
/// which reads as "your item is missing" rather than "your base_url has a
/// trailing slash".
pub fn join(base_url: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

/// Append the selector as a query parameter, when there is one.
///
/// The selector is percent-encoded: it is operator-supplied text going into a
/// URL, and a selector containing `&` would otherwise add a parameter the
/// declaration never named.
pub fn with_selector(url: &str, parameter: &str, selector: Option<&str>) -> String {
    let Some(selector) = selector else {
        return url.to_string();
    };
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}{parameter}={}", encode(selector))
}

/// Percent-encode everything outside the unreserved set.
///
/// Written out rather than pulled from a crate: the unreserved set is 66
/// characters, and a dependency for it would add a transitive tree to a
/// dependency-light workspace for a function this short.
pub fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
