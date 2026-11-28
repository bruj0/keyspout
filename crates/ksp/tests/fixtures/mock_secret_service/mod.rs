//! An in-process secret service, for the end-to-end import test.
//!
//! # Why a server rather than a fixture file
//!
//! The `http` arm of a declaration names an endpoint. Proving that arm works —
//! rather than proving a JSON file parses — needs something that answers a
//! request over a socket. This is that thing: a loopback listener serving a fixed
//! shape, with a switch that makes it serve the **wrong** shape so the shape
//! refusal is testable against a real response rather than a hand-built string.
//!
//! # Design constraints, each from a failure it prevents
//!
//! - **A test fixture, never a runtime dependency.** It lives under `tests/`, so
//!   it cannot be reached from the binary's non-test code. Nothing in `src/`
//!   knows it exists.
//! - **An ephemeral port.** Binding `127.0.0.1:0` and reporting what the operating
//!   system chose means two test runs in parallel never collide, and a developer
//!   with something on a fixed port is not given a failure that is not theirs.
//! - **Stops cleanly.** The listener is dropped when the guard is, and
//!   [`MockService::port`] is the only way to learn where to send a request, so a
//!   test cannot hold a port by accident: it holds the value, not the socket.
//! - **It records what it received.** The end-to-end test asserts the mock saw the
//!   selector the declaration substituted, which is how a marshalling bug shows up
//!   as a test failure rather than as a passing import of the wrong thing.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// What the service should serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The declared shape: a JSON object of items.
    Correct,
    /// A shape the declaration does not name, so the shape check must refuse.
    WrongShape,
    /// A redirect to another host, so the client's refusal to follow one can be
    /// proven. The target is deliberately a host the declaration never named:
    /// following it would carry the credential header there, which is the defect
    /// the refusal exists to prevent.
    Redirect,
}

/// One request the service received, for assertions about what was actually sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The request line, verbatim: method, path and query.
    pub line: String,
}

/// A listener on a loopback ephemeral port, serving a fixed shape.
pub struct MockService {
    port: u16,
    shutdown: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<Request>>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl MockService {
    /// Start a service on an ephemeral port.
    ///
    /// Returns once the listener is bound, so the port in the returned value is
    /// already listening: a test that started a thread first would race its own
    /// first request.
    pub fn start(mode: Mode) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));

        let handle = {
            let shutdown = Arc::clone(&shutdown);
            let requests = Arc::clone(&requests);
            std::thread::spawn(move || {
                while !shutdown.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let _ = serve(stream, mode, &requests);
                        }
                        // A non-blocking listener returns `WouldBlock` between
                        // connections. Sleeping briefly keeps the loop from
                        // spinning a core while the test does its own work.
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        Ok(Self {
            port,
            shutdown,
            requests,
            handle: Some(handle),
        })
    }

    /// The port the operating system chose.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The base URL a declaration would name.
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Every request received so far.
    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

impl Drop for MockService {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            // Joined rather than detached: a detached thread outlives the test and
            // the port stays bound for whatever runs next, which is the "no test
            // leaves a listener behind" failure the acceptance criterion names.
            let _ = handle.join();
        }
    }
}

/// Answer one connection and close it.
fn serve(
    mut stream: TcpStream,
    mode: Mode,
    requests: &Arc<Mutex<Vec<Request>>>,
) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    let mut reader = BufReader::new(stream.try_clone()?);

    // The request line is all this service needs, and reading exactly it avoids
    // waiting for a body a GET does not send.
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    if let Ok(mut recorded) = requests.lock() {
        recorded.push(Request {
            line: request_line.trim_end().to_string(),
        });
    }

    // A redirect answers with a `Location` and no body, before any JSON is
    // considered: the client must refuse it rather than fetch the target.
    if mode == Mode::Redirect {
        let response = "HTTP/1.1 307 Temporary Redirect\r\nLocation: \
                        http://169.254.169.254/latest/meta-data/\r\n\
                        Content-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes())?;
        return stream.flush();
    }

    let body = match mode {
        Mode::Correct => r#"{"items":[{"id":"k1","value":"alpha"},{"id":"k2","value":"beta"}]}"#,
        // A table, which is what a manager that changed its output might print. The
        // declaration names `json`, so this must be refused before any value is
        // read.
        Mode::WrongShape => "ID   VALUE\nk1   alpha\n",
        // Handled above, before any body is chosen.
        Mode::Redirect => unreachable!("a redirect answers before a body is selected"),
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

/// A declaration that points at a running service.
///
/// Beside the service rather than in the test, so the end-to-end test and the
/// shape test use one document and cannot disagree about what an `http` adapter
/// looks like.
pub fn http_declaration(name: &str, base_url: &str) -> String {
    format!(
        r#"name = "{name}"
kind = "http"
base_url = "{base_url}"
credential_env = "MOCK_TOKEN"

[ops.list]
path = "/items"
"#
    )
}
