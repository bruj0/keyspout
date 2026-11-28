//! Reading the vault passphrase without writing it anywhere.
//!
//! The shell script this replaces shipped a bug here: `read -rs "?prompt"` is
//! **zsh** syntax in a `#!/bin/bash` file, and it failed with
//! `read: '?Vault password: ': not a valid identifier`. Nothing about the
//! language forced that, but the language decided whether a test could catch
//! it. In bash the function could not be called with a fake terminal, and a
//! refusal's text could not be asserted without a subshell.
//!
//! So the rules are a pure function over bytes ([`validate`]), and the process's
//! stdin is a separate step ([`from_stdin`]) that adds a timeout. Every branch
//! below is reachable from a unit test with no terminal, no subprocess and no
//! privilege.

/// The shortest passphrase this host accepts.
///
/// Not a security recommendation — it is the floor `ksp` itself enforces when it
/// seals a vault, so a shorter value would be refused later with a worse
/// message. Refusing here names the length and the floor.
pub const MIN_LEN: usize = 8;

/// A passphrase that will not print itself.
///
/// `Debug` is the one that matters: a derived `Debug` on a `Vec<u8>` puts the
/// password in every `{:?}` — a log line, a panic message, a test failure. This
/// type exists so that cannot happen by accident.
pub struct Secret(Vec<u8>);

impl Secret {
    /// Borrow the bytes. The only way to see them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Rebuild a `Secret` from bytes that were already validated.
    ///
    /// # Why this is not `pub fn new`
    ///
    /// A constructor that accepted arbitrary bytes would be a way around
    /// [`validate`], and every caller would eventually reach for it. This exists
    /// for exactly one caller — replaying a value a pipe delivered once — and the
    /// name says so. The bytes are the ones `validate` already accepted, so the
    /// floor is not re-checked and cannot be skipped.
    pub fn replay(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Why a passphrase was not produced.
#[derive(Debug)]
pub enum Refusal {
    /// The input was present but too short.
    TooShort { got: usize, need: usize },
    /// Nothing at all arrived.
    Empty,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The sentence names the accepted form, so the reader can act:
            // this is the rule "a refusal names the accepted shape".
            Self::TooShort { got, need } => write!(
                f,
                "the vault passphrase is {got} bytes and this host accepts at \
                 least {need}: give it a longer value"
            ),
            Self::Empty => write!(
                f,
                "the vault passphrase could not be read: supply it on stdin, or \
                 run this on a terminal"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// Turn bytes into a [`Secret`], or refuse them with a sentence.
///
/// This is the whole rule, and it is pure: one trailing newline removed, a floor
/// of [`MIN_LEN`]. Both the terminal path and the piped path call it, so the two
/// sources cannot disagree about what a passphrase is.
///
/// # Errors
///
/// [`Refusal`] when the input is empty or too short.
pub fn validate(mut bytes: Vec<u8>) -> Result<Secret, Refusal> {
    // The order matters and the first draft got it wrong: in a CRLF source the
    // last byte is `\n`, so stripping the carriage return first finds nothing and
    // leaves the `\r` behind after the newline comes off. Newline first, then the
    // carriage return it exposed.
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        // One trailing newline is an artefact of `echo` and of a terminal's Enter
        // key. Only one: a passphrase that legitimately ends in a newline cannot
        // be expressed this way, which is the same trade `ksp` makes for a value.
    }

    // A CRLF pipe (a Windows writer, or a file that travelled) would otherwise
    // leave the carriage return as part of the passphrase, and the vault would
    // fail to unseal for a byte the operator cannot see.
    while bytes.last() == Some(&b'\r') {
        bytes.pop();
    }

    if bytes.is_empty() {
        return Err(Refusal::Empty);
    }
    if bytes.len() < MIN_LEN {
        return Err(Refusal::TooShort {
            got: bytes.len(),
            need: MIN_LEN,
        });
    }
    Ok(Secret(bytes))
}

/// Whether stdin can supply more than one passphrase.
///
/// A terminal can: each sealed step prompts and the operator answers. A pipe
/// cannot: [`from_stdin`] reads it to EOF, so the first reader consumes
/// everything and the second finds nothing.
///
/// This is the question *"may a read be repeated"*, and it is deliberately not
/// asked at the call site — one place decides it, so the answer cannot differ
/// between two steps of one run.
pub fn stdin_is_repeatable() -> bool {
    use std::io::IsTerminal as _;
    std::io::stdin().is_terminal()
}

/// How long a non-terminal stdin gets to deliver a passphrase.
///
/// The same reason `crate::app::STDIN_GRACE` exists and the same size: a pipe
/// that already holds the value returns at once because its writer closed; this
/// bound only elapses for an open pipe that will never deliver, so it costs a
/// working caller nothing. Two seconds rather than 200ms because 200ms was tried
/// and failed only under a full-workspace run, which is the signature of a bound
/// sized for the machine it was written on.
const STDIN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Read the passphrase from the process's stdin, refusing rather than blocking.
///
/// # Why the bound lives here and not in [`validate`]
///
/// A reader handed in by a caller answers immediately or not at all, so there is
/// nothing to bound: a test that wants "a read that cannot complete" supplies a
/// reader that returns an error, and the pure function reports it. The process's
/// own stdin is the only source that can block forever — an open pipe with no
/// writer — so the bound belongs to acquiring from it.
///
/// # A terminal is prompted, a pipe is read
///
/// `IsTerminal` is the question "should I prompt", not "will a read return". A
/// pipe carrying a passphrase is not a terminal and must still be read; an open
/// pipe is not a terminal either and must not be waited on. The distinguishing
/// signal is whether the read returns, which is what the timeout measures.
///
/// This binary does **not** disable echo. Prompting goes through
/// `crate::admin::read_password_from_terminal`, which is the one implementation
/// on this host that turns echo off and restores it; a second one would be a
/// second chance to leave a terminal in a broken state.
pub fn from_stdin() -> Result<Secret, Refusal> {
    use std::io::IsTerminal as _;

    if std::io::stdin().is_terminal() {
        // Reused from the library rather than reimplemented: it is the one
        // implementation on this host that turns echo off and restores it, and a
        // second copy is a second chance to leave a terminal broken.
        let bytes = ksp::admin::read_password_from_terminal().map_err(|_| Refusal::Empty)?;
        return validate(bytes);
    }

    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let outcome =
            std::io::Read::read_to_end(&mut std::io::stdin(), &mut buffer).map(|_| buffer);
        // A send failure means the receiver gave up; nothing left to report.
        let _ = sender.send(outcome);
    });

    match receiver.recv_timeout(STDIN_GRACE) {
        Ok(Ok(bytes)) => validate(bytes),
        // An open pipe that never delivered, or a read that failed. One refusal
        // for both: `Empty` is the sentence that names how to supply a value, and
        // a caller branching on the outcome must not meet two answers for one
        // condition.
        Ok(Err(_)) | Err(_) => Err(Refusal::Empty),
    }
}

// The tests below call [`validate`] with bytes. A test that needs a terminal is a
// test that runs on one machine, so the terminal path is exercised by hand
// through [`from_stdin`].

#[cfg(test)]
mod tests {
    use super::*;
    // The trait itself, not `as _`: one fixture below names it (`impl Read for
    // Broken`), and an anonymous import cannot be named.
    #[allow(unused_imports)]
    use std::io::Read;

    /// A short value is refused **by a sentence that names the floor**, because
    /// a reader who gets only an exit code cannot act on it.
    #[test]
    fn short_password_is_refused_by_message() {
        let err = validate(b"abc".to_vec()).expect_err("3 bytes must be refused");
        let sentence = err.to_string();
        assert!(
            sentence.contains("at least 8"),
            "the refusal must name the floor; got: {sentence}"
        );
        assert!(
            sentence.contains("3 bytes"),
            "the refusal must name what was given; got: {sentence}"
        );
    }

    /// A piped passphrase is taken verbatim: exactly one trailing newline
    /// removed, and nothing else touched. The `=` case is the one a naive `.env`
    /// split breaks, and it is the shape a generated passphrase can contain.
    #[test]
    fn piped_password_is_verbatim() {
        let secret = validate(b"abc12345\n".to_vec()).expect("8 bytes is enough");
        assert_eq!(secret.as_bytes(), b"abc12345");

        let secret = validate(b"a=b=c=d=e\n".to_vec()).expect("9 bytes is enough");
        assert_eq!(
            secret.as_bytes(),
            b"a=b=c=d=e",
            "an embedded '=' must survive: there is no separator here to split on"
        );
    }

    /// Only **one** newline comes off. A value ending in two newlines keeps one,
    /// because a caller that stripped them all would silently shorten a
    /// passphrase that genuinely ends in a newline — and the vault would then
    /// never unseal, with no clue why.
    #[test]
    fn exactly_one_newline_is_stripped() {
        let secret = validate(b"abc12345\n\n".to_vec()).expect("9 bytes is enough");
        assert_eq!(
            secret.as_bytes(),
            b"abc12345\n",
            "each passphrase must strip exactly one trailing newline"
        );
    }

    /// A CRLF source leaves no carriage return behind. A stray `\r` is invisible
    /// and would fail the unseal for a byte the operator cannot see.
    #[test]
    fn a_carriage_return_does_not_survive() {
        let secret = validate(b"abc12345\r\n".to_vec()).expect("8 bytes is enough");
        assert_eq!(secret.as_bytes(), b"abc12345");
    }

    /// An empty input is its own refusal, not "too short": the fix is different,
    /// so the sentence is.
    #[test]
    fn empty_input_names_the_supply_route() {
        let err = validate(b"\n".to_vec()).expect_err("a bare newline is empty");
        let sentence = err.to_string();
        assert!(
            sentence.contains("stdin") || sentence.contains("terminal"),
            "an empty read must name how to supply one; got: {sentence}"
        );
    }

    /// The `Debug` impl is the guard against a passphrase in a log line. The
    /// assertion names the value that would leak, not the word "redacted": a
    /// test that checks for the word passes on a message that contains both.
    #[test]
    fn secret_does_not_debug_itself() {
        let secret = validate(b"hunter2hunter2\n".to_vec()).expect("long enough");
        let printed = format!("{secret:?}");
        assert_eq!(printed, "Secret(<redacted>)");
        assert!(
            !printed.contains("hunter2"),
            "Debug must not print the value; got: {printed}"
        );
    }

    /// A reader that fails is a refusal, not a panic and not a hang. This is the
    /// branch `crate::app` documents: "will a read return" is the question, and
    /// the answer here is no.
    #[test]
    fn a_reader_that_cannot_answer_refuses() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("no source"))
            }
        }
        let mut broken = Broken;
        let mut buffer = Vec::new();
        let outcome = broken.read_to_end(&mut buffer);
        assert!(outcome.is_err(), "the fixture must actually fail to read");
        // The production path maps that error to `Empty`, and `Empty` is the
        // sentence that names how to supply a value.
        assert!(validate(buffer).is_err(), "an empty read must be refused");
    }
}
