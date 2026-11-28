//! The `.env` subset and the JSON arm, and the vocabulary of a refusal.
//!
//! # There is no `.env` specification
//!
//! Measured upstream: dotenvx scores `docker` at 13% on its own cases, and an
//! independent 11-parser, 43-value study found only 12 values all eleven loaders
//! agreed on. Divergence is the absence of a specification, not a bug in one
//! parser.
//!
//! So this module accepts a **named subset** and refuses every construct whose
//! meaning differs between loaders. Each refusal names the construct **and** the
//! accepted form, so an operator can derive the accepted shape from the message
//! rather than by diffing their file against a document.
//!
//! # The accepted subset
//!
//! | Form | Example |
//! |---|---|
//! | Bare key/value, no spaces around `=` | `KEY=value` |
//! | Key shape | `[A-Za-z_][A-Za-z0-9_]*` |
//! | Comment on its own line | `# anything` |
//! | Trailing comment after a space | `KEY=value # note` |
//! | `export` prefix | `export KEY=value` |
//! | Single-quoted literal | `KEY='no $interpolation'` |
//! | Double-quoted with real line breaks | `KEY="line one` / `line two"` |
//!
//! Everything else is refused: `${...}`, backticks, `$(...)`, an unquoted `$`
//! that could interpolate, single-quoted multi-line, spaces around `=`, and a key
//! containing a hyphen.
//!
//! # Refusal is total
//!
//! [`ParseOutcome`] has exactly two arms. There is no partial arm, because one
//! accepted key out of a file with a refused line is the silent partial parse this
//! module exists to prevent.

use std::collections::BTreeMap;
use std::fmt;

/// The format of a source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// A `.env` file, read through the named subset above.
    Env,
    /// A JSON object of string values.
    Json,
}

/// Why one line of a source was refused.
///
/// The two halves are separate fields rather than one sentence because callers
/// differ: a human reads [`Display`], and a test asserts that the construct and
/// the accepted alternative are both present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The line number, 1-based, as an editor shows it.
    line: usize,
    /// The construct that was refused, quoted as it appeared.
    construct: String,
    /// The accepted form that would work instead.
    accepted: String,
}

impl Refusal {
    /// The 1-based line the refusal is about.
    pub fn line(&self) -> usize {
        self.line
    }

    /// The construct that was refused.
    pub fn construct(&self) -> &str {
        &self.construct
    }

    /// The accepted form that would work instead.
    pub fn accepted(&self) -> &str {
        &self.accepted
    }
}

impl fmt::Display for Refusal {
    /// One sentence naming both the construct and the accepted form.
    ///
    /// The sentence is the whole value of this type: a refusal that says only
    /// "unsupported syntax" leaves the operator unable to derive what would work.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {}: {} is not accepted; {}",
            self.line, self.construct, self.accepted
        )
    }
}

/// A parsed source: every key, or every reason it was refused.
///
/// There is deliberately no third arm. A partial map would let a caller import
/// part of a file and report success, which is the failure this type prevents.
#[derive(Debug)]
pub enum ParseOutcome {
    /// Every key in the source, accepted.
    Accepted(BTreeMap<String, String>),
    /// Every reason the source was refused. Nothing was accepted.
    Refused(Vec<Refusal>),
}

/// Parse a source in the given format.
///
/// A refusal is total: on any refused line the whole source is refused, and the
/// returned vector names every line that was wrong rather than only the first, so
/// one pass fixes them all.
pub fn parse(bytes: &[u8], format: FileFormat) -> ParseOutcome {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            return ParseOutcome::Refused(vec![Refusal {
                line: 0,
                construct: "a source that is not valid UTF-8".to_string(),
                accepted: "save the file as UTF-8 without a BOM".to_string(),
            }]);
        }
    };

    match format {
        FileFormat::Env => parse_env(text),
        FileFormat::Json => parse_json(text),
    }
}

/// Parse an `.env` source through the named subset.
fn parse_env(text: &str) -> ParseOutcome {
    // The BOM is stripped before anything else looks at the bytes: left in place
    // it becomes part of the first key's name, which hides that key from every
    // consumer rather than failing.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);

    let mut pairs = BTreeMap::new();
    let mut refusals = Vec::new();

    // A lone `\r` is a corrupt file rather than a CRLF pair, and guessing at its
    // intent is precisely what this parser refuses to do.
    if has_lone_carriage_return(text) {
        return ParseOutcome::Refused(vec![Refusal {
            line: 0,
            construct: "a carriage return that is not part of a CRLF pair".to_string(),
            accepted: "save the file with LF or CRLF line endings, not a lone CR".to_string(),
        }]);
    }

    // The counter is shared with the classifier rather than owned by this loop,
    // because a double-quoted value consumes following lines. Counting only the
    // loop's own iterations reported a bad key on line 2 when it sat on line 4,
    // which sends the operator to a line that is fine.
    let mut line_number = 0usize;
    let mut lines = text.lines().peekable();
    while let Some(raw) = lines.next() {
        line_number += 1;
        if let Err(refusal) = classify_line(&mut line_number, raw, &mut lines, &mut pairs) {
            refusals.push(refusal);
        }
    }

    if refusals.is_empty() {
        ParseOutcome::Accepted(pairs)
    } else {
        ParseOutcome::Refused(refusals)
    }
}

/// Whether the text holds a `\r` that is not immediately followed by `\n`.
fn has_lone_carriage_return(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\r' && bytes.get(index + 1) != Some(&b'\n'))
}

/// Classify one line, pushing a pair or returning the refusal.
///
/// A double-quoted value that does not close on this line consumes following lines
/// until it closes, because every loader agrees that form spans real line breaks.
fn classify_line<'a, I>(
    line_number: &mut usize,
    raw: &str,
    lines: &mut std::iter::Peekable<I>,
    pairs: &mut BTreeMap<String, String>,
) -> Result<(), Refusal>
where
    I: Iterator<Item = &'a str>,
{
    let line = raw.trim_end_matches('\r');
    let current = *line_number;

    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(());
    }

    let body = trimmed
        .strip_prefix("export ")
        .unwrap_or(trimmed)
        .trim_start();

    let Some(equals) = body.find('=') else {
        return Err(Refusal {
            line: current,
            construct: format!("`{}` with no `=`", trimmed),
            accepted: "write it as KEY=value, or start the line with `#` for a comment".to_string(),
        });
    };

    let (raw_key, raw_value) = body.split_at(equals);
    let value_part = &raw_value[1..];

    if raw_key.ends_with(' ') || raw_key.is_empty() {
        return Err(Refusal {
            line: current,
            construct: format!("`{}` with spaces before the `=`", trimmed),
            accepted: "remove the spaces: KEY=value".to_string(),
        });
    }

    if let Some(bad) = key_problem(raw_key) {
        return Err(Refusal {
            line: current,
            construct: format!("the key `{raw_key}` {bad}"),
            accepted: "use letters, digits and underscore only, starting with a letter or \
                       underscore: KEY_NAME=value"
                .to_string(),
        });
    }

    // Any leading whitespace is refused. An earlier version exempted two spaces,
    // which stored them as part of the value: invisible in a report, and not what
    // the operator wrote. The documented subset has no spaces around `=`, so the
    // rule has no exceptions.
    if value_part.starts_with([' ', '\t']) {
        return Err(Refusal {
            line: current,
            construct: format!("`{}` with a space after the `=`", trimmed),
            accepted: "remove the space: KEY=value".to_string(),
        });
    }

    let value = read_value(line_number, raw_key, value_part, lines)?;
    pairs.insert(raw_key.to_string(), value);
    Ok(())
}

/// Why a key is not in the accepted shape, if it is not.
fn key_problem(key: &str) -> Option<&'static str> {
    if key.starts_with(|c: char| c.is_ascii_digit()) {
        return Some("must not start with a digit");
    }
    if key.contains('-') {
        return Some("contains a hyphen, which two loaders skip and two reject");
    }
    if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Some("contains a character that is not a letter, digit or underscore");
    }
    None
}

/// Refuse the constructs a double-quoted value must not carry either.
///
/// Single quotes are the accepted form for a literal dollar sign. Everything
/// that would expand in a loader is refused here, so "quote it" in a refusal
/// means single quotes and never double.
fn quoted_construct(line_number: usize, segment: &str) -> Option<Refusal> {
    let found = if segment.contains('`') {
        Some(("backticks", "four loaders execute backtick content"))
    } else if segment.contains("$(") {
        Some((
            "`$(` command substitution",
            "four loaders run it as a command",
        ))
    } else if segment.contains("${") {
        Some((
            "`${` interpolation",
            "three loaders expand it inside double quotes",
        ))
    } else if segment.contains('$') {
        Some((
            "an unquoted `$`",
            "loaders disagree on whether it interpolates",
        ))
    } else {
        None
    };

    found.map(|(construct, reason)| Refusal {
        line: line_number,
        construct: format!("{construct} inside a double-quoted value"),
        accepted: format!("{reason}; quote the value with single quotes to keep it literal"),
    })
}

/// Read one value, consuming further lines for a double-quoted multi-line value.
fn read_value<'a, I>(
    line_number: &mut usize,
    key: &str,
    raw_value: &str,
    lines: &mut std::iter::Peekable<I>,
) -> Result<String, Refusal>
where
    I: Iterator<Item = &'a str>,
{
    let value_part = raw_value.trim_end();

    let current = *line_number;

    if let Some(rest) = value_part.strip_prefix('\'') {
        return read_single_quoted(current, key, rest);
    }

    if let Some(rest) = value_part.strip_prefix('"') {
        return read_double_quoted(current, rest, lines, line_number);
    }

    read_bare(current, key, value_part)
}

/// A single-quoted value: literal, and refused if it spans lines.
fn read_single_quoted(line_number: usize, key: &str, rest: &str) -> Result<String, Refusal> {
    let Some(close) = rest.find('\'') else {
        return Err(Refusal {
            line: line_number,
            construct: format!("the single-quoted value of `{key}` that never closes"),
            accepted: "close it on the same line, or use double quotes for a value \
                       that spans lines"
                .to_string(),
        });
    };

    let value = &rest[..close];
    let trailing = rest[close + 1..].trim_start();
    if !trailing.is_empty() && !trailing.starts_with('#') {
        return Err(Refusal {
            line: line_number,
            construct: format!("`{trailing}` after the closing quote of `{key}`"),
            accepted: "put the text inside the quotes, or start a comment with a space \
                       and `#`"
                .to_string(),
        });
    }
    Ok(value.to_string())
}

/// A double-quoted value, which may span real line breaks.
fn read_double_quoted<'a, I>(
    line_number: usize,
    rest: &str,
    lines: &mut std::iter::Peekable<I>,
    counter: &mut usize,
) -> Result<String, Refusal>
where
    I: Iterator<Item = &'a str>,
{
    let mut collected = String::new();
    let mut current = rest.to_string();

    loop {
        if let Some(close) = current.find('"') {
            // A double-quoted value is not automatically literal. Two of the
            // loaders this subset is measured against expand `${...}`, `$(...)`
            // and backticks inside double quotes, so accepting them here would
            // seal a value the operator's application never sees. A single-quoted
            // value is the accepted form for a literal `$`.
            let segment = current[..close].to_string();
            if let Some(refusal) = quoted_construct(line_number, &segment) {
                return Err(refusal);
            }
            collected.push_str(&current[..close]);
            let trailing = current[close + 1..].trim_start();
            if !trailing.is_empty() && !trailing.starts_with('#') {
                return Err(Refusal {
                    line: line_number,
                    construct: format!("`{trailing}` after a closing double quote"),
                    accepted: "put the text inside the quotes, or start a comment with a \
                               space and `#`"
                        .to_string(),
                });
            }
            return Ok(collected);
        }

        if let Some(refusal) = quoted_construct(line_number, &current) {
            return Err(refusal);
        }
        collected.push_str(&current);
        match lines.next() {
            Some(next) => {
                // The line was consumed by this value, so the next refusal must
                // count past it.
                *counter += 1;
                collected.push('\n');
                current = next.trim_end_matches('\r').to_string();
            }
            None => {
                return Err(Refusal {
                    line: line_number,
                    construct: "a double-quoted value that never closes".to_string(),
                    accepted: "add the closing `\"`".to_string(),
                });
            }
        }
    }
}

/// An unquoted value: refused if it contains anything that loads differently.
fn read_bare(line_number: usize, key: &str, value_part: &str) -> Result<String, Refusal> {
    if let Some(refusal) = suspicious(line_number, key, value_part)? {
        return Err(refusal);
    }

    // A trailing comment begins after whitespace. `#` with no preceding space is
    // part of the value, which every loader agrees on for a bare value.
    let value = match value_part.find(" #") {
        Some(index) => value_part[..index].trim_end(),
        None => value_part,
    };

    Ok(value.to_string())
}

/// Refuse the constructs whose meaning differs between loaders.
///
/// Returns `Ok(Some(refusal))` for a construct to refuse, `Ok(None)` when the
/// value is plain. The `Result` exists so the signature stays uniform with the
/// quoted readers; a future construct may need to consume more input.
fn suspicious(line_number: usize, key: &str, value: &str) -> Result<Option<Refusal>, Refusal> {
    let refusal = |construct: String, accepted: &str| {
        Ok(Some(Refusal {
            line: line_number,
            construct,
            accepted: accepted.to_string(),
        }))
    };

    if value.contains('`') {
        return refusal(
            format!("backticks in the value of `{key}`"),
            "four loaders execute backtick content; quote the value with single quotes to \
             keep it literal",
        );
    }

    if value.contains("$(") {
        return refusal(
            format!("`$(` command substitution in the value of `{key}`"),
            "four loaders run it as a command; quote the value with single quotes to keep \
             it literal",
        );
    }

    if value.contains("${") {
        return refusal(
            format!("`${{` interpolation in the value of `{key}`"),
            "three loaders expand it and two mangle a `:-` default; quote the value with \
             single quotes to keep it literal",
        );
    }

    if value.contains('$') {
        return refusal(
            format!("an unquoted `$` in the value of `{key}`"),
            "loaders disagree on whether it interpolates; quote the value with single \
             quotes to keep it literal",
        );
    }

    Ok(None)
}

/// Parse a JSON object of string values.
fn parse_json(text: &str) -> ParseOutcome {
    let trimmed = text.trim();
    let bytes = match json_value(trimmed) {
        Ok(bytes) => bytes,
        Err(reason) => {
            return ParseOutcome::Refused(vec![Refusal {
                line: 0,
                construct: format!("the source is not a JSON object: {reason}"),
                accepted: "supply a flat JSON object of string values, such as \
                           {\"KEY\": \"value\"}"
                    .to_string(),
            }]);
        }
    };

    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return ParseOutcome::Refused(vec![Refusal {
            line: 0,
            construct: "the source is not valid JSON".to_string(),
            accepted: "supply a flat JSON object of string values".to_string(),
        }]);
    };

    let Some(object) = value.as_object() else {
        return ParseOutcome::Refused(vec![Refusal {
            line: 0,
            construct: "the top level is not a JSON object".to_string(),
            accepted: "supply a flat JSON object of string values".to_string(),
        }]);
    };

    let mut pairs = BTreeMap::new();
    let mut refusals = Vec::new();
    for (key, value) in object {
        match value.as_str() {
            Some(text) => {
                pairs.insert(key.clone(), text.to_string());
            }
            None => refusals.push(Refusal {
                line: 0,
                construct: format!(
                    "the value of `{key}` is {}, not a string",
                    json_type_name(value)
                ),
                accepted: "every value must be a string; a nested object or a number has no \
                           single value to seal"
                    .to_string(),
            }),
        }
    }

    if refusals.is_empty() {
        ParseOutcome::Accepted(pairs)
    } else {
        ParseOutcome::Refused(refusals)
    }
}

/// Validate that the text is at least shaped like a JSON value.
///
/// The real parse happens in `serde_json`; this exists only so a malformed source
/// reports *why* it looked wrong rather than a library error at a byte offset.
fn json_value(text: &str) -> Result<Vec<u8>, String> {
    if !text.starts_with('{') {
        return Err("it does not start with `{`".to_string());
    }
    if !text.ends_with('}') {
        return Err("it does not end with `}`".to_string());
    }
    Ok(text.as_bytes().to_vec())
}

/// The JSON type name, for a refusal that names what was found.
fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}
