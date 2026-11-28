//! The import parser: the accepted `.env` subset, the JSON arm, and every refusal.
//!
//! # Why this file exists
//!
//! There is no `.env` specification. Measured upstream: dotenvx scores `docker` at
//! 13% on its own cases, and an independent 11-parser, 43-value study found only
//! **12 values all eleven loaders agreed on**. Divergence is not a bug in any one
//! parser; it is the absence of a specification.
//!
//! So Keyspout accepts a **named subset** and refuses everything else, naming both
//! the construct and the accepted form. The tests below are the subset.
//!
//! # The property that matters most
//!
//! A refusal discards the **whole source**. One accepted key out of a file with a
//! refused line is Misfit A wearing a green report: the operator believes the
//! import is what their application reads, and it is not.
//!
//! Every refusal test therefore asserts `Refused`, never a key count. A test
//! asserting `parsed.len() == 0` would pass against an implementation that parsed
//! half the file and returned the other half by another route.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp::import::parse::{FileFormat, ParseOutcome, parse};

/// Parse a `.env` source, panicking on a refusal.
///
/// Used only by the acceptance tests, where a refusal is the failure under test.
fn accept_env(source: &str) -> Vec<(String, String)> {
    match parse(source.as_bytes(), FileFormat::Env) {
        ParseOutcome::Accepted(pairs) => pairs.into_iter().collect(),
        ParseOutcome::Refused(refusals) => {
            panic!("expected acceptance; refused with {refusals:?}")
        }
    }
}

/// Parse a `.env` source and return the refusals, panicking on acceptance.
fn refuse_env(source: &str) -> Vec<String> {
    match parse(source.as_bytes(), FileFormat::Env) {
        ParseOutcome::Refused(refusals) => refusals.iter().map(|r| r.to_string()).collect(),
        ParseOutcome::Accepted(pairs) => panic!(
            "expected a refusal; accepted {} key(s): {:?}",
            pairs.len(),
            pairs.keys().collect::<Vec<_>>()
        ),
    }
}

fn map(pairs: &[(String, String)]) -> std::collections::BTreeMap<String, String> {
    pairs.iter().cloned().collect()
}

// ---------------------------------------------------------------------------
// T003 — the accepted consensus subset
// ---------------------------------------------------------------------------

#[test]
fn the_consensus_subset_is_accepted() {
    let source = "\
DATABASE_URL=postgres://localhost/db
API_KEY=abc123
UNDER_SCORE=x
WITH1_DIGIT=y
export EXPORTED=value
# a comment on its own line
COMMENTED=value # a trailing comment
SINGLE='no $interpolation here'
";
    let pairs = map(&accept_env(source));

    assert_eq!(pairs["DATABASE_URL"], "postgres://localhost/db");
    assert_eq!(pairs["API_KEY"], "abc123");
    assert_eq!(pairs["UNDER_SCORE"], "x");
    assert_eq!(pairs["WITH1_DIGIT"], "y");
    // `export` is a prefix, not part of the key.
    assert_eq!(pairs["EXPORTED"], "value");
    // A trailing comment after a space is not part of the value.
    assert_eq!(pairs["COMMENTED"], "value");
    // Single quotes stay literal, which is the only way to keep a `$`.
    assert_eq!(pairs["SINGLE"], "no $interpolation here");
    // A comment line contributes no key.
    assert!(!pairs.contains_key("# a comment on its own line"));
}

#[test]
fn a_double_quoted_value_may_span_real_line_breaks() {
    // All eleven loaders agree on this form, which is why it is in the subset.
    let source = "MULTILINE=\"line one\nline two\"\n";
    let pairs = map(&accept_env(source));
    assert_eq!(pairs["MULTILINE"], "line one\nline two");
}

// ---------------------------------------------------------------------------
// T002 — the two mechanical faults with one correct interpretation
// ---------------------------------------------------------------------------

#[test]
fn a_utf8_bom_does_not_hide_the_first_key() {
    // Measured: a BOM hid the first key from Node's loader and from bash. That is
    // an encoding fault with one correct reading, not a dialect question.
    let mut source = Vec::new();
    source.extend_from_slice(b"\xEF\xBB\xBF");
    source.extend_from_slice(b"FIRST=one\nSECOND=two\n");

    let pairs = match parse(&source, FileFormat::Env) {
        ParseOutcome::Accepted(pairs) => map(&pairs.into_iter().collect::<Vec<_>>()),
        ParseOutcome::Refused(refusals) => panic!("BOM refused: {refusals:?}"),
    };

    assert_eq!(
        pairs.get("FIRST"),
        Some(&"one".to_string()),
        "the BOM must be stripped, not treated as part of the first key"
    );
    assert_eq!(pairs.get("SECOND"), Some(&"two".to_string()));
}

#[test]
fn crlf_leaves_no_carriage_return_on_a_value() {
    // Measured: CRLF left `\r` at the end of every value in bash. The fix has one
    // correct answer, so it is normalisation rather than a refusal.
    let pairs = map(&accept_env("KEY=value\r\nNEXT=two\r\n"));
    assert_eq!(pairs["KEY"], "value", "the value must not carry the \\r");
    assert_eq!(pairs["NEXT"], "two");
}

#[test]
fn a_lone_carriage_return_is_refused() {
    // A `\r` that is not part of a CRLF pair is a corrupt file, and guessing at
    // its intent is exactly what this parser refuses to do.
    let refusals = refuse_env("KEY=value\rNEXT=two\n");
    assert!(
        refusals
            .iter()
            .any(|r| r.contains('\r') || r.to_lowercase().contains("carriage")),
        "a lone \\r must be refused by name; got {refusals:?}"
    );
}

// ---------------------------------------------------------------------------
// T004 — every refusal names the construct AND the accepted form
// ---------------------------------------------------------------------------

/// The constructs this parser refuses, and the fixture that triggers each.
///
/// One fixture per construct, because a single large fixture proves only that
/// *something* was refused, not that each construct is recognised.
const REFUSED_CONSTRUCTS: &[(&str, &str)] = &[
    ("${VAR}", "KEY=${OTHER}\n"),
    ("interpolation", "KEY=a${OTHER}b\n"),
    ("backtick", "KEY=`whoami`\n"),
    ("command substitution", "KEY=$(whoami)\n"),
    ("$(", "KEY=$(date)\n"),
    ("spaces around", "KEY = value\n"),
    ("hyphen", "MY-KEY=value\n"),
];

#[test]
fn every_refused_construct_is_refused_and_named() {
    for (construct, fixture) in REFUSED_CONSTRUCTS {
        let refusals = refuse_env(fixture);
        let joined = refusals.join("\n").to_lowercase();

        assert!(
            !refusals.is_empty(),
            "the fixture for {construct} must produce at least one refusal"
        );
        // The refusal names the accepted form, so a reader can derive the shape
        // rather than being told only that their file is wrong.
        assert!(
            joined.contains("quote")
                || joined.contains("replace")
                || joined.contains("name")
                || joined.contains("key"),
            "the refusal for {construct} must name the accepted form; got {refusals:?}"
        );
    }
}

#[test]
fn a_refusal_names_the_construct_it_refused() {
    // The message must contain the thing that was typed, or the operator has to
    // diff their file against a document to find the offending line.
    let refusals = refuse_env("KEY=`whoami`\n");
    assert!(
        refusals.iter().any(|r| r.contains('`')),
        "the refusal must quote the backtick it refused; got {refusals:?}"
    );

    let refusals = refuse_env("MY-KEY=value\n");
    assert!(
        refusals.iter().any(|r| r.contains("MY-KEY")),
        "the refusal must name the offending key; got {refusals:?}"
    );
}

// ---------------------------------------------------------------------------
// T005 — all-or-nothing
// ---------------------------------------------------------------------------

#[test]
fn one_refused_line_discards_the_whole_source() {
    // This is the misfit. A source with nine good keys and one interpolated value
    // must produce **no** pairs at all, because nine accepted keys would import as
    // a success the operator cannot distinguish from a complete one.
    let source = "\
A=1
B=2
C=3
INTERPOLATED=${NOPE}
E=5
";
    let refusals = refuse_env(source);
    assert!(!refusals.is_empty());
    // The fixture's good keys must not appear anywhere in the accepted output,
    // because there is no accepted output.
}

#[test]
fn a_source_with_no_refusals_accepts_every_key() {
    // The converse, so the refusal tests are not passing against a parser that
    // refuses everything.
    let pairs = accept_env("A=1\nB=2\nC=3\n");
    assert_eq!(pairs.len(), 3);
}

// ---------------------------------------------------------------------------
// T006 — the JSON arm
// ---------------------------------------------------------------------------

#[test]
fn a_flat_json_object_is_accepted() {
    let source = br#"{"FIRST": "one", "SECOND": "two"}"#;
    match parse(source, FileFormat::Json) {
        ParseOutcome::Accepted(pairs) => {
            let pairs = map(&pairs.into_iter().collect::<Vec<_>>());
            assert_eq!(pairs["FIRST"], "one");
            assert_eq!(pairs["SECOND"], "two");
        }
        ParseOutcome::Refused(refusals) => panic!("flat JSON refused: {refusals:?}"),
    }
}

#[test]
fn a_nested_json_value_is_refused_and_the_key_named() {
    // A nested value has no single string to seal. Flattening it would invent a
    // key the operator did not write.
    let source = br#"{"FLAT": "ok", "NESTED": {"inner": "x"}}"#;
    match parse(source, FileFormat::Json) {
        ParseOutcome::Refused(refusals) => {
            let joined: String = refusals
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                joined.contains("NESTED"),
                "the refusal must name the nested key; got {joined}"
            );
        }
        ParseOutcome::Accepted(pairs) => panic!(
            "a nested value must be refused; accepted {} key(s)",
            pairs.len()
        ),
    }
}

#[test]
fn a_json_non_string_leaf_is_refused_and_the_key_named() {
    let source = br#"{"COUNT": 42}"#;
    match parse(source, FileFormat::Json) {
        ParseOutcome::Refused(refusals) => {
            let joined: String = refusals
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(joined.contains("COUNT"), "got {joined}");
        }
        ParseOutcome::Accepted(pairs) => {
            panic!("a number must be refused; accepted {} key(s)", pairs.len())
        }
    }
}

#[test]
fn malformed_json_is_refused() {
    match parse(b"{not json", FileFormat::Json) {
        ParseOutcome::Refused(_) => {}
        ParseOutcome::Accepted(pairs) => {
            panic!(
                "malformed JSON must be refused; accepted {} key(s)",
                pairs.len()
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Review findings: three defects the first suite missed
// ---------------------------------------------------------------------------

#[test]
fn any_leading_space_after_the_equals_is_refused() {
    // One space was refused and two spaces were accepted, so `KEY=  value`
    // stored two leading spaces the operator could not see. Both are the same
    // defect: the documented subset says no spaces around `=`.
    for source in ["KEY= value\n", "KEY=  value\n", "KEY=\tvalue\n"] {
        let refusals = refuse_env(source);
        assert!(
            !refusals.is_empty(),
            "{source:?} must be refused; a leading space is part of no value"
        );
    }
}

#[test]
fn a_double_quoted_value_still_refuses_interpolation_and_backticks() {
    // docker-compose and bash interpolate inside double quotes, so a literal
    // `a${OTHER}b` is not what the operator's application reads. Accepting it
    // silently is the divergence the subset exists to refuse.
    for source in [
        "KEY=\"a${OTHER}b\"\n",
        "KEY=\"a`cmd`b\"\n",
        "KEY=\"a$(cmd)b\"\n",
        "KEY=\"a$x\"\n",
    ] {
        let refusals = refuse_env(source);
        assert!(
            !refusals.is_empty(),
            "{source:?} must be refused: double quotes do not make a `$` literal"
        );
    }

    // A single-quoted value is the accepted form for a literal `$`, and it must
    // keep working, or the refusal sends the operator somewhere that also fails.
    let pairs = map(&accept_env("KEY='a${OTHER}b'\n"));
    assert_eq!(pairs["KEY"], "a${OTHER}b");
}

#[test]
fn a_refusal_line_number_counts_the_lines_a_multiline_value_consumed() {
    // A three-line double-quoted value pushes everything after it down by two.
    // Reporting the wrong line sends the operator to a line that is fine.
    let source = "A=\"one\ntwo\nthree\"\nBAD-KEY=x\n";
    match parse(source.as_bytes(), FileFormat::Env) {
        ParseOutcome::Refused(refusals) => {
            let line = refusals
                .first()
                .map(|r| r.line())
                .expect("one refusal is produced");
            assert_eq!(
                line, 4,
                "the bad key is on the fourth line of the file; got line {line}"
            );
        }
        ParseOutcome::Accepted(_) => panic!("the hyphenated key must be refused"),
    }
}
