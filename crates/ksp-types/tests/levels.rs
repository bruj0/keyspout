//! The four level words, and the one that is not a delivery target.
//!
//! A level's `path_segment()` is interpolated into a record path and bound into
//! the AAD, so the set of accepted spellings is a wire decision: a fifth word, or
//! a case variant of a fourth, is a different path rather than a cosmetic
//! difference.
//!
//! A test reports a failure by panicking, and the panic message is what says why.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ksp_types::Level;

#[test]
fn the_publication_level_is_its_own_path_segment() {
    assert_eq!(Level::Granted.path_segment(), "granted");
    assert_eq!(Level::parse("granted").unwrap(), Level::Granted);

    // The three words that existed before are unchanged, so a record written by
    // an earlier build still parses.
    assert_eq!(Level::parse("admin").unwrap(), Level::Admin);
    assert_eq!(Level::parse("user").unwrap(), Level::User);
    assert_eq!(
        Level::parse("agent-00000000-0000-4000-8000-000000000007").unwrap(),
        Level::Agent(ksp_types::AgentId::parse("00000000-0000-4000-8000-000000000007").unwrap())
    );

    // The spelling is exact: a case variant and a padded word are not levels.
    for refused in ["Granted", "GRANTED", "granted ", " granted", "granteds"] {
        assert!(
            Level::parse(refused).is_err(),
            "{refused:?} is not a level segment"
        );
    }

    // A refusal a reader can act on names every accepted spelling, which is what
    // the fourth word made necessary.
    let message = Level::parse("shared").unwrap_err().to_string();
    for accepted in ["admin", "user", "granted", "agent-"] {
        assert!(
            message.contains(accepted),
            "the refusal names {accepted}: {message}"
        );
    }
}

#[test]
fn a_publication_level_never_parses_from_an_agent_segment() {
    // `agent-granted` is not an agent identity and is not the publication level
    // either: the two namespaces do not overlap.
    assert!(Level::parse("agent-granted").is_err());
    assert_ne!(Level::Granted.path_segment(), "agent-granted");
}
