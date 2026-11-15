//! The `ksp agent` group: enrol, publish the public halves, rotate.
//!
//! # Where the private halves go
//!
//! `enroll` generates both keypairs and hands them to S6 (WP15), which writes the
//! protected `agent/<id>.key`. Nothing here holds a private half after that
//! call returns: this module never sees the bytes, only the typed bundle S2
//! publishes.
//!
//! # What is printed
//!
//! The fingerprint and the public halves. A fingerprint is what the operator
//! compares out of band, so it has to be printable; it is a digest, not a key.
//! `pubkey` reads the stored enrolment and never opens the key file.

use std::path::Path;

use ksp_identity::{EnrolmentFingerprint, KeyId};
use ksp_key_lifecycle::{KeyError, KeyRoot, KeyStore};
use ksp_types::{AgentId, PrincipalId};

use crate::exit::{self, Outcome};
use crate::keys::{PinError, StoredEnrolment};
use crate::output::{Emitter, Report};
/// A public key or digest as lowercase hex.
///
/// Hex is what an operator compares between two terminals, so it stays one
/// definition here rather than three inline `format!` calls that could differ.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

use crate::config::Layout;

/// Why an agent operation failed.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// The protected key file could not be written or read.
    #[error("the protected key file could not be used")]
    Keys(#[from] KeyError),
    /// The stored pin could not be read.
    #[error("the stored enrolment is not readable")]
    Pin(#[from] PinError),
    /// The agent identifier is not a principal UUID.
    #[error("an agent identity is a canonical lowercase v4 UUID (8-4-4-4-12); got '{0}'")]
    Identity(String),
    /// A principal already carries this display name.
    #[error(
        "agent {agent} is already enrolled under that display name; its UUID is never reissued"
    )]
    AlreadyEnrolled {
        /// The UUID the existing principal keeps.
        agent: AgentId,
    },
    /// An enrolment file could not be read or decoded.
    ///
    /// The path is named because a listing that skipped the file would report a
    /// complete answer it does not have, and an omitted row reads as an agent
    /// that does not exist.
    #[error(
        "the enrolment at {0} could not be read; the listing is incomplete and names only the \
         agents it could decode"
    )]
    Unreadable(String),
}

impl AgentError {
    /// The exit code this failure maps to.
    pub fn exit_code(&self) -> i32 {
        match self {
            // A key file that is missing, tampered with, wrong-mode or
            // mismatched is missing *usable* key material, not an internal bug.
            Self::Keys(error) if error.failure().is_missing_key_material() => exit::MISSING_KEY,
            Self::Pin(_) => exit::MISSING_KEY,
            // A malformed identity and a taken display name are the caller's
            // mistake, and both messages name the accepted form. `INTERNAL` told
            // an agent to report a crash where the right response was to fix its
            // own invocation.
            Self::Identity(_) | Self::AlreadyEnrolled { .. } => exit::USAGE,
            // A file that cannot be decoded is missing usable key material rather
            // than an internal bug: re-running will not decode it, and the operator
            // has a file to replace. `MISSING_KEY` is the code every other surface
            // uses for that state.
            Self::Unreadable(_) => exit::MISSING_KEY,
            Self::Keys(_) => exit::INTERNAL,
        }
    }
}

/// Parse an agent identity supplied on a command line.
///
/// The value is a principal UUID. A display name is metadata and is refused
/// here rather than resolved to some principal the caller did not name.
pub fn parse_agent(text: &str) -> Result<AgentId, AgentError> {
    AgentId::parse(text).map_err(|_| AgentError::Identity(text.to_string()))
}

/// The principal already enrolled under one display name, if any.
///
/// A name is not an identity, so this is a lookup that *reports* the UUID it
/// found rather than deriving one: the principal it names is the one the
/// operator must use from then on.
fn enrolled_as(layout: &Layout, display_name: &str) -> Option<AgentId> {
    for entry in std::fs::read_dir(layout.enrolments_dir()).ok()?.flatten() {
        if let Ok(stored) = StoredEnrolment::load(&entry.path())
            && stored.display_name.as_deref() == Some(display_name)
        {
            return Some(stored.identity);
        }
    }
    None
}

fn key_store(layout: &Layout) -> Result<KeyStore, AgentError> {
    Ok(KeyStore::new(KeyRoot::open(layout.agent_key_root())?))
}

/// Generate an agent's keypairs, store the protected key file, and pin the
/// enrolment this host will reload against.
///
/// The agent's principal UUID is issued here, once. `display_name` is stored as
/// mutable metadata: it is what a human typed, never what a path or a grant is
/// keyed on. A name already held by a principal is refused and the existing UUID
/// is reported, because two principals a human cannot tell apart is misfit J.
pub fn enroll(display_name: &str, layout: &Layout) -> Result<EnrolledKeys, AgentError> {
    if let Some(agent) = enrolled_as(layout, display_name) {
        return Err(AgentError::AlreadyEnrolled { agent });
    }
    let store = key_store(layout)?;
    let agent = AgentId::new(PrincipalId::generate());
    let signing_key_id = KeyId::new(format!("{agent}-ed25519-1"));
    let recipient_key_id = KeyId::new(format!("{agent}-x25519-1"));

    // S6 refuses to replace an existing file: a silent new key would make every
    // artifact already sealed to the old one unopenable while every command
    // still reported success.
    let enrolled = store.generate_agent(agent, signing_key_id, recipient_key_id)?;
    let unsigned = &enrolled.enrolment;

    let stored = StoredEnrolment {
        identity: agent,
        display_name: Some(display_name.to_string()),
        signing_key: *unsigned.signing_key(),
        recipient_key: *unsigned.recipient_key(),
        signing_key_id: unsigned.signing_key_id().clone(),
        recipient_key_id: unsigned.recipient_key_id().clone(),
        fingerprint: *unsigned.fingerprint(),
    };
    stored.save(&layout.enrolment_file(&agent.to_string()))?;

    Ok(EnrolledKeys {
        key_file: enrolled.path,
        enrolment: stored,
    })
}

/// Generate fresh agent keys, replace the protected file, and repin.
///
/// S6 archives the bundle being replaced before the new one lands, so a
/// deployment that kept the old private half can still open artifacts sealed to
/// it: rotation changes future minting and the new trust state, and it does not
/// revoke a copy someone already holds.
pub fn rotate(
    agent: &AgentId,
    layout: &Layout,
    signing_key_id: KeyId,
    recipient_key_id: KeyId,
) -> Result<EnrolledKeys, AgentError> {
    let store = key_store(layout)?;
    let stored = StoredEnrolment::load(&layout.enrolment_file(&agent.to_string()))?;
    let pin = stored.pin();

    // A fresh identity bundle, built in memory: S6 owns which file it lands in
    // and what happens to the one it replaces.
    let keys = ksp_identity::AgentKeys::generate();
    let bundle =
        ksp_identity::AgentKeyBundle::from_keys(&keys, *agent, signing_key_id, recipient_key_id)
            .map_err(|_| AgentError::Keys(KeyError::Enrolment))?;
    let rotation = store.rotate_agent(&pin, &bundle)?;

    // The pin is rewritten only after the file it names is in place: a pin for a
    // key that never landed would make every later reload fail against a record
    // this host does not hold.
    let repinned = StoredEnrolment {
        identity: *agent,
        display_name: stored.display_name.clone(),
        signing_key: bundle.signing_public(),
        recipient_key: bundle.recipient_public(),
        signing_key_id: bundle.signing_key_id().clone(),
        recipient_key_id: bundle.recipient_key_id().clone(),
        fingerprint: *bundle.fingerprint(),
    };
    repinned.save(&layout.enrolment_file(&agent.to_string()))?;

    let _ = rotation;
    Ok(EnrolledKeys {
        key_file: rotation.current,
        enrolment: repinned,
    })
}

/// What `enroll` produced.
pub struct EnrolledKeys {
    /// The protected key file S6 wrote.
    pub key_file: std::path::PathBuf,
    /// The public halves and fingerprint this host now pins.
    pub enrolment: StoredEnrolment,
}

impl std::fmt::Debug for EnrolledKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrolledKeys")
            .field("key_file", &self.key_file)
            .field("fingerprint", &self.enrolment.fingerprint.to_hex())
            .finish()
    }
}

/// List every agent this host holds, ordered by identity.
///
/// # Why this exists
///
/// The enrolment file exists for every agent and no command read it as a list, so
/// a report that wanted to join a policy's agent UUIDs to display names had to
/// decode CBOR by hand. `admin policy --show` printed UUIDs with nothing to join
/// them to.
///
/// # What it reads, and what it does not
///
/// `enrolments/<uuid>.cbor` only. The private halves live under `agent/`, a
/// different directory, and this function never opens it — the row type has no
/// field that could carry one, so a listing cannot print what it never receives.
///
/// # Failure
///
/// A file that cannot be decoded is returned as an error that names it, together
/// with the rows that did decode. An omitted row reads as an agent that does not
/// exist, so the caller gets both the partial answer and the reason it is
/// partial, and the non-zero exit is what marks it partial.
///
/// A missing `enrolments/` directory is an empty listing, not an error: a host
/// with no agents is a normal state, and a listing that failed here would make
/// every status report branch on an exit code for the ordinary case.
///
/// # What it does not do
///
/// It creates, chowns and repairs nothing. A listing is a read.
pub fn list(
    layout: &Layout,
) -> Result<Vec<crate::output::AgentListing>, (AgentError, Vec<crate::output::AgentListing>)> {
    let dir = layout.enrolments_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => {
            return Err((
                AgentError::Unreadable(dir.display().to_string()),
                Vec::new(),
            ));
        }
    };

    let mut rows = Vec::new();
    let mut failure = None;
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        // Only the enrolment records. A stray file in this directory is not an
        // agent, and decoding it as one would invent a row.
        if path.extension().and_then(|ext| ext.to_str()) != Some("cbor") {
            continue;
        }
        match StoredEnrolment::load(&path) {
            Ok(stored) => rows.push(crate::output::AgentListing {
                identity: stored.identity.to_string(),
                display_name: stored.display_name.clone(),
                signing_key_id: stored.signing_key_id.as_str().to_string(),
                recipient_key_id: stored.recipient_key_id.as_str().to_string(),
                fingerprint: hex(stored.fingerprint.as_bytes()),
            }),
            // The first failure is kept and the walk continues, so the caller
            // receives every row that did decode rather than stopping at the bad
            // one. The message names the first file it could not read.
            Err(_) => {
                if failure.is_none() {
                    failure = Some(AgentError::Unreadable(path.display().to_string()));
                }
            }
        }
    }
    // Ordered by identity rather than by directory order: a listing a caller
    // diffs against an earlier one must not reorder because a file was rewritten.
    rows.sort_by(|left, right| left.identity.cmp(&right.identity));
    match failure {
        Some(error) => Err((error, rows)),
        None => Ok(rows),
    }
}

/// Run one `agent` subcommand that needs no private half.
pub fn run<W: std::io::Write>(
    command: &crate::commands::AgentCommand,
    layout: &Layout,
    emitter: &mut Emitter<W>,
) -> Outcome {
    match command {
        crate::commands::AgentCommand::List => match list(layout) {
            Ok(agents) => match emitter.report(&Report::Agents { agents }) {
                Ok(()) => Outcome::Success,
                Err(_) => Outcome::Failed(exit::INTERNAL),
            },
            // The rows that decoded are printed before the refusal, so a caller
            // gets the partial answer and the reason it is partial from one run.
            // The message says the listing is incomplete; printing nothing would
            // make that sentence false.
            Err((error, agents)) => {
                if !agents.is_empty() {
                    let _ = emitter.report(&Report::Agents { agents });
                }
                let _ = emitter.refusal(&error.to_string());
                Outcome::Failed(error.exit_code())
            }
        },
        crate::commands::AgentCommand::Pubkey { agent } => {
            let path = layout.enrolment_file(agent);
            match StoredEnrolment::load(Path::new(&path)) {
                Ok(stored) => {
                    let report = Report::Identity(crate::output::PublicIdentity {
                        identity: format!("agent:{}", stored.identity),
                        signing_key: hex(&stored.signing_key.to_bytes()),
                        recipient_key: hex(&stored.recipient_key.to_bytes()),
                        signing_key_id: stored.signing_key_id.as_str().to_string(),
                        recipient_key_id: stored.recipient_key_id.as_str().to_string(),
                        fingerprint: hex(stored.fingerprint.as_bytes()),
                    });
                    match emitter.report(&report) {
                        Ok(()) => Outcome::Success,
                        Err(_) => Outcome::Failed(exit::INTERNAL),
                    }
                }
                Err(error) => Outcome::Failed(AgentError::from(error).exit_code()),
            }
        }
        // `enroll` and `rotate` write a protected key file and are dispatched
        // with the paths they need.
        _ => Outcome::Failed(exit::INTERNAL),
    }
}

/// Print the fingerprint an operator compares out of band.
pub fn fingerprint_line(fingerprint: &EnrolmentFingerprint) -> String {
    format!("fingerprint: {}", hex(fingerprint.as_bytes()))
}
