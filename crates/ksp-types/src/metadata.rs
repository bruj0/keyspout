//! Identifiers, levels and the bound metadata that names one record version.
//!
//! These types are the vocabulary every subsystem agrees on. They hold no
//! behaviour, no policy and no I/O: a subsystem that disagrees with another
//! about an identifier or a level disagrees *here*, in one place.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The identifier of one user's vault. Every record path is rooted at it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VaultId(String);

impl VaultId {
    /// Wrap an already-validated vault identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VaultId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The UUID a principal is issued once at enrolment.
///
/// A principal is an actor that has one of these: the deployment's admin, a
/// user, or one enrolled agent. The UUID — never a display name — is the
/// identity every binding, policy grant, record path segment, evidence report
/// and audit entry refers to (FR-036, FR-037). A display name is mutable
/// metadata, and no security decision may read it.
///
/// The canonical form is a lowercase hyphenated version 4 UUID
/// (`8-4-4-4-12`). Parsing is strict: an uppercase digit, a missing hyphen, a
/// wrong version or a wrong variant is refused rather than normalised, so two
/// spellings can never name one principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrincipalId([u8; 16]);

/// Why a principal identifier could not be read.
///
/// Every message names the canonical form, because the caller's next question
/// is what a valid value looks like.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrincipalIdError {
    /// The text is not the 36 characters of `8-4-4-4-12`.
    #[error("a principal id is a canonical lowercase UUID (8-4-4-4-12); got {0} characters")]
    Length(usize),
    /// A hyphen is missing, or a non-hyphen sits where one belongs.
    #[error("a principal id is a canonical lowercase UUID (8-4-4-4-12); byte {0} must be a hyphen")]
    Hyphen(usize),
    /// A character is not a lowercase hexadecimal digit.
    #[error(
        "a principal id is a canonical lowercase UUID (8-4-4-4-12); byte {0} is not a lowercase hexadecimal digit"
    )]
    Digit(usize),
    /// The third group does not start with `4`.
    #[error(
        "a principal id must be a version 4 UUID (the third group starts with '4'); got version {0}"
    )]
    Version(u8),
    /// The fourth group does not start with `8`, `9`, `a` or `b`.
    #[error(
        "a principal id must have the RFC 4122 variant (the fourth group starts with 8, 9, a or b); got 0x{0:02x}"
    )]
    Variant(u8),
}

impl PrincipalId {
    /// Issue a new principal identifier.
    ///
    /// Called once at enrolment; the value is immutable for the life of the
    /// principal and is never reissued (FR-036). The version and variant bits
    /// are set so the result is a well-formed RFC 4122 version 4 UUID, not
    /// merely sixteen random bytes.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::fill(&mut bytes);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self(bytes)
    }

    /// Parse the canonical lowercase hyphenated form.
    pub fn parse(text: &str) -> Result<Self, PrincipalIdError> {
        const HYPHENS: [usize; 4] = [8, 13, 18, 23];

        let chars = text.as_bytes();
        if chars.len() != 36 {
            return Err(PrincipalIdError::Length(chars.len()));
        }

        let mut digits = [0u8; 32];
        let mut written = 0;
        for (index, byte) in chars.iter().copied().enumerate() {
            if HYPHENS.contains(&index) {
                if byte != b'-' {
                    return Err(PrincipalIdError::Hyphen(index));
                }
                continue;
            }
            let value = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => return Err(PrincipalIdError::Digit(index)),
            };
            digits[written] = value;
            written += 1;
        }

        let mut bytes = [0u8; 16];
        for index in 0..16 {
            bytes[index] = (digits[index * 2] << 4) | digits[index * 2 + 1];
        }

        if bytes[6] >> 4 != 4 {
            return Err(PrincipalIdError::Version(bytes[6] >> 4));
        }
        if bytes[8] & 0xc0 != 0x80 {
            return Err(PrincipalIdError::Variant(bytes[8]));
        }

        Ok(Self(bytes))
    }

    /// The sixteen raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for PrincipalId {
    type Err = PrincipalIdError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl Serialize for PrincipalId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PrincipalId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// The principal UUID of one enrolled agent, viewed in its agent role.
///
/// It appears in the `agent-<uuid>` segment of a record path. The id inside is
/// the *agent's* principal UUID, while the `<principal-uuid>` segment of the
/// same path is the vault owner's: two different principals, and the path is
/// not redundant.
///
/// A display name is not an identity and cannot be wrapped here. The `agent-`
/// prefix belongs to the level segment, so [`fmt::Display`] renders the bare
/// UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(PrincipalId);

impl AgentId {
    /// View an agent's principal UUID in its agent role.
    pub const fn new(principal: PrincipalId) -> Self {
        Self(principal)
    }

    /// The principal UUID this agent role names.
    pub const fn principal(self) -> PrincipalId {
        self.0
    }

    /// Parse the canonical lowercase hyphenated UUID form.
    pub fn parse(text: &str) -> Result<Self, PrincipalIdError> {
        PrincipalId::parse(text).map(Self)
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for AgentId {
    type Err = PrincipalIdError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// The identifier of a principal that may act: a user, an agent, or the admin.
///
/// `User` and `Agent` carry the [`PrincipalId`] issued at enrolment. `Admin`
/// carries the admin principal's UUID, issued by `admin init`; the key that
/// signed a claim is named separately by `signer_key_id`, so role and key are
/// never inferred from one another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActorId {
    /// A human user.
    User(PrincipalId),
    /// An enrolled agent.
    Agent(AgentId),
    /// The admin principal: the collector that runs the sweep and signs its
    /// reports. It is not the user whose records it removes.
    Admin(PrincipalId),
}

impl fmt::Display for ActorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User(id) => write!(f, "user:{id}"),
            Self::Agent(id) => write!(f, "agent:{id}"),
            Self::Admin(id) => write!(f, "admin:{id}"),
        }
    }
}

/// A random, opaque identifier for one stored value.
///
/// The opaque secret ID is what appears in a record path. A secret *name*
/// never leaves the encrypted payload, so a backend listing discloses no
/// secret name (FR-011).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpaqueSecretId(String);

impl OpaqueSecretId {
    /// Wrap an already-generated opaque identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OpaqueSecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One of `admin`, `user` or `agent-<id>`.
///
/// The three are *siblings* in the record path, never nested, and the
/// direction of sharing is one-way: an `agent-<id>` record is never copied
/// back to `user` or `admin` level (FR-013, FR-016).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Level {
    /// The vault owner's administrative level.
    Admin,
    /// The vault owner's personal level.
    User,
    /// A specific agent's level.
    Agent(AgentId),
}

impl Level {
    /// The path segment for this level.
    ///
    /// `admin` and `user` are fixed words; an agent level is
    /// `agent-<principal-uuid>`. The segment is what the record path is built
    /// from, so it must be stable and must never contain a path separator.
    pub fn path_segment(&self) -> String {
        match self {
            Self::Admin => "admin".to_string(),
            Self::User => "user".to_string(),
            Self::Agent(id) => format!("agent-{id}"),
        }
    }

    /// Parse one path segment: `admin`, `user` or `agent-<principal-uuid>`.
    ///
    /// An `agent-` segment whose remainder is not a canonical UUID is refused:
    /// a display name is not an agent identity, and accepting one here would
    /// let a record be filed under a name that no binding names.
    pub fn parse(segment: &str) -> Result<Self, LevelError> {
        match segment {
            "admin" => Ok(Self::Admin),
            "user" => Ok(Self::User),
            _ => match segment.strip_prefix("agent-") {
                Some(agent) => AgentId::parse(agent)
                    .map(Self::Agent)
                    .map_err(|_| LevelError::Agent(segment.to_string())),
                None => Err(LevelError::Unknown(segment.to_string())),
            },
        }
    }
}

/// Why a level segment could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LevelError {
    /// The segment is not one of the three level words.
    #[error("a level segment is 'admin', 'user' or 'agent-<principal-uuid>'; got '{0}'")]
    Unknown(String),
    /// The agent id after `agent-` is not a canonical UUID.
    #[error(
        "an agent level carries the agent's principal UUID, which must be a canonical lowercase v4 UUID (8-4-4-4-12); got '{0}'"
    )]
    Agent(String),
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.path_segment())
    }
}

/// The five-tuple that names exactly one stored record version and is bound
/// cryptographically to it (FR-006).
///
/// The same canonical serialization of this structure is the AEAD associated
/// data of the content blob *and* the HPKE associated data of the record
/// envelope. There is exactly one function that produces those bytes, and
/// both consumers call it — a second, looser binding would reintroduce the
/// record-swap misfit.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BoundMetadata {
    /// The vault the record lives in.
    pub vault_id: VaultId,
    /// The principal UUID of the vault's owner, in its record-owner role.
    ///
    /// It is bound into the associated data, so renaming the principal cannot
    /// change it and changing it is a re-seal rather than a rename.
    pub user_id: PrincipalId,
    /// The level the record lives at.
    pub level: Level,
    /// The opaque identifier of the stored value.
    pub secret_id: OpaqueSecretId,
    /// The version of the record.
    pub version: u32,
}

impl BoundMetadata {
    /// The canonical associated data that binds this record version.
    ///
    /// This is the deterministic CBOR of
    /// `[vault_id, principal_uuid, level, secret_id, version]`.
    ///
    /// **This is the single binding.** The content blob's AEAD associated
    /// data and the record envelope's HPKE associated data are both these
    /// exact bytes. There is one function that produces them, and every
    /// consumer calls it — a second, looser binding would reintroduce the
    /// record-swap misfit (FR-006).
    pub fn bound_aad(&self) -> Result<Vec<u8>, crate::cbor::CborError> {
        use ciborium::value::{Integer, Value};

        // The five elements have different Rust types, so the CBOR value
        // tree is assembled explicitly rather than through a homogeneous
        // Rust slice. The *order* is the fixed one the design pins, and the
        // encoder writes it exactly that way.
        let items = vec![
            Value::Text(self.vault_id.as_str().to_string()),
            Value::Text(self.user_id.to_string()),
            Value::Text(self.level.path_segment()),
            Value::Text(self.secret_id.as_str().to_string()),
            Value::Integer(Integer::from(self.version)),
        ];

        let mut out = Vec::new();
        ciborium::into_writer(&Value::Array(items), &mut out)
            .map_err(|e| crate::cbor::CborError::Encode(e.to_string()))?;
        Ok(out)
    }
}

/// One numbered, immutable revision of a record at a given level.
///
/// A delivery binds an exact version, never "the current one". The version
/// is the unit a lease deletes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RecordVersion(pub u32);

impl RecordVersion {
    /// The first version of a record.
    pub const FIRST: Self = Self(1);

    /// The version number.
    pub fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for RecordVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is
    // what says why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// A fixed canonical UUID, so a test states the exact spelling it means.
    const ALICE: &str = "6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f";

    fn alice() -> PrincipalId {
        PrincipalId::parse(ALICE).unwrap()
    }

    fn sample() -> BoundMetadata {
        BoundMetadata {
            vault_id: VaultId::new("v-1"),
            user_id: alice(),
            level: Level::User,
            secret_id: OpaqueSecretId::new("s-9"),
            version: 3,
        }
    }

    #[test]
    fn a_generated_principal_is_a_canonical_version_four_uuid() {
        for _ in 0..64 {
            let id = PrincipalId::generate();
            let text = id.to_string();

            // The canonical form, exactly: 36 characters, hyphens at the four
            // fixed positions, lowercase hex between them.
            assert_eq!(text.len(), 36);
            for index in [8, 13, 18, 23] {
                assert_eq!(text.as_bytes()[index], b'-');
            }
            assert!(text.bytes().all(|byte| !byte.is_ascii_uppercase()));

            // The version nibble and the RFC 4122 variant are set, rather than
            // trusted to be random.
            assert_eq!(text.as_bytes()[14], b'4');
            assert!(matches!(text.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));

            // Parsing the rendering gives the same value back.
            assert_eq!(PrincipalId::parse(&text).unwrap(), id);
        }
    }

    #[test]
    fn two_principals_are_two_identities() {
        // Misfit J: a name that happens to collide is not an identity. Two
        // enrolments produce two UUIDs, and their bound AAD cannot agree.
        let one = PrincipalId::generate();
        let two = PrincipalId::generate();
        assert_ne!(one, two);

        let first = BoundMetadata {
            user_id: one,
            ..sample()
        };
        let second = BoundMetadata {
            user_id: two,
            ..sample()
        };
        assert_ne!(first.bound_aad().unwrap(), second.bound_aad().unwrap());
    }

    #[test]
    fn parsing_refuses_a_display_name_and_names_the_canonical_form() {
        // Acceptance criterion 5: a hand-written path segment that carries a
        // display name is refused, and the error says what a valid value is.
        let error = PrincipalId::parse("alice").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("canonical lowercase UUID (8-4-4-4-12)"));
        assert!(matches!(error, PrincipalIdError::Length(5)));
    }

    #[test]
    fn parsing_is_strict_about_case_version_and_variant() {
        // Uppercase is a different spelling, not the same identity.
        assert!(matches!(
            PrincipalId::parse("6F5A1C8E-3B2D-4F7A-9C1E-0A2B3C4D5E6F").unwrap_err(),
            PrincipalIdError::Digit(1)
        ));
        // A missing hyphen is not a UUID.
        assert!(matches!(
            PrincipalId::parse("6f5a1c8e3-b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap_err(),
            PrincipalIdError::Hyphen(8)
        ));
        // Version 5 is a real UUID and not this type.
        assert!(matches!(
            PrincipalId::parse("6f5a1c8e-3b2d-5f7a-9c1e-0a2b3c4d5e6f").unwrap_err(),
            PrincipalIdError::Version(5)
        ));
        // A value that is not an RFC 4122 variant.
        assert!(matches!(
            PrincipalId::parse("6f5a1c8e-3b2d-4f7a-1c1e-0a2b3c4d5e6f").unwrap_err(),
            PrincipalIdError::Variant(0x1c)
        ));
    }

    #[test]
    fn a_principal_serializes_as_its_canonical_string() {
        let id = alice();
        let bytes = crate::cbor::encode(&id).unwrap();
        let back: PrincipalId = crate::cbor::decode(&bytes).unwrap();
        assert_eq!(back, id);

        // A non-canonical encoding is refused at the decoder, not accepted and
        // normalised later.
        let bad = crate::cbor::encode(&"alice").unwrap();
        assert!(crate::cbor::decode::<PrincipalId>(&bad).is_err());
    }

    #[test]
    fn agent_levels_carry_the_agents_uuid_and_nothing_else() {
        // Misfit K: a binding that names nothing. A display name in an agent
        // segment is refused, with the canonical form named.
        let error = Level::parse("agent-deploy-bot").unwrap_err();
        assert!(error.to_string().contains("canonical lowercase v4 UUID"));

        let agent = AgentId::new(PrincipalId::generate());
        let segment = Level::Agent(agent).path_segment();
        assert_eq!(segment, format!("agent-{agent}"));
        assert_eq!(Level::parse(&segment).unwrap(), Level::Agent(agent));
    }

    #[test]
    fn the_three_levels_are_siblings_never_nested() {
        let agent = AgentId::new(PrincipalId::generate());
        let segments = [
            Level::Admin.path_segment(),
            Level::User.path_segment(),
            Level::Agent(agent).path_segment(),
        ];

        for (index, segment) in segments.iter().enumerate() {
            // A level is exactly one path segment.
            assert!(!segment.contains('/'), "level {segment} is not one segment");
            for (other_index, other) in segments.iter().enumerate() {
                if index != other_index {
                    // And no level is a prefix of another, so a path can never
                    // be read as one level nested inside another.
                    assert!(
                        !other.starts_with(segment.as_str()),
                        "{segment} is a prefix of {other}"
                    );
                }
            }
        }
    }

    #[test]
    fn level_segments_are_stable() {
        assert_eq!(Level::Admin.path_segment(), "admin");
        assert_eq!(Level::User.path_segment(), "user");
        assert_eq!(Level::parse("admin").unwrap(), Level::Admin);
        assert_eq!(Level::parse("user").unwrap(), Level::User);
        assert!(matches!(
            Level::parse("owner").unwrap_err(),
            LevelError::Unknown(_)
        ));
    }

    #[test]
    fn the_bound_aad_contains_the_principal_uuid() {
        let aad = sample().bound_aad().unwrap();
        let value: ciborium::value::Value = crate::cbor::decode(&aad).unwrap();
        let items = match value {
            ciborium::value::Value::Array(items) => items,
            other => panic!("the bound AAD must be an array, got {other:?}"),
        };
        match &items[1] {
            ciborium::value::Value::Text(text) => assert_eq!(text, ALICE),
            other => panic!("the principal must be text, got {other:?}"),
        }
    }
}
