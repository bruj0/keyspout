//! The one definition of a record path.
//!
//! A record path is
//! `p/<vault>/<principal-uuid>/<level>/<opaque-secret-id>/<version>`. It is
//! derived from the bound metadata, so the path a writer stores under and the
//! path a reader looks up cannot disagree about the principal, the level, the
//! secret or the version.
//!
//! No other module formats these five segments by hand. A second formatter
//! would be a second layout, and a layout that exists twice is a layout that
//! will disagree with itself.

use std::fmt;

use ksp_types::{
    BoundMetadata, Level, LevelError, OpaqueSecretId, PrincipalId, PrincipalIdError, VaultId,
};

/// The location of one record version.
///
/// The value is always a canonical path: one built from typed parts, or one
/// parsed and validated. There is no public constructor from an arbitrary
/// string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordPath(String);

impl RecordPath {
    /// Build the canonical path for one bound metadata.
    pub fn of(metadata: &BoundMetadata) -> Self {
        Self(format!(
            "p/{}/{}/{}/{}/{}",
            metadata.vault_id.as_str(),
            metadata.user_id,
            metadata.level.path_segment(),
            metadata.secret_id.as_str(),
            metadata.version
        ))
    }

    /// Parse a record path, refusing any segment that is not canonical.
    ///
    /// The principal segment must be a canonical UUID and an agent level must
    /// carry the agent's canonical UUID. A display name in either place is
    /// refused, because a name is not an identity (FR-037).
    pub fn parse(text: &str) -> Result<Self, RecordPathError> {
        let parts: Vec<&str> = text.split('/').collect();
        if parts.len() != 6 || parts[0] != "p" || parts.iter().any(|part| part.is_empty()) {
            return Err(RecordPathError::Shape(text.to_string()));
        }

        let principal = PrincipalId::parse(parts[2])?;
        let level = Level::parse(parts[3])?;
        let version: u32 = parts[5]
            .parse()
            .map_err(|_| RecordPathError::Version(parts[5].to_string()))?;

        let canonical = Self::of(&BoundMetadata {
            vault_id: VaultId::new(parts[1]),
            user_id: principal,
            level,
            secret_id: OpaqueSecretId::new(parts[4]),
            version,
        });

        // The round trip is what rejects a second spelling of one path:
        // `007` for version 7, or a principal written any other way.
        if canonical.0 != text {
            return Err(RecordPathError::NotCanonical(text.to_string()));
        }
        Ok(canonical)
    }

    /// The path of the head pointer that names this record's current version.
    ///
    /// Built from the path's own prefix, so the head can never point into a
    /// different principal's or level's directory.
    pub fn head(&self) -> String {
        let mut parts: Vec<&str> = self.0.split('/').collect();
        let _ = parts.pop();
        parts.push("head");
        parts.join("/")
    }

    /// The directory that holds one principal's records, optionally at one
    /// level only.
    ///
    /// A listing needs a prefix rather than a record path, and a
    /// `<vault>/<user>` prefix formatted anywhere else would be a second
    /// statement of the layout. The trailing slash is part of the directory:
    /// without it `p/v/a/user` would also match `p/v/ab.../`.
    pub fn directory(vault_id: &VaultId, user: PrincipalId, level: Option<&Level>) -> String {
        let mut directory = format!("p/{}/{}/", vault_id.as_str(), user);
        if let Some(level) = level {
            directory.push_str(&level.path_segment());
            directory.push('/');
        }
        directory
    }

    /// The path as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RecordPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&BoundMetadata> for RecordPath {
    fn from(metadata: &BoundMetadata) -> Self {
        Self::of(metadata)
    }
}

/// Why a record path could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordPathError {
    /// The path does not have the six canonical segments.
    #[error(
        "a record path is 'p/<vault>/<principal-uuid>/<level>/<opaque-secret-id>/<version>'; got '{0}'"
    )]
    Shape(String),
    /// The principal segment is not a canonical UUID.
    #[error(
        "the principal segment of a record path must be a canonical lowercase v4 UUID (8-4-4-4-12): {0}"
    )]
    Principal(#[from] PrincipalIdError),
    /// The level segment is not `admin`, `user` or `agent-<uuid>`.
    #[error("the level segment of a record path is not a level: {0}")]
    Level(#[from] LevelError),
    /// The version segment is not a decimal `u32`.
    #[error("the version segment of a record path must be a decimal u32; got '{0}'")]
    Version(String),
    /// The path spells a value in a way the canonical form does not.
    #[error("the record path is not in its canonical form; got '{0}'")]
    NotCanonical(String),
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use ksp_types::{AgentId, Level, OpaqueSecretId, PrincipalId, VaultId};

    const OWNER: &str = "6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f";
    const AGENT: &str = "00000000-0000-4000-8000-000000000007";

    fn metadata() -> BoundMetadata {
        BoundMetadata {
            vault_id: VaultId::new("vault-1"),
            user_id: PrincipalId::parse(OWNER).unwrap(),
            level: Level::User,
            secret_id: OpaqueSecretId::new("secret-1"),
            version: 3,
        }
    }

    #[test]
    fn the_path_has_the_specified_shape() {
        assert_eq!(
            RecordPath::of(&metadata()).as_str(),
            "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/user/secret-1/3"
        );
    }

    #[test]
    fn an_agent_level_is_one_sibling_segment() {
        let mut meta = metadata();
        meta.level = Level::Agent(AgentId::parse(AGENT).unwrap());

        let path = RecordPath::of(&meta);
        let segments: Vec<&str> = path.as_str().split('/').collect();
        assert_eq!(
            segments.len(),
            6,
            "p, vault, principal, level, secret, version"
        );
        assert_eq!(segments[3], "agent-00000000-0000-4000-8000-000000000007");
    }

    #[test]
    fn a_path_round_trips_through_parse() {
        let path = RecordPath::of(&metadata());
        assert_eq!(RecordPath::parse(path.as_str()).unwrap(), path);
    }

    #[test]
    fn a_hand_written_display_name_is_refused_and_names_the_canonical_form() {
        // Acceptance criterion 5. The alternative — accepting `alice` and
        // treating it as an identity — is misfit J.
        let error = RecordPath::parse("p/vault-1/alice/user/secret-1/3").unwrap_err();
        assert!(matches!(error, RecordPathError::Principal(_)));
        assert!(error.to_string().contains("canonical lowercase v4 UUID"));

        // The same rule applies to an agent level: a display name there is
        // misfit K, a binding that names nothing.
        let error = RecordPath::parse(
            "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent-deploy-bot/secret-1/3",
        )
        .unwrap_err();
        assert!(matches!(error, RecordPathError::Level(_)));
        assert!(error.to_string().contains("canonical lowercase v4 UUID"));
    }

    #[test]
    fn a_non_canonical_spelling_is_refused() {
        // A version written with a leading zero would name the same record and
        // spell a different path, which is exactly what one definition
        // prevents.
        let error =
            RecordPath::parse("p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/user/secret-1/03")
                .unwrap_err();
        assert!(matches!(error, RecordPathError::NotCanonical(_)));

        for shape in [
            "",
            "p",
            "p/vault-1",
            "q/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/user/secret-1/3",
            "p//6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/user/secret-1/3",
            "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/agent/secret-1/3",
        ] {
            assert!(
                RecordPath::parse(shape).is_err(),
                "shape {shape:?} must be refused"
            );
        }
    }

    #[test]
    fn a_directory_is_the_prefix_every_path_under_it_starts_with() {
        let meta = metadata();

        let all = RecordPath::directory(&meta.vault_id, meta.user_id, None);
        assert_eq!(all, "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/");
        assert!(RecordPath::of(&meta).as_str().starts_with(&all));

        let user_level = RecordPath::directory(&meta.vault_id, meta.user_id, Some(&meta.level));
        assert!(RecordPath::of(&meta).as_str().starts_with(&user_level));

        // One level's directory is a sibling of the other's, never its prefix:
        // an agent listing must not reach the owner's records.
        let agent = Level::Agent(AgentId::parse(AGENT).unwrap());
        let agent_level = RecordPath::directory(&meta.vault_id, meta.user_id, Some(&agent));
        assert!(!RecordPath::of(&meta).as_str().starts_with(&agent_level));
    }

    #[test]
    fn the_head_path_is_the_record_prefix_plus_head() {
        let path = RecordPath::of(&metadata());
        assert_eq!(
            path.head(),
            "p/vault-1/6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f/user/secret-1/head"
        );
        assert!(
            path.head()
                .starts_with(path.as_str().rsplit_once('/').unwrap().0)
        );
    }
}
