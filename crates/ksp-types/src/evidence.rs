//! The structures that record what is *claimed* about a version's deletion.
//!
//! None of these is a tombstone and none is evidence of erasure. A
//! **deletion intent** contains no keys and is not a tombstone: it says what
//! was asked for. A **deletion report** is one actor's signed claim about
//! what that actor did. An **absence observation** records only that a
//! version was not observed, and the time of the observation — never a
//! deletion time.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability_config::{AdapterName, GuaranteeLevel, HostCapability};
use crate::metadata::{ActorId, Level, OpaqueSecretId, PrincipalId, VaultId};

/// The outcome of an operation an actor performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// The actor's operation completed as intended.
    Success,
    /// The actor's operation did not complete.
    Failure,
}

/// A key-free request to delete one exact record version.
///
/// The intent contains no key material and is **not** a tombstone. It names
/// the version to act on, the deadline, and the actors authorized to act.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionIntent {
    /// The identity of this intent; retries reuse it.
    pub intent_id: String,
    /// The vault the target version lives in.
    pub vault_id: VaultId,
    /// The user who owns the target version.
    pub user_id: PrincipalId,
    /// The level the target version lives at.
    pub level: Level,
    /// The opaque identifier of the target value.
    pub secret_id: OpaqueSecretId,
    /// The exact target version.
    pub version: u32,
    /// The deadline, as a Unix timestamp.
    pub deadline: i64,
    /// The actors authorized to perform the deletion.
    pub authorized_deleters: Vec<ActorId>,
}

/// One actor's signed, version-scoped claim about a deletion it performed.
///
/// `reported_deleted_at` is the actor's *claim* about when it deleted, not
/// evidence that anything was destroyed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionReport {
    /// The intent this report answers.
    pub intent_id: String,
    /// The actor that performed the deletion.
    pub actor: ActorId,
    /// The key ID the actor signed with.
    pub signer_key_id: String,
    /// The actor's stated reason.
    pub reason: String,
    /// The outcome the actor observed.
    pub outcome: Outcome,
    /// The actor's claim about the deletion time. Not evidence of erasure.
    pub reported_deleted_at: i64,
    /// The level the target version lived at.
    pub level: Level,
    /// The opaque identifier of the target value.
    pub secret_id: OpaqueSecretId,
    /// The exact target version.
    pub version: u32,
}

/// An observation that a version was not seen.
///
/// `observed_at` is the observation time and nothing else. A version that
/// was never observed is *missing or unconfirmed* — it is not *deleted*.
/// Native expiry that removed a record with no Keyspout actor leaves no
/// report, and a client must never fabricate one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbsenceObservation {
    /// The level the observed-absent version lives at.
    pub level: Level,
    /// The opaque identifier of the target value.
    pub secret_id: OpaqueSecretId,
    /// The exact version observed absent.
    pub version: u32,
    /// The observer.
    pub observer: ActorId,
    /// The key ID the observer signed with.
    pub signer_key_id: String,
    /// The observation time only. No deletion time is implied.
    pub observed_at: i64,
}

/// The component that wrote an audit record.
///
/// A closed set, not a free string: the component is what a reader groups the log
/// by, and a typo'd string would silently create a second group. A new component
/// is a visible change to this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditComponent {
    /// The foreground command line.
    CommandLine,
    /// One sweep run.
    Sweeper,
    /// An agent process delivering or consuming a lease.
    Agent,
}

impl AuditComponent {
    /// The name a view prints for this component.
    pub fn label(&self) -> &'static str {
        match self {
            Self::CommandLine => "cli",
            Self::Sweeper => "sweeper",
            Self::Agent => "agent",
        }
    }
}

/// The operation an audit record describes.
///
/// Closed for the same reason the component is, and for one more: FR-046 requires
/// the writers to be *structurally* unable to place a secret in a record, and a
/// free-text operation is a field a secret could be formatted into. Adding an
/// operation is a deliberate change here rather than a string at a call site.
///
/// # The set grew, and why
///
/// The set grew by one variant, [`Capability`](Self::Capability), in feature
/// 004. A capability acceptance — "the path confinement was accepted as
/// unenforced, the adapter was `portable_confinement`, the guarantee is
/// `none`" — has to be **durable**, or a later reader cannot tell an accepted
/// absence from an unnoticed one (Misfit N, NFR-009). The status line says it;
/// the audit log is what survives.
///
/// The variant is recorded against the existing
/// [`AuditTarget::Deployment`], because a capability is a property of the
/// deployment rather than of one record. The record carries a
/// [`CapabilityAcceptance`], whose fields are three public facts — so the
/// extension adds no field a secret could be formatted into, which is the
/// property the closed set exists to protect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOperation {
    /// Provisioning the deployment.
    Init,
    /// Writing a new record version.
    Put,
    /// Reading a record version.
    Get,
    /// Listing records.
    List,
    /// Removing a record version.
    Delete,
    /// Delivering a lease to a child.
    Deliver,
    /// Consuming a lease and reporting its deletion.
    Consume,
    /// One sweep run.
    Sweep,
    /// An enrolment.
    Enrol,
    /// Verifying the log.
    Verify,
    /// Accepting a host capability, with the adapter that ran and the
    /// guarantee it established.
    ///
    /// Recorded against [`AuditTarget::Deployment`] and carrying a
    /// [`CapabilityAcceptance`].
    Capability,
}

impl AuditOperation {
    /// The name a view prints for this operation.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Put => "put",
            Self::Get => "get",
            Self::List => "list",
            Self::Delete => "delete",
            Self::Deliver => "deliver",
            Self::Consume => "consume",
            Self::Sweep => "sweep",
            Self::Enrol => "enrol",
            Self::Verify => "verify",
            Self::Capability => "capability",
        }
    }
}

/// What an audited operation acted on.
///
/// Typed rather than a free-form path so the target cannot carry a value: every
/// variant is built from identifiers that are already in the record's metadata.
/// The rendering is a projection of these fields, never a second string that could
/// disagree with them (FR-039).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditTarget {
    /// The deployment as a whole: provisioning, policy, rotation.
    Deployment,
    /// One record version, named by the identifiers the record already carries.
    Record {
        /// The vault the version lives in.
        vault: VaultId,
        /// The level the version lives at.
        level: Level,
        /// The opaque identifier of the value.
        secret: OpaqueSecretId,
        /// The exact version.
        version: u32,
    },
}

impl AuditTarget {
    /// The one-line rendering a view prints for this target.
    pub fn label(&self) -> String {
        match self {
            Self::Deployment => "deployment".to_string(),
            Self::Record {
                vault,
                level,
                secret,
                version,
            } => format!(
                "{}/{}/{}/{}",
                vault.as_str(),
                level.path_segment(),
                secret.as_str(),
                version
            ),
        }
    }
}

/// One audit record: what a component did, to what, with what outcome, when.
///
/// # What may not be in here
///
/// No secret value, password, token, proof of possession, raw key or plaintext
/// record name. This is enforced by the field types rather than by redaction:
/// every field is an identifier, a closed enum, an outcome, a timestamp or a
/// digest, so there is no `String` a writer could format a secret into. A record
/// that would need one is refused instead of written and scrubbed afterwards
/// (FR-046).
///
/// # What a record is, and is not
///
/// A record is the writer's claim at the time it wrote (FR-045). An **absent**
/// record is not evidence that the operation did not happen: a process killed
/// between its effect and its append leaves an effect nobody recorded, and the log
/// cannot tell that from an operation that never ran.
///
/// `prev_digest` is the digest of the record this one followed in its writer's
/// chain, and it is inside the signed bytes, so an edited or reordered record
/// breaks the link at the point it was edited (FR-047).
///
/// # One writer per chain
///
/// Records are chained per writing principal, so two writers never contend for one
/// lock and no daemon has to arbitrate. The consequence is stated rather than
/// hidden: the order *between* two chains is a timestamp claim by their writers,
/// not an order this build can prove (FR-053).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// The principal the operation was performed for.
    ///
    /// Not necessarily the signer: an administrative write on the tenant's behalf
    /// names the tenant here and is signed with the admin's key, which is why
    /// [`AuditRecord::signer_key_id`] is a separate field. The admin has a principal
    /// of its own since 002 (`deployment.admin`), and this field still names the
    /// **subject** so a tenant's own scope can show what was done to her records.
    /// Verification decides who may sign a record from the signer's pin and the
    /// record's component, never from this field (FR-049).
    pub actor: PrincipalId,
    /// The key ID that signed this record.
    ///
    /// Inside the signed payload, like `DeletionReport::signer_key_id`, so a record
    /// moved into another writer's segment still says who signed it: the segment
    /// name is a path, and a path is not a signature (Misfit W).
    pub signer_key_id: String,
    /// The component that wrote it.
    pub component: AuditComponent,
    /// What it was doing.
    pub operation: AuditOperation,
    /// What it acted on, when the operation names one.
    pub target: Option<AuditTarget>,
    /// Whether the operation completed, did not complete, or was refused.
    pub outcome: Outcome,
    /// The exit class the command produced: `0` for a completed operation.
    pub exit_code: i32,
    /// The writer's clock at the time it wrote.
    pub observed_at: i64,
    /// The digest of the record this one follows, or `None` for the first.
    pub prev_digest: Option<[u8; 32]>,
    /// The capability this record accepted, when the operation is
    /// [`AuditOperation::Capability`].
    ///
    /// `None` for every other operation. The field is a typed value and
    /// not a free-text blob, so it cannot carry a secret (FR-046).
    pub acceptance: Option<CapabilityAcceptance>,
}

impl AuditRecord {
    /// A record carrying `acceptance`, with every other field defaulted.
    ///
    /// The defaults are the ones a capability acceptance always has: the
    /// deployment target, a successful outcome and no exit code of its own.
    /// A caller that needs a different outcome builds the record directly.
    pub fn with_acceptance(mut self, acceptance: CapabilityAcceptance) -> Self {
        self.operation = AuditOperation::Capability;
        self.target = Some(AuditTarget::Deployment);
        self.acceptance = Some(acceptance);
        self
    }

    /// The capability this record accepted, when it accepted one.
    pub fn acceptance(&self) -> Option<&CapabilityAcceptance> {
        self.acceptance.as_ref()
    }
}

/// What a capability acceptance names: the capability, the adapter that
/// ran, and the guarantee it established.
///
/// # Every field is a public fact
///
/// The capability is one of two. The adapter is a name from the closed
/// set. The guarantee is one of three words. There is no field a path or a
/// passphrase could be formatted into, which is what lets this live in an
/// audit record at all (FR-046).
///
/// # The adapter field is the closed type, not a string
///
/// The field holds an [`AdapterName`], not a `String`. A `String` here would
/// be a hole in the closure: the record would accept any text, so a
/// passphrase could be formatted into the adapter field, and the type's own
/// claim that every field is a public fact would be false.
///
/// Holding the closed type makes the claim true by construction rather than
/// by convention: a value of this type can only name an adapter in the set,
/// whether it was built by a constructor or decoded from a document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityAcceptance {
    /// The capability that was established, or accepted as unenforced.
    pub capability: HostCapability,
    /// The adapter that ran, as a name from the closed set.
    pub adapter: AdapterName,
    /// The guarantee the adapter established.
    pub guarantee: GuaranteeLevel,
}

impl CapabilityAcceptance {
    /// An acceptance of `adapter` for `capability`, at `guarantee`.
    ///
    /// The adapter name is taken as given. Use
    /// [`for_adapter`](Self::for_adapter) when the name comes from outside
    /// this crate, because that constructor checks it against the closed
    /// set.
    pub fn new(
        capability: HostCapability,
        adapter: AdapterName,
        guarantee: GuaranteeLevel,
    ) -> Self {
        Self {
            capability,
            adapter,
            guarantee,
        }
    }

    /// An acceptance of `adapter` for `capability`, at `guarantee`.
    ///
    /// `None` when `adapter` is not a name from the closed set. A name
    /// outside the set is refused rather than recorded, so nothing can be
    /// formatted into the adapter field — which is the property the closed
    /// set exists to protect (FR-046).
    pub fn for_adapter(
        capability: HostCapability,
        adapter: &str,
        guarantee: GuaranteeLevel,
    ) -> Option<Self> {
        let name = AdapterName::parse(adapter).ok()?;
        Some(Self::new(capability, name, guarantee))
    }
}

impl fmt::Display for CapabilityAcceptance {
    /// The one-line rendering a view prints.
    ///
    /// The guarantee level is always named, including when it is `none`:
    /// an accepted absence that reads as an enforced capability is the
    /// failure this subsystem exists to prevent (FR-038, Misfit H).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} capability: adapter {} ({})",
            self.capability.label(),
            self.adapter,
            self.guarantee.label()
        )
    }
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is
    // what says why. The production code keeps the strict settings.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::metadata::AgentId;

    #[test]
    fn an_intent_carries_no_key_material() {
        // The intent's fields are all identifiers and timestamps. A key
        // would have to be added as a new field, which is visible in a
        // review — this test names the invariant so it stays visible.
        let intent = DeletionIntent {
            intent_id: "i-1".into(),
            vault_id: VaultId::new("v-1"),
            user_id: PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
            level: Level::User,
            secret_id: OpaqueSecretId::new("s-1"),
            version: 2,
            deadline: 1_700_000_000,
            authorized_deleters: vec![ActorId::Agent(AgentId::new(
                PrincipalId::parse("8a0e2d4c-1b3f-4a5e-9c7d-0e1f2a3b4c5d").unwrap(),
            ))],
        };

        // The intent round-trips through the canonical encoding, and the
        // decoded form has exactly the same fields. A key would have to
        // appear as an extra field on either side.
        let encoded = crate::cbor::encode(&intent).unwrap();
        let decoded: DeletionIntent = crate::cbor::decode(&encoded).unwrap();
        assert_eq!(decoded, intent);

        // The encoded form contains no byte string long enough to be key
        // material. Every string in the intent is an identifier of a few
        // characters, so a 32-byte string would be the only way to smuggle
        // a key through this structure.
        let longest_string = longest_text_string(&encoded);
        assert!(
            longest_string <= 8,
            "the encoded intent holds a {longest_string}-byte string, long enough to be key material"
        );
    }

    /// The length of the longest text string in an encoded CBOR document.
    ///
    /// This walks the encoded bytes looking for CBOR text strings (major
    /// type 3) and returns the largest length. It is deliberately simple:
    /// the input is a document this crate produced, not an untrusted one.
    fn longest_text_string(encoded: &[u8]) -> usize {
        let mut longest = 0usize;
        let mut index = 0usize;

        while index < encoded.len() {
            let header = encoded[index];
            let major = header >> 5;
            let additional = header & 0x1f;

            let (length, header_len) = if additional < 24 {
                (additional as usize, 1usize)
            } else if additional == 24 {
                if index + 1 >= encoded.len() {
                    break;
                }
                (encoded[index + 1] as usize, 2usize)
            } else {
                // Longer forms are not produced by this crate's encoder
                // for the values under test.
                break;
            };

            if major == 3 {
                longest = longest.max(length);
            }

            index += header_len;
            // Skip the value. Only the shapes this crate emits need to be
            // handled: byte strings, text strings, arrays and maps.
            match major {
                2 | 3 => index += length,
                4 => index += length, // an array of `length` items
                5 | 6 => break,       // a map: not walked
                _ => index += 0,
            }
        }

        longest
    }

    #[test]
    fn an_absence_observation_is_not_a_deletion_time() {
        // The struct has no deletion-time field at all. The compile-time
        // absence is the guarantee; this test documents it.
        let observation = AbsenceObservation {
            level: Level::User,
            secret_id: OpaqueSecretId::new("s-1"),
            version: 2,
            observer: ActorId::Agent(AgentId::new(
                PrincipalId::parse("8a0e2d4c-1b3f-4a5e-9c7d-0e1f2a3b4c5d").unwrap(),
            )),
            signer_key_id: "k-1".into(),
            observed_at: 1_700_000_000,
        };
        assert_eq!(observation.observed_at, 1_700_000_000);
    }

    fn audit_record(outcome: Outcome) -> AuditRecord {
        AuditRecord {
            actor: PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap(),
            signer_key_id: "admin-2026".to_string(),
            component: AuditComponent::CommandLine,
            operation: AuditOperation::Put,
            target: Some(AuditTarget::Record {
                vault: VaultId::new("vault-1"),
                level: Level::User,
                secret: OpaqueSecretId::new("db-password"),
                version: 3,
            }),
            outcome,
            exit_code: 0,
            observed_at: 1_700_000_000,
            prev_digest: Some([7u8; 32]),
            acceptance: None,
        }
    }

    /// Every text value in the encoded record.
    fn texts(value: &ciborium::value::Value, out: &mut Vec<String>) {
        match value {
            ciborium::value::Value::Text(text) => out.push(text.clone()),
            ciborium::value::Value::Array(items) => {
                for item in items {
                    texts(item, out);
                }
            }
            ciborium::value::Value::Map(entries) => {
                for (key, item) in entries {
                    texts(key, out);
                    texts(item, out);
                }
            }
            _ => {}
        }
    }

    /// FR-046, asserted over the bytes rather than over the field list.
    ///
    /// A reader trusts this by looking at the type; a reviewer should not have to.
    /// The walk is what catches the day someone adds a `details: String` field and
    /// a caller formats a token into it.
    #[test]
    fn an_encoded_audit_record_contains_no_secret_shaped_value() {
        // The shapes a secret would arrive in, including the fixture's password.
        const FIXTURE_PASSWORD: &str = "correct-horse-battery-staple";
        let looks_like_base64 = |text: &str| {
            text.len() >= 40
                && text
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        };
        let looks_like_hex =
            |text: &str| text.len() >= 40 && text.chars().all(|c| c.is_ascii_hexdigit());

        let encoded = crate::cbor::encode(&audit_record(Outcome::Success)).unwrap();
        let value: ciborium::value::Value = crate::cbor::decode(&encoded).unwrap();
        let mut found = Vec::new();
        texts(&value, &mut found);

        assert!(
            found.iter().any(|text| text == "db-password"),
            "the walk must see the record's own identifiers, or it proves nothing: {found:?}"
        );
        for text in &found {
            assert!(
                !text.starts_with("ksp-")
                    && !text.starts_with("v1.")
                    && !text.starts_with("Bearer "),
                "a value carries a token prefix: {text}"
            );
            assert!(
                !looks_like_base64(text),
                "a value looks like base64 key material: {text}"
            );
            assert!(
                !looks_like_hex(text),
                "a value looks like hex key material: {text}"
            );
            assert_ne!(
                text, FIXTURE_PASSWORD,
                "a value carries the fixture password"
            );
        }
    }

    /// The canonical encoding is what the signature covers, so it must be stable.
    #[test]
    fn an_audit_record_encodes_deterministically() {
        let first = crate::cbor::encode(&audit_record(Outcome::Success)).unwrap();
        let second = crate::cbor::encode(&audit_record(Outcome::Success)).unwrap();
        assert_eq!(first, second, "two encodings of one record must agree");

        let changed = crate::cbor::encode(&audit_record(Outcome::Failure)).unwrap();
        assert_ne!(
            first, changed,
            "the outcome is part of what is signed, so it must change the bytes"
        );
    }

    /// The target renders from its own typed fields, never from a stored string
    /// that could disagree with them (FR-039).
    #[test]
    fn an_audit_target_renders_from_its_identifiers() {
        let target = AuditTarget::Record {
            vault: VaultId::new("vault-1"),
            level: Level::Agent(AgentId::parse("1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f").unwrap()),
            secret: OpaqueSecretId::new("db-password"),
            version: 7,
        };
        assert_eq!(
            target.label(),
            "vault-1/agent-1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f/db-password/7"
        );
        assert_eq!(AuditTarget::Deployment.label(), "deployment");
        assert_eq!(AuditComponent::Sweeper.label(), "sweeper");
        assert_eq!(AuditOperation::Deliver.label(), "deliver");
    }
}
