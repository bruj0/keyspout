//! The signed audit record and the per-writer chain it lives in.
//!
//! # Why the chain is per writer
//!
//! Two principals write to this log — the admin's CLI and the sweeper share no
//! lock, and neither shares one with an agent process. A single linear chain would
//! have both claiming the same predecessor, and whichever append won would leave
//! the other's record a fork that a verifier either reports or silently drops
//! (Misfit X). Each writer therefore owns a directory and a chain inside it, and
//! the order *between* two chains is a timestamp claim rather than something this
//! build can prove (FR-053).
//!
//! # What the chain does and does not prove
//!
//! A record carries the digest of the record it followed, and the signature covers
//! that digest, so editing or reordering one record breaks the link at exactly that
//! index (Misfit R). What the chain cannot prove is that its own tail is complete:
//! deleting the last records leaves a shorter valid chain. Only a head digest kept
//! outside the log answers that, and saying so is cheaper than implying otherwise
//! (FR-051).
//!
//! # Framing
//!
//! A segment is a file of framed records — a big-endian `u32` length followed by
//! that many canonical CBOR bytes — so a reader streams in record order with
//! bounded memory instead of loading a segment to find one page (NFR-006). A
//! partial trailing frame is a truncated append and is reported as one rather than
//! decoded as a shorter record.

use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use ksp_types::cbor;
use ksp_types::evidence::{AuditComponent, AuditRecord};
use ksp_types::metadata::PrincipalId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::signing::{EvidenceError, EvidenceSignature, EvidenceSigningKey, sign, verify};

/// The domain an audit record is signed under.
///
/// Re-exported from the shared registry rather than re-declared: the registry is
/// the one place a prefix is defined, so an audit record and a deletion report
/// cannot end up sharing a domain by two files each writing their own string.
pub const AUDIT_DOMAIN: &str = "keyspout-audit-record-v1";

#[derive(Serialize)]
struct AuditSubject<'a> {
    domain: &'a str,
    record: &'a AuditRecord,
}

/// An audit record with its writer's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAuditRecord {
    /// The domain this signature was made under.
    pub domain: String,
    /// What the writer claims.
    pub record: AuditRecord,
    /// The writer's signature.
    pub signature: EvidenceSignature,
}

impl SignedAuditRecord {
    /// Sign one record.
    pub fn sign(writer: &EvidenceSigningKey, record: AuditRecord) -> Result<Self, EvidenceError> {
        let subject = AuditSubject {
            domain: AUDIT_DOMAIN,
            record: &record,
        };
        let signature = sign(writer.key(), AUDIT_DOMAIN, &subject)?;
        Ok(Self {
            domain: AUDIT_DOMAIN.to_owned(),
            record,
            signature,
        })
    }

    /// Verify the writer's signature.
    ///
    /// The carried domain is compared before the signature is checked, so a
    /// signature made under another domain is reported as foreign evidence rather
    /// than as a bad signature.
    pub fn verify(&self, writer: &VerifyingKey) -> Result<(), EvidenceError> {
        let subject = AuditSubject {
            domain: &self.domain,
            record: &self.record,
        };
        verify(
            writer,
            AUDIT_DOMAIN,
            &subject,
            &self.domain,
            &self.signature,
        )
    }

    /// The digest the *next* record must name to follow this one.
    ///
    /// It is the hash of the signed payload plus its domain — never of the
    /// signature, which is not part of what the writer claims (a second signature
    /// over the same claim must not look like a different record). The domain is
    /// included so a record from another kind of evidence cannot be spliced into
    /// the chain even if its payload happened to encode identically.
    pub fn digest(&self) -> [u8; 32] {
        let subject = AuditSubject {
            domain: &self.domain,
            record: &self.record,
        };
        // The subject is `Serialize` by construction, so this cannot fail for any
        // record this type holds; a failure would mean a value that cannot be
        // encoded at all, which no `AuditRecord` contains.
        let bytes = cbor::encode(&subject).unwrap_or_else(|_| Vec::from(self.domain.as_bytes()));
        Sha256::digest(&bytes).into()
    }

    /// The canonical bytes written to a segment.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EvidenceError> {
        cbor::encode(self).map_err(|_| EvidenceError::Encoding)
    }

    /// Parse one framed record body.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EvidenceError> {
        cbor::decode(bytes).map_err(|_| EvidenceError::Encoding)
    }

    /// The domain string this type is pinned to.
    pub fn domain() -> &'static str {
        AUDIT_DOMAIN
    }
}

/// Why a chain operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// The chain directory could not be created.
    #[error("the audit directory could not be created: {path}")]
    Directory {
        /// The path that failed.
        path: PathBuf,
    },
    /// A segment could not be read.
    #[error("the audit segment could not be read: {path}")]
    Read {
        /// The path that failed.
        path: PathBuf,
    },
    /// A record could not be encoded, signed or appended.
    #[error("the audit record could not be appended: {path}")]
    Append {
        /// The path that failed.
        path: PathBuf,
    },
    /// A segment contains bytes that are not a framed record.
    #[error("the audit segment is not a sequence of framed records: {path}")]
    Malformed {
        /// The path that failed.
        path: PathBuf,
    },
    /// The record names a different signing key than the one appending it.
    ///
    /// A record whose payload says one key while another key signed it is the
    /// attribution mistake this subsystem exists to make impossible, so the two are
    /// compared before anything is written.
    #[error("the record names a signer other than the key appending it")]
    Signer,
    /// The signer's key ID cannot name a segment.
    ///
    /// The label comes from a pin, and a pin is data: letting it contain `/` or
    /// `..` would let a pin decide which file is written.
    #[error("the signer key ID cannot name an audit segment")]
    Writer,
}

/// Where the chain broke, for a verifier that must name the link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Break {
    /// The record's signature does not verify under the pinned key.
    Signature {
        /// Zero-based index of the record in its segment.
        index: usize,
    },
    /// The record names a predecessor the chain does not contain.
    Dangling {
        /// Zero-based index of the record whose link is dangling.
        index: usize,
    },
    /// Two records name the same predecessor, so the chain forks here.
    Fork {
        /// Index of the first record on the branch the walk was following.
        index: usize,
        /// Index of the record that claims the same predecessor.
        other: usize,
    },
    /// A record with no predecessor appears after the first, so a second root was
    /// appended.
    SecondRoot {
        /// Zero-based index of the record.
        index: usize,
    },
}

impl Break {
    /// One sentence naming the link, for a report a human reads.
    pub fn describe(&self) -> String {
        match self {
            Self::Signature { index } => {
                format!("signature at index {index} does not verify under its pinned key")
            }
            Self::Dangling { index } => {
                format!("the link at index {index} names a predecessor this chain does not contain")
            }
            Self::Fork { index, other } => {
                format!("two records name one predecessor: indices {index} and {other}")
            }
            Self::SecondRoot { index } => {
                format!("a second root record appears at index {index}")
            }
        }
    }
}

/// What verification found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChain {
    /// The number of records the segment contains.
    pub records: usize,
    /// The digest of the last record the walk could reach, when it reached one.
    pub head: Option<[u8; 32]>,
    /// Where the chain broke, if it did.
    pub broken: Option<Break>,
}

impl VerifiedChain {
    /// Whether every record verified and every link was found.
    pub fn is_intact(&self) -> bool {
        self.broken.is_none()
    }
}

/// The per-writer chains under one audit root.
#[derive(Debug, Clone)]
pub struct AuditChain {
    root: PathBuf,
}

impl AuditChain {
    /// The chains under `root` (`KSP_HOME/audit`).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory one principal writes into.
    pub fn writer_root(&self, writer: PrincipalId) -> PathBuf {
        self.root.join(writer.to_string())
    }

    /// The segment one signer appends to, inside its writer's directory.
    ///
    /// The directory answers *whose log this is*, and the segment answers *which
    /// key* wrote it. The two are named by the same principal on purpose: a
    /// directory is `0700` and only its owner can read the tail a link needs, so a
    /// record about the tenant signed by the admin's key belongs in the admin's
    /// chain. The subject stays in [`AuditRecord::actor`], which is what a
    /// `--principal` view filters on.
    pub fn segment(&self, actor: PrincipalId, signer_key_id: &str) -> PathBuf {
        self.writer_root(actor)
            .join(format!("segment-{signer_key_id}.cbor"))
    }

    /// Append one record to one signer's chain and return the new digest.
    ///
    /// The append is the caller's durability point: the file is synced and the
    /// directory synced on creation before this returns, so a record this function
    /// reported is on disk. The predecessor digest is read from the segment's tail
    /// here rather than by the caller, so a caller cannot append a stale link.
    ///
    /// The directory is the *actor's*, which is the one-writer case: every caller
    /// that appends about its own principal.
    ///
    /// # The directory is the writer's, not the subject's
    ///
    /// [`Self::append_for`] is the form a host with more than one principal needs.
    /// A chain directory is `0700` and its owner is the only account that may read
    /// or append to it, so the admin cannot link a record into the tenant's
    /// directory even though the record is about the tenant's record: the link is
    /// read from the tail, and the tail is not the admin's to read. `actor` stays
    /// the subject — that is what a `--principal` view filters on — while the
    /// directory follows the key that signs.
    pub fn append(
        &self,
        writer: &EvidenceSigningKey,
        actor: PrincipalId,
        signer_key_id: &str,
        record: AuditRecord,
    ) -> Result<[u8; 32], ChainError> {
        self.append_for(writer, actor, actor, signer_key_id, record)
    }

    /// Append one record about `actor`, signed by `writer`, into `writer`'s chain.
    ///
    /// Two principals, one record: `actor` is whose authority or whose record the
    /// operation concerns, and `writer_principal` is the account whose key signs it.
    /// The directory belongs to the second, because that is the one the kernel lets
    /// read its own tail and no other.
    pub fn append_for(
        &self,
        writer: &EvidenceSigningKey,
        writer_principal: PrincipalId,
        actor: PrincipalId,
        signer_key_id: &str,
        record: AuditRecord,
    ) -> Result<[u8; 32], ChainError> {
        let path = self.segment(writer_principal, signer_key_id);
        if !is_safe_label(signer_key_id) {
            return Err(ChainError::Writer);
        }
        if record.signer_key_id != signer_key_id {
            return Err(ChainError::Signer);
        }
        ensure_directory(&self.writer_root(writer_principal))?;

        let previous = self
            .read_segment(&path)?
            .last()
            .map(SignedAuditRecord::digest);
        // Both statements of the record's subject come from one place: the caller
        // names the actor it is writing about, and the path it landed in names the
        // writer. A record whose `actor` disagreed with the argument would be a
        // record the `--principal` view files under a different principal than the
        // caller thought.
        let record = AuditRecord {
            actor,
            prev_digest: previous,
            ..record
        };
        let signed = SignedAuditRecord::sign(writer, record)
            .map_err(|_| ChainError::Append { path: path.clone() })?;
        let body = signed
            .to_bytes()
            .map_err(|_| ChainError::Append { path: path.clone() })?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|_| ChainError::Append { path: path.clone() })?;
        let length =
            u32::try_from(body.len()).map_err(|_| ChainError::Append { path: path.clone() })?;
        file.write_all(&length.to_be_bytes())
            .and_then(|()| file.write_all(&body))
            .and_then(|()| file.sync_all())
            .map_err(|_| ChainError::Append { path: path.clone() })?;

        Ok(signed.digest())
    }

    /// Every record one signer has appended, in file order.
    pub fn read(
        &self,
        actor: PrincipalId,
        signer_key_id: &str,
    ) -> Result<Vec<SignedAuditRecord>, ChainError> {
        if !is_safe_label(signer_key_id) {
            return Err(ChainError::Writer);
        }
        self.read_segment(&self.segment(actor, signer_key_id))
    }

    /// Verify one writer's chain: every signature under `key`, every link present,
    /// no fork, one root.
    ///
    /// A fork is reported rather than resolved: two records that name the same
    /// predecessor are both evidence, and choosing one would be this function
    /// writing history (FR-053).
    pub fn verify(
        &self,
        actor: PrincipalId,
        signer_key_id: &str,
        key: &VerifyingKey,
    ) -> Result<VerifiedChain, ChainError> {
        let records = self.read(actor, signer_key_id)?;
        Ok(verify_records(&records, key))
    }

    fn read_segment(&self, path: &Path) -> Result<Vec<SignedAuditRecord>, ChainError> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            // A writer that has never appended has no segment, which is an empty
            // chain rather than a failure: the first append creates it.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => {
                return Err(ChainError::Read {
                    path: path.to_path_buf(),
                });
            }
        };

        // One implementation of the frame format, shared with the view: a chain read
        // refuses a torn tail, because a record it cannot see might be the one the
        // next link names.
        let mut records = Vec::new();
        for frame in frames(&bytes) {
            let Frame::Body(body) = frame else {
                return Err(ChainError::Malformed {
                    path: path.to_path_buf(),
                });
            };
            records.push(SignedAuditRecord::from_bytes(body).map_err(|_| {
                ChainError::Malformed {
                    path: path.to_path_buf(),
                }
            })?);
        }
        Ok(records)
    }
}

/// Verify a segment's records without touching the filesystem.
pub fn verify_records(records: &[SignedAuditRecord], key: &VerifyingKey) -> VerifiedChain {
    let total = records.len();
    // The index of the record that first named each predecessor digest, so a second
    // record naming the same one is detectable in one pass.
    // The index of the record that first followed each predecessor, so a second
    // record naming the same one is a fork between the two claimants.
    let mut claimants: std::collections::HashMap<[u8; 32], usize> =
        std::collections::HashMap::with_capacity(total);

    let mut head: Option<[u8; 32]> = None;
    let mut expected: Option<[u8; 32]> = None;

    for (index, signed) in records.iter().enumerate() {
        if signed.verify(key).is_err() {
            return VerifiedChain {
                records: total,
                head,
                broken: Some(Break::Signature { index }),
            };
        }

        let digest = signed.digest();
        match signed.record.prev_digest {
            None if index != 0 => {
                return VerifiedChain {
                    records: total,
                    head,
                    broken: Some(Break::SecondRoot { index }),
                };
            }
            None => {}
            Some(previous) => {
                if let Some(first) = claimants.get(&previous) {
                    return VerifiedChain {
                        records: total,
                        head,
                        broken: Some(Break::Fork {
                            index: *first,
                            other: index,
                        }),
                    };
                }
                if Some(previous) != expected {
                    // The link names a record this walk cannot reach: either the
                    // predecessor was never written (an append that lost its
                    // predecessor) or it was removed.
                    return VerifiedChain {
                        records: total,
                        head,
                        broken: Some(Break::Dangling { index }),
                    };
                }
            }
        }

        if let Some(previous) = signed.record.prev_digest {
            claimants.insert(previous, index);
        }
        expected = Some(digest);
        head = Some(digest);
    }

    VerifiedChain {
        records: total,
        head,
        broken: None,
    }
}

/// Whether a key ID can be used as a file-name component.
///
/// A pin's key ID is data read from a file, so it is checked rather than trusted:
/// a label containing a separator or a parent reference would otherwise choose the
/// path an append writes to.
fn is_safe_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 128
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && label != "."
        && label != ".."
}

/// Create `path` owner-only, tolerating an existing directory.
///
/// The mode is set explicitly after creation because `DirBuilder::mode` is masked
/// by the umask; a log another principal can read is the confidentiality mistake
/// this whole tree exists to avoid.
fn ensure_directory(path: &Path) -> Result<(), ChainError> {
    if path.is_dir() {
        return Ok(());
    }
    // Not recursive: the audit root itself is a protected root created by the
    // layout table, and a chain that quietly created it with the caller's umask
    // would be the drift that table exists to prevent. A missing root is a
    // refusal, not a directory this function invents.
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| ChainError::Directory {
            path: path.to_path_buf(),
        })?;
    std::fs::set_permissions(path, PermissionsExt::from_mode(0o700)).map_err(|_| {
        ChainError::Directory {
            path: path.to_path_buf(),
        }
    })
}

// ---------------------------------------------------------------------------
// Framing, and the records this build cannot type
// ---------------------------------------------------------------------------

/// One frame of a segment file: a body, or the bytes at the end that are not one.
///
/// The framing is a four-byte big-endian length followed by that many bytes. A body
/// that does not decode is still a frame — the length was intact, so the walk can
/// continue and report the next one; only a length or a body that runs past the end of
/// the file stops it (FR-042: counted and printed, never skipped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// A complete frame body, as the writer framed it.
    Body(&'a [u8]),
    /// Bytes that do not form a complete frame, at this index.
    Torn {
        /// The index the torn frame starts at.
        index: usize,
        /// What the bytes say is wrong, so a rendering does not invent one cause.
        cause: TornCause,
    },
}

/// Why the walk stopped, in the terms the bytes support.
///
/// A partial write and a corrupt length both leave a frame that cannot be read, but they
/// are different findings: only the first is an append that lost its tail. Saying
/// "the append lost its tail" for both would attribute a cause the reader cannot know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TornCause {
    /// The length prefix, or the body it names, is not in the file.
    Truncated,
    /// The length prefix is larger than any record this build writes.
    Oversized,
}

impl TornCause {
    /// The finding, worded so it names what was seen and not who caused it.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Truncated => "a truncated frame: the length names a body the file does not hold",
            Self::Oversized => "a frame length larger than any record this build writes",
        }
    }
}

/// Split a segment's bytes into frames, tolerantly and without copying a body.
///
/// The one implementation of the frame format for readers that hold the file in
/// memory; [`SegmentReader`] streams the same format for verification, which must not
/// hold even one segment at once (NFR-009).
pub fn frames(bytes: &[u8]) -> Vec<Frame<'_>> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    let mut index = 0usize;
    while cursor < bytes.len() {
        let Some(header) = bytes.get(cursor..cursor.saturating_add(4)) else {
            out.push(Frame::Torn {
                index,
                cause: TornCause::Truncated,
            });
            return out;
        };
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        cursor += 4;
        // A length field is data read from a file: a corrupt or hostile one must not
        // decide a read past the buffer, and the reader refuses to believe a size the
        // file cannot hold.
        if length > MAX_FRAME_BYTES {
            out.push(Frame::Torn {
                index,
                cause: TornCause::Oversized,
            });
            return out;
        }
        let Some(body) = bytes.get(cursor..cursor.saturating_add(length)) else {
            out.push(Frame::Torn {
                index,
                cause: TornCause::Truncated,
            });
            return out;
        };
        out.push(Frame::Body(body));
        cursor += length;
        index += 1;
    }
    out
}

/// One field of a record this build cannot type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawField {
    /// The field name the writer used.
    pub name: String,
    /// What may be printed for it.
    pub value: RawFieldValue,
}

/// What a reader may print for a field it has no type for.
///
/// The rule is by type, not by name. A record this build does not know was written by a
/// writer that has not agreed to this build's no-secret rule (FR-046), so **no text and
/// no bytes are printed**: a text value is reported by length, a byte string by size, a
/// structure by shape. Numbers and flags are printed, because they are the only values
/// whose content cannot be material on their own, and a field whose *name* announces
/// material is refused even then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RawFieldValue {
    /// A text value, reported by its length and never by its content.
    Text {
        /// How many characters the writer's text holds.
        chars: usize,
    },
    /// An integer.
    Integer(i64),
    /// A boolean.
    Flag(bool),
    /// A byte string, reported by its length and never by its bytes.
    Bytes(usize),
    /// An array or a map, reported by its shape.
    Nested {
        /// `array` or `map`.
        kind: &'static str,
        /// How many entries it holds.
        len: usize,
    },
    /// A value of a type this projection does not print.
    Other(&'static str),
    /// A field whose name says it could carry secret material.
    Redacted,
}

/// Field names that are never printed, whatever their type.
///
/// This build's writers cannot place material in a record (FR-046). An unknown kind is
/// a writer this build does not know, which is exactly where such a field could appear,
/// so the projection refuses the names that announce one instead of trusting the shape.
pub const REDACTED_FIELD_MARKERS: [&str; 7] = [
    "secret",
    "value",
    "token",
    "password",
    "passphrase",
    "key",
    "plaintext",
];

/// One record this build cannot type, with the fields it carries.
///
/// FR-040: a kind this build does not recognise is printed as its kind plus its raw
/// fields rather than omitted. The projection is deliberately shallow — a name and a
/// printable value per top-level field — so an unknown payload cannot smuggle bytes
/// into a rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawRecord {
    /// The domain the writer named, which is the kind this build does not know.
    pub domain: String,
    /// The payload's top-level fields, in the writer's order.
    pub fields: Vec<RawField>,
}

impl RawRecord {
    /// Project a framed body, or `None` when it is not even a CBOR map.
    pub fn project(body: &[u8]) -> Option<Self> {
        let value = cbor::decode_value(body).ok()?;
        let cbor::RawValue::Map(entries) = value else {
            return None;
        };
        let find = |name: &str| {
            entries.iter().find_map(|(key, value)| match key {
                cbor::RawValue::Text(key) if key == name => Some(value),
                _ => None,
            })
        };
        let domain = match find("domain") {
            Some(cbor::RawValue::Text(domain)) => domain.clone(),
            // A record with no domain is a shape this build does not know either; the
            // kind says so rather than inventing one.
            _ => "unnamed".to_string(),
        };
        // A known envelope nests the payload under `record`; a future one may not, in
        // which case every top-level field except the signature is the payload.
        let payload: Vec<(cbor::RawValue, cbor::RawValue)> = match find("record") {
            Some(cbor::RawValue::Map(record)) => record.clone(),
            _ => entries
                .iter()
                .filter(
                    |(key, _)| !matches!(key, cbor::RawValue::Text(name) if name == "signature"),
                )
                .cloned()
                .collect(),
        };
        let fields = payload
            .iter()
            .filter_map(|(key, value)| {
                let cbor::RawValue::Text(name) = key else {
                    return None;
                };
                Some(RawField {
                    name: name.clone(),
                    value: project_value(name, value),
                })
            })
            .collect();
        Some(Self { domain, fields })
    }
}

/// What may be printed for one field, by name and then by type.
fn project_value(name: &str, value: &cbor::RawValue) -> RawFieldValue {
    let lowered = name.to_ascii_lowercase();
    if REDACTED_FIELD_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return RawFieldValue::Redacted;
    }
    match value {
        cbor::RawValue::Text(text) => RawFieldValue::Text {
            chars: text.chars().count(),
        },
        cbor::RawValue::Integer(integer) => i64::try_from(*integer).map_or(
            RawFieldValue::Other("large integer"),
            RawFieldValue::Integer,
        ),
        cbor::RawValue::Bool(flag) => RawFieldValue::Flag(*flag),
        cbor::RawValue::Bytes(bytes) => RawFieldValue::Bytes(bytes.len()),
        cbor::RawValue::Array(items) => RawFieldValue::Nested {
            kind: "array",
            len: items.len(),
        },
        cbor::RawValue::Map(entries) => RawFieldValue::Nested {
            kind: "map",
            len: entries.len(),
        },
        cbor::RawValue::Null => RawFieldValue::Other("null"),
        _ => RawFieldValue::Other("float"),
    }
}

// ---------------------------------------------------------------------------
// Verification against pinned public material
// ---------------------------------------------------------------------------

/// The largest frame the reader will allocate for.
///
/// A length field is data read from a file, so a corrupt or hostile one must not
/// decide an allocation. A record is a few hundred bytes; a megabyte is three
/// orders of magnitude of headroom.
const MAX_FRAME_BYTES: usize = 1 << 20;

/// One framed segment, read on demand.
///
/// Verification streams: a record is decoded, checked and dropped, so the log
/// never has to fit in memory (NFR-009). What stays is one 32-byte digest per
/// record, because telling a fork from a dangling link needs the predecessors the
/// walk has already passed.
pub struct SegmentReader {
    file: std::io::BufReader<std::fs::File>,
    path: PathBuf,
    finished: bool,
}

impl SegmentReader {
    /// Open one segment, or `None` when the writer has never appended.
    pub fn open(path: &Path) -> Result<Option<Self>, ChainError> {
        match std::fs::File::open(path) {
            Ok(file) => Ok(Some(Self {
                file: std::io::BufReader::new(file),
                path: path.to_path_buf(),
                finished: false,
            })),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(ChainError::Read {
                path: path.to_path_buf(),
            }),
        }
    }

    /// The next 4-byte header, `None` at a clean end, `Malformed` at a torn one.
    fn header(&mut self) -> Result<Option<[u8; 4]>, ChainError> {
        use std::io::Read as _;

        let mut header = [0u8; 4];
        let mut filled = 0usize;
        while filled < header.len() {
            match self.file.read(&mut header[filled..]) {
                Ok(0) if filled == 0 => return Ok(None),
                // A partial header is a torn append, not a shorter record.
                Ok(0) => {
                    return Err(ChainError::Malformed {
                        path: self.path.clone(),
                    });
                }
                Ok(read) => filled += read,
                Err(_) => {
                    return Err(ChainError::Read {
                        path: self.path.clone(),
                    });
                }
            }
        }
        Ok(Some(header))
    }

    fn frame(&mut self) -> Result<Option<SignedAuditRecord>, ChainError> {
        use std::io::Read as _;

        let Some(header) = self.header()? else {
            self.finished = true;
            return Ok(None);
        };
        let length = u32::from_be_bytes(header) as usize;
        if length > MAX_FRAME_BYTES {
            self.finished = true;
            return Err(ChainError::Malformed {
                path: self.path.clone(),
            });
        }
        let mut body = vec![0u8; length];
        if self.file.read_exact(&mut body).is_err() {
            self.finished = true;
            return Err(ChainError::Malformed {
                path: self.path.clone(),
            });
        }
        match SignedAuditRecord::from_bytes(&body) {
            Ok(record) => Ok(Some(record)),
            Err(_) => {
                self.finished = true;
                Err(ChainError::Malformed {
                    path: self.path.clone(),
                })
            }
        }
    }
}

impl Iterator for SegmentReader {
    type Item = Result<SignedAuditRecord, ChainError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        match self.frame() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(error) => {
                self.finished = true;
                Some(Err(error))
            }
        }
    }
}

impl AuditChain {
    /// The labels of the segments one actor has written, sorted.
    ///
    /// The label is a path component, never a key: verification uses it to find
    /// files, and takes the signing key from a pin (Misfit W).
    pub fn labels(&self, actor: PrincipalId) -> Result<Vec<String>, ChainError> {
        let directory = self.writer_root(actor);
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => {
                return Err(ChainError::Read { path: directory });
            }
        };
        let mut labels = entries
            .flatten()
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.strip_prefix("segment-"))
                    .and_then(|rest| rest.strip_suffix(".cbor"))
                    .map(str::to_owned)
            })
            .collect::<Vec<_>>();
        labels.sort();
        Ok(labels)
    }

    /// A streaming reader over one segment.
    pub fn reader(
        &self,
        actor: PrincipalId,
        label: &str,
    ) -> Result<Option<SegmentReader>, ChainError> {
        if !is_safe_label(label) {
            return Err(ChainError::Writer);
        }
        SegmentReader::open(&self.segment(actor, label))
    }
}

/// What a pinned key is: the role bounds which records it may sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRole {
    /// The admin's key. Administration and sweep runs.
    Admin,
    /// The tenant's key. Its own command-line records.
    User,
    /// An enrolled agent's key. Agent records only.
    Agent,
}

/// What the pins say about a key at verification time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    /// The key is the one this pin currently authorises.
    Current,
    /// The key's grant was withdrawn. The signature still verifies; a revoked
    /// record is reported as such and never counted as equivalent to a current one.
    Revoked {
        /// The policy revision that removed the grant.
        policy_revision: u64,
        /// When the withdrawal was recorded, when this host's ledger holds the time.
        at: Option<u64>,
    },
}

/// One public key the operator pinned, outside the log.
#[derive(Debug, Clone)]
pub struct PinnedKey {
    /// The key ID the pin names.
    pub key_id: String,
    /// The public key itself.
    pub key: VerifyingKey,
    /// The principal the pin belongs to.
    pub principal: Option<PrincipalId>,
    /// What the key may sign.
    pub role: PinRole,
    /// Whether the key is current or its grant was withdrawn.
    pub status: PinStatus,
}

impl PinnedKey {
    /// Whether this key may sign one record.
    ///
    /// The rule is the component the record names, not a claim the record makes
    /// about itself: a sweeper record is the admin's, an agent record is an
    /// enrolled agent's, and a command-line record is the admin's on the subject's
    /// behalf or the subject's own key. An agent key signing a command-line record,
    /// or a tenant key signing for another principal, is the misattribution FR-049
    /// asks verification to name.
    pub fn may_sign(&self, record: &AuditRecord) -> bool {
        match (record.component, self.role) {
            (AuditComponent::Sweeper, PinRole::Admin) => true,
            (AuditComponent::Agent, PinRole::Agent) => true,
            (AuditComponent::CommandLine, PinRole::Admin) => true,
            (AuditComponent::CommandLine, PinRole::User) => self.principal == Some(record.actor),
            _ => false,
        }
    }
}

/// The public material verification resolves against.
#[derive(Debug, Clone, Default)]
pub struct Pins {
    keys: Vec<PinnedKey>,
}

impl Pins {
    /// Build a pin set.
    pub fn new(keys: Vec<PinnedKey>) -> Self {
        Self { keys }
    }

    /// The pins, for a caller that wants to report what it resolved from.
    pub fn keys(&self) -> &[PinnedKey] {
        &self.keys
    }
}

/// What verification decided about one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribution {
    /// A pinned key signed it and may sign this record.
    Verified {
        /// The key that verified.
        key_id: String,
        /// The key's status at verification time.
        status: PinStatus,
    },
    /// No pin holds the named signing key.
    Unpinned,
    /// A pinned key signed it, and that key may not sign this record, or the
    /// record names one key while another pinned key signed the bytes.
    Mismatch {
        /// The pinned key whose signature verified.
        signer: String,
    },
    /// The named key is pinned and the bytes do not verify under it.
    Invalid {
        /// The key the record names.
        signer: String,
    },
}

/// Resolve one record's signature against the pins.
///
/// The key is chosen from the pins, never from the record: the record's
/// `signer_key_id` is matched against pinned key IDs, and a record whose claim
/// names nothing pinned is reported unpinned whatever its bytes verify under
/// (Misfit W).
pub fn attribute(signed: &SignedAuditRecord, pins: &Pins) -> Attribution {
    let claimed = pins
        .keys
        .iter()
        .filter(|pin| pin.key_id == signed.record.signer_key_id)
        .collect::<Vec<_>>();

    if !claimed.is_empty() {
        for pin in claimed {
            if signed.verify(&pin.key).is_ok() {
                return if pin.may_sign(&signed.record) {
                    Attribution::Verified {
                        key_id: pin.key_id.clone(),
                        status: pin.status,
                    }
                } else {
                    Attribution::Mismatch {
                        signer: pin.key_id.clone(),
                    }
                };
            }
        }
        // The claim names a pin and the bytes are not that pin's signature. This is
        // the tampered case, and it is not the same finding as an unknown signer.
        return Attribution::Invalid {
            signer: signed.record.signer_key_id.clone(),
        };
    }

    // The claim names nothing pinned. If a pin that *may* sign this record verified
    // the bytes, the record's own naming is wrong, which is a mismatch rather than
    // a stranger at the gate.
    for pin in pins.keys.iter().filter(|pin| pin.may_sign(&signed.record)) {
        if signed.verify(&pin.key).is_ok() {
            return Attribution::Mismatch {
                signer: pin.key_id.clone(),
            };
        }
    }
    Attribution::Unpinned
}

/// Per-class counts, so every finding class can be reported apart (T051).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerifyCounts {
    /// Records a pinned key signed with the authority its component requires.
    pub verified: usize,
    /// Records that verify under a key whose grant was withdrawn.
    pub revoked: usize,
    /// Records whose named signer no pin holds.
    pub unpinned: usize,
    /// Records whose signature is genuine but not authorised for the record.
    pub mismatch: usize,
    /// Records whose named key is pinned and whose bytes do not verify.
    pub invalid: usize,
}

impl VerifyCounts {
    /// Records that counted as verified, whether or not the key is still current.
    pub fn attributed(&self) -> usize {
        self.verified
    }
}

/// What one segment's verification found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// How many records the segment holds.
    pub records: usize,
    /// The digest of the last record the link walk reached.
    pub head: Option<[u8; 32]>,
    /// Where the link walk stopped, when it did.
    pub broken: Option<Break>,
    /// Whether the segment ends with bytes that are not a complete framed record.
    pub torn_tail: bool,
    /// The index the torn tail starts at, when there is one.
    pub torn_tail_at: Option<usize>,
    /// The signer that verified the first record, when one did.
    ///
    /// The file name is a path, not an identity: a segment named for the admin key
    /// may hold records another pinned key signed. Reporting the signer that
    /// actually verified keeps the head and the finding names honest (Misfit W).
    pub chain_signer: Option<String>,
    /// One count per finding class.
    pub counts: VerifyCounts,
    /// The first index in each class, so an operator has something to look at
    /// without the verifier holding every finding.
    pub first_unpinned: Option<usize>,
    /// The first record whose signature is genuine but not authorised.
    pub first_mismatch: Option<usize>,
    /// The first record whose signature does not verify.
    pub first_invalid: Option<usize>,
    /// The first record signed by a revoked key.
    pub first_revoked: Option<usize>,
}

impl VerifyReport {
    /// Whether every record verifies and the chain is unbroken.
    ///
    /// A revoked signer still verifies cryptographically; the caller decides
    /// whether to report that as a failure. This says only what the bytes prove.
    pub fn is_sound(&self) -> bool {
        self.broken.is_none()
            && !self.torn_tail
            && self.counts.unpinned == 0
            && self.counts.mismatch == 0
            && self.counts.invalid == 0
    }
}

/// Verify one segment, record by record, against the pins.
///
/// Signatures are checked for every record even after a link breaks: a tampered
/// record and a chain break are separate findings, and stopping at the first would
/// hide the others. The link walk stops at the first break, because past it there is
/// no expected predecessor left to check against.
pub fn verify_segment<I>(records: I, pins: &Pins) -> Result<VerifyReport, ChainError>
where
    I: IntoIterator<Item = Result<SignedAuditRecord, ChainError>>,
{
    let mut report = VerifyReport {
        records: 0,
        head: None,
        broken: None,
        torn_tail: false,
        torn_tail_at: None,
        chain_signer: None,
        counts: VerifyCounts::default(),
        first_unpinned: None,
        first_mismatch: None,
        first_invalid: None,
        first_revoked: None,
    };

    let mut claimants: std::collections::HashMap<[u8; 32], usize> =
        std::collections::HashMap::new();
    let mut expected: Option<[u8; 32]> = None;

    for item in records {
        let index = report.records;
        let signed = match item {
            Ok(record) => record,
            Err(ChainError::Malformed { .. }) => {
                // A torn frame is the last thing in the segment: an append that
                // lost its tail bytes, not a record to decrypt.
                report.torn_tail = true;
                report.torn_tail_at = Some(index);
                break;
            }
            Err(error) => return Err(error),
        };
        report.records += 1;

        match attribute(&signed, pins) {
            Attribution::Verified { status, key_id } => {
                report.counts.verified += 1;
                report.chain_signer.get_or_insert(key_id);
                if let PinStatus::Revoked { .. } = status {
                    report.counts.revoked += 1;
                    report.first_revoked.get_or_insert(index);
                }
            }
            Attribution::Unpinned => {
                report.counts.unpinned += 1;
                report.first_unpinned.get_or_insert(index);
            }
            Attribution::Mismatch { .. } => {
                report.counts.mismatch += 1;
                report.first_mismatch.get_or_insert(index);
            }
            Attribution::Invalid { .. } => {
                report.counts.invalid += 1;
                report.first_invalid.get_or_insert(index);
                // The record at this index is not the record its signature covers, so
                // no link that starts here can be trusted. The chain breaks at the
                // edited record, which is the index an operator needs (FR-049).
                if report.broken.is_none() {
                    report.broken = Some(Break::Signature { index });
                }
            }
        }

        if report.broken.is_some() {
            continue;
        }

        let digest = signed.digest();
        match signed.record.prev_digest {
            // A second root is two chains in one file, which is a break rather than
            // a shorter chain.
            None if index != 0 => {
                report.broken = Some(Break::SecondRoot { index });
                continue;
            }
            None => {}
            Some(previous) => {
                if let Some(first) = claimants.get(&previous) {
                    // Both claimants stay in the counts: the fork is reported, and
                    // neither record is dropped on the strength of the other (T051).
                    report.broken = Some(Break::Fork {
                        index: *first,
                        other: index,
                    });
                    continue;
                }
                if Some(previous) != expected {
                    report.broken = Some(Break::Dangling { index });
                    continue;
                }
            }
        }

        if let Some(previous) = signed.record.prev_digest {
            claimants.insert(previous, index);
        }
        expected = Some(digest);
        report.head = Some(digest);
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    // A test reports a failure by panicking, and the panic message is what says
    // why. The production code keeps the strict lints.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use ksp_types::evidence::{AuditComponent, AuditOperation, AuditTarget, Outcome};
    use ksp_types::metadata::{Level, OpaqueSecretId, VaultId};

    fn actor() -> PrincipalId {
        PrincipalId::parse("6f5a1c8e-3b2d-4f7a-9c1e-0a2b3c4d5e6f").unwrap()
    }

    fn other_actor() -> PrincipalId {
        PrincipalId::parse("1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f").unwrap()
    }

    fn record(outcome: Outcome) -> AuditRecord {
        AuditRecord {
            actor: actor(),
            signer_key_id: ADMIN.to_string(),
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
            prev_digest: None,
            acceptance: None,
        }
    }

    fn chain_in(directory: &tempfile::TempDir) -> AuditChain {
        AuditChain::new(directory.path().join("audit"))
    }

    fn writer() -> EvidenceSigningKey {
        EvidenceSigningKey::generate()
    }

    const ADMIN: &str = "admin-2026";

    /// Write frames the way an append does, so a tampering test edits the same
    /// on-disk shape the reader parses.
    fn write_frames(path: &Path, records: &[SignedAuditRecord]) {
        let mut bytes = Vec::new();
        for record in records {
            let body = record.to_bytes().unwrap();
            bytes.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(&body);
        }
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn a_fresh_chain_has_no_segment_and_reads_as_empty() {
        let directory = tempfile::tempdir().unwrap();
        let chain = chain_in(&directory);
        assert!(chain.read(actor(), ADMIN).unwrap().is_empty());
        assert!(!chain.segment(actor(), ADMIN).exists());
    }

    #[test]
    fn an_append_names_the_record_it_follows() {
        let directory = tempfile::tempdir().unwrap();
        let chain = chain_in(&directory);
        let key = writer();
        std::fs::create_dir_all(directory.path().join("audit")).unwrap();

        let first = chain
            .append(&key, actor(), ADMIN, record(Outcome::Success))
            .unwrap();
        let second = chain
            .append(&key, actor(), ADMIN, record(Outcome::Failure))
            .unwrap();
        assert_ne!(first, second, "two records have two digests");

        let records = chain.read(actor(), ADMIN).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].record.prev_digest, None);
        assert_eq!(
            records[1].record.prev_digest,
            Some(first),
            "the second record must name the first record's digest"
        );
        assert_eq!(records[1].digest(), second);
    }

    /// Misfit R: an edited record is not silently accepted.
    #[test]
    fn editing_one_record_breaks_the_chain_at_that_index() {
        let directory = tempfile::tempdir().unwrap();
        let chain = chain_in(&directory);
        let key = writer();
        std::fs::create_dir_all(directory.path().join("audit")).unwrap();

        for outcome in [Outcome::Success, Outcome::Success, Outcome::Success] {
            chain.append(&key, actor(), ADMIN, record(outcome)).unwrap();
        }

        let mut records = chain.read(actor(), ADMIN).unwrap();
        // Rewrite the middle record's outcome and re-sign with a key the verifier
        // does not pin: the signature is what breaks, at the edited index.
        let mut tampered = records[1].record.clone();
        tampered.outcome = Outcome::Failure;
        records[1] = SignedAuditRecord::sign(&EvidenceSigningKey::generate(), tampered).unwrap();
        write_frames(&chain.segment(actor(), ADMIN), &records);

        let verdict = chain.verify(actor(), ADMIN, &key.verifying_key()).unwrap();
        assert_eq!(
            verdict.broken,
            Some(Break::Signature { index: 1 }),
            "the verifier must name the edited link"
        );
        assert!(!verdict.is_intact());
    }

    /// Misfit R, second shape: dropping a record leaves a link that names nothing.
    #[test]
    fn a_removed_record_leaves_a_dangling_link() {
        let directory = tempfile::tempdir().unwrap();
        let chain = chain_in(&directory);
        let key = writer();
        std::fs::create_dir_all(directory.path().join("audit")).unwrap();

        for outcome in [Outcome::Success, Outcome::Failure, Outcome::Success] {
            chain.append(&key, actor(), ADMIN, record(outcome)).unwrap();
        }

        let mut records = chain.read(actor(), ADMIN).unwrap();
        records.remove(1);
        write_frames(&chain.segment(actor(), ADMIN), &records);

        let verdict = chain.verify(actor(), ADMIN, &key.verifying_key()).unwrap();
        assert_eq!(verdict.broken, Some(Break::Dangling { index: 1 }));
    }

    /// Misfit X: a fork is reported, with both claimants named, never resolved.
    #[test]
    fn two_records_that_follow_one_predecessor_are_reported_as_a_fork() {
        let key = writer();

        // The root, then two records that each name it: what two concurrent
        // appends to one segment produce.
        let root = SignedAuditRecord::sign(&key, record(Outcome::Success)).unwrap();
        let root_digest = root.digest();
        let mut left = record(Outcome::Success);
        left.prev_digest = Some(root_digest);
        let mut right = record(Outcome::Failure);
        right.prev_digest = Some(root_digest);

        let records = vec![
            root,
            SignedAuditRecord::sign(&key, left).unwrap(),
            SignedAuditRecord::sign(&key, right).unwrap(),
        ];

        let verdict = verify_records(&records, &key.verifying_key());
        assert_eq!(
            verdict.broken,
            Some(Break::Fork { index: 1, other: 2 }),
            "both branches are evidence; the verifier must not choose one"
        );
    }

    /// Misfit X, the other half: two writers never contend, so both chains are
    /// whole and neither truncates the other.
    #[test]
    fn two_writers_produce_two_segments_that_both_read_back() {
        let directory = tempfile::tempdir().unwrap();
        let chain = chain_in(&directory);
        let key = writer();
        std::fs::create_dir_all(directory.path().join("audit")).unwrap();

        for _ in 0..3 {
            chain
                .append(&key, actor(), ADMIN, record(Outcome::Success))
                .unwrap();
            chain
                .append(&key, other_actor(), ADMIN, record(Outcome::Failure))
                .unwrap();
        }

        assert_ne!(
            chain.segment(actor(), ADMIN),
            chain.segment(other_actor(), ADMIN),
            "one directory per actor"
        );
        assert_eq!(chain.read(actor(), ADMIN).unwrap().len(), 3);
        assert_eq!(chain.read(other_actor(), ADMIN).unwrap().len(), 3);
        assert!(
            chain
                .verify(actor(), ADMIN, &key.verifying_key())
                .unwrap()
                .is_intact()
        );
        assert!(
            chain
                .verify(other_actor(), ADMIN, &key.verifying_key())
                .unwrap()
                .is_intact()
        );
    }

    /// One actor can be represented by two keys — the admin's CLI and the tenant's
    /// own command act for the same principal UUID — and each keeps its own
    /// segment, so a chain is verifiable under exactly one key.
    #[test]
    fn two_signers_of_one_actor_do_not_share_a_segment() {
        let directory = tempfile::tempdir().unwrap();
        let chain = chain_in(&directory);
        let admin = writer();
        let tenant = writer();
        std::fs::create_dir_all(directory.path().join("audit")).unwrap();

        chain
            .append(&admin, actor(), ADMIN, record(Outcome::Success))
            .unwrap();
        let mut tenant_record = record(Outcome::Failure);
        tenant_record.signer_key_id = "user-2026".to_string();
        chain
            .append(&tenant, actor(), "user-2026", tenant_record)
            .unwrap();

        assert_ne!(
            chain.segment(actor(), ADMIN),
            chain.segment(actor(), "user-2026")
        );
        assert!(
            chain
                .verify(actor(), ADMIN, &admin.verifying_key())
                .unwrap()
                .is_intact()
        );
        assert!(
            chain
                .verify(actor(), "user-2026", &tenant.verifying_key())
                .unwrap()
                .is_intact()
        );
    }

    /// A record cannot be filed under a segment whose key did not sign it, so
    /// relabelling a record means moving it to a segment where it will not
    /// verify. Without this guard the actor/signer pair in the payload is a
    /// claim the chain never checks.
    #[test]
    fn a_record_claiming_another_signer_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let chain = chain_in(&directory);
        let admin = writer();
        std::fs::create_dir_all(directory.path().join("audit")).unwrap();

        let mut mismatched = record(Outcome::Success);
        mismatched.signer_key_id = "user-2026".to_string();
        let refused = chain.append(&admin, actor(), ADMIN, mismatched);

        assert!(matches!(refused, Err(ChainError::Signer)));
        assert!(
            chain
                .verify(actor(), ADMIN, &admin.verifying_key())
                .unwrap()
                .is_intact()
        );
    }

    /// The digest covers the claim, not the signature over it.
    #[test]
    fn the_digest_does_not_depend_on_which_key_signed() {
        let first = SignedAuditRecord::sign(&writer(), record(Outcome::Success)).unwrap();
        let second = SignedAuditRecord::sign(&writer(), record(Outcome::Success)).unwrap();
        assert_ne!(first.signature, second.signature);
        assert_eq!(first.digest(), second.digest());
    }

    /// The domain is a signed field: a record relabelled as another kind of
    /// evidence is foreign, not merely badly signed.
    #[test]
    fn a_record_relabelled_into_another_domain_is_refused_as_foreign() {
        let key = writer();
        let mut signed = SignedAuditRecord::sign(&key, record(Outcome::Success)).unwrap();
        signed.domain = crate::observation::OBSERVATION_DOMAIN.to_owned();

        match signed.verify(&key.verifying_key()) {
            Err(EvidenceError::Domain { expected, found }) => {
                assert_eq!(expected, AUDIT_DOMAIN);
                assert_eq!(found, crate::observation::OBSERVATION_DOMAIN);
            }
            other => panic!("a foreign domain must be reported as foreign, got {other:?}"),
        }
    }

    /// A truncated append is reported, never decoded as a shorter record.
    #[test]
    fn a_partial_trailing_frame_is_reported_rather_than_decoded() {
        let directory = tempfile::tempdir().unwrap();
        let chain = chain_in(&directory);
        let key = writer();
        std::fs::create_dir_all(directory.path().join("audit")).unwrap();
        chain
            .append(&key, actor(), ADMIN, record(Outcome::Success))
            .unwrap();

        let path = chain.segment(actor(), ADMIN);
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();

        assert!(matches!(
            chain.read(actor(), ADMIN),
            Err(ChainError::Malformed { .. })
        ));
    }

    /// A key ID naming a path is refused before anything is written.
    #[test]
    fn a_key_id_that_names_a_path_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let chain = chain_in(&directory);
        std::fs::create_dir_all(directory.path().join("audit")).unwrap();
        for label in ["../escape", "a/b", "", "..", "."] {
            assert_eq!(
                chain
                    .append(&writer(), actor(), label, record(Outcome::Success))
                    .unwrap_err()
                    .to_string(),
                ChainError::Writer.to_string(),
                "{label} must not name a segment"
            );
        }
        assert!(
            !chain.writer_root(actor()).join("a").exists(),
            "a refused label must not create a path"
        );
    }

    /// A missing audit root is a refusal, not a directory the chain invents: the
    /// root is a protected root owned by the layout table.
    #[test]
    fn a_missing_audit_root_is_refused_rather_than_created() {
        let directory = tempfile::tempdir().unwrap();
        let chain = chain_in(&directory);
        let error = chain
            .append(&writer(), actor(), ADMIN, record(Outcome::Success))
            .unwrap_err();
        assert!(matches!(error, ChainError::Directory { .. }));
        assert!(
            !directory.path().join("audit").exists(),
            "a failed append must not leave a directory it created"
        );
    }

    // -----------------------------------------------------------------------
    // Verification against pins
    // -----------------------------------------------------------------------

    fn pin(key_id: &str, key: &VerifyingKey, principal: PrincipalId, role: PinRole) -> PinnedKey {
        PinnedKey {
            key_id: key_id.to_string(),
            key: *key,
            principal: Some(principal),
            role,
            status: PinStatus::Current,
        }
    }

    /// Sign one record with `writer`, then check it under `pins`.
    fn attribute_with(
        writer: &EvidenceSigningKey,
        pins: &Pins,
        record: AuditRecord,
    ) -> Attribution {
        attribute(&SignedAuditRecord::sign(writer, record).unwrap(), pins)
    }

    /// Misfit W: the log nominates its own signer. A stranger signs and names a key
    /// no pin holds, so the answer is "unpinned" — never "valid", whatever the
    /// record says about itself.
    #[test]
    fn a_record_signed_by_an_unpinned_key_is_unpinned_not_valid() {
        let attacker = EvidenceSigningKey::generate();
        let admin = EvidenceSigningKey::generate();
        let pins = Pins::new(vec![pin(
            ADMIN,
            &admin.verifying_key(),
            actor(),
            PinRole::Admin,
        )]);

        let mut forged = record(Outcome::Success);
        forged.signer_key_id = "attacker-2026".to_string();
        assert_eq!(
            attribute_with(&attacker, &pins, forged),
            Attribution::Unpinned
        );
    }

    /// Misfit W, the other direction: a record that *claims* the pinned admin key ID
    /// while a stranger signed it is invalid, because the claim is credible and the
    /// bytes are not.
    #[test]
    fn a_record_claiming_the_admin_key_but_signed_elsewhere_is_invalid() {
        let attacker = EvidenceSigningKey::generate();
        let admin = EvidenceSigningKey::generate();
        let pins = Pins::new(vec![pin(
            ADMIN,
            &admin.verifying_key(),
            actor(),
            PinRole::Admin,
        )]);

        assert_eq!(
            attribute_with(&attacker, &pins, record(Outcome::Success)),
            Attribution::Invalid {
                signer: ADMIN.to_string()
            }
        );
    }

    /// A genuine signature by a pinned key that names a different key ID: the claim
    /// is wrong, and the verifier says which pin actually signed the bytes.
    #[test]
    fn a_pinned_signature_naming_another_key_is_a_mismatch() {
        let admin = EvidenceSigningKey::generate();
        let pins = Pins::new(vec![pin(
            ADMIN,
            &admin.verifying_key(),
            actor(),
            PinRole::Admin,
        )]);

        let mut relabelled = record(Outcome::Success);
        relabelled.signer_key_id = "admin-2099".to_string();
        assert_eq!(
            attribute_with(&admin, &pins, relabelled),
            Attribution::Mismatch {
                signer: ADMIN.to_string()
            }
        );
    }

    /// FR-052: a revoked key still verifies, and the report carries the revision and
    /// time that withdrew it, so a revoked record is not shown as a current one.
    #[test]
    fn a_revoked_pin_verifies_and_carries_its_withdrawal() {
        let agent = EvidenceSigningKey::generate();
        let pins = Pins::new(vec![PinnedKey {
            key_id: "agent-key-1".to_string(),
            key: agent.verifying_key(),
            principal: Some(other_actor()),
            role: PinRole::Agent,
            status: PinStatus::Revoked {
                policy_revision: 7,
                at: Some(1_700_000_000),
            },
        }]);

        let mut delivery = record(Outcome::Success);
        delivery.actor = other_actor();
        delivery.signer_key_id = "agent-key-1".to_string();
        delivery.component = AuditComponent::Agent;

        assert_eq!(
            attribute_with(&agent, &pins, delivery),
            Attribution::Verified {
                key_id: "agent-key-1".to_string(),
                status: PinStatus::Revoked {
                    policy_revision: 7,
                    at: Some(1_700_000_000)
                }
            }
        );
    }

    /// FR-049: a tenant key signing a record that names another principal is a
    /// mismatch, not a valid record.
    #[test]
    fn a_tenant_key_signing_for_another_principal_is_a_mismatch() {
        let tenant = EvidenceSigningKey::generate();
        let pins = Pins::new(vec![pin(
            "user-key-1",
            &tenant.verifying_key(),
            actor(),
            PinRole::User,
        )]);

        let mut other = record(Outcome::Success);
        other.actor = other_actor();
        other.signer_key_id = "user-key-1".to_string();
        assert_eq!(
            attribute_with(&tenant, &pins, other),
            Attribution::Mismatch {
                signer: "user-key-1".to_string()
            }
        );

        // The same key signing for its own principal is valid.
        let mut own = record(Outcome::Success);
        own.signer_key_id = "user-key-1".to_string();
        assert!(matches!(
            attribute_with(&tenant, &pins, own),
            Attribution::Verified { .. }
        ));
    }

    /// A sweep record is the admin's. An agent key signing one is a mismatch even
    /// though its signature is genuine.
    #[test]
    fn an_agent_key_cannot_sign_a_sweeper_record() {
        let agent = EvidenceSigningKey::generate();
        let pins = Pins::new(vec![pin(
            "agent-key-1",
            &agent.verifying_key(),
            other_actor(),
            PinRole::Agent,
        )]);

        let mut sweep = record(Outcome::Success);
        sweep.component = AuditComponent::Sweeper;
        sweep.signer_key_id = "agent-key-1".to_string();
        assert_eq!(
            attribute_with(&agent, &pins, sweep),
            Attribution::Mismatch {
                signer: "agent-key-1".to_string()
            }
        );
    }

    /// Editing one record's outcome makes its signature invalid at that index, and
    /// the link from the record that followed it no longer resolves.
    #[test]
    fn an_edited_record_is_invalid_and_breaks_the_chain_at_its_index() {
        let directory = tempfile::tempdir().unwrap();
        let chain = chain_in(&directory);
        std::fs::create_dir_all(directory.path().join("audit")).unwrap();
        let admin = EvidenceSigningKey::generate();
        chain
            .append(&admin, actor(), ADMIN, record(Outcome::Success))
            .unwrap();
        chain
            .append(&admin, actor(), ADMIN, record(Outcome::Failure))
            .unwrap();

        let path = chain.segment(actor(), ADMIN);
        let records = chain.read(actor(), ADMIN).unwrap();
        // The first record is edited, so its own signature and the link the second
        // record wrote to the original both stop resolving.
        let mut edited = records[0].clone();
        edited.record.outcome = Outcome::Failure;
        let bytes = |records: &[SignedAuditRecord]| {
            let mut bytes = Vec::new();
            for record in records {
                let body = record.to_bytes().unwrap();
                bytes.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
                bytes.extend_from_slice(&body);
            }
            bytes
        };
        std::fs::write(&path, bytes(&[edited, records[1].clone()])).unwrap();

        let pins = Pins::new(vec![pin(
            ADMIN,
            &admin.verifying_key(),
            actor(),
            PinRole::Admin,
        )]);
        let reader = chain.reader(actor(), ADMIN).unwrap().unwrap();
        let report = verify_segment(reader, &pins).unwrap();

        assert_eq!(report.records, 2);
        assert_eq!(report.counts.invalid, 1);
        assert_eq!(report.first_invalid, Some(0));
        assert_eq!(
            report.broken,
            Some(Break::Signature { index: 0 }),
            "the chain breaks at the edited record"
        );
        assert!(!report.is_sound());
    }

    /// Misfit X: two records naming one predecessor are both counted and both named;
    /// the verifier does not choose a branch.
    #[test]
    fn a_fork_keeps_both_claimants_and_names_them() {
        let admin = EvidenceSigningKey::generate();
        let first = SignedAuditRecord::sign(&admin, record(Outcome::Success)).unwrap();
        let previous = first.digest();

        let second = SignedAuditRecord::sign(
            &admin,
            AuditRecord {
                prev_digest: Some(previous),
                acceptance: None,
                ..record(Outcome::Success)
            },
        )
        .unwrap();
        let third = SignedAuditRecord::sign(
            &admin,
            AuditRecord {
                prev_digest: Some(previous),
                acceptance: None,
                ..record(Outcome::Failure)
            },
        )
        .unwrap();
        // Both claimants verify, so the fork is the only reason to stop.
        assert!(second.verify(&admin.verifying_key()).is_ok());
        assert!(third.verify(&admin.verifying_key()).is_ok());
        let records = vec![Ok(first), Ok(second), Ok(third)];
        let pins = Pins::new(vec![pin(
            ADMIN,
            &admin.verifying_key(),
            actor(),
            PinRole::Admin,
        )]);
        let report = verify_segment(records, &pins).unwrap();

        assert_eq!(report.records, 3, "both claimants are kept");
        assert_eq!(report.broken, Some(Break::Fork { index: 1, other: 2 }));
        assert_eq!(report.counts.verified, 3);
    }

    /// A segment that ends in a partial frame is a torn append: reported as a torn
    /// tail, never decoded as a shorter record.
    #[test]
    fn a_torn_tail_is_reported_rather_than_decoded() {
        let directory = tempfile::tempdir().unwrap();
        let chain = chain_in(&directory);
        std::fs::create_dir_all(directory.path().join("audit")).unwrap();
        let admin = EvidenceSigningKey::generate();
        chain
            .append(&admin, actor(), ADMIN, record(Outcome::Success))
            .unwrap();
        let path = chain.segment(actor(), ADMIN);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.truncate(bytes.len() - 3);
        std::fs::write(&path, bytes).unwrap();

        let pins = Pins::new(vec![pin(
            ADMIN,
            &admin.verifying_key(),
            actor(),
            PinRole::Admin,
        )]);
        let reader = chain.reader(actor(), ADMIN).unwrap().unwrap();
        let report = verify_segment(reader, &pins).unwrap();

        assert_eq!(report.records, 0);
        assert!(report.torn_tail);
        assert_eq!(report.torn_tail_at, Some(0));
        assert!(!report.is_sound());
    }

    /// The reader streams: it yields one record at a time, in file order, without
    /// the caller loading the segment.
    #[test]
    fn the_segment_reader_yields_records_in_file_order() {
        let directory = tempfile::tempdir().unwrap();
        let chain = chain_in(&directory);
        std::fs::create_dir_all(directory.path().join("audit")).unwrap();
        let admin = EvidenceSigningKey::generate();
        for outcome in [Outcome::Success, Outcome::Failure, Outcome::Success] {
            chain
                .append(&admin, actor(), ADMIN, record(outcome))
                .unwrap();
        }

        let reader = chain.reader(actor(), ADMIN).unwrap().unwrap();
        let streamed = reader
            .collect::<Result<Vec<_>, _>>()
            .expect("every frame decodes");
        assert_eq!(streamed.len(), 3);
        assert_eq!(streamed[1].record.outcome, Outcome::Failure);
        assert_eq!(
            chain.read(actor(), ADMIN).unwrap().len(),
            streamed.len(),
            "the streaming reader and the whole-segment read agree"
        );
    }

    // -----------------------------------------------------------------------
    // Framing and unknown kinds (FR-040, FR-042)
    // -----------------------------------------------------------------------

    /// Build a segment body: a four-byte length, then the body.
    fn framed(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::from((u32::try_from(body.len()).unwrap()).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// A body that does not decode is still a frame: the walk continues past it.
    #[test]
    fn a_bad_body_does_not_end_the_walk_but_a_torn_tail_does() {
        let mut bytes = framed(b"not a record");
        bytes.extend(framed(b"also not a record"));
        let split = frames(&bytes);
        assert_eq!(split.len(), 2, "two framed bodies, neither decodable");
        assert!(matches!(split[0], Frame::Body(body) if body == b"not a record"));

        // A length that runs past the end is a torn tail at that index.
        let mut torn = framed(b"fine");
        torn.extend_from_slice(&[0, 0, 0, 9, b'x']);
        let split = frames(&torn);
        assert_eq!(split.len(), 2);
        assert_eq!(
            split[1],
            Frame::Torn {
                index: 1,
                cause: TornCause::Truncated
            }
        );

        // So is a header that is not four bytes long.
        let mut short = framed(b"fine");
        short.extend_from_slice(&[0, 0]);
        assert_eq!(
            frames(&short)[1],
            Frame::Torn {
                index: 1,
                cause: TornCause::Truncated
            }
        );

        // And a length above the cap is refused rather than believed.
        let huge = [0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            frames(&huge),
            vec![Frame::Torn {
                index: 0,
                cause: TornCause::Oversized
            }]
        );
    }

    /// A partial write and a corrupt length are different findings, so the two reasons
    /// must not read the same: one names a tail that is not there, the other does not
    /// claim a cause it cannot see.
    #[test]
    fn a_corrupt_length_is_not_reported_as_a_lost_append() {
        assert_ne!(TornCause::Truncated.reason(), TornCause::Oversized.reason());
        assert!(
            TornCause::Truncated.reason().contains("truncated"),
            "the partial write says what it is"
        );
        assert!(
            !TornCause::Oversized.reason().contains("append"),
            "a length nobody could have written is not called a lost append: {}",
            TornCause::Oversized.reason()
        );
    }

    /// FR-040: an unknown kind is projected with its fields, not dropped.
    #[test]
    fn an_unknown_record_is_projected_with_its_fields() {
        use ksp_types::cbor::RawValue;

        let field = |name: &str, value: RawValue| (RawValue::Text(name.to_string()), value);
        // Built as raw values so a byte string is a byte string: serde encodes a
        // `Vec<u8>` as an array of integers, which is not the shape a future writer
        // would use for material.
        let body = cbor::encode(&RawValue::Map(vec![
            field("domain", RawValue::Text("keyspout-audit-record-v2".into())),
            field(
                "record",
                RawValue::Map(vec![
                    field("actor", RawValue::Text("6f5a1c8e".into())),
                    field("secret_value", RawValue::Text("must not print".into())),
                    field("secret_count", RawValue::Integer(2.into())),
                    field("blob", RawValue::Bytes(vec![1, 2, 3])),
                    field("counts", RawValue::Array(vec![RawValue::Integer(1.into())])),
                    field("flag", RawValue::Bool(true)),
                    field("count", RawValue::Integer(7.into())),
                ]),
            ),
            field("signature", RawValue::Bytes(vec![0; 64])),
        ]))
        .unwrap();

        let raw = RawRecord::project(&body).expect("a CBOR map projects");
        assert_eq!(raw.domain, "keyspout-audit-record-v2");
        let projected = |name: &str| {
            raw.fields
                .iter()
                .find(|entry| entry.name == name)
                .unwrap_or_else(|| panic!("{name} is projected: {:?}", raw.fields))
                .value
                .clone()
        };
        // No text and no bytes are printed for a kind this build does not know: the
        // writer has not agreed to this build's no-secret rule.
        assert_eq!(projected("actor"), RawFieldValue::Text { chars: 8 });
        // A name that announces material is refused even when its value is a number.
        assert_eq!(projected("secret_value"), RawFieldValue::Redacted);
        // A byte string is reported by length, never by bytes.
        assert_eq!(projected("blob"), RawFieldValue::Bytes(3));
        assert_eq!(
            projected("counts"),
            RawFieldValue::Nested {
                kind: "array",
                len: 1
            }
        );
        assert_eq!(projected("flag"), RawFieldValue::Flag(true));
        assert_eq!(projected("count"), RawFieldValue::Integer(7));
        assert_eq!(
            projected("secret_count"),
            RawFieldValue::Redacted,
            "a name that announces material is refused even for a number"
        );
        // The signature is envelope, not payload.
        assert!(
            raw.fields.iter().all(|entry| entry.name != "signature"),
            "the signature is not a payload field"
        );
    }

    /// A body that is not a CBOR map cannot be projected, and is reported as malformed.
    #[test]
    fn a_body_that_is_not_a_map_projects_to_nothing() {
        assert!(RawRecord::project(b"not cbor at all").is_none());
        let scalar = cbor::encode(&7u32).unwrap();
        assert!(RawRecord::project(&scalar).is_none());
    }

    /// The projection reads a payload that is not nested under `record` too.
    #[test]
    fn a_future_envelope_without_a_record_field_is_still_projected() {
        #[derive(Serialize)]
        struct Flat {
            domain: &'static str,
            actor: &'static str,
            signature: Vec<u8>,
        }
        let body = cbor::encode(&Flat {
            domain: "keyspout-audit-record-v3",
            actor: "someone",
            signature: vec![0; 64],
        })
        .unwrap();
        let raw = RawRecord::project(&body).expect("a map projects");
        assert_eq!(raw.domain, "keyspout-audit-record-v3");
        assert_eq!(raw.fields.len(), 2, "domain and actor, never the signature");
    }
}
