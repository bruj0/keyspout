//! The sealed delivery artifact and the downstream copy.
//!
//! # The misfit this resolves
//!
//! Misfit B: a saved artifact that carries a raw content key is decryptable by
//! anyone who copies the file, and no proof of possession inside the CLI changes
//! that — the key is already out. So the content keys appear **only** inside an
//! HPKE envelope sealed to the agent's fingerprint-verified X25519 key. The
//! artifact names the recipient's public key and key ID and holds no private
//! material at all.
//!
//! The guarantee is deliberately narrow: *the artifact alone* is inert. A holder
//! who has both the agent's private key and the matching ciphertext can decrypt,
//! which is what NFR-006 says and what the tests assert rather than hide.
//!
//! # Two verified types, because a check a caller can skip is not a check
//!
//! A key enters through [`VerifiedRecipientKey::confirm`]: the record's
//! fingerprint is **re-derived from its own keys and key IDs** and compared to the
//! value the user read out of band, so a record read back from a file cannot
//! carry a genuine fingerprint beside a substituted key (Misfit Q).
//!
//! An artifact enters through [`verify`], which returns a [`VerifiedDelivery`].
//! [`open`] takes only that, so opening an artifact whose issuer signature was
//! never checked does not compile. That matters because sealing is *not* a secret
//! operation: the agent's X25519 public key is a field of the header, so anyone
//! who can replace the artifact file can seal a content-key map of their choosing
//! to it. Without the type, the natural call order — open, because the private
//! key is at hand — would hand an agent attacker-chosen content keys.
//!
//! # One document
//!
//! [`DeliveryArtifact`] is a single fixed-order CBOR structure whose fields are
//! the header, the envelope and the signature. There is no length-prefix framing
//! to drift out of step with the encoding, and the signature covers
//! `[header, envelope]` rather than the bytes it lives in.

use ksp_record::kem;
use ksp_types::{
    BoundMetadata, ContentKey, HPKE_INFO_DELIVERY, Level, OpaqueSecretId, RecordVersion, cbor,
};
use serde::{Deserialize, Serialize};

use crate::enrolment::{EnrollmentRecord, SigningSecretKey, UnsignedEnrolment, VerifyingPublicKey};
use crate::fingerprint::EnrolmentFingerprint;
use crate::header::{DeliveryHeader, HEADER_VERSION, HeaderError, SelectedRecord};
use crate::token::{self, DeliveryEnvelope, TokenError, TokenSignature};

/// An X25519 recipient key that has been checked against a confirmed fingerprint.
///
/// The inner key is private and there is no `From<RecipientPublicKey>`, so a
/// caller cannot wrap an arbitrary key. It exists at all only because
/// [`confirm`](Self::confirm) succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedRecipientKey {
    key: [u8; 32],
}

impl VerifiedRecipientKey {
    /// Take the recipient key out of an enrolment record the user confirmed.
    ///
    /// `confirmed` is the fingerprint the user read through a channel separate
    /// from the store.
    ///
    /// The comparison is against the fingerprint **re-derived from the record's
    /// own identity, both keys and both key IDs**, never against the value the
    /// record claims. `EnrollmentRecord` can be deserialized, so a record read
    /// back from a file can carry a genuine fingerprint field beside a
    /// substituted recipient key; comparing the claim would accept it and seal
    /// the delivery to the substitute.
    pub fn confirm(
        record: &EnrollmentRecord,
        confirmed: &EnrolmentFingerprint,
    ) -> Result<Self, DeliveryError> {
        let binding = record
            .binding_fingerprint()
            .map_err(|err| DeliveryError::Binding {
                cause: err.to_string(),
            })?;
        if !binding.matches(confirmed) {
            return Err(DeliveryError::UnconfirmedRecipient);
        }
        Ok(Self {
            key: record.recipient_key().to_bytes(),
        })
    }

    /// Take the recipient key out of an enrolment *pin* the user confirmed.
    ///
    /// The pin is this host's record of what `agent enroll` printed — identity,
    /// both public keys, both key IDs — and the user confirms its fingerprint
    /// through a channel independent of the store. No signature takes part, and
    /// none is needed: [`UnsignedEnrolment`] recomputes its own fingerprint from
    /// its own claims, so a pin whose recipient key was swapped does not match the
    /// fingerprint the user confirmed, and the delivery is not sealed to it.
    ///
    /// [`EnrollmentRecord`] remains the stronger form: it carries the admin's
    /// signature over the same claims, and a caller that holds one should prefer
    /// [`Self::confirm`].
    pub fn confirm_pin(
        pin: &UnsignedEnrolment,
        confirmed: &EnrolmentFingerprint,
    ) -> Result<Self, DeliveryError> {
        if !pin.fingerprint().matches(confirmed) {
            return Err(DeliveryError::UnconfirmedRecipient);
        }
        Ok(Self {
            key: pin.recipient_key().to_bytes(),
        })
    }

    /// The raw X25519 public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// The content keys for the records one delivery names.
///
/// Keyed by the **whole** selected record — secret *and* version — because the
/// version chain is per record path: two different secrets routinely sit at the
/// same version number, and keying on the number alone would deliver one
/// secret's key under the other's path.
pub struct SelectedContentKeys {
    keys: Vec<(SelectedRecord, ContentKey)>,
}

impl SelectedContentKeys {
    /// Pair the selected records with their content keys, in header order.
    ///
    /// Refuses a missing key, a surplus one and a duplicated one. The surplus
    /// check is the FR-022 rule: only the selected records' keys may appear
    /// inside the envelope, so a key for a record the header does not name would
    /// be a key delivered without authority.
    pub fn new(
        header: &DeliveryHeader,
        supplied: Vec<(SelectedRecord, ContentKey)>,
    ) -> Result<Self, DeliveryError> {
        let selected = header.records();

        for record in selected {
            if !supplied.iter().any(|(s, _)| s == record) {
                return Err(DeliveryError::MissingContentKey {
                    secret: record.secret.as_str().to_string(),
                    version: record.version.get(),
                });
            }
        }
        for (record, _) in &supplied {
            if !selected.contains(record) {
                return Err(DeliveryError::UnselectedContentKey {
                    secret: record.secret.as_str().to_string(),
                    version: record.version.get(),
                });
            }
        }

        // Header order, so the plaintext is a function of the header alone.
        let mut keys = Vec::with_capacity(selected.len());
        for record in selected {
            let matching: Vec<&(SelectedRecord, ContentKey)> =
                supplied.iter().filter(|(s, _)| s == record).collect();
            if matching.len() > 1 {
                return Err(DeliveryError::DuplicateContentKey {
                    secret: record.secret.as_str().to_string(),
                    version: record.version.get(),
                });
            }
            keys.push((record.clone(), matching[0].1.clone()));
        }
        Ok(Self { keys })
    }

    /// How many keys the selection carries.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the selection is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The selected records.
    pub fn records(&self) -> Vec<SelectedRecord> {
        self.keys.iter().map(|(record, _)| record.clone()).collect()
    }

    /// The key for one selected record.
    pub fn get(&self, secret: &OpaqueSecretId, version: RecordVersion) -> Option<&ContentKey> {
        self.keys
            .iter()
            .find(|(record, _)| record.secret == *secret && record.version == version)
            .map(|(_, key)| key)
    }

    /// The plaintext that goes inside the envelope.
    ///
    /// An explicit CBOR array of `[secret, version, key bytes]` entries in header
    /// order: an array rather than a map, so the bytes do not depend on an
    /// encoder's map ordering, and the secret is carried so the opening side can
    /// tell two records at the same version apart.
    fn plaintext(&self) -> Result<Vec<u8>, DeliveryError> {
        #[derive(Serialize)]
        struct Entry<'a> {
            secret: &'a str,
            version: RecordVersion,
            key: &'a [u8],
        }

        let entries: Vec<Entry<'_>> = self
            .keys
            .iter()
            .map(|(record, key)| Entry {
                secret: record.secret.as_str(),
                version: record.version,
                key: key.as_bytes().as_slice(),
            })
            .collect();
        cbor::encode(&entries).map_err(|err| DeliveryError::Encoding {
            cause: err.to_string(),
        })
    }
}

impl std::fmt::Debug for SelectedContentKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A content key must never reach a log, and a derived `Debug` would put
        // every one of them there.
        write!(
            f,
            "SelectedContentKeys(<{} content keys redacted>)",
            self.keys.len()
        )
    }
}

/// The saved and transferable form of one delivery.
///
/// A single CBOR document. The three fields are the whole of it: the header that
/// describes the delivery, the envelope that seals the selected content keys to
/// the agent, and the issuer's signature over the first two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryArtifact {
    header: DeliveryHeader,
    envelope: DeliveryEnvelope,
    signature: TokenSignature,
}

impl DeliveryArtifact {
    /// Assemble an artifact from parts that arrived separately.
    ///
    /// The parts are not checked against each other here: assembling a mismatched
    /// pair is exactly what [`verify`] and [`open`] exist to refuse, and a caller
    /// that reassembled a file needs a way to hand the pieces back to them.
    pub fn from_parts(
        header: DeliveryHeader,
        envelope: DeliveryEnvelope,
        signature: TokenSignature,
    ) -> Self {
        Self {
            header,
            envelope,
            signature,
        }
    }

    /// The header describing this delivery.
    pub fn header(&self) -> &DeliveryHeader {
        &self.header
    }

    /// The sealed content-key map.
    pub fn envelope(&self) -> &DeliveryEnvelope {
        &self.envelope
    }

    /// The issuer's signature.
    pub fn signature(&self) -> &TokenSignature {
        &self.signature
    }

    /// The canonical bytes of the whole artifact.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DeliveryError> {
        cbor::encode(self).map_err(|err| DeliveryError::Encoding {
            cause: err.to_string(),
        })
    }

    /// Parse an artifact.
    ///
    /// Every failure is a typed error; nothing here can panic on hostile bytes.
    /// Three things are checked beyond decoding: the header's own invariants
    /// (a decoded header bypasses its constructor), the format version, and that
    /// the bytes are the *canonical* encoding of what was parsed. The last one
    /// rejects trailing data, which a streaming decoder would otherwise ignore,
    /// and pins the single document form this crate produces.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DeliveryError> {
        let artifact: Self = cbor::decode(bytes).map_err(|err| DeliveryError::Malformed {
            cause: err.to_string(),
        })?;
        artifact
            .header
            .validate()
            .map_err(|err| DeliveryError::Malformed {
                cause: err.to_string(),
            })?;
        if artifact.header.version() != HEADER_VERSION {
            return Err(DeliveryError::UnsupportedVersion {
                found: artifact.header.version(),
                expected: HEADER_VERSION,
            });
        }
        let canonical = artifact.to_bytes()?;
        if canonical != bytes {
            return Err(DeliveryError::Malformed {
                cause: "the artifact is not in canonical form, or carries trailing data"
                    .to_string(),
            });
        }
        Ok(artifact)
    }
}

/// An artifact whose issuer signature has been checked.
///
/// The only constructor is [`verify`], so [`open`] cannot be called on an
/// artifact that was not verified. That is the whole point: a check a caller can
/// skip is not a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelivery {
    artifact: DeliveryArtifact,
}

impl VerifiedDelivery {
    /// The artifact that was verified.
    pub fn artifact(&self) -> &DeliveryArtifact {
        &self.artifact
    }

    /// The header of the verified delivery.
    pub fn header(&self) -> &DeliveryHeader {
        self.artifact.header()
    }
}

/// Seal the selected content keys to a verified recipient and sign the result.
///
/// The AAD is the complete canonical header, so a modified header — a different
/// scope, a different expiry, a different version set, a substituted key — makes
/// the envelope fail to open instead of opening under the wrong description.
///
/// The recipient must be the key the header names. The header is the AAD *and*
/// the signed description of the delivery, so sealing to a key the header does
/// not name would produce an artifact that names one recipient while only
/// another can open it.
pub fn seal(
    // The principal who owns the record signs its own lease: a delivery is
    // Alice's authorisation, and the admin's key never enters her command
    // (spec §3.7 step 2, FR-020's converse).
    signer: &SigningSecretKey,
    header: &DeliveryHeader,
    keys: &SelectedContentKeys,
    recipient: &VerifiedRecipientKey,
) -> Result<DeliveryArtifact, DeliveryError> {
    // A header that arrived by decoding bypasses its constructor, and signing one
    // would make its defects authoritative. The issuer refuses to sign a structure
    // its own constructor would reject, as it does for an enrolment record.
    header.validate().map_err(DeliveryError::Header)?;

    if recipient.as_bytes() != &header.agent_recipient_key().to_bytes() {
        return Err(DeliveryError::RecipientMismatch);
    }

    let aad = header.canonical().map_err(DeliveryError::Header)?;
    let plaintext = keys.plaintext()?;

    let (enc, ciphertext) =
        kem::seal_to(recipient.as_bytes(), HPKE_INFO_DELIVERY, &aad, &plaintext).map_err(
            |err| DeliveryError::Seal {
                cause: err.to_string(),
            },
        )?;

    let envelope = DeliveryEnvelope::new(enc, ciphertext);
    let signature = token::sign_delivery(signer, header, &envelope)?;

    Ok(DeliveryArtifact {
        header: header.clone(),
        envelope,
        signature,
    })
}

/// Verify an artifact's issuer signature against a pinned key.
///
/// Returns the proof that [`open`] requires, so the verification cannot be
/// skipped by a caller that only wants the content keys.
pub fn verify(
    artifact: &DeliveryArtifact,
    anchor: &VerifyingPublicKey,
) -> Result<VerifiedDelivery, DeliveryError> {
    artifact
        .header()
        .validate()
        .map_err(|err| DeliveryError::Malformed {
            cause: err.to_string(),
        })?;
    token::verify_delivery(
        anchor,
        artifact.header(),
        artifact.envelope(),
        artifact.signature(),
    )
    .map_err(DeliveryError::Token)?;
    Ok(VerifiedDelivery {
        artifact: artifact.clone(),
    })
}

/// Open the envelope with the agent's X25519 private key.
///
/// Takes a [`VerifiedDelivery`], so the issuer signature has been checked by the
/// time the content keys exist. This is the operation an artifact *holder*
/// cannot perform: without the private key the sealed map stays sealed, which is
/// why the saved artifact is inert.
pub fn open(
    verified: &VerifiedDelivery,
    recipient_private_key: &[u8; 32],
) -> Result<SelectedContentKeys, DeliveryError> {
    let artifact = verified.artifact();
    let aad = artifact
        .header()
        .canonical()
        .map_err(DeliveryError::Header)?;
    let plaintext = kem::open_from(
        recipient_private_key,
        artifact.envelope().enc(),
        HPKE_INFO_DELIVERY,
        &aad,
        artifact.envelope().ciphertext(),
    )
    .map_err(|err| DeliveryError::Open {
        cause: err.to_string(),
    })?;

    #[derive(Deserialize)]
    struct Entry {
        secret: String,
        version: RecordVersion,
        key: Vec<u8>,
    }

    let entries: Vec<Entry> = cbor::decode(&plaintext).map_err(|err| DeliveryError::Malformed {
        cause: err.to_string(),
    })?;

    let mut supplied = Vec::with_capacity(entries.len());
    for entry in entries {
        let bytes: [u8; 32] =
            entry
                .key
                .as_slice()
                .try_into()
                .map_err(|_| DeliveryError::Malformed {
                    cause: "a content key was not 32 bytes".to_string(),
                })?;
        supplied.push((
            SelectedRecord {
                secret: OpaqueSecretId::new(entry.secret),
                version: entry.version,
            },
            ContentKey::from_bytes(bytes),
        ));
    }

    SelectedContentKeys::new(artifact.header(), supplied)
}

/// A one-way copy of a `user`-level record at an agent's level.
pub struct DownstreamCopy {
    /// The new record's metadata: a fresh level and version.
    pub metadata: BoundMetadata,
    /// The new record's content key. Never the source's.
    pub content_key: ContentKey,
}

impl std::fmt::Debug for DownstreamCopy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DownstreamCopy {{ level: {}, version: {}, content_key: <redacted> }}",
            self.metadata.level.path_segment(),
            self.metadata.version
        )
    }
}

/// Build the downstream copy of a `user`-level record for one agent.
///
/// FR-015 and FR-016: the copy is a **new** record at `agent-<id>` level with a
/// **fresh** content key and a **fresh** version, and the source is untouched.
/// The reverse direction — copying an agent-level record back up to `user` or
/// `admin` — is refused here rather than left to a caller to remember.
pub fn downstream_copy(
    source: &BoundMetadata,
    source_key: &ContentKey,
    agent: &ksp_types::AgentId,
    version: RecordVersion,
) -> Result<DownstreamCopy, DeliveryError> {
    if let Level::Agent(existing) = &source.level {
        return Err(DeliveryError::ReverseCopy {
            from_level: existing.to_string(),
        });
    }

    // A fresh key, and one that is known not to be the source's: regenerating
    // until it differs makes "fresh" structural rather than probabilistic. The
    // branch is unreachable unless the CSPRNG returns the same 32 bytes twice,
    // so it is defence behind a premise no test can arrange.
    let mut content_key = ContentKey::generate();
    let mut attempts = 0u8;
    while content_key.as_bytes() == source_key.as_bytes() {
        content_key = ContentKey::generate();
        attempts += 1;
        if attempts > 8 {
            return Err(DeliveryError::FreshKeyUnavailable);
        }
    }

    Ok(DownstreamCopy {
        metadata: BoundMetadata {
            vault_id: source.vault_id.clone(),
            user_id: source.user_id,
            level: Level::Agent(*agent),
            secret_id: source.secret_id.clone(),
            version: version.get(),
        },
        content_key,
    })
}

/// Why a delivery could not be sealed, opened or copied.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    /// The header could not be built or encoded.
    #[error(transparent)]
    Header(#[from] HeaderError),
    /// The token signature could not be produced or checked.
    #[error(transparent)]
    Token(#[from] TokenError),
    /// The artifact's bytes were not an artifact.
    #[error("the delivery artifact could not be parsed: {cause}")]
    Malformed {
        /// The decoder's reason.
        cause: String,
    },
    /// The artifact is a format this build does not understand.
    #[error("the artifact is format version {found}, this build understands {expected}")]
    UnsupportedVersion {
        /// The version the artifact declares.
        found: u16,
        /// The version this build understands.
        expected: u16,
    },
    /// A structure could not be canonically encoded.
    #[error("the delivery could not be encoded: {cause}")]
    Encoding {
        /// The encoder's reason.
        cause: String,
    },
    /// A record's own fingerprint could not be re-derived.
    #[error("the enrolment's binding fingerprint could not be re-derived: {cause}")]
    Binding {
        /// The encoder's reason.
        cause: String,
    },
    /// The recipient key was not the one the user confirmed.
    #[error("the recipient key does not match the confirmed enrolment fingerprint")]
    UnconfirmedRecipient,
    /// The recipient key is not the key this header names.
    #[error("the recipient key is not the key this header names")]
    RecipientMismatch,
    /// A selected record had no content key.
    #[error("no content key was supplied for {secret} at version {version}")]
    MissingContentKey {
        /// The secret identifier.
        secret: String,
        /// The version that had no key.
        version: u32,
    },
    /// A content key was supplied for a record the header does not name.
    #[error(
        "a content key was supplied for {secret} at version {version}, which the header does not name"
    )]
    UnselectedContentKey {
        /// The secret identifier.
        secret: String,
        /// The version that was not selected.
        version: u32,
    },
    /// Two content keys were supplied for one selected record.
    #[error("two content keys were supplied for {secret} at version {version}")]
    DuplicateContentKey {
        /// The secret identifier.
        secret: String,
        /// The duplicated version.
        version: u32,
    },
    /// The seal failed, including on a low-order recipient key.
    #[error("the delivery could not be sealed: {cause}")]
    Seal {
        /// The KEM's reason.
        cause: String,
    },
    /// The envelope could not be opened.
    ///
    /// An associated-data mismatch and a wrong private key are indistinguishable
    /// at this layer: the KEM reports one authentication failure for both.
    #[error("the delivery envelope could not be opened: {cause}")]
    Open {
        /// The KEM's reason.
        cause: String,
    },
    /// An agent-level record was offered for a downstream copy.
    #[error("an agent-level record at {from_level} cannot be copied back upstream")]
    ReverseCopy {
        /// The level the source record lives at.
        from_level: String,
    },
    /// A fresh content key could not be generated.
    #[error("a fresh content key could not be generated")]
    FreshKeyUnavailable,
}
