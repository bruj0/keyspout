---
context_name: "Shared Contract Types"
version: "1"
subsystem: "crates/ksp-types"
created: "2026-10-21T16:20:00+00:00"
updated: "2026-10-28T19:05:00+00:00"
---

# Shared Contract Types

The crate of types and encodings that more than one subsystem must agree on
byte for byte. It holds no behaviour, no policy and no I/O. If two subsystems
disagree about an identifier, a domain string or an encoding, they disagree
here, in one place, and nowhere else.

This context owns every term that more than one subsystem uses, so that no
other context repeats a name.

## Language

**Vault ID**:
The identifier of one user's vault. Every record path is rooted at it.
_Avoid_: vault name, vault path, account
_Subsystems_: Shared Contract Types, Record Cryptography and Version Integrity
_Files_: crates/ksp-types/src/metadata.rs
_Relates to_: User ID (is a sibling of), Opaque Secret ID (is a sibling of), Record Path (is a segment of)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**User ID**:
The **Principal** UUID of the vault's owner, viewed in its role as the record's
owner: it is the `<principal-uuid>` segment of every **Record Path** and it is
bound into the record's AAD. Because it is bound, renaming a principal cannot
change it, and changing it is a re-seal rather than a rename.
_Avoid_: username, account name, owner name
_Subsystems_: Shared Contract Types, Record Cryptography and Version Integrity
_Files_: crates/ksp-types/src/metadata.rs
_Relates to_: Vault ID (is a sibling of), Level (is qualified by), Actor ID (is a form of), Principal (is the same UUID as)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-10-24 (002-file-os-split-sweeper): Re-keyed from a display name to the
  principal's UUID. The bound AAD made a rename a re-seal, which is why homes are
  recreated instead of migrated.

**Principal**:
An actor in a deployment that has a **UUID issued at enrolment**: exactly one
admin principal, one or more user principals, and one agent principal per enrolled
agent. The UUID is the identity that bindings, grants, record paths and reports
refer to; the display name is mutable metadata and nothing security-relevant keys
on it.
_Avoid_: user, account, actor, identity, Alice
_Subsystems_: Shared Contract Types, Host Confinement and Key Material Posture
_Files_: crates/ksp-types/src/metadata.rs, crates/ksp/src/admin.rs, crates/ksp/src/agent.rs
_Relates to_: Actor ID (signs as), User ID (is a role-specific view of), Principal Binding (owns), Signature Domain (is scoped by), Principal Registry (is issued by)
_History_:
- 2026-10-23 (002-file-os-split-sweeper): Term introduced to replace the "Alice"
  stand-in. Two principals cannot be confused by a shared display name, and a rename
  cannot be mistaken for a rebind.

**Principal Registry**:
The rule and the two entry points that issue a **Principal** UUID once at
enrolment and never reissue it: `admin init` mints the user principal and
`agent enroll` mints an agent principal. A repeat reports the existing UUID; a
display name is recorded as mutable metadata and is never resolved to an
identity without an explicit lookup.
_Avoid_: user database, account list, id allocator
_Subsystems_: Shared Contract Types, Keyspout Command-Line Interface
_Files_: crates/ksp-types/src/metadata.rs, crates/ksp/src/admin.rs, crates/ksp/src/agent.rs, crates/ksp/src/deployment.rs
_Relates to_: Principal (issues), Actor ID (is carried by), Enrolment Fingerprint (binds the keys)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced. The rule is what makes
  a shared display name harmless and a re-run unable to mint a second identity.

**Agent ID**:
The **Principal** UUID of one enrolled agent, viewed in its agent role: it is
the `<principal-uuid>` inside the `agent-<uuid>` level segment. The UUID is the
agent's; the path's other principal segment belongs to the vault owner.
_Avoid_: agent name, service id, principal name, deploy-bot
_Subsystems_: Shared Contract Types, Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-types/src/metadata.rs
_Relates to_: Level (is a form of), Actor ID (is a form of), Principal (is the same UUID as)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-10-24 (002-file-os-split-sweeper): Re-keyed from a display name to the
  agent's principal UUID. A name is metadata and an `agent-` segment that is not
  a canonical UUID is refused.

**Actor ID**:
The identifier of any principal that signs an artifact: a user, an agent or
an enrolled collector.
_Avoid_: signer id, principal, subject
_Subsystems_: Shared Contract Types, Deletion Evidence and Consume Outcome
_Files_: crates/ksp-types/src/metadata.rs
_Relates to_: User ID (is a form of), Agent ID (is a form of), Principal (names one)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-10-24 (002-file-os-split-sweeper): Both variants now carry a
  **Principal** UUID; the variant names the role, never a display name.

**Opaque Secret ID**:
A random identifier that appears in a record path in place of a secret's name.
A backend listing therefore discloses no secret name.
_Avoid_: secret name, key name, filename, slug
_Subsystems_: Shared Contract Types, Record Cryptography and Version Integrity
_Files_: crates/ksp-types/src/metadata.rs
_Relates to_: Record Path (is a segment of)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Record Path**:
The location of one record version:
`p/<vault>/<principal-uuid>/<level>/<opaque-secret-id>/<version>`.
One definition builds and parses it; no other module formats the five segments
by hand.
_Avoid_: key path, object key, blob path
_Subsystems_: Shared Contract Types, Record Cryptography and Version Integrity
_Files_: crates/ksp-types/src/metadata.rs, crates/ksp-record/src/path.rs
_Relates to_: Opaque Secret ID (contains), Level (is a segment of), Record Version (is a segment of), Principal (is a segment of)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-10-24 (002-file-os-split-sweeper): The second segment is a **Principal**
  UUID. Construction and parsing moved into `ksp-record`, so a display name in a
  path is refused rather than accepted as an identity.

**Record Version**:
One numbered, immutable revision of a record at a given level. A delivery
binds an exact version, never "the current one". The version is the unit a
lease deletes.
_Avoid_: revision, generation, snapshot
_Subsystems_: Shared Contract Types, Record Cryptography and Version Integrity, Deletion Evidence and Consume Outcome
_Files_: crates/ksp-types/src/metadata.rs
_Relates to_: Record (is instance of), Record Path (is a segment of), Deletion Intent (is targeted by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Bound Metadata**:
The five-tuple `vault_id`, `user_id`, `level`, `secret_id`, `version` that
names exactly one stored record version and is bound cryptographically to it.
_Avoid_: context, binding, record context
_Subsystems_: Shared Contract Types, Record Cryptography and Version Integrity, Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-types/src/metadata.rs, crates/ksp-record/src/blob.rs
_Relates to_: Record Version (names), Content Key (guards), Level (part of), Principal (is bound by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-10-24 (002-file-os-split-sweeper): The second AAD element is the owner's
  **Principal** UUID, not a display name. The element count and its CBOR text
  encoding are unchanged; the value is. Every fixture containing a path segment
  or a bound AAD was regenerated.

**Level**:
One of `admin`, `user` or `agent-<principal-uuid>`. The three are siblings in
the record path, never nested, and the direction of sharing is one-way.
_Avoid_: scope, tier, role, namespace
_Subsystems_: Shared Contract Types, Record Cryptography and Version Integrity, Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-types/src/metadata.rs
_Relates to_: Bound Metadata (part of), Policy (bounds), Downstream Copy (is created by), Agent ID (names)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-10-24 (002-file-os-split-sweeper): An agent segment carries the agent's
  **Principal** UUID; an `agent-` segment that is not a canonical UUID is refused.

**Agent Keys**:
The independent Ed25519 signing keypair and X25519 recipient keypair belonging
to one agent identity. Neither half is derived from the other.
_Avoid_: keypair, credentials, agent key
_Subsystems_: Shared Contract Types, Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-types/src/metadata.rs, crates/ksp-identity/src/enrolment.rs, crates/ksp-identity/src/key_bundle.rs
_Relates to_: Enrolment Fingerprint (is covered by), Signing Key (is part of), Recipient Key (is part of)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Signing Key**:
An Ed25519 private key used to sign a protocol artifact. It never derives a
recipient key.
_Avoid_: private key, auth key, identity key
_Subsystems_: Shared Contract Types, Identity Sealed Delivery and Policy Verification, Deletion Evidence and Consume Outcome
_Files_: crates/ksp-types/src/domains.rs, crates/ksp-identity/src/token.rs
_Relates to_: Agent Keys (is part of), Signature Domain (scopes)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Recipient Key**:
An X25519 public key, verified against a fingerprint, that a content key may
be sealed to. It is never derived from a signing key.
_Avoid_: public key, encryption key, pubkey
_Subsystems_: Shared Contract Types, Record Cryptography and Version Integrity, Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-types/src/metadata.rs, crates/ksp-identity/src/fingerprint.rs
_Relates to_: Agent Keys (is part of), KEM Validation Gate (is subject of), Content Key (is sealed to)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced. "public key" is avoided
  because the same system also has Ed25519 signing public keys.

**Signature Domain**:
A versioned byte string prefixed to a signed structure so that one signature
is never valid in another context. Token, proof of possession, deletion
intent, deletion report and absence observation each have their own.
_Avoid_: context string, prefix, label, separator
_Subsystems_: Shared Contract Types, Identity Sealed Delivery and Policy Verification, Deletion Evidence and Consume Outcome
_Files_: crates/ksp-types/src/domains.rs
_Relates to_: Proof of Possession (scopes), Deletion Intent (scopes), Deletion Report (scopes), Absence Observation (scopes)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Canonical Encoding**:
The byte-level representation of a structure, produced by a fixed-order struct
or an explicit array so that two independent code paths produce identical
bytes.
_Avoid_: serialization, encoding format, wire format, canonical CBOR
_Subsystems_: Shared Contract Types, Identity Sealed Delivery and Policy Verification, Deletion Evidence and Consume Outcome
_Files_: crates/ksp-types/src/cbor.rs
_Relates to_: Signature Domain (is signed over), Golden Fixture (is pinned by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced. "canonical CBOR" is
  avoided because the underlying encoder is not RFC 8949 canonical CBOR.

**Golden Fixture**:
A committed file holding exact expected bytes, pinning an encoding so a
change to it fails a test rather than silently altering a signature's meaning.
_Avoid_: snapshot, test vector, golden file
_Subsystems_: Shared Contract Types
_Files_: tests/fixtures/
_Relates to_: Canonical Encoding (pins)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Lease Capability**:
What a storage backend is configured to guarantee about a lease's deadline:
`None`, `NativeExpiry` or `Scheduled { interval }`. A missing
mechanism is `None`, never an optimistic guess.
_Avoid_: expiry mode, TTL support, retention policy
_Subsystems_: Shared Contract Types, Backend Admission and Durable Arming
_Files_: crates/ksp-types/src/capability.rs
_Relates to_: Admission Decision (is produced by), Canonical Encoding (is encoded by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced. "expiry mode" is avoided
  because the three values describe configuration, not behaviour.

**Admission Decision**:
Whether a requested lease duration is admitted under a **Lease Capability**,
and the reason for a refusal. The two-times floor is conservative admission
policy, not a timing theorem.
_Avoid_: admission check, TTL validation, lease approval
_Subsystems_: Shared Contract Types, Backend Admission and Durable Arming
_Files_: crates/ksp-types/src/capability.rs
_Relates to_: Lease Capability (is produced by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Sealed Bundle**:
The user's own sealed key bundle — the only value Shamir recovery may split.
The split function takes this type and not a bare byte string, so splitting an
admin-supplied value is structurally impossible.
_Avoid_: key bundle, recovery blob, master bundle
_Subsystems_: Shared Contract Types, Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-types/src/shamir.rs
_Relates to_: Content Key (contains), Canonical Encoding (is encoded by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Absence Observation**:
A signed record that a version was not seen. It carries an observation time
and never a deletion time, so native expiry with no actor report stays
*missing or unconfirmed* rather than becoming a deletion claim.
_Avoid_: deletion evidence, expiry proof, tombstone
_Subsystems_: Shared Contract Types, Deletion Evidence and Consume Outcome
_Files_: crates/ksp-types/src/evidence.rs
_Relates to_: Deletion Report (is distinguished from), Record Version (names)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced. "deletion evidence" is
  avoided because an observation is not evidence of erasure.

**Sweep Proof**:
The signed record a sweeper writes at the end of every run — success or failure —
carrying its run window, the interval its arming declared (when one did), the interval
it actually realised, what it removed, what it found already absent, what was not yet
due, its error classes, the arming it ran under, the admin **Principal** who armed it,
and the digest of the proof it follows. It proves that a run happened and what the run
reported; it does not prove that any named version is gone, and it carries no path,
secret identifier or version.
_Avoid_: sweep receipt, deletion proof, evidence of erasure, proof
_Subsystems_: Shared Contract Types, Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/proof.rs
_Relates to_: Proven Cadence (establishes), Lease Capability (supplies the interval of a `Scheduled` one), Admission Decision (gates), Sweeper Arming (names), Audit Record (links), Canonical Encoding (is signed over)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced to replace reading a
  declaration or querying a unit manager. "deletion proof" is avoided because a
  proof of a run is not a proof of an effect.
- 2026-10-24 (002-file-os-split-sweeper): Implemented in `ksp-backend` beside the
  gate that reads it, not in `ksp-types`: it is evidence, not a shared wire type.
  Prior files: crates/ksp-types/src/evidence.rs.

**Audit Record**:
One signed entry in an **Audit Chain**: the actor, the component, the operation,
the target, the outcome and the observing time, chained to the previous entry by
its digest. It carries no secret material.
_Avoid_: log line, event, audit event
_Subsystems_: Shared Contract Types, Backend Admission and Durable Arming
_Files_: crates/ksp-types/src/evidence.rs
_Relates to_: Audit Chain (is one entry of), Actor ID (names the signer), Signature Domain (is scoped by)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced; the record is the unit
  that can be verified, the chain is what says whether the record set is whole.

**Capability Acceptance**:
What a run accepted about one **Host Capability**: the capability, the
**Capability Adapter** that ran and the **Guarantee Level** it established.
Every field is a public fact, so nothing can be formatted into it.
_Avoid_: capability record, acceptance, posture receipt
_Subsystems_: Shared Contract Types
_Files_: crates/ksp-types/src/evidence.rs
_Relates to_: Audit Record (is carried by), Host Capability (is about), Guarantee Level (is carried)
_History_:
- 2026-10-30 (004-os-capability-adapters): Term introduced. The acceptance is
  what makes an unenforced capability durable, so a later reader can tell an
  accepted absence from an unnoticed one.

**Audit Chain**:
The append-only sequence of **Audit Records** written by one signer, each naming
its predecessor's digest. Chains are per writer, so no cross-principal lock is
needed; the order between two chains is a timestamp claim and is disclosed as one.
A verifier reports a fork, a gap or a truncation but cannot prove the tail is
complete without a head digest kept outside the chain.
_Avoid_: audit log, ledger, journal
_Subsystems_: Shared Contract Types, Backend Admission and Durable Arming
_Files_: crates/ksp-types/src/evidence.rs
_Relates to_: Audit Record (is made of), Principal (has one per writer), Signing Key (is signed by)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced with per-writer chains,
  no shared lock, and an honest limit on completeness.

**Audit Segment**:
The one file inside an **Audit Chain** directory that a single signing key appends
to. The directory answers *whose* log it is (the actor principal); the segment
answers *which writer* wrote it, because the admin's command and the tenant's own
command act for one principal under two keys and a segment appended by both could
not be verified under either.
_Avoid_: log file, chunk, shard
_Subsystems_: Shared Contract Types, Backend Admission and Durable Arming
_Files_: crates/ksp-deletion/src/audit.rs
_Relates to_: Audit Chain (is one file of), Audit Record (contains), Signing Key (is named by)

**Host Capability**:
A function of the machine that Keyspout depends on and must state honestly:
restricting the paths a confined process may reach, or holding key material in
memory the kernel protects. It is a property of the *host*, not of a
deployment, and it is not the backend's **Lease Capability**.
_Avoid_: capability, lease capability, feature flag, backend capability
_Subsystems_: Shared Contract Types, Host Confinement and Key Material Posture
_Files_: crates/ksp-types/src/capability_config.rs
_Relates to_: Capability Adapter (is established by), Capability Configuration (is named in), Guarantee Level (is qualified by)
_History_:
- 2026-10-28 (004-os-capability-adapters): Term introduced. Named "Host
  Capability" to keep it distinct from the backend's "Lease Capability", which
  the design spec also uses.

**Capability Adapter**:
A named mechanism that establishes one **Host Capability** on one host, behind
a trait, so that the mechanism can be chosen by configuration rather than
hard-wired into a caller. The set of adapters is closed: a name outside it is
a configuration error, never a runtime lookup.
_Avoid_: plugin, provider, driver, backend
_Subsystems_: Shared Contract Types, Host Confinement and Key Material Posture
_Files_: crates/ksp-types/src/capability_config.rs
_Relates to_: Host Capability (establishes), Guarantee Level (declares), Adapter Availability (is assessed by), Adapter Name (is identified by)
_History_:
- 2026-10-28 (004-os-capability-adapters): Term introduced.

**Adapter Name**:
The stable identifier of one **Capability Adapter**, drawn from a closed set of
five. An identifier outside the set is refused where it is read, so that it
never reaches the registry.
_Avoid_: adapter id, adapter type, mechanism name
_Subsystems_: Shared Contract Types, Host Confinement and Key Material Posture
_Files_: crates/ksp-types/src/capability_config.rs
_Relates to_: Capability Adapter (identifies), Capability Setting (lists), Adapter Kind (is discriminated by)
_History_:
- 2026-10-28 (004-os-capability-adapters): Term introduced.

**Adapter Kind**:
The discriminant of an **Adapter Name**: one variant per adapter in the closed
set. A registry matches on the kind rather than on the name string, so that
the compiler proves the match exhaustive and an adapter added without a
registry arm breaks the build.
_Avoid_: enum variant, tag, discriminator
_Subsystems_: Shared Contract Types, Host Confinement and Key Material Posture
_Files_: crates/ksp-types/src/capability_config.rs
_Relates to_: Adapter Name (is the discriminant of), Capability Adapter (is identified by)
_History_:
- 2026-10-29 (004-os-capability-adapters): Term introduced.

**Guarantee Level**:
What a **Capability Adapter** establishes for its **Host Capability**, on a
scale from `Full` through `Weakened` to `None`. The levels are relative to a
capability, not to each other, and `None` means the capability is not
established at all.
_Avoid_: strength, security level, trust level, mode
_Subsystems_: Shared Contract Types, Host Confinement and Key Material Posture
_Files_: crates/ksp-types/src/capability_config.rs
_Relates to_: Capability Adapter (declares), Host Capability (qualifies), Requirement Level (is checked against)
_History_:
- 2026-10-28 (004-os-capability-adapters): Term introduced.

**Requirement Level**:
Whether a run refuses when a **Host Capability** cannot be established. The
level is the operator's, read from the **Capability Configuration** rather
than fixed in a code path.
_Avoid_: strictness, optional flag, required flag
_Subsystems_: Shared Contract Types, Host Confinement and Key Material Posture
_Files_: crates/ksp-types/src/capability_config.rs
_Relates to_: Capability Setting (holds), Guarantee Level (is checked against)
_History_:
- 2026-10-28 (004-os-capability-adapters): Term introduced.

**Capability Configuration**:
The operator's statement of which **Capability Adapter** to use for each
**Host Capability**, in what order, and whether the run requires it. It is pure
data; the file format that carries it belongs to the command line.
_Avoid_: policy, preferences, settings
_Subsystems_: Shared Contract Types, Keyspout Command-Line Interface
_Files_: crates/ksp-types/src/capability_config.rs
_Relates to_: Host Capability (names), Capability Setting (holds), Adapter Name (lists), Requirement Level (holds)
_History_:
- 2026-10-28 (004-os-capability-adapters): Term introduced.

**Capability Setting**:
One **Host Capability**'s half of the **Capability Configuration**: the ordered
list of **Adapter Names** to try, and the **Requirement Level** to apply.
_Avoid_: capability entry, per-capability block
_Subsystems_: Shared Contract Types, Keyspout Command-Line Interface
_Files_: crates/ksp-types/src/capability_config.rs
_Relates to_: Capability Configuration (is one of), Adapter Name (lists), Requirement Level (holds)
_History_:
- 2026-10-28 (004-os-capability-adapters): Term introduced.

**Adapter Availability**:
The host's answer about one **Capability Adapter**: whether the host provides
its mechanism, and, when it does not, the host's own reason. The reason is what
a refusal and a disclosure quote, so it is carried rather than summarised.
_Avoid_: support, platform check, feature flag
_Subsystems_: Shared Contract Types, Host Confinement and Key Material Posture
_Files_: crates/ksp-types/src/capability_config.rs
_Relates to_: Capability Adapter (is assessed by), Guarantee Level (precedes)
_History_:
- 2026-10-28 (004-os-capability-adapters): Term introduced.

## Relationships

- A **Record Path** contains a **Vault ID**, a **User ID**, a **Level**, an **Opaque Secret ID** and a **Record Version**
- An **Actor ID** covers a **User ID** or an **Agent ID**
- **Bound Metadata** names exactly one **Record Version**
- **Agent Keys** comprises one **Signing Key** and one **Recipient Key**
- Every signed structure uses one **Canonical Encoding** and one **Signature Domain**
- A **Capability Configuration** holds one **Capability Setting** per **Host Capability**
- A **Capability Setting** holds an ordered list of **Adapter Names** and one **Requirement Level**
- A **Capability Adapter** declares one **Guarantee Level** for its **Host Capability**
- An **Adapter Availability** carries the host's reason when the **Capability Adapter** is unavailable
- An **Adapter Name** carries one **Adapter Kind**, and a registry matches on the kind
- A **Golden Fixture** pins a **Canonical Encoding**
- An **Admission Decision** is produced from a **Lease Capability** and a requested duration
- A **Sealed Bundle** holds **Content Key** material and is the only value Shamir recovery may split
- An **Absence Observation** names a **Record Version** and is distinguished from a **Deletion Report**
- A **Sweep Proof** supplies the proven interval of a `Scheduled` **Lease Capability** and gates the **Admission Decision**
- An **Audit Chain** is a sequence of **Audit Records** by one signer, each naming its predecessor's digest
- A **User ID** is a **Principal**'s UUID, so a path segment and a binding cannot disagree

## Flagged Ambiguities

- "id" was used to mean any of the identifier kinds — resolved: each
  identifier kind has its own name, and the `* ID` suffix is the only
  abbreviation permitted.
- "path" was used to mean both a record's storage location and a filesystem
  path — resolved: **Record Path** is the storage location; a filesystem path
  is always written "file path".
- "public key" was used to mean both a signing key and a recipient key —
  resolved: "Recipient Key" is the X25519 half; "Signing Key" is the Ed25519
  half. A fingerprint binds both plus both key IDs.
- "expiry" was used to mean both the deadline a lease is given and the
  backend's ability to enforce it — resolved: the deadline is a duration in
  the **Admission Decision**; the backend's ability is a **Lease
  Capability**. A configured expiry is not a guarantee.
- "proof" was used to mean both evidence that a sweep ran and evidence that a
  named version was deleted — resolved: a **Sweep Proof** is evidence of a run
  and its report; only a **Deletion Report** or an **Absence Observation**
  speaks about a version, and neither is erasure.
- "bundle" was used for both a user's sealed key material and a group of
  unrelated records — resolved: a **Sealed Bundle** is always the user's own
  sealed key material.
- "capability" was used for both a host function the workspace depends on and
  a backend's configured guarantee about a lease deadline — resolved: a
  **Host Capability** is a function of the machine; the backend's is a
  **Lease Capability**. The two never meet, and the design spec uses both
  words.
