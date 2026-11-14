---
context_name: "Record Cryptography and Version Integrity"
version: "1"
subsystem: "crates/ksp-record"
created: "2026-10-21T16:20:00+00:00"
updated: "2026-10-21T16:36:00+00:00"
---

# Record Cryptography and Version Integrity

The subsystem that turns a secret into an immutable, bound, tamper-evident
stored record, and that decides whether a recipient key is safe to encrypt to.
It owns the key schedule, the associated data, and the version-commit write
path. It never decides *who* may read a record and never talks to a backend
policy.

Identifier and encoding terms live in the shared-types context; this context
owns only the concepts specific to sealing and committing a record. The shared
**Record Path** is built and parsed in `src/path.rs`, and nothing else formats
its five segments.

## Language

**Record**:
An immutable stored unit holding signed metadata, an AEAD content blob and an
HPKE envelope. The version, not the record, is the unit a lease deletes.
_Avoid_: secret, entry, row, document
_Subsystems_: Record Cryptography and Version Integrity
_Files_: crates/ksp-record/src/envelope.rs
_Relates to_: Record Version (is instance of), Content Key (is sealed in), Bound Metadata (names)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Content Key**:
A fresh random 256-bit symmetric key that encrypts one record version's
payload. It exists in the clear only inside the sealing process; every saved
artifact carries it sealed to a recipient key.
_Avoid_: sk, secret key, data key, DEK, master key
_Subsystems_: Record Cryptography and Version Integrity, Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-record/src/envelope.rs, crates/ksp-identity/src/delivery.rs
_Relates to_: Record (encrypts), Recipient Key (is sealed to), Bound Metadata (binds)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced. "sk" is retained as an
  explicit avoidance because the design spec uses it for the same thing.

**KEM Validation Gate**:
The check that rejects a recipient or encapsulated key whose X25519 shared
secret would be all zero, in both directions, before any envelope exists.
_Avoid_: low-order check, point validation, sanity check
_Subsystems_: Record Cryptography and Version Integrity
_Files_: crates/ksp-record/src/kem.rs
_Relates to_: Recipient Key (validates), HPKE Envelope (gates creation of)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**HPKE Envelope**:
The RFC 9180 ciphertext sealing a content key to one recipient key under a
named `info` label and a bound associated-data value.
_Avoid_: wrapped key, sealed key, box, capsule
_Subsystems_: Record Cryptography and Version Integrity, Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-record/src/envelope.rs, crates/ksp-identity/src/delivery.rs
_Relates to_: Content Key (contains), Recipient Key (sealed to), KEM Validation Gate (is gated by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Content Blob**:
The AEAD ciphertext over a record's name and value, bound to the same
associated data as the record envelope.
_Avoid_: ciphertext, payload, encrypted value
_Subsystems_: Record Cryptography and Version Integrity
_Files_: crates/ksp-record/src/blob.rs
_Relates to_: Bound Metadata (is bound to), Content Key (encrypts)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Conditional Publication**:
The write that commits a complete record version and makes it the current
head only if no competing writer already holds that version or head.
_Avoid_: atomic write, compare-and-swap, last-write-wins
_Subsystems_: Record Cryptography and Version Integrity
_Files_: crates/ksp-record/src/version.rs
_Relates to_: Record Version (publishes), Blob Store (writes to)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Version Conflict**:
The refusal that occurs when a competing writer already holds the version or
head being published. The conflict is refused, never overwritten.
_Avoid_: clash, collision, EEXIST
_Subsystems_: Record Cryptography and Version Integrity
_Files_: crates/ksp-record/src/version.rs
_Relates to_: Conditional Publication (is raised by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Blob Store**:
The storage contract the record subsystem writes through: `get`, `put`,
`list` and `delete` over opaque blobs, with no decrypt method. The
conditional publication is expressed through the store's own
compare-and-set write.
_Avoid_: backend, storage adapter, blob client
_Subsystems_: Record Cryptography and Version Integrity, Backend Admission and Durable Arming
_Files_: crates/ksp-record/src/version.rs
_Relates to_: Conditional Publication (is written through), Record (is stored in)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced. "backend" is avoided
  because the concrete backends are a later work package, while the
  contract is what this subsystem owns.

**Provider Guard**:
The build-time check that refuses an HPKE provider below the version whose
`dh` implementation performs the all-zero shared-secret check. It reads
the *resolved* version, not the declared minimum, so a downgrade fails the
build rather than passing silently.
_Avoid_: version pin, dependency check, cargo audit
_Subsystems_: Record Cryptography and Version Integrity
_Files_: crates/ksp-record/src/provider_guard.rs, crates/ksp-record/build.rs
_Relates to_: KEM Validation Gate (guards the provider behind)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

## Relationships

- A **Record Version** is a **Record** at one version number
- A **KEM Validation Gate** guards creation of an **HPKE Envelope**
- **Conditional Publication** makes a **Record Version** current
- A **Version Conflict** is refused, never resolved by overwriting
- A **Blob Store** holds **Record** versions and expresses **Conditional Publication**
- A **Provider Guard** protects the **KEM Validation Gate** from a downgraded provider

## Flagged Ambiguities

- "secret" was used to mean both the *value* a user stores and the *content
  key* that protects it — resolved: "value" is the user's plaintext;
  "Content Key" is the cryptographic key. A "secret" in a path or filename is
  neither.
- "head" was used for both the current version pointer and the record's
  payload header — resolved: the pointer is written "head"; a payload
  header is written "header".
- "audit" was used for both a security review of dependencies and a log of
  what happened — resolved: the **Provider Guard** is a build check; a log
  of what happened is an "audit event".
