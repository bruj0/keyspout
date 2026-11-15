---
context_name: "Deletion Evidence and Consume Outcome"
version: "1"
subsystem: "crates/ksp-deletion"
created: "2026-10-21T16:26:00+00:00"
updated: "2026-10-25T00:25:00+02:00"
---

# Deletion Evidence and Consume Outcome

The subsystem that answers "what do we actually know about this version, and
who is responsible?". It distinguishes an authorization to delete, an actor's
signed claim that it deleted, and an observer's signed statement that the
version was absent. It also sequences the consume operation and states its
postcondition honestly.

Identifier and encoding terms live in the shared-types context; this context
owns only the concepts specific to deletion evidence and the consume
sequence.

## Language

**Deletion Intent**:
A signed, key-free authorization to attempt cleanup of one exact version by a
deadline. It is not a tombstone and not a report.
_Avoid_: tombstone, delete request, order, lease
_Subsystems_: Deletion Evidence and Consume Outcome, Backend Admission and Durable Arming
_Files_: crates/ksp-types/src/evidence.rs, crates/ksp-deletion/src/intent.rs
_Relates to_: Record Version (targets), Durable Arming (is written by), Deletion Report (is fulfilled by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced. "tombstone" is explicitly
  avoided because the design spec forbids treating an intent as one.

**Deletion Report**:
A separately retained, signed, version-scoped statement by the deleting actor,
written after backend acknowledgement, binding intent, actor, signer key ID,
reason, outcome and the claimed time. It attributes a claim; it does not
prove destruction.
_Avoid_: deletion proof, receipt, attestation, certificate of deletion
_Subsystems_: Deletion Evidence and Consume Outcome
_Files_: crates/ksp-types/src/evidence.rs, crates/ksp-deletion/src/report.rs
_Relates to_: Deletion Intent (fulfils), Actor (is signed by), Absence Observation (is distinct from)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Absence Observation**:
A signed statement by an authorized observer that a version was absent at a
stated observation time. It names no deleting actor and invents no deletion
time.
_Avoid_: missing record, negative report, evidence of deletion
_Subsystems_: Deletion Evidence and Consume Outcome
_Files_: crates/ksp-types/src/evidence.rs, crates/ksp-deletion/src/observation.rs
_Relates to_: Deletion Report (is distinct from), Record Version (observes)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Actor**:
The principal that performed a deletion and signs its own deletion report.
_Avoid_: deleter, executor, agent, operator
_Subsystems_: Deletion Evidence and Consume Outcome
_Files_: crates/ksp-deletion/src/report.rs
_Relates to_: Deletion Report (signs), Authorized Deleter (must be)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Authorized Deleter**:
The set of actors permitted to sign a report for one specific version. A
report signed by anyone else is rejected even when the signature is valid.
_Avoid_: permission, deleter list, approver
_Subsystems_: Deletion Evidence and Consume Outcome
_Files_: crates/ksp-types/src/evidence.rs
_Relates to_: Actor (is drawn from), Deletion Report (is scoped by), Record Version (is scoped by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Missing Unconfirmed**:
The state of a version that is absent without an authenticated actor report.
It is reported as unconfirmed, never upgraded to a deletion.
_Avoid_: deleted, gone, expired, confirmed deleted
_Subsystems_: Deletion Evidence and Consume Outcome
_Files_: crates/ksp-deletion/src/observation.rs
_Relates to_: Absence Observation (may follow), Deletion Report (is distinguished from)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Acknowledgement Journal**:
The durable record of a delete acknowledgement, allowing an idempotent retry
of a report write by intent, version, actor and event without restoring
ciphertext.
_Avoid_: retry log, outbox, write-ahead log, dead letter queue
_Subsystems_: Deletion Evidence and Consume Outcome
_Files_: crates/ksp-deletion/src/journal.rs
_Relates to_: Operation Identity (is keyed by), Deletion Report (is retried via), Durable Arming (mirrors)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Field Projection**:
The single reduction of one decoded log-record payload to printable fields, where
a field name that may hold a secret becomes `Redacted` and every other value
keeps only its type and shape.
_Avoid_: field scrubber, redaction pass, preview
_Subsystems_: Deletion Evidence and Consume Outcome
_Files_: crates/ksp-deletion/src/audit.rs
_Relates to_: Log Projection (is consumed by), Audit Event (reduces)
_History_:
- 2026-10-25 (002-file-os-split-sweeper): Term introduced.

**Consume**:
The ordered operation that retrieves a version, decrypts it, hands plaintext
to the child without persisting a recovery copy, deletes that exact version,
and signs a report after acknowledgement.
_Avoid_: consume-once, read-and-delete, burn, one-shot read
_Subsystems_: Deletion Evidence and Consume Outcome
_Files_: crates/ksp-deletion/src/consume.rs
_Relates to_: Record Version (is removed by), Deletion Report (is produced by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced. "consume-once" is avoided
  because the operation is explicitly not exactly-once.

**Lost Fresh Fetch**:
The condition in which a version has been removed but a later fresh fetch
still finds it, or in which a removal succeeded and the child then failed. The
run exits with its own distinct code and never auto-remints.
_Avoid_: lost capability, lease lost, expired lease, re-mint needed
_Subsystems_: Deletion Evidence and Consume Outcome
_Files_: crates/ksp-deletion/src/consume.rs
_Relates to_: Consume (is a state of), Record Version (is removed), Fresh Fetch (is the counterpart of)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Fresh Fetch**:
A retrieval that happens after a removal, from an honest store. It fails
because the version is gone, not because a token was revoked.
_Avoid_: later read, refetch, subsequent fetch
_Subsystems_: Deletion Evidence and Consume Outcome
_Files_: crates/ksp-deletion/src/consume.rs
_Relates to_: Lost Fresh Fetch (is the counterpart of), Record Version (is fetched)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Recovery Copy**:
A persisted duplicate of a delivered plaintext, kept so a failed run could be
retried. Consume never creates one.
_Avoid_: backup, spool, shadow copy, cache
_Subsystems_: Deletion Evidence and Consume Outcome
_Files_: crates/ksp-deletion/src/consume.rs
_Relates to_: Consume (is forbidden by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Pinned Key**:
A public key a host trusts because it was pinned outside the log — the admin
anchor, the user policy the admin signed, or an enrolment record the operator
read a fingerprint from. Verification resolves a signer here and never from the
record's own key id, filename or fingerprint.
_Avoid_: trusted key, known key, allowlist entry
_Subsystems_: Deletion Evidence and Consume Outcome
_Files_: crates/ksp-deletion/src/audit.rs, crates/ksp/src/audit_verify.rs
_Relates to_: Audit Record (is verified by), Unpinned Signer (is the absence of), Head Digest (is read beside)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced. A verifier that reads the
  key out of the artifact it checks answers its own question (Misfit W).

**Unpinned Signer**:
A record whose named signing key no pin holds. It is a finding of its own, not a
bad signature: the remedy is to find the key and pin it, or to distrust the
record. A key retired by rotation is reported this way on a host that keeps no
public archive, because claiming "archived" would mean trusting the record.
_Avoid_: unknown key, invalid signature, bad key
_Subsystems_: Deletion Evidence and Consume Outcome
_Files_: crates/ksp-deletion/src/audit.rs
_Relates to_: Pinned Key (is the absence of), Audit Record (is a finding about)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced.

**Head Digest**:
The digest of a chain's last record, written down outside the log. It is the only
thing that turns a shortened but internally valid chain into a mismatch; without
one the honest answer is that completeness is unknown.
_Avoid_: checksum, hash, log pointer
_Subsystems_: Deletion Evidence and Consume Outcome
_Files_: crates/ksp-deletion/src/audit.rs, crates/ksp/src/audit_verify.rs
_Relates to_: Audit Record (is the digest of one), Chain Break (is distinguished from)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced.

## Relationships

- A **Deletion Intent** authorizes a **Deletion Report** for one record version
- An **Actor** signs a **Deletion Report** only if it is an **Authorized Deleter**
- A **Deletion Report** and an **Absence Observation** are different evidence for the same record version
- **Missing Unconfirmed** is the state when neither exists
- **Consume** produces a **Deletion Report** and may end in **Lost Fresh Fetch**
- The **Acknowledgement Journal** makes the report write retryable by operation identity
- **Consume** never persists a **Recovery Copy**
- An **Audit Record** verifies only against a **Pinned Key**; the record never supplies its own
- A **Head Digest** turns a shortened chain into a **Head Mismatch**, and its absence leaves completeness unknown
- An **Unpinned Signer** and a bad signature are different findings with different remedies

## Flagged Ambiguities

- "deletion" was used to mean both the act and the evidence of the act —
  resolved: "delete" is the backend operation; "Deletion Report" is the signed
  claim; "Absence Observation" is the signed absence.
- "deleted" was used to mean both "the store no longer returns this version"
  and "an actor has claimed responsibility" — resolved: the first is
  **Missing Unconfirmed** until a report exists; the second is a
  **Deletion Report**.
- "consume" was used to imply exactly-once — resolved: **Consume** promises
  only that later **Fresh Fetch** fails.
