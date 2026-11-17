---
version: "1"
project_name: "Keyspout"
created: "2026-10-21T16:50:00+00:00"
updated: "2026-10-25T00:30:00+02:00"
contexts_count: 9
---

# Context Map

Keyspout's vocabulary is split by bounded context. Every term is defined in
exactly one context file; the shared-types context owns the identifiers,
encodings and domain strings that more than one subsystem must agree on
byte for byte.

## Contexts

- [Shared Contract Types](crates/ksp-types/CONTEXT.md) — identifiers, levels, signature domains and the canonical encoding that every subsystem shares.
- [Record Cryptography and Version Integrity](crates/ksp-record/CONTEXT.md) — sealing a secret into an immutable, bound record and committing its version.
- [Identity, Sealed Delivery and Policy Verification](crates/ksp-identity/CONTEXT.md) — who is speaking, may they have this, and what is sealed to whom.
- [Backend Admission and Durable Arming](crates/ksp-backend/CONTEXT.md) — what a store is configured to do, and whether the cleanup has proven that it runs.
- [Deletion Evidence and Consume Outcome](crates/ksp-deletion/CONTEXT.md) — what is actually known about a version, and who is responsible for it.
- [Host Confinement and Key Material Posture](crates/ksp-posture/CONTEXT.md) — what the host can actually enforce, stated honestly before a run.
- [Durable Key Lifecycle](crates/ksp-key-lifecycle/CONTEXT.md) — owner-only key files, crash-safe replacement and verified identity reload across invocations.
- [Keyspout Command-Line Interface](crates/ksp/CONTEXT.md) — the foreground entry point, its exit codes, and the rules about what may be printed.
- [Developer Test Environment](scripts/CONTEXT.md) — the Linux VM the gate needs, the guard that refuses to run its targets elsewhere, and what a status report may claim.

## Inter-Context Relationships

- **Shared Contract Types → Record Cryptography and Version Integrity**: the record subsystem binds the shared bound metadata as associated data and writes the shared record path.
- **Shared Contract Types → Identity, Sealed Delivery and Policy Verification**: the delivery header and proof of possession are encoded with the shared canonical encoding and scoped by the shared signature domains.
- **Shared Contract Types → Deletion Evidence and Consume Outcome**: the deletion intent, report and observation are shared structures with shared signature domains and shared identifiers.
- **Identity, Sealed Delivery and Policy Verification → Durable Key Lifecycle**: S2 supplies and validates opaque typed agent/admin bundles; S6 persists and reloads them without exposing private halves to the CLI.
- **Identity, Sealed Delivery and Policy Verification → the CLI and its consumers**: S2 lends a private half to one closure (Scoped Key Use) so a delivery or record can be opened without key bytes ever reaching the caller.
- **Durable Key Lifecycle → Identity, Sealed Delivery and Policy Verification**: verified key reload restores the same pinned authority for a later invocation.
- **Identity, Sealed Delivery and Policy Verification → Backend Admission and Durable Arming**: verified identity, grant set, requested duration and the level pair are the input to an admission decision.
- **Backend Admission and Durable Arming → Deletion Evidence and Consume Outcome**: the armed intent, the exact version and the deadline are the input to the evidence subsystem.
- **Backend Admission and Durable Arming → every principal**: a sweep proof is signed by the arming admin and verified against pinned keys, so any principal can check the interval the store is admitted under without trusting the store.
- **Record Cryptography and Version Integrity → Deletion Evidence and Consume Outcome**: the record version identity is what a report and an observation must bind.
- **Host Confinement and Key Material Posture → every other context**: posture is reported through its own API and never through the backend capability channel.
- **Deletion Evidence and Consume Outcome → Keyspout Command-Line Interface**: the printable shape of a log record is decided once, in S2, so S3 can render a record it does not understand without inventing fields.
- **All contexts → Keyspout Command-Line Interface**: the CLI is the only place where these subsystems are wired together, and it owns the exit-code vocabulary and the redaction rule.
