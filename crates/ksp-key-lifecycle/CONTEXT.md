---
context_name: "Durable Key Lifecycle"
version: "1"
subsystem: "crates/ksp-key-lifecycle"
created: "2026-10-23T07:31:35Z"
updated: "2026-10-23T07:31:35Z"
---

# Durable Key Lifecycle

The host-local boundary that keeps one enrolled agent or pinned admin signing
identity available across foreground invocations without giving the CLI raw
private keys. S2 alone interprets the typed key bundle; this context owns the
protected file, its durability and verified reload.

## Language

**Protected Key File**:
An owner-only local file containing one versioned S2-encoded agent or admin
identity bundle, never a plaintext user vault or token.
_Avoid_: token file, vault file, credentials file
_Subsystems_: Durable Key Lifecycle
_Files_: crates/ksp-key-lifecycle/src/file.rs
_Relates to_: Agent Keys (persists), Trust Anchor (is checked against)
_History_:
- 2026-10-23 (001-keyspout-mvp): Term introduced for Misfit R.

**Verified Key Reload**:
An operation that returns typed S2 authority only after the expected identity,
role, key IDs and derived public keys agree with pinned trust state and the
Protected Key File passes owner-only checks.
_Avoid_: automatic enrollment, key regeneration, bearer access
_Subsystems_: Durable Key Lifecycle, Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-key-lifecycle/src/lib.rs, crates/ksp-identity/src/key_bundle.rs
_Relates to_: Protected Key File (reads), Enrolment Fingerprint (checks)
_History_:
- 2026-10-23 (001-keyspout-mvp): Term introduced for Misfit R.

**Durable Key Replacement**:
An atomic, synced replacement of a Protected Key File that either preserves the
previous complete identity or publishes a complete new identity, never a
partially accepted one.
_Avoid_: overwrite in place, silent rotation, key reset
_Subsystems_: Durable Key Lifecycle
_Files_: crates/ksp-key-lifecycle/src/file.rs
_Relates to_: Protected Key File (replaces), Rotation (does not revoke old artifacts)
_History_:
- 2026-10-23 (001-keyspout-mvp): Term introduced for Misfit R.

## Relationships

- **Verified Key Reload** reads a **Protected Key File** and returns only a verified typed identity.
- **Durable Key Replacement** replaces a **Protected Key File** without exposing a partial identity.
- **Agent Keys** remain independent signing and recipient pairs owned by S2's types.

## Flagged Ambiguities

- A **Protected Key File** holds host-local private identity material; a **Delivery Artifact** is a recipient-sealed transferable token. They are never interchangeable.
