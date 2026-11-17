---
context_name: "Identity, Sealed Delivery and Policy Verification"
version: "1"
subsystem: "crates/ksp-identity"
created: "2026-10-21T16:22:00+00:00"
updated: "2026-10-23T18:20:00Z"
---

# Identity, Sealed Delivery and Policy Verification

The subsystem that answers "who is speaking, and may they have this?". It
enrols identities, binds each identity to a fingerprint, seals a delivery to a
verified recipient key, signs what it issues, and verifies what it receives
against a pinned trust anchor. It never stores a record and never decides
whether a backend may host a lease.

Identifier, level and encoding terms live in the shared-types context; this
context owns only the concepts specific to trust and delivery.

## Language

**Enrollment Record**:
An identity's public keys, its key IDs, its identity and the fingerprint that
binds them, signed by the admin. It is the trust anchor an agent verifies
against.
_Avoid_: registration, onboarding record, user record, key record
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/enrolment.rs
_Relates to_: Enrolment Fingerprint (binds), Agent Keys (contains), Policy (trusts)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Audit Scope**:
The set of audit records one caller may read, decided from the pinned key that
proved the caller and not from anything the request claims. A tenant sees what it
authored and what names its own level; the admin sees every chain. A requested
principal selects a subject, so it can narrow a view and never widen one.
_Avoid_: permission, access level, audit filter
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/scope.rs
_Relates to_: Trust Anchor (the pin decides), Audit Record (is selected from), Policy Denial (refuses with exit 2)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced.

**Enrolment Fingerprint**:
A single verified digest over an identity plus *both* its public keys and
*both* its key IDs. Verifying a fingerprint is the only way a key becomes
trusted.
_Avoid_: key fingerprint, pin, thumbprint, checksum
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/fingerprint.rs
_Relates to_: Enrollment Record (binds), Agent Keys (summarises), Recipient Key (covers)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Scoped Key Use**:
The only way a caller outside this context may use a private half: the key
lends its bytes to one closure and returns only that closure's non-secret
result. The type cannot stop a closure from copying the bytes out, so the rule
is on the caller — never return, log or store the borrowed half.
_Avoid_: key getter, private_bytes, key export, raw key accessor
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/enrolment.rs, crates/ksp-identity/src/key_bundle.rs
_Relates to_: Agent Keys (lends), Durable Key Lifecycle (reloads the authority that lends)
_History_:
- 2026-10-23 (001-keyspout-mvp): Term introduced for Misfit R, after the
  integration layer found that a typed identity could be loaded but not used.

**Trust Anchor**:
A key pinned on the host beforehand and never taken from the artifact being
verified. A key inside a token is data, never an anchor.
_Avoid_: root key, issuer, certificate, trust store
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/policy.rs, crates/ksp-identity/src/token.rs
_Relates to_: Enrollment Record (is), Policy (is signed by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Policy**:
An admin-signed statement of a user's identity, the enrolment keys it trusts,
which user-level secrets may be shared and with whom, a maximum TTL per level,
a monotonic revision and a validity period.
_Avoid_: ACL, permissions, grant, ruleset
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/policy.rs, crates/ksp-identity/src/policy_edge.rs
_Relates to_: Enrollment Record (trusts), Trusted Checkpoint (is versioned against), Level (bounds), Publication (names the entry it authorises)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-11-16 (014-policy-scoped-sharing): Redefined as one signed access edge
  naming exactly one user, one secret version and one target (one agent UUID or
  `AnyEnrolled`). **Implemented**: `PolicyEdge` in
  `crates/ksp-identity/src/policy_edge.rs`, recorded and published by
  `crates/ksp/src/edges.rs`. The product-of-lists form survives only as the
  legacy `admin policy --show` read-back; no new grant is written into it.
  Prior definition: product of `shareable_secrets` and `shareable_agents`.

**Publication**:
A sealed record the admin writes at `p/<vault>/<admin>/granted/<secret-id>/<version>`
so that a policy-bound delivery can be read by any principal and opened only by
the agent the policy names.
_Avoid_: granted copy, shared blob, export
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp/src/publication.rs
_Relates to_: Policy (is published for), Level (sits at), Delivery Artifact (is read in place by)
_History_:
- 2026-11-16 (014-policy-scoped-sharing): Term introduced by specification.
- 2026-11-17 (014-policy-scoped-sharing): **Implemented** — the `granted` level,
  the derived path, the `0750`/`0740` permission class, an entry sealed to the one
  agent a grant names, and the content key sealed to the admin vault so a later
  entry can recover it. Test `crates/ksp/tests/publication.rs`.

**Cooperative Target**:
The `AnyEnrolled` policy target, under which the record is sealed to the user
rather than to an agent, so the agent binding is a checked statement and not a
cryptographic restriction.
_Avoid_: any-agent policy, wildcard grant
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/policy_edge.rs, crates/ksp/src/token.rs
_Relates to_: Policy (is a target of), Publication (is not used by), Downstream Copy (reuses)
_History_:
- 2026-11-16 (014-policy-scoped-sharing): Term introduced by specification.
- 2026-11-17 (014-policy-scoped-sharing): **Implemented** — `PolicyTarget::AnyEnrolled`,
  labelled `cooperative` on every read surface, carrying no publication and issuing
  no token (`TokenError::Cooperative`). Its delivery is the agent-level copy the
  user makes herself.

**Trusted Checkpoint**:
The highest policy revision a host has already accepted. Without one, freshness
is unavailable rather than implied.
_Avoid_: floor, watermark, min revision, lock
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/checkpoint.rs
_Relates to_: Policy (bounds revision), Rollback (is detected against)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Rollback**:
The presentation of an older but validly signed policy below the host's
trusted checkpoint. It is a replay, not a valid policy.
_Avoid_: downgrade, stale policy, replay
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/checkpoint.rs
_Relates to_: Trusted Checkpoint (is detected against), Policy (is a)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Delivery Header**:
The signed, fixed-order description of one delivery: vault, issuer, agent
identity, both agent public keys and key IDs, level, scope, exact paths and
versions, expiry and `jti`.
_Avoid_: token header, claims, manifest, descriptor
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/header.rs
_Relates to_: Delivery Artifact (is part of), Proof of Possession (binds), Level (part of)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Delivery Artifact**:
The complete saved or transferred delivery: one canonical CBOR document whose
fields are the delivery header, the HPKE envelope and the issuer signature.
_Avoid_: token file, blob, delivery, package
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/delivery.rs, crates/ksp-identity/src/token.rs
_Relates to_: Delivery Header (contains), HPKE Envelope (contains), Signature (contains), Proof of Possession (is required by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced. "token file" is avoided
  because the artifact is not necessarily a file and "token" alone is
  ambiguous between the artifact and its header.

**Signature**:
An Ed25519 signature produced by a signing key over a domain-separated
canonical encoding. One signature is never valid in another context.
_Avoid_: signed blob, attestation
_Subsystems_: Identity Sealed Delivery and Policy Verification, Deletion Evidence and Consume Outcome
_Files_: crates/ksp-identity/src/token.rs
_Relates to_: Signing Key (is produced by), Signature Domain (is scoped by), Canonical Encoding (covers)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Proof of Possession**:
An Ed25519 signature by the enrolled agent over a domain-separated preimage
binding the `jti`, the record version, the record path, a hash of the ordered
child argv and a time bucket. It authenticates a compliant invocation; it
does not protect a key already exposed outside the CLI.
_Avoid_: PoP proof, attestation, nonce, challenge
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/pop.rs
_Relates to_: Delivery Header (binds jti), Delivery Artifact (is required by), Signature Domain (scopes)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Time Bucket**:
A 30-second window start, computed as `floor(now/30) x 30`. Five bucket
starts are accepted, at offsets `0, -30, +30, -60, +60` seconds.
_Avoid_: window, tolerance, clock skew allowance
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/pop.rs
_Relates to_: Proof of Possession (is a component of)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced. The five-bucket acceptance
  is explicitly not an elapsed-time tolerance.

**Downstream Copy**:
A new record version created at `agent-<id>` level from a user-level record,
with a fresh content key and a fresh version. The source is untouched and the
copy never travels back upstream.
_Avoid_: share, copy, delegation, mirror
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/delivery.rs
_Relates to_: Level (is placed at), Record Version (is instance of)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Rotation**:
The replacement of an agent's keys with newly authenticated ones, affecting
future minting and trust state. It does not revoke an old key, artifact or
ciphertext pair that was already captured.
_Avoid_: rekey, revoke, reissue
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/enrolment.rs
_Relates to_: Agent Keys (replaces), Enrolment Fingerprint (is recomputed)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced. "revoke" is avoided because
  upstream credential revocation is a separate operation.

**Issuance Ledger**:
The minting host's own append-only record of the tokens it published and the
decisions it made against them — a local owner-only file beside the deployment,
never a registry, never a service.
_Avoid_: token registry, token database, revocation list, central ledger
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/issuance.rs
_Relates to_: Issuance Record (contains), Revocation Mark (is appended to), Delivery Artifact (records the publication of)
_History_:
- 2026-10-23 (001-keyspout-mvp): Term introduced for Misfit R. A crash can only
  cut the file's tail, never rewrite an entry, so a torn tail is reported rather
  than raised.

**Issuance Record**:
One token this host minted: its opaque identifier, agent, secret, exact version,
armed deadline and the policy revision that authorised it. It carries no key, no
content key and no value.
_Avoid_: token entry, token row, mint log line
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/issuance.rs
_Relates to_: Issuance Ledger (is contained by), Delivery Artifact (describes)
_History_:
- 2026-10-23 (001-keyspout-mvp): Term introduced.

**Revocation Mark**:
A recorded decision that one token identifier, or one grant, is no longer honoured
here. It is trust state: it stops future mints and is honoured by a client holding
this ledger, and it does not recall a copy taken earlier.
_Avoid_: revocation, blocklist entry, invalidation, token kill
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/issuance.rs
_Relates to_: Grant Withdrawal (is one form of), Token Standing (produces), Rotation (is not)
_History_:
- 2026-10-23 (001-keyspout-mvp): Term introduced for Misfit H. "revocation"
  alone was avoided because an operator reads it as erasure.

**Grant Withdrawal**:
The narrower policy revision an admin signs to remove one grant, together with the
ledger record of the same decision so a local client sees it without verifying a
whole policy.
_Avoid_: policy edit, permission change, revoke grant
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/policy.rs, crates/ksp-identity/src/issuance.rs
_Relates to_: Policy (advances the revision of), Revocation Mark (is recorded as), Issuance Record (covers)
_History_:
- 2026-10-23 (001-keyspout-mvp): Term introduced. A withdrawal reaches a token
  minted at or before its revision; a later re-grant is a new trust state.

**Token Standing**:
What this host can say about one identifier: live, revoked, or unknown — where
unknown records whether the host held a ledger at all.
_Avoid_: token status, token state, validity, verdict
_Subsystems_: Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-identity/src/issuance.rs
_Relates to_: Issuance Record (is about), Revocation Mark (decides), Proof of Possession (is checked separately from)
_History_:
- 2026-10-23 (001-keyspout-mvp): Term introduced. Unknown never refuses a token:
  a host that did not mint it has nothing to say about it.

## Relationships

- **Scoped Key Use** is what a caller outside this context gets instead of key
  bytes; it lends to one closure and returns only the result.

- An **Enrolment Fingerprint** binds an **Enrollment Record** to its agent keys
- A **Trust Anchor** is an **Enrollment Record** pinned beforehand
- A **Policy** trusts **Enrollment Records** and is versioned against a **Trusted Checkpoint**
- A **Delivery Artifact** contains a **Delivery Header** and an **HPKE Envelope**
- A **Proof of Possession** binds a **Delivery Header** to one compliant invocation
- **Rotation** replaces agent keys without revoking captured artifacts
- An **Issuance Ledger** holds one **Issuance Record** per published **Delivery Artifact**
- A **Revocation Mark** decides a **Token Standing** without reaching a **Downstream Copy**
- A **Grant Withdrawal** advances a **Policy** revision and is recorded as a **Revocation Mark**

## Flagged Ambiguities

- "token" was used to mean both the complete **Delivery Artifact** and its
  **Delivery Header** — resolved: "artifact" is the whole document, "header"
  is the signed description inside it.
- "grant" was used to mean both a **Policy** rule and the resulting decision
  at mint time — resolved: "policy" is the signed rule set; "admission" is the
  decision.
- "verify" was used to mean both checking a signature and checking a
  fingerprint — resolved: "verify" is a signature check; "confirm" is a
  fingerprint match.
- "rekey" was used to mean both **Rotation** of an agent identity and a
  vault-level key change — resolved: **Rotation** is an agent-identity
  operation; a vault-level change is a *vault rekey*
- "revoked" was used to mean both a trust-state decision and an erasure — resolved:
  a **Revocation Mark** is trust state; it stops future mints and clients holding
  the ledger, and it recalls no copy
- "unknown" was used to mean both "this host did not mint it" and "this token is
  invalid" — resolved: unknown is a **Token Standing** that refuses nothing
