---
context_name: "Backend Admission and Durable Arming"
version: "1"
subsystem: "crates/ksp-backend"
created: "2026-10-21T16:24:00+00:00"
updated: "2026-11-07T10:05:00+00:00"
---

# Backend Admission and Durable Arming

The subsystem that answers "may this store hold this lease, and is the
cleanup armed?". It classifies each backend's configured capability, applies
the conservative admission floor, and durably arms a key-free deletion intent
before any token bytes are published.

Identifier and encoding terms live in the shared-types context; this context
owns only the concepts specific to storage capability and arming.

## Language

**Blob Store**:
The storage contract of `get`, `put`, `list` and `delete` over opaque blobs.
It has no decrypt method, so it cannot observe plaintext even by accident.
_Avoid_: backend, store, storage, vault
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/store.rs
_Relates to_: Lease Capability (is declared by), Record Version (is stored as)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced. "backend" is retained as an
  explicit avoidance because the design spec uses it for the same thing.

**Lease Capability**:
Exactly one of `None`, `NativeExpiry` or `Scheduled { interval }`,
describing what a backend is *configured* to do about expiry. It never
describes what has already happened to a copy.
_Avoid_: guarantee, TTL support, expiry support, cleanup level
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-types/src/capability.rs, crates/ksp-backend/src/admission.rs
_Relates to_: Admission Decision (determines), Declared Cadence (is distinct from), Proven Cadence (carries the interval of), Cleanup Lag (is distinct from)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Declared Cadence**:
The interval a backend is configured to run cleanup on. It is a stated
schedule, not a measured delay and not a bound, and admission never uses it
while a **Sweep Proof** can be read instead.
_Avoid_: sweep interval, TTL, retention period, max lag
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/admission.rs, crates/ksp/src/admission.rs
_Relates to_: Lease Capability (is disclosed beside it), Proven Cadence (is distinct from), Admission Floor (does not set it), Cleanup Lag (is not)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-10-24 (002-file-os-split-sweeper): Admission moved to evidence, so the
  declaration is disclosure only; the floor doubles the proven interval instead.

**Proven Cadence**:
The interval the newest usable **Sweep Proof** establishes — measured from the gap
between scheduled runs, declared when only one has run — and the interval admission
uses and `status` prints beside the declaration. A shorter observed gap than the
declaration is a retry, not a faster schedule, so the larger of the two is used.
_Avoid_: actual interval, real cadence, measured lag, effective schedule
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/proof.rs, crates/ksp-backend/src/admission.rs, crates/ksp/src/admission.rs
_Relates to_: Declared Cadence (corrects), Sweep Proof (is measured by), Admission Floor (doubles), Lease Capability (supplies the interval of a `Scheduled` one)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced when admission moved from
  configuration to evidence; reported separately so a disagreement is visible.

**Cleanup Lag**:
The unknown interval between a record's logical expiry and the last copy
disappearing. It is disclosed as unknown, never estimated.
_Avoid_: delay, grace period, retention window
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/status.rs
_Relates to_: Declared Cadence (is not), Lease Capability (is disclosed by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Admission Floor**:
The conservative rule that a `Scheduled` backend admits a requested duration
only when `D >= 2 x interval`. It is an admission policy for this
gate, not a timing theorem and not a claim about physical deletion.
_Avoid_: minimum TTL, safety margin, two-times rule, guarantee
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-types/src/capability.rs, crates/ksp-backend/src/admission.rs
_Relates to_: Proven Cadence (doubles), Admission Decision (produces)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Admission Decision**:
The admitted-or-refused outcome of checking a lease capability, a requested
duration, a policy and a grant set. A refusal names the reason and the
capability that produced it.
_Avoid_: allow, gate, check, permission result
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/admission.rs
_Relates to_: Lease Capability (is derived from), Admission Floor (is applied), Capability Refusal (is a form of)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Capability Refusal**:
The exit-`7` outcome when the selected backend cannot support the requested
lease. It is a tested success path, not an error condition to be smoothed
over.
_Avoid_: rejection, error, failure, unsupported
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/admission.rs
_Relates to_: Admission Decision (is a form of), Lease Capability (is None when)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Durable Arming**:
The acknowledged, idempotent write of a deletion intent to the backend, using
an operation identity so a lost acknowledgement can be reconciled. No token
bytes exist before it is acknowledged.
_Avoid_: arm, lease, schedule, register
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/sweeper.rs, crates/ksp/src/arm.rs
_Relates to_: Deletion Intent (is a write of), Operation Identity (is keyed by), Arming Acknowledgement (proves)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Operation Identity**:
The stable key that makes a durable arming write idempotent, so a retry after
a lost acknowledgement reconciles rather than duplicates.
_Avoid_: idempotency key, request ID, dedup key, nonce
_Subsystems_: Backend Admission and Durable Arming, Deletion Evidence and Consume Outcome
_Files_: crates/ksp-backend/src/sweeper.rs, crates/ksp/src/arm.rs, crates/ksp-deletion/src/journal.rs
_Relates to_: Durable Arming (is keyed by), Deletion Report (is retried by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Arming Acknowledgement**:
The backend's confirmation that a deletion intent is durably stored. It is the
precondition for publishing a token; losing it blocks publication and forces
reconciliation.
_Avoid_: ack, confirmation, commit
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/sweeper.rs, crates/ksp/src/arm.rs
_Relates to_: Durable Arming (proves), Deletion Intent (is about)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Status Disclosure**:
The one `ksp status` document: effective capability, mechanism, evidence, declared
cadence, admission minimum where scheduled, unknown cleanup lag, known or unknown
retention, the recorded schedule with its **Measured Unit State**, the newest proof of
each outcome, the **Audit Head** and the two postures. Every fact the host cannot
observe is printed as `unknown` with its own reason rather than left blank or filled
with a default. It never asserts erasure or a timing guarantee.
_Avoid_: status, report, health check, capability report
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/status.rs, crates/ksp/src/app.rs, crates/ksp/src/output.rs
_Relates to_: Lease Capability (discloses), Cleanup Lag (is disclosed as unknown), Proven Cadence (names beside the declared one), Run Window (prints), Audit Head (prints)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-10-24 (002-file-os-split-sweeper): Composed into one document from the
  schedule, both proofs, the head and the posture; a disagreement between the
  declared and the proven cadence is stated, and the proven one is what admission uses.

**Run Window**:
The start and end a **Sweep Proof** records for its run, printed beside the proof's age
so a reader can tell when the evidence was produced. A window describes one run; it is
not a lag, a bound or an interval, and does not say when any copy stops existing.
_Avoid_: duration, elapsed, lag, timing
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/proof.rs, crates/ksp-backend/src/status.rs, crates/ksp/src/output.rs
_Relates to_: Sweep Proof (is recorded by), Proven Cadence (is measured from), Cleanup Lag (is not)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced when status had to print the
  proof's window instead of a single age.

**Retention Disclosure**:
Whether the backend's copies are known to survive a delete, and for how long,
or whether that is unknown. It is reported as known or unknown, never assumed.
_Avoid_: backup retention, versioning retention
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/status.rs
_Relates to_: Lease Capability (is disclosed by), Cleanup Lag (is distinct from)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Lease Sweep**:
A foreground invocation that removes the exact versions whose armed deadlines
have passed, journalling each removal through S4. It is a client action on an
honest store, not a store mechanism. Each candidate is **re-read** at delete
time: the listing is a snapshot, and only the record read immediately before the
delete may say that the deadline has passed.
_Avoid_: garbage collection, purge, cleanup job, reaper, daemon
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/sweep.rs
_Relates to_: Durable Arming (reads and re-reads what it armed), Sweep Bound (is limited by), Sweep Report (produces), Backlog (leaves when bounded)
_History_:
- 2026-10-23 (001-keyspout-mvp): Term introduced for Misfits D and O. "gc"
  survives only as a command name; the concept is a sweep.

**Sweep Bound**:
How much of the due set one invocation may remove: a `Lazy` limit for
`secret purge-expired`, or `Batch` for `secret gc`. The bound decides when to
stop, never what to look at.
_Avoid_: batch size, page size, chunk
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/sweep.rs
_Relates to_: Lease Sweep (limits), Sweep Report (records whether it was reached)
_History_:
- 2026-10-23 (001-keyspout-mvp): Term introduced. Reaching the bound is not a
  failure; the next run continues from the same place.

**Sweep Report**:
The counts one sweep observed — selected, removed, already absent, not yet due,
**backlog**, and every record it could not finish — with a sentence that names
the mechanism a `None` backend lacks.
_Avoid_: sweep result, gc stats, sweep summary
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/sweep.rs
_Relates to_: Lease Sweep (is produced by), Arming Acknowledgement (is why a
removal is counted)
_History_:
- 2026-10-23 (001-keyspout-mvp): Term introduced. A zero from a `None` backend
  is reported with its mechanism, never as an absence of copies.

**Backlog**:
Due versions still to remove when a **Sweep Bound** stopped the invocation. It is
zero for an unbounded run, and it is what makes "swept some" distinguishable from
"swept all": a bounded run that reports a backlog says the backend was not
cleared.
_Avoid_: remaining work, queue depth, debt
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/sweep.rs, crates/ksp/src/output.rs
_Relates to_: Lease Sweep (is left by), Sweep Bound (is caused by), Sweep Report (is counted in), Sweep Proof (is not carried by)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced for Misfit H; the proof
  keeps the run's counts, and the backlog belongs to the invocation.

**Already Absent**:
A due armed record naming a version the store did not hold when the sweep
looked. It is not an error and not a removal: this host observed no deletion and
records no deletion time.
_Avoid_: missing, 404, stale, orphan
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/sweep.rs
_Relates to_: Sweep Report (counts separately), Lease Sweep (does not claim)
_History_:
- 2026-10-23 (001-keyspout-mvp): Term introduced for Misfit O.

**Sweeper Declaration**:
The interval, unit name, recording principal and recording time a `file`
deployment states for its cleanup timer. It is configuration and it decides
nothing: admission uses the **Sweep Proof** of a real run, and `status` reports
the declaration beside the proven interval so a disagreement is visible.
_Avoid_: cron config, timer, schedule, guarantee
_Subsystems_: Backend Admission and Durable Arming
_Relates to_: Declared Cadence (supplies), Sweep Proof (is corrected by), Arming Query (is compared with), Lease Capability (discloses, never decides)
_History_:
- 2026-10-23 (002-file-os-split-sweeper): Term introduced so a declaration cannot be read as a mechanism.
- 2026-10-24 (002-file-os-split-sweeper): Demoted to disclosure. A declaration plus a
  unit query still only says a unit exists; only a run's proof is evidence.

**Measured Unit State**:
What the host's service manager reports about the declared unit — active or not,
next elapse, last trigger — with `unknown` for anything the host cannot query. A
last trigger is not a completed sweep and says nothing about what was removed.
_Avoid_: evidence, proof, last sweep, success
_Subsystems_: Backend Admission and Durable Arming
_Relates to_: Sweeper Declaration (completes), Declared Cadence (measures as configured), Sweep Report (is distinct from)
_History_:
- 2026-10-23 (002-file-os-split-sweeper): Term introduced; a fired timer is not a sweep.
- 2026-10-24 (002-file-os-split-sweeper): Demoted to disclosure, for the same reason
  as the declaration: a unit that fired is not a run that finished.

**Sweeper Arming**:
The admin action that installs a scheduled sweep in whatever form the selected
backend provides — a systemd unit or a `launchd` property list on `file`, whichever
the host runs, a crontab entry on `sftp`, a provider lifecycle rule on `s3`, an
external job for `valkey` — and records its kind, identifier, interval, scope and
credential binding. The record is configuration;
what authorises a lease is the signed **Sweep Proof** the armed job writes.
_Avoid_: cron config, timer, declare-sweeper, schedule
_Subsystems_: Backend Admission and Durable Arming
_Relates to_: Sweeper Declaration (is the interval it records), Sweep Proof (is produced by), Lease Capability (decides when proven), Principal Binding (runs under one), Host Platform (decides its default form)
_History_:
- 2026-10-23 (002-file-os-split-sweeper): Term introduced to generalize the file-only declaration to every backend kind.
- 2026-10-24 (002-file-os-split-sweeper): The arming no longer authorises anything by
  itself. A freshly armed backend admits nothing until the first successful proof.
- 2026-10-24 (002-file-os-split-sweeper): `SweeperArming` and `ArmingQuery` are built.
  The record is signed configuration under `sweeper/armings/`; the query is pure — it
  builds the argv an operator runs and interprets an answer, and spawns nothing.
- 2026-11-06 (006-macos-parity-and-design-spec-truth): `file` no longer means a
  systemd unit everywhere. The form follows the host, and both local forms stay
  accepted on either host so a recorded arming can name the machine it will be
  installed on.

**Host Platform**:
The operating system whose scheduler an arming names, passed to the mapping rather
than read from a compile-time branch. It decides the *default* form for a local
store and never the accepted set: a Mac may record a systemd unit to install
elsewhere, and a Linux host may record a property list.
_Avoid_: OS, target, arch, cfg
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/sweeper.rs
_Relates to_: Sweeper Arming (decides its default form), Arming Query (does not
change what can be measured)
_History_:
- 2026-11-06 (006-macos-parity-and-design-spec-truth): Term introduced. A `cfg`
  branch inside the mapping would be untested on whichever host the gate does not
  run, so the platform became a value both mappings can be tested against.

**Arming Query**:
The backend-specific query that answers whether an arming exists, the interval it
is configured at and the scope it covers. Its answer is **disclosure**: it tells a
human whether the thing they armed is present, and it never gates admission.
_Avoid_: arming verifier, validation, config check
_Subsystems_: Backend Admission and Durable Arming
_Relates to_: Sweeper Arming (describes), Measured Unit State (is the systemd form of), Sweeper Declaration (is compared with), Sweep Proof (is the gate instead)
_History_:
- 2026-10-23 (002-file-os-split-sweeper): Term introduced as "Arming Verifier".
- 2026-10-24 (002-file-os-split-sweeper): Renamed. A query that gates admission
  answers a question about configuration, which is not the question admission needs.

**Proof Gate**:
The admission step that reads the newest **successful** **Sweep Proof**, verifies its
signature against the pinned admin key, computes its age on the invoking principal's
clock and admits against the interval the proof reports. No proof means `None`; a failed
run never resets the freshness clock and never shadows an earlier success; a clock too
skewed to trust reports `unknown`.
_Avoid_: verifier, arming check, heartbeat
_Subsystems_: Backend Admission and Durable Arming
_Relates to_: Sweep Proof (reads), Lease Capability (produces a `Scheduled` one), Admission Decision (gates), Signing Key (verifies with)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced when admission moved from
  configuration to evidence.

**Canonical Admission Scope**:
The one scope string `file` admission compares a **Sweeper Arming** against, of the
form `p/<vault>/<principal>/agent-*`. A scope that parses but is not this shape
reaches no lease, so the arming constructor refuses it rather than recording a
schedule nothing reads.
_Avoid_: arming scope, sweep prefix, target scope
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/sweeper.rs, crates/ksp/src/admission.rs
_Relates to_: Sweeper Arming (is the scope of), Declared Cadence (is the schedule of), Capability State (explains the absence of a proven one)
_History_:
- 2026-11-07 (007-file-cleanup-capability): Term introduced. `agent-*` was
  written twice - in the scope parser and in `deployment_scope` - and the second
  is the one admission reads; naming the shape makes the pair one rule.

**Capability State**:
Which single cause explains a **Lease Capability**, chosen in the same
classification that produces the capability, together with the one operator
action derived from that cause. Distinct from the capability itself: several
causes produce `None` and each needs a different next step.
_Avoid_: status, diagnosis, next step, hint
_Subsystems_: Backend Admission and Durable Arming
_Files_: crates/ksp-backend/src/admission.rs, crates/ksp/src/output.rs
_Relates to_: Lease Capability (explains), Declared Cadence (may be the missing cause), Proven Cadence (may be the stale cause), Proof Gate (supplies the evidence causes)
_History_:
- 2026-11-07 (007-file-cleanup-capability): Term introduced. A next action
  rendered from a source other than the classifier is the same defect as a status
  marker with no path.

## Relationships

- A **Run Window** is what one **Sweep Proof** recorded, never a **Cleanup Lag**
- A **Capability State** explains exactly one **Lease Capability**, and several states explain the same `None`
- A **Sweeper Arming** is read only when its scope is the **Canonical Admission Scope**
- A **Blob Store** declares exactly one **Lease Capability**
- An **Admission Decision** follows from a **Lease Capability** and the **Admission Floor**
- A **Capability Refusal** is an **Admission Decision** with a `None` capability
- **Durable Arming** writes a **Deletion Intent** under an **Operation Identity**
- An **Arming Acknowledgement** permits token publication
- **Status Disclosure** reports the **Lease Capability**, the **Cleanup Lag** and the **Retention Disclosure**
- A **Lease Sweep** reads the **Durable Arming** records and is limited by a **Sweep Bound**
- A **Sweep Report** counts an **Already Absent** version apart from a removal
- A **Sweeper Declaration** supplies a **Declared Cadence**; a **Measured Unit State** is what the host reports beside it
- An **Arming Query** describes a **Sweeper Arming**; a **Sweep Proof** is what admits a lease
- A **Proof Gate** turns the newest **Sweep Proof** into a `Scheduled` **Lease Capability** or into **None**
- A **Sweep Proof** establishes a **Proven Cadence**; a **Declared Cadence** alone establishes nothing
- A **Declared Cadence** and a **Proven Cadence** are disclosed in separate fields, never averaged

## Flagged Ambiguities

- "arm" was used for both **Durable Arming** of a deletion intent before token
  publication and **Sweeper Arming** of a scheduled job — resolved: they are
  different acts on different objects, and neither implies the other. A token is
  armed durably so publication is safe; a sweeper is armed so deletion is scheduled.
- "proof" was used for both the fact that a sweep ran and the fact that a version
  is gone — resolved: a **Sweep Proof** proves a run and reports counts; a
  **Deletion Report** or an **Absence Observation** is what speaks about a version,
  and neither is erasure. A proof of a run is not a proof of an effect.
- "verifier" was used for both a query about configuration and the gate that admits
  a lease — resolved: the query is an **Arming Query** and decides nothing; the gate
  is the **Proof Gate** and reads evidence.
- "expiry" was used to mean both the backend's configured logical expiry and
  the lease's requested duration — resolved: "capability" is what the backend
  is configured to do; "requested duration" is what one lease asks for.
- "guarantee" was used to mean both the configured capability and a promise
  about what has already happened — resolved: capability is configuration;
  a **Deletion Report** attributes a claim; neither is a guarantee of erasure.
- "retention" was used to mean both a backend's configured copy lifetime and
  the confidentiality lifetime of a delivered value — resolved:
  **Retention Disclosure** is about copies in storage; the delivery lifetime
  is the token's expiry.
- "purge" was used to mean both the command and the concept — resolved: a
  **Lease Sweep** is the concept; `purge-expired` and `gc` are its two bounds
- "gone" was used to mean both "this host did not find it" and "no copy
  survives" — resolved: **Already Absent** is what the sweep observed; erasure
  is never claimed
- "scope" was used for the armed prefix, a credential's grant range and a store
  path — resolved: only the **Canonical Admission Scope** is what admission
  compares; a grant's scope is what a credential may act on; the store prefix is
  a path
