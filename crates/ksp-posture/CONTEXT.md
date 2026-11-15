---
context_name: "Host Confinement and Key Material Posture"
version: "1"
subsystem: "crates/ksp-posture"
created: "2026-10-21T16:28:00+00:00"
updated: "2026-10-30T13:00:00+00:00"
---

# Host Confinement and Key Material Posture

The subsystem that states, before a run, what the host can actually enforce.
It applies kernel path confinement to the opted-in process tree, keeps key
material out of ordinary memory, and reports both facts honestly — including
when a fact is weaker than it should be.

## Language

**Confinement**:
Kernel-enforced restriction of which paths a process tree may open, applied
by the Landlock `LANDLOCK_RULE_PATH_BENEATH` rules over `O_PATH` descriptors
before the tree is launched.
_Avoid_: sandbox, isolation, jail, permissions
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/confinement.rs
_Relates to_: Confinement Posture (is reported by), Descriptor Sanitation (supports), Path Confinement (is)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced. "sandbox" is avoided
  because the system never confines a same-UID outsider or a remote key.

**Path Confinement**:
The restriction of *which paths* a process may reach. It says nothing about
*which key* is speaking.
_Avoid_: access control, authorization, isolation
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/confinement.rs
_Relates to_: Confinement (is part of), Key Authentication (is distinct from)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Key Authentication**:
The establishment of *which key* is speaking, by signature verification
against a pinned trust anchor. It is a separate control from path
confinement and neither substitutes for the other.
_Avoid_: authorization, identity, trust
_Subsystems_: Host Confinement and Key Material Posture, Identity Sealed Delivery and Policy Verification
_Files_: crates/ksp-posture/src/posture.rs, crates/ksp-identity/src/policy.rs
_Relates to_: Path Confinement (is distinct from), Trust Anchor (is established by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Confinement Posture**:
The effective state of confinement for a run: enforced, weakened or
unavailable, together with the Landlock ABI status and compatibility level in
force.
_Avoid_: security level, posture, hardening level
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/posture.rs
_Relates to_: Confinement (is reported by), Optional Confinement (is a mode of),
 Required Confinement (is a mode of), Capability Adapter (is named by),
 Guarantee Level (is carried by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-10-30 (004-os-capability-adapters): The adapter's name and its guarantee
  were added, so a reader can tell a configured `landlock` from another
  adapter. The guarantee is the adapter's *own* level, never the level of a
  stronger adapter the operator preferred.

**Capability Disclosure**:
What one capability's status line says: the platform, the configured order, the
adapter that ran, the guarantee it established, and what did not run with the
host's reason.
_Avoid_: status line, capability report, posture summary
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/posture.rs
_Relates to_: Capability Adapter (names), Guarantee Level (carries), Confinement Posture (is reported by), Barrier Posture (is reported by)
_History_:
- 2026-10-30 (004-os-capability-adapters): Term introduced. Named "disclosure"
  rather than "status" because the record's job is to disclose, and a reader
  who cannot tell an accepted absence from an unnoticed one has not been told
  anything.

**Required Confinement**:
A run configured so that missing confinement rights cause a refusal rather
than a warning.
_Avoid_: strict mode, mandatory sandbox
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/posture.rs
_Relates to_: Confinement Posture (is decided by), Optional Confinement (is the counterpart of), Confinement Refusal (refuses through)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Optional Confinement**:
A run configured so that missing confinement rights produce a warning and a
weakened posture in status, but not a refusal. A qualifying remote backend
is never rejected solely for missing local Landlock.
_Avoid_: best effort, lenient mode, degraded mode
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/posture.rs
_Relates to_: Confinement Posture (is decided by), Required Confinement (is the counterpart of)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Descriptor Sanitation**:
The closing of unrelated inherited descriptors so that raw access to a sibling
path fails under the kernel rather than being prevented by a client-side check.
_Avoid_: fd cleanup, close-on-exec, fdsan
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/descriptors.rs
_Relates to_: Confinement (supports), Sibling Path (is denied access to)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Sibling Path**:
A path belonging to another level, such as another agent's directory. A
confined process must be denied it by the kernel with `EACCES` before any
Keyspout code runs.
_Avoid_: neighbour, other level, foreign path
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/confinement.rs
_Relates to_: Descriptor Sanitation (is closed to), Confinement (denies)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Memory Barrier**:
The mechanism keeping key material out of ordinary memory: `memfd_secret`
where available, otherwise a sealed `memfd`, otherwise `mlock`. The fallbacks
are weaker and are reported as such.
_Avoid_: secure memory, encrypted memory, protected heap
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/barrier.rs
_Relates to_: Barrier Posture (is reported by), Lockability Check (is verified by), Mlock Barrier (is)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-10-30 (004-os-capability-adapters): `mlock` added as the portable
  barrier, and named separately because it is a real mechanism and a weaker one.

**Mlock Barrier**:
The portable memory barrier: `mlock(2)` on an anonymous mapping. The pages
stay resident and never reach swap, but they remain in the kernel's direct map
and are not excluded from a dump. It is a real mechanism with a **Guarantee
Level** of weakened, and it is never reported as `memfd_secret`.
_Avoid_: macOS barrier, portable secure memory, locked memory
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/barrier.rs, crates/ksp-posture/src/adapters/barrier.rs
_Relates to_: Memory Barrier (is a kind of), Lockability Check (is verified by), Guarantee Level (is weakened for)
_History_:
- 2026-10-30 (004-os-capability-adapters): Term introduced. Feature 003
  measured the mechanism on Darwin and found no equivalent of `memfd_secret`;
  the name avoids "the macOS barrier", which reads as the primary one.

**Barrier Posture**:
Which memory barrier is in force: `memfd_secret`, sealed `memfd`, `mlock`, or
unavailable — together with the observed `RLIMIT_MEMLOCK` value, the
**Capability Adapter** that produced it and the **Guarantee Level** it
established.
_Avoid_: key protection, memory state
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/posture.rs
_Relates to_: Memory Barrier (is reported by), Lockability Check (constrains),
 Mlock Barrier (is reported as), Capability Adapter (is named by),
 Guarantee Level (is carried by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-10-30 (004-os-capability-adapters): `mlock` added as a third kind.
- 2026-10-30 (004-os-capability-adapters): The adapter's name and its guarantee
  were added, so a reader can tell a configured `memfd_secret` from a
  fallback to `sealed_memfd`.

**Dump Posture**:
The two controls that decide whether this process can be dumped, answered
separately: the core-dump exclusion (`RLIMIT_CORE = 0`) and the attach refusal
(`PR_SET_DUMPABLE` on Linux, `PT_DENY_ATTACH` on macOS). Each is *applied* or
*unavailable* with the kernel's own reason; the process is undumpable only when
both applied.
_Avoid_: undumpable flag, dump protection, core dump setting
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/memlock.rs, crates/ksp-posture/src/sys.rs
_Relates to_: Barrier Posture (is reported beside), Lockability Check (is
distinct from), Memory Barrier (is not implied by)
_History_:
- 2026-11-06 (006-macos-parity-and-design-spec-truth): Term introduced. It
  replaces the single `undumpable` boolean, which answered one call and left a
  host unable to say which half was missing.

**Lockability Check**:
The verification that the region can actually be locked, by reading
`RLIMIT_MEMLOCK` and locking with `mlock`. On failure the process aborts
naming the observed limit and the remedy the running platform provides, and does
not fall back to unlocked memory.
_Avoid_: memlock check, mlock test
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/memlock.rs
_Relates to_: Memory Barrier (gates), Barrier Posture (is reported in)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-11-06 (006-macos-parity-and-design-spec-truth): The refusal names a
  remedy the running host has, not the systemd directive unconditionally.

**Owner Enumeration**:
The fact that a `0711` parent directory lets its owner enumerate entries while
non-owners cannot list them. Neither fact authenticates an agent.
_Avoid_: listing, enumeration, dir permissions
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/confinement.rs
_Relates to_: Sibling Path (is about), Key Authentication (is distinct from), Principal Split (is not)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Principal Split**:
The use of two distinct UNIX principals for administration and for the user, so
that each side's key material is unreadable by the other's processes. It bounds
admin against user; it does not bound two processes that share one UID.
_Avoid_: user separation, roles, sandbox, isolation
_Subsystems_: Host Confinement and Key Material Posture
_Relates to_: Path Confinement (is distinct from), Same-UID Boundary (does not cover), Key Authentication (is not)
_History_:
- 2026-10-23 (002-file-os-split-sweeper): Term introduced; the spec previously placed account separation only on remote `sftp`.

**Same-UID Boundary**:
The limit that no UNIX permission separates one process from another process of
the same user, so an agent running as the user is bounded by path confinement and
by its lease, not by file modes. A passphrase over a key file protects that file
at rest and is not this boundary.
_Avoid_: passphrase protection, user isolation, ownership check
_Subsystems_: Host Confinement and Key Material Posture
_Relates to_: Principal Split (is not covered by), Path Confinement (is bounded by), Confinement Posture (is disclosed in)
_History_:
- 2026-10-23 (002-file-os-split-sweeper): Term introduced to stop "protected by a passphrase" from being read as agent confinement.

**Principal Binding**:
One **Principal** UUID recorded against one host identity on one backend — a UNIX
user on `file`, an ACL user on `valkey`, an IAM principal on `s3`, a login account
on `sftp` — with the recording principal and time. The key is the UUID, never a
display name, so a rename cannot move authority and a shared name cannot merge two
principals. It says which principal may touch a path; it is not the principal's key.
_Avoid_: account, role, mapping, identity
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-backend/src/admission.rs
_Relates to_: Principal (binds one), Principal Split (is what makes it possible), Key Authentication (is distinct from), Same-UID Boundary (does not move)
_History_:
- 2026-10-23 (002-file-os-split-sweeper): Term introduced for the multi-principal story; two actors may never share one binding on a backend.

**Permission Audit**:
The measurement of each protected root against the mode and owner recorded for
it: path, expected mode, actual mode, expected owner, actual owner, verdict. It
reports; it never repairs, because tightening someone else's directory would
erase the drift the operator has to see.
_Avoid_: permission check, chmod check, hardening scan, audit log
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/permissions.rs
_Relates to_: Mode Drift (detects), Protected Root (measures), Narrowed Root (does not refuse)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced for misfit B; the admin
  ↔ user boundary is mode bits, so drift is the failure to look for.

**Mode Drift**:
A protected root whose mode grants more than the record says, or whose owner is
not the recorded one, or that is a symlink where a directory or file is required.
It is a measurement, not an accusation: `0775` is evidence of `0775`.
_Avoid_: misconfiguration, permission bug, breach
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/permissions.rs
_Relates to_: Permission Audit (is found by), Narrowed Root (is the counterpart of), Capability Refusal (refuses through)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced.

**Narrowed Root**:
A protected root that grants strictly less than the record says. It is a
functional problem for whoever must write it and never a weaker boundary, so it
is disclosed and does not refuse.
_Avoid_: over-hardened, stricter, drift
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/permissions.rs
_Relates to_: Mode Drift (is distinct from), Permission Audit (is reported by)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced; treating it as drift
  would refuse a delivery through a boundary that got tighter.

**Confinement Refusal**:
The typed reason a *required* confinement could not be established: the
mechanism, the kernel ABI it reported, and the rights the spec asked for that
the kernel does not implement — or the rule path that could not be opened. It
describes the host; it is not a decision, because the optional posture reports
the same facts and proceeds. A refusal raised by an adapter that applies no
mechanism names that adapter and carries no kernel fact: there was no kernel
to ask, so there is no ABI and no missing right.
_Avoid_: sandbox error, landlock failure, confinement exception, strict-mode warning
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/confinement.rs, crates/ksp-posture/src/sys.rs
_Relates to_: Required Confinement (refuses through), Optional Confinement (is not raised by), Confinement Posture (describes the same host)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced for misfit A. A refusal
  an operator cannot act on is one they route around, so the mechanism, ABI and
  right are part of the type.
- 2026-10-29 (004-os-capability-adapters): An adapter that applies no mechanism
  must not report a kernel fact. The refusal names the adapter and reports no
  ABI and no missing right.

**Capability Adapter**:
The value that establishes one **Host Capability**'s mechanism, behind one of two
traits. It answers three questions and no others: its name in the closed
**Adapter Registry**, whether this host provides the mechanism (**Adapter
Availability**), and what it establishes when asked (**Guarantee Level**). It
decides nothing: the **Resolver** picks, the caller judges the level against the
operator's **Requirement Level**.
_Avoid_: backend, driver, provider, plugin
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/adapters/mod.rs, crates/ksp-posture/src/adapters/confinement.rs, crates/ksp-posture/src/adapters/barrier.rs
_Relates to_: Adapter Registry (is named by), Adapter Availability (answers), Guarantee Level (reports), Resolver (is selected by), Portable Confinement (is a kind of)
_History_:
- 2026-10-31 (004-os-capability-adapters): Term introduced. Named "adapter"
  rather than "backend" because a backend is the storage layer and answers a
  different question; and not "provider" because a provider reads as the thing
  supplying the work, while an adapter establishes a mechanism and then gets out
  of the way.

**Adapter Registry**:
The closed, compile-time mapping from an **Adapter Name** to the
**Capability Adapter** this build contains. It answers whether a name is *in
this build*, which is a different fact from whether the host provides the
mechanism. The two registries
are disjoint: a name asked of the registry that does not own it yields nothing.
_Avoid_: plugin registry, lookup table, map of adapters
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/adapters/mod.rs
_Relates to_: Capability Adapter (finds), Adapter Name (is keyed by), Adapter Availability (is not), Portable Confinement (is in)
_History_:
- 2026-10-29 (004-os-capability-adapters): Term introduced.

**Portable Confinement**:
The **Capability Adapter** that establishes no path confinement at all. It
exists so a host with no kernel mechanism still has an answer for the
capability: the run
proceeds and the posture says the child is not confined. Its guarantee is none,
and it refuses to establish anything — it is not a weaker confinement.
_Avoid_: fallback confinement, soft confinement, best-effort confinement
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/adapters/confinement.rs
_Relates to_: Capability Adapter (is a kind of), Confinement (is not), Guarantee Level (is none for)
_History_:
- 2026-10-29 (004-os-capability-adapters): Term introduced. Named "portable
  confinement" rather than "confinement fallback", because a fallback reads as
  a weaker confinement and this establishes nothing at all.

**Resolver**:
The walk over a capability's configured preference list. It asks each named
**Capability Adapter** for its **Adapter Availability** and selects the first
one the host confirms, recording the rest as skipped with the host's reason.
It never reorders the list and never infers an adapter the configuration did
not name.
_Avoid_: selector, dispatcher, fallback picker
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/resolver.rs
_Relates to_: Adapter Registry (consults), Resolution (produces), Unavailable Capability (produces on failure)
_History_:
- 2026-10-30 (004-os-capability-adapters): Term introduced. Named "resolver"
  rather than "selector" because it resolves the operator's stated order and
  does not select by merit.

**Resolution**:
What the **Resolver** selected: the chosen adapter's name, its **Guarantee
Level**, and every adapter it skipped with the host's reason. The skipped list
is part of the result, not a log line, because the disclosure surface reads it
and has nowhere else to get the fact.
_Avoid_: result, selection, outcome
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/resolver.rs
_Relates to_: Resolver (produces), Selected Adapter (holds), Skipped Adapter (holds), Guarantee Level (carries)
_History_:
- 2026-10-30 (004-os-capability-adapters): Term introduced.

**Selected Adapter**:
The one **Capability Adapter** the **Resolver** chose from the operator's
ordered list: the first entry this host confirms. Exactly one per capability,
and named everywhere the capability is reported, because a surface that says a
mechanism was established without saying which one cannot be checked against the
configuration.
_Avoid_: chosen adapter, active adapter, winning adapter
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/resolver.rs, crates/ksp-posture/src/posture.rs
_Relates to_: Resolution (is held by), Resolver (is chosen by), Skipped Adapter (is distinguished from), Guarantee Level (is the level of)
_History_:
- 2026-10-31 (004-os-capability-adapters): Term introduced. It is a distinct
  term from Resolution because a resolution also carries what did *not* run,
  and "selected" would then describe the whole result rather than one of its
  two halves.

**Unavailable Capability**:
Why a capability could not be established: the capability, and each adapter the
**Resolver** could not use with the host's reason. It carries **no** requirement
level, because the resolver was never told it — the level belongs to the
caller, which read the configuration and knows it.
_Avoid_: resolution failure, capability error, missing adapter
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/resolver.rs
_Relates to_: Resolver (produces), Skipped Adapter (lists), Requirement Level (is not carried by)
_History_:
- 2026-10-30 (004-os-capability-adapters): Term introduced.
- 2026-10-30 (004-os-capability-adapters): The requirement level was removed.
  The resolver receives the adapter list and nothing else, so a refusal that
  stated a level would be making a claim about the operator's own
  configuration it cannot support — claiming "required" for a capability the
  operator marked optional, on the path FR-029 governs.

**Unenforced Capability**:
A **Host Capability** whose **Selected Adapter** established a guarantee level
of `none`. It is not the same fact as an unavailable capability: an adapter ran,
was asked for its mechanism, and had none to apply. The distinction is what lets
a reader tell an accepted absence from an unnoticed one, so it is reported on
the status surface and, for a delivery, written to the audit log as a
**Capability Acceptance**.
_Avoid_: unconfined feature, missing capability, disabled capability
_Subsystems_: Host Confinement and Key Material Posture
_Files_: crates/ksp-posture/src/posture.rs, crates/ksp/src/establish.rs
_Relates to_: Guarantee Level (is `none` for), Selected Adapter (names), Unavailable Capability (is distinct from), Capability Acceptance (is recorded as)
_History_:
- 2026-10-31 (004-os-capability-adapters): Term introduced for misfit N. An
  absence that is only printed is an absence nobody can review later, and an
  absence that is only recorded is one the operator launching a child never
  sees; the term exists so both surfaces name the same thing.

## Relationships

- **Confinement** produces a **Confinement Posture**
- **Required Confinement** and **Optional Confinement** decide what a weakened posture causes
- **Descriptor Sanitation** makes a **Sibling Path** unreachable under the kernel
- **Lockability Check** gates the **Memory Barrier**
- **Memory Barrier** produces a **Barrier Posture**
- **Path Confinement** and **Key Authentication** are separate controls, both required
- A **Confinement Refusal** names the mechanism, the ABI and the missing right; a **Confinement Posture** states what was enforced
- An **Adapter Registry** is closed at compile time: a name with no arm breaks the build
- The two **Adapter Registry** lookups are disjoint, and neither ever returns a default
- **Portable Confinement** establishes no **Confinement**, and its **Guarantee Level** is none
- A **Permission Audit** finds **Mode Drift** and distinguishes a **Narrowed Root**
- **Confinement** restricts paths; a **Permission Audit** measures modes — neither substitutes for the other
- An **Adapter Registry** answers whether an adapter is *in this build*; an **Adapter Availability** answers whether the *host* provides its mechanism. A Linux-only adapter stays in the registry on every target and reports itself unavailable where the kernel has no such mechanism
- A **Capability Adapter** whose guarantee is none establishes no mechanism, and its refusal names no kernel fact
- The **Mlock Barrier** is a real **Memory Barrier** with a weakened **Guarantee Level**, and it is never reported as `memfd_secret`
- A public signature that names a target-gated type makes the whole crate target-gated, so the crate owns its Landlock ABI and Access Right vocabulary rather than re-exporting the mechanism crate's
- A **Confinement Posture** and a **Barrier Posture** each name the **Capability
  Adapter** that produced them and the **Guarantee Level** it establishes; a
  **Capability Disclosure** gathers both into what the status line prints
- A **Capability Disclosure** renders a `none` **Guarantee Level** in the same
  terms as a `full` one: the difference is the level and not the presence of a
  row
- A **Resolver** walks the configured order and takes the first adapter the
  host confirms; it never reorders the list and never consults an adapter the
  configuration did not name
- A **Resolution** carries the skipped list, so a disclosure can always say what
  did not run and why
- The **Resolver** resolves and the **Requirement Level** judges; a caller that
  wants "may this run proceed?" needs both, and neither answers the other's
  question
- An **Unavailable Capability** states the capability and the host's reasons
  and **no requirement level**: the resolver was never told it, and a refusal
  that guessed would misstate the operator's own configuration
- A **Guarantee Level** of none refuses a required capability and lets an
  optional one proceed; the level travels with the **Resolution** so the
  disclosure can report that nothing was established
- One **Selected Adapter** per capability, and every surface that says a
  mechanism was established names it: a surface that omits the name cannot be
  checked against the configuration
- An **Unenforced Capability** had an adapter run and establish nothing; an
  **Unavailable Capability** had no adapter to run. The two have different
  fixes, so they never share a sentence

## Flagged Ambiguities

- "security" was used to mean both confinement and authentication — resolved:
  **Path Confinement** restricts paths, **Key Authentication** establishes the
  speaking key. A system with only one of them is not secured.
- "sandbox" was used to mean the whole hardening story — resolved: the
  subsystem reports **Confinement Posture** and **Barrier Posture**
  separately, because a run can be perfectly confined and still hold an
  unlocked key in ordinary memory.
- "locked" was used to mean both "the region is `mlock`ed" and "the policy is
  enforced" — resolved: only the memory region is locked; policy enforcement
  is the **Confinement Posture**.
