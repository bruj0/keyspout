---
context_name: "Keyspout Command-Line Interface"
version: "1"
subsystem: "crates/ksp"
created: "2026-10-21T16:32:00+00:00"
updated: "2026-10-30T18:05:00+01:00"
---

# Keyspout Command-Line Interface

The foreground entry point of the whole system. Every operation is one
invocation that starts, does its work and exits. There is no daemon, no
listener and no session. This context owns the command surface, the exit
codes, the output shapes and the rules about what may be printed.

## Language

**Agent Index**:
The public half of an agent's enrolment, published at
`p/<vault>/<owner>/agents/<agent>.cbor` so a principal that cannot read the owner's
home can still resolve the agent. It holds the principal, both public keys, both key
IDs and the fingerprint — no private half and no secret.
_Avoid_: agent registry, agent document, agent pin
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/agent_index.rs, crates/ksp/src/agent.rs
_Relates to_: Principal Registry (is the agent-side analogue of), Stored Enrolment (is published from), Publication (is what an edge names)
_History_:
- 2026-11-16 (014-policy-scoped-sharing): Term introduced. The home-local pin stays
  the reload anchor; the index answers "does this agent exist for this user", which
  the admin needs because it signs the edge in a different home (CF-011). Rotation
  rewrites both in the same step, because a stale index names a key the agent no
  longer has.

**Command Surface**:
The complete tree of subcommands the binary exposes. It is fixed by the
design specification, and extended only by an authorised feature specification —
never ad hoc, and never by a hidden command for user-facing work.
_Avoid_: CLI, commands, subcommands
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/main.rs, crates/ksp/src/commands/
_Relates to_: Exit Code (is shaped by), JSON Output (is produced by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-10-24 (002-file-os-split-sweeper): `ksp audit` joins the surface on
  FR-040…FR-043 and US7. It is **not** `ksp admin audit`, which reports the
  deletion acknowledgement journal: two commands, two stores, two answers. The
  design specification's §6 list predates the feature and does not carry it.
- 2026-10-24 (002-file-os-split-sweeper): `ksp audit verify` joins it on
  FR-047…FR-054 and US8. It reads the same log as `ksp audit` and answers a
  different question: the view projects what is there, verification checks who
  wrote it.
- 2026-11-17 (014-policy-scoped-sharing): `admin seal-vault`, `admin put --own`,
  `admin policy create`, `admin policy update`, `admin policy delete` and
  `secret share --policy` join the surface. The write side had no entry point
  before them: a grant could be read but not made, and the admin vault every
  publication seals its content key to had no verb at all. `admin put --own` is
  the transfer verb with one flag, and the flag decides which key seals the
  record — the admin's own vault, or the user's. `secret share --policy` is the
  export that reads no vault, so it takes none of `--name`, `--uses`, `--ttl` or
  `--passphrase-file`.

**Exit Code**:
The integer a run returns to its caller, carrying the outcome category.
`0` success, `2` policy denial, `6` missing key material, `7` capability or
admission refusal, `8` invalid or missing proof of possession, `12` an audit log
that did not verify, plus distinct codes for a lost fresh fetch and a refused
scheduled run.
_Avoid_: status, result code, return value
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/exit.rs
_Relates to_: Capability Refusal (is 7), Lost Fresh Fetch (has its own)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Policy Denial**:
The outcome in which a request was well-formed but not permitted by a policy
or a grant. It exits `2` and publishes no token.
_Avoid_: forbidden, unauthorized, access denied
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/exit.rs
_Relates to_: Exit Code (is 2), Admission Decision (may be)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Missing Key Material**:
The outcome in which a key the operation needs is absent — an unenrolled
agent's signing key, or a recipient key that cannot unwrap. It exits `6` and
delivers no secret.
_Avoid_: no key, key not found, not enrolled
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/exit.rs
_Relates to_: Exit Code (is 6)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**JSON Output**:
The machine-readable form of a command's result, carrying identifiers,
versions, actors and outcomes — never values, keys, raw tokens or successful
proof-of-possession material.
_Avoid_: machine output, structured output, api response
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/json.rs
_Relates to_: Audit Event (has the same content rule), Command Surface (is produced by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Audit Event**:
A record of one enrollment, rotation, mint, admission, arming, delivery,
consumption, deletion, report recovery, observation or failure, carrying
opaque record identifiers, a version, an actor and an outcome.
_Avoid_: log entry, audit log, trace
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/output.rs, crates/ksp/src/json.rs, crates/ksp-deletion/src/audit.rs
_Relates to_: JSON Output (has the same content rule), Log Projection (is projected by)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-10-25 (002-file-os-split-sweeper): Files moved to `output.rs` and the record
  projection in `ksp-deletion`.
  Prior files: crates/ksp/src/commands/, crates/ksp/src/json.rs.

**Log Projection**:
One decoded log record rendered for a human or, from the same value, as one JSON
object tagged `kind` — the two cannot disagree because there is one decoder.
_Avoid_: audit dump, log dump, second parser
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/audit_view.rs, crates/ksp/src/output.rs, crates/ksp-deletion/src/audit.rs
_Relates to_: Audit Event (projects), Unknown Record (represents without decoding)
_History_:
- 2026-10-25 (002-file-os-split-sweeper): Term introduced.

**Unknown Record**:
A log record whose operation kind this build does not know; it is rendered with
its field names and the shape of each value, and never with text or bytes.
_Avoid_: unknown entry, unrecognised record
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/output.rs, crates/ksp-deletion/src/audit.rs
_Relates to_: Log Projection (is rendered by), Audit Event (is one)
_History_:
- 2026-10-25 (002-file-os-split-sweeper): Term introduced.

**Child Delivery**:
The handing of a plaintext secret to the process a run was asked to execute.
It is the one deliberate exception to the rule that plaintext never reaches
argv, a log or the inherited environment.
_Avoid_: secret passing, injection, handoff
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/commands/run.rs
_Relates to_: Consume (is performed by), Environment Delivery (is a form of)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Environment Delivery**:
The form of Child Delivery that places a plaintext value in one named
variable of the child's environment. It is explicit and documented, never
implicit and never inherited by the parent.
_Avoid_: env var, secret env, injection
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/commands/run.rs
_Relates to_: Child Delivery (is a form of)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Session Agent**:
The optional long-lived local process of a later design phase. It is
**excluded** from the MVP: the agent path works with the vault never unsealed
on the agent host.
_Avoid_: daemon, agent service, session cache
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/commands/agent.rs
_Relates to_: Command Surface (excludes it)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced. "daemon" is avoided
  because the MVP has no resident process at all.

**Collector**:
The narrowly enrolled principal that runs scheduled cleanup and signs
reports. It holds no decryption authority and no session state, and it is
invoked in the foreground as a batch. Its identity is the **Admin** actor: a
principal UUID minted by `admin init`, never the user whose records it removes.
_Avoid_: janitor, sweeper, gc daemon
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/admin.rs, crates/ksp/src/sweep.rs
_Relates to_: Deletion Report (signs as the Admin actor), Actor (is a), Admin Principal (has the UUID of)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.
- 2026-10-24 (002-file-os-split-sweeper): Given its own principal UUID, so a
  sweep report names the admin rather than the user.

**Admin Principal**:
The UUID `admin init` issues to the deployment's admin actor. It is distinct from
the user principal's UUID even when one human holds both roles; a sweep report's
`actor` is this identity, and its `signer_key_id` names the admin key that signed.
_Avoid_: admin user, root, operator, superuser
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/deployment.rs, crates/ksp-types/src/metadata.rs
_Relates to_: Collector (is the identity of), Principal (is one), Actor (is the `admin` variant)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced when FR-018 needed an
  actor to name; the user is not the actor that sweeps.

**Redaction**:
The rule that a secret value, a key, a raw token or successful
proof-of-possession material never reaches stdout, stderr, an audit event or
a JSON output — and that a raw error stack or message never reaches a
response body.
_Avoid_: sanitisation, masking, scrubbing
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/json.rs, crates/ksp/src/exit.rs
_Relates to_: JSON Output (is applied to), Audit Event (is applied to)
_History_:
- 2026-10-21 (001-keyspout-mvp): Term introduced.

**Capability Refusal**:
The outcome in which the host cannot establish what a delivery requires — path
confinement or descriptor sanitation — and the child is therefore not started.
It exits `7` and prints the mechanism, the kernel ABI and the right or rule
path that refused, because the code's generic sentence does not say what to fix.
_Avoid_: capability error, sandbox failure, permission error
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/run_gate.rs, crates/ksp/src/process.rs, crates/ksp/src/deliver.rs
_Relates to_: Exit Code (is 7), Confinement Refusal (is reported by), Environment Delivery (prevents), Admission Decision (is distinct from)
_History_:
- 2026-10-21 (001-keyspout-mvp): Implied by exit `7`.
- 2026-10-24 (002-file-os-split-sweeper): Term defined; the refusal now carries the
  typed reason instead of the code alone.

**Protected Root**:
A path the layout table names, with the mode it is created with and the reason
it is not more open. Creation reads the table; measurement compares against it.
_Avoid_: directory, folder, config path
_Subsystems_: Keyspout Command-Line Interface, Host Confinement and Key Material Posture
_Files_: crates/ksp/src/layout.rs
_Relates to_: Layout Record (is recorded in), Permission Audit (is measured by), Capability Refusal (refuses through)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced. The table replaces
  per-call-site modes, which is how `store/` and `enrolments/` came to be `0775`.

**Principal Binding**:
The host identity one actor is bound to on one backend — a UNIX account on `file` —
recorded against the actor's UUID and never derived from its display name.
_Avoid_: mapping, account link, identity alias
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/deployment.rs, crates/ksp/src/admin.rs, crates/ksp/src/layout.rs, crates/ksp/src/storegroup/mod.rs
_Relates to_: Layout Record (is judged by its expected owners), Protected Root (owns), Exit Code (refuses with 2 when it names nothing), Store Group (joins the account to it)
_History_:
- 2026-10-25 (002-file-os-split-sweeper): Term introduced while wiring the
  two-account layout; FR-023 and FR-024 name the binding, WP13 completes it.
- 2026-11-06 (006-macos-parity-and-design-spec-truth): The binding is now
  completed by the store-group step on both platforms.

**Store Group**:
The host group that owns the store root, resolved from the root's own gid and
joined by the principal's account so the `0730` agent level can be given a group
the sweep shares without being able to read the copy.
_Avoid_: sweep group, store group name, ksp group
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/storegroup/mod.rs, crates/ksp/src/storegroup/tools.rs, crates/ksp/src/storegroup/linux.rs, crates/ksp/src/storegroup/darwin.rs
_Relates to_: Principal Binding (joins the account to it), Protected Root (the store root whose gid it is), Permission Audit (reads the group a level carries)
_History_:
- 2026-11-06 (006-macos-parity-and-design-spec-truth): Term introduced. The step
  was inline in `admin.rs` and named only Linux tools; it now resolves the group
  from the store root's gid with the host's own tools, and the gid is read from
  the directory rather than from a recorded name.

**Layout Record**:
`layout.cbor`: which UNIX uid was recorded as the owner of each protected root
when it was created. Written once per root; a later run never re-records an
existing row, because a silently updated owner is how a rebind becomes invisible.
_Avoid_: ownership file, permissions manifest
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/layout.rs, crates/ksp/src/config.rs
_Relates to_: Protected Root (records the owner of), Permission Audit (is read by), Principal Binding (is the host-side counterpart of)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced.

**Level Parent**:
The directory above a principal's level directories. `0711` by design: a
principal that can name a level traverses into it, and one that cannot name it
cannot enumerate the siblings it might guess.
_Avoid_: store root, levels tree, shared directory
_Subsystems_: Keyspout Command-Line Interface, Host Confinement and Key Material Posture
_Files_: crates/ksp/src/layout.rs
_Relates to_: Level Directory (parents), Owner Enumeration (is why it is 0711)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced.

**Level Directory**:
One principal's directory inside the store, keyed by its **Principal** UUID and
carrying a **Level** segment (`user`, `admin`, `agent-<uuid>`). The level is the
boundary, and its owner is the principal whose records live in it. A `user` or
`admin` level is `0700`. An `agent-<uuid>` level is `0730` with the store root's
group, so the admin's sweep can unlink a version it is authorised to remove while
it still cannot list the level or read a copy; records are `0600`.
_Avoid_: namespace, folder, tenant
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/layout.rs
_Relates to_: Level Parent (is parented by), Record Path (is the directory half of), Principal Split (is enforced by), Collector (deletes inside an agent level)
_History_:
- 2026-10-24 (002-file-os-split-sweeper): Term introduced.
- 2026-10-24 (002-file-os-split-sweeper): Agent levels widened to `0730` with the
  store's group (C2); records pinned to `0600` so the widen grants delete, not read.

**Capability Configuration**:
The validated contract saying which mechanisms a host may establish for path
confinement and for the memory barrier, and whether it refuses without them. It
is the **output** of reading `config.toml` and the **input** to the resolver, so
a host that cannot confine can still say why. Absent, it is `None` — the
unconfigured state — and not an empty document, because an empty document is one
the operator wrote.
_Avoid_: config, settings, host config
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/capability_config.rs, crates/ksp-types/src/capability_config.rs
_Relates to_: Stored Configuration (is produced from), Configuration Refusal (is
refused by), Mode and Owner Guard (is preceded by), Capability Refusal (supplies
the requirement it is judged against)
_History_:
- 2026-10-30 (004-os-capability-adapters): Term introduced. It is a separate type
  from the on-disk shape on purpose: the file format may change, and the contract
  the resolver reads must not.

**Stored Configuration**:
The on-disk shape of `config.toml` — one table per capability, each holding an
ordered adapter list and a requirement level, with the schema closed. Its adapter
lists are held as **written**, not as parsed names, so that a name outside the
closed set can be reported with the key and index it appeared under. Validation is
the step that turns the raw strings into the closed type.
_Avoid_: file schema, config struct, TOML model
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/capability_config.rs
_Relates to_: Capability Configuration (is validated into), Configuration Refusal
(names the key a bad value appeared under)
_History_:
- 2026-10-30 (004-os-capability-adapters): Term introduced. `deny_unknown_fields`
  is what makes "capability names and requirement levels only" structural rather
  than a convention, so there is no field a passphrase could be written into.

**Mode and Owner Guard**:
The check a file must pass before its content is parsed: it is owned by the
invoking principal, and no other principal can write it. The file is the downgrade
path — a principal who can rewrite it demotes a required capability to an optional
one and every command keeps working — so the guard runs **before** the read, and
it measures the open **descriptor** rather than the path, because the path can be
repointed between the check and the read.
_Avoid_: permission check, ownership validation, security check
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/capability_config.rs
_Relates to_: Capability Configuration (guards), Configuration Refusal (refuses
with `NotPrivate`), Protected Root (is the different question of what a directory
is created with)
_History_:
- 2026-10-30 (004-os-capability-adapters): Term introduced. Permission to read the
  file is not the hazard — permission to change what the host may establish is.

**Configuration Refusal**:
The outcome in which `config.toml` exists but cannot be trusted, and the run
therefore stops. Five kinds, each naming the file and the thing to fix: unreadable,
not private, malformed, an adapter this build does not contain, and an adapter that
belongs to the other capability. The last two are separate because their fixes are
separate — and because accepting `confinement.adapters = ["mlock"]` would make the
reader claim a host limitation the host does not have.
_Avoid_: config error, parse failure, invalid config
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/capability_config.rs
_Relates to_: Capability Configuration (refuses), Mode and Owner Guard (the
`NotPrivate` kind is the boundary itself), Exit Code (is `7` for `NotPrivate` and
`2` for the rest), Capability Refusal (is not one)
_History_:
- 2026-10-30 (004-os-capability-adapters): Term introduced. The parser's `Display`
  is deliberately not used: it renders the offending **source line**, so a
  passphrase pasted into `config.toml` by mistake would be printed back in a
  refusal on its way to a log.

**Host Probe**:
The measurement that writes a **Capability Configuration** for this host. It asks
the registry for each adapter and the adapter for its own availability, so it
holds no availability rule of its own — a copy of that rule is how a probe writes
a document the resolver then rejects on the same host. It reads only the host's
capability mechanisms: no vault, no enrolment, no key.
_Avoid_: capability check, host scan, detector
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/probe.rs
_Relates to_: Capability Configuration (writes), Adapter (asks, and holds no
answer of its own), Overwrite Policy (is governed by), Probe Outcome (is reported
as)
_History_:
- 2026-10-30 (004-os-capability-adapters): Term introduced. It validates its own
  document through the reader before writing, so it cannot write a file that
  `ksp status` would then refuse to read.

**Overwrite Policy**:
The one question the two probe verbs answer differently: may I replace a
configuration that is already there. `IfAbsent` leaves it byte-for-byte, and
`Replace` — reached only through `--force` — rewrites it. It asks whether
something is *placed* at the path, using the link's own metadata, because a
dangling symlink is something placed there and a following check would say the
host is unconfigured.
_Avoid_: force flag, clobber mode, overwrite setting
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/probe.rs, crates/ksp/src/app.rs
_Relates to_: Host Probe (governs), Capability Configuration (decides whether one
is replaced), Mode and Owner Guard (the written file must satisfy it)
_History_:
- 2026-10-30 (004-os-capability-adapters): Term introduced. `ksp init` and
  `ksp config init` are the same probe with the same default policy; only
  `ksp config init --force` selects `Replace`.

**Probe Outcome**:
What the probe decided, in the words a reader needs: per capability the level
written, the adapter this host will actually run, that adapter's guarantee, and
the host's own reason for every adapter it cannot provide. A level written
`optional` appears here with its reason, because "optional" alone reads like a
choice the operator made rather than a fact about the host.
_Avoid_: probe result, decision object
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/probe.rs
_Relates to_: Host Probe (is produced by), Capability Configuration (describes),
Guarantee Level (names what the selected adapter buys), Capability Refusal (is the
outcome's opposite: it is what a document says when the run must stop)
_History_:
- 2026-10-30 (004-os-capability-adapters): Term introduced. It is what FR-022's
  "what this configuration does not guarantee" is rendered from, so the
  disclosure is data rather than a second copy of the decision.
- 2026-10-30 (004-os-capability-adapters): The _Avoid_ list no longer forbids
  "report" or "summary". Those are two **other** types in the same module, not
  synonyms for this one: a **Write Result** says whether a file was written or
  left alone, and a **Probe Summary** is that result's serialisable shape. An
  _Avoid_ list that names the identifiers the code actually uses tells the next
  agent the code is wrong.

**Write Result**:
What the probe did about the file, either way: it wrote this text, or a
configuration was already there and the policy left it byte-for-byte. It is the
probe's outcome plus the one fact the outcome cannot carry — whether anything
reached the disk — so a caller can print what is on disk rather than render the
decision a second time.
_Avoid_: report, outcome, result
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/probe.rs
_Relates to_: Probe Outcome (carries it), Overwrite Policy (produces the
left-alone case), Probe Summary (is rendered from)
_History_:
- 2026-10-30 (004-os-capability-adapters): Term introduced, in the review, after
  the glossary was found to forbid the name the type already had.

**Probe Summary**:
The write result in the shape a caller prints or serialises: names as strings,
`written` or `existing`, and one row per capability. It exists so the JSON and
the text are two renderings of one value rather than two code paths that drift —
the defect that had the audit view drop a field the record carried.
_Avoid_: report, output, view
_Subsystems_: Keyspout Command-Line Interface
_Files_: crates/ksp/src/probe.rs, crates/ksp/src/output.rs
_Relates to_: Write Result (is rendered from), Probe Outcome (its rows come from
one), Guarantee Level (each row names one)
_History_:
- 2026-10-30 (004-os-capability-adapters): Term introduced.

## Relationships

- A **Log Projection** represents one **Audit Event**
- An **Unknown Record** is an **Audit Event** the projection cannot classify

- The **Command Surface** determines the **Exit Code** vocabulary
- A **Policy Denial** is an **Exit Code** of `2`; a **Missing Key Material** is an **Exit Code** of `6`
- A **Capability Refusal** is an **Exit Code** of `7`; an invalid proof of possession is `8`
- A **Lost Fresh Fetch** has an **Exit Code** distinct from all of the above
- **Child Delivery** takes the form of **Environment Delivery** when the value is named
- **Redaction** governs both **JSON Output** and **Audit Event**
- The **Command Surface** excludes the **Session Agent**
- A **Level Directory** sits under a **Level Parent**, and the pair is created by the layout table
- A **Collector** is the **Admin Principal**, and the sweep report's actor is that UUID
- A **Protected Root** has a **Layout Record**; a **Permission Audit** reads both
- A **Stored Configuration** is validated into a **Capability Configuration**, and
  a **Mode and Owner Guard** stands between them
- A **Configuration Refusal** is an **Exit Code** of `7` when the mode guard
  refused, and `2` otherwise
- A **Host Probe** writes a **Capability Configuration** under one **Overwrite
  Policy**, and reports a **Probe Outcome**
- A **Write Result** carries a **Probe Outcome** and is rendered as a **Probe
  Summary**


## Flagged Ambiguities

- "agent" was used to mean both an enrolled agent identity and the future
  local session process — resolved: an enrolled identity is an **Agent ID**;
  the excluded process is the **Session Agent**.
- "run" was used to mean both one invocation of the binary and the consume
  operation — resolved: an invocation is a **run** of the CLI; the operation
  that removes a version is a **Consume**.
- "secret" was used to mean both a stored value and the `secret` command
  group — resolved: a stored value is a *value*; the command group is spelled
  `ksp secret`.
