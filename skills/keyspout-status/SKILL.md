---
name: keyspout-status
description: Report what this host's Keyspout deployment can and cannot do, right now. Use when the operator asks "what is my status", "is Keyspout set up", "what can this host do", "is my cleanup running", "what is my posture", or asks for a health check before or after any other Keyspout action.
---

# Keyspout status

Answer one question: **what is true on this host right now**, and what can this
host not observe. Every line comes from a `ksp` invocation, never from memory of
a previous run and never from inference.

This skill changes nothing. It reads, and it reports.

## The one thing to get right

**`ksp status` exits `0` on a host that has nothing set up.** It is a disclosure,
not a health check. An agent that branches on the exit code concludes "healthy"
on an empty directory.

So read the JSON, not the code:

```bash
ksp status --json
```

Decide from `backend.capability` and `binding.state`, which are the two fields
that say whether a deployment exists and whether a lease could be admitted. An
empty host reports `"capability": "None"` and `"binding": {"state": "none"}`.

## Step 1 — read the state

```bash
ksp status --json
```

One object. The fields that answer the operator's question:

| Field | What it says |
|---|---|
| `platform` | `macos` or `linux`. Decides which guarantees are even possible. |
| `backend.capability` | `None` until a sweep has been proven. `Scheduled` once one has. |
| `backend.mechanism` | Why the capability is what it is, in the host's own words. |
| `backend.evidence` | The declared cadence and the proven cadence, or why neither exists. |
| `backend.admission_minimum_secs` | The shortest lease this host admits. `null` when it admits none. |
| `backend.cleanup_lag` | `Unknown` unless the host can bound it. It usually cannot. |
| `backend.retention` | The backend's retention window, or an `Unknown` carrying the reason. |
| `backend.next_action` | The one action that would move the state forward, or `null`. |
| `arming` | The recorded schedule, or `None` with the reason none is recorded. |
| `proof` | The newest successful and failed sweep proofs, their age, and any malformed count. |
| `binding.state` | `none`, `verified` or `unverified`. `none` means single-account. |
| `permissions` | One entry per protected root: `verdict`, `actual_mode`, `expected_mode`. |
| `posture` | `confinement`, `barrier`, `undumpable`, each naming the adapter that ran. |
| `capabilities` | One line per capability: what was configured, what ran, what did not and why. |
| `audit` | `records`, `segments`, `chains`, `unreadable`, `unattributed`, `broken`. |
| `freshness` | Whether rollback detection is available. Usually it is not. |

## Step 2 — verify the log, without a credential

```bash
ksp audit verify --json
```

This needs no password, which is why it belongs in a status report. Read
`valid`, `invalid`, `mismatch`, `revoked`, `unpinned`, `unreadable` and
`broken`. `broken` is `null` when the chain is unbroken.

`completeness` is a sentence, not a verdict, and it says the same thing every
time: no head digest arrived from outside the log, so a deleted tail verifies
exactly like a whole one. **Report that sentence. Do not paraphrase it into
"the log is complete".**

## Step 3 — count what exists, without a password

```bash
ksp admin list --json
ksp token list --json
```

`admin list` returns `{"kind":"records","records":[...]}` naming every level.
`token list` returns `{"kind":"tokens","rows":[...],"scope":"..."}` and its
`scope` field states that a token minted elsewhere is unknown here — quote it.

Neither needs the vault password. Both answer "what is on this host" without
opening anything.

## Step 4 — the tenant's own records, only if asked

`ksp audit --json` reads the log scoped to the caller, and it needs the vault
password:

```bash
ksp audit --json --passphrase-file <file>
```

Ask the operator for the path rather than inventing one. Two rules that will
otherwise produce a wrong answer:

- **The output is JSONL, not one object.** The first line is
  `{"kind":"log",...}`; every later line is `{"kind":"audit-record",...}`. A
  consumer that parses the whole output as one document fails with
  `Extra data`.
- **Never report a count from the header alone.** `records` counts what this
  invocation emitted; `total` counts what the scope holds. If they differ, say
  so and name `--limit`.

If the operator has no password to hand, skip this step and say the tenant view
was not read. An unread log and an empty log are different answers.

## Step 5 — report

### What I did

One line per command run, with its outcome. Nothing was changed, so say that
plainly:

- `ksp status --json` — read the host state
- `ksp audit verify --json` — checked the chain; `broken` is `null`
- `ksp admin list --json` — counted `N` records
- `ksp token list --json` — counted `N` tokens minted here
- `ksp audit --json` — **skipped**: no vault password supplied

### What is true now

Render the measured state, one row per fact, each citing the field it came from.
Do not summarise a `null` into "unknown" without the host's own reason beside
it — the reason is the actionable part.

```
Platform:            macos
Backend capability:  None — no sweep proof has been written; a declaration is not evidence
Admits a lease:      no — this backend admits no lease
Next action:         record a schedule with 'ksp backend arm-sweep', then let the job run once
Binding:             none — the vault belongs to whoever created it
Confinement:         unavailable (landlock not implemented by this kernel)
Memory barrier:      mlock (weakened)
Protected roots:     1 of 15 drifted
Audit chain:         unbroken, 0 records
```

The `1 of 15 drifted` line is not decoration. If `permissions` reports any entry
with `"verdict": "drift"`, print the path, the actual mode and the expected mode,
and say what the drift means for that root.

### What this cannot do

Take these from the design specification's status markers, not from your own
reading of the output:

- **Deletion is best effort.** No sweep recalls a copy already saved, and no
  command reports a moment by which a copy is gone. `cleanup_lag` reads
  `Unknown` because the host cannot bound it.
- **On macOS, no path confinement is enforced.** The child runs unconfined, and
  the barrier is `mlock`, reported `weakened` — never `memfd_secret`.
- **A verified chain is not a complete one.** A deleted tail verifies like a
  whole one until a head digest arrives from outside the log.
- **`token list` knows only this host.** A token minted elsewhere is invisible
  here, and the command says so in its own `scope` field.

## Refusals

If a command fails, report the exit code and the message verbatim and stop.
Do not retry and do not work around it. `7` means this host cannot hold that
lease, not that the command was wrong; `6` means key material is missing or the
password was wrong; `13` means the invocation was malformed and the message
names the accepted form.

An empty result and a refused result are different answers. Never report "no
records" when the read was refused.
