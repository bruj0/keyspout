---
name: keyspout-backends
description: Choose and test a Keyspout storage backend, and arm and prove a cleanup schedule. Use when the operator says "use Valkey", "switch backends", "why is my lease refused", "arm the sweeper", "set up cleanup", "test a lease length", or asks what this backend can and cannot promise about deletion.
---

# Keyspout backends

Two jobs: pick the backend this host stores records in, and make the cleanup
schedule real enough that the host admits a lease.

## The one thing to get right

**A recorded schedule is configuration. Only a signed proof of a run admits a
lease.** `arm-sweep` writes the record and the capability stays `None`. The first
`secret gc` after it writes the proof, and only then does the capability move to
`Scheduled`.

An operator who arms a schedule and stops has a host that still refuses every
share, and the refusal reads like a bug.

## What is selectable

```bash
ksp backend list --json
```

```json
{"kind":"backend","backend":"file","capability":"None","detail":"selectable: file, valkey (selected: file)",…}
```

`detail` names what this build can open. `file` and `valkey` are selectable; the
`s3` store exists in the code but the CLI cannot select it, and `sftp` has no
store type at all. Do not offer either as an option.

`file` is the default and needs nothing. `valkey` needs a running server with
acknowledged durability and its configuration gates satisfied; a Valkey that
cannot acknowledge durability is not admitted, and the refusal says which gate
failed.

## Test a lease before minting one

```bash
ksp backend test --ttl <seconds> --json
```

```json
{"kind":"backend","backend":"file","capability":"Scheduled { interval: 3600s }","admitted":true,"requested_ttl_secs":7200,…}
```

`admitted` is the answer; `detail` says why when it is `false`. Exit `7` with
`admitted: false` means this host cannot hold that lease — not that the command
was wrong.

## Arm the schedule

```bash
ksp backend arm-sweep --interval 1h \
  --scope "p/<vault>/<user-uuid>/agent-*" \
  --credential ksp-sweep \
  --grant "delete:p/<vault>/<user-uuid>/agent-*" \
  --identifier ksp-sweep.service \
  --kind systemd
```

```
arming: backend=file  kind=systemd  identifier=ksp-sweep.service  interval=3600s  scope=p/vault-1/…/agent-*  credential=ksp-sweep  rights=delete:p/vault-1/…/agent-*  principal=…  recorded_at=…  id=…
note: this records a schedule; it is configuration until a signed sweep proof confirms a run. The interval says how often the job is declared to run, never how long a lease lives.
note: nothing was installed. ksp wrote no unit, no property list, no crontab entry and ran no privileged helper.
```

Three things about that output:

- **`<user-uuid>` is the user principal from `admin init`, not the display name.**
  A scope built from the name is refused with exit `2`, and the message says the
  scope is outside the deployment.
- **`--kind systemd` is correct on both platforms.** The `file` backend's form of
  a periodic job is a systemd unit, so the record looks the same everywhere.
  Nothing is installed unless you pass `--install`, and on macOS `--install`
  writes a `launchd` property list under the operator's own home and loads it.
- **The grant must be no wider than delete and list on that scope, plus write on
  the journal.** A broader credential is refused.

### A user's own sweep

```bash
ksp backend arm-sweep --interval 1h \
  --scope "p/<vault>/<user-uuid>/agent-*" \
  --credential ksp-user-sweep \
  --grant "delete:p/<vault>/<user-uuid>/agent-*" \
  --identifier com.keyspout.user-sweep \
  --user-arming --passphrase-file <file>
```

`--user-arming` signs the record with the user's own key, and the printed plist
runs `secret gc --user-arming`. A user's sweep bounds only her own copies, so it
needs no proof and no admin key. **This is the right choice when the operator
wants cleanup without the admin key present on the host.**

## Prove it

```bash
ksp secret gc
```

```
capability=Scheduled { interval: 3600s }  selected=0  removed=0  already_absent=0  not_yet_due=0  bound_reached=false  backlog=0
removed 0 of 0 expired lease(s) on this host; 0 were already absent; no armed record on this host has passed its deadline, which is not evidence that the store cleaned anything
```

`capability` moving from `None` to `Scheduled` is the change that matters. It
removed nothing because nothing was due, and the second line says so.

Confirm:

```bash
ksp status --json
```

```
backend.capability            Scheduled { interval: 3600s }
backend.proven_cadence_secs   3600
backend.admission_minimum_secs 7200
```

`admission_minimum_secs` is `2 ×` the proven interval. **That is admission
policy, not a promise that a copy dies at 7200 seconds.** Say it that way.

## The scope trap

A **deeper** scope than the lease needs is accepted and never admits. Arming
`p/<vault>/<uuid>/agent-*/db-password` exits `0`, the sweep runs, and the
capability stays `None` — the sweep that ran under it genuinely does not prove the
cadence admission needs. The `next_action` line then advises recording a schedule
that is already recorded.

If the operator reports this, do not re-run `arm-sweep`. Read
`backend.mechanism` and `backend.next_action`, then re-arm at the level the sweep
owns: `agent-*`, not a record beneath it. Narrowing a scope is a legitimate
operator right and this build does not forbid it; it simply does not admit a lease
under it.

## Report

### What I did

- `ksp backend list --json` — selectable `file`, `valkey`; selected `file`
- `ksp backend test --ttl <n>` — admitted / refused with the reason
- `ksp backend arm-sweep` — recorded a `<interval>` schedule for `<scope>`
- `ksp secret gc` — ran once; capability moved to `Scheduled`
- `ksp status --json` — read the proven cadence and the admission floor

### What is true now

```
Backend:            file
Capability:         Scheduled { interval: 3600s }
Declared cadence:   3600s
Proven cadence:     3600s (proof age Ns)
Admission floor:    7200s (2 × the proven interval)
Cleanup lag:        unknown
Retention:          unknown (the backend's classification states no window)
```

### What this cannot do

- **Deletion is best effort.** No sweep recalls a copy already saved, and no
  command reports a moment by which a copy is gone.
- **`2 ×` is admission policy.** It is not a maximum lag and not a deadline.
- **`cleanup_lag` reads `unknown`** because this host cannot bound it. Report the
  word, not "zero".
- **A recorded schedule is not evidence.** Only a signed proof of a run is.
- **`s3` and `sftp` are not selectable.** `s3` exists in the code and the CLI
  cannot open it; `sftp` has no store type.
- **A deeper scope does not admit a lease.** The sweep under it proves a cadence
  admission does not accept.

## Refusals

Report the exit code and the message verbatim and stop.

| Code | What it means here |
|---|---|
| `2` | The scope is outside this deployment, or the credential is wider than allowed |
| `7` | The lease is below the floor, or no sweep is proven |
| `13` | The invocation was malformed; the message names the accepted form |

A `7` on `arm-sweep` is about the record, not the lease. A `7` on `share` or
`mint` is about the lease. Read which command returned it before deciding what to
change.
