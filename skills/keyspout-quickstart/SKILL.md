---
name: keyspout-quickstart
description: Set up Keyspout on this host for one operator with sane defaults, end to end. Use when the operator says "set up Keyspout", "install Keyspout", "get Keyspout working", "initialise the deployment", or asks to be walked through first-time setup. Stops at the first refusal and reports it rather than continuing.
---

# Keyspout quickstart

Set up one operator's deployment on one host, in the order the design requires,
and end with a report of what is true now.

**Read `keyspout-status` first if it is installed.** It tells you which steps are
already done, and this skill assumes a host that has none of them.

## What you are building

One admin, one user, one agent, one secret, and a proven cleanup schedule. Every
step below is a `ksp` command; none of them is a script.

```
ksp init            probe the host, write its capability configuration
ksp admin init      the admin signing key and the vault's identity
ksp admin user add  the user's sealed vault, bound to her UNIX account
ksp backend arm-sweep   record a cleanup schedule
ksp secret gc           run it once, which writes the proof
ksp agent enroll    an agent's own keypairs
ksp secret set      one secret, value on stdin
ksp admin policy    grant the agent
ksp secret share    a leased copy, sealed to the agent
ksp run             deliver it to a child
```

## Before you start

Ask the operator for three things and wait for the answers. Do not invent any of
them.

1. **The vault name.** A short identifier, `vault-1` by default.
2. **The vault password.** It is not stored and cannot be reset. It must arrive
   on stdin or from a file, never in argv. Ask where the file is, or have the
   operator type it when a step prompts.
3. **Whether this is a single-account host or a two-account host.** A
   single-account host runs every step as the operator. A two-account host runs
   `admin init` and `admin user add` as the admin account and everything else as
   the user. `ksp admin user add` needs root on the two-account host because it
   hands the vault to another account.

Confirm `ksp` is on `PATH` before anything else:

```bash
ksp version
```

If that fails, stop. Tell the operator to install it and do not try to install it
yourself — the install method differs per platform and the operator knows which
one they want.

## Step 1 — probe the host

```bash
ksp init --json
```

Writes `config.toml` naming, for each capability, an ordered adapter preference
and whether it is required. Read `capabilities[]` from the output: each entry has
`capability`, `selected`, `guarantee` and `unavailable[]`.

**Report `guarantee` for each capability now, not at the end.** On macOS the path
confinement guarantee is `none` and the memory barrier is `weakened`, and an
operator who learns that after setup has been misled about what was built.

Running it twice is safe: a second run reports that a configuration already
exists and changes nothing.

## Step 2 — initialise the deployment

```bash
ksp admin init --vault <vault> --user <name> --json
```

Two UUIDs come back and they are different things: `principal` is the **admin**,
`user` is the **user principal**. Capture the user UUID — step 4 needs it.

```
USER_ID=<the user field from the output>
```

`--user` is a display name only. It is stored and never printed again; the
identity is the UUID.

## Step 3 — enrol the user

The password arrives on stdin. This step needs root on a two-account host.

```bash
ksp admin user add --unix-user <account> \
  --signing-key-id <name>-ed25519-1 \
  --recipient-key-id <name>-x25519-1 \
  < <password-file>
```

The two key-id flags are labels that appear in the policy, in `token inspect` and
in the audit chain head. They are **not** derived from `--user`; the defaults are
`alice-ed25519-1` and `alice-x25519-1`, so pass them explicitly.

A second `admin user add` on the same host is refused by design: it would replace
the sealed vault and lock the principal out of every record already sealed to
her. Changing the password is `ksp vault rekey`, and it is a different command.

Verify the binding:

```bash
ksp status | grep -E '^(binding|permissions):'
```

`binding:` names the account that owns the vault. On a single-account host it
reads `none — the vault belongs to whoever created it`, and that is correct for
that shape, not an error.

## Step 4 — arm the cleanup schedule and prove it

**A lease is refused until a sweep has been proven.** This is the step that gets
skipped, and skipping it means `secret share` and `token mint` refuse with exit
`7` later.

Record the schedule:

```bash
ksp backend arm-sweep --interval 1h \
  --scope "p/<vault>/$USER_ID/agent-*" \
  --credential ksp-sweep \
  --grant "delete:p/<vault>/$USER_ID/agent-*" \
  --identifier ksp-sweep.service \
  --kind systemd
```

`--kind systemd` is correct on both platforms: the `file` backend's form of a
periodic job is a systemd unit, so the record looks the same everywhere. Nothing
is installed unless you pass `--install`, and on macOS `--install` writes a
`launchd` property list under the operator's own home and loads it.

Then run the sweep once. **This is what writes the proof:**

```bash
ksp secret gc
```

Confirm the capability moved:

```bash
ksp status --json
```

`backend.capability` must now read `Scheduled`, and
`backend.admission_minimum_secs` must be non-null. If it still reads `None`, the
proof did not land — read `backend.mechanism` and `backend.next_action` and
report them rather than proceeding.

`admission_minimum_secs` is `2 ×` the proven interval. That is admission policy,
not a promise that a copy dies at that moment.

## Step 5 — enrol an agent

```bash
ksp agent enroll --agent <name>-laptop --json
```

Read `identity` (it is `agent:<uuid>`), both key IDs, both public keys and
`fingerprint`. The UUID is the identity; the display name is metadata.

**Give the operator the fingerprint and tell them to confirm it out of band.**
It is the only thing that binds the agent's identity to both public keys, and
nothing later re-checks it for them.

## Step 6 — store a secret

The value arrives on stdin. The password comes from a file, because stdin carries
the value.

```bash
ksp secret set <record-id> --name <name> --passphrase-file <file> < <value-file>
```

Then confirm it reads back, redacted:

```bash
ksp secret get <record-id> --passphrase-file <file>
```

Without `--reveal` the value prints as dots. That is the default because stdout
is a file a shell redirects and a terminal scrolls back. Use `--reveal` only when
the operator asks to see the value.

## Step 7 — grant the agent, then share

Grant first. A grant is a policy statement; it delivers nothing.

```bash
ksp admin policy --agent <agent-uuid> --secret <record-id>
```

**`admin policy` replaces the whole grant set.** A call naming one agent revokes
every other grant. Before and after this step, read what the host holds:

```bash
ksp admin policy --show
```

If grants already exist, re-sign with **all** of them named, not just the new one.
This is the single most destructive mistake available in this skill, and the
read-back is the only way to avoid it.

Now share:

```bash
ksp secret share <record-id> --agent <agent-uuid> --name <name> \
  --out <token-file> --ttl 7200 --passphrase-file <file>
```

`7200` is admitted because step 4 proved a `3600s` cadence. A `--ttl` beyond
`admission_minimum_secs` is refused.

Inspect the token — no key, no value, only scope and expiry:

```bash
ksp token inspect --token <token-file>
```

## Step 8 — deliver it

```bash
ksp run --token <token-file> --env <VAR_NAME> -- <child command>
```

The value reaches the child through its environment, never argv. On macOS the
first line on stderr is the confinement disclosure: no path confinement was
enforced and the child ran unconfined. **Report that line.** It is the guarantee
the host could not give, not a warning to suppress.

`--consume` adds the deletion: retrieve, decrypt, hand to the child, delete the
exact version, report. A copy taken before the consume still opens — nothing
recalls a copy already saved.

## Step 9 — verify the log

```bash
ksp audit verify --json
```

No password needed. Read `valid`, `invalid`, `mismatch` and `broken`. `broken`
is `null` when the chain is unbroken.

`completeness` is a sentence and it says the same thing every time: no head
digest arrived from outside the log, so a deleted tail verifies like a whole one.
Quote it; do not turn it into "the log is complete".

## Report

### What I did

One line per step, naming the command and its outcome. A skipped step says why:

- `ksp init --json` — wrote the capability configuration
- `ksp admin init` — admin key `…`, user principal `…`
- `ksp admin user add` — vault sealed, bound to `<account>` / not bound
- `ksp backend arm-sweep` — recorded a `3600s` schedule for `p/<vault>/…/agent-*`
- `ksp secret gc` — ran once; capability moved to `Scheduled`
- `ksp agent enroll` — agent `…`, fingerprint `…`
- `ksp secret set` — record `…`, version 1
- `ksp admin policy --show` — read the grants before re-signing
- `ksp admin policy` — granted `…`
- `ksp secret share` — agent-level copy, `7200s` lease
- `ksp run` — child received the value / **skipped**: <reason>

### What is true now

From `ksp status --json`, one row per fact, each citing the field:

```
Platform:            macos
Backend capability:  Scheduled { interval: 3600s }
Admits a lease:      yes, from 7200s
Binding:             <account> (uid N)  |  none — single-account host
Confinement:         unavailable (landlock not implemented by this kernel)
Memory barrier:      mlock (weakened)
Protected roots:     N of M drifted  (list each drift with its path and modes)
Audit chain:         unbroken, N records
Agents enrolled:     N
```

Then the one thing the operator must do that no command can do for them: **write
the vault password down and store the recovery phrase somewhere safe.** The
recovery phrase restores the sealed file; it does not restore the password.

### What this cannot do

- **Deletion is best effort.** No sweep recalls a copy already saved, and no
  command reports a moment by which a copy is gone.
- **On macOS, no path confinement is enforced.** The child runs unconfined and
  the barrier is `mlock`, reported `weakened` — never `memfd_secret`.
- **A verified chain is not a complete one.** A deleted tail verifies like a
  whole one until a head digest arrives from outside the log.
- **`admin policy` replaces the whole grant set.** Re-sign with every grant named
  or the others are revoked.
- **`token list` knows only this host.** A token minted elsewhere is invisible.

## Refusals

Stop at the first refusal and report the exit code and the message verbatim.
Do not retry, do not work around it, and do not continue to a state you cannot
describe.

| Code | What it means here |
|---|---|
| `2` | The policy refused it, or the operation was denied |
| `6` | Key material is missing or unreadable — also a wrong password |
| `7` | This host cannot hold that lease. Run step 4; do not raise the TTL |
| `13` | The invocation was malformed; the message names the accepted form |

`7` after step 4 usually means the sweep scope was narrower than the lease needs.
Report `backend.mechanism` and `backend.next_action` rather than widening the
scope yourself.
