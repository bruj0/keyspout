---
name: keyspout-agents
description: Enrol a Keyspout agent, grant it a secret, share a leased copy, deliver it to a process, and rotate its keys. Use when the operator says "enrol an agent", "give the agent access", "share a secret with the agent", "run a command with the secret", "rotate the agent keys", or asks why a share or a run was refused.
---

# Keyspout agents

An agent is a principal with two independent keypairs of its own — it is not a
copy of the user's. This skill enrols one, grants it a secret, shares a leased
copy, delivers it, and rotates the keys.

## The one thing to get right

**`admin policy` merges by default.** A call naming one agent **adds** that grant
and keeps every other one — measured, and the report names what was added. That
is the opposite of what this skill said until 2026-11-27, when the behaviour was
changed to match FR-016: a second policy for the same secret version *adds an
entry and never replaces the artifact*, so one grant can no longer break
another's.

Read what is there before writing:

```bash
ksp admin policy --show
```

**`--replace` is the only whole-set form.** It writes the named grants and
withdraws every other, and it is the one destructive call in this skill:

```bash
ksp admin policy --replace --agent <a> --secret <r1> --agent <b> --secret <r2>
```

Omitting a grant from a `--replace` revokes it, silently — that agent's next
share starts being refused. For dropping **one** grant and recording the
decision, use `ksp admin revoke` instead; it re-signs without that grant and
keeps a record of why, which `--replace` does not.

## Before you start

The host must have a proven sweep, or `secret share` and `token mint` refuse with
exit `7`. Check:

```bash
ksp status --json
```

`backend.capability` must read `Scheduled` and `backend.admission_minimum_secs`
must be non-null. If it reads `None`, run `keyspout-quickstart` step 4 first.

## Enrol an agent

```bash
ksp agent enroll --agent <name> --json
```

```json
{"kind":"identity","identity":"agent:7975116e-…","signing_key_id":"7975116e-…-ed25519-1","signing_key":"e0db84…","recipient_key_id":"7975116e-…-x25519-1","recipient_key":"e0db84…","fingerprint":"e5f6c4…"}
```

Three things to do with that output:

1. **Capture `identity` and strip the `agent:` prefix.** That UUID is the
   identity; every later command takes it. The display name you enrolled under is
   metadata and is never accepted in its place.
2. **Give the operator the `fingerprint` and tell them to confirm it out of
   band.** It is the only thing binding the agent's identity to both public keys,
   and nothing later re-checks it for them.
3. **Do not record the private halves anywhere.** They are written to a protected
   file under the agent root and never printed.

A second `enroll` under the same display name issues a **new** principal. To
change an existing agent's keys, use `rotate`, not `enroll`.

## Grant, then share

A grant is a policy statement. It delivers nothing.

```bash
ksp admin policy --show
```

Read the current grants first. Then add the new one. **It merges** — every grant
this invocation does not name is kept:

```bash
ksp admin policy --agent <agent-uuid> --secret <record-id>
```

With more than one new grant, pass the flags once per grant in the same
invocation. Then confirm:

```bash
ksp admin policy --show
```

`issuer: verified against the pinned anchor` must be present, and every agent and
secret you meant to keep must be listed. If one is missing, you revoked it — say
so rather than proceeding.

Now share a leased copy:

```bash
ksp secret share <record-id> --agent <agent-uuid> --name <name> \
  --out <token-file> --ttl <seconds> --passphrase-file <file>
```

`--ttl` must be at least `backend.admission_minimum_secs`, which is `2 ×` the
proven sweep interval. A shorter lease is refused, and the refusal names both
numbers:

```
ksp: the mint was refused: a 3600s lease is below the 7200s minimum: the backend sweeps every 3600s and must sweep after the deadline
```

**Do not raise the TTL to get past a refusal of a different kind.** If the refusal
is about the sweep scope rather than the floor, raising the TTL changes nothing
and the real problem stays.

`--uses N` bounds how many deliveries the copy permits. A bound is spent by a
plain run too, not only by a consuming one.

## Inspect the token

```bash
ksp token inspect --token <token-file> --json
```

Scope, issuer, expiry and key IDs. Never a key and never a value. Confirm the
`expires_at` is what the operator expected before delivering anything.

## Deliver it

```bash
ksp run --token <token-file> --env <VAR_NAME> -- <child command>
```

The value reaches the child through its environment, never argv. `--env-all`
delivers every secret the delivery names.

**On macOS the first line on stderr is the confinement disclosure.** No path
confinement was enforced and the child ran unconfined. Report that line; it is
the guarantee the host could not give.

`--consume` adds the deletion: retrieve, decrypt, hand to the child, delete the
exact version, report. A copy taken before the consume still opens, and nothing
recalls it.

## Rotate the keys

```bash
ksp agent rotate --agent <agent-uuid> \
  --signing-key-id <name>-ed25519-2 \
  --recipient-key-id <name>-x25519-2
```

The previous bundle is retained beside the new one, so an old artifact still
opens. **Rotation changes future minting and new trust state; it does not revoke
anything already issued.** An old token still works until it expires or is
revoked, and an old copy of the private key still opens what it opened before.
If the operator's intent is to stop an old token, that is `token revoke`, and it
is a different command.

## Report

### What I did

- `ksp agent enroll` — agent `…`, fingerprint `…`
- `ksp admin policy --show` — read N existing grants before re-signing
- `ksp admin policy` — granted `<record>` to `<agent>`; N grants now held
- `ksp secret share` — agent-level copy, `<ttl>s` lease
- `ksp token inspect` — expires at `<time>`
- `ksp run` — child received the value / **skipped**: `<reason>`
- `ksp agent rotate` — new key IDs `…`; old bundle retained

### What is true now

```
Agent:        <uuid> (fingerprint <…>)
Granted:      <record> → <agent>
Lease:        <ttl>s, expires <time>
Tokens:       N minted on this host
Grants held:  N agents, M secrets
```

Then the one thing no command can do: **the operator must confirm the fingerprint
out of band.** Say so explicitly.

### What this cannot do

- **`--replace` revokes what it does not name.** The plain form merges, so the
  destructive case is now opt-in. Use `admin revoke` to drop one grant and keep
  the record of why.
- **Rotation does not revoke old offline pairs.** It changes future minting and
  new trust state. Revoking an issued token is `token revoke`; revoking the
  upstream credential is a separate action.
- **Consume is not exactly once.** Retrieve, decrypt, hand to the child, delete,
  report. Concurrent reads and copies taken earlier survive.
- **Deletion is best effort.** No sweep recalls a copy already saved.
- **`token list` knows only this host.** A token minted elsewhere is invisible.
- **On macOS, no path confinement is enforced.** The child runs unconfined.

## Refusals

Report the exit code and the message verbatim and stop. The table is the
contract from spec 010 — a machine branches on these, so do not paraphrase one.

| Code | What it means here |
|---|---|
| `2` | The policy refused it — the secret is not shareable, or the grant is gone |
| `6` | Key material is missing or unreadable — the agent key file, or the password |
| `7` | The lease is below the admission floor, or no sweep is proven |
| `8` | Proof of possession was invalid or missing |
| `9` | The delete failed; the record may still be present and a retry may help |
| `10` | The child ran after the record was removed; retrying cannot help |
| `11` | A compliant run was refused because the backend requires consumption |
| `12` | The audit chain did not verify against the pinned material |
| `13` | The invocation was malformed — a flag, a value or a missing argument. The message names the accepted form |

`9` and `10` are separate on purpose: one says try again, the other says ask for
a new delivery.
