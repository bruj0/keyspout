---
name: keyspout-secrets
description: Store, read, list and remove secrets in a Keyspout deployment. Use when the operator says "store a secret", "save this credential", "read a secret", "show me the value", "list my secrets", "remove a secret", or asks how to get a value into a process without putting it in argv.
---

# Keyspout secrets

The four operations on a stored record: set, get, list, remove. Each is one
`ksp` command, and the value never appears in argv.

## The one thing to get right

**The value goes in on stdin, and it comes out only when `--reveal` asked for
it.** `ksp secret set` reads the value from stdin because argv is visible in `ps`
and in the shell history. `ksp secret get` prints dots by default because stdout
is a file a shell redirects and a terminal scrolls back.

The password is separate and arrives from `--passphrase-file`. It cannot come on
stdin at the same time as the value, because stdin carries the value.

## Before you start

You need the vault password. Ask the operator where the file is; do not invent a
path and do not ask them to type it into a command you compose.

```bash
ksp vault status
```

`sealed, version N` is the normal answer. There is no unlocked session — every
read opens the vault again, which is why every read needs the password.

## Store a secret

The record id is opaque and the operator chooses it. The name is encrypted with
the value and is what a human reads later.

```bash
printf '%s' "$VALUE" | ksp secret set <record-id> --name <name> --passphrase-file <file>
```

Never put the value on the command line. If the operator pastes a value into the
conversation, write it to a temporary file with mode `0600`, feed it on stdin,
and remove the file. Say that you did.

```bash
ksp secret set <record-id> --name <name> --passphrase-file <file> --json
```

```json
{"kind":"record","level":"user","record":"s1","version":1}
```

`level` is `user`, because `secret set` writes at the user's own level. That is
the record's provenance and it decides who may later read it.

An empty value is refused with exit `13` and a message naming the accepted form.
That is not a crash; it means stdin delivered nothing.

## Read a secret

```bash
ksp secret get <record-id> --passphrase-file <file>
```

```
db_password     ••••
```

The name and the redaction, so a caller can tell "redacted" from "empty". Add
`--reveal` only when the operator asked to see the value:

```bash
ksp secret get <record-id> --reveal --passphrase-file <file>
```

`--json` works on both and emits one object:

```json
{"kind":"secret","name":"db_password","record":"s1","revealed":false,"value":"••••","version":1}
```

**Prefer `ksp run` over `get --reveal` when the value is going to a process.**
`run` hands the value to a child through its environment and never writes it to
stdout, so it cannot end up in a scrollback buffer or a redirected file. Use
`get --reveal` only when a human asked to see the value.

`--version N` reads a specific version. Versions are not overwritten: a second
`set` on the same record id writes version 2 and leaves version 1 in place.

## List what exists

```bash
ksp secret ls --json
```

```json
{"kind":"records","records":[{"level":"user","record":"s1","version":1}]}
```

One entry per stored version, with no name and no value. An empty store returns
`{"kind":"records","records":[]}` — an empty array, not an error.

If a listing comes back with fewer entries than the operator expects, do not
conclude the records are gone. `secret ls` lists the user's own level. A record
written by `admin put` lives at the `admin` level; `ksp admin list` is the command
that names every level.

## Remove one version

```bash
ksp secret rm <record-id> --version 1 --passphrase-file <file>
```

```json
{"kind":"confirmation","operation":"secret rm s1 version 1"}
```

This removes exactly the version named. It is not a deletion guarantee: a copy
taken before the removal still opens, and nothing recalls it. Say that when you
report the removal.

`--version` defaults to `1`. If the operator means "remove this secret", confirm
which version they mean rather than assuming the record has only one.

## Cleanup of expired leases

```bash
ksp secret purge-expired --limit 100
ksp secret gc
```

`purge-expired` removes at most `--limit` versions whose armed deadline has
passed. `gc` removes every one that has passed. Both read the capability first:

```
capability=Scheduled { interval: 3600s }  selected=0  removed=0  already_absent=0  not_yet_due=0  bound_reached=false  backlog=0
```

On a host that never armed a schedule, `capability` reads `None` and the second
line explains that no sweep can remove anything. The command still exits `0`,
because it ran; it did not clean anything. **Do not report a cleanup from the
exit code.** Report `removed` and `not_yet_due`.

## Hand a secret to an agent

Two ways, and the difference is who can decrypt:

```bash
# A leased copy. Sealed to the agent, deleted on expiry or after --uses.
ksp secret share <id> --agent <agent-uuid> --out token.ksp [--ttl 3600] [--uses 3]

# Through a grant the admin signed. Takes no password: the publication entry is
# already sealed to the agent, and this command only copies the artifact out.
ksp secret share <id> --policy <policy-uuid> --out token.ksp
```

**Prefer `--policy` when a grant exists.** A committed policy is what the admin
signed, so the artifact was sealed at `admin policy create` time and the share
carries no content key at all. A minted lease is a fresh copy sealed to this
agent, and it is the only option when no grant names it.

Then deliver it. `--env` puts the value in the child's environment; it is never
the child's argv:

```bash
ksp run --token token.ksp --env DB_PASSWORD -- psql
```

**What `share` does not do.** It does not make the record readable to the agent
by path — the agent's copy is at its own level, and the original stays at the
user's. It does not prove the agent received it; that is `--consume` plus the
acknowledgement journal, and consume is not exactly once. A copy taken before
the lease expired survives it.

**Listing what was shared** is `ksp token list` (this host's minted tokens) and
`ksp admin policy list` (every grant). A token minted on another host is
invisible to both.

## Report

### What I did

One line per command, naming the record and the outcome:

- `ksp secret set s1` — version 1 written at the `user` level
- `ksp secret get s1` — read back, redacted
- `ksp secret ls --json` — N versions across the user level
- `ksp secret rm s1 --version 1` — removed version 1

### What is true now

```
Record:     s1 (name db_password)
Level:      user
Versions:   1
Readable:   yes, with the vault password
```

### What this cannot do

- **A removal is not an erasure.** A copy taken before it still opens, and no
  command reports a moment by which a copy is gone.
- **`secret ls` shows one level.** Records written by `admin put` are at `admin`
  and invisible to it; `ksp admin list` names every level.
- **The password is not recoverable.** The recovery phrase restores the sealed
  file, not the password.
- **A value printed with `--reveal` is in the terminal.** Prefer `ksp run` when
  the value is going to a process.

## Refusals

Report the exit code and the message verbatim and stop.

| Code | What it means here |
|---|---|
| `6` | Wrong password, or the vault is not readable |
| `7` | This host cannot hold that lease — arm and prove a sweep first |
| `13` | The invocation was malformed; the message names the accepted form |

An empty value with exit `13` means stdin delivered nothing. That is a usage
error, not a missing secret.
