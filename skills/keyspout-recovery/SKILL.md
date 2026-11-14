---
name: keyspout-recovery
description: Re-share a Keyspout vault's recovery phrase and rotate key material. Use when the operator says "rekey the vault", "change the recovery phrase", "I lost the recovery phrase", "rotate the admin key", "rotate the agent keys", or asks what rotation does and does not revoke.
---

# Keyspout recovery

Two operations, and they are easy to confuse:

- **`vault rekey`** re-shares the sealed vault under a new recovery phrase. The
  password is unchanged.
- **`agent rotate`** replaces an agent's keypairs. The old bundle is retained.

Neither one revokes anything already issued. Say that before you run either.

## The one thing to get right

**A recovery phrase restores the sealed bundle. It does not restore a lost
password.** If the operator has lost the password, no phrase and no share set
brings it back — the vault is sealed under it and there is no escrow. Stop and
say so rather than running a command that will not help.

The same asymmetry in the other direction: `vault rekey` changes nothing about
the password. An operator who thinks rekeying changes their password will be
surprised at the next read.

## Re-share the vault

```bash
ksp vault status
```

`sealed, version N` is the normal answer. Then:

```bash
ksp vault rekey --threshold 2 --shares 3 < <password-file>
```

```
threshold=2  shares=3
write this down now: it is the only copy, and the previous phrase no longer recovers this vault
keyspout-recovery-v1 k=2 n=3
share 149 9ac93f…
share 65 cfe3fd…
share 230 795af1…
```

Four things about that output:

1. **The phrase is printed after the re-sealed vault is on disk, and printed
   once.** There is no way to print it again.
2. **The previous phrase no longer recovers this vault.** A rekey retires it. If
   the operator has the old phrase written down, tell them it is now useless.
3. **`k` of `n` shares are needed.** With `--threshold 2 --shares 3`, any two
   restore the bundle and one alone does not. Losing `n - k + 1` shares loses the
   bundle.
4. **The password is unchanged.** Every read still needs the same password.

**Write the shares down before the terminal scrolls.** Give the operator the
shares and tell them to store them separately — two shares in one place is one
share as far as a fire is concerned.

`--json` emits a `RecoveryPhrase` document instead of the text block. Either way
the phrase appears once.

## Rotate an agent's keys

```bash
ksp agent rotate --agent <agent-uuid> \
  --signing-key-id <name>-ed25519-2 \
  --recipient-key-id <name>-x25519-2
```

The previous bundle is retained beside the new one, so an artifact sealed to the
old recipient key still opens.

**Rotation changes future minting and new trust state. It revokes nothing.**

- An old token still works until it expires or is revoked.
- An old copy of the private key still opens what it opened before.
- A new enrolment fingerprint must be confirmed out of band, exactly as at first
  enrolment.

If the operator's intent is "stop the old token", that is `token revoke`, not
rotation. If the intent is "the old key file leaked", rotation alone does not
contain it — the old key still opens old copies, and the upstream credential the
copies protect needs revoking separately.

## Rotate the admin key

The admin anchor is what verifies policy, admin arming records and admin sweep
proofs. Rotating it changes who signs those, and every surface that prints an
issuer key id will print the new one.

This is not a routine operation. Before running it, confirm with the operator
that they intend to change which key signs policy, because a host whose policy was
signed by the old key needs that policy re-signed under the new one or every
policy check fails.

If they confirm, re-sign the policy in the same session and verify:

```bash
ksp admin policy --show
```

`issuer: verified against the pinned anchor` must be present. If it is not, the
policy and the anchor disagree and the host will refuse every delivery until they
agree.

## What rotation does not do

| Operation | Changes | Does not change |
|---|---|---|
| `vault rekey` | The recovery phrase, and the shares that restore the sealed file | The password, any record, any key |
| `agent rotate` | Future minting, new trust state, the fingerprint | Any issued token, any copy already sealed, any old key file |
| `token revoke` | Whether the named token is accepted | Any copy already delivered |
| Revoking the upstream credential | Whether the protected service accepts the old credential | Any copy of the value already saved |

Each row is a separate action. An operator who wants all four has four steps.

## Report

### What I did

- `ksp vault status` — sealed, version N
- `ksp vault rekey --threshold K --shares N` — new phrase printed once
- `ksp agent rotate` — new key IDs `…`; old bundle retained
- `ksp admin policy --show` — issuer verified against the pinned anchor

### What is true now

```
Vault:           sealed, version N
Recovery:        K of N shares restore the sealed file
Password:        unchanged
Agent keys:      <new signing key id>, <new recipient key id>
Old bundle:      retained beside the new one
Policy issuer:   verified against the pinned anchor
```

Then the instruction that matters: **the shares are printed once and the operator
must store them now, separately.**

### What this cannot do

- **A recovery phrase restores the sealed bundle, not a lost password.** There is
  no escrow and no reset.
- **A rekey retires the previous phrase.** The old one no longer recovers the
  vault.
- **Rotation does not revoke old offline pairs.** Old tokens work until they
  expire or are revoked; old copies of a key open old copies of a record.
- **Revoking the upstream credential is a separate action.** It is not part of
  rotation and this tool cannot do it.
- **Shamir restores a sealed bundle.** It does not recover a lost phrase and it
  does not open a record on its own.

## Refusals

| Code | What it means here |
|---|---|
| `6` | The password is missing or wrong |
| `2` | The operation was denied — the policy and the anchor disagree, or the account is not resolvable |
| `13` | The invocation was malformed; the message names the accepted form |

If `vault rekey` refuses, do not retry with a different share count. Read the
message: a refusal here is about the password or the host, not about `k` and `n`.
