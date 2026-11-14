---
name: keyspout-audit
description: Read what happened in a Keyspout deployment and check whether the log verifies. Use when the operator asks "what happened", "show me the audit log", "who did what", "did that deletion happen", "is the log intact", "verify the chain", or asks for evidence behind a claim a report made.
---

# Keyspout audit

Two different questions, two different commands, and neither answers the other:

- **What happened?** `ksp audit` — the signed log, scoped to the caller.
- **Is it intact?** `ksp audit verify` — every record checked against pinned
  public material.

A third reads a different journal entirely: `ksp admin audit` reports deletion
intents, actor reports and absence observations. It is not the same log.

## The one thing to get right

**`ksp audit --json` is JSONL, not one object.** The first line is a header and
every later line is a record. A consumer that parses the whole output as one
document fails with `Extra data: line 2 column 1`. Split on newlines and branch
on `kind`.

This is the only command in the tool that behaves this way, and the reason is
that a log grows without limit: one object per record lets a consumer read a
record at a time instead of buffering the whole log.

## Read the log without a password

Three paths need no credential, which is why they come first:

```bash
ksp audit --admin
ksp audit verify
ksp admin audit
```

`--admin` reads the complete view. `verify` checks the chain. `admin audit` reads
the deletion acknowledgement journal. None of them opens the vault.

```
audit: scope=complete  segments=2  records=2  unknown=0  malformed=0  unreadable=0  withheld=0
note: this view has not checked signatures or chain links; `ksp audit verify` checks them
note: records are grouped by chain (writer); the order between chains is each writer's timestamp claim, not a sequence this host can prove
record: actor=…  signer=admin-2026  component=sweeper  operation=sweep  outcome=success  code=0  at=…  segment=…  index=0
record: actor=…  signer=alice-ed25519-1  component=cli  operation=put  target=vault-1/user/s1/1  outcome=success  code=0  at=…  segment=…  index=0
```

**The second note is not boilerplate.** Records are grouped by chain, and the
order *between* chains is each writer's own timestamp claim. Two records can
appear out of chronological order and that is the view declining to claim a
sequence it cannot prove. Do not re-sort them and do not present them as a
timeline.

## Read the tenant's own records

```bash
ksp audit --json --passphrase-file <file>
```

The scoped view needs the vault password, because opening the vault is how the
caller proves a pinned key. Ask the operator for the file path.

```jsonl
{"kind":"log","scope":"own","records":2,"total":2,"limit":200,…}
{"kind":"audit-record","actor":"…","component":"cli","operation":"put","outcome":"success","observed_at":…,"target":"vault-1/user/s1/1",…}
```

Bound the read when the log is long:

```bash
ksp audit --limit 50 --since 1h --passphrase-file <file>
```

- `--limit` caps the record lines. `--limit 0` reads without a bound.
- `--since` filters by each record's own `observed_at`, as `<n><s|m|h|d>`.
- The header reports `records` (what this invocation emitted) beside `total`
  (what the scope holds). **If they differ, say so and name `--limit`.**

A duration that will not parse is exit `13` and the message names the accepted
forms.

## Verify the chain

```bash
ksp audit verify --json
```

```
audit verify: segments=2  records=2  valid=2  revoked=0  unpinned=0  mismatch=0  invalid=0  unreadable=0  chain=unbroken
head <uuid>/admin-2026=<digest>
note: completeness unknown: no head digest was supplied from outside the log, so a deleted tail verifies exactly like a whole one
note: a record that verifies is the writer's claim at the time it wrote; an absent record is not evidence that an operation did not happen
```

Read `valid`, `invalid`, `mismatch`, `revoked`, `unpinned`, `unreadable` and
`broken`. `broken` is `null` when the chain is unbroken.

**Report `completeness` as the sentence it is.** It says the same thing every
time, and turning it into "the log is complete" is a claim the tool explicitly
declines to make. A deleted tail verifies exactly like a whole one.

`--head <digest>` supplies a head from outside the log, which is the only way
completeness becomes checkable. If the operator has no external head, say
completeness is unknown and stop there.

## Read the deletion journal

```bash
ksp admin audit --json
```

```json
{"kind":"audit","lines":[],"unreadable":0}
```

This is the acknowledgement journal: deletion intents, actor reports and absence
observations. It is not the signed log, and an empty journal is not an empty log.

Read the one line the text view prints: *a report's time is the actor's claim,
not a deletion this host observed.* An intent contains no keys and is not a
tombstone. Native absence without a report is missing or unconfirmed.

## Report

### What I did

- `ksp audit verify --json` — N records, `broken` is `null`
- `ksp audit --admin` — read the complete view, N records across M chains
- `ksp admin audit --json` — N journal lines
- `ksp audit --json` — **skipped**: no vault password supplied

### What is true now

```
Records:       N across M chains
Verifies:      yes — valid N, invalid 0, mismatch 0
Completeness:  unknown — no head digest arrived from outside the log
Journal:       N acknowledgements, N unreadable
```

Then the records themselves, grouped by chain, with the ordering caveat stated
once.

### What this cannot do

- **A verified record is the writer's claim at the time it wrote.** It is not
  proof the operation had the effect it describes.
- **An absent record is not evidence that an operation did not happen.**
- **Completeness is unknown without an external head.** A deleted tail verifies
  like a whole one.
- **The order between chains is a timestamp claim.** This host cannot prove a
  global sequence.
- **An intent is not a tombstone.** It contains no keys, and it does not establish
  that anything was deleted.
- **`withheld` counts records a narrowed view can see but not attribute.**
  Counting without printing is deliberate: the count says the log is not fully
  rendered.

## Refusals

| Code | What it means here |
|---|---|
| `6` | The vault password is missing or wrong, or this host has no deployment |
| `12` | The log did not verify |
| `13` | The invocation was malformed; the message names the accepted form |

**An unreadable log and an empty log are different answers.** If a read is
refused, say the log was not read and name the missing credential. Never report
"no records" from a refusal.
