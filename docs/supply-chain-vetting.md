# Dependency review — `cargo-vet`

**Status:** configured and enforced. **No crate has been audited yet.**

```
$ cargo vet --locked
Vetting Succeeded (314 exempted)

$ grep -c '^\[\[exemptions\.' supply-chain/config.toml
314

$ grep -c '^\[\[audits\.' supply-chain/audits.toml
0
```

Read those two numbers together. **314 exempted, 0 audited** means the ledger
exists and enforces something, and that nothing in it is a review.

## What it is

`cargo-vet` is a review ledger for dependencies. Every crate in the tree needs
either an **audit** — a record that a human read it and judged it acceptable — or
an **exemption**, which records that nobody has yet.

It is the only control in the hardening plan that catches a **compromised
dependency** (T2) before it ships. A scanner finds *known* bad versions; `cargo
vet` is your own review of *what the code does*, which is what catches a typosquat
or a hijacked maintainer account that no advisory has named.

## What the current state enforces

An exemption is not a pass. It is a recorded decision to defer, and the gate
still does something useful with it:

- **A new dependency fails the gate.** Adding a crate requires someone to write an
  exemption or an audit. That is a decision made in a commit rather than a silent
  pull, which is exactly the control this work package wanted.
- **A version bump of an exempted crate also fails**, because the exemption is
  pinned to a version. A bump is a new crate as far as the ledger is concerned.

  This happened on 2026-11-14 and is the clearest demonstration of the control.
  Upgrading `rustix` 1.1.5 → 1.1.6 to fix `RUSTSEC-2026-0486` made `cargo vet`
  fail:

  ```
  $ cargo vet --locked
  1 unvetted dependencies:
    rustix:1.1.6 missing ["safe-to-deploy"]
  ```

  The exemption was pinned to 1.1.5, so the fixed version counted as a new crate.
  The gate refused the upgrade until someone moved the exemption. That is the
  behaviour the work package wanted: a dependency change cannot happen without a
  recorded decision.

What it does **not** do is review anything. The 314 exemptions are the size of the
backlog, not a measure of coverage, and the gate prints both numbers on every run
so a reader cannot mistake "Vetting Succeeded" for "everything was reviewed".

## Reducing the backlog

```bash
cargo vet suggest          # the cheapest reviews first, by dependent count
cargo vet                  # interactive review, records the audit entry
```

Start with the crates that have the most dependents — `serde`, `libc`, `sha2`.
Each review replaces an exemption with an audit entry that says what was checked.

The Mozilla and Google audit sets cover a large part of the ecosystem. Trusting
one means you accept their reviewers rather than doing the review yourself. That
is a real decision with a real trade-off, and it is worth stating in the commit
that makes it rather than being assumed.

## A trap: `cargo vet` can write an audit nobody performed

When a version bump is small, `cargo vet --locked` may **auto-record a delta
audit** attributed to the repository owner:

```toml
[[audits.ctutils]]
who = "Rodrigo DL <ramakandra@gmail.com>"
criteria = "safe-to-deploy"
delta = "0.4.5 -> 0.4.8"
```

That happened here on 2026-11-14, when `crypto-bigint` moved to 0.7.11 and pulled
`ctutils` 0.4.8 with it. Nobody read the diff. The entry says someone did.

It is removed, and the crate is exempted instead. An exemption is honest — it
records that the review has not happened. **Check `audits.toml` after any
dependency bump**, and treat an entry you did not write as a claim to delete
rather than a convenience to keep.

This is the one place where the tool's convenience works against the property the
ledger exists to provide.

## The files

| File | Role |
|---|---|
| `supply-chain/config.toml` | The exemptions, one per crate, each `safe-to-deploy` |
| `supply-chain/audits.toml` | The audits. **Empty today.** |
| `supply-chain/imports.lock` | Pins the audit sets that are trusted |

All three are `authored` in `sync.json`. They live in the downstream tree and a
sync must never overwrite or delete them — a `cargo vet` ledger that a sync
replaced would silently reset the review state.

## Why this is in the downstream tree

The ledger describes the tree that is released, and the release runs downstream.
Keeping it upstream would mean the gate that enforces it and the ledger it
enforces are in different repositories.
