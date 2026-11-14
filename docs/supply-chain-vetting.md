# Dependency review — `cargo-vet`

**Status:** not initialised. This file records what the control is, why it is not
enabled yet, and exactly what enabling it requires.

## What it is

`cargo-vet` is a review ledger for dependencies. Every crate in the tree needs an
audit entry that says a human read it and judged it acceptable, or a
`exemptions` entry that says nobody has yet. A new dependency with neither fails
`cargo vet`.

It is the only control in the hardening plan that catches a **compromised
dependency** (T2) before it ships. A scanner finds *known* bad versions; `cargo
vet` is your own review of *what the code does*, which is what catches a typosquat
or a hijacked maintainer account that no advisory has named yet.

## Why it is not enabled

`cargo vet init` is interactive: it asks which audit sets to trust and writes
`supply-chain/config.toml` from the answers. Running it non-interactively
produces nothing, and writing the config by hand would mean inventing audit
entries — a ledger that claims reviews nobody performed is worse than no ledger,
because it looks like evidence.

So the work package ships the **check** and leaves the **initialisation** to a
human, which is the only honest split.

## What enabling it requires

1. Run `cargo vet init` at the repository root and answer the prompts. It writes
   `supply-chain/config.toml` and `supply-chain/audits.toml`.
2. Choose an audit set to trust. The Mozilla and Google sets cover a large part
   of the ecosystem; trusting one means you accept their reviewers rather than
   doing the review yourself. That is a real decision, not a formality.
3. Run `cargo vet suggest` to see the cheapest reviews to do first.
4. Commit both files. The CI check below then enforces them.

## The check

`scripts/ksp-gate.sh ci` runs `cargo vet --locked` **only when
`supply-chain/config.toml` exists**. That is deliberate:

- Before initialisation, the check would fail for a reason that is not a defect,
  and a gate that is red for a known non-defect teaches people to ignore it.
- After initialisation, the check runs and a new unvetted dependency fails the
  build.

The conditional is not a way to skip the control. It is a way to make the
control's absence visible: `cargo vet` prints that it is not configured, so a
reader sees the gap rather than a green tick that means nothing.
