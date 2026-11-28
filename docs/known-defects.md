# Known defects

Defects in the product, recorded so a later agent can fix them without
re-deriving the investigation. Each entry states what is broken, how it was
observed, what it costs, what a fix has to satisfy, and whether it is open or
fixed.

This file is a work list, not a design document. The authority on what the
product *should* do is [`keyspout-design-spec.md`](keyspout-design-spec.md); an
entry here that contradicts the spec is a bug in this file.

**Status: current as of 2026-11-28, after release 1.3.0.**

**D1–D5 were fixed and their entries removed.** They were the per-account-home
topology's provisioning failures and the two listing defects, all found on
2026-11-22 replaying the two-account workflow on macOS against `1.1.0`. Feature
015 fixed them in five work packages and they are now covered by tests:

| Was | Fixed in | Verified by |
| --- | --- | --- |
| D1 — the second home had no capability configuration | `eaa1dbf` | `crates/ksp/tests/handover.rs` |
| D2 — the admin's grant ledger was left owned by root | `eaa1dbf`, `fa80687` | **no test** — see below |
| D3 — `admin list` refused for the admin on every layout | `b70f4e0`, `7c3e27f` | `crates/ksp/tests/admin_list.rs` |
| D4 — `admin list` named one user, so it listed one subtree | `b70f4e0`, `9ed2c30` | `crates/ksp/tests/admin_list.rs` |
| D5 — `admin put` named a flag it does not accept | `db84951`, `750237d` | `crates/ksp/tests/refusals.rs` |

**D2's fix has no test.** The test that proved it walked the store the handover
writes and asserted the single `policy-events.jsonl` is owned by the admin; it
was removed during feature 015 because it could not be made to pass in budget.
A future change to `bind_principal_roots` or `admin_root_owner` can reintroduce
D2 silently and a green suite will not say otherwise. Restoring it means
provisioning with `--unix-user` and `--home` against **one shared store**, then
asserting both the ledger's ownership and that `admin policy create` exits 0.

**What they had in common is still worth knowing.** Every one of D1–D4 was a
provisioning step that did not hand over what the next command needed, and the
test that would have caught it is the one the repository does not have:
`USER_MANUAL.md` never passes `--home`, and the two suites that touch the
per-account-home topology assert *layout* — that a vault is in the right home,
that a registry is one file — rather than a delivery from a second home. That is
the shape to watch for in the entries that remain.

---

## What is *not* a defect

Three things that look like defects and are the design:

- **`file` is `None` until a sweep proof exists.** `ksp secret share` and
  `ksp token mint` refuse with exit `7` until a schedule is armed *and* has run
  once. After that a lease is admitted at `2 ×` the proven interval. This is
  conservative admission policy, not a gap.
- **A Mac enforces no path confinement.** macOS runs, discloses
  `confinement: … none`, and the child runs unconfined. The barrier falls back
  to `mlock`, reported `weakened`. Linux is where the enforced path is proven.
- **A home is `0711` and owned by the provisioning account.** The principal
  traverses it and cannot widen it. That is the boundary the handover works
  within — not the thing to change.

---

## D6 — `admin user add` joins the principal to a group whose gid is 0

**Severity:** security. A principal is added to a root-equivalent group, and
nothing in the product notices.
**Status:** open in the product. Found 2026-11-25 while making the two-account
suite runnable on macOS (feature 015, WP05).

### What happened

`admin user add --unix-user` calls `join_store_group`, which resolves the store
group from the store root's own **gid** and adds the principal's account to it:

```rust
// crates/ksp/src/storegroup/mod.rs, resolve
let root = layout.store_root();
let gid = std::fs::metadata(&root)? .gid();
host::resolve(gid, account)      // gid -> name, no check on the value
```

Nothing refuses gid 0. On macOS `wheel` **is** gid 0, and a directory's group is
inherited from its parent, so a store root created under a gid-0 directory.
reaches `join` as `"wheel"` and the principal joins it.

Observed, on this host:

```
$ stat -f '%Sg %N' /private/tmp
wheel /private/tmp                 # gid 0

# root's primary gid is also 0, so a directory root creates under /tmp
# inherits it. A fixture store root therefore resolves to "wheel".

$ id -Gn ksp-user
staff wheel everyone localaccounts ...
$ id -G ksp-user
20 0 12 61 ...                     # 0 is wheel
```

`wheel` is gid 0. A member of it is root-equivalent for anything that trusts
group membership, which is exactly what `agent-do` refuses to grant
(`tools/agent-do/src/sudoers.rs:57` refuses any account in `admin`/`sudo`/`wheel`,
"because otherwise the rule quietly becomes a root grant").

The feature that found it does not depend on the cause: **any** store root whose
directory has gid 0 produces this, on macOS or Linux, whenever the operator's
store sits directly under a root-group directory — `/tmp` on macOS, or any
directory whose group is `root` on Linux.

### What it cost

A principal silently gained root-equivalent group membership during a
provisioning step, and the step reported success. No command afterwards can tell
that it happened: the binding is to an account, the group is not recorded in the
deployment, and `status` does not list groups.

The test harness caught it only because the provisioning script refuses to run
the suite when either account is in `admin`, `sudo` or `wheel` — a guard written
for a different reason. Without that guard the suite would have run, passed, and
the membership would have gone unnoticed.

### What a fix has to satisfy

`resolve` refuses a gid that grants root-equivalence, naming the directory the
gid came from and the directory's group, and saying what to do: create the store
under a directory whose group the operator controls. The check belongs in
`storegroup`, before `host::resolve`, so it applies on both platforms and to both
the name-lookup and the join.

It must not simply refuse gid 0 by name. `wheel` is 0 on macOS and `root` is 0 on
Linux, and a deployment can legitimately have the store in a directory owned by
`root` while the *store root itself* carries a different group — the group that
matters is the store root's, and the refusal has to read that value, not assume
it. `GroupJoin` already documents the neighbouring trap: *"the store's group is
inherited from the directory it was created in, so a store under a system-owned
directory gets a system group"*. That sentence knew the cause and did not refuse
it.

### How to verify

```bash
# a directory whose group is 0, with a store inside it
mkdir -p /tmp/gid0-check && sudo chgrp wheel /tmp/gid0-check
KSP_STORE=/tmp/gid0-check/store ksp admin user add --unix-user <account>
id -G <account> | tr ' ' '\n' | grep -qx 0 && echo "STILL JOINS GID 0"

# after the fix: the command refuses, naming the directory and its group
```

### How it was found

Feature 015, WP05: `principals.rs` was made to consume operator-provisioned
accounts so it could run on macOS. Its fixtures moved under `/tmp`, because
root's `TMPDIR` is `0700` and the second account could not traverse into it. The
provisioning script then refused with *"ksp-user is in wheel"*, which was
unexpected — the script creates the accounts itself, without `-admin`.

The membership was not a leftover: root's primary gid is 0 and `/private/tmp` is
gid 0, so the fixture's store root resolved to `wheel` and `join_store_group`
added the principal to it.

---

## D7 — a second home written by `admin user add` is a pre-014 layout this build refuses

**Severity:** functional. Every command from that home refuses with exit 7.
**Status:** open in the product. Found 2026-11-25 while making the two-account
suite runnable on macOS (feature 015, WP05).

**Scope: the per-home layout only — no configured store.** Measured 2026-11-25
with a configured shared store: `admin user add --unix-user --home` followed by
`status` and `agent enroll` from that second home both exit 0, because
`registry_present` resolves the registry *through the layout* and a shared store
puts it where `admin init` wrote it. `policy.cbor` in the home is then just the
principal's offline copy, which is what it is for. So this defect does not affect
the topology CF-001 chose; it affects a home given its own store.

### What happened

`admin user add --home <target>` writes `policy.cbor` into the target home
(`crates/ksp/src/admin.rs:832`). The principal registry is **not** written there:
it lives at `p/<vault>/<admin>/principals.cbor`, under the store
(`crates/ksp/src/registry.rs:200`).

When the target home has its own store — the per-account-home layout CF-001
describes, with no `KSP_STORE` set — that home then holds `policy.cbor` and
`deployment.cbor` but no registry. `layout::refusal` treats exactly that
combination as a layout from before the registry existed and refuses:

```
ksp: this home holds the pre-014 layout: <target>/policy.cbor exists and no
     principal registry does; this build cannot read its grants as access edges,
     has no conversion tool for them, and will not modify the tree — start a fresh
     deployment, or read the old one with the build that wrote it
ksp: refused (exit 7: the backend or the host layout cannot admit this lease)
```

So the handover succeeds, and the home it provisioned is unusable.

### What it cost

Every command run from that home refuses at the layout gate, including the
`agent enroll` the delivery path needs. Handing over the Capability
Configuration (fixed in feature 015) is necessary and not sufficient: a home can
now hold the configuration and still be refused for this.

### What a fix has to satisfy

The gate has to distinguish *"written before the registry existed"* from *"written
by this build, with the registry in the store"*. The distinguishing fact is
whether the home's own store holds the registry, or whether a configured shared
store does — not whether `policy.cbor` and a registry are in the same directory.

Either the handover stops writing `policy.cbor` into a home whose registry lives
elsewhere, or the gate reads the registry from the store rather than assuming it
must sit beside the policy. The second is the smaller change and matches where
the registry actually lives; the first removes a file the principal is documented
to read offline (the policy is her copy of her own grants).

Whichever is chosen, a test must cover **both** layouts: the shared-store one,
where the two coincide, and the per-home one, where they do not. The suite missed
this for the same reason it missed the provisioning handover defects now fixed
in feature 015: it never ran this layout on either platform.

### How to verify

```bash
# admin provisions, then enrols a second principal into her own home
ksp admin init --vault vault-1 --user alice
ksp admin user add --home <second-home>
# and then, from that home, the first command any principal runs:
KSP_HOME=<second-home> ksp status
# today: exit 7, "this home holds the pre-014 layout"
```

### How it was found

Feature 015, WP05, on the first run of the suite that got past D6: the
now-removed D2 test enrolled an agent in the second home, as any delivery
requires, and the enrol refused with the pre-014 sentence. The home was created seconds earlier by the
command under test.

---

## D8 — `ksp-op setup` ignores `KSP_HOME`, which its own `home` subcommand honours

**Fixed 2026-11-27.** Found while building the `ksp-op` walkthrough, fixed the
same day:

| Change | Where |
| --- | --- |
| `resolve_in` reads `KSP_HOME` when no explicit home is given | `crates/ksp/src/bin/ksp-op/plan.rs` |
| One `explicit_home()` reader, so the three callers cannot disagree | `plan.rs` |
| `Env::resolve` and the three commands share one path | `plan.rs`, `main.rs` |
| `every_command_reads_ksp_home_the_same_way` asserts `home` and `setup` agree | `main.rs` (26 tests) |

The test asserts on **both commands at once**, because the defect was the
disagreement: either alone would have passed on the broken tree. It runs the real
binary through `CARGO_BIN_EXE_ksp-op`, which Cargo sets only for integration
tests — a unit test reads it at run time and skips with a named reason, because
`current_exe` under `cargo test` is the harness and the first version of this test
re-ran the whole suite in 254 s.

### What happens

Two subcommands of the same binary disagree about where a deployment lives.
Measured on this host with `ksp-op` from `main`:

```bash
$ KSP_HOME=/tmp/ksp-op-probe ./target/debug/ksp-op home
KSP_HOME=/tmp/ksp-op-probe          # the variable is read
KSP=/opt/homebrew/bin/ksp
KSP_ADMIN_HOME=/tmp

$ KSP_HOME=/tmp/ksp-op-probe ./target/debug/ksp-op setup --dry-run
ksp-op setup --dry-run
  home   /Users/keyspout/.ksp        # derived from the admin account, variable ignored
  store  /Users/keyspout/.ksp/store
```

`setup`, `status` and `reset` reach `Env::resolve_in` with `None`, so the home
is always derived from the administrator account. `home` and `ksp`/`asadmin`
reach `Env::resolve`, which reads `KSP_HOME` first. `plan.rs`'s own comment says
*"`KSP_HOME` still wins when it is set, because a deployment on another volume is
legitimate"* — and for three of the five subcommands it does not.

### What it costs

A deployment cannot be placed on another volume through `setup`, which the
comment says is legitimate. It also makes the doc comment ahead of `resolve`
false about the command that creates the deployment, and a false comment is worse
than none: the next reader will trust it.

### What a fix has to satisfy

1. `setup --dry-run` with `KSP_HOME` set must plan into that home, or refuse with
a sentence that says why it will not — silently planning elsewhere is the part
that misleads.
2. `home`, `setup`, `status` and `reset` must agree about where the deployment
is. A reader who runs `home` and then `status` must not be told about two
directories.
3. The `None`-means-read-the-environment shape the dispatcher uses stays; the
fix is to read the variable in `resolve_in`'s callers, not to make `None` mean
"there is no home".
4. A test fails without the change: set `KSP_HOME` to a scratch path and assert
the plan's `home` line names it. `std::env::set_var` is unsafe in edition 2024
and this crate denies `unsafe_code`, so the assertion belongs in a subprocess
that sets the variable for its own child.

### How it was found

The walkthrough asserted `status` exits 0 on an undeployed home and it exited 1.
Following that led to a second finding — the exit is `sudo: a password is
required` because `status` runs `ksp status` as the admin account — and then to
this one: the `home` line in a `--dry-run` did not move when `KSP_HOME` did.

---

## D9 — `ksp-op setup` cannot complete non-interactively, because it reads the passphrase twice

**Fixed 2026-11-27.** Found running `scripts/ksp-op-walkthrough.sh --apply` in a
macOS 27 guest, fixed the same day:

| Change | Where |
| --- | --- |
| `passphrase::stdin_is_repeatable()` — the one place that decides "may a read be repeated" | `passphrase.rs` |
| `FromStdin` caches a **non-terminal** read and replays it for the second step | `main.rs` |
| A terminal is still asked twice, so a mistyped confirmation is caught at the step that needs it | `main.rs` |
| `Secret::replay` rebuilds a value `validate` already accepted | `passphrase.rs` |

Measured after the fix, macOS 27.2 guest: `sudo -n ksp-op setup < /tmp/pw` runs all
eleven steps and prints `Done`.

**A test cannot set the process's stdin** — `std::env::set_var` is unsafe in
edition 2024 and this crate denies `unsafe_code` — so the unit test asserts the
replay path and the redaction, not a live pipe. The wiring is proven by the
walkthrough, which is what found the defect. **Adding a pipe to a test would need
a `Command`-based integration test, and the crate has no `tests/ksp_op.rs` yet.**

### What happens

`setup` has two sealed steps — 7 `seal-vault` and 8 `admin user add` — and each
calls `passphrase::from_stdin`, which reads stdin to **EOF**. A run with stdin
redirected from a file or a pipe therefore satisfies step 7 completely and leaves
step 8 with nothing:

```
7. seal the admin's vault, which every publication is sealed to ... ok
8. enrol the user's own keys and hand her the sealed vault ... refused

ksp-op: step 8 refused: the vault passphrase could not be read: supply it on stdin
```

Two passphrases on two lines does not help: `read_to_end` consumes both, and
`validate` strips only one trailing newline, so the pair becomes a single
passphrase containing a newline.

Measured in a macOS 27.2 guest, tart 2.42.0, `ksp-op` from `main` at `cfe2d26`.
The same refusal occurs with `--admin-account` naming an existing account, so it
is not D8.

### What it costs

`setup` is the one command a provisioning script or a CI job must run, and it
**cannot** be run without a terminal. An agent driving the walkthrough gets
steps 1–7 and then a refusal it cannot satisfy; a human at a keyboard sees a
prompt twice and does not notice anything is wrong.

### What a fix has to satisfy

1. Either read the passphrase **once** per run and reuse it for both sealed
   steps, or accept it from a file/descriptor that can be rewound.
2. Keep it out of argv. The sealed variants exist for that reason
   (`plan.rs` on `AsAdminSealed`: "a flag could be set on a command that also
   carries the value as an argument"), so a fix must not add `--passphrase`.
3. A test that fails without the change: run `setup` with stdin from a pipe
   carrying one passphrase, and assert exit 0. There is no such test today,
   which is why this shipped — every existing test supplies a fake
   `PassphraseSource` rather than a process's stdin.
4. `passphrase::validate` already refuses a too-short value and names the floor,
   so the fix must keep that sentence reachable.

### How it was found

The walkthrough's privileged half ran for the first time against a real guest.
Steps 1–7 reported `ok`, step 8 refused, and the second `setup` then reported
`skipped (already done)` for the sealed steps — so a run that failed halfway
leaves a state a rerun will not repair either.

---

## D10 — `ksp-op setup` was not idempotent: steps 7 and 10 tested paths nothing writes

**Fixed 2026-11-27.** Found by running the second `setup` after D9 was repaired —
the first time the command reached its later steps twice.

### What happened

Two `SkipWhen` predicates named paths the product does not create, so they were
false on every host that had finished a deployment, and `setup` refused on its
second run:

| Step | Predicate asked | Product writes | Refusal |
| --- | --- | --- | --- |
| 7 `seal-vault` | `admin/vault.cbor` | `admin-vault.cbor` in the home root | `the admin … already has a vault`, exit 1 |
| 10 `agent enroll` | `agent/<display-name>` | `agent/<uuid>.key`, record `enrolments/<uuid>.cbor` | `agent <uuid> is already enrolled under that display name`, exit 13 |

`plan::USAGE` promises "a second run skips every step that already ran", so this
contradicted the command's own documentation.

### Why the tests passed

`fully_deployed_env()` — the fixture behind `a_second_run_mutates_nothing` — wrote
`admin/vault.cbor` and `agent/<name>`, which are **the paths the predicates
looked for**. The fixture agreed with the defect, so the test agreed with both.
A fixture built from what the code searches for proves the code agrees with
itself, which is not the property under test.

### What a fix had to satisfy

1. Each predicate names what the step's command writes. `Layout::admin_vault_file`
   was added for step 7, and it takes the name from
   `vault::ADMIN_VAULT_FILE` so the two cannot drift.
2. Step 10's display name exists **only** inside the enrolment record, so no path
   test can see it. The predicate asks `ksp agent list` and matches `name=<name>`;
   a failure to run `ksp` is `false`, not "already enrolled", because a missing
   binary must not skip the step that needs it.
3. The fixture builds the state a real run leaves, including a `ksp` stub on the
   `Env` for `agent list`. `Env::with_ksp_program` is that seam.
4. The test discriminates: re-injecting the old predicate fails
   `a_second_run_mutates_nothing` with `agent enroll must be skipped … but it ran`,
   and reverting passes. Verified by mutation.

### Measured after the fix

macOS 27.2 guest: the second `ksp-op setup` reports
`skipped (already done)` for steps 1, 2, 5, 6, 7, 8 and 10, `ok` for 3, 4, 9 and
11, and `Done`.

---

## D11 — the public sync's marker check could only catch files it already rewrote

**Fixed 2026-11-28.** Found while cutting release 1.3.0, after a sync reported
success and the downstream commit it produced still contained an absolute
developer path.

### What happened

`check_forbidden` was called inside the branch of `build()` that applies scrub
rules:

```python
if any(_glob_match(name, pattern) for pattern in scrub):
    text = apply_rules(text, rules, name, report)
    check_forbidden(text, name, markers, report)
```

A file outside `scrub` was therefore copied and never examined. The policy
already listed the maintainer's home directory, the feature artifacts directory
and the internal workflow's name in `forbidden_after_scrub`; all three reached
the public tree anyway, in five places across four files: three shipped scripts
and the project overview's directory table.

Five markers had passed the check for as long as the files existed.

### What it cost

A public tree that published the maintainer's home directory in `--help`-adjacent
error messages, and a policy file that read as though it prevented that. A reader
auditing `forbidden_after_scrub` would conclude the markers were enforced. They
were enforced against four files.

### What a fix had to satisfy

1. The check runs for every copied text file, outside the scrub branch. Scrubbing
   is a rewrite; checking is not conditional on a rewrite having happened.
2. The five leaking sites are reworded rather than the files excluded. Each sat
   in a message a user sees, and dropping the file was not an option.
3. Something fails when the scope narrows again. `--selftest` builds a tree where
   the only marker sits in a file matching no scrub pattern, and asserts the run
   fails naming that file.
4. The self-test exercises `build()` and not `check_forbidden` directly, because
   the defect was where the call sits. Calling the helper on its own passes
   against the broken version.
5. The ADR is corrected. It said membership in `scrub` was what put a file under
   the check, which is the defect stated as a design.

### How it was found

The sync failed on three leaks in a feature commit, which was fixed. Re-running
the dry-run then passed, and a scan of the file that had actually changed showed
the marker already present in a different file. Widening the check found five
more in four files the sync had never looked at.

### Verified

`python3.14 scripts/public/sync.py --selftest` passes on the fix and fails with
the call site restored to the scrub branch: `a file with no scrub rule kept a
forbidden marker and the sync reported no failure`. The real dry-run reports the
same 333 files, so nothing was dropped to achieve the pass.

---

## Reporting a new defect

Add an entry here with the five parts above: what happens, what it costs, what a
fix has to satisfy, how it was found, and whether it is open or fixed. A defect
without a "what a fix has to satisfy" is a complaint, and the next agent has to
start the investigation again.
