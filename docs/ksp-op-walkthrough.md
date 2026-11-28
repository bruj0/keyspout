# The `ksp-op` walkthrough

`ksp-op` turns a stock macOS or Linux host into a two-account Keyspout
deployment. This document records what that looks like from a terminal, what the
walkthrough asserts, and where each assertion came from.

**Where these transcripts came from.** Both halves ran in a macOS 27.2 guest —
`scripts/ksp-macos-vm.sh`'s, tart 2.42.0, image `macos-golden-gate-base` — and
both pass: **19 assertions — 11 read-only, 8 privileged — 0 failures.** D8, D9
and D10 were found by running it
and are now fixed.

**Running it:**

```bash
scripts/ksp-op-walkthrough.sh              # read-only; safe on any host
scripts/ksp-op-walkthrough.sh --apply      # privileged; macOS guest only
scripts/ksp-op-walkthrough.sh --selftest   # the assertions, no binary
```

Build `ksp-op` first: `cargo build -p ksp --bin ksp-op`.

---

## 1. Why there are two halves

`setup` is the only subcommand that changes a host, and it needs root: it creates
the administrator account, `chown`s the tree, and writes a launchd agent. On a
developer's own Mac that is the last thing anyone wants to run by accident.

So the walkthrough splits:

| Half | Changes the host | Runs on | What it proves |
| --- | --- | --- | --- |
| read-only | no | any host with a build | the plan is complete, stable, and reads no passphrase |
| privileged | yes | a disposable macOS guest | the deployment is created, is idempotent, and is removable |

The read-only half is the one a developer replays. It caught two real findings
while this document was written (see §5).

## 2. The read-only half

Measured output, 2026-11-27:

```
setup --dry-run exits 0                                       ok
the plan names the administrator account step                 ok
the plan names the tree handover                              ok
the plan names the user enrolment                             ok
the plan names the agent enrolment                            ok
the plan marks the sealed steps                               ok
two dry runs print the same plan                              ok
status on an undeployed home answers                          ok
home resolves and exits 0                                     ok
reset without --yes is refused                                ok
an unknown command exits 2                                    ok

11 passed, 0 failed
```

### 2.1 What `setup --dry-run` prints

Captured whole, because the walkthrough asserts on these lines:

```
ksp-op setup --dry-run
  home   /Users/keyspout/.ksp
  store  /Users/keyspout/.ksp/store
  vault  vault-1

  1. [root] create the administrator account, if it does not exist
       create the account only if it is absent
  2. [in-process] create the administrator's home at the mode the user may traverse
       mkdir /Users/keyspout/.ksp (mode 0711)
  3. [in-process] provision the layout: key root, enrolments, sweeper, store
       ksp::layout::ensure (every mode from the library)
  4. [root] give the tree to the administrator, so every later step can write
       chown -R keyspout (the tree belongs to the administrator)
  5. [admin] probe this host and write its capability configuration
       ksp init
  6. [admin] create the admin signing key and name the vault
       ksp admin init --vault vault-1 --user bruj0 --key-id keyspout
  7. [admin] seal the admin's vault, which every publication is sealed to
       ksp-op: passphrase read from stdin
       ksp admin seal-vault
  8. [root] enrol the user's own keys and hand her the sealed vault
       ksp-op: passphrase read from stdin
       env KSP_HOME=/Users/keyspout/.ksp ksp admin user add --unix-user bruj0 --signing-key-id bruj0-ed25519-1 --recipient-key-id bruj0-x25519-1
  9. [admin] widen the capability configuration so the user's account can read it
       chmod 0644 /Users/keyspout/.ksp/config.toml
  10. [user] enrol the agent, which receives deliveries
       ksp agent enroll --agent bruj0-laptop
  11. [admin] report the deployment so the operator can confirm it
       ksp status
```

Four things in that output are worth reading closely.

**The tag is who runs the step.** `[root]`, `[admin]`, `[user]` and
`[in-process]`. Steps 1 and 4 are root, and they are exactly the two that create
an account and hand a tree to it — which is why `agent-do` refuses `(root)` and
why this binary exists separately from `ksp`.

**Step 3 is in-process and prints no argv.** It calls `ksp::layout::ensure`
rather than a command, so there is nothing to show. A step that printed a command
it did not run would be a step a reader could not distinguish from a real one.

**Steps 7 and 8 print `passphrase read from stdin` and then the command.** The
`sealed` variants are what make a `--dry-run` read no passphrase: the read
happens inside `execute_steps` at the step that needs it, so a run that stops
earlier never asks. This is the shipped bug in the shell script that
`plan.rs`'s module comment names, and it is why the walkthrough asserts on the
sentence rather than on the absence of a prompt.

**Step 8 names `env KSP_HOME=…` and step 9 widens `config.toml`.** Those are the
two places the two-account deployment has to be told about the second principal.
Dropping either silently produces a deployment where the user cannot read the
configuration she is supposed to read.

### 2.2 `status` on an undeployed home

Measured, and this is why the assertion accepts either exit code:

```bash
$ KSP_HOME=/tmp/ksp-op-walk ./target/debug/ksp-op status
1. the backend capability, its cadence and this host's posture ... refused

ksp-op: step 1 refused: `ksp status` failed as keyspout: sudo: a password is required
$ echo $?
1
```

`status` runs `ksp status` **as the administrator account**, so on a host where
that account cannot be reached without a password it refuses — correctly. On a
guest provisioned by `scripts/ksp-macos-vm.sh` the account has `NOPASSWD` and it
succeeds.

An assertion that demanded exit 0 would fail on every ordinary developer machine
and pass only where the whole privileged setup already exists, which inverts what
a read-only half is for. The assertion is therefore *that it answered*, and the
document says which answer each environment gets.

## 3. The privileged half

Measured in a macOS 27.2 guest on 2026-11-27, after D8, D9 and D10 were fixed:

```
the admin account already exists                              ok
setup exits 0 from a redirected stdin                         ok
setup printed its completion line                             ok
a second setup exits 0                                        ok
a second setup skipped its steps                              ok
status after setup exits 0                                    ok
reset --dry-run exits 0                                       ok
reset --yes exits 0                                           ok
```

`setup` runs all eleven steps from `< /tmp/pw` and ends with `Done.`; a second run
reports `skipped (already done)` for the seven steps that create or seal. The
sequence it performs:

```bash
sudo -n ksp-op setup --passphrase-file "$PASS"      # creates the deployment
sudo -n ksp-op setup --passphrase-file "$PASS"      # must report "skipped (already done)"
ksp-op status                                        # must exit 0
ksp-op reset --yes --dry-run                         # may
sudo -n ksp-op reset --yes                           # removes it
```

The passphrase goes in a file at mode `0600` and reaches the process on **stdin**.
There is no `--passphrase-file`: measured, the binary refuses it with
`unknown option '--passphrase-file': the options are --vault, --admin-account,
--dry-run, --yes, --purge-account`. Never argv: argv is visible in `ps`.

The assertion that matters most is the second `setup`. A first run that reports
`ok` for every step says nothing about idempotence; a second run that reports
`skipped (already done)` does. Every step in `plan.rs` carries a `SkipWhen`, and
this is the check that they hold.

## 4. Running it in a guest

```bash
scripts/ksp-macos-vm.sh provision          # tart or lume, plus one sudoers line
scripts/ksp-macos-vm.sh copy-in            # git archive HEAD -> guest
scripts/ksp-macos-vm.sh exec bash -lc \
  'cd /Users/ci/src/keyspout && ./scripts/ksp-op-walkthrough.sh --apply'
scripts/ksp-macos-vm.sh destroy            # throws the guest away
```

`copy-in` extracts `git archive HEAD`, never the working copy. A half-finished
edit produces a build failure that reads as a test failure, and the run is meant
to be reproducible from a commit.

The tree lands on the guest's own disk, never on a share. Measured 2026-11-27:
`chown` on a virtiofs share returns 0 and the reported owner does not change, and
`ksp-op` verifies ownership after `chown -R` — so a run against a share fails a
check that is correct.

## 5. What this walkthrough found

Four defects, all found by asserting on real output rather than on what the code
was expected to do. **All four are fixed**, each with a test that fails without the
change.

| Defect | What it was | Test |
| --- | --- | --- |
| **D8** | `setup` ignored `KSP_HOME` while `home` honoured it | `every_command_reads_ksp_home_the_same_way`, asserting on both commands at once |
| **D9** | `setup` read the passphrase twice, so a pipe could never satisfy step 8 | the walkthrough's `setup exits 0 from a redirected stdin` |
| **D10** | steps 7 and 10 tested paths nothing writes, so a second run refused | `a_second_run_mutates_nothing`, proven by mutation |
| — | `invoking_user` read `USER`, which `sudo` sets to `root`, so an elevated `setup` bound root | the walkthrough's `status after setup` |

D10's entry is in [`known-defects.md`](known-defects.md#d10--ksp-op-setup-was-not-idempotent-steps-7-and-10-tested-paths-nothing-writes).
Its most useful lesson: **the fixture wrote the paths the predicates looked for**,
so the test agreed with the defect. A fixture built from what the code searches
for proves the code agrees with itself.

**D8 — `setup` ignores `KSP_HOME`, which `home` honours.** Measured: `ksp-op
home` reports `/tmp/ksp-op-probe` from the variable; `setup --dry-run` plans into
`/Users/keyspout/.ksp`. `plan.rs`'s own comment says the variable "still wins
when it is set". For three of five subcommands it does not. Recorded in
[`known-defects.md`](known-defects.md#d8--ksp-op-setup-ignores-ksp_home-which-its-own-home-subcommand-honours).

**`status` needs passwordless sudo to the admin account.** Not a defect — it is
what the command is for — but it is the reason the read-only half cannot assert
`status` exits 0. A reader who expects a read-only `status` to be reachable
without privilege will spend time on it.

**`setup` refuses when the administrator account is absent, and `KSP_HOME` does
not help.** That is D8, reproduced in the guest on a second platform: `ksp-op
home` reports `KSP_HOME`, while `setup --dry-run` ignores it and derives the home
from the account. The read-only half now names an account that exists, which is
why it passes on a fresh guest.

## 6. What this document does not claim

**Nothing about Linux.** The privileged half exercises `sysadminctl`, `dscl` and
`launchctl`. The Linux path in the same file is different code, and the evidence
for it is `ksp:principals` under `scripts/ksp-gate.sh`, not this walkthrough.

**That a green run means the deployment is secure.** The walkthrough asserts that
the commands completed and that a second run was a no-op. Separation between the
two accounts is measured by the boundary suite, on a filesystem where `chown`
takes effect, and by nothing here.
