# Known defects

Open defects in the product, recorded so a later agent can fix them without
re-deriving the investigation. Each entry states what is broken, how it was
observed, what it costs, and what a fix has to satisfy.

This file is a work list, not a design document. The authority on what the
product *should* do is [`keyspout-design-spec.md`](keyspout-design-spec.md); an
entry here that contradicts the spec is a bug in this file.

**Status: current as of `4822ee4`.** D1–D5 were recorded at the `1.0.0` release.
D6–D12 were found while writing the operator skills in `skills/` and are recorded
with a reproduction each.

Two of the twelve are fixed (D11, D12) and are kept because the shape recurs: a
surface that answers plausibly and wrongly. The open ones are D1–D10. None is a
silent data-loss or a key-disclosure bug. D6 is the most destructive — it revokes
an authorisation without saying so — and D8 is the most misleading, because it
reports success for a record that can never admit a lease.

---

## D1 — `secret share` cannot mint on a deployment with no bound account

**Severity:** functional. The command refuses.
**Status:** fixed for the bound-account path in `1e13c47`; this entry records the
remaining case.

### What happens

A deployment provisioned by `admin init` and never bound to a UNIX account with
`admin user add --unix-user` writes its issuance ledger as whoever runs the
command. That works. A deployment bound to an account works too, since `1e13c47`.

The gap is a deployment where the ledger was created by one account and a
*different* account then runs `secret share` without a binding. The ledger is
`0640` in the store's group, so the second account can read it and cannot append.
The refusal is

```
the mint was refused: the delivery was sealed but not recorded, so no token was
written: the issuance ledger at <root>/issuance.jsonl could not be used:
Permission denied (os error 13)
```

### Why it is not simply "make the file writable"

The ledger has three writers and they are not one account:

| Event | Written by | Command |
|---|---|---|
| `Issued` | the user principal | `secret share`, `token mint` |
| `TokenRevoked` | whoever holds the token record | `token revoke` |
| `GrantWithdrawn` | the admin | `admin revoke` |

`run` reads the file to decide whether a token may still be used. A
group-*writable* ledger would let any group member append a revocation or remove
one, which is a mint history that member can forge. `1e13c47` split the file in
two — `issuance.jsonl` for the principal, `withdrawals.jsonl` for the admin — so
each has one writer and `0640` is enough.

### What a fix has to satisfy

A third account that is not the deployment's user must not be able to append an
issuance. The honest options are:

1. **Refuse earlier and say so.** `secret share` checks that the caller owns
   `issuance.jsonl` (or is the bound account) before it seals anything, and
   refuses with a sentence that names `admin user add --unix-user`. This is the
   cheap fix: it turns a permission error into an instruction, and it changes no
   mode.
2. **Per-principal ledgers under a shared root.** `run` then reads every
   principal's file. This is a real format change and it needs the spec to say
   which principal a token belongs to, which it currently does not.

Option 1 is what the design vocabulary supports today. Option 2 is a design
change and needs agreement in an issue first.

### How it was found

`crates/ksp-cli/tests/principals.rs::two_accounts_complete_the_session_and_the_kernel_keeps_them_apart`
failed on the first CI run the gate ever did. It had been failing since
`cffdd55` (2026-10-25) and nobody saw it, because the gate had never run in CI.
That specific test now passes. The unbound third-account case is what remains.

---

## D2 — OSV-Scanner cannot build this workspace, so every finding has no reachability analysis

**Severity:** tooling. The vulnerability gate is stricter than intended, not
weaker.
**Status:** open. Documented in `SECURITY.md` §4.3.

### What happens

`osv-scanner --all-vulns` fails to build the tree:

```
error: lto can only be run for executables, cdylibs and static library outputs
error: could not compile `crc-fast` (lib)
failed to build cargo/rust project from source: ... exit status 101
```

The same `cargo build --workspace --all-targets --release` succeeds when run
directly, so the failure is in the scanner's own copy of the tree.

### What it costs

Every OSV finding on this repository arrives with `analysis: None`. Under the
gate's rule — no analysis entry means treated as reachable — every high-severity
finding fails the build. That is the conservative direction and it is why the
rule is not optional: a gate that required `called: true` would pass everything
on this tree forever and look green.

The cost is that reachability is inert. A finding in an uncalled code path still
fails the gate, so the gate cannot distinguish a real exposure from a vendored
path that no `ksp` binary reaches.

### What a fix has to satisfy

Either the scanner builds the tree, or the gate stops claiming reachability. Two
routes:

1. **Find why `crc-fast` fails only under the scanner.** The scanner copies the
   tree and builds it with its own environment. A `[profile.release] lto`
   setting that applies to a `lib` target is the likely cause, and `crc-fast` is
   a dependency rather than this workspace's code. Reproduce by building
   `crc-fast` alone with the same profile.
2. **Run the scanner against `Cargo.lock` only.** `osv-scanner --lockfile
   Cargo.lock` needs no build, so it produces findings with no analysis by
   design. That is honest and it is what the gate already assumes; it should be
   stated in the gate rather than implied by a build failure.

The reopen trigger is a fixed `crc-fast` or a scanner that can build the tree.

### Related

`SECURITY.md` §4.3 discloses the blind spot to users. The investigation that
produced this entry, including the scanner's own build failure and the two routes
below, is recorded in the release supply-chain hardening plan kept with the
project's internal planning documents.

---

## D3 — The reproducibility job has no known-bad case, so it proves nothing

**Severity:** tooling. A control that has never been seen to fail.
**Status:** open. Recorded as WP03 in the hardening plan.

### What happens

`.github/workflows/release.yml` has no `reproduce` job. The plan calls for one
that builds the same commit twice and compares the bytes. It was not written
because the failure it is meant to catch could not be reproduced: five attempts
at deliberately breaking reproducibility — a timestamp, a path, a build-script
read of the clock — all produced identical output.

### What it costs

`SOURCE_DATE_EPOCH` and the three `--remap-path-prefix` flags are in place and
measured (207 occurrences of the builder's home reduced to 0). What is missing is
a job that would *fail* if a later change reintroduced a nondeterministic input.
Without it, the flags are a claim rather than a control.

### What a fix has to satisfy

A test that fails when reproducibility breaks. The rule from this repository's
own vocabulary applies: a gate that has never been seen to fail is not a gate.
The job must be proven by breaking the build on purpose and watching the job go
red, before it is trusted green.

---

## D4 — Release immutability is not available through the API

**Severity:** tooling. A hardening item that cannot be delivered as specified.
**Status:** open. Recorded as WP07 in the hardening plan.

### What happens

The hardening plan asks for immutable releases — a published tag and its assets
that cannot be moved or replaced. The GitHub REST API exposes no
`immutable_releases` field on a repository, so the setting cannot be read or
enforced from CI.

### What it costs

A published release can be edited or its assets replaced by anyone with write
access to the repository. The `release` environment with a required reviewer
(`bruj0`, `can_admins_bypass: false`) gates *publication*; it does not make the
published artifact immutable afterwards.

### What a fix has to satisfy

Either the setting becomes available and the workflow asserts it, or `SECURITY.md`
stops implying the release is immutable. It currently does not claim
immutability, which is the honest position — but the plan lists it as delivered,
which is not.

---

## D5 — A sync gap reached CI, and nothing checks for one

**Severity:** process. It produced a red CI run that looked like a product bug.
**Status:** open. Observed on `1.0.0`.

### What happens

`crates/ksp-cli/src/app.rs` in the public tree was missing `d9d53c7`, the commit
that made `--json` on `secret get` emit a document. The test
`wired_surface::json_on_get_emits_a_document_and_still_honours_revoke` failed on
the runner and passed locally, because the local tree had the fix and the public
tree did not.

The failure cost an investigation that started from the product code, because a
missing file looks exactly like a broken one.

### What it costs

A release tag can be cut from a public tree that does not match upstream. On
`1.0.0` it was caught by CI. It would not have been caught by anything else.

### What a fix has to satisfy

The control already exists: the release procedure requires
`python3.14 scripts/public/sync.py --check` to exit 0 before the tag. The defect
is that the check was not run on this release, so the gap reached CI.

Two things would make it hard to skip again:

1. **Run it from the workflow, not only from the skill.** A `sync-check` job
   before `gate` that fails when the public tree is stale turns the process rule
   into an enforced one. It needs the upstream tree, which the public workflow
   does not have, so this is only possible if the check moves into the upstream
   repository's own CI.
2. **Make the failure legible.** The symptom was a test failing on code that was
   correct upstream, which reads as a product bug. A preflight that prints the
   stale file list before the tag would have named `app.rs` immediately.

Until then, the rule is the skill's step 3, and this entry exists so a reader
knows what happens when it is skipped.

---

## D6 — `admin policy` replaces the whole grant set, so a second grant silently revokes the first

**Severity:** functional, and the most destructive defect in this file. It revokes
an authorisation without saying so.
**Status:** open. The read-back that makes it visible shipped in `526c524`; the
silent replacement is unchanged.

### What happens

`ksp admin policy` builds a fresh policy from the flags on that one invocation and
writes it over the previous one. There is no merge and no diff. A grant to a
second agent therefore removes the first agent's grant, and the command reports
success:

```
$ ksp admin policy --agent <A1> --secret s1
admin policy: ok
$ ksp admin policy --show | grep -E '^(secret|agent):'
secret:      s1
agent:       edf92e72-c9f1-4493-99ee-f9989024d4ba
$ ksp admin policy --agent <A2> --secret s1
admin policy: ok
$ ksp admin policy --show | grep -E '^(secret|agent):'
secret:      s1
agent:       a98c3abb-40c2-48aa-8b10-8746565c3758      # A1 is gone
```

The help text says `--agent <AGENTS>` "Grant a delivery to this agent. Repeatable".
Repeatable is true within one invocation and false across invocations, and nothing
in the output distinguishes the two.

### How to reproduce

```bash
export KSP_HOME=$(mktemp -d)
ksp init && ksp admin init --vault vault-1 --user alice
printf 'a long enough password' > "$KSP_HOME/pw" && chmod 600 "$KSP_HOME/pw"
ksp admin user add < "$KSP_HOME/pw"

A1=$(ksp agent enroll --agent lap   --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["identity"].split(":")[1])')
A2=$(ksp agent enroll --agent phone --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["identity"].split(":")[1])')

ksp admin policy --agent "$A1" --secret s1
ksp admin policy --agent "$A2" --secret s1
ksp admin policy --show        # A1 is no longer listed
```

The consequence is one step further out: `ksp secret share` for A1 now refuses
with exit `2` and `secret s1 is not shareable under this policy`, which reads as a
policy decision rather than as the grant that was overwritten two commands ago.

### What it costs

An operator or an agent that grants access to a second agent loses the first one's
access, and the loss is invisible unless the policy is read back. The failure
surfaces later, on the first agent's next share, at which point the cause is two
steps behind the symptom. Every skill that re-signs the policy has to read it
first, which is a rule the tool should enforce rather than a rule prose has to
remember.

### What a fix has to satisfy

The write must not be able to discard a grant the caller did not name. Three
routes, in increasing cost:

1. **Refuse a narrowing write without an explicit flag.** If the new policy drops
   a grant the old one held, refuse and name the grants that would be lost, unless
   `--replace` is passed. This turns the silent revocation into a decision and
   needs no format change.
2. **Merge by default, with `--replace` for the current behaviour.** `--agent` and
   `--secret` add to what is there; removing a grant becomes `admin revoke`, which
   already exists and already records the withdrawal. This is the shape the
   vocabulary supports: `revoke` is the verb for taking a grant away, and a write
   that also revokes is two operations behind one flag.
3. **Make the write print the diff.** Even with 1 or 2, the command should say
   which grants it added and which it removed, so a caller reading stdout learns
   what changed without a second command.

Option 2 matches the existing command set best. Whichever is chosen, the help text
must stop saying "repeatable" without saying what a re-sign does to grants the
invocation does not name.

### How it was found

While writing the operator skills. `keyspout-agents` needs to grant an agent
access, and the first draft granted a second agent and then could not explain why
the first agent's share was refused. The read-back (`ksp admin policy --show`,
added in `526c524`) was written to make the current grants visible and is what
turned the symptom into a reproduction.

---

## D7 — A missing password prints only an exit code on `get`, `rm` and `share`

**Severity:** functional. The refusal carries no sentence, so a caller cannot tell
a missing password from a policy decision.
**Status:** open.

### What happens

When the password cannot be read, `password()` returns an exit code and the
command arm does `Err(code) => return Outcome::Failed(code)`. Nothing is printed.
The code is `2`, which the exit-code table defines as "policy denied the
operation":

```
$ ksp secret get s1 < /dev/null
ksp: refused (exit 2: policy denied the operation)
$ ksp secret rm s1 < /dev/null
ksp: refused (exit 2: policy denied the operation)
$ ksp secret share s1 --agent lap --name n1 --out t.ksp < /dev/null
ksp: refused (exit 2: policy denied the operation)
```

The cause is `AdminError::NoPassword`, which maps to `POLICY_DENIAL` in
`crates/ksp-cli/src/admin.rs`. An empty or absent password is not a policy
decision, and the sentence the type carries — "the password could not be read" —
is discarded before it reaches the caller.

`ksp secret set` does not have this defect. It prints a message that names the
accepted form and exits `13`:

```
$ printf 'v' | ksp secret set s9 --name n9 < /dev/null
ksp: the value could not be read from the input: the value comes from stdin, and the password comes from --passphrase-file when stdin carries a value
ksp: refused (exit 13: the invocation was malformed; the message names the accepted form)
```

That is the shape the other three should have.

### How to reproduce

```bash
export KSP_HOME=$(mktemp -d)
ksp init && ksp admin init --vault vault-1 --user alice
printf 'a long enough password' > "$KSP_HOME/pw" && chmod 600 "$KSP_HOME/pw"
ksp admin user add < "$KSP_HOME/pw"
printf 'v1' | ksp secret set s1 --name n1 --passphrase-file "$KSP_HOME/pw"

ksp secret get s1 < /dev/null      # exit 2, no sentence
ksp secret rm  s1 < /dev/null      # exit 2, no sentence
```

### What it costs

An agent driving the tool sees exit `2` and concludes the policy refused the
operation. It then reports a policy problem to the operator, or tries to widen the
policy, when the actual fix is to supply `--passphrase-file`. This is the same
class of defect feature 010 removed from `secret set` and `admin put`: a refusal
that returns only a code tells the caller nothing it can act on.

The exit code also collides. `2` is a real policy denial elsewhere in the tool, so
a caller cannot use the code to separate "the password was missing" from "the
policy said no". `6` is the code the rest of the tool uses for missing key
material, and `read_password_from_stdin` already returns `6` when an open pipe
never delivers — so the same condition reports `6` or `2` depending on which
branch inside the reader caught it.

### What a fix has to satisfy

Every command that reads a password prints the typed sentence before returning,
and the code distinguishes a missing credential from a policy decision. The
narrowest change is in the three command arms: replace
`Err(code) => return Outcome::Failed(code)` with a branch that calls
`emitter.refusal(...)` with the message the error carries, as `secret set` already
does. `AdminError::NoPassword` should then map to `MISSING_KEY`, matching
`read_password_from_stdin`'s own fallback and the rest of the tool. A test per
command asserting both the code and the sentence is what proves it.

### How it was found

While writing `keyspout-secrets` and `keyspout-audit`. Both skills tell an agent to
supply `--passphrase-file`, and a check of what happens when it does not produced
`exit 2: policy denied the operation` with no reason. `secret set` was tested at
the same time and did not have the defect, which is what identified the three
command arms as the cause rather than the password reader.

---

## D8 — A sweep scope deeper than the level the sweep owns is accepted and never admits

**Severity:** functional. `arm-sweep` reports success and the capability never
moves.
**Status:** open, and it is a design question rather than a coding error. The
onboarding plan records it as a known behaviour and leaves it unfixed by decision;
this entry adds the reproduction and the measured output.

### What happens

`arm-sweep` accepts a scope that names a record beneath the agent level —
`p/<vault>/<uuid>/agent-*/db-password` — records it, and exits `0`. The sweep that
runs under that scope genuinely does not prove the cadence admission needs, so the
capability stays `None` and every lease is still refused.

The output is actively misleading in three places:

```
$ ksp backend arm-sweep --interval 1h \
    --scope "p/vault-1/$U/agent-*/db-password" \
    --credential ksp-sweep --grant "delete:p/vault-1/$U/agent-*/db-password" \
    --identifier ksp-sweep.service --kind systemd
arming: backend=file  kind=systemd  …  scope=p/vault-1/…/agent-*/db-password  …
note: this records a schedule; it is configuration until a signed sweep proof confirms a run.
exit=0

$ ksp secret gc
capability=None  selected=0  removed=0  …
this backend has no deadline mechanism, so no sweep can remove anything here: no armed record was read and no version was removed.

$ ksp status --json | jq .backend.next_action
"a run completed but not under a recorded schedule, so it proves no cadence; record a schedule and let the job run under it"
```

1. `arm-sweep` exits `0`, so a script sees success.
2. `gc` says "no armed record was read" while an armed record exists.
3. `next_action` advises recording a schedule that is already recorded, which sends
   the operator to a command that changes nothing.

### How to reproduce

```bash
export KSP_HOME=$(mktemp -d)
ksp init
U=$(ksp admin init --vault vault-1 --user alice --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["user"])')
printf 'a long enough password' > "$KSP_HOME/pw" && chmod 600 "$KSP_HOME/pw"
ksp admin user add < "$KSP_HOME/pw"

# The deeper scope: a record beneath agent-*, not the level itself.
ksp backend arm-sweep --interval 1h \
  --scope "p/vault-1/$U/agent-*/db-password" \
  --credential ksp-sweep \
  --grant "delete:p/vault-1/$U/agent-*/db-password" \
  --identifier ksp-sweep.service --kind systemd
ksp secret gc
ksp status --json | jq -r '.backend.capability, .backend.next_action'
```

Compare with the scope the sweep owns, `p/vault-1/$U/agent-*`, which admits a
lease after one `gc`.

### What it costs

An operator who narrows the scope to be careful — the conservative instinct — gets
a host that refuses every share and a `next_action` that repeats the step already
done. The refusal that follows (`exit 7` on `secret share`) names the admission
floor, not the scope, so the scope is the last thing a reader suspects.

### What a fix has to satisfy

Either the scope is refused at arm time, or the record is accepted and the
capability explains why it does not admit. The design question is that narrowing a
scope is a legitimate operator right: a sweep that only reaches one record is a
real thing to want. What must not happen is a success report for a record that can
never admit.

The cheapest honest fix is at `arm-sweep`: when the scope is deeper than the level
the sweep owns, either refuse it with a sentence naming the level, or accept it and
say in the same output that no lease will be admitted under it and why. The
`next_action` for this state must stop advising a command that has already run —
that is a separate defect in the cause mapping and is worth fixing whatever
happens to the scope.

### How it was found

While writing `keyspout-backends`. The skill has to tell an agent which scope to
use, and running the deeper scope to see what happened produced a host that
reported success and admitted nothing. The onboarding plan recorded the behaviour
and left it unfixed by decision; this entry adds the reproduction and the three
misleading outputs.

---

## D9 — Nothing enumerates enrolled agents

**Severity:** functional gap. A report cannot list the agents a host holds.
**Status:** open.

### What happens

There is no `ksp agent list`. The subcommand does not exist, and clap reports it as
a usage error:

```
$ ksp agent list
error: unrecognized subcommand 'list'
exit=2
```

`ksp agent pubkey` needs the principal UUID, and a display name is refused with
exit `6` and no sentence:

```
$ ksp agent pubkey --agent lap
ksp: refused (exit 6: key material is missing or unreadable)
```

The enrolment file exists for every agent — `enrolments/<uuid>.cbor`, which carries
the `display_name` — so the data is there and no command reads it as a list.

### How to reproduce

```bash
export KSP_HOME=$(mktemp -d)
ksp init && ksp admin init --vault vault-1 --user alice
printf 'a long enough password' > "$KSP_HOME/pw" && chmod 600 "$KSP_HOME/pw"
ksp admin user add < "$KSP_HOME/pw"
ksp agent enroll --agent lap
ksp agent enroll --agent phone

ksp agent list                    # unrecognized subcommand
ksp agent pubkey --agent lap      # exit 6: a display name is not an identity
ls "$KSP_HOME/enrolments/"        # two files, named by UUID, with the names inside
```

### What it costs

A status report cannot answer "which agents does this host hold" without reading
the enrolment directory by hand and decoding CBOR. `keyspout-status` reports agent
counts from that directory, which is a workaround a skill should not need. It also
makes the grant read-back harder to use: `admin policy --show` lists agent UUIDs,
and without a list there is nothing to join them to a display name.

### What a fix has to satisfy

A command that enumerates the enrolments this host holds, naming each agent's UUID,
display name and both key IDs, with `--json`. It reads the directory
`agent enroll` already writes, so it adds a read path and no format. It must not
print a private half. A display name is metadata and may be absent, so the output
has to be usable when it is.

### How it was found

While writing `keyspout-status` and `keyspout-agents`. Both need to name the agents
a host holds, and both had to fall back to counting files under `enrolments/`. The
onboarding plan records the absence and calls it not blocking; this entry records
what it costs a skill.

---

## D10 — `status` exits `0` on a host with nothing set up

**Severity:** design. Not a bug, and recorded here because every agent gets it
wrong once.
**Status:** open by decision. This is the disclosure behaviour the spec asks for.

### What happens

`ksp status` is a disclosure, not a health check, so it exits `0` on an empty
directory and on a fully provisioned host alike:

```
$ export KSP_HOME=$(mktemp -d) && ksp init
$ ksp status >/dev/null; echo $?
0
```

An agent that branches on the exit code concludes the host is healthy. It is not:
the same run reports `capability: None` and `binding: none`.

### How to reproduce

```bash
export KSP_HOME=$(mktemp -d)
ksp init
ksp status >/dev/null; echo "exit=$?"          # 0
ksp status --json | jq -r '.backend.capability, .binding.state'   # None, none
```

### What it costs

Nothing, if the caller reads the JSON. A wrong conclusion, if the caller reads the
exit code. Every skill in `skills/` therefore decides from `backend.capability` and
`binding.state` rather than from the code, and each one says so explicitly.

### What a fix has to satisfy

Nothing should change: `status` refusing on a host it was asked to describe is
worse than `status` describing it. What a fix would have to satisfy is the other
direction — a caller that needs a verdict wants a different command. That is
`ksp doctor` in the plan's §5.5, deferred until three skills repeat the same state
derivation. Until then this entry exists so a reader does not read the `0` as a
health signal.

### How it was found

While writing `keyspout-status`. The skill's first draft branched on the exit code
and reported a healthy host with no deployment.

---

## D11 — `admin list` exited `1` on a host with no deployment, where every other surface exited `6`

**Severity:** functional. An agent could not tell a broken tool from an unconfigured
host.
**Status:** fixed in `6a3070c`. Recorded because the shape recurs.

### What happened

On a host with no deployment, `ksp admin list` exited `1` — "unexpected internal
failure" — while `secret ls`, `agent pubkey` and `audit verify` all exited `6` for
the identical state:

```
$ export KSP_HOME=$(mktemp -d) && ksp init
$ ksp admin list
ksp: the deployment is not readable
ksp: refused (exit 1: unexpected internal failure)
$ ksp secret ls
ksp: refused (exit 6: key material is missing or unreadable)
```

Three surfaces agreed and one did not, and the one that disagreed is the one a
status report calls first.

### How to reproduce the original

```bash
export KSP_HOME=$(mktemp -d)
ksp init
for c in "secret ls" "admin list" "agent pubkey --agent x" "audit verify"; do
  ksp ${=c} >/dev/null 2>&1; echo "$c -> $?"
done
```

Before the fix `admin list` returned `1` and the rest returned `6`. After it, all
four return `6`.

### What it cost

`1` tells an agent the tool broke and there is nothing to do; `6` tells it the host
has no deployment and setup is the next step. An agent reading `1` reports a bug to
the operator instead of offering to run the quickstart.

### What the fix did

`AdminError::Pin` was grouped with the write failures in `exit_code`. The fix
splits `PinError::Absent` out and maps it to `MISSING_KEY`, leaving the remaining
`PinError` variants — a corrupt or mismatched pin — on `INTERNAL`, because
re-running setup does not fix a file that is there and wrong. The test
`agent_contract::an_unprovisioned_host_reports_missing_key_material_on_every_surface`
asserts that no surface returns `1` and that `admin list` returns `6`.

### How it was found

While writing `keyspout-status`, whose first command is `ksp admin list --json` to
count what exists. On a fresh host it returned `1` and the skill had no way to
report "not set up yet" that was distinguishable from "the tool is broken".

---

## D12 — `--json` on `secret get` was accepted and ignored

**Severity:** functional. A caller that asked for JSON got a tab-separated line.
**Status:** fixed in `d9d53c7`. Recorded because the shape recurs.

### What happened

`ksp --json secret get` printed the human line and exited `0`, whatever `--json`
said:

```
$ ksp --json secret get s1 --passphrase-file "$KSP_HOME/pw"
n1      ••••
```

An agent that passed `--json` and parsed stdout got `expected value at line 1
column 1`. This is the same silent-plausible-output failure feature 010 removed from
the listing commands, on a command that was not in that feature's scope.

### How to reproduce the original

```bash
export KSP_HOME=$(mktemp -d)
ksp init && ksp admin init --vault vault-1 --user alice
printf 'a long enough password' > "$KSP_HOME/pw" && chmod 600 "$KSP_HOME/pw"
ksp admin user add < "$KSP_HOME/pw"
printf 'v1' | ksp secret set s1 --name n1 --passphrase-file "$KSP_HOME/pw"

ksp --json secret get s1 --passphrase-file "$KSP_HOME/pw" | python3 -m json.tool
```

Before the fix that fails to parse. After it, the command emits one object:

```json
{"kind":"secret","name":"n1","record":"s1","revealed":false,"value":"••••","version":1}
```

and `--reveal` sets `revealed: true` and carries the value.

### What it cost

An agent that asked for machine-readable output got a line it could not parse, and
the failure looked like a malformed document rather than an ignored flag.

### What the fix did

The value still has no route into `Report`, and that invariant is deliberate:
`Report` is what the audit path renders, so a value with a route into it is a value
in the log. The document is built in the command arm that already holds the value
and written straight to stdout. `Emitter` gained `is_json()` so a command that
writes its own output can still honour the flag. The test
`wired_surface::json_on_get_emits_a_document_and_still_honours_reveal` asserts both
halves — the redacted document must not carry the value, and the revealed one must.

### How it was found

While writing `keyspout-secrets`, which tells an agent to read a secret back and
parse the result. The first draft used `--json` and got a tab-separated line.

---

## What is *not* a defect

Two things that look like defects and are the design:

- **`file` is `None` until a sweep proof exists.** `ksp secret share` and
  `ksp token mint` refuse with exit `7` until a schedule is armed *and* has run
  once. After that a lease is admitted at `2 ×` the proven interval. This is
  conservative admission policy, not a gap.
- **A Mac enforces no path confinement.** macOS runs, discloses
  `confinement: … none`, and the child runs unconfined. The barrier falls back to
  `mlock`, reported `weakened`. Linux is where the enforced path is proven.

---

## Reporting a new defect

Add an entry here with the five parts above: what happens, what it costs, what a
fix has to satisfy, how it was found, and whether it is open or fixed. A defect
without a "what a fix has to satisfy" is a complaint, and the next agent has to
start the investigation again.
