# Known defects

Defects in the product, recorded so a later agent can fix them without
re-deriving the investigation. Each entry states what is broken, how it was
observed, what it costs, what a fix has to satisfy, and whether it is open or
fixed.

This file is a work list, not a design document. The authority on what the
product *should* do is [`keyspout-design-spec.md`](keyspout-design-spec.md); an
entry here that contradicts the spec is a bug in this file.

**Status: current as of 2026-11-25, after feature 015 merged.**

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
`QUICKSTART.md` never passes `--home`, and the two suites that touch the
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

## Reporting a new defect

Add an entry here with the five parts above: what happens, what it costs, what a
fix has to satisfy, how it was found, and whether it is open or fixed. A defect
without a "what a fix has to satisfy" is a complaint, and the next agent has to
start the investigation again.
