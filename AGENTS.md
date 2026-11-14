# Contributing to Keyspout

Read this before your first change. It covers the build, the test gate, and the
rules that are not stylistic — the design decisions that cost something real and
must not be quietly reversed.

The authoritative design is [`docs/keyspout-design-spec.md`](docs/keyspout-design-spec.md).
**That document wins over anything you infer from the code.** If the code and the
spec disagree about what *should* happen, that is a design change and it needs
agreement in an issue before you write it. A status marker in the spec is not
that agreement.

---

## 1. Build

```bash
cargo build -p ksp-cli
./target/release/ksp version
```

`rust-toolchain.toml` pins the toolchain. `Cargo.toml` sets `resolver = "3"` and
`edition = "2024"`, so an older `cargo` fails before it compiles anything.

**macOS and Linux both build.** The Linux-only adapters (`landlock`,
`memfd_secret`, `sealed_memfd`) are target-gated. macOS enforces no path
confinement and its memory barrier is `mlock`, reported as `weakened` — never as
`memfd_secret`. Every run discloses which one it got.

[`DEVELOPMENT.md`](DEVELOPMENT.md) covers the VM, the backend services (Valkey,
RustFS, Garage), and the places where an assumed API differs from the real one.

---

## 2. Test

```bash
scripts/ksp-gate.sh host < /dev/null   # fmt, clippy, audit, the unprivileged suite
scripts/ksp-gate.sh                    # both halves; re-executes into the Linux VM
```

Two things about that script are deliberate and should not be "simplified":

- **It is one script, not four commands.** The obvious four-command list can
  never be green here, and a gate that is permanently red teaches contributors
  to ignore it. `cargo test --workspace` fails on
  `crates/ksp-cli/tests/principals.rs`, which needs two UNIX accounts and
  refuses to run without root *on purpose*. `cargo test` stops at the first
  failing binary, so that one by-design failure would skip every target after
  it.
- **Redirect stdin.** `bash scripts/ksp-gate.sh < /dev/null`. One test reads
  stdin; with stdin left as an open pipe the suite blocks for thirty minutes
  instead of failing.

Never call the suite green from a fail-fast run. Never run the whole suite as
`root` — root bypasses `umask`, `0600` modes and `CAP_IPC_LOCK`, so the tests
that assert those properties fail as root.

**A test exists that would fail without your change, and it fails for the right
reason.** Prove it discriminates: break the code the test covers and confirm the
test goes red. A test that passes both before and after the change tests nothing.

---

## 3. Rules that are not stylistic

The design reached these by argument. Most of them cost something real, and each
one is a place where the obvious implementation is wrong.

### Deletion is best effort, never a guarantee

Use `NativeExpiry` for configured logical expiry and
`Scheduled { declared_interval }` for configured cleanup cadence.
`D >= 2 × declared_interval` is conservative admission policy, not proof of a
sweep or a maximum lag. Do not describe deletion as erasure, and do not claim a
deletion time.

### A missing mechanism is `None`

`file` is `None`. Valkey needs acknowledged durability and configuration gates.
Unversioned S3 needs configured cleanup and a declared cadence. A known mismatch
fails admission. Status discloses unknown lag and retention.

### Hiding is not erasing, and a probe cannot prove erasure

Versioned S3, soft-delete configurations and B2 hiding remain `None`. A delete
marker is not an erasure.

### Seal every saved or transferred delivery artifact

Independent agent Ed25519 and X25519 pairs. The user verifies a fingerprint
binding identity, both public keys and key IDs. No implicit key conversion, no
raw `sk` in tokens, no optional sealing. Proof of possession authenticates a
compliant invocation; it is not a decryption policy.

### Arm durably before token publication

There is no distributed atomic output transaction. Publish no token while arming
is uncertain. Reconcile with idempotent identity.

### Attribute deletion honestly

An intent contains no keys and is not a tombstone. Prefer authorized per-version
actor reports after a delete acknowledgement. Native absence without a report is
missing or unconfirmed. An observer records `observed_at`, not an invented
deletion time. Retry reports without resurrecting the record.

### Consume is not exactly once

Retrieve, decrypt, hand to the child, delete, report. Only subsequent fresh
fetches are prevented after removal, absent restoration or replay. Concurrent
reads and copies survive. There is no automatic remint.

### Rotation does not revoke old offline pairs

Rotation changes future minting and new trust state. Revoking the upstream
credential is a separate action.

### Never `eval()`, and never shell-interpolate a path

Validate inputs with a schema. Pass non-secret runtime values through `env`.
Never return a raw `err.stack` or `err.message` in a response body.

### No plaintext secret in argv, logs or environment

A deliberate child `--env` delivery is an output exception. Never audit raw
tokens or successful proof-of-possession material. Shamir restores a sealed
bundle, not a lost phrase. The unseal key is symmetric.

### Public upstream credentials go through a resolver

Never a string literal.

### Backend admission is evidence-based

SSHFS, DNS and static HTTP are refused, each for a specific measured reason:
SSHFS has no `.lock` op, writes asynchronously by default and cannot rename
atomically; a DNS TTL is not a deadline and AXFR can dump the zone; static HTTP
has no `put`. Do not re-admit one without a mechanism that addresses the
specific reason it was refused.

### Enforcement beats convention

A level tree is real only when something enforces it — kernel permissions behind
per-agent accounts on `sftp`, or Landlock in-process on `file`. Code that merely
*named* the levels would enforce nothing, and a test that asserts a client-side
check proves nothing about containment.

Landlock confines only the opted-in process tree; sanitize inherited descriptors.
It does not confine same-UID outsiders or remote keys. Warn if optional file
confinement is unavailable; refuse required confinement.

### Confinement is not authentication

Landlock restricts *paths*; only a signature establishes *which key* is speaking.
Both are required and neither substitutes for the other.

---

## 4. Traps that have already cost time

Each of these shipped or nearly shipped a bug.

- **A mode that crosses an account boundary is set by `fchmod` or
  `set_permissions`, never by `open(2)`'s `mode`.** Both are masked by the
  caller's `umask`.
- **A signed artifact must name the key that signed it.** Changing who signs
  means grepping every `issuer_key_id` and `signer_key_id`.
- **A directory is a capability, not just a level.** Creating `agent-<id>/`
  beside `user/` needs write on the parent, not on `user/`.
- **A directory `fsync` needs read permission.** A write-only journal cannot
  acknowledge durability.
- **A `list(prefix)` must descend both ways** — above the prefix to reach it, and
  below it when the prefix names a directory.
- **`cfg(target_os = "darwin")` is never true.** rustc sets
  `target_os = "macos"`, so a Darwin branch written the other way compiles out
  silently.
- **Applying a confinement ruleset confines the *calling* process,
  irreversibly.** A refusal is decided after the restriction is in force, so
  `establish()` returning `Err` does not mean nothing happened. A test that
  needs the kernel's answer re-executes a throwaway child.
- **Never byte-scan a signed or hashed artifact.** A random signature contains
  `/` about one time in five, so a scan for a path fails at random.
- **A test that compares a value against another value the same expression
  produced cannot fail.** Take the expected value from the code that produces
  it.
- **A fixture already in canonical order cannot prove order.** Give the wrong
  answer a different shape than the right one.
- **A fixture that supplies a precondition hides the code that produces it.** If
  a command's job is to create X, at least one test must start without X.
- **A surface that reports a measurement must also report the policy behind
  it**, or the label is read as the policy.
- **A hint appended to an error must name a command that can act on that
  state.**
- **A parser's `Display` is a debugging aid, not a user-facing message.** A TOML
  error renders the offending source line, which may be a passphrase.

---

## 5. Commits

Conventional Commits:

```
feat(seal): add HPKE envelope with low-order-point rejection
fix(authz): reject token bound to a sibling agent level
docs: correct the admission rule for versioned buckets
```

Branch prefixes: `feat/`, `fix/`, `refactor/`, `docs/`, `test/`, `chore/`.
Merge target is `main`.

Before you commit:

- The gate passes, and you can say which parts you ran.
- `git status` shows no secrets, no `.env`, no vault state, no key files.
- The spec's status markers still match the tree. If your change moves one,
  update it in the same commit. A marker is a claim about the merged tree, and a
  stale marker tells a reader a control exists when it does not.

---

## 6. Design vocabulary

Source comments and the context files use a few shorthand labels. They are
defined here so a reader does not have to guess.

**`S1`–`S6`** name the six subsystems, one per context in
[`CONTEXT-MAP.md`](CONTEXT-MAP.md):

| Label | Subsystem | Crate |
|---|---|---|
| `S1` | Record Cryptography and Version Integrity | `ksp-record` |
| `S2` | Identity, Sealed Delivery and Policy Verification | `ksp-identity` |
| `S3` | Backend Admission and Durable Arming | `ksp-backend` |
| `S4` | Deletion Evidence and Consume Outcome | `ksp-deletion` |
| `S5` | Host Confinement and Key Material Posture | `ksp-posture` |
| `S6` | Durable Key Lifecycle | `ksp-key-lifecycle` |

`S3` also names the Amazon S3 storage service. Where the meaning matters, the
comment says which — `S3's arm record` is the subsystem, `an S3 bucket` is the
service.

**`Misfit <letter>`** names a specific failure mode the design has to survive.
Each use states the failure in the same sentence, because the letters are
scoped per design document and do not carry across all of them. Read the
sentence, not the letter.

---

## 7. Reporting a security issue

Do not open a public issue for a vulnerability. Email the maintainer directly
and allow time for a fix before disclosure.
