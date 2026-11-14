# Development environment

This document records the toolchain, the services and the platform facts that
Keyspout's implementation depends on, and how to bring them up. It is a
**development** document: it does not change the design, and it does not weaken
any rule in [`keyspout-design-spec.md`](docs/keyspout-design-spec.md).

**Read this before the first `cargo build`.**

---

## 0. What runs where

**macOS and Linux both build and both run the suite.** The Linux-only adapters
are gated by target in `crates/ksp-posture/Cargo.toml`, so the workspace
compiles on Darwin and the two mechanisms become an *adapter availability* fact
rather than a compiler error.

| Mechanism | Linux | macOS | Effect |
|---|---|---|---|
| `landlock` 0.4.7 | available (ABI V8 on the VM kernel) | not compiled | Path confinement is enforced on Linux, reported unenforced on macOS |
| `memfd_secret` | available (kernel >= 5.14) | not compiled | Strong memory barrier on Linux; `mlock` fallback on macOS, reported `weakened` |
| `PR_SET_DUMPABLE`, `mlock`, `MADV_DONTDUMP` | available | `mlock` only | Posture reporting differs per host |

Two consequences worth stating plainly:

- **A macOS run proves the suite, not the controls.** macOS enforces no path
  confinement and reaches a weaker memory barrier. Every run discloses which one
  it got, in its own output and in `ksp status`.
- **The Linux half needs a Linux host.** Five test targets assert a Linux
  mechanism or the two-account boundary. They are listed in `VM_TARGETS` in
  `scripts/ksp-gate.sh`, and a name whose test file is gone fails the gate
  rather than being skipped.

The reference build and test environment for the Linux half is a **colima VM**
with the repository mounted in. macOS remains a supported editing and build
host.

---

## 1. The default backend is `file`

**Nothing needs to be installed to use Keyspout.** `ksp` defaults to the local
directory store, and a missing backend selection file is the `file` backend
rather than an error — the default has to be the one that always works, or a
fresh host cannot even run `ksp backend test` to find out what it has.

The `file` backend is also the reference implementation of the storage
contract, and the natural negative case: it declares no lease mechanism, so
`ksp token mint` and `ksp secret share` refuse with exit `7`. That refusal is
the design, not a missing feature.

| Backend | Needs a service | Lease capability | Status |
|---|---|---|---|
| `file` | **no** | `None` (or `Scheduled` with a recorded schedule plus a fresh signed sweep proof) | Default, implemented |
| `valkey` / `redis` | a Valkey or Redis instance | `NativeExpiry`, subject to durability and configuration gates | Implemented |
| `s3` | an S3-compatible server | `Scheduled` only with configured cleanup and a declared cadence | Partial — not selectable from the CLI |

Choose the backend by writing `backend.cbor` in the Keyspout home. The CLI
reads it and falls back to `file` when it is absent.

---

## 2. Toolchain

Installed via rustup. The version is pinned by `rust-toolchain.toml`.

| Tool | Version |
|---|---|
| `rustc` / `cargo` | 1.99.1 |
| `rustfmt` | 1.10.0-stable |
| `clippy` | 0.1.99 |
| `cargo-audit` | 0.22.2 |

`Cargo.toml` sets `resolver = "3"` and `edition = "2024"`, so an older `cargo`
fails before it compiles anything.

```bash
cargo build -p ksp-cli
./target/release/ksp version
```

---

## 3. Optional services

Only the tests and the non-default backends need these. A `file`-backend
deployment needs none of them.

### 3.1 Valkey

Ubuntu's `valkey-server` 7.2.13, started with `systemctl enable --now
valkey-server`. `valkey-cli ping` -> `PONG`. Listens on
`redis://127.0.0.1:6379/0`.

Valkey is the only backend that declares `NativeExpiry`, so it is the only one
that accepts a short logical lease. Admission still requires acknowledged
durability and the configuration gates; a Valkey with persistence off is not
admitted for a lease.

### 3.2 S3-compatible servers (test-only)

The `ksp-backend:s3_store` test target needs a live S3 server. It is the only
thing in the suite that does, and it **fails identically on an unmodified tree
when the service is absent** — that is an environmental exception, not a code
defect.

Two servers are used, so the backend contract is not proven against a single
implementation:

| Service | Endpoint | Versioning |
|---|---|---|
| `ksp-rustfs` — [rustfs/rustfs](https://github.com/rustfs/rustfs) v1.0.3 | `http://127.0.0.1:9000` | on and off |
| `ksp-garage` — [Deuxfleurs Garage](https://garagehq.deuxfleurs.fr/) v2.1.0 | `http://127.0.0.1:3900` | off only |

RustFS is the primary because it is the only one here that supports **bucket
versioning**, which the design needs to cover both the versioned and the
non-versioned admission case. Garage has no versioning, so it cannot cover the
versioned case; it is kept as an independent second implementation.

Buckets:

| Bucket | Versioning | Admission outcome |
|---|---|---|
| `ksp-s3-unversioned` | off | `Scheduled { declared_interval }` if cleanup + cadence are configured |
| `ksp-s3-versioned` | **on** | `None` under the MVP safety policy |

Credentials are test-only, local and disposable. Both servers run as native
binaries under systemd rather than in Docker: MinIO was archived upstream and
its download URLs return `410 Gone`, so there is no maintained image to use.

> **MinIO is not an option.** `dl.min.io` returns 410 and `minio/minio` is no
> longer on Docker Hub.

---

## 4. The Linux VM (colima)

Only needed for the Linux half of the gate. Skip it if you are working on
portable code and running `scripts/ksp-gate.sh host`.

```bash
colima start --cpu 4 --memory 8 --disk 60 --vm-type=vz --mount-type=virtiofs
```

| Property | Value | Why |
|---|---|---|
| Guest OS | Ubuntu 24.04.4 LTS | matches the target platform |
| Guest kernel | **7.0.0-38-generic** | needed for Landlock **ABI V8** (`all_threads`) |
| Architecture | aarch64 | native, no emulation |
| RAM / CPU / Disk | 8 GiB / 4 / 60 GiB | AWS SDK + rustc link steps are memory-hungry |
| Mount | `virtiofs`, `~` -> `~` | the repo is visible to the VM at its macOS path |

### 4.1 Why the kernel was upgraded

Ubuntu 24.04 ships kernel 6.8, whose Landlock ABI is **V4**. Keyspout requires
`all_threads()`, which the kernel only accepts from **ABI V8** (Linux 6.10+).
On 6.8 the call fails with
`RestrictSelfFlags(NotSupported { flag: AllThreads, set: true })`.

The VM boots through UEFI/GRUB, so the guest kernel was switched with:

```bash
# inside the VM
apt-get install -y linux-image-generic-hwe-24.04
sed -i 's/^GRUB_DEFAULT=0/GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux 7.0.0-38-generic"/' /etc/default/grub
update-grub
```

**This is a guest-side change and does not affect the host.** After it, the
Landlock status reports `effective_abi: V8` and `all_threads: true`.

### 4.2 Guest toolchain

Rust 1.99.1 with `rustfmt` + `clippy`, plus `cargo-audit` 0.22.2, installed
with `cargo install --locked`. `build-essential`, `pkg-config`, `libssl-dev`,
`clang` and `cmake` are required for the C-transitive crates in the AWS SDK and
HPKE dependency tree.

The guest toolchain lives at `~/.cargo` in the VM; `source ~/.cargo/env` (or
`export PATH="$HOME/.cargo/bin:$PATH"`) before invoking `cargo` over
`colima ssh`.

### 4.3 Keep the checkout inside the mounted home

The `~` mount is `virtiofs`, and **only the home directory is visible to the
VM** — a checkout created under `/tmp` on the host is *not* visible in the VM,
because `/tmp` is not shared.

---

## 5. Running the gates

```bash
scripts/ksp-gate.sh host < /dev/null   # fmt, clippy, audit, the unprivileged suite
scripts/ksp-gate.sh                    # both halves; re-executes into the VM
scripts/ksp-gate.sh vm                 # the Linux half alone
```

The script is one gate split into two parts, not two gates. Every test file in
the workspace runs in exactly one part, and a target named in `VM_TARGETS`
whose file is gone is a gate failure, so the list cannot rot silently.

`scripts/ksp-vm.sh` runs a single command inside the VM:

```bash
scripts/ksp-vm.sh cargo test --workspace
scripts/ksp-vm.sh cargo fmt --check
scripts/ksp-vm.sh cargo clippy --all-targets -- -D warnings
scripts/ksp-vm.sh cargo audit
```

### 5.1 Two ways the gate hangs or dies without saying so

- **Redirect stdin.** `bash scripts/ksp-gate.sh < /dev/null`. One test reads
  stdin; with stdin left as an open pipe the suite blocks for thirty minutes
  instead of failing.
- **The VM disk fills.** It is 19 GiB and a debug build of the test binaries is
  several GiB. A full disk fails while *linking* with `No space left on device`,
  which names neither the disk nor the target directory. The gate sets
  `CARGO_INCREMENTAL=0` and uses two `/tmp` target directories; delete both
  between machines or after a large change.

---

## 6. Verified on this machine

| Check | Result |
|---|---|
| `rustc 1.99.1`, edition 2024, on host and in VM | yes |
| `cargo fmt --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test --workspace` (unprivileged) | passes except `ksp-backend:s3_store`, which needs RustFS |
| `cargo audit` | exit 0 — see §7.5 for the `aws-sdk-s3` feature trim |
| Landlock enforcement (VM) | `FullyEnforced`, `effective_abi: V8`, `all_threads: true` |
| `memfd_secret` (VM) | available; see §7.1 for the flag correction |
| `mlock` barrier (macOS) | available, reported `weakened` |
| HPKE typed KEM error | `HpkeRustCrypto::dh` returns `KemInvalidPublicKey` for a low-order point |
| Valkey `SET ... PX` | `redis` 1.7.1 `SetExpiry::PX(60_000)` round-trips; `TTL` reports 60 s |
| S3 put / get / delete | `aws-sdk-s3` against RustFS |
| S3 versioning | `ksp-s3-versioned` reports `Status: Enabled` |

---

## 7. Findings the implementation must absorb

These are not style notes. They are places where an assumed mechanism does not
match the real API or kernel. Each was confirmed by running the code, not by
reading it.

### 7.1 `memfd_secret` takes `O_CLOEXEC`, not `MFD_CLOEXEC`

`MFD_CLOEXEC` is `0x0001`, from `linux/memfd.h`, and is **not** a valid
`memfd_secret` flag. The kernel's mask is
`SECRETMEM_FLAGS_MASK | O_CLOEXEC` where `SECRETMEM_FLAGS_MASK` is `0x0`, so
the only accepted bit is **`O_CLOEXEC` (`0x80000`)**.

Measured on the VM (kernel 7.0):

| Call | Result |
|---|---|
| `memfd_secret(O_CLOEXEC /* 0x80000 */)` | `fd=3`, `FD_CLOEXEC` set — **correct** |
| `memfd_secret(MFD_CLOEXEC /* 0x1 */)` | `fd=-1`, `errno=EINVAL` — **wrong** |

`memfd_create` is different: it takes `MFD_CLOEXEC` (`0x1`) and
`MFD_ALLOW_SEALING` (`0x2`) as its own flags, which is why the *fallback* path
is unaffected.

**Implementation consequence:** the confinement adapter uses
`libc::O_CLOEXEC` for the `memfd_secret` syscall and treats `EINVAL` as "this
kernel rejects the flag" rather than "the mechanism is absent". A
`memfd_secret` failure is `ENOSYS` when the mechanism is unavailable — that is
the signal that selects the sealed-`memfd` fallback. Conflating `EINVAL` with
`ENOSYS` would silently demote a working barrier on every kernel.

`memfd_secret` is *not* `F_SEAL`-able, so the two mechanisms are not conflated
in the posture report.

### 7.2 `landlock` 0.4.7 API shape

The API descriptions in the design are directionally right but the call shapes
differ:

| Sketch says | landlock 0.4.7 actually is |
|---|---|
| `Ruleset::…::create()` | `handle_access(…)` returns `Result<Ruleset, _>`; `create()` is on `Ruleset` |
| `restrict_self() -> RestrictionStatus` | returns `Result<RestrictionStatus, _>`; **`RestrictionStatus` has no `.status()` method** — the status *is* the returned value |
| `all_threads()` (no args) | `RulesetCreated::all_threads(bool) -> Result<_, _>`, called **before** `restrict_self()` |
| `set_compatibility(CompatLevel::HardRequirement)` | correct, but needs `use landlock::Compatible` |
| `access` from `AccessFs::from_all(abi)` | needs `use landlock::Access` |

`all_threads(true)` requires **Landlock ABI V8**; on the stock Ubuntu 24.04
kernel (ABI V4) it returns
`RestrictSelfFlags(NotSupported { flag: AllThreads, set: true })`. See §4.1.

`AccessFs::from_all(ABI::V9)` fails under `HardRequirement` on an ABI V8
kernel, because V9 adds `ResolveUnix` and `IoctlDev`. **Do not use `ABI::V9`
with `HardRequirement`** — use `ABI::V8` or lower. `landlock` 0.4.7 exposes V9
as a *maximum*, not as a *requirement*.

### 7.3 `redis` 1.7.1: the `SET` shape is `SetExpiry::PX`

```rust
// redis 1.7.1
use redis::{AsyncCommands, SetExpiry, SetOptions};

let opts = SetOptions::default().with_expiration(SetExpiry::PX(60_000));
let _: () = conn.set_options(key, value, opts).await?;
```

- The variant is **`SetExpiry::PX(u64)`** (milliseconds), not `Milliseconds`.
  `SetExpiry` has `EX`, `PX`, `EXAT`, `PXAT`, `KEEPTTL`.
- `set_options` is the method that takes `SetOptions`; plain `set` does not.
- The async API needs the **`tokio-comp`** feature on the `redis` crate, and
  `AsyncCommands` must be imported.
- `conn.ttl(key)` returns **seconds**; a 60 000 ms `PX` reads back as `60`.

### 7.4 `aws-sdk-s3` needs an explicit behavior version

Without it, every request panics at client construction:

```
Invalid client configuration: A behavior major version must be set when
sending a request or constructing a client.
```

Enable `behavior-version-latest` in the workspace, and prefer pinning an
explicit behavior version over the floating `latest` feature once a specific
major is chosen.

### 7.5 `cargo audit` passes only with an explicit `aws-sdk-s3` feature trim

`aws-sdk-s3`'s default features include `rustls` -> `tls-rustls` ->
`aws-smithy-runtime/legacy-rustls-ring` -> `aws-smithy-http-client/hyper-014`,
which pins `hyper` 0.14, `h2` 0.3, `rustls` 0.21 and `rustls-webpki` 0.101 —
six RustSec advisories. Keyspout does not need the legacy path. Trimming the
features selects `aws-smithy-http-client/rustls-aws-lc` instead, which uses
`hyper` 1.x, `h2` 0.4, `rustls` 0.23 and `rustls-webpki` 0.103 — no advisories.

```toml
# workspace Cargo.toml
aws-sdk-s3 = { version = "1.153.0", default-features = false, features = [
    "http-1x",
    "default-https-client",
    "rt-tokio",
] }
```

With that trim, `cargo audit` exits **0**. Three further notes:

- `sigv4a` is deliberately **not** enabled. It is the only thing that pulls
  `crypto-bigint` 0.5 (through `aws-sigv4` -> `p256`/`ecdsa`), and no 0.5.x
  release fixes RUSTSEC-2026-0387 — only `>=0.7.6` does, which is a different
  major line `aws-sigv4` cannot use. Keyspout signs single-region requests
  against a configured endpoint, never a multi-region access point, so the
  feature buys nothing.
- `tokio` 1.54.0 is **yanked** on crates.io; `cargo update -p tokio --precise
  1.54.1` selects a non-yanked release.
- `proc-macro-error2` 2.0.1 (pulled by `hpke-rs` -> `libcrux` on non-Linux
  targets) is an **unmaintained** warning, not a vulnerability. `cargo audit`
  still exits 0.

The lesson generalises: when an audit fails inside one dependency's subtree,
check the *feature selection* before concluding the version is unsafe.

### 7.6 `rand_core` is at 0.10.1, not 0.10.3

crates.io has **0.10.1** as the latest; `rand` 0.10.3 pulls it transitively.
Use `rand` 0.10.3 and let `rand_core` resolve, rather than pinning a version
that does not exist.

### 7.7 The workspace test gate must run as `root`

`crates/ksp-cli/tests/principals.rs` creates two UNIX accounts and asserts that
the admin cannot read or write the user's level and vice versa. It **fails**
when it is not `root`, naming the command that runs it, because a skipped
security test reads like a pass. That makes the gate:

```bash
scripts/ksp-vm.sh sudo -n bash -c \
  'CARGO_TARGET_DIR=/tmp/ksp-root-target cargo test --workspace'
```

`CARGO_TARGET_DIR` matters: a `root`-owned `target/` would break every later
non-`root` build in the same checkout. `cargo fmt --check`, `cargo clippy` and
`cargo audit` do not need `root`.

`scripts/ksp-gate.sh` runs all of it — fmt, clippy, both halves of the suite and
`cargo audit` — in that order, from the host or the VM. Prefer it to typing the
list by hand: the list as it used to be written could never be green, and an
agent that finds a gate permanently red learns to skip it.

Whichever way the gate is split, note that `cargo test` stops at the first
failing test binary. Because this file fails by design without privileges, a
plain `cargo test --workspace` reports *only* this failure and silently skips
every target after it — a fail-fast run once hid three real defects for a whole
release. Run the unprivileged half with `--no-fail-fast`:

```bash
scripts/ksp-vm.sh bash -c 'cargo test --workspace --no-fail-fast'
scripts/ksp-vm.sh sudo -n bash -c \
  'CARGO_TARGET_DIR=/tmp/ksp-root-target cargo test -p ksp-cli --test principals'
```

Running the suite as `root` also exposes tests whose precondition was a
discretionary-access check rather than the property they assert — `root`
bypasses `umask`, `0600` modes and `RLIMIT_MEMLOCK` (`CAP_IPC_LOCK`). Those
tests now either establish the precondition in a way that holds for any uid or
say why it cannot. Two more places where the same class of leak appeared:

- `ksp-posture`'s confinement tests applied a Landlock ruleset to the whole
  test process, so every later test in that binary hit `EACCES`; they now re-run
  themselves in a child process.
- `ksp-backend`'s valkey tests reuse a port across runs; an `appendonly yes`
  directory left behind replays a stale AOF into the next run.

---

## 8. Service lifecycle

```bash
colima status                       # VM up?
colima ssh -- systemctl status valkey-server ksp-rustfs ksp-garage
colima restart                      # restarts the VM; systemd brings the services back
```

The S3 data directories live in the VM's persistent disk, so buckets and
objects survive a VM restart. `/tmp` in the VM does **not** survive — keep
scratch work under `~/work`.

---

## 9. What was deliberately *not* installed

- **No `cargo-deny`.** The gate list names `cargo audit`, not `cargo deny`.
  Adding a second policy engine would impose a policy the design never
  authorized.
- **No coverage tooling.** Not in the gate list.
- **No host-side `valkey`/`minio` service.** The tests run against the VM's
  services, and a second instance on the host would only invite a test
  accidentally pointed at the wrong one.
- **No `minio` in the VM.** It is archived upstream and its download URLs
  return 410.
