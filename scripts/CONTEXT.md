---
context_name: "Developer Test Environment"
version: "1"
subsystem: "scripts"
created: "2026-11-17T10:45:00+00:00"
updated: "2026-11-24T20:45:00+00:00"
---

# Developer Test Environment

The Linux environment the gate needs, and the commands that prove it before a
build trusts it. This context owns the VM lifecycle, the probes that report what
the guest actually is, and the refusal that stops a Linux-only test from being
run on a macOS host where the code it exercises was never compiled.

## Language

**Linux VM**:
The colima guest the VM half of the gate runs in. It carries guest kernel 7.0
for Landlock ABI V8, the pinned Rust toolchain, and the three backend services.
_Avoid_: container, docker, devbox, sandbox
_Subsystems_: Developer Test Environment
_Files_: scripts/ksp-vm.sh, scripts/ksp-vm-provision.sh
_Relates to_: VM Guard (is required by), Service Probe (is reported by)
_History_:
- 2026-11-17 (014-policy-scoped-sharing): Term introduced.

**VM Guard**:
The one check that decides whether a command may run in the VM. It refuses when
the host is not Linux or when the VM is not running, and it names the command
that starts it. There is no fallback path: a Linux-only target that runs on the
host reports a defect that is not there.
_Avoid_: precondition, sanity check, environment check
_Subsystems_: Developer Test Environment
_Files_: scripts/lib/vm-guard.sh
_Relates to_: Linux VM (guards), Provisioning (is superseded by a started VM)

**Provisioning**:
The idempotent command that brings a VM to the documented shape: resources,
guest kernel, toolchain, C build dependencies and the services enabled at boot.
A second run reports every step as `no change` and exits zero; a run that fails
names the step and leaves no half-created VM.
_Avoid_: setup, bootstrap, install (each names one part of it)
_Subsystems_: Developer Test Environment
_Files_: scripts/ksp-vm-provision.sh
_Relates to_: Linux VM (provisions), Status Report (is verified by)

**Status Report**:
What the environment can and cannot do right now, in five groups: VM state,
guest kernel and Landlock ABI, toolchain versions, each service endpoint with
its health, and free disk. A group it cannot read is reported as unknown, never
as healthy.
_Avoid_: health check, diagnostics, doctor
_Subsystems_: Developer Test Environment
_Files_: scripts/ksp-vm.sh
_Relates to_: Service Probe (is composed of), Provisioning (verifies)

**Service Probe**:
One endpoint question — is Valkey answering, is RustFS listening, is Garage
listening — asked of the endpoint rather than of systemd. A unit that is
`active` is not a server that answers, and the gate needs the second fact.
_Avoid_: ping, health check
_Subsystems_: Developer Test Environment
_Files_: scripts/ksp-vm.sh
_Relates to_: Status Report (composes), Linux VM (runs them)

**Privilege Ticket**:
The time-boxed sudoers *rule* a human authorises once, which lets an agent act as
the `keyspout` admin account without a sudo password. It is not a file the tool
owns: it is `/etc/sudoers.d/privilege-ticket`, carrying `NOTAFTER`, so **sudo
itself** enforces the expiry. Written by `privilege-ticket grant` (password),
reported by `status` (read from `sudo -n -l`, no password), removed by `revoke`
(password). It never grants root: the runas target is `(keyspout)`.
_Avoid_: sudo rule, passwordless sudo, root access, ticket file
_Subsystems_: Developer Test Environment
_Files_: tools/privilege-ticket (planned), DEVELOPMENT.md §4.2
_Relates to_: Privilege Ceiling (is bounded by)

**Privilege Ceiling**:
The statement that a **Privilege Ticket** reaches the `keyspout` account and
stops there, which holds only while that account is not itself an admin.
`grant` refuses to install a rule for an account in `admin`/`sudo`/`wheel`.
Two steps sit above the ceiling and stay human with a `sudo` password:
`admin user add --unix-user` (it chowns a vault to another account) and the
privileged half of the workspace gate (DEVELOPMENT.md §7.7).
_Avoid_: scope, permission level
_Subsystems_: Developer Test Environment
_Relates to_: Privilege Ticket (bounds)

**Scratch Layout**:
The four directories on the guest's own disk that hold every path whose
*ownership* a test asserts on: `KSP_HOME`, `TMPDIR`, `CARGO_TARGET_DIR` and
`KSP_ROOT_TARGET_DIR`, all under `/mnt/lima-colima/ksp`. It exists because the
host mount is not a POSIX filesystem for ownership purposes — measured, `chown`
there returns 0 and the reported owner does not change.
_Avoid_: temp dir, workdir, scratch space (each names one directory, not the set)
_Subsystems_: Developer Test Environment
_Files_: scripts/ksp-guest-scratch.sh, scripts/ksp-guest.sh
_Relates to_: Scratch Guard (is enforced by), Guest Transport (is exported by)
_History_:
- 2026-11-27 (agent-sandbox): Term introduced, with the four variables.

**Scratch Guard**:
The predicate that refuses a path not on guest disk, because an ownership
assertion there is answered by nothing while a `chmod` assertion beside it is
answered correctly. It accepts an allow-list of real filesystems rather than
rejecting a list of shares: the virtiofs mount reports `fuseblk` to
`stat -f -c %T`, so a deny-list naming `virtiofs` accepts every path it exists
to reject.
_Avoid_: mount check, filesystem check
_Subsystems_: Developer Test Environment
_Files_: scripts/lib/scratch-guard.sh
_Relates to_: Scratch Layout (guards), VM Guard (is a sibling of — both refuse rather than warn)

**Guest Transport**:
The one way a host command enters the Linux guest with the **Scratch Layout**
exported and the guest's exit status preserved verbatim. It exists because
`colima ssh` maps every non-zero guest status to 1, so a caller cannot tell a
failing test (1) from a binary that did not start (101); the transport records
the real status on guest disk and reads it back.
_Avoid_: ssh wrapper, remote runner
_Subsystems_: Developer Test Environment
_Files_: scripts/ksp-guest.sh
_Relates to_: Scratch Layout (exports), Linux VM (enters)

**macOS Guest**:
A disposable macOS VM the `ksp-op` walkthrough runs in, because `sysadminctl`,
`dscl` and `launchctl` have no Linux equivalent. It is a **second** guest, not a
replacement for the Linux VM: it proves the macOS half of `ksp-op` and nothing
about Landlock. Apple's licence allows two per host.
_Avoid_: the VM (that is the Linux one), sandbox
_Subsystems_: Developer Test Environment
_Files_: scripts/ksp-macos-vm.sh, docs/ksp-op-walkthrough.md
_Relates to_: Linux VM (is a sibling of, not a replacement), ksp-op (hosts the walkthrough for)

## Relationships

- A **VM Guard** refusal precedes every **Provisioning** and every VM-run target
- A **Status Report** is a list of **Service Probe** answers plus the facts only the guest can report
- **Provisioning** is verified by a second run of itself and by a **Status Report**
- A **Privilege Ticket** is bounded by a **Privilege Ceiling**, and deleting the ticket revokes the grant
- A **Scratch Guard** refusal precedes every target that asserts on file ownership
- A **Guest Transport** exports the **Scratch Layout** and preserves the guest's exit status
- A **macOS Guest** is independent of the **Linux VM**; neither substitutes for the other
