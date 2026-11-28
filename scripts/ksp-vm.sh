#!/usr/bin/env bash
#
# ksp-vm.sh — run a command inside the Keyspout Linux VM, and report what it is.
#
# The implementation targets Linux only: `landlock` and `memfd` do not
# compile on macOS, and the Landlock / memfd_secret / mlock guarantees
# cannot be demonstrated off Linux. This script runs a command inside the
# colima VM, with the guest Rust toolchain on PATH, and refuses rather than
# falling back to the host.
#
# See DEVELOPMENT.md for the environment description and
# scripts/ksp-vm-provision.sh for bringing the VM to the documented shape.
#
# Usage:
#   scripts/ksp-gate.sh                 # the whole gate (this wrapper + split suite)
#   scripts/ksp-vm.sh status            # what the environment can and cannot do now
#   scripts/ksp-vm.sh cargo test --workspace
#   scripts/ksp-vm.sh cargo fmt --check
#   scripts/ksp-vm.sh cargo clippy --all-targets -- -D warnings
#   scripts/ksp-vm.sh cargo audit
#   scripts/ksp-vm.sh bash -c 'cd .worktrees/001-keyspout-mvp-WP01 && cargo test'
#   scripts/ksp-vm.sh --selftest        # the guard and the status groups, no VM
#
# The repository root is the working directory unless the command changes it.
# Only the repository directory is visible inside the VM (the home directory
# is mounted with virtiofs), so worktrees must live under .worktrees/.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

# shellcheck source=lib/vm-guard.sh
. "${script_dir}/lib/vm-guard.sh"

# The three services the gate's VM half needs, and the port each answers on.
# Ports rather than unit names, because a unit that is `active` is not a server
# that answers, and the gate needs the second fact.
VM_SERVICE_NAMES=(valkey rustfs garage)
VM_SERVICE_PORTS=(6379 9000 3900)

# The free space below which a build fails at link with "No space left on device".
VM_MIN_FREE_MIB=${VM_MIN_FREE_MIB:-4096}

# The Landlock ABI the gate needs. `all_threads` — the call the plan requires so a
# ruleset covers every thread of the process — is accepted only from V8.
VM_MIN_LANDLOCK_ABI=${VM_MIN_LANDLOCK_ABI:-8}

# Ask one endpoint whether it answers.
#
# `$1` is the service name, `$2` its port. The probe is overridable so the
# self-test can answer without a VM; the override is a test seam, not
# configuration, and nothing in the product reads it.
vm_probe() {
    local name="$1" port="$2" override
    override="KSP_VM_PROBE_$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')"
    if [ -n "${!override:-}" ]; then
        "${!override}"
        return $?
    fi
    # A TCP connect, not an HTTP request: it asks "is something listening", which is
    # the fact a refused test is usually missing. The S3 servers answer a bare
    # connect even while their API is not ready, and this probe does not claim more.
    (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null
}

# The binary to ask for the Landlock ABI, when this tree has one.
#
# `KSP_VM_KSP_BINARY` replaces the search for the self-test, so the fixture exercises
# the parse below rather than the answer: a fixture that printed `V8` directly would
# pass against a parse that matched nothing.
vm_ksp_binary() {
    if [ -n "${KSP_VM_KSP_BINARY:-}" ]; then
        if [ -x "$KSP_VM_KSP_BINARY" ]; then
            printf '%s' "$KSP_VM_KSP_BINARY"
        fi
        return 0
    fi
    local binary
    for binary in "${repo_root}/target/debug/ksp" "${repo_root}/target/release/ksp"; do
        if [ -x "$binary" ]; then
            printf '%s' "$binary"
            return 0
        fi
    done
    return 0
}

# The Landlock ABI the guest kernel accepts.
#
# The ABI is not in sysfs: it is the return value of a syscall the binary makes, so
# the only honest source is a build of this tree running in this guest. When no
# binary answers the result is `unknown` and names the command that produces it —
# a version table in a shell script would be a second answer that goes stale.
#
# The ABI is read from the sentence `ksp status` prints for the Landlock observation,
# which is `landlock available (abi N)` inside the `confinement:` line. It is not
# printed under any Rust field name, and an earlier version of this probe grepped for
# one: it matched nothing on every host that had a binary, which is the single case
# the probe exists for.
vm_landlock_abi() {
    local binary observed abi

    binary="$(vm_ksp_binary)"
    if [ -z "$binary" ]; then
        printf 'unknown'
        return 0
    fi

    observed="$("$binary" status 2>/dev/null || true)"

    case "$observed" in
    *"landlock available (abi "*)
        abi="$(printf '%s\n' "$observed" \
            | sed -n 's/.*landlock available (abi \([0-9][0-9]*\)).*/V\1/p' \
            | head -1 || true)"
        if [ -n "$abi" ]; then
            printf '%s' "$abi"
            return 0
        fi
        ;;
    *"landlock not implemented"*)
        printf 'none — this kernel does not implement Landlock'
        return 0
        ;;
    *"landlock not enabled"*)
        printf 'none — Landlock is not enabled at boot'
        return 0
        ;;
    esac

    printf 'unknown'
    return 0
}

# Free space on the guest's root, in MiB.
vm_free_mib() {
    df -Pk / | awk 'NR==2 {printf "%d", $4/1024}'
}

# The status report, printed inside the guest.
#
# Exit 0 when every required group answers and the disk is above the floor; 1 when
# a group fails. The report is printed either way: a failing group is the answer,
# and a report that stopped at the first failure would hide the rest.
vm_status_report() {
    local failed=0
    local kernel abi free_mib

    kernel="$(uname -r)"
    abi="$(vm_landlock_abi)"
    free_mib="$(vm_free_mib)"

    printf 'vm:        %s\n' "${KSP_VM_STATE:-running}"
    printf 'kernel:    %s\n' "$kernel"
    case "$abi" in
    unknown)
        printf 'landlock:  unknown — build ksp-cli in this tree, then: ksp status\n'
        ;;
    V*)
        printf 'landlock:  abi %s\n' "${abi#V}"
        # Below V8 the gate's `all_threads` call refuses, so a VM at V4 or V7 is not
        # the environment this repository tests: the failure would arrive later, in a
        # confinement test, and read like a code defect.
        if [ "${abi#V}" -lt "$VM_MIN_LANDLOCK_ABI" ]; then
            printf 'landlock:  below abi V%s — all_threads() refuses; see DEVELOPMENT.md §2.1\n' \
                "$VM_MIN_LANDLOCK_ABI"
            failed=1
        fi
        ;;
    *)
        printf 'landlock:  %s\n' "$abi"
        printf 'landlock:  the kernel cannot confine a process, so the confinement tests cannot pass\n'
        failed=1
        ;;
    esac

    local tool
    for tool in rustc cargo; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '%-10s %s\n' "${tool}:" "$("$tool" --version 2>/dev/null | head -1)"
        else
            printf '%-10s missing\n' "${tool}:"
            failed=1
        fi
    done
    # The two cargo tools the gate runs. Absent is a failing group: `cargo audit`
    # would otherwise fail later with a different sentence, far from the cause.
    for tool in cargo-audit cargo-nextest; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '%-10s %s\n' "${tool}:" "$("$tool" --version 2>/dev/null | head -1)"
        else
            printf '%-10s missing — cargo install --locked %s\n' "${tool}:" "$tool"
            failed=1
        fi
    done

    local index service port
    for index in "${!VM_SERVICE_NAMES[@]}"; do
        service="${VM_SERVICE_NAMES[$index]}"
        port="${VM_SERVICE_PORTS[$index]}"
        if vm_probe "$service" "$port"; then
            printf 'service:   %-8s port %-5s answering\n' "$service" "$port"
        else
            printf 'service:   %-8s port %-5s NOT answering — systemctl status ksp-%s\n' \
                "$service" "$port" "$service"
            failed=1
        fi
    done

    printf 'disk:      %s MiB free on /\n' "$free_mib"
    if [ "$free_mib" -lt "$VM_MIN_FREE_MIB" ]; then
        printf 'disk:      below the %s MiB floor — a build will fail at link with "No space left on device"\n' \
            "$VM_MIN_FREE_MIB"
        printf 'disk:      clean a previous root target first: sudo rm -rf /tmp/ksp-gate-root-target\n'
        failed=1
    fi
    printf 'note:      /tmp does not survive a restart, and shares the 19 GiB root\n'
    printf 'note:      scripts/ksp-guest-scratch.sh --apply lays out a scratch\n'
    printf 'note:      layout on the data disk and prints the variables to export\n'

    return "$failed"
}

# The self-test: a fixture `colima`, fixture probes, no VM.
#
# Kept in the host half of the gate, which is the point: the guard is the thing that
# must be provable without the environment it guards.
vm_selftest() {
    local failed=0
    VM_SELFTEST_DIR="$(mktemp -d)"
    local dir="$VM_SELFTEST_DIR"
    # `dir` is a local of this function; the trap runs when the script exits, long
    # after the frame is gone, so it reads a global.
    trap 'rm -rf "${VM_SELFTEST_DIR:-}"' EXIT

    # A colima that reports a stopped VM, and a cargo that records being started —
    # the second is how "no cargo process is started" is checked rather than assumed.
    mkdir -p "$dir/bin"
    cat > "$dir/bin/colima" <<'FAKE_STOPPED'
#!/usr/bin/env bash
case "$1" in
    status) exit 1 ;;
    ssh) echo "colima-ssh-was-called" >&2; exit 0 ;;
esac
exit 0
FAKE_STOPPED
    cat > "$dir/bin/cargo" <<'FAKE_CARGO'
#!/usr/bin/env bash
echo "cargo-was-called" >&2
exit 0
FAKE_CARGO
    chmod +x "$dir/bin/colima" "$dir/bin/cargo"

    # 1. The guard refuses a stopped VM, names the start command, and starts nothing.
    local out code
    out="$(PATH="$dir/bin:$PATH" "$0" cargo test 2>&1 || true)"
    if ! printf '%s' "$out" | grep -q 'the VM is not running'; then
        printf 'selftest: a stopped VM did not refuse: %s\n' "$out" >&2
        failed=1
    fi
    if ! printf '%s' "$out" | grep -qF "$VM_START_COMMAND"; then
        printf 'selftest: the refusal did not print the start command: %s\n' "$out" >&2
        failed=1
    fi
    if printf '%s' "$out" | grep -q 'cargo-was-called'; then
        printf 'selftest: the guard started cargo anyway: %s\n' "$out" >&2
        failed=1
    fi
    code="$(PATH="$dir/bin:$PATH" "$0" cargo test >/dev/null 2>&1; echo $?)"
    if [ "$code" -ne 69 ]; then
        printf 'selftest: a refused run exited %s, expected 69\n' "$code" >&2
        failed=1
    fi

    # 1b. A shell that is already the guest is not asked for colima.
    #
    # The gate's VM half runs *inside* the VM, where colima is never installed, so a
    # guard that checked colima first refused there with "colima is not installed" —
    # the one place the command is supposed to run. The guest branch has to answer
    # before the tool is looked for, and the fixture records whether it was.
    cat > "$dir/bin/colima" <<'FAKE_RECORDING'
#!/usr/bin/env bash
echo "colima-was-consulted" >&2
exit 1
FAKE_RECORDING
    chmod +x "$dir/bin/colima"
    # `ksp-gate.sh vm` cannot be run here without a VM, so the guard is asked
    # directly: it is one function in one file, and it is what the gate calls.
    out="$(PATH="$dir/bin:$PATH" KSP_VM_GUEST=1 bash -c '
        . "$1"
        vm_guard "scripts/ksp-gate.sh vm" "scripts/ksp-gate.sh" && echo "guard-passed"
    ' _ "$repo_root/scripts/lib/vm-guard.sh" 2>&1 || true)"
    if ! printf '%s' "$out" | grep -q 'guard-passed'; then
        printf 'selftest: a guest shell was refused the VM part: %s\n' "$out" >&2
        failed=1
    fi
    if printf '%s' "$out" | grep -q 'colima-was-consulted'; then
        printf 'selftest: a guest shell was asked for colima: %s\n' "$out" >&2
        failed=1
    fi
    # And on a host, the same guard still refuses — the branch above must not have
    # become "pass everywhere".
    out="$(PATH="$dir/bin:$PATH" KSP_VM_GUEST=0 bash -c '
        . "$1"
        vm_guard "scripts/ksp-gate.sh vm" "scripts/ksp-gate.sh" && echo "guard-passed"
    ' _ "$repo_root/scripts/lib/vm-guard.sh" 2>&1 || true)"
    if printf '%s' "$out" | grep -q 'guard-passed'; then
        printf 'selftest: a host shell was allowed the VM part: %s\n' "$out" >&2
        failed=1
    fi

    # 2. The status report prints every group and fails when a service is down.
    #
    # The toolchain is faked too: the report asks `command -v`, and a self-test that
    # depended on this host having cargo-audit would fail on a host without it while
    # reporting a defect that is not there.
    mkdir -p "$dir/tools"
    for tool in rustc cargo cargo-audit cargo-nextest; do
        cat > "$dir/tools/$tool" <<FAKE_TOOL
#!/usr/bin/env bash
echo "$tool 1.0.0 (fixture)"
FAKE_TOOL
        chmod +x "$dir/tools/$tool"
    done
    # A fixture `ksp` that prints the sentence the real binary prints, so the *parse*
    # is exercised rather than the answer. A fixture that printed `V8` directly would
    # pass against any parse, including one that matched nothing.
    cat > "$dir/tools/ksp" <<'FAKE_KSP'
#!/usr/bin/env bash
printf 'capability:  None\nconfinement: confinement unavailable (landlock available (abi 8); SoftRequirement); no adapter\n'
FAKE_KSP
    chmod +x "$dir/tools/ksp"

    local healthy broken group
    healthy="$(PATH="$dir/tools:$PATH" \
        KSP_VM_PROBE_VALKEY=true KSP_VM_PROBE_RUSTFS=true KSP_VM_PROBE_GARAGE=true \
        KSP_VM_KSP_BINARY="$dir/tools/ksp" KSP_VM_STATE=running \
        "$0" __status 2>&1; echo "exit:$?")"
    for group in 'vm:' 'kernel:' 'landlock:  abi 8' 'rustc:' 'service:' 'disk:'; do
        if ! printf '%s' "$healthy" | grep -q "$group"; then
            printf 'selftest: the status report omitted %s\n%s\n' "$group" "$healthy" >&2
            failed=1
        fi
    done
    if ! printf '%s' "$healthy" | grep -q 'exit:0'; then
        printf 'selftest: a healthy environment did not exit 0:\n%s\n' "$healthy" >&2
        failed=1
    fi

    broken="$(PATH="$dir/tools:$PATH" \
        KSP_VM_PROBE_VALKEY=false KSP_VM_PROBE_RUSTFS=true KSP_VM_PROBE_GARAGE=true \
        KSP_VM_KSP_BINARY="$dir/tools/ksp" KSP_VM_STATE=running \
        "$0" __status 2>&1; echo "exit:$?")"
    if ! printf '%s' "$broken" | grep -q 'NOT answering'; then
        printf 'selftest: a failing service was not reported as failing:\n%s\n' "$broken" >&2
        failed=1
    fi
    if printf '%s' "$broken" | grep -q 'exit:0'; then
        printf 'selftest: a failing service left the exit code zero:\n%s\n' "$broken" >&2
        failed=1
    fi

    # 2b. The ABI parse, which is the whole reason this group exists.
    #
    # Three fixtures, because there are three answers: an ABI the gate can use, an ABI
    # below the floor `all_threads` needs, and a kernel with no Landlock at all. Each
    # is read through the parse, so a probe that stopped matching the rendered sentence
    # fails here instead of reporting `unknown` on a healthy VM.
    cat > "$dir/tools/ksp-old-abi" <<'FAKE_KSP_OLD'
#!/usr/bin/env bash
printf 'confinement: confinement unavailable (landlock available (abi 4); SoftRequirement); no adapter\n'
FAKE_KSP_OLD
    cat > "$dir/tools/ksp-no-landlock" <<'FAKE_KSP_NONE'
#!/usr/bin/env bash
printf 'confinement: confinement unavailable (landlock not implemented by this kernel; SoftRequirement); no adapter\n'
FAKE_KSP_NONE
    chmod +x "$dir/tools/ksp-old-abi" "$dir/tools/ksp-no-landlock"

    local old_abi no_landlock
    old_abi="$(PATH="$dir/tools:$PATH" \
        KSP_VM_PROBE_VALKEY=true KSP_VM_PROBE_RUSTFS=true KSP_VM_PROBE_GARAGE=true \
        KSP_VM_KSP_BINARY="$dir/tools/ksp-old-abi" KSP_VM_STATE=running \
        "$0" __status 2>&1; echo "exit:$?")"
    if ! printf '%s' "$old_abi" | grep -q 'below abi V8'; then
        printf 'selftest: an ABI below the floor was not reported as below it:\n%s\n' "$old_abi" >&2
        failed=1
    fi
    if printf '%s' "$old_abi" | grep -q 'exit:0'; then
        printf 'selftest: an ABI below the floor left the exit code zero:\n%s\n' "$old_abi" >&2
        failed=1
    fi
    # No binary to ask: `unknown` has to name the command that produces one, because
    # "unknown" alone sends a reader to the script instead of to the build.
    local no_binary
    no_binary="$(PATH="$dir/tools:$PATH" \
        KSP_VM_PROBE_VALKEY=true KSP_VM_PROBE_RUSTFS=true KSP_VM_PROBE_GARAGE=true \
        KSP_VM_KSP_BINARY="$dir/tools/absent" KSP_VM_STATE=running \
        "$0" __status 2>&1; echo "exit:$?")"
    if ! printf '%s' "$no_binary" | grep -q 'unknown — build ksp-cli'; then
        printf 'selftest: no binary did not print the command that produces an ABI:\n%s\n' \
            "$no_binary" >&2
        failed=1
    fi
    if printf '%s' "$no_binary" | grep -q 'exit:1'; then
        printf 'selftest: an unmeasured ABI failed the report, which cannot be measured yet:\n%s\n' \
            "$no_binary" >&2
        failed=1
    fi

    no_landlock="$(PATH="$dir/tools:$PATH" \
        KSP_VM_PROBE_VALKEY=true KSP_VM_PROBE_RUSTFS=true KSP_VM_PROBE_GARAGE=true \
        KSP_VM_KSP_BINARY="$dir/tools/ksp-no-landlock" KSP_VM_STATE=running \
        "$0" __status 2>&1; echo "exit:$?")"
    if ! printf '%s' "$no_landlock" | grep -q 'does not implement Landlock'; then
        printf 'selftest: a kernel with no Landlock was not named:\n%s\n' "$no_landlock" >&2
        failed=1
    fi
    if printf '%s' "$no_landlock" | grep -q 'exit:0'; then
        printf 'selftest: a kernel with no Landlock left the exit code zero:\n%s\n' "$no_landlock" >&2
        failed=1
    fi

    # 3. The gate's VM half is guarded by the same sentence, and starts nothing.
    local gate_out
    gate_out="$(PATH="$dir/bin:$PATH" "${script_dir}/ksp-gate.sh" vm 2>&1 || true)"
    if ! printf '%s' "$gate_out" | grep -q 'the VM is not running'; then
        printf 'selftest: ksp-gate.sh vm was not guarded:\n%s\n' "$gate_out" >&2
        failed=1
    fi
    if printf '%s' "$gate_out" | grep -q 'cargo-was-called'; then
        printf 'selftest: ksp-gate.sh vm started cargo on the host:\n%s\n' "$gate_out" >&2
        failed=1
    fi

    # 4. With the VM running and the shell still on the host, the gate refuses to run
    # its VM half here and says where to route it. This is the case the stopped-VM
    # check cannot reach, and it is the one that silently ran cargo before.
    mkdir -p "$dir/running-bin"
    cat > "$dir/running-bin/colima" <<'FAKE_RUNNING'
#!/usr/bin/env bash
case "$1" in
    status) exit 0 ;;
esac
exit 0
FAKE_RUNNING
    chmod +x "$dir/running-bin/colima"
    local running_out
    running_out="$(PATH="$dir/running-bin:$dir/bin:$PATH" "${script_dir}/ksp-gate.sh" vm 2>&1 || true)"
    if ! printf '%s' "$running_out" | grep -q 'runs Linux-only targets'; then
        printf 'selftest: a running VM on a host did not route the gate:\n%s\n' "$running_out" >&2
        failed=1
    fi
    if printf '%s' "$running_out" | grep -q 'cargo-was-called'; then
        printf 'selftest: the gate ran cargo on the host with the VM up:\n%s\n' "$running_out" >&2
        failed=1
    fi

    if [ "$failed" -eq 0 ]; then
        printf 'ksp-vm: self-test passed (guard, status groups, gate wiring)\n'
    fi
    return "$failed"
}

# `__status` is the guest-side report; `status` is the host-side verb that reaches
# it. Hidden because it is not a verb an operator types: run on the host it would
# report the host, which is the confusion this script exists to prevent.
case "${1:-}" in
--selftest)
    vm_selftest
    exit $?
    ;;
__status)
    vm_status_report
    exit $?
    ;;
status)
    vm_require_colima "scripts/ksp-vm.sh status"
    exec colima ssh -- bash -lc "
        set -euo pipefail
        export PATH=\"\$HOME/.cargo/bin:\$PATH\"
        cd '$(printf '%q' "${repo_root}")' && $(printf '%q' "${script_dir}/ksp-vm.sh") __status
    "
    ;;
esac

if [ "$#" -eq 0 ]; then
    echo "usage: $(basename "$0") [status|--selftest|<command> [args...]]" >&2
    exit 64
fi

# The guard is the whole contract: refuse, or run in the guest. There is no third
# branch, and in particular no "run it here instead". This script is the route in, so
# it requires colima rather than requiring the guest shell.
vm_require_colima "scripts/ksp-vm.sh $1"

exec colima ssh -- bash -lc "
    set -euo pipefail
    export PATH=\"\$HOME/.cargo/bin:\$PATH\"
    cd '$(printf '%q' "${repo_root}")' && $(printf '%q ' "$@")
"
