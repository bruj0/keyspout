#!/usr/bin/env bash
#
# vm-guard.sh — the one check that decides whether a command may touch the VM.
#
# Sourced, not executed. Two callers: `scripts/ksp-vm.sh` (everything it runs goes
# through the guest) and `scripts/ksp-gate.sh` (the `vm` part).
#
# # Why one guard and not two
#
# The failure this prevents is asymmetric: a Linux-only target that runs on macOS
# does not fail loudly, it either fails to compile on code that was never meant
# for it or, worse, compiles a `cfg(target_os = "linux")` branch out and reports
# the host's answer as the kernel's. Two copies of the check drift, and the drift
# is invisible until someone trusts the wrong run. This file exists so there is
# one sentence and one exit code.
#
# # What it does not do
#
# It does not start the VM. A guard that starts things is a guard that can leave a
# half-created machine behind a refusal, and the operator who typed the command is
# the one who decides to spend the boot.
#
# Exit code 69 is `EX_UNAVAILABLE`: the command is well-formed and the environment
# is not there.

# Matches DEVELOPMENT.md §2. One variable, so a change to the resources is one edit.
VM_START_COMMAND=${VM_START_COMMAND:-colima start --cpu 4 --memory 8 --disk 60 --vm-type=vz --mount-type=virtiofs}

# Whether this shell is inside the guest.
#
# `KSP_VM_GUEST` is a test seam, not configuration: the self-test has to exercise the
# guest branch on a host, and a guard that can only be tested by being wrong is a
# guard nobody tests. Nothing in the product reads it, and an unset value asks the
# kernel.
vm_is_guest() {
    if [ -n "${KSP_VM_GUEST:-}" ]; then
        [ "$KSP_VM_GUEST" = "1" ]
        return
    fi
    [ "$(uname -s)" = "Linux" ]
}

# Print the line that starts the VM, indented as the second half of a refusal.
vm_print_start_command() {
    printf '  %s\n' "$VM_START_COMMAND" >&2
}

# Refuse when colima is absent or the VM is not running.
#
# This is what `scripts/ksp-vm.sh` needs: it *is* the route into the guest, so it must
# not refuse merely because the caller is on the host.
vm_require_colima() {
    local command_name="$1"

    if ! command -v colima >/dev/null 2>&1; then
        printf 'error: %s needs the Linux VM, and colima is not installed.\n' "$command_name" >&2
        printf 'See DEVELOPMENT.md §2 (the Linux VM). Then:\n' >&2
        vm_print_start_command
        return 69
    fi

    if ! colima status >/dev/null 2>&1; then
        printf 'error: %s needs the Linux VM, and the VM is not running.\n' "$command_name" >&2
        printf 'Start it with:\n' >&2
        vm_print_start_command
        return 69
    fi
}

# Refuse when this shell is not the guest.
#
# This is what a command that must run *inside* needs — `scripts/ksp-gate.sh vm`
# invoked directly on a host. It names the routing command, not the start one,
# because the VM may already be up and the missing step is the routing.
vm_require_guest() {
    local command_name="$1" routed="${2:-scripts/ksp-gate.sh}"

    if vm_is_guest; then
        return 0
    fi
    printf 'error: %s runs Linux-only targets; this host is %s.\n' "$command_name" "$(uname -s)" >&2
    printf 'Run it in the VM:\n  %s\n' "$routed" >&2
    return 69
}

# Both checks, and the guest is answered before either of them.
#
# `scripts/ksp-gate.sh vm` uses this, and it is the *only* caller. Its whole job is to
# stop the VM targets being run on a host, so a shell that is already the guest has
# nothing to prove: `scripts/ksp-vm.sh` is the route in, and it has done the routing.
#
# Checking colima first was a defect this gate found: colima is not installed *in the
# guest*, so the documented full gate refused inside the VM with "colima is not
# installed" — the one place the command is supposed to run. The targets behind it
# (`ksp:confinement`, `ksp:principals`, `ksp:sc008_consume`,
# `ksp:sc019_separate_process`) were unreachable from the host, so the gate could
# never be green and the failure blamed a missing install that was correct.
#
# On the host the order still gives the most useful sentence first: with the VM
# stopped the reader needs the start command, and with it running they need to know
# the command has to be routed.
vm_guard() {
    if vm_is_guest; then
        return 0
    fi
    vm_require_colima "${1:-scripts/ksp-gate.sh vm}" || return $?
    vm_require_guest "${1:-scripts/ksp-gate.sh vm}" "${2:-scripts/ksp-gate.sh}"
}
