#!/usr/bin/env bash
#
# ksp-guest.sh — run one command in the Linux guest, with the scratch layout
# exported and the guest's exit status preserved.
#
# # Why this exists rather than `colima ssh -- …` at every call site
#
# Two reasons, and both have already cost time in this repository.
#
# 1. **The exit code.** A wrapper that pipes its output through `tr`, `head` or
#    `tail` returns the *pipe's* status. `AGENTS.md` records the case: `msb exec
#    … | tr -d '\r'` made `guest test -f` read as success, because `tr` exited 0
#    and `test` did not. This wrapper has no pipe in the path to the status.
#
# 2. **The scratch layout.** Four variables decide where state lives, and a
#    privileged run has to point all four at guest disk or it is asserting on a
#    virtiofs share where `chown` does nothing. One file sets them, so a call
#    site cannot spell one of them differently.
#
# # What it does not do
#
# It does not start the VM. `scripts/ksp-vm-provision.sh` does that, and a
# wrapper that starts things can leave a half-created machine behind a refusal.
# It is also not the gate: `scripts/ksp-gate.sh` still decides what runs.
#
# # Usage
#
#   scripts/ksp-guest.sh cargo test -p ksp --test principals --no-fail-fast
#   scripts/ksp-guest.sh bash -lc 'df -hT / | cat'
#   scripts/ksp-guest.sh --selftest          # the wiring, no VM
#   scripts/ksp-guest.sh --env               # the exports, no VM
#
# Exit codes:
#   0   the guest command exited 0
#   *   the guest command's own status, verbatim
#   64  usage
#   69  colima is absent or the VM is not running

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

# shellcheck source=lib/vm-guard.sh
. "${script_dir}/lib/vm-guard.sh"

# Where the scratch layout lives. The same default `ksp-guest-scratch.sh` uses,
# and overridable for the same reason: a second data disk is legitimate.
SCRATCH_ROOT=${KSP_GUEST_SCRATCH_ROOT:-/mnt/lima-colima/ksp}

# The four variables, in one place.
#
# `KSP_HOME` and `TMPDIR` are the two that matter for a boundary test. The two
# cargo directories are here because a build's target tree lands on whatever
# filesystem `CARGO_TARGET_DIR` names, and a root-owned target on the 19 GiB root
# is how the disk filled the first time.
guest_env() {
    printf '%s\n' \
        "KSP_HOME=$SCRATCH_ROOT/home" \
        "TMPDIR=$SCRATCH_ROOT/tmp" \
        "CARGO_TARGET_DIR=$SCRATCH_ROOT/target" \
        "KSP_ROOT_TARGET_DIR=$SCRATCH_ROOT/root-target"
}

print_env() {
    local pair
    while IFS= read -r pair; do
        printf 'export %s\n' "$pair"
    done <<<"$(guest_env)"
}

# Run one command in the guest.
#
# # The exit status, and why there is a second call
#
# Measured 2026-11-27: `colima ssh` maps **every** non-zero guest status to 1.
#
#   colima ssh -- bash -lc 'exit 1'    -> 1
#   colima ssh -- bash -lc 'exit 42'   -> 1
#   colima ssh -- bash -lc 'exit 255'  -> 1
#
# So a wrapper that only forwards `colima`'s status reports "something failed"
# and loses which. For a test runner that distinction is the difference between
# "one test failed" (1) and "the binary could not start" (101) — and the gate's
# own `principals` step reads it.
#
# The guest therefore writes its status to a file on guest disk, and this reads
# it back **only when the first call reported failure**. A successful run costs
# one call; a failed one costs two, which is the right trade because the failure
# path is the one that needs the detail.
guest_exec() {
    local script pair argv status=0 status_file exact

    # One file per invocation, under `/tmp` rather than the scratch root.
    #
    # `/tmp` is guest disk on every colima guest, so the write cannot fail for
    # lack of a directory the way `$SCRATCH_ROOT` can before
    # `ksp-guest-scratch.sh --apply` has run — measured: a missing parent made
    # the write fail, the read answer 0, and every failing command report
    # success. The name carries this shell's pid so two runs cannot overwrite
    # each other's status.
    status_file="/tmp/ksp-guest-status.$$"

    # The guest script is assembled in a heredoc rather than by concatenating
    # `$'...'` fragments. The fragment form was tried first and produced a script
    # that `bash -n` rejected on a quote the concatenation had split; a heredoc
    # is one literal block and cannot be split that way.
    argv="$(printf '%q ' "$@")"

    script="$(cat <<GUEST
set -euo pipefail
export PATH="\$HOME/.cargo/bin:\$PATH"
GUEST
)"
    # The exports are literal `NAME=value` pairs whose values this script
    # controls, so they need no quoting — and quoting them would put a literal
    # backslash into the guest's environment.
    while IFS= read -r pair; do
        script+="export ${pair}"$'\n'
    done <<<"$(guest_env)"

    script+="cd $(printf '%q' "$repo_root")"$'\n'
    # `set +e` around the command is what lets the status be recorded; the final
    # `exit 0` is what keeps `colima` from collapsing the value before it is read.
    script+="set +e"$'\n'
    script+="${argv}"$'\n'
    script+="rc=\$?"$'\n'
    script+="printf %s \"\$rc\" > $(printf '%q' "$status_file")"$'\n'
    script+="exit 0"$'\n'

    colima ssh -- bash -lc "$script" || status=$?
    if [ "$status" -ne 0 ]; then
        # The transport itself failed rather than the command (a dropped
        # connection, a stopped VM). There is no recorded status to read, and
        # inventing one would hide the real problem.
        printf 'error: %s: the guest connection failed with status %s\n' \
            "scripts/ksp-guest.sh" "$status" >&2
        return "$status"
    fi

    # A missing or unreadable file is not a success. Reporting 0 here is how a
    # wrapper silently turns every failure into a pass, which is the defect this
    # whole script exists to prevent.
    exact="$(colima ssh -- bash -lc "cat $(printf '%q' "$status_file") 2>/dev/null || printf missing; rm -f $(printf '%q' "$status_file")")"
    case "$exact" in
    '' | missing | *[!0-9]*)
        printf 'error: %s: the guest wrote no usable status (%s)\n' \
            "scripts/ksp-guest.sh" "$exact" >&2
        return 70
        ;;
    esac
    return "$exact"
}

# The self-test: the wrapper's contract, against a fixture `colima`.
#
# Three properties, because they are the three ways a transport wrapper fails:
# it loses the exit code, it lets the host shell expand the command, and it
# silently succeeds when the guest did not run anything.
selftest() {
    local failed=0 dir out code
    dir="$(mktemp -d)"
    trap 'rm -rf "${dir:-}"' EXIT
    mkdir -p "$dir/bin"

    # A colima that records what it was asked and then behaves like the guest
    # shell would: run the command, return its status.
    # The fixture reproduces colima's measured behaviour: run the script, and
    # return 1 for any non-zero status. A fixture that returned the guest status
    # directly would make the wrapper look correct while it lost the number.
    cat > "$dir/bin/colima" <<FAKE_COLIMA
#!/usr/bin/env bash
case "\$1" in
    status) exit 0 ;;
    ssh)
        shift 2   # "ssh" and "--"
        shift 1   # "bash"
        shift 1   # "-lc"
        printf '%s\n---\n' "\$1" >> "$dir/recorded"
        bash -lc "\$1"
        rc=\$?
        [ "\$rc" -eq 0 ] && exit 0
        exit 1
        ;;
esac
exit 0
FAKE_COLIMA
    chmod +x "$dir/bin/colima"

    # 1. A success is a success and the command reached the guest.
    out="$(PATH="$dir/bin:$PATH" "$0" printf 'ran' 2>&1)"
    if [ "$out" != "ran" ]; then
        printf 'selftest: the guest command did not run: %s\n' "$out" >&2
        failed=1
    fi

    # 2. A non-zero status survives **exactly**, not as a boolean. `colima ssh`
    #    maps every non-zero guest status to 1, so the fixture does the same: a
    #    test that let the fixture return 42 directly would pass against a
    #    wrapper that forwarded `colima`'s status and lost the number.
    PATH="$dir/bin:$PATH" "$0" sh -c 'exit 42' >/dev/null 2>&1 || code=$?
    if [ "${code:-0}" -ne 42 ]; then
        printf 'selftest: exit 42 became %s\n' "${code:-0}" >&2
        failed=1
    fi
    PATH="$dir/bin:$PATH" "$0" sh -c 'exit 101' >/dev/null 2>&1 || code=$?
    if [ "${code:-0}" -ne 101 ]; then
        printf 'selftest: exit 101 became %s\n' "${code:-0}" >&2
        failed=1
    fi

    # 3. The scratch exports are in the guest's environment.
    out="$(PATH="$dir/bin:$PATH" KSP_GUEST_SCRATCH_ROOT=/mnt/lima-colima/ksp \
        "$0" sh -c 'printf "%s|%s" "$KSP_HOME" "$TMPDIR"' 2>&1)"
    if [ "$out" != "/mnt/lima-colima/ksp/home|/mnt/lima-colima/ksp/tmp" ]; then
        printf 'selftest: the scratch exports were not set: %s\n' "$out" >&2
        failed=1
    fi

    # 4. An argument with a space survives as one argument. This is the case
    #    a naive `ssh host "$*"` breaks, and the break is silent.
    out="$(PATH="$dir/bin:$PATH" "$0" sh -c 'printf "[%s]" "$1"' _ 'a b' 2>&1)"
    if [ "$out" != "[a b]" ]; then
        printf 'selftest: an argument with a space was split: %s\n' "$out" >&2
        failed=1
    fi

    # 5. A variable in the command is expanded in the GUEST, not by this shell.
    #    The assertion reads the script that was sent, because a host-side
    #    expansion and a guest-side one are indistinguishable from the output:
    #    both print a value. What differs is the text on the wire.
    X_TEST_HOST_VALUE=expanded-on-the-host \
        PATH="$dir/bin:$PATH" "$0" sh -c 'printf %s "$X_TEST_HOST_VALUE"' >/dev/null 2>&1 || true
    if grep -q 'expanded-on-the-host' "$dir/recorded" 2>/dev/null; then
        printf 'selftest: the host expanded a variable into the guest command:\n%s\n' \
            "$(cat "$dir/recorded")" >&2
        failed=1
    fi
    if ! grep -qF 'X_TEST_HOST_VALUE' "$dir/recorded" 2>/dev/null; then
        printf 'selftest: the variable did not reach the guest at all:\n%s\n' \
            "$(cat "$dir/recorded" 2>/dev/null)" >&2
        failed=1
    fi

    if [ "$failed" -eq 0 ]; then
        printf 'ksp-guest: self-test passed (status, exports, argv, no host expansion)\n'
    fi
    return "$failed"
}

case "${1:-}" in
--selftest)
    selftest
    exit $?
    ;;
--env)
    print_env
    exit 0
    ;;
"")
    echo "usage: $(basename "$0") [--selftest|--env|<command> [args...]]" >&2
    exit 64
    ;;
esac

# The host is the only place this runs from. A shell that is already the guest
# must use the command directly, or `scripts/ksp-vm.sh`, which is the gate's
# routing command. Refusing here is what stops the guest half recursing into
# itself, and it names the route rather than the start command — the VM is up,
# and what is missing is the direction.
if [ "$(uname -s)" = "Linux" ]; then
    printf 'error: scripts/ksp-guest.sh runs on the host and enters the guest.\n' >&2
    printf 'This shell is already the guest. Run the command directly, or use\n' >&2
    printf 'scripts/ksp-vm.sh for the gate'"'"'s routing.\n' >&2
    exit 69
fi

vm_require_colima "scripts/ksp-guest.sh $1"
guest_exec "$@"
