#!/usr/bin/env bash
#
# ksp-guest-scratch.sh — lay out the guest's scratch space on guest disk.
#
# # Why this exists
#
# The colima guest mounts the macOS home over virtiofs at the same absolute path
# the host uses for it. That mount accepts `chown`, returns 0, and reports an
# owner that is neither the requested one nor the previous one — measured
# 2026-11-27. So any state whose
# *ownership* is under test must live on the guest's own disk, and the natural
# place (`/tmp`) is on a 19 GiB root that has already been filled once by an
# abandoned `CARGO_TARGET_DIR`.
#
# This script does three things and nothing else:
#
#   1. reports what is using the root, so a full disk is diagnosable rather than
#      discovered at a link step;
#   2. with `--apply`, removes a **named list** of known-abandoned trees. A path
#      that is not on the list is reported and left alone — a cleaner that
#      deletes what it happens to find is a cleaner nobody can run twice;
#   3. creates the scratch roots under `/mnt/lima-colima` and prints the four
#      environment variables a caller should export, so the choice of location
#      lives in one file rather than in every invocation.
#
# The environment output is the point. Documenting "put scratch on the data
# disk" produces a dozen places that each spell the path slightly differently.
#
# # Usage
#
#   scripts/ksp-guest-scratch.sh            # report only; change nothing
#   scripts/ksp-guest-scratch.sh --apply    # reclaim, then lay out the roots
#   scripts/ksp-guest-scratch.sh --env      # print only the exports
#   scripts/ksp-guest-scratch.sh --selftest # the steps against a fixture guest
#
# Exit codes:
#   0   the report ran and nothing is over the thresholds (or --apply finished)
#   1   a step failed, named on stderr
#   69  colima is absent or the VM is not running

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/vm-guard.sh
. "${script_dir}/lib/vm-guard.sh"

# The data disk colima attaches for the container runtime. 99 GiB measured, and
# writable, but root-owned: `sudo mkdir` then `chown` before it can be used.
# `--root-disk` and `--disk` are separate flags in `colima start`, so this is
# not the same partition as the 19 GiB `/`.
SCRATCH_ROOT=${KSP_GUEST_SCRATCH_ROOT:-/mnt/lima-colima/ksp}

# The roots a caller exports. One list, so a directory added here is a directory
# in the environment printout and nowhere else.
SCRATCH_ROOTS=(home tmp target root-target)

# Trees this script is allowed to delete.
#
# Named explicitly rather than matched by pattern: `/tmp/ksp-*` would also match
# a live `ksp-valkey-<pid>` directory belonging to a running Valkey, and deleting
# that while the service holds the socket is a data-loss bug dressed as cleanup.
#
# Every entry is a build output or a repro tree. None of them is state the
# product reads.
ABANDONED=(
    /tmp/ksp-repro
    /tmp/ksp-gate-root-target
)

# Directories above this size are reported, because a full root is diagnosed by
# what is on it rather than by the fact that `df` says 100 %.
ABANDON_REPORT_MIB=${KSP_GUEST_SCRATCH_REPORT_MIB:-100}

# Run one shell string in the guest.
#
# `KSP_GUEST_RUN` replaces the transport for the self-test: a command that takes
# the script as its only argument. It is a test seam, not configuration, and
# nothing in the product reads it. The real transport is `colima ssh`, which is
# the only way in.
guest_run() {
    if [ -n "${KSP_GUEST_RUN:-}" ]; then
        "$KSP_GUEST_RUN" "$1"
        return $?
    fi
    # `2>/dev/null` on purpose: colima prints
    # `level=fatal msg="exit status 1"` to stderr for every non-zero guest
    # status, and half the calls here are *expected* negatives — `test -e` on a
    # tree that should be absent. Forwarding that noise makes a clean run look
    # like a failing one, and the caller already reports the exit code it cares
    # about. Nothing this script needs is ever on colima's stderr.
    colima ssh -- bash -lc "set -euo pipefail; $1" 2>/dev/null
}

# The guest's own account name.
#
# Read in the guest rather than taken from the host: colima maps the macOS uid to
# a guest account (`bruj0` here, home `/home/bruj0.guest`), and `$USER` on the
# host is not that name on every colima version. A `chown` to the wrong name
# fails loudly, which is the good case; a `chown` to a name that happens to exist
# for another reason is the bad one.
guest_user() {
    guest_run 'id -un'
}

# Where the host home is mounted inside the guest.
#
# The mount location is the **host** home's absolute path, and the same string
# resolves inside the guest — that is why the repository is visible there at its
# macOS path. Reading `$HOME` inside the guest answers the guest account's own
# home (`/home/<user>.guest`), which is guest disk, not the share; measured, and
# the first version of this function did exactly that and reported ext2/ext3 for
# the share it was supposed to describe.
guest_mount_path() {
    printf '%s' "${KSP_HOST_HOME:-$HOME}"
}

# Free MiB on a filesystem.
#
# `df -Pk` is the POSIX form and gives 1K blocks, so the arithmetic is one
# division and a caller can compare it with a threshold without knowing the
# locale's thousands separator.
guest_free_mib() {
    guest_run "df -Pk '$1' | awk 'NR==2 {printf \"%d\", \$4/1024}'"
}

# The filesystem type of a path, as a program reads it.
#
# Not `mount`'s driver name. Measured: the virtiofs mount reports `fuseblk` to
# `stat -f -c %T`, and neither `virtiofs` nor `fuse.virtiofs` appears. This is
# reported here because it is the second question an operator asks after "is the
# disk full", and the answer is not what the documentation calls the mount.
guest_fstype() {
    guest_run "stat -f -c %T '$1' 2>/dev/null || echo unknown"
}

# Report what is on the root and how much room the scratch disk has.
#
# Printed whether or not anything is wrong: a report that stops at the first
# finding hides the rest, and the numbers are the diagnostic.
report() {
    local root_free scratch_free fstype scratch_fstype mount_path

    root_free="$(guest_free_mib /)"
    scratch_fstype="$(guest_fstype /mnt/lima-colima)"
    mount_path="$(guest_mount_path)"

    printf 'guest root:        %s MiB free on /\n' "$root_free"

    if [ "$scratch_fstype" = unknown ] || [ "$scratch_fstype" = "" ]; then
        printf 'guest data disk:   /mnt/lima-colima is absent\n'
        printf 'guest data disk:   the scratch layout needs it; see DEVELOPMENT.md §2\n'
        scratch_free=0
    else
        scratch_free="$(guest_free_mib /mnt/lima-colima)"
        printf 'guest data disk:   %s MiB free on /mnt/lima-colima (%s)\n' \
            "$scratch_free" "$scratch_fstype"
    fi

    fstype="$(guest_fstype "$mount_path")"
    printf 'host mount:        %s is %s\n' "$mount_path" "$fstype"
    printf 'note:              chown on that mount returns 0 and does not take\n'
    printf 'note:              effect; ownership assertions belong on guest disk\n'

    # The trees large enough to explain a full root. Sorted ascending so the
    # biggest is last, which is where the eye goes.
    local listing path mib abandoned=0
    listing="$(guest_run "sudo -n du -xm --max-depth=1 / 2>/dev/null || du -xm --max-depth=1 / 2>/dev/null || true")"
    while IFS=$'\t' read -r mib path; do
        [ -n "$path" ] || continue
        if [ "$mib" -ge "$ABANDON_REPORT_MIB" ]; then
            printf 'root usage:        %6s MiB  %s\n' "$mib" "$path"
            abandoned=1
        fi
    done <<<"$(printf '%s\n' "$listing" | sort -n)"

    # And `/tmp` broken down, because that is where a target directory lands.
    listing="$(guest_run "sudo -n du -xm --max-depth=1 /tmp 2>/dev/null || du -xm --max-depth=1 /tmp 2>/dev/null || true")"
    while IFS=$'\t' read -r mib path; do
        [ -n "$path" ] || continue
        if [ "$mib" -ge "$ABANDON_REPORT_MIB" ]; then
            printf 'tmp usage:         %6s MiB  %s\n' "$mib" "$path"
        fi
    done <<<"$(printf '%s\n' "$listing" | sort -n)"

    if [ "$root_free" -lt 4096 ]; then
        printf 'warning:           the root has under 4 GiB free; a debug build\n'
        printf 'warning:           will fail at link with "No space left on device"\n'
    fi

    # Named even when the tree is absent, so a reader can see what --apply would
    # have removed rather than guessing whether it ran.
    local candidate size
    for candidate in "${ABANDONED[@]}"; do
        if guest_run "test -e '$candidate'"; then
            size="$(guest_run "sudo -n du -sh '$candidate' 2>/dev/null | cut -f1 || echo '?'")"
            printf 'reclaimable:       %-6s %s\n' "$size" "$candidate"
        fi
    done

    return 0
}

# Remove the abandoned trees, then lay out the scratch roots.
apply() {
    local candidate user root mib

    user="$(guest_user)"
    if [ -z "$user" ]; then
        printf 'error: could not read the guest account name\n' >&2
        return 1
    fi

    for candidate in "${ABANDONED[@]}"; do
        if ! guest_run "test -e '$candidate'"; then
            printf 'no change: %s — absent\n' "$candidate"
            continue
        fi
        # `sudo` because a `CARGO_TARGET_DIR` written by the privileged suite is
        # root-owned and an unprivileged `rm -rf` fails silently, then the next
        # link step reports "No space left on device" at exit 101 — disk, not
        # code. Check the removal rather than trusting it.
        if ! guest_run "sudo -n rm -rf '$candidate'"; then
            printf 'error: step "%s" failed: sudo rm -rf refused\n' "$candidate" >&2
            return 1
        fi
        if guest_run "test -e '$candidate'"; then
            printf 'error: step "%s" failed: still present after removal\n' "$candidate" >&2
            return 1
        fi
        printf 'changed:   %s — removed\n' "$candidate"
    done

    if ! guest_run "test -d /mnt/lima-colima"; then
        printf 'error: step "scratch" failed: /mnt/lima-colima is absent\n' >&2
        printf '       the scratch layout needs the data disk; see DEVELOPMENT.md §2\n' >&2
        return 1
    fi

    # The parent is root-owned, so creating it needs sudo; giving it away needs
    # root too. Both, then, in one step that reports whether it changed anything:
    # a second run must say `no change` for every root or the step is not
    # idempotent and cannot sit in a setup script.
    for root in "${SCRATCH_ROOTS[@]}"; do
        if guest_run "test -d '$SCRATCH_ROOT/$root' && [ \"\$(stat -c %U '$SCRATCH_ROOT/$root')\" = '$user' ]"; then
            printf 'no change: %s — present and owned by %s\n' "$root" "$user"
            continue
        fi
        if ! guest_run "sudo -n mkdir -p '$SCRATCH_ROOT/$root' && sudo -n chown '$user' '$SCRATCH_ROOT/$root' && sudo -n chmod 0755 '$SCRATCH_ROOT/$root'"; then
            printf 'error: step "%s" failed: mkdir or chown refused\n' "$root" >&2
            return 1
        fi
        printf 'changed:   %s — created at %s, owned by %s\n' "$root" "$SCRATCH_ROOT/$root" "$user"
    done

    # Prove the layout is usable rather than asserting it: a chown under the
    # scratch root that does not read back as requested means the path is on a
    # share, and every ownership test downstream is answered by nothing.
    local probe_owner
    if ! guest_run "touch '$SCRATCH_ROOT/tmp/.probe' && sudo -n chown 4242:4242 '$SCRATCH_ROOT/tmp/.probe'"; then
        printf 'error: step "probe" failed: could not place a probe file\n' >&2
        return 1
    fi
    probe_owner="$(guest_run "stat -c %u '$SCRATCH_ROOT/tmp/.probe'")"
    guest_run "rm -f '$SCRATCH_ROOT/tmp/.probe'" || true
    if [ "$probe_owner" != 4242 ]; then
        printf 'error: step "probe" failed: chown under %s read back as uid %s, not 4242\n' \
            "$SCRATCH_ROOT" "$probe_owner" >&2
        printf '       the scratch root is not on guest disk, so ownership tests there\n' >&2
        printf '       would be answered by nothing. The sandbox environment\n' >&2
        printf '       research note records the measurement\n' >&2
        return 1
    fi
    # `verified`, not `changed`: the probe creates and removes a file, so it is
    # not a change to the layout and a second run must not claim one. The plan's
    # acceptance is that a second `--apply` changes nothing, and a step that
    # printed `changed` on every run would make that criterion unreadable.
    printf 'verified:  probe — a chown under %s reads back as requested\n' "$SCRATCH_ROOT"

    printf '\nThe guest has scratch space. Export these before a privileged run:\n\n'
    print_env
    return 0
}

# The four variables, in the form a caller can `eval`.
#
# Printed by `--env` so a script can consume it, and printed by `apply` so a
# human sees it without a second command. Both go through one function, because
# two printouts of four variables is two chances to disagree.
print_env() {
    printf 'export KSP_HOME=%s\n' "$SCRATCH_ROOT/home"
    printf 'export TMPDIR=%s\n' "$SCRATCH_ROOT/tmp"
    printf 'export CARGO_TARGET_DIR=%s\n' "$SCRATCH_ROOT/target"
    printf 'export KSP_ROOT_TARGET_DIR=%s\n' "$SCRATCH_ROOT/root-target"
}

# The self-test: the steps against a fixture guest, no VM.
#
# Three properties, because they are the three ways this script fails: a second
# run that changes something, a removal it reports and did not do, and a probe
# that passes on a filesystem where `chown` does nothing.
selftest() {
    local failed=0 dir
    dir="$(mktemp -d)"
    trap 'rm -rf "${dir:-}"' EXIT

    # A guest whose answers are a function of the script it was handed. Small on
    # purpose: a fixture with its own control flow is a second implementation,
    # and a self-test that passes against a wrong fixture proves nothing.
    mkdir -p "$dir/state"
    cat > "$dir/guest" <<FIXTURE
#!/usr/bin/env bash
case "\$1" in
    "id -un") printf 'fixture\n' ;;
    *'df -Pk'*lima-colima*) printf '90000\n' ;;
    *'df -Pk'*) printf '3000\n' ;;
    *'stat -f -c %T'*lima-colima*) printf 'ext2/ext3\n' ;;
    *'stat -f -c %T'*'/Users/'*) printf 'fuseblk\n' ;;
    *'stat -f -c %T'*) printf 'ext2/ext3\n' ;;
    *'du -xm'*'/tmp'*) printf '12000\t/tmp\n12000\t/tmp/ksp-repro\n' ;;
    *'du -xm'*) printf '19000\t/\n12000\t/tmp\n' ;;
    *'du -sh'*) printf '12G\n' ;;
    *"test -e"*ksp-repro*) [ -e "$dir/state/repro" ] ;;
    *"rm -rf"*ksp-repro*) rm -f "$dir/state/repro" ;;
    *"test -e"*) exit 1 ;;
    *"test -d /mnt/lima-colima"*) exit 0 ;;
    *"test -d"*) exit 1 ;;
    *"mkdir -p"*) printf '%s\n' "\$1" >> "$dir/state/created" ;;
    *"touch"*) exit 0 ;;
    *'stat -c %u'*) printf '4242\n' ;;
    *"rm -f"*) exit 0 ;;
    *) exit 0 ;;
esac
FIXTURE
    chmod +x "$dir/guest"
    touch "$dir/state/repro"

    local first second
    first="$(KSP_GUEST_RUN="$dir/guest" KSP_GUEST_SCRATCH_ROOT=/mnt/lima-colima/ksp \
        "$0" --apply 2>&1 || true)"
    if ! printf '%s' "$first" | grep -q 'verified:  probe'; then
        printf 'selftest: the first run did not prove the probe:\n%s\n' "$first" >&2
        failed=1
    fi
    if ! printf '%s' "$first" | grep -q 'export KSP_HOME=/mnt/lima-colima/ksp/home'; then
        printf 'selftest: the first run did not print the environment:\n%s\n' "$first" >&2
        failed=1
    fi

    # The layout now exists, so the second run must change nothing. The fixture
    # answers "present and owned" for every root, which is what a completed first
    # run leaves behind.
    cat > "$dir/guest2" <<FIXTURE2
#!/usr/bin/env bash
case "\$1" in
    "id -un") printf 'fixture\n' ;;
    *'df -Pk'*) printf '90000\n' ;;
    *'stat -f -c %T'*) printf 'fuseblk\n' ;;
    *'stat -f -c %T'*) printf 'ext2/ext3\n' ;;
    *'du -xm'*) printf '16\t/\n' ;;
    *"test -e"*) exit 1 ;;
    *"test -d /mnt/lima-colima"*) exit 0 ;;
    *"test -d"*) exit 0 ;;
    *) exit 0 ;;
esac
FIXTURE2
    chmod +x "$dir/guest2"
    second="$(KSP_GUEST_RUN="$dir/guest2" KSP_GUEST_SCRATCH_ROOT=/mnt/lima-colima/ksp \
        "$0" --apply 2>&1 || true)"
    if printf '%s' "$second" | grep -q '^changed:'; then
        printf 'selftest: the second run changed something:\n%s\n' "$second" >&2
        failed=1
    fi

    # A probe that reads back the wrong uid must fail the run. This is the whole
    # reason the step exists: on the host mount `chown` returns 0 and the owner
    # does not change, so a probe that trusts the exit status proves nothing.
    cat > "$dir/guest-wrong" <<'FIXTURE_WRONG'
#!/usr/bin/env bash
case "$1" in
    "id -un") printf 'fixture\n' ;;
    *'printf %s'*) printf '/Users/fixture\n' ;;
    *'df -Pk'*) printf '90000\n' ;;
    *'stat -f -c %T'*) printf 'fuseblk\n' ;;
    *'du -xm'*) printf '16\t/\n' ;;
    *"test -e"*) exit 1 ;;
    *"test -d"*) exit 0 ;;
    *"touch"*) exit 0 ;;
    *'stat -c %u'*) printf '0\n' ;;
    *) exit 0 ;;
esac
FIXTURE_WRONG
    chmod +x "$dir/guest-wrong"
    local wrong code
    wrong="$(KSP_GUEST_RUN="$dir/guest-wrong" KSP_GUEST_SCRATCH_ROOT=/mnt/lima-colima/ksp \
        "$0" --apply 2>&1 || true)"
    if ! printf '%s' "$wrong" | grep -q 'read back as uid 0'; then
        printf 'selftest: a probe that did not take effect was not reported:\n%s\n' "$wrong" >&2
        failed=1
    fi
    code="$(KSP_GUEST_RUN="$dir/guest-wrong" KSP_GUEST_SCRATCH_ROOT=/mnt/lima-colima/ksp \
        "$0" --apply >/dev/null 2>&1; echo $?)"
    if [ "$code" -eq 0 ]; then
        printf 'selftest: a failed probe left the exit code zero\n' >&2
        failed=1
    fi

    # And the report must name the mount's real filesystem type, because the
    # documented one is not what a program reads.
    local reported
    reported="$(KSP_GUEST_RUN="$dir/guest2" "$0" 2>&1 || true)"
    if ! printf '%s' "$reported" | grep -q 'fuseblk'; then
        printf 'selftest: the report did not name the mount filesystem:\n%s\n' "$reported" >&2
        failed=1
    fi

    if [ "$failed" -eq 0 ]; then
        printf 'ksp-guest-scratch: self-test passed (idempotent apply, probe, report)\n'
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
--apply)
    vm_require_colima "scripts/ksp-guest-scratch.sh --apply"
    report
    apply
    exit $?
    ;;
"")
    vm_require_colima "scripts/ksp-guest-scratch.sh"
    report
    exit 0
    ;;
*)
    echo "usage: $(basename "$0") [--apply|--env|--selftest]" >&2
    exit 64
    ;;
esac
