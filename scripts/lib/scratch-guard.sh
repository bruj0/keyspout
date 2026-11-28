#!/usr/bin/env bash
#
# scratch-guard.sh — refuse to run an ownership assertion on a shared filesystem.
#
# Sourced, not executed. Callers: `scripts/ksp-gate.sh` before the privileged
# target, and `scripts/two-account-smoke.sh` before its first `chown`.
#
# # The failure this prevents
#
# Measured 2026-11-27 in the colima guest, on the virtiofs share over the mounted
# home directory:
#
#   for u in 0 501 1000 4242 1601; do chown $u:$u f; stat -c %u f; done
#   -> 0:0 for every one of them
#
# `chown` returns 0 and the owner does not change. Separately, `chmod 0000` on the
# same mount is *enforced*. So on that path an ownership assertion is answered by
# nothing while a permission assertion is answered correctly, and a suite mixing
# the two greens for one and reds for the other, on the same file, for reasons
# that have nothing to do with the product.
#
# # Why an allow-list
#
# The first version of this guard rejected a named list — `virtiofs`, `9p`,
# `fuse*` — and missed every case it existed for, because the mount does not
# report any of those. Measured with `stat -f -c %T`, which is the call a program
# makes:
#
#   <the mounted home>/Projects/keyspout   fuseblk
#   /mnt/lima-colima                      ext2/ext3
#   /tmp                             ext2/ext3
#
# `fuseblk` is what a FUSE-backed share reports, and there is no stable name to
# reject. Accept the filesystems that carry real ownership, and let everything
# else — including a path that cannot be read — fail closed.
#
# # Exit codes
#
# The function returns 0 for an accepted path and 1 for a refusal. It is a
# predicate, so it never exits and never prints on success; the caller decides
# what a refusal means.

# Whether guest disk, or an equivalent, backs this path.
#
# Returns 0 when ownership on `path` is real, 1 when it is not (or cannot be
# established). Prints a refusal naming the fix, so a caller that only forwards
# the status still tells the operator what to do.
#
# The `2>/dev/null` is deliberate: `stat` on a missing path prints its own error,
# and that message is less useful than the one below it.
scratch_is_local() {
    local path="${1:-}" fstype
    if [ -z "$path" ]; then
        printf 'refusing: scratch_is_local needs a path\n' >&2
        return 1
    fi
    # `-f -c %T` is the Linux form. macOS `stat` uses `-f '%HT'`, which this
    # cannot use: the guard runs in the guest, and a copy pasted into a host
    # script would silence itself rather than mislead. The `uname` check turns
    # that mistake into a refusal.
    if [ "$(uname -s)" != "Linux" ]; then
        printf 'refusing: scratch_is_local reads Linux stat; this host is %s.\n' \
            "$(uname -s)" >&2
        printf 'It belongs in the guest. Run it there, or use scripts/ksp-guest.sh.\n' >&2
        return 1
    fi
    fstype="$(stat -f -c %T -- "$path" 2>/dev/null)" || fstype=""
    case "$fstype" in
    ext2/ext3 | ext4 | xfs | btrfs | zfs)
        return 0
        ;;
    "")
        printf 'refusing: %s: cannot read a filesystem type.\n' "$path" >&2
        printf 'A path that does not resolve is not proof that ownership is real.\n' >&2
        return 1
        ;;
    *)
        printf 'refusing: %s is on %s, not guest disk.\n' "$path" "$fstype" >&2
        printf 'An ownership assertion there is answered by nothing: chown returns\n' >&2
        printf '0 and the reported owner does not change. Put the state on guest\n' >&2
        printf 'disk instead:\n' >&2
        printf '  scripts/ksp-guest-scratch.sh --apply\n' >&2
        return 1
        ;;
    esac
}

# Refuse unless every path given is on guest disk.
#
# A convenience for a caller with several paths: it names the first refusal and
# stops, because the second refusal is not extra information — the fix is the
# same and one sentence is easier to act on than three.
scratch_require_local() {
    local path
    for path in "$@"; do
        scratch_is_local "$path" || return 1
    done
    return 0
}

# The self-test: the predicate against a fixture `stat` and `uname`.
#
# Kept here rather than in a caller because the guard is the thing that must be
# provable without the environment it guards — the same argument vm-guard.sh
# makes. `KSP_GUARD_UNAME` and `KSP_GUARD_STAT` are test seams: nothing in the
# product sets them.
scratch_guard_selftest() {
    local failed=0 dir out code
    dir="$(mktemp -d)"
    trap 'rm -rf "${dir:-}"' EXIT

    mkdir -p "$dir/bin"
    cat > "$dir/bin/uname" <<'FAKE_UNAME'
#!/usr/bin/env bash
printf '%s\n' "${KSP_GUARD_UNAME:-Linux}"
FAKE_UNAME
    # Answers the filesystem type from a lookup file, so one fixture covers all
    # four branches. A fixture that printed one answer would pass against a
    # predicate that returned one answer.
    cat > "$dir/bin/stat" <<FAKE_STAT
#!/usr/bin/env bash
case "\$*" in
    *guest*) printf 'ext2/ext3\n' ;;
    *share*) printf 'fuseblk\n' ;;
    *missing*) exit 1 ;;
    *) exit 1 ;;
esac
FAKE_STAT
    chmod +x "$dir/bin/uname" "$dir/bin/stat"

    out="$(PATH="$dir/bin:$PATH" bash -c '. "$1"; scratch_is_local /guest/x' _ "$0" 2>&1)"
    code=$?
    if [ "$code" -ne 0 ]; then
        printf 'selftest: guest disk was refused: %s\n' "$out" >&2
        failed=1
    fi

    out="$(PATH="$dir/bin:$PATH" bash -c '. "$1"; scratch_is_local /share/x' _ "$0" 2>&1)"
    code=$?
    if [ "$code" -eq 0 ]; then
        printf 'selftest: a share was accepted\n' >&2
        failed=1
    fi
    if ! printf '%s' "$out" | grep -q 'fuseblk'; then
        printf 'selftest: the refusal did not name the filesystem: %s\n' "$out" >&2
        failed=1
    fi

    out="$(PATH="$dir/bin:$PATH" bash -c '. "$1"; scratch_is_local /missing/x' _ "$0" 2>&1)"
    code=$?
    if [ "$code" -eq 0 ]; then
        printf 'selftest: an unreadable path was accepted\n' >&2
        failed=1
    fi

    # A guard that always refuses is indistinguishable from one that always
    # accepts, so the multi-path form is checked in both directions.
    out="$(PATH="$dir/bin:$PATH" bash -c '. "$1"; scratch_require_local /guest/a /guest/b' _ "$0" 2>&1)"
    code=$?
    if [ "$code" -ne 0 ]; then
        printf 'selftest: all-guest paths were refused: %s\n' "$out" >&2
        failed=1
    fi
    out="$(PATH="$dir/bin:$PATH" bash -c '. "$1"; scratch_require_local /guest/a /share/b' _ "$0" 2>&1)"
    code=$?
    if [ "$code" -eq 0 ]; then
        printf 'selftest: a mixed list was accepted\n' >&2
        failed=1
    fi

    # And the host branch: this predicate is a guest-only call, so a macOS
    # caller must be refused rather than answered with macOS `stat` semantics.
    out="$(PATH="$dir/bin:$PATH" KSP_GUARD_UNAME=Darwin bash -c '. "$1"; scratch_is_local /guest/x' _ "$0" 2>&1)"
    code=$?
    if [ "$code" -eq 0 ]; then
        printf 'selftest: the host branch was accepted on a non-Linux host\n' >&2
        failed=1
    fi
    if ! printf '%s' "$out" | grep -q 'belongs in the guest'; then
        printf 'selftest: the host refusal did not say where it belongs: %s\n' "$out" >&2
        failed=1
    fi

    if [ "$failed" -eq 0 ]; then
        printf 'scratch-guard: self-test passed (guest, share, unreadable, multi, host)\n'
    fi
    return "$failed"
}

# `bash scripts/lib/scratch-guard.sh --selftest` proves the predicate without a
# VM. Sourced by callers, so the check is guarded rather than run on every load.
if [ "${BASH_SOURCE[0]}" = "$0" ] && [ "${1:-}" = "--selftest" ]; then
    scratch_guard_selftest
    exit $?
fi
