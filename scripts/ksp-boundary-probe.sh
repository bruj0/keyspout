#!/usr/bin/env bash
#
# ksp-boundary-probe.sh — does this machine really give root and a two-account
# permission boundary today?
#
# # What this is for
#
# Before blaming the product for a failure, answer the environmental question in
# seconds. A test that expects `Permission denied` passes for the wrong reason
# when the file does not exist, and a test that expects a `chown` to take effect
# passes for the wrong reason when it runs on a share. Both have happened here.
#
# # Where it runs
#
# In a microsandbox (`msb run alpine`), because that is the cheapest environment
# that gives real root, real uid changes and no host mount — measured 2026-11-27:
# a `1501:1501` directory at mode `0700` denies a second uid, and the sandbox's
# own root can create both accounts.
#
# It is **not** a substitute for `ksp:principals`. This proves the environment;
# the suite proves the product.
#
# # Usage
#
#   scripts/ksp-boundary-probe.sh
#   scripts/ksp-boundary-probe.sh --local    # same sequence, on this host, if root
#   scripts/ksp-boundary-probe.sh --selftest # the assertions, no sandbox
#
# # Exit codes
#
#   0   root, uid separation, and a mode-denied read all held
#   1   one of them did not; the failing one is named
#   69  `msb` is absent
#   64  usage

set -uo pipefail

PROBE_DIR=${KSP_PROBE_DIR:-/s/ksp-boundary}
PROBE_FILE="$PROBE_DIR/secret"
PROBE_VALUE="boundary-probe-value"

# The sequence, as one script, because it runs in a different machine.
#
# Every assertion is paired: the owner must be able to read and the second uid
# must not. An assertion that only checked the denial would pass on a file that
# was never written, which is the failure mode this exists to avoid.
#
# The `stat` output is printed rather than only tested: a probe that reported a
# bare "ok" would hide that the mode was not what it expected.
PROBE_SCRIPT=$(cat <<'SCRIPT'
set -u
dir="${KSP_PROBE_DIR:-/s/ksp-boundary}"
file=$dir/secret

fail=0
say() { printf '%-46s' "$1"; shift; "$@"; }

# Root is the precondition for everything below.
if [ "$(id -u)" -eq 0 ]; then
    printf '%-46s ok (uid 0)\n' "the sandbox gives real root"
else
    printf '%-46s FAILED (uid %s)\n' "the sandbox gives real root" "$(id -u)"
    exit 1
fi

# Two accounts, created fresh. `-D` on Alpine, `-M -N` on a distro with
# `adduser`; the flag set differs by implementation, so the failure names which.
adduser -D -u 1501 probeowner >/dev/null 2>&1 || adduser -u 1501 probeowner >/dev/null 2>&1
adduser -D -u 1502 probeother >/dev/null 2>&1 || adduser -u 1502 probeother >/dev/null 2>&1
if id probeowner >/dev/null 2>&1 && id probeother >/dev/null 2>&1; then
    printf '%-46s ok (1501, 1502)\n' "two accounts exist"
else
    printf '%-46s FAILED\n' "two accounts exist"
    exit 1
fi

# The directory must belong to the *owner* account. A root-owned 0700 directory
# denies both accounts, which is why the first version of this probe reported a
# correct denial for the wrong reason.
mkdir -p "$dir" || exit 1
printf '%s' "boundary-probe-value" > "$file" || exit 1
${KSP_PROBE_CHOWN:-chown} -R 1501:1501 "$dir" || exit 1
${KSP_PROBE_CHMOD:-chmod} 700 "$dir" || exit 1

reported="$(${KSP_PROBE_STAT:-stat} -c '%u:%g %a' "$dir")"
if [ "$reported" = "1501:1501 700" ]; then
    printf '%-46s ok (%s)\n' "chown took effect" "$reported"
else
    printf '%-46s FAILED (asked 1501:1501 700, read %s)\n' "chown took effect" "$reported"
    fail=1
fi

# The owner reads it.
if got="$(su probeowner -s /bin/sh -c "cat $file" 2>/dev/null)" && [ "$got" = "boundary-probe-value" ]; then
    printf '%-46s ok\n' "the owner account reads the file"
else
    printf '%-46s FAILED (got %s)\n' "the owner account reads the file" "${got:-nothing}"
    fail=1
fi

# And the other account does not. Both the file read and the directory listing:
# a mode that denies `cat` but allows `ls` is a different hole.
if su probeother -s /bin/sh -c "cat $file" >/dev/null 2>&1; then
    printf '%-46s FAILED (the read succeeded)\n' "the other account is denied"
    fail=1
else
    printf '%-46s ok\n' "the other account is denied the file"
fi
if su probeother -s /bin/sh -c "ls $dir" >/dev/null 2>&1; then
    printf '%-46s FAILED (the listing succeeded)\n' "the other account is denied the listing"
    fail=1
else
    printf '%-46s ok\n' "the other account is denied the listing"
fi

exit "$fail"
SCRIPT
)

run_in_sandbox() {
    if ! command -v msb >/dev/null 2>&1; then
        printf 'error: msb is not installed; the sandbox environment research note\n' >&2
        printf '       records why the macOS guest needs it\n' >&2
        return 69
    fi
    # `--net-default-egress deny` because a probe needs no network, and a probe
    # that quietly downloads something is a probe with a dependency.
    msb run alpine --net-default-egress deny -- sh -c "$PROBE_SCRIPT"
}

run_locally() {
    if [ "$(id -u)" -ne 0 ]; then
        printf 'error: --local needs root, because the probe creates two accounts.\n' >&2
        printf '       Without it, run the default: it uses microsandbox.\n' >&2
        return 1
    fi
    printf 'warning: --local creates two accounts on THIS machine (1501, 1502).\n' >&2
    printf '         They are not removed. Use the sandbox unless you mean this.\n' >&2
    sh -c "$PROBE_SCRIPT"
}

# The self-test: the probe's own logic, against a fake `id`/`su`/`stat`.
#
# Two cases, and the second is the one that matters: a denial that is caused by
# a missing file must not be reported as a boundary. That distinction is the
# whole reason the assertions are paired.
selftest() {
    local failed=0 dir out code
    dir="$(mktemp -d)"
    trap 'rm -rf "${dir:-}"' EXIT
    mkdir -p "$dir/bin"

    # A world where every assertion holds.
    cat > "$dir/bin/id" <<'FAKE_ID'
#!/usr/bin/env bash
[ "$1" = "-u" ] && { printf '0\n'; exit 0; }
exit 0
FAKE_ID
    printf '#!/usr/bin/env bash\nexit 0\n' > "$dir/bin/adduser"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$dir/chown-ok"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$dir/chmod-ok"
    printf '#!/usr/bin/env bash\nprintf "1501:1501 700\\n"\n' > "$dir/stat-ok"
    chmod +x "$dir/chown-ok" "$dir/chmod-ok" "$dir/stat-ok"
    # `su probeowner` reads, `su probeother` does not.
    cat > "$dir/bin/su" <<'FAKE_SU'
#!/usr/bin/env bash
case "$1" in
    probeowner) [ "$3" = cat* ] || true; printf 'boundary-probe-value'; exit 0 ;;
    *) exit 1 ;;
esac
FAKE_SU
    chmod +x "$dir/bin/"*

    out="$(KSP_PROBE_DIR="$dir/probe" \
        KSP_PROBE_CHOWN="$dir/chown-ok" KSP_PROBE_CHMOD="$dir/chmod-ok" \
        KSP_PROBE_STAT="$dir/stat-ok" \
        PATH="$dir/bin:$PATH" sh -c "$PROBE_SCRIPT" 2>&1; echo "exit:$?")"
    for phrase in 'gives real root' 'two accounts exist' 'chown took effect' \
        'the owner account reads the file' 'the other account is denied the file'; do
        if ! printf '%s' "$out" | grep -q "$phrase.*ok"; then
            printf 'selftest: "%s" was not reported ok:\n%s\n' "$phrase" "$out" >&2
            failed=1
        fi
    done
    if ! printf '%s' "$out" | grep -q 'exit:0'; then
        printf 'selftest: a boundary that held did not exit 0:\n%s\n' "$out" >&2
        failed=1
    fi

    # And a world where `chown` silently does nothing, which is the measured
    # behaviour of the virtiofs share. The probe must fail.
    printf '#!/usr/bin/env bash\nprintf "0:0 700\\n"\n' > "$dir/stat-bad"
    chmod +x "$dir/stat-bad"
    code=0
    KSP_PROBE_DIR="$dir/probe2" \
        KSP_PROBE_CHOWN="$dir/chown-ok" KSP_PROBE_CHMOD="$dir/chmod-ok" \
        KSP_PROBE_STAT="$dir/stat-bad" \
        PATH="$dir/bin:$PATH" sh -c "$PROBE_SCRIPT" >/dev/null 2>&1 || code=$?
    if [ "$code" -eq 0 ]; then
        printf 'selftest: a chown that did not take effect was accepted\n' >&2
        failed=1
    fi

    if [ "$failed" -eq 0 ]; then
        printf 'ksp-boundary-probe: self-test passed (held, and chown that did not)\n'
    fi
    return "$failed"
}

case "${1:-}" in
--selftest)
    selftest
    exit $?
    ;;
--local)
    run_locally
    exit $?
    ;;
"")
    run_in_sandbox
    exit $?
    ;;
*)
    printf 'usage: %s [--local|--selftest]\n' "$(basename "$0")" >&2
    exit 64
    ;;
esac
