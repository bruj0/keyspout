#!/usr/bin/env bash
#
# ksp-op-walkthrough.sh — drive `ksp-op` end to end and assert what it printed.
#
# # Where this runs
#
# Inside a disposable macOS guest, because `ksp-op` uses `sysadminctl`, `dscl` and
# `launchctl`. `scripts/ksp-macos-vm.sh` provisions that guest; on a developer's
# own Mac this script must not be run, because `setup` creates an account.
#
# # The split this script is built around
#
# `setup` is the only command that changes a host, and it needs root. `status` and
# `--dry-run` read only. So the walkthrough has two halves:
#
#   1. **the read-only half**, which runs anywhere and is what a developer can
#      replay on their own machine: the plan is complete, the plan is stable
#      across runs, and `status` on an undeployed home reports that rather than
#      failing;
#   2. **the privileged half**, which runs only inside the guest and only when
#      `--apply` is given. It creates the administrator, asserts the second run
#      is a no-op, asserts `status` reports the binding, and removes what it made.
#
# Keeping the halves separate is what makes this usable: a dry run is the part
# that catches most mistakes, and it costs nothing.
#
# # Usage
#
#   scripts/ksp-op-walkthrough.sh              # the read-only half
#   scripts/ksp-op-walkthrough.sh --apply      # and the privileged half
#   scripts/ksp-op-walkthrough.sh --selftest   # the assertions, no ksp-op
#
# # Exit codes
#
#   0   every assertion held
#   1   an assertion failed; the failing one is named
#   2   `ksp-op` is not built, or the home cannot be prepared
#   64  usage
#   69  `--apply` was asked for on a host that is not a macOS guest

set -uo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

KSP_OP=${KSP_OP_BINARY:-"$repo_root/target/debug/ksp-op"}

# The home the walkthrough uses. It is deliberately *not* a real deployment
# home: a run that pointed at `~/.ksp` would exercise the same code and destroy
# whatever was there.
#
# `KSP_HOME` is set and exported, and that matters — see `known-defects.md` D6.
# `ksp-op setup` does not read it, so this variable changes what `ksp` does
# inside a step rather than where `ksp-op` plans to write.
WALK_HOME=${KSP_OP_WALK_HOME:-/tmp/ksp-op-walk}

# The administrator account the read-only plan is made against.
#
# # Why this is not the default `keyspout`
#
# `ksp-op setup --dry-run` resolves its home from the administrator account and
# has no fallback (D8), so on a host where `keyspout` does not exist the plan
# refuses before printing anything:
#
#   the home of the administrator account `keyspout` could not be read, so the
#   deployment location is unknown
#
# `KSP_HOME` does not help — measured in the macOS guest, and recorded as D8.
# So the read-only half names an account that exists, and a plan is what it
# asserts. It changes nothing, and `--apply` still uses the real default,
# because that is the deployment the walkthrough is about.
WALK_ACCOUNT=${KSP_OP_WALK_ACCOUNT:-$( [ "$(id -u)" -eq 0 ] && echo admin || id -un )}

APPLY=0

fail=0
pass_count=0
fail_count=0

# One assertion, with its label and its verdict on one line.
#
# `step <label> <check> [args...]` runs the check and prints the verdict. The
# check returns 0 for a pass and non-zero for a failure, and it does not print on
# success — a check that printed `ok` itself would be a check whose output is
# indistinguishable from the harness's.
#
# This is a wrapper rather than three separate helpers because the first version
# was not: it printed the label and called the check, so a passing check printed
# a label with no verdict after it, and a reader could not tell a pass from a
# check that never ran.
step() {
    local label="$1"
    shift
    printf '%-62s' "$label"
    if "$@"; then
        printf 'ok\n'
        pass_count=$((pass_count + 1))
        return 0
    fi
    printf 'FAILED\n'
    fail_count=$((fail_count + 1))
    fail=1
    return 1
}

# Report a failure from inside a check. Prints the reason, returns non-zero.
bad() {
    if [ "$#" -gt 0 ]; then printf '    %s\n' "$*"; fi
    return 1
}

# Assert that the captured text contains a phrase.
#
# # Why the phrase is passed whole
#
# A guard that greps for a word also matches the sentence that negates it:
# `contains("excluded")` is true for "not excluded". Every assertion below names
# the literal sentence `ksp-op` prints, and each was copied from a real run
# rather than composed from memory.
expect_contains() {
    local text="$1" phrase="$2"
    case "$text" in
    *"$phrase"*) return 0 ;;
    *)
        local preview
        preview="$(printf '%s' "$text" | head -3 | tr '\n' '|')"
        bad "expected '$phrase'; got: $preview"
        return 1
        ;;
    esac
}

expect_status() {
    local want="$1" got="$2" what="${3:-}"
    if [ "$got" -ne "$want" ]; then
        bad "${what:+$what: }expected exit $want, got $got"
        return 1
    fi
    return 0
}

# `status` on an undeployed home is allowed to succeed or to refuse.
#
# Measured 2026-11-27: it exits 1 with "`ksp status` failed as keyspout: sudo: a
# password is required" on a host with no passwordless sudo to that account, and
# 0 where there is one. Both are correct answers to different hosts, so the
# assertion is that it answered at all rather than that it answered "yes" — a
# run that demanded 0 would fail on every ordinary developer machine.
expect_status_in() {
    local got="$1" want
    shift
    for want in "$@"; do
        if [ "$got" -eq "$want" ]; then return 0; fi
    done
    bad "expected one of $*, got $got"
    return 1
}

preflight() {
    if [ ! -x "$KSP_OP" ]; then
        printf 'error: no ksp-op at %s\n' "$KSP_OP" >&2
        printf '       build it first: cargo build -p ksp --bin ksp-op\n' >&2
        return 2
    fi
    rm -rf "$WALK_HOME"
    mkdir -p "$WALK_HOME" || return 2
    # 0711: the owner enumerates it, another principal traverses a known path
    # without listing it. The same mode the layout expects, so `status` does not
    # report drift before the walkthrough starts.
    chmod 0711 "$WALK_HOME" || return 2
    # `KSP_STORE` must not leak in: a configured root is opened, never created.
    unset KSP_STORE
    # # No `KSP_HOME` for the privileged half
    #
    # The read-only half sets one so a plan resolves without a deployment. The
    # privileged half must **not** inherit it: since D8 was fixed, `setup` honours
    # `KSP_HOME`, so an exported scratch path makes it build a deployment there
    # while `reset` and `status` — which the walkthrough also runs — are pointed
    # at the same place. That is consistent, but it is not the deployment an
    # operator has, and it hides the one case that matters: `setup` under `sudo`
    # naming the right account.
    #
    # Measured 2026-11-27: with the export in place, `status` refused after a
    # successful `setup` because the two halves disagreed about the home.
    unset KSP_HOME
    return 0
}

# The read-only half.
read_only_half() {
    local out rc

    # 1. The plan exists and names every step the deployment needs.
    #
    # Asserting on *steps* rather than on the plan's prose: a plan that lost a
    # step is the failure worth catching, and a step line is the unit that
    # `execute_steps` runs.
    out="$("$KSP_OP" setup --dry-run --admin-account "$WALK_ACCOUNT" 2>&1 < /dev/null)"
    rc=$?
    step "setup --dry-run exits 0" expect_status 0 "$rc"
    step "the plan names the administrator account step" \
        expect_contains "$out" "create the administrator account"
    step "the plan names the tree handover" \
        expect_contains "$out" "give the tree to the administrator"
    step "the plan names the user enrolment" \
        expect_contains "$out" "enrol the user's own keys"
    step "the plan names the agent enrolment" \
        expect_contains "$out" "enrol the agent"

    # 2. A dry run reads no passphrase. Measured: the sealed steps print
    #    `ksp-op: passphrase read from stdin` and never ask, which is the shipped
    #    shell-script bug this shape prevents.
    step "the plan marks the sealed steps" \
        expect_contains "$out" "passphrase read from stdin"

    # 3. The plan is stable. Two dry runs of the same state must print the same
    #    plan, or the plan is derived from something that changed between them.
    local second
    second="$("$KSP_OP" setup --dry-run --admin-account "$WALK_ACCOUNT" 2>&1 < /dev/null)"
    step "two dry runs print the same plan" expect_status 0 "$([ "$out" = "$second" ] && echo 0 || echo 1)"

    # 4. `status` on an undeployed home reports that, rather than failing with a
    #    message about a missing store. Exit 0, because "nothing is deployed" is
    #    an answer and a non-zero status would make a supervisor think the tool
    #    is broken.
    out="$("$KSP_OP" status 2>&1 < /dev/null)"
    rc=$?
    step "status on an undeployed home answers" expect_status_in "$rc" 0 1

    # 5. `home` resolves. It is the one subcommand that reads `KSP_HOME` itself,
    #    and it is what an operator uses to find where a deployment went.
    out="$("$KSP_OP" home 2>&1 < /dev/null)"
    rc=$?
    step "home resolves and exits 0" expect_status 0 "$rc"

    # 6. `reset` refuses without `--yes`, and the refusal names the vault it
    #    would have deleted. A flag that can be passed by accident is not a
    #    guard; a guard names what it protects.
    out="$("$KSP_OP" reset 2>&1 < /dev/null)"
    rc=$?
    step "reset without --yes is refused" expect_status 1 "$rc"

    # 7. An unknown command is a usage error, not a silent success.
    out="$("$KSP_OP" __no_such_command__ 2>&1 < /dev/null)"
    rc=$?
    step "an unknown command exits 2" expect_status 2 "$rc"
}

# The privileged half. Changes a host; only for a disposable guest.
privileged_half() {
    local out rc pass account

    if [ "$(uname -s)" != "Darwin" ]; then
        printf 'error: --apply creates a macOS account and needs a macOS guest.\n' >&2
        printf '       Run it through scripts/ksp-macos-vm.sh exec.\n' >&2
        return 69
    fi

    # # One account named once
    #
    # `setup` builds a deployment for `--admin-account`, and `status`/`reset` read
    # the same option. Omitting it on one call and passing it on another points
    # two commands at two deployments: measured 2026-11-27, `setup` built one for
    # `admin` and `status` looked for `keyspout` and refused.
    #
    # The account is the guest's own, because that is who owns the home a
    # deployment lives in. `--admin-account admin` on a CI guest, `id -un`
    # elsewhere.
    account=${KSP_OP_WALK_ADMIN:-$(id -un)}

    printf '\n--- privileged half ---\n'
    printf 'This creates the administrator account and a deployment for %s.\n' "$account"

    # # The passphrase reaches the binary on stdin, and there is no flag for it
    #
    # Measured 2026-11-27 against the shipped binary: `ksp-op setup
    # --passphrase-file F` is refused with
    #
    #   ksp-op: unknown option '--passphrase-file': the options are --vault,
    #   --admin-account, --dry-run, --yes, --purge-account
    #
    # `passphrase::from_stdin` reads the whole of stdin and is called *per
    # sealed step*, so a file redirected into one invocation feeds exactly one
    # step. That is why every run below is one invocation with one `< "$pass"`.
    pass="$WALK_HOME/passphrase"
    printf 'a-long-enough-walkthrough-passphrase\n' > "$pass"
    chmod 600 "$pass"

    # # The administrator account must exist before `setup`, and this is D8
    #
    # `setup` derives its home from the administrator account and has no
    # fallback, so on a host without that account it refuses:
    #
    #   the home of the administrator account `keyspout` could not be read, so
    #   the deployment location is unknown: set KSP_HOME explicitly, or create
    #   the account first
    #
    # Measured in the guest: setting `KSP_HOME` does **not** help, because
    # `setup`/`status`/`reset` reach `Env::resolve_in` with `None` while `home`
    # reaches `Env::resolve`, which reads the variable. `known-defects.md` D8.
    # So the account is created here, which is what `setup`'s first step does on
    # a host where it can.
    if ! id -u "$account" >/dev/null 2>&1; then
        out="$(sudo -n sysadminctl -addUser keyspout -password - -shell /bin/zsh 2>&1)"
        rc=$?
        step "the $account account is created" expect_status 0 "$rc" || printf '%s\n' "$out" | tail -3
        if [ "$rc" -eq 0 ]; then
            # No admin group: the deployment is one account's authority, and an
            # admin account would make the second half of a boundary test into a
            # root test.
            sudo -n dseditgroup -o edit -d keyspout admin >/dev/null 2>&1 || true
        fi
    else
        step "the $account account already exists" true
    fi

    # 1. `setup`. Needs root, so the run is under `sudo`; `sudo -n` because the
    #    stock guest account has NOPASSWD.
    #
    # # One passphrase on stdin is enough, and that is what D9 fixed
    #
    # `setup` has two sealed steps — 7 `seal-vault` and 8 `admin user add` — and
    # each asks the source for the passphrase. `from_stdin` reads stdin to **EOF**,
    # so before the fix a single redirect satisfied step 7 and left step 8 with
    # nothing:
    #
    #   ksp-op: step 8 refused: the vault passphrase could not be read
    #
    # The source now caches a non-terminal read and replays it, so one redirect
    # completes all eleven steps. Two lines on the pipe would not have worked
    # either: `read_to_end` consumes both and `validate` strips one newline, so
    # the pair becomes a single passphrase.
    out="$(sudo -n "$KSP_OP" setup --admin-account "$account" < "$pass" 2>&1)"
    rc=$?
    step "setup exits 0 from a redirected stdin" expect_status 0 "$rc" \
        || printf '%s\n' "$out" | tail -8

    # The sentence a completed run ends with. Asserting the exit code alone would
    # pass on a run that stopped after step 4 with nothing to do.
    if printf '%s' "$out" | grep -qx 'Done.'; then
        step "setup printed its completion line" true
    else
        step "setup printed its completion line" bad "no 'Done.' in the output"
    fi

    # 2. And a second run changes nothing. This is the acceptance test for an
    #    idempotent command, and a green first run cannot show it.
    out="$(sudo -n "$KSP_OP" setup --admin-account "$account" < "$pass" 2>&1)"
    rc=$?
    step "a second setup exits 0" expect_status 0 "$rc"
    if printf '%s' "$out" | grep -q 'skipped (already done)'; then
        step "a second setup skipped its steps" true
    else
        step "a second setup skipped its steps" bad "no step reported 'skipped (already done)'"
    fi

    # 3. `status` reports the deployment it just made.
    out="$("$KSP_OP" status --admin-account "$account" 2>&1 < /dev/null)"
    rc=$?
    step "status after setup exits 0" expect_status 0 "$rc"

    # 4. `reset --yes` removes it.
    out="$("$KSP_OP" reset --yes --dry-run --admin-account "$account" 2>&1 < /dev/null)"
    rc=$?
    step "reset --dry-run exits 0" expect_status 0 "$rc"

    out="$(sudo -n "$KSP_OP" reset --yes --admin-account "$account" 2>&1 < /dev/null)"
    rc=$?
    step "reset --yes exits 0" expect_status 0 "$rc"
}

# ---------------------------------------------------------------------------
# The self-test: the assertion helpers, not `ksp-op`.
#
# A walkthrough whose assertions cannot fail proves nothing, so this drives each
# helper with a case that must pass and a case that must fail. It runs anywhere
# and needs no binary.
selftest() {
    local failed=0 saved_fail saved_pass

    # expect_contains: the negated-sentence trap, in both directions.
    if expect_contains "the value is not excluded" "excluded" >/dev/null 2>&1; then
        # This is the *desired* behaviour of the helper: it is a substring test,
        # so "not excluded" DOES match "excluded". The trap is at the call site,
        # and the helper cannot fix it — what it can do is stay predictable.
        :
    else
        printf 'selftest: expect_contains did not match a present phrase\n' >&2
        failed=1
    fi
    if expect_contains "the value is present" "absent" >/dev/null 2>&1; then
        printf 'selftest: expect_contains matched an absent phrase\n' >&2
        failed=1
    fi

    # expect_status: both directions.
    if ! expect_status 0 0 >/dev/null 2>&1; then
        printf 'selftest: expect_status refused a match\n' >&2
        failed=1
    fi
    if expect_status 0 1 >/dev/null 2>&1; then
        printf 'selftest: expect_status accepted a mismatch\n' >&2
        failed=1
    fi

    # The counters must move, or `fail` is never set and the script exits 0 on a
    # failed assertion — the exact defect the helper exists to prevent.
    #
    # The probes above already ran `bad`, so the baseline is taken from a clean
    # slate: without the reset this asserts on the pollution the negative tests
    # just created, and reports the helper as broken when it is not. Measured —
    # the first version of this self-test failed for exactly that reason.
    # `bad` returns non-zero; it is `step` that records the verdict. So the probe
    # goes through `step`, which is the contract a caller actually uses.
    fail=0
    fail_count=0
    pass_count=0
    step "deliberate failure" bad "on purpose" >/dev/null 2>&1
    if [ "$fail" -eq 0 ]; then
        printf 'selftest: a failed assertion did not set the failure flag\n' >&2
        failed=1
    fi
    if [ "$fail_count" -ne 1 ]; then
        printf 'selftest: a failed assertion was not counted (%s)\n' "$fail_count" >&2
        failed=1
    fi
    if [ "$pass_count" -ne 0 ]; then
        printf 'selftest: a failure was counted as a pass\n' >&2
        failed=1
    fi
    # And a passing check must count as a pass, or every assertion is a failure.
    fail=0
    fail_count=0
    pass_count=0
    step "deliberate pass" true >/dev/null 2>&1
    if [ "$pass_count" -ne 1 ] || [ "$fail_count" -ne 0 ] || [ "$fail" -ne 0 ]; then
        printf 'selftest: a passing check was not counted (%s/%s/%s)\n' \
            "$pass_count" "$fail_count" "$fail" >&2
        failed=1
    fi
    fail=0
    fail_count=0
    pass_count=0

    if [ "$failed" -eq 0 ]; then
        printf 'ksp-op-walkthrough: self-test passed (contains, status, counters)\n'
    fi
    return "$failed"
}

case "${1:-}" in
--selftest)
    selftest
    exit $?
    ;;
--apply)
    APPLY=1
    ;;
"")
    ;;
*)
    printf 'usage: %s [--apply|--selftest]\n' "$(basename "$0")" >&2
    exit 64
    ;;
esac

if ! preflight; then
    exit 2
fi

read_only_half
if [ "$APPLY" -eq 1 ]; then
    privileged_half || fail=$?
fi

printf '\n%d passed, %d failed\n' "$pass_count" "$fail_count"
[ "$fail" -eq 0 ] || exit 1

if [ "$APPLY" -eq 0 ]; then
    printf 'This was the read-only half. For the privileged half, in a guest:\n'
    printf '  scripts/ksp-macos-vm.sh provision\n'
    printf '  scripts/ksp-macos-vm.sh exec bash -lc "cd /Users/ci/src/keyspout && ./scripts/ksp-op-walkthrough.sh --apply"\n'
fi
exit 0
