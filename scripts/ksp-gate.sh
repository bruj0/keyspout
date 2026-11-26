#!/usr/bin/env bash
#
# ksp-gate.sh — the gates, split into the part a host can run and the part only
# the Linux VM can.
#
# Why this exists. The gate list used to read:
#
#   cargo fmt --check
#   cargo clippy --all-targets -- -D warnings
#   cargo test --workspace
#   cargo audit
#
# and that list can never be green here. `crates/ksp/tests/principals.rs`
# creates two UNIX accounts and refuses to run without privileges, on purpose (a
# skipped security test reads like a pass). `cargo test` stops at the first
# failing test binary, so in a non-root run that file failed first and every
# target after it was skipped — which is how three real defects survived a whole
# feature, and why `cargo audit`, last in the list, was never reached.
#
# Nor is "run everything as root" the answer: root bypasses umask, `0600` modes
# and `CAP_IPC_LOCK`, so targets that assert those properties fail as root
# (`ksp-backend`'s unit tests, `status_composition`). Hence the privileged and
# unprivileged split.
#
# Feature 004 adds the second axis. The workspace now **builds and runs on
# macOS**, so most of the suite runs on the host — but the tests whose subject is
# a Linux mechanism cannot: Landlock's ruleset, `memfd_secret`, and the
# two-account boundary that needs root. Those run in the VM.
#
# The split is a **partition of the checks inside one script**, not a second gate
# that can be skipped:
#
#   * every test file in the workspace is run by exactly one part;
#   * a target named in VM_TARGETS whose file is gone is a gate failure, so the
#     list cannot rot silently;
#   * running this script on a host runs both parts, in order.
#
# Clippy runs in **both** parts. Clippy would otherwise stop linting the
# `cfg(target_os = "linux")` branches — the code that carries the security
# controls — because a host-only run never compiles them.
#
# The host part also runs `scripts/ksp-markers.sh`, which fails when a status
# marker in `docs/keyspout-design-spec.md` carries no resolving path. That is
# not a test of the code; it is a test of the document that describes the code,
# and it runs here because the spec is what a reader trusts.
#
# Usage:
#
#   scripts/ksp-gate.sh          # everything: the host part, then the VM part
#   scripts/ksp-gate.sh host     # the host part alone
#   scripts/ksp-gate.sh vm       # the VM part alone (also what the re-exec runs)
#   scripts/ksp-gate.sh ci       # the gate as a GitHub Linux runner runs it
#   scripts/ksp-gate.sh ci --scope docs   # prose only; see the scope block below
#   CARGO_TARGET_DIR=/tmp/mine scripts/ksp-gate.sh
#
# The `ci` part exists because the release workflow must not reimplement the
# gate. It runs every check the VM part runs, natively, and adds nothing: a test
# that only CI runs is a test the operator never sees fail. The difference is in
# what each part assumes, not in what it checks — the VM part re-executes into
# colima and expects Valkey and RustFS to be up, because the VM starts them at
# boot; the `ci` part runs where it lands and starts nothing.
#
# The unprivileged and privileged runs use separate target directories on
# purpose: a root-owned `target/` breaks every later non-root build.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# The VM half compiles and runs targets whose subject is a Linux mechanism. On a
# host that is not Linux they either fail to compile or — worse — compile a
# `cfg(target_os = "linux")` branch out and report the host's answer as the
# kernel's. One guard, shared with `scripts/ksp-vm.sh`, refuses instead.
#
# shellcheck source=lib/vm-guard.sh
. "${script_dir}/lib/vm-guard.sh"

# Test targets whose subject is a mechanism a non-Linux host cannot provide, or
# that need root. Everything else is a host target.
#
#   ksp-backend:valkey_durability   needs a running Valkey service
#   ksp:confinement             asserts the Landlock ruleset refused a path
#   ksp:sc008_consume           ditto, through the consume sequence
#   ksp:sc019_separate_process  ditto, across two processes
#   ksp:principals              root to run it, and two operator-provisioned accounts
#                               (KSP_TEST_ADMIN_USER, KSP_TEST_USER; see DEVELOPMENT.md 7.7)
VM_TARGETS=(
    ksp-backend:valkey_durability
    ksp:confinement
    ksp:principals
    ksp:sc008_consume
    ksp:sc019_separate_process
)

is_vm_target() {
    local needle="$1" candidate
    for candidate in "${VM_TARGETS[@]}"; do
        [ "$candidate" = "$needle" ] && return 0
    done
    return 1
}

repo_root="$(cd -- "${script_dir}/.." && pwd)"
cd "$repo_root"

part="${1:-}"

# The scope narrows what the `ci` part runs. It is an argument to this script
# rather than a second script, so there stays exactly one definition of what the
# gate is. `--scope full` is the behaviour every part had before the flag
# existed, and it is the default whenever the scope is not stated.
#
#   docs   prose only: markers, fmt, actionlint. A docs change can still make the
#          documentation claim a control that does not exist, which is why
#          ksp-markers.sh stays in this scope.
#   code   the product: everything except the VM-only targets and principals.
#   full   everything this part can run.
#
# The scope is never widened by this script. A caller that passes `docs` for a
# code change gets a gate that did not check the code, and that is the caller's
# error to make visible — see scripts/ksp-gate-scope.sh, which is the thing that
# classifies and which refuses to narrow on an empty diff.
scope="full"
if [ "${2:-}" = "--scope" ]; then
    scope="${3:?--scope needs a value: docs, code, or full}"
fi
case "$scope" in
    docs|code|full) ;;
    *)
        echo "error: unknown scope '$scope'; use docs, code, or full." >&2
        exit 64
        ;;
esac

if [ -z "$part" ]; then
    if [ "$(uname -s)" = "Linux" ]; then
        # Inside the VM, or on a Linux host: the VM part is what this machine can
        # run, and there is no host part to add to it.
        part="vm"
    else
        part="all"
    fi
fi

target="${CARGO_TARGET_DIR:-/tmp/ksp-gate-target}"
root_target="${KSP_ROOT_TARGET_DIR:-/tmp/ksp-gate-root-target}"

# Incremental artifacts are worth several GiB across the test binaries, and a gate
# run does not benefit from them: the VM's `/tmp` is 19 GiB in total and has
# filled twice during this project, which fails *linking* with an error that names
# neither disk nor target directory.
export CARGO_INCREMENTAL=0

step() {
    phase_close
    phase_name="$*"
    phase_start=$SECONDS
    printf '\n== %s\n' "$*"
}

# Phase timings, printed in the summary.
#
# Without these the next person optimising this gate starts by guessing, which is
# what happened: the first optimisation pass parsed workflow logs to find that
# `principals` spent 73 of its 75 seconds compiling. The gate could have said so.
#
# `$SECONDS` rather than `date`: it is a shell builtin, so it costs nothing and
# cannot fail. It measures whole seconds since shell start, which is the
# resolution this needs.
phase_name=""
phase_start=0
phase_names=()
phase_secs=()

phase_close() {
    [ -n "$phase_name" ] || return 0
    phase_names+=("$phase_name")
    phase_secs+=($((SECONDS - phase_start)))
    phase_name=""
}

phase_summary() {
    phase_close
    [ "${#phase_names[@]}" -gt 0 ] || return 0
    local i total=0
    printf '\n== %s: phase timings\n' "$1"
    for i in "${!phase_names[@]}"; do
        printf '   %-44s %5ss\n' "${phase_names[$i]}" "${phase_secs[$i]}"
        total=$((total + phase_secs[i]))
    done
    printf '   %-44s %5ss\n' "total" "$total"
}

# The VM disk is small enough that a full debug build can nearly fill it, and the
# failure then appears as a linker error naming neither the disk nor the target.
check_disk() {
    local free_kib probe
    # `df` needs a directory that exists, and `${target%/*}` is the *parent* of
    # the target — which is the wrong thing to probe when `target` is a bare
    # relative name like `target`, because `${target%/*}` is then `target`
    # itself and it does not exist yet.
    #
    # That aborted the whole gate with exit 1 and no output, before the first
    # `step` printed: `df` failed, the pipeline's status propagated through the
    # assignment, and `set -e` stopped there. A gate that dies silently is worse
    # than one that warns, so the probe falls back to the nearest directory that
    # does exist.
    probe="${target%/*}"
    [ -d "$probe" ] || probe="."
    free_kib="$(df -Pk "$probe" 2>/dev/null | awk 'NR==2 {print $4}')" || free_kib=""
    if [ -n "${free_kib:-}" ] && [ "$free_kib" -lt $((6 * 1024 * 1024)) ]; then
        printf 'warning: %s has %s MiB free; a debug build of this workspace needs several GiB.\n' \
            "$probe" "$((free_kib / 1024))" >&2
        printf '         A linker failure reading "No space left on device" is disk, not code.\n' >&2
    fi
}

# Every `crate:target` pair the workspace contains, one per line.
all_targets() {
    local file name
    for file in crates/*/tests/*.rs; do
        [ -e "$file" ] || continue
        name="$(basename "$file" .rs)"
        printf '%s:%s\n' "$(basename "$(dirname "$(dirname "$file")")")" "$name"
    done
}

run_target() {
    local pair="$1" crate="${1%%:*}" name="${1##*:}"
    cargo test -p "$crate" --test "$name" --no-fail-fast
}

host_part() {
    check_disk

    # First, because it takes a second and because a status marker without a
    # path is documentation drift rather than a build failure: the spec claims
    # a control exists, and a reader who trusts that claim acts on it. Running
    # it here means the drift fails a build instead of surviving to a review.
    step "host: scripts/ksp-markers.sh"
    ./scripts/ksp-markers.sh --selftest
    ./scripts/ksp-markers.sh

    # A shipped skill is instructions to run `ksp`, so a skill that names a
    # command the binary does not have is a broken product with no compiler to
    # catch it. The build is part of this step, so the binary it checks against is
    # the one this tree produces. Exit 2 means there are no skills yet, which is
    # not a failure.
    # The VM guard is the check that a Linux-only target cannot be run here, and a
    # guard that has never refused is a guard nobody has seen work. Its self-test
    # needs no VM: a fixture `colima` on PATH is the whole environment.
    step "host: scripts/ksp-vm.sh --selftest"
    ./scripts/ksp-vm.sh --selftest
    step "host: scripts/ksp-vm-provision.sh --selftest"
    ./scripts/ksp-vm-provision.sh --selftest

    step "host: scripts/ksp-skills.sh"
    # The binary is built here, into this script's own target directory, because
    # the check reads its command list. `ksp-skills.sh` defaults to
    # `$ROOT/target/debug/ksp`, which this script never writes — every build it
    # runs goes to $target — and a VM run into the repository's target directory
    # leaves an ELF there that no macOS host can execute. The fixture skill was
    # then refused for naming a command the "binary" did not have, so the gate
    # failed before the build that was supposed to precede it.
    CARGO_TARGET_DIR="$target" cargo build -p ksp --bin ksp
    KSP_BIN="$target/debug/ksp" ./scripts/ksp-skills.sh --selftest
    KSP_BIN="$target/debug/ksp" ./scripts/ksp-skills.sh || [ $? -eq 2 ]

    step "host: cargo fmt --check"
    cargo fmt --check

    step "host: cargo clippy --all-targets -- -D warnings"
    CARGO_TARGET_DIR="$target" cargo clippy --all-targets -- -D warnings

    # No root needed and no target dependency: it reads the advisory database and
    # the lockfile.
    step "host: cargo audit"
    cargo audit

    # The unit and documentation tests of every crate. `--no-fail-fast` matters
    # even here: without it a failure in one target hides the ones after it.
    #
    # Each crate is its own command, so `set -e` would end the loop on the first
    # failure — the same defect this script exists to prevent, one level down. A
    # failing target is recorded and the loop continues; the part ends non-zero
    # with every failure named, so a missing service cannot hide 47 targets.
    step "host: tests: unit targets (--no-fail-fast)"
    export CARGO_TARGET_DIR="$target"
    local crate_dir crate pair
    local -a failed=()
    for crate_dir in crates/*/; do
        crate="$(basename "$crate_dir")"
        if ! cargo test -p "$crate" --lib --bins --no-fail-fast; then
            failed+=("$crate:lib")
        fi
    done
    step "host: tests: doc targets (--no-fail-fast)"
    for crate_dir in crates/*/; do
        crate="$(basename "$crate_dir")"
        if ! cargo test -p "$crate" --doc --no-fail-fast; then
            failed+=("$crate:doc")
        fi
    done

    # Every integration target that is not a VM target. A file in neither list is
    # run here, which is the safe direction: it fails loudly rather than being
    # silently skipped.
    step "host: tests: integration targets (--no-fail-fast)"
    while IFS= read -r pair; do
        if is_vm_target "$pair"; then
            continue
        fi
        printf '\n-- %s\n' "$pair"
        if ! run_target "$pair"; then
            failed+=("$pair")
        fi
    done < <(all_targets)

    if [ "${#failed[@]}" -gt 0 ]; then
        printf '\n== host: %d target(s) failed\n' "${#failed[@]}" >&2
        printf '   %s\n' "${failed[@]}" >&2
        return 1
    fi

    # Last, because it is independent of everything above and a failure here
    # should not stop the product's tests from reporting.
    tools_part
}

# Every nested workspace under `tools/`, tested from its own directory.
#
# These are deliberately *not* members of the root workspace: `tools/agent-do`
# must be extractable with `git subtree split`, so it keeps its own Cargo.toml,
# Cargo.lock and lints. The cost of that independence is that the root cargo
# commands cannot see it at all — `cargo build --workspace`,
# `cargo test --workspace`, `cargo clippy --workspace --all-targets` and even
# `cargo fmt --all --check` all exit 0 with the crate deliberately broken.
# Verified. This part is the only thing that notices.
#
# Run in a subshell so the `cd` cannot leak into the rest of the gate, and with
# `&&` rather than separate `step`s so a compile failure does not then produce
# four unrelated failures.
tools_part() {
    local dir found=0
    for dir in tools/*/; do
        # A tools/ entry that is not a workspace (a README, a scratch dir) is
        # skipped rather than failing the gate.
        [ -f "${dir}Cargo.toml" ] || continue
        found=1
        step "tools: ${dir%/} (nested workspace)"
        if ! (
            cd "$dir" || exit 1
            cargo test --lib --bins --no-fail-fast &&
            cargo test --doc --no-fail-fast &&
            cargo clippy --all-targets -- -D warnings &&
            cargo fmt --all --check
        ); then
            return 1
        fi
    done
    [ "$found" -eq 1 ] || printf '\n== tools: no nested workspace present; nothing to run\n'
    return 0
}

vm_part() {
    # Before anything else, including the disk check: a run on the host is not a
    # run that can be trusted, and it must stop before it spends a second on it.
    vm_guard "scripts/ksp-gate.sh vm" "scripts/ksp-gate.sh"

    check_disk
    export CARGO_TARGET_DIR="$target"

    # Clippy again, and this is the copy that matters most: only here are the
    # `cfg(target_os = "linux")` branches compiled and linted at all.
    step "vm: cargo clippy --all-targets -- -D warnings"
    cargo clippy --all-targets -- -D warnings

    # The nested workspaces again, because this is the only place they are
    # built for Linux. `vm_guard` has already refused a run on the host, so this
    # is a real second platform for the portability claim.
    tools_part || return 1

    # Every VM target except the privileged one, and a check that each named
    # target still exists — a name that has rotted would otherwise skip a test
    # without saying so.
    step "vm: tests: Linux-only targets (--no-fail-fast)"
    local pair
    local -a failed=()
    for pair in "${VM_TARGETS[@]}"; do
        if [ "$pair" = "ksp:principals" ]; then
            continue
        fi
        if [ ! -f "crates/${pair%%:*}/tests/${pair##*:}.rs" ]; then
            echo "error: ${pair} is listed as a VM target but has no test file." >&2
            echo "       Move it in scripts/ksp-gate.sh rather than letting it vanish." >&2
            exit 1
        fi
        printf '\n-- %s\n' "$pair"
        if ! run_target "$pair"; then
            failed+=("$pair")
        fi
    done
    if [ "${#failed[@]}" -gt 0 ]; then
        printf '\n== vm: %d Linux-only target(s) failed\n' "${#failed[@]}" >&2
        printf '   %s\n' "${failed[@]}" >&2
        return 1
    fi

    # The two-account boundary. It refuses to run unprivileged, so a missing sudo
    # is a failed gate, not a skipped one.
    step "vm: tests: two-account boundary (root, principals.rs)"
    if [ "$(id -u)" -eq 0 ]; then
        CARGO_TARGET_DIR="$root_target" cargo test -p ksp --test principals --no-fail-fast
    else
        if ! sudo -n true 2>/dev/null; then
            echo "error: the two-account tests need root and 'sudo -n' is unavailable." >&2
            echo "       Run this gate inside the VM, or grant passwordless sudo." >&2
            exit 69
        fi
        sudo -n env \
            HOME="$HOME" \
            PATH="$HOME/.cargo/bin:$PATH" \
            RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
            CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
            CARGO_TARGET_DIR="$root_target" \
            cargo test -p ksp --test principals --no-fail-fast
    fi
}

# The CI part. This is the gate as it runs on a GitHub Actions Linux runner, and
# it exists so that the release workflow and this script cannot disagree about
# what "the gate passed" means.
#
# It is a third part rather than a flag on the VM part because the two differ in
# what they assume, not in what they check:
#
#   * the VM part re-executes into colima, which a runner does not have;
#   * the VM part expects Valkey and RustFS to be running already, because the
#     VM starts them at boot. A runner starts them here, and waits for them.
#
# Everything the VM part checks is checked here. Nothing is added: a test that
# only CI runs is a test the operator never sees fail.
ci_part() {
    check_disk
    export CARGO_TARGET_DIR="$target"

    step "ci: scripts/ksp-markers.sh"
    ./scripts/ksp-markers.sh --selftest
    ./scripts/ksp-markers.sh

    step "ci: cargo fmt --check"
    cargo fmt --check

    # A workflow that GitHub refuses to parse reports `failure` with zero jobs
    # and no annotation, so the only symptom is a release that never starts.
    # That cost sixteen failed tag pushes on the first 1.0.0 attempt. The cause
    # was `${{ env.HOME }}` in a job-level `env:` block, where the `env` context
    # is not available; `actionlint` names that line immediately.
    #
    # Skipped when not installed, because a gate that cannot run is not a gate
    # that failed. `-shellcheck=` disables the shellcheck pass on purpose: those
    # are style findings inside `run:` blocks, they are not why GitHub rejects a
    # file, and they would leave this gate permanently red — which teaches a
    # contributor to ignore it. The expression-context check is the one that
    # matters, and it is the one that would have caught this.
    #
    # Guarded on the directory because the workflows live only in the public
    # tree: this repository has no `.github/workflows/` and `actionlint` exits 3
    # when it finds no file, which would fail the gate in the tree that must not
    # carry a workflow at all.
    if [ -d .github/workflows ]; then
        if command -v actionlint > /dev/null 2>&1; then
            step "ci: actionlint (workflow syntax and expression contexts)"
            actionlint -shellcheck=
        else
            echo "actionlint not installed; skipping workflow lint"
        fi
    else
        echo "no .github/workflows/ here; skipping workflow lint"
    fi

    # The `docs` scope stops here. Prose cannot change what the binary does, but
    # it can change what the documentation claims, and `ksp-markers.sh` above is
    # the check that reads the document. Everything below this point compiles or
    # scans code, and a documentation-only diff cannot affect any of it.
    #
    # The scope is chosen by scripts/ksp-gate-scope.sh from the diff, never by a
    # judgement about what "cannot be affected". A path rule is checkable.
    if [ "$scope" = "docs" ]; then
        printf '\n== ci: scope docs — markers, fmt and workflow lint only\n'
        phase_summary "ci"
        return 0
    fi

    # This is the copy of clippy that matters: only on Linux are the
    # `cfg(target_os = "linux")` branches compiled and linted at all.
    step "ci: cargo clippy --all-targets -- -D warnings"
    cargo clippy --all-targets -- -D warnings

    # Declared here rather than beside the test loop below, because the scanner
    # steps above it also record failures. A `local` used before its declaration
    # is an empty string under `set -u` in some shells and an unbound-variable
    # abort in others, and either way the failure is not counted.
    local -a failed=()
    local crate_dir crate pair

    step "ci: cargo audit"
    cargo audit

    # Dependency review. `cargo vet` needs `supply-chain/config.toml`, which
    # `cargo vet init` writes interactively — see docs/supply-chain-vetting.md.
    #
    # The conditional is not a way to skip the control: before initialisation it
    # would fail for a reason that is not a defect, and a gate that is red for a
    # known non-defect teaches people to ignore it. After initialisation a new
    # unvetted dependency fails the build. The message says which state this is,
    # so the gap is visible rather than a green tick that means nothing.
    step "ci: cargo vet"
    if [ -f supply-chain/config.toml ]; then
        if ! cargo vet --locked; then
            failed+=("cargo-vet")
        fi
        # The exemption count is the size of the review backlog, not a measure of
        # coverage. Printing it means a reader sees how much is unreviewed rather
        # than reading "Vetting Succeeded" as "everything was reviewed".
        exempted=$(grep -c '^\[\[exemptions\.' supply-chain/config.toml || true)
        audited=$(grep -c '^\[\[audits\.' supply-chain/audits.toml 2>/dev/null || true)
        echo "cargo vet: ${exempted} exempted (not reviewed), ${audited} audited"
        if [ "${audited:-0}" -eq 0 ]; then
            echo "           Every dependency is exempted, so the gate enforces"
            echo "           'a new crate needs a decision' and nothing more."
            echo "           docs/supply-chain-vetting.md says how to reduce it."
        fi
    else
        echo "cargo vet: NOT CONFIGURED — no supply-chain/config.toml."
        echo "           Dependency review is not running. See"
        echo "           docs/supply-chain-vetting.md for what enabling it takes."
    fi

    # A second scanner, because the two disagree about what a vulnerability is.
    # `cargo audit` reports the current findings as *warnings* and exits 0;
    # OSV-Scanner reports them as vulnerabilities. Neither is wrong, and the
    # overlap is not total.
    #
    # The severity policy is a separate step: OSV-Scanner has no threshold flag,
    # so it exits 1 on any finding. `osv-gate.py` applies the policy and, on this
    # repository, treats a finding with no analysis conclusion as reachable —
    # the Rust call analysis cannot build this workspace, so every finding
    # arrives without one.
    #
    # `--all-vulns` is required: without it the tool hides the findings the gate
    # exists to see. `--output-file`, not `--output`, which v2.7.1 deprecates.
    step "ci: osv-scanner"
    if command -v osv-scanner >/dev/null 2>&1; then
        osv-scanner scan source \
            --call-analysis=rust --no-call-analysis=go \
            --all-vulns \
            --format=json --output-file=/tmp/ksp-osv.json \
            . >/dev/null 2>&1 || true
        # A missing output file means the scan did not run, which is a gate
        # failure rather than a pass: an empty inventory is not a clean one.
        if [ ! -s /tmp/ksp-osv.json ]; then
            echo "error: osv-scanner produced no output; the scan did not run." >&2
            echo "       An absent result is not a clean result." >&2
            failed+=("osv-scanner")
        elif ! python3 scripts/osv-gate.py /tmp/ksp-osv.json --fail-on high; then
            failed+=("osv-scanner:high")
        fi
    else
        echo "error: osv-scanner is not on PATH." >&2
        echo "       Install it: https://google.github.io/osv-scanner/" >&2
        echo "       A scanner that is absent is not a scanner that passed." >&2
        failed+=("osv-scanner:missing")
    fi

    # One `cargo test` per phase, not one per target.
    #
    # The loop form ran 67 separate `cargo test` invocations and took 6m32s in
    # CI, while the tests themselves execute in about 90 seconds. The other five
    # minutes were cargo's own startup and fingerprint check, paid 67 times.
    #
    # `--no-fail-fast` is what makes this safe: it keeps going after a failing
    # binary and reports every failure, which is the property the loop was
    # written to get. Proven by breaking one test deliberately — the batched run
    # named the test, the file, the line and the target, and still ran the other
    # target:
    #
    #   test deliberate_batch_probe ... FAILED
    #   panicked at crates/ksp-types/tests/fixtures.rs:183:31
    #   error: 1 target failed:
    #
    # The trade-off, stated so it is not discovered later: `failed+=("$crate:lib")`
    # used to record one entry per failing target and the summary printed them
    # all. A batched run exits once, so the summary records the phase rather than
    # each target inside it. The per-target detail is still in the log, in the
    # `error: N target failed:` block cargo prints.
    step "ci: tests: unit targets (--no-fail-fast)"
    if ! cargo test --workspace --lib --bins --no-fail-fast; then
        failed+=("workspace:unit")
    fi

    step "ci: tests: doc targets (--no-fail-fast)"
    if ! cargo test --workspace --doc --no-fail-fast; then
        failed+=("workspace:doc")
    fi

    # Every integration target, including the ones the host part skips. A target
    # named in VM_TARGETS whose file has vanished fails here rather than being
    # skipped, for the same reason the vm part checks it.
    #
    # `ksp:principals` is excluded on purpose: it asserts `geteuid() == 0` and
    # refuses to run otherwise, and this part never invokes `sudo`. It runs once,
    # under sudo, in the step below.
    #
    # It is no longer a *Linux* target. It used to create its two accounts with
    # `useradd`, which does not exist on macOS, so it could not run here at all.
    # Since WP05 of feature 015 the accounts are provisioned by the operator and
    # the suite consumes `KSP_TEST_ADMIN_USER`/`KSP_TEST_USER`, so the reason it
    # stays in `VM_TARGETS` is the missing sudo step, not the platform. The other
    # VM targets really do need a Linux mechanism this host may not have; the `vm`
    # and `ci` parts run them where the mechanism exists.
    #
    # ONE `cargo test` PER PACKAGE, not one for the whole workspace.
    #
    # `-p` and `--test` are **independent global filters**, not pairs. The
    # previous form built one argument list like
    #
    #   -p ksp-posture --test confinement -p ksp --test adapters_five ...
    #
    # which cargo reads as "packages ksp-posture and ksp, targets named
    # confinement or adapters_five" — the cross product, not the pairs. So naming
    # `-p ksp` for one of its targets made EVERY `--test` name match inside `ksp`,
    # including `confinement`, which is a VM target that had been filtered out of
    # the list. On a Linux runner `ksp:confinement` passes and the defect was
    # invisible; on macOS it fails, which is how it was found.
    #
    # Grouping by package keeps the batching (one cargo startup per package
    # rather than per target) and makes the exclusion mean what it says.
    #
    # No associative arrays: macOS ships bash 3.2, where `local -A` is an invalid
    # option and the gate dies with `local: -A: invalid option`. The grouping is
    # done by asking `all_targets` for each package's targets in turn, which is
    # also easier to read than a map.
    step "ci: tests: integration targets (--no-fail-fast)"
    local -a packages=()
    while IFS= read -r pair; do
        if [ "$pair" = "ksp:principals" ]; then
            continue
        fi
        if is_vm_target "$pair"; then
            if [ ! -f "crates/${pair%%:*}/tests/${pair##*:}.rs" ]; then
                echo "error: ${pair} is listed as a VM target but has no test file." >&2
                echo "       Move it in scripts/ksp-gate.sh rather than letting it vanish." >&2
                exit 1
            fi
            # No `part` check here: this function *is* the `ci` part, which runs
            # on a Linux runner where every VM mechanism exists. The `host` part
            # is the one that skips them, and it has its own loop.
            #
            # The `code` scope is the exception, and it is a deliberate one: it
            # is the PR scope, and these targets need a Linux mechanism or root
            # that a PR runner may not have. `full` runs on `main` and on every
            # tag, so a defect they would catch is caught before a release.
            if [ "$scope" = "code" ]; then
                continue
            fi
        fi
        packages+=("${pair%%:*}")
    done < <(all_targets)

    # Deduplicate while keeping order, so the log reads in a stable sequence.
    #
    # `${ordered[@]}` on an empty array is an *unbound variable* under `set -u`
    # in bash 3.2, which macOS ships. `${ordered[@]+"${ordered[@]}"}` is the
    # portable spelling: it expands to nothing when the array is unset or empty.
    local -a ordered=()
    local p q seen
    for p in ${packages[@]+"${packages[@]}"}; do
        seen=0
        for q in ${ordered[@]+"${ordered[@]}"}; do
            if [ "$p" = "$q" ]; then seen=1; break; fi
        done
        [ "$seen" -eq 0 ] && ordered+=("$p")
    done

    local crate name
    local -a crate_tests
    for crate in "${ordered[@]}"; do
        crate_tests=()
        while IFS= read -r pair; do
            [ "${pair%%:*}" = "$crate" ] || continue
            if [ "$pair" = "ksp:principals" ]; then
                continue
            fi
            if is_vm_target "$pair" && [ "$scope" = "code" ]; then
                continue
            fi
            crate_tests+=("--test" "${pair##*:}")
        done < <(all_targets)
        if [ "${#crate_tests[@]}" -eq 0 ]; then
            continue
        fi
        printf '\n-- %s: %s\n' "$crate" "${#crate_tests[@]} arg(s)"
        if ! cargo test -p "$crate" "${crate_tests[@]}" --no-fail-fast; then
            failed+=("$crate:integration")
        fi
    done

    # The two-account boundary, under sudo with its own target directory. A
    # root-owned `target/` breaks every later non-root build, which is why the
    # directory is separate rather than shared.
    #
    # Skipped in the `code` scope for the same reason the VM targets are: it
    # needs root, and it is the slowest thing in the gate because the separate
    # target directory is a second full compile. `main` and every tag run it.
    if [ "$scope" = "code" ]; then
        printf '\n== ci: scope code — skipping the two-account boundary (needs root; runs on main and tags)\n'
    else
        step "ci: tests: two-account boundary (root, principals.rs)"
        if [ "$(id -u)" -eq 0 ]; then
            CARGO_TARGET_DIR="$root_target" cargo test -p ksp --test principals --no-fail-fast \
                || failed+=("ksp:principals")
        else
            if ! sudo -n true 2>/dev/null; then
                echo "error: the two-account tests need root and 'sudo -n' is unavailable." >&2
                echo "       A GitHub runner has passwordless sudo; a local run needs it granted." >&2
                exit 69
            fi
            sudo -n env \
                HOME="$HOME" \
                PATH="$HOME/.cargo/bin:$PATH" \
                RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
                CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
                CARGO_TARGET_DIR="$root_target" \
                cargo test -p ksp --test principals --no-fail-fast \
                || failed+=("ksp:principals")
        fi
    fi

    phase_summary "ci"

    if [ "${#failed[@]}" -gt 0 ]; then
        printf '\n== ci: %d target(s) failed\n' "${#failed[@]}" >&2
        printf '   %s\n' "${failed[@]}" >&2
        return 1
    fi
}

case "$part" in
host)
    host_part
    phase_summary "host"
    printf '\n== host part passed\n'
    # The VM part is deprecated while the product stabilises on macOS, so this
    # message points at the reason rather than implying the run was incomplete by
    # mistake. See AGENTS.md, "Linux support is deprecated".
    printf 'the VM part has not run. It is deprecated: run scripts/ksp-gate.sh vm\n'
    printf 'only when changing the Linux adapters or when Linux returns to scope.\n'
    ;;
vm)
    vm_part
    phase_summary "vm"
    printf '\n== vm part passed\n'
    ;;
ci)
    ci_part
    printf '\n== ci part passed\n'
    ;;
all)
    host_part
    phase_summary "host"
    printf '\n== host part passed; running the VM part\n'
    exec "${script_dir}/ksp-vm.sh" "${script_dir}/ksp-gate.sh" vm
    ;;
*)
    echo "usage: $(basename "$0") [host|vm|ci] [--scope docs|code|full]" >&2
    exit 64
    ;;
esac
