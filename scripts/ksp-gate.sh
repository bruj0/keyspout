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
# and that list can never be green here. `crates/ksp-cli/tests/principals.rs`
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

# Test targets whose subject is a mechanism a non-Linux host cannot provide, or
# that need root. Everything else is a host target.
#
#   ksp-backend:valkey_durability   needs a running Valkey service
#   ksp-cli:confinement             asserts the Landlock ruleset refused a path
#   ksp-cli:sc008_consume           ditto, through the consume sequence
#   ksp-cli:sc019_separate_process  ditto, across two processes
#   ksp-cli:principals              two UNIX accounts, and root to create them
VM_TARGETS=(
    ksp-backend:valkey_durability
    ksp-cli:confinement
    ksp-cli:principals
    ksp-cli:sc008_consume
    ksp-cli:sc019_separate_process
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
    printf '\n== %s\n' "$*"
}

# The VM disk is small enough that a full debug build can nearly fill it, and the
# failure then appears as a linker error naming neither the disk nor the target.
check_disk() {
    local free_kib
    free_kib="$(df -Pk "${target%/*}" 2>/dev/null | awk 'NR==2 {print $4}')"
    if [ -n "${free_kib:-}" ] && [ "$free_kib" -lt $((6 * 1024 * 1024)) ]; then
        printf 'warning: %s has %s MiB free; a debug build of this workspace needs several GiB.\n' \
            "${target%/*}" "$((free_kib / 1024))" >&2
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
    # catch it. This runs after the build so the binary it checks against is the
    # one in this tree. Exit 2 means there are no skills yet, which is not a
    # failure.
    step "host: scripts/ksp-skills.sh"
    ./scripts/ksp-skills.sh --selftest
    ./scripts/ksp-skills.sh || [ $? -eq 2 ]

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
}

vm_part() {
    check_disk
    export CARGO_TARGET_DIR="$target"

    # Clippy again, and this is the copy that matters most: only here are the
    # `cfg(target_os = "linux")` branches compiled and linted at all.
    step "vm: cargo clippy --all-targets -- -D warnings"
    cargo clippy --all-targets -- -D warnings

    # Every VM target except the privileged one, and a check that each named
    # target still exists — a name that has rotted would otherwise skip a test
    # without saying so.
    step "vm: tests: Linux-only targets (--no-fail-fast)"
    local pair
    local -a failed=()
    for pair in "${VM_TARGETS[@]}"; do
        if [ "$pair" = "ksp-cli:principals" ]; then
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
        CARGO_TARGET_DIR="$root_target" cargo test -p ksp-cli --test principals --no-fail-fast
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
            cargo test -p ksp-cli --test principals --no-fail-fast
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

    step "ci: tests: unit targets (--no-fail-fast)"
    for crate_dir in crates/*/; do
        crate="$(basename "$crate_dir")"
        if ! cargo test -p "$crate" --lib --bins --no-fail-fast; then
            failed+=("$crate:lib")
        fi
    done

    step "ci: tests: doc targets (--no-fail-fast)"
    for crate_dir in crates/*/; do
        crate="$(basename "$crate_dir")"
        if ! cargo test -p "$crate" --doc --no-fail-fast; then
            failed+=("$crate:doc")
        fi
    done

    # Every integration target, including the ones the host part skips. A target
    # named in VM_TARGETS whose file has vanished fails here rather than being
    # skipped, for the same reason the vm part checks it.
    #
    # `ksp-cli:principals` is excluded from this loop on purpose: it asserts
    # `geteuid() == 0` and refuses to run otherwise, so running it here would
    # fail every time. It runs once, under sudo, in the step below.
    step "ci: tests: integration targets (--no-fail-fast)"
    while IFS= read -r pair; do
        if [ "$pair" = "ksp-cli:principals" ]; then
            continue
        fi
        if is_vm_target "$pair"; then
            if [ ! -f "crates/${pair%%:*}/tests/${pair##*:}.rs" ]; then
                echo "error: ${pair} is listed as a VM target but has no test file." >&2
                echo "       Move it in scripts/ksp-gate.sh rather than letting it vanish." >&2
                exit 1
            fi
        fi
        printf '\n-- %s\n' "$pair"
        if ! run_target "$pair"; then
            failed+=("$pair")
        fi
    done < <(all_targets)

    # The two-account boundary, under sudo with its own target directory. A
    # root-owned `target/` breaks every later non-root build, which is why the
    # directory is separate rather than shared.
    step "ci: tests: two-account boundary (root, principals.rs)"
    if [ "$(id -u)" -eq 0 ]; then
        CARGO_TARGET_DIR="$root_target" cargo test -p ksp-cli --test principals --no-fail-fast \
            || failed+=("ksp-cli:principals")
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
            cargo test -p ksp-cli --test principals --no-fail-fast \
            || failed+=("ksp-cli:principals")
    fi

    if [ "${#failed[@]}" -gt 0 ]; then
        printf '\n== ci: %d target(s) failed\n' "${#failed[@]}" >&2
        printf '   %s\n' "${failed[@]}" >&2
        return 1
    fi
}

case "$part" in
host)
    host_part
    printf '\n== host part passed\n'
    printf 'the VM part has not run: run scripts/ksp-gate.sh for the whole gate.\n'
    ;;
vm)
    vm_part
    printf '\n== vm part passed\n'
    ;;
ci)
    ci_part
    printf '\n== ci part passed\n'
    ;;
all)
    host_part
    printf '\n== host part passed; running the VM part\n'
    exec "${script_dir}/ksp-vm.sh" "${script_dir}/ksp-gate.sh" vm
    ;;
*)
    echo "usage: $(basename "$0") [host|vm|ci]" >&2
    exit 64
    ;;
esac
