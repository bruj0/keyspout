#!/usr/bin/env bash
#
# ksp-vm.sh — run a command inside the Keyspout Linux VM.
#
# The implementation targets Linux only: `landlock` and `memfd` do not
# compile on macOS, and the Landlock / memfd_secret / mlock guarantees
# cannot be demonstrated off Linux. This script runs a command inside the
# colima VM, with the guest Rust toolchain on PATH.
#
# See docs/development-environment.md for the full environment description.
#
# Usage:
#   scripts/ksp-gate.sh                 # the whole gate (this wrapper + split suite)
#   scripts/ksp-vm.sh cargo test --workspace
#   scripts/ksp-vm.sh cargo fmt --check
#   scripts/ksp-vm.sh cargo clippy --all-targets -- -D warnings
#   scripts/ksp-vm.sh cargo audit
#   scripts/ksp-vm.sh bash -c 'cd .worktrees/001-keyspout-mvp-WP01 && cargo test'
#
# The repository root is the working directory unless the command changes it.
# Only the repository directory is visible inside the VM (the home directory
# is mounted with virtiofs), so worktrees must live under .worktrees/.

set -euo pipefail

if [ "$#" -eq 0 ]; then
    echo "usage: $(basename "$0") <command> [args...]" >&2
    exit 64
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

if ! command -v colima >/dev/null 2>&1; then
    echo "error: colima is not installed; see docs/development-environment.md" >&2
    exit 69
fi

if ! colima status >/dev/null 2>&1; then
    echo "error: the colima VM is not running. Start it with:" >&2
    echo "  colima start --cpu 4 --memory 8 --disk 60 --vm-type=vz --mount-type=virtiofs" >&2
    exit 69
fi

# The guest repository path mirrors the host path: the home directory is
# mounted at the same absolute path inside the VM.
exec colima ssh -- bash -lc "
    set -euo pipefail
    export PATH=\"\$HOME/.cargo/bin:\$PATH\"
    cd '$(printf '%q' "${repo_root}")' && $(printf '%q ' "$@")
"
