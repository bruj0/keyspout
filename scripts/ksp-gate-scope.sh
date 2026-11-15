#!/usr/bin/env bash
#
# ksp-gate-scope.sh — classify a diff into a gate scope.
#
# Why this exists. Every PR used to run the full gate, so a README typo paid the
# same five minutes as a change to the memory barrier. That teaches people to
# batch unrelated changes, and a gate people stop watching is a gate that stops
# working.
#
# The classification is by **what changed**, never by what someone believes is
# unaffected. A path rule is checkable; a belief is not. The default for anything
# unrecognised is `full`, because a scope that silently widened would be worse
# than no split at all.
#
# Usage:
#
#   scripts/ksp-gate-scope.sh                 # classify the working tree against HEAD
#   scripts/ksp-gate-scope.sh --base <rev>    # classify <rev>..HEAD (a PR)
#   scripts/ksp-gate-scope.sh --paths <file>  # classify a newline-separated list
#   scripts/ksp-gate-scope.sh --selftest      # prove the classifier discriminates
#
# Prints exactly one of `docs`, `code`, `full` on stdout, and nothing else.
#
# The scopes, from narrowest to widest:
#
#   docs   documentation only. Prose cannot change what the binary does, but it
#          can change what the documentation *claims*, so `ksp-markers.sh` stays
#          in this scope — it is the check that reads the document.
#   code   the product: crates, manifests, the lockfile, the gate itself.
#   full   everything, including the workflow definitions and anything unknown.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

# A path that decides the scope on its own, widest first. The first match wins,
# so `full` patterns must be tested before `code` ones.
#
# `.github/` is `full` because a workflow change can alter what the gate *is*:
# a narrower scope for a workflow edit would let a PR weaken its own gate.
classify_path() {
    local p="$1"
    case "$p" in
        # Anything that can change what runs, or weaken the gate itself.
        .github/*|.github) echo full; return ;;
        scripts/ksp-gate.sh|scripts/ksp-gate-scope.sh|scripts/ksp-vm.sh) echo full; return ;;
        scripts/public/*) echo full; return ;;
        # The product.
        crates/*|Cargo.toml|Cargo.lock|rust-toolchain.toml|dist-workspace.toml) echo code; return ;;
        scripts/*) echo code; return ;;
        # Documentation and assets. Prose, diagrams, and the licence.
        *.md|docs/*|assets/*|LICENSE|SECURITY.md) echo docs; return ;;
        # Anything else is unknown, and unknown is not narrow.
        *) echo full; return ;;
    esac
}

# The widest scope in a list. `full` beats `code` beats `docs`.
widen() {
    local current="$1" next="$2"
    case "$current" in
        full) echo full ;;
        code) [ "$next" = "full" ] && echo full || echo code ;;
        docs) echo "$next" ;;
        *) echo full ;;
    esac
}

classify_list() {
    local scope="docs" path count=0
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        count=$((count + 1))
        scope="$(widen "$scope" "$(classify_path "$path")")"
    done
    # An empty diff is not a docs change. It means the classification failed,
    # and a failed classification must not narrow the gate.
    if [ "$count" -eq 0 ]; then
        echo full
        return
    fi
    echo "$scope"
}

selftest() {
    local failures=0
    check() {
        local want="$1" got="$2" what="$3"
        if [ "$want" != "$got" ]; then
            printf 'FAIL: %s: want %s, got %s\n' "$what" "$want" "$got" >&2
            failures=$((failures + 1))
        else
            printf 'ok: %s -> %s\n' "$what" "$got"
        fi
    }

    # Single paths, one per scope.
    check docs "$(classify_path README.md)" "README.md"
    check docs "$(classify_path docs/known-defects.md)" "docs/known-defects.md"
    check code "$(classify_path crates/ksp/src/app.rs)" "crates/ksp/src/app.rs"
    check code "$(classify_path Cargo.lock)" "Cargo.lock"
    check full "$(classify_path .github/workflows/release.yml)" "a workflow"
    check full "$(classify_path scripts/ksp-gate.sh)" "the gate itself"
    check full "$(classify_path some/unknown/file.bin)" "an unknown path"

    # Widening. A docs change beside a code change is a code change, and a code
    # change beside a workflow change is a full run. Testing only the single-path
    # cases would pass a classifier that returned the FIRST match instead of the
    # widest, which is the defect that would let a workflow edit ride in on a
    # README change.
    check docs "$(printf 'README.md\ndocs/a.md\n' | classify_list)" "two docs files"
    check code "$(printf 'README.md\ncrates/ksp/src/app.rs\n' | classify_list)" "docs then code"
    check code "$(printf 'crates/ksp/src/app.rs\nREADME.md\n' | classify_list)" "code then docs"
    check full "$(printf 'crates/ksp/src/app.rs\n.github/workflows/release.yml\n' | classify_list)" "code then workflow"
    check full "$(printf '.github/workflows/release.yml\nREADME.md\n' | classify_list)" "workflow then docs"

    # An empty list must not narrow to docs. This is the one that would turn a
    # broken diff command into a green gate.
    check full "$(printf '' | classify_list)" "an empty diff"

    if [ "$failures" -gt 0 ]; then
        printf '\n%s selftest check(s) failed\n' "$failures" >&2
        return 1
    fi
    printf '\nall scope checks passed\n'
}

case "${1:-}" in
    --selftest)
        selftest
        ;;
    --base)
        base="${2:?--base needs a revision}"
        git -C "$repo_root" diff --name-only "${base}...HEAD" | classify_list
        ;;
    --paths)
        file="${2:?--paths needs a file}"
        classify_list < "$file"
        ;;
    "")
        # The working tree against HEAD, plus untracked files. A new file is a
        # change, and `git diff` alone would miss it.
        {
            git -C "$repo_root" diff --name-only HEAD
            git -C "$repo_root" ls-files --others --exclude-standard
        } | classify_list
        ;;
    *)
        echo "usage: $(basename "$0") [--base <rev> | --paths <file> | --selftest]" >&2
        exit 64
        ;;
esac
