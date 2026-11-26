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
#   manifest  the workspace version and nothing else. It still builds, lints and
#          scans, because the version reaches `ksp version` through
#          `env!("CARGO_PKG_VERSION")`; it skips the test battery. See the note in
#          scripts/ksp-gate.sh, which is where the skip is implemented and where
#          the claim that no test asserts a version is written down.
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
#
# `manifest` is only ever reached through `classify_list`, which digs into a
# `Cargo.toml` before giving the whole file a scope. A single `Cargo.toml` path
# on its own is still `code`: classify_path cannot see the diff hunk, so it must
# assume the worst. The narrowing happens where the evidence is.
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

# Whether a changed `Cargo.toml` carries a version change and nothing else.
#
# This is the one narrowing that reads a diff rather than a path, and it earns
# that exception: a release bump is the only change that touches it, it is
# mechanical, and testing it costs the whole battery for two `version =` lines.
#
# The test is deliberately narrow. Every added or removed line that is not the
# workspace version is a reason to fall back to `code`, because any other
# manifest edit — a dependency, a feature, a lint level — can change what
# compiles or what the binary does.
#   $1 the path
#   $2 the ref to diff against, or empty for the working tree
manifest_is_version_only() {
    local path="$1" base="${2:-}" diff added
    diff="$(diff_of "$path" "$base")" || return 1
    [ -n "$diff" ] || return 1

    # Every `+`/`-` line must be the version, and at least one must be.
    #
    # `^version` anchored at the start of the line body: the workspace version is
    # the only bare `version =` in the root manifest. A crate's
    # `version.workspace = true` is a different line and would not match, which is
    # the correct answer — a crate manifest is not the workspace version.
    added="$(changed_lines "$diff")"
    [ -n "$added" ] || return 1
    if printf '%s\n' "$added" | grep -qvE '^[+-]version = "'; then
        return 1
    fi
    return 0
}

# Whether a changed `Cargo.lock` moved only the workspace crates' versions.
#
# It has to be handled, not ignored: a version bump changes the lockfile as well
# as the manifest, and `Cargo.lock` classifies as `code` on its own. Without this
# rule `widen` would push every version bump back up to `code` and the `manifest`
# scope would never be reached — measured, which is why this exists.
#
# Two conditions, both required, because the lockfile holds a `version =` line for
# every one of 300+ dependencies:
#
#   1. every changed line is a `version =` line, and
#   2. every hunk it appears in still names a workspace crate.
#
# (2) is what stops a dependency bump from passing: a `serde` version change also
# satisfies (1), and only the surrounding `name =` line tells the two apart.
lock_is_version_only() {
    local path="$1" base="${2:-}" diff added hunk
    diff="$(diff_of "$path" "$base")" || return 1
    [ -n "$diff" ] || return 1

    added="$(changed_lines "$diff")"
    [ -n "$added" ] || return 1
    if printf '%s\n' "$added" | grep -qvE '^[+-]version = "'; then
        return 1
    fi

    # Every hunk must still name a workspace crate. This is a single `awk` and
    # its exit status rather than a bash loop, because `read` splits on newlines
    # and a hunk is several lines: reading it line by line tested `[[package]]`
    # on its own, which never matches, and rejected every version bump. Measured
    # on the 1.2.0 bump: 8 hunks, all named `ksp*`, reported as not version-only.
    printf '%s\n' "$diff" | awk '
        /^@@/ { if (seen) { total++; if (has) named++ } has = 0; seen = 1; next }
        seen && /^[[:space:]]+name = "ksp/ { has = 1 }
        END {
            if (seen) { total++; if (has) named++ }
            # Success needs at least one hunk and every hunk named.
            exit !(total > 0 && named == total)
        }
    '
}

# The diff of one path against a ref, or against the working tree.
diff_of() {
    local path="$1" base="${2:-}"
    if [ -n "$base" ]; then
        git -C "$repo_root" diff "${base}...HEAD" -- "$path" 2>/dev/null
    else
        git -C "$repo_root" diff HEAD -- "$path" 2>/dev/null
    fi
}

# The added and removed lines of a diff, without the file headers.
changed_lines() {
    printf '%s\n' "$1" | grep -E '^[+-]' | grep -vE '^(\+\+\+|---)' || true
}

# The widest scope in a list. `full` beats `code` beats `manifest` beats `docs`.
#
# The ordering is by how much the scope runs, so `manifest` sits between `docs`
# and `code`: it runs everything `docs` does plus the compiler. Listing the pairs
# rather than ranking numbers keeps it readable, and the selftest proves every
# combination that matters.
widen() {
    local current="$1" next="$2"
    case "$current" in
        full) echo full ;;
        code) [ "$next" = "full" ] && echo full || echo code ;;
        manifest) case "$next" in full|code) echo "$next" ;; *) echo manifest ;; esac ;;
        docs) echo "$next" ;;
        *) echo full ;;
    esac
}

classify_list() {
    local base="${1:-}"
    local scope="docs" path count=0
    local manifest_seen=0 non_manifest_seen=0

    # Two passes over the list, because `widen` cannot undo a `code` that a
    # later path upgrades. A version bump changes `Cargo.toml` and `Cargo.lock`,
    # both of which classify as `code` on their own, and the diff lists them in
    # that order only by luck: measured, `Cargo.lock` arrived first and pushed the
    # scope to `code` before the manifest rule could narrow it.
    #
    # So the content rules are evaluated for the whole list, and a list is
    # `manifest` only when EVERY path narrowed that way. One ordinary `code` path
    # keeps it `code`, which is what makes this safe rather than a way to skip a
    # gate.
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        count=$((count + 1))
        case "$path" in
            Cargo.toml)
                if manifest_is_version_only "$path" "$base"; then
                    manifest_seen=$((manifest_seen + 1))
                else
                    # NOT version-only, so this is an ordinary manifest edit and
                    # takes the ordinary scope. Falling through to `classify_path`
                    # matters: without it the path is counted as "not manifest"
                    # and never classified, leaving the scope at its initial
                    # `docs` — measured, a `license` change beside a version bump
                    # classified as `docs` and would have skipped the compiler,
                    # the scanners and every test.
                    non_manifest_seen=$((non_manifest_seen + 1))
                    scope="$(widen "$scope" "$(classify_path "$path")")"
                fi
                ;;
            Cargo.lock)
                if lock_is_version_only "$path" "$base"; then
                    manifest_seen=$((manifest_seen + 1))
                else
                    non_manifest_seen=$((non_manifest_seen + 1))
                    scope="$(widen "$scope" "$(classify_path "$path")")"
                fi
                ;;
            *)
                non_manifest_seen=$((non_manifest_seen + 1))
                scope="$(widen "$scope" "$(classify_path "$path")")"
                ;;
        esac
    done

    # An empty diff is not a docs change. It means the classification failed,
    # and a failed classification must not narrow the gate.
    if [ "$count" -eq 0 ]; then
        echo full
        return
    fi

    # A version-only release bump: every path narrowed, and at least one did.
    #
    # This is checked before the `docs` short-circuit so a bump that also touches
    # a document stays `manifest` — the documents are still checked by
    # `ksp-markers.sh` in that scope, which is why `widen` ranks manifest above
    # docs.
    if [ "$non_manifest_seen" -eq 0 ] && [ "$manifest_seen" -gt 0 ]; then
        echo manifest
        return
    fi

    # A `docs` scope beside a version-only bump is still a version-only change
    # once the bump is the wider of the two, which `widen` already says.
    if [ "$manifest_seen" -gt 0 ]; then
        scope="$(widen "$scope" manifest)"
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
    # A bare `Cargo.toml` path is still `code`: the content rule needs a base, and
    # classify_path must not guess without one.
    check code "$(classify_path Cargo.toml)" "Cargo.toml as a path"
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

    # `manifest` ordering, which is the part most likely to be got wrong: it is
    # narrower than `code` and wider than `docs`, in both directions.
    check manifest "$(widen manifest docs)" "manifest then docs"
    check manifest "$(widen docs manifest)" "docs then manifest"
    check code "$(widen manifest code)" "manifest then code"
    check code "$(widen code manifest)" "code then manifest"
    check full "$(widen manifest full)" "manifest then full"
    check full "$(widen full manifest)" "full then manifest"

    # The content rules, against real commits rather than a fixture.
    #
    # This is the pair that would fail if either rule were loosened into "any
    # Cargo.toml change is manifest" — the mistake that would let a dependency
    # bump skip the tests. The 1.2.0 bump must narrow; the commit that renamed
    # `ksp-cli` to `ksp` in the same file must not.
    local bump
    bump="$(git -C "$repo_root" log --format=%H --diff-filter=M -1 -- Cargo.toml)"
    if [ -n "$bump" ] && manifest_is_version_only Cargo.toml "${bump}^"; then
        printf 'ok: %s\n' "the last Cargo.toml commit is version-only"
    else
        printf 'FAIL: the last Cargo.toml commit is not version-only\n' >&2
        failures=$((failures + 1))
    fi

    # A manifest change that is not a version bump must be refused. The commit
    # has to be one that genuinely changed something else: the previous release
    # bump also only touched `version =`, so picking "the second-newest" tests
    # the wrong thing and reports a truthful rule as broken.
    #
    # `9b08046` renamed the workspace member `ksp-cli` to `ksp` in the same
    # commit as its version bump, which is exactly the case that must not narrow.
    # Guarded on the commit existing so a shallow clone skips rather than fails.
    if git -C "$repo_root" cat-file -e '9b08046^{commit}' 2>/dev/null; then
        if manifest_is_version_only Cargo.toml '9b08046^'; then
            printf 'FAIL: the version-only rule accepted a manifest change that renamed a crate\n' >&2
            failures=$((failures + 1))
        else
            printf 'ok: %s\n' "a manifest change beyond the version is refused"
        fi
    else
        printf 'skip: %s\n' "the non-version manifest commit is not in this clone"
    fi

    # An empty list must not narrow to docs. This is the one that would turn a
    # broken diff command into a green gate.
    check full "$(printf '' | classify_list)" "an empty diff"

    # A manifest edit that is NOT a version bump must be classified as an
    # ordinary manifest, not counted-and-dropped.
    #
    # This is the regression that shipped into the first version of this rule: a
    # `license` change beside a version bump produced `docs`, because the path was
    # counted as "not manifest" and never reached `classify_path`. `docs` skips
    # the compiler, the scanners and every test, so the mistake would have made a
    # real manifest change the cheapest possible commit.
    if git -C "$repo_root" cat-file -e '9b08046^{commit}' 2>/dev/null; then
        check code "$(printf 'Cargo.toml\n' | classify_list '9b08046^')" \
            "a non-version Cargo.toml is code, not docs"
    fi

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
        git -C "$repo_root" diff --name-only "${base}...HEAD" | classify_list "$base"
        ;;
    --paths)
        file="${2:?--paths needs a file}"
        # No base, so a `Cargo.toml` in this list is classified as `code`: without
        # a diff to read, the content rule cannot run, and a path list is not
        # evidence that the change is version-only.
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
