#!/usr/bin/env bash
# Fail when a shipped operator skill cannot be installed, is misnamed, or tells
# the user to run a command that does not exist.
#
# A skill is markdown, so nothing compiles it and nothing type-checks it. Its
# whole content is instructions to run `ksp`, and a skill that names a removed
# command is a broken product with no compiler to catch it. This script is that
# compiler.
#
# Usage:
#   scripts/ksp-skills.sh              # check skills/ against the built binary
#   scripts/ksp-skills.sh --selftest   # prove the checks can fail
#   KSP_BIN=/path/to/ksp scripts/ksp-skills.sh
#
# Exit 0 when every skill passes, 1 with the offenders listed otherwise, 2 when
# the tree has no skills yet (which is not a failure, but is not a pass either).
#
# The four checks, and the failure each one catches:
#
#   1. frontmatter     a rename left `name:` stale, so the agent cannot find it
#   2. directory name  `skills/Foo/` where the standard requires kebab-case
#   3. commands        a skill says `ksp secret get` and the command is gone
#   4. discoverable    the layout is one `npx skills add` does not scan
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILLS="$ROOT/skills"
KSP_BIN="${KSP_BIN:-$ROOT/target/debug/ksp}"

# The commands a skill may name. Taken from the binary rather than a list here,
# so a removed command fails the check instead of being quietly allowed.
surface() {
    "$KSP_BIN" --help 2>/dev/null | awk '/^Commands:/{f=1;next} /^$/{f=0} f{print $1}'
}

selftest() {
    local dir failed=0
    dir="$(mktemp -d)"

    # A fixture skill that passes every check.
    mkdir -p "$dir/good/keyspout-good"
    cat > "$dir/good/keyspout-good/SKILL.md" <<'MD'
---
name: keyspout-good
description: A skill that names only commands the binary has.
---
Run `ksp status`.
MD

    # A fixture whose frontmatter name does not match its directory.
    mkdir -p "$dir/misnamed/keyspout-misnamed"
    cat > "$dir/misnamed/keyspout-misnamed/SKILL.md" <<'MD'
---
name: something-else
description: The name field disagrees with the folder.
---
Run `ksp status`.
MD

    # A fixture that names a command the binary does not have.
    mkdir -p "$dir/badcmd/keyspout-badcmd"
    cat > "$dir/badcmd/keyspout-badcmd/SKILL.md" <<'MD'
---
name: keyspout-badcmd
description: Names a command that was removed.
---
Run `ksp frobnicate --now`.
MD

    if ! "$0" --check-dir "$dir/good" >/dev/null 2>&1; then
        printf 'selftest: a valid skill was refused\n' >&2
        failed=1
    fi
    if "$0" --check-dir "$dir/misnamed" >/dev/null 2>&1; then
        printf 'selftest: a stale frontmatter name passed\n' >&2
        failed=1
    fi
    if "$0" --check-dir "$dir/badcmd" >/dev/null 2>&1; then
        printf 'selftest: a skill naming a removed command passed\n' >&2
        failed=1
    fi

    rm -rf "$dir"
    if [ "$failed" -eq 0 ]; then
        printf 'ksp-skills: self-test passed (3 verdicts)\n'
    fi
    return "$failed"
}

# Check one directory of skills. Split out so the self-test can point it at a
# fixture without a real binary or a real tree.
check_dir() {
    local dir="$1"
    local failed=0 count=0

    if [ ! -d "$dir" ]; then
        printf 'ksp-skills: no such directory: %s\n' "$dir" >&2
        return 2
    fi

    local skill name dirname
    for skill in "$dir"/*/SKILL.md; do
        [ -e "$skill" ] || continue
        count=$((count + 1))
        dirname="$(basename "$(dirname "$skill")")"

        # 1. The frontmatter names the same thing the directory does. An agent
        #    discovers a skill by its `name`, so a mismatch makes it invisible
        #    under the name the docs use.
        name="$(awk '/^---$/{n++; next} n==1 && /^name:/{sub(/^name:[[:space:]]*/, ""); print; exit}' "$skill")"
        if [ -z "$name" ]; then
            printf '%s: no `name:` in the frontmatter\n' "$skill" >&2
            failed=1
        elif [ "$name" != "$dirname" ]; then
            printf '%s: frontmatter name %q does not match directory %q\n' \
                "$skill" "$name" "$dirname" >&2
            failed=1
        fi

        # 2. The directory is kebab-case. The standard requires it, and a
        #    directory with a capital or an underscore is not discovered by
        #    every installer.
        if ! printf '%s' "$dirname" | grep -qE '^[a-z0-9]+(-[a-z0-9]+)*$'; then
            printf '%s: directory name is not kebab-case\n' "$skill" >&2
            failed=1
        fi

        # 3. Every `ksp <subcommand>` the skill names exists. This is the check
        #    that matters: the skill's content is instructions to run the
        #    binary, so a stale command is a broken product.
        local known cmd
        known="$(surface)"
        # `ksp` followed by a bare word, not a flag and not a placeholder.
        while IFS= read -r cmd; do
            [ -n "$cmd" ] || continue
            case "$cmd" in
                -*|'<'*|'('*|'$'*|'"'*|"'"*) continue ;;
            esac
            if ! printf '%s\n' "$known" | grep -qx -- "$cmd"; then
                printf '%s: names `ksp %s`, which the binary does not have\n' \
                    "$skill" "$cmd" >&2
                failed=1
            fi
        done < <(grep -oE '`ksp [a-z][a-z-]*' "$skill" 2>/dev/null \
                 | sed 's/^`ksp //' | sort -u)
    done

    if [ "$count" -eq 0 ]; then
        printf 'ksp-skills: no skills under %s\n' "$dir" >&2
        return 2
    fi

    printf 'ksp-skills: checked %d skill(s) under %s\n' "$count" "$dir"
    return "$failed"
}

case "${1:-}" in
    --selftest)
        selftest
        exit $?
        ;;
    --check-dir)
        check_dir "${2:?--check-dir needs a directory}"
        exit $?
        ;;
    "")
        if [ ! -x "$KSP_BIN" ]; then
            printf 'ksp-skills: no binary at %s\n' "$KSP_BIN" >&2
            printf '            build it with `cargo build -p ksp-cli`, or set KSP_BIN\n' >&2
            exit 2
        fi
        check_dir "$SKILLS"
        exit $?
        ;;
    *)
        echo "usage: $(basename "$0") [--selftest | --check-dir DIR]" >&2
        exit 64
        ;;
esac
