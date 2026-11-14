#!/usr/bin/env bash
# Fail when a status marker in the design spec carries no evidence.
#
# A status marker is a claim a reader will act on: `[Implemented]` says the
# control exists in the merged tree. A claim with no file beside it cannot be
# checked, and a claim that cannot be checked is the drift this project exists to
# remove. This script does not decide whether the cited file *implements* the
# claim — only a reader can. It decides whether the claim carries a citation that
# resolves.
#
# Usage:
#   scripts/ksp-markers.sh [spec-path]
#
# Exit 0 when every marked block carries a resolving path, or the fixed token
# `no file` with its reason. Exit 1 and list the offenders otherwise.
set -euo pipefail

SPEC="${1:-docs/keyspout-design-spec.md}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The rules below were wrong twice before they were right: a line rule reported
# 87 offenders where 33 blocks lacked evidence, and a block-wide `no file` rule
# flagged an honest table. Each mistake was caught by hand, which is not a
# safeguard. This self-test pins all three verdicts so the next edit to a rule
# fails here rather than in a review.
selftest() {
    local dir failed=0
    dir="$(mktemp -d)"
    # The cited path must be repo-relative and carry a slash: a bare `mint.rs`
    # names no file any reader could open, and the spec's blocks that use one
    # also name a full path.
    printf '| a | **[Implemented]** — `crates/ksp-types/Cargo.toml` |\n' > "$dir/evidenced.md"
    printf '| a | **[Implemented]** |\n' > "$dir/unchecked.md"
    printf '| a | **[Implemented]** — no file: nothing here |\n' > "$dir/escape.md"
    printf '| a | **[Not implemented]** — no file: it does not exist |\n' > "$dir/absent.md"

    if ! "$0" "$dir/evidenced.md" >/dev/null; then
        printf 'selftest: a marker that names a resolving path was refused\n' >&2
        failed=1
    fi
    if "$0" "$dir/unchecked.md" >/dev/null; then
        printf 'selftest: a marker with no path passed\n' >&2
        failed=1
    fi
    if "$0" "$dir/escape.md" >/dev/null; then
        printf 'selftest: `no file` excused an [Implemented] claim\n' >&2
        failed=1
    fi
    if ! "$0" "$dir/absent.md" >/dev/null; then
        printf 'selftest: `no file` was refused on a claim that nothing exists\n' >&2
        failed=1
    fi

    rm -rf "$dir"
    if [ "$failed" -eq 0 ]; then
        printf 'ksp-markers: self-test passed (4 verdicts)\n'
    fi
    return "$failed"
}

if [ "$SPEC" = "--selftest" ]; then
    selftest
    exit $?
fi

if [ ! -f "$ROOT/$SPEC" ] && [ ! -f "$SPEC" ]; then
    echo "ksp-markers: no such spec: $SPEC" >&2
    exit 2
fi

python3 - "$ROOT" "$SPEC" <<'PY'
"""Check every marked block for evidence.

# What counts as a block

A claim can wrap. A `> **Status: ...**` blockquote runs over four lines, and a
table row is one claim in one line. Treating a line as the unit would report 87
failures and force cosmetic rewraps; treating a paragraph, a blockquote run and
a table row as the unit reports the claims that genuinely lack a citation.

# What counts as evidence

A backticked path that resolves. Or the fixed token `no file`, for a claim that
by construction has no implementing file — a description, an argument, or a
mechanism the design refuses. That token is not an escape hatch: it must appear
with its reason, a reader sees both, and it is refused outright on a line marked
`[Implemented]` or `[Partial]`, because those two say something exists.

# What is not a path

A URL (`syslog://`) and a store prefix (`p/`) both contain a slash. Neither is a
file, and treating either as one produces a false failure on an honest line.
"""

import os
import re
import sys

root, spec = sys.argv[1], sys.argv[2]
path = os.path.join(root, spec) if not os.path.isabs(spec) else spec

MARKER = re.compile(r"\[(Implemented|Partial|Not implemented|Absent by decision|Design only)\]")
BACKTICK = re.compile(r"`([^`]+)`")
# The legend's own rows define the markers; they are not claims about the tree.
LEGEND = re.compile(r"^\| \*\*\[(Implemented|Partial|Not implemented|Absent by decision|Design only)\]\*\* \|")
NO_FILE = re.compile(r"no file", re.I)
# A marker that asserts nothing exists has no file by construction. A marker
# that asserts something does exist cannot use `no file` to escape the check.
NO_FILE_MARKERS = {"Not implemented", "Absent by decision", "Design only"}


def block_kind(line):
    stripped = line.strip()
    if not stripped:
        return "blank"
    if stripped.startswith("#"):
        return "heading"
    if stripped.startswith("|"):
        return "row"
    if stripped.startswith(">"):
        return "quote"
    if stripped.startswith("```"):
        return "fence"
    return "text"


def blocks(lines):
    """Yield (first_line_number, text) for each claim block."""
    current, fenced = [], False

    def flush():
        if current:
            yield_blocks.append((current[0][0], "\n".join(text for _, text in current)))
            current.clear()

    yield_blocks = []
    for number, line in enumerate(lines, 1):
        kind = block_kind(line)
        if kind == "fence" or fenced:
            flush()
            yield_blocks.append((number, line))
            if kind == "fence":
                fenced = not fenced
            continue
        if kind in ("blank", "heading", "row"):
            flush()
            if kind == "row":
                yield_blocks.append((number, line))
            continue
        if current and block_kind(current[-1][1]) != kind:
            flush()
        current.append((number, line))
    flush()
    return yield_blocks


def cited_paths(text):
    out = []
    for candidate in BACKTICK.findall(text):
        if "://" in candidate:
            continue
        # `p/` is a store prefix and `crates/ksp-record/src/` is a directory. The
        # first names no file and cannot be checked; the second can.
        if candidate.endswith("/") and "/" not in candidate[:-1]:
            continue
        if "/" in candidate or candidate.endswith((".rs", ".sh", ".md", ".json", ".toml")):
            out.append(candidate)
    return out


with open(path, encoding="utf-8") as handle:
    lines = handle.read().split("\n")

offenders = []
for start, text in blocks(lines):
    markers = set(MARKER.findall(text))
    if not markers:
        continue
    if LEGEND.match(text.split("\n")[0].strip()):
        continue

    # `no file` is an answer for a claim that nothing exists. It is not an
    # escape from evidence for a claim that something does, so a line pairing
    # it with `[Implemented]` or `[Partial]` is a contradiction, not a pass.
    #
    # The pairing is per line, not per block. A blockquote that carries a table
    # holds several claims: its Phase 4 row says `[Not implemented] — no file`
    # while the rows above it name real crates, and judging the block as one
    # claim would flag an honest document.
    contradiction = None
    for line in text.split("\n"):
        if not NO_FILE.search(line):
            continue
        escaped = sorted(set(MARKER.findall(line)) - NO_FILE_MARKERS)
        if escaped:
            contradiction = (line.strip(), ", ".join(escaped))
            break
    if contradiction:
        offenders.append((start, contradiction[0], f"says `no file` while marked {contradiction[1]}"))
        continue

    if NO_FILE.search(text):
        continue

    whole = [c for c in cited_paths(text) if "/" in c]
    if whole and all(os.path.exists(os.path.join(root, c.rstrip("/"))) for c in whole):
        continue
    first = text.split("\n")[0].strip()
    offenders.append((start, first, "carries no resolvable path"))

if offenders:
    print(f"ksp-markers: {len(offenders)} marker block(s) lack evidence:")
    for start, first, reason in offenders:
        print(f"  {spec}:{start}: {reason}\n    {first[:110]}")
    print(
        "\nAdd the file that implements the claim, or `no file` with the reason "
        "the claim has none. `no file` belongs to a claim that nothing exists."
    )
    sys.exit(1)

print(f"ksp-markers: every marker block in {spec} carries evidence")
PY
