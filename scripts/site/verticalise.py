#!/usr/bin/env python3
"""Make the site's diagrams vertical, without changing what they say.

# Why

Several of the diagrams are wider than the content column. A reader on a
narrow screen scrolls sideways to reach the right-hand end, and a diagram
that is 2000 pixels wide is a diagram nobody reads.

Mermaid lays a diagram out with dagre, and dagre puts **sibling** subgraphs in
a row. The way to make a diagram narrow is therefore not to shrink it but to
*chain* its subgraphs, so each one hangs below the last instead of beside
it.

# What this script does

For each diagram it is told about:

1. it inserts `direction TB` as the first line of every named subgraph, so
   the nodes inside one stack vertically;
2. it appends edges between the subgraphs, in the order it is given, so the
   subgraphs themselves stack vertically.

Both changes are **additive**. The script never removes or rewrites a line
that names a node or an edge, because a transformation that drops a node
silently changes what the diagram says. An earlier attempt at this rewrote
the subgraph bodies and emptied five of them; the diagrams still parsed and
still rendered, and they said nothing at all.

# Usage

    scripts/site/verticalise.py --check
    scripts/site/verticalise.py
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
SITE = REPO / "site" / "docs"

# The diagrams to make vertical.
#
# Each entry is: the file, the one-based index of the diagram in that file,
# and the subgraph ids in the order they should hang.
#
# The order is the *reading* order, not the dependency order: the diagram
# should read top to bottom the way the prose does.
VERTICAL: dict[tuple[str, int], list[str]] = {
    ("index.md", 2): ["Top", "Domain", "Storage", "Base"],
    ("architecture/overview.md", 2): ["Host", "Storage", "Keys"],
    ("architecture/overview.md", 3): [
        "CLI",
        "IDENTITY",
        "RECORD",
        "STORAGE",
        "EVIDENCE",
        "HOST",
    ],
    ("components/ksp-cli.md", 1): ["CLI", "Feature", "Runpath", "Host"],
    ("components/ksp-backend.md", 1): [
        "Contract",
        "Backends",
        "Decision",
        "Configuration",
    ],
    ("components/ksp-deletion.md", 1): [
        "Evidence",
        "Durable",
        "Verify",
        "Use",
    ],
    ("components/ksp-identity.md", 1): ["Enrol", "Auth", "Use", "Mint"],
    ("components/ksp-posture.md", 1): ["Model", "Resolve", "Platform"],
}

FENCE = "```mermaid"
END = "```"


def blocks(text: str) -> list[str]:
    """The bodies of every mermaid fence, in order."""
    return [m.strip("\n") for m in re.findall(re.escape(FENCE) + r"\n(.*?)\n" + re.escape(END), text, re.DOTALL)]


def subgraph_body(lines: list[str], start: int) -> tuple[list[str], int]:
    """The lines of the subgraph that starts at `start`, and the index after it.

    `start` is the index of the line *after* the `subgraph` line. The
    subgraph ends at the `end` that closes it, which is found by counting
    the nesting depth: a `subgraph` opens one and an `end` closes one.

    The body is every line between the two, and every one of them is
    returned. A version of this function that dropped the `end` lines
    emptied five subgraphs, and the diagrams still parsed and still
    rendered, and they said nothing at all.
    """
    body: list[str] = []
    depth = 1
    index = start
    while index < len(lines):
        line = lines[index]
        if re.match(r"\s*subgraph\b", line):
            depth += 1
        elif line.strip() == "end":
            depth -= 1
            if depth == 0:
                return body, index + 1
        body.append(line)
        index += 1
    return body, index


def transform(block: str, order: list[str]) -> str:
    """Add `direction TB` to the named subgraphs and chain them."""
    lines = block.split("\n")

    # 1. Insert `direction TB` as the first line of each named subgraph.
    result: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        result.append(line)
        match = re.match(r"(\s*)subgraph\s+(\w+)\[", line)
        if match and match.group(2) in order:
            body, after = subgraph_body(lines, index + 1)
            # The body is re-emitted verbatim. Nothing is removed.
            if not any(b.strip() == "direction TB" for b in body):
                result.append(f"{match.group(1)}    direction TB")
            result.extend(body)
            # `after` is the index of the `end` line, which was consumed by
            # `subgraph_body`. It is re-emitted here, so the subgraph is
            # still closed.
            if after <= len(lines):
                result.append(lines[after - 1])
            index = after
            continue
        index += 1

    lines = result

    # 2. Chain the subgraphs, unless the chain is already there.
    edges = []
    for first, second in zip(order, order[1:]):
        edge = f"  {first} --> {second}"
        if edge not in lines:
            edges.append(edge)

    if edges:
        # The edges go after the last line of the diagram, which is the
        # closing fence's line before it: the diagram body ends at the last
        # non-empty line.
        while lines and not lines[-1].strip():
            lines.pop()
        lines.extend(edges)

    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if a diagram is not yet vertical. Writes nothing.",
    )
    args = parser.parse_args(argv)

    changed: list[str] = []
    failed = 0

    for (relative, number), order in VERTICAL.items():
        path = SITE / relative
        if not path.is_file():
            print(f"error: {path} does not exist", file=sys.stderr)
            failed += 1
            continue

        text = path.read_text(encoding="utf-8")
        bodies = blocks(text)
        if number > len(bodies):
            print(
                f"error: {relative} has {len(bodies)} diagram(s), "
                f"not {number}",
                file=sys.stderr,
            )
            failed += 1
            continue

        original = bodies[number - 1]
        updated = transform(original, order)

        if updated == original:
            continue

        # Replace exactly this block, once.
        replaced = text.replace(original, updated, 1)
        if replaced == text:
            print(f"error: could not replace the block in {relative}", file=sys.stderr)
            failed += 1
            continue

        changed.append(f"{relative}:{number}")
        if not args.check:
            path.write_text(replaced, encoding="utf-8")

    if args.check:
        if changed:
            print(
                f"error: {len(changed)} diagram(s) are not vertical:",
                file=sys.stderr,
            )
            for item in changed:
                print(f"  {item}", file=sys.stderr)
            return 1
        print("every named diagram is vertical")
        return 0

    print(f"made {len(changed)} diagram(s) vertical")
    for item in changed:
        print(f"  {item}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
