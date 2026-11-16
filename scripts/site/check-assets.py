#!/usr/bin/env python3
"""Check that the site's scripts are registered, present and in order.

# Why

`site/mkdocs.yml` names its stylesheets and scripts in `extra_css` and
`extra_javascript`, and MkDocs copies whatever it finds in `site/docs/` whether
or not anything names it. So a file can be added, committed, published - and
never loaded. Nothing says so: the page renders, it is simply missing a
behaviour.

That is not hypothetical here. The site shipped with its diagrams invisible
because `mermaid.min.js` was never registered: MkDocs turned every ```mermaid
fence into `<pre class="mermaid">` and stopped, and the reader got the diagram's
source in a grey box. Every other check passed, because every other check asks
about the *markdown*, and this was a question about the *configuration*.

Order matters too, and it fails the same silent way. A library has to be
registered before the script that uses it, so `mermaid.min.js` and
`panzoom.min.js` must come before `diagram-zoom.js`. Reversed, the consuming
script runs first, finds no global, and returns early - which looks like a
script that does nothing.

# What it checks

* every entry in `extra_css` and `extra_javascript` exists under `site/docs/`;
* the vendored libraries are registered at all;
* each library is registered before its consumer.

It reads `site/mkdocs.yml` as text rather than through a YAML parser, so it
needs nothing installed beyond Python. The file is a flat list of paths under
two known keys; a regex is enough, and it keeps this check runnable in a bare
checkout.

    scripts/site/check-assets.py
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent

# The keys that name a file, and the directory those names resolve against.
KEYS = ("extra_css", "extra_javascript")
DOCS = "site/docs"

# A list entry: two spaces of indent, a dash, then a bare path. A quoted entry
# with a URL in it is not one of ours and is skipped by the `://` test.
ENTRY = re.compile(r"^\s{2,}-\s+(\S+)\s*$")

# Each library and the script that cannot work without it.
LIBRARIES = {
    "media/mermaid.min.js": "media/diagram-zoom.js",
    "media/panzoom.min.js": "media/diagram-zoom.js",
}


def entries(text: str) -> list[tuple[str, str]]:
    """`(key, path)` for every file the configuration names, in file order."""
    found: list[tuple[str, str]] = []
    key = ""
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith(":"):
            name = stripped[:-1].strip()
            key = name if name in KEYS else ""
            continue
        if not key:
            continue
        match = ENTRY.match(line)
        if not match:
            # A list ended: the next top-level key.
            key = ""
            continue
        path = match.group(1)
        if "://" in path:
            continue
        found.append((key, path))
    return found


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO / "site",
        help=f"The site directory holding mkdocs.yml. Default: {REPO / 'site'}",
    )
    args = parser.parse_args(argv)

    config = args.root / "mkdocs.yml"
    if not config.is_file():
        print(f"error: {config} does not exist", file=sys.stderr)
        return 1

    listed = entries(config.read_text(encoding="utf-8"))
    problems: list[str] = []

    for key, path in listed:
        target = args.root / "docs" / path
        if not target.is_file():
            problems.append(f"{key} names {path}, which is not at {target}")

    order = [path for key, path in listed if key == "extra_javascript"]

    for library, consumer in LIBRARIES.items():
        if library not in order:
            problems.append(
                f"{library} is not in extra_javascript. A script nobody loads "
                "is a behaviour the page silently lacks."
            )
            continue
        if consumer in order and order.index(library) > order.index(consumer):
            problems.append(
                f"{library} is registered after {consumer}. The consumer runs "
                "first, finds no global, and does nothing."
            )

    if problems:
        print(f"error: {len(problems)} problem(s) in {config}:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print(f"checked {len(listed)} asset(s) in {config.name}: all registered, in order")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
