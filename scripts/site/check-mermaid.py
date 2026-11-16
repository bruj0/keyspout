#!/usr/bin/env python3
"""Render every Mermaid block in the site docs through `mmdc`.

The upstream skill's checker assumes GNU `mktemp --suffix`, which macOS's BSD
`mktemp` does not have, so this script does the same job portably: extract
each ```mermaid fence into its own file, render it, and fail on a parse error
or an empty SVG.

An empty SVG with a zero exit code is a *false negative*, not a pass: that is
what a Chromium launch failure looks like. So the size check is the gate.

Usage:

    scripts/site/check-mermaid.py site/docs
    scripts/site/check-mermaid.py site/docs --keep-svgs /tmp/svgs
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

FENCE = "```mermaid"
END = "```"
BLOCK = re.compile(re.escape(FENCE) + r"\n(.*?)\n" + re.escape(END), re.DOTALL)


def blocks(text: str) -> list[str]:
    """The bodies of every mermaid fence, in order."""
    return [match.strip("\n") for match in BLOCK.findall(text)]


def diagram_width(svg: Path) -> int:
    """The intrinsic width of a diagram, in CSS pixels.

    Mermaid writes the root `<svg>` as `width="100%"` with the diagram's
    natural width in the `viewBox` and repeated in `style` as `max-width`.
    The `viewBox` is the authority: it is the coordinate system the drawing
    was laid out in, so it is the width the diagram *wants* regardless of
    the container it ends up in.

    Reading `max-width` instead would report the same number for a diagram
    that has been squeezed into a narrow column, which is exactly the case
    where the intrinsic width is what a reader needs to know.
    """
    import re

    text = svg.read_text(encoding="utf-8", errors="replace")
    match = re.search(r'<svg[^>]*\bviewBox="[^"]*?([0-9.]+)\s+([0-9.]+)"', text)
    if match:
        return round(float(match.group(1)))
    match = re.search(r"max-width:\s*([0-9.]+)px", text)
    if match:
        return round(float(match.group(1)))
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="A markdown file or a directory of them.")
    parser.add_argument("--mmdc", default="mmdc", help="The mmdc binary.")
    parser.add_argument(
        "--puppeteer-config",
        type=Path,
        help="A Puppeteer configuration file passed to mmdc. Chromium needs "
        "--no-sandbox in a container that runs as root, which is what a CI "
        "runner is.",
    )
    parser.add_argument("--keep-svgs", type=Path, help="Save the rendered SVGs here.")
    args = parser.parse_args(argv)

    root = Path(args.path)
    files = [root] if root.is_file() else sorted(root.rglob("*.md"))
    files = [f for f in files if FENCE in f.read_text(encoding="utf-8")]

    if not files:
        print("no markdown file contains a mermaid block", file=sys.stderr)
        return 2

    if args.keep_svgs:
        args.keep_svgs.mkdir(parents=True, exist_ok=True)

    total = ok = failed = 0

    command = [args.mmdc]
    if args.puppeteer_config:
        command += ["--puppeteerConfigFile", str(args.puppeteer_config)]

    for path in files:
        bodies = blocks(path.read_text(encoding="utf-8"))
        for number, body in enumerate(bodies, 1):
            total += 1
            with tempfile.TemporaryDirectory() as work:
                source = Path(work) / "diagram.mmd"
                target = Path(work) / "diagram.svg"
                source.write_text(body + "\n", encoding="utf-8")
                result = subprocess.run(
                    command + ["--input", str(source), "--output", str(target)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                stderr = result.stderr
                rendered = target.exists() and target.stat().st_size > 0

                if result.returncode != 0 or not rendered:
                    failed += 1
                    print(f"FAIL {path}:{number}")
                    for line in stderr.splitlines():
                        if re.search(
                            r"Parse error|Lexical error|Expecting|got |error",
                            line,
                            re.I,
                        ):
                            print(f"  {line.strip()[:160]}")
                            break
                    else:
                        print("  mmdc exited 0 but produced no SVG (Chromium unavailable?)")
                    continue

                ok += 1
                size = target.stat().st_size // 1024
                width = diagram_width(target)
                print(f"OK  {path}:{number} ({size} KB, {width}px wide)")
                if args.keep_svgs:
                    # The name is built from the path *relative to the site
                    # root*, so two files with the same stem - two
                    # `overview.md` - do not overwrite each other.
                    relative = path.relative_to(path.parents[len(path.parts) - 1])
                    stem = "_".join(relative.with_suffix("").parts)
                    name = f"{stem}-block-{number}.svg"
                    (args.keep_svgs / name).write_bytes(target.read_bytes())

    print(f"\nchecked {total} mermaid block(s): {ok} OK, {failed} FAIL")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
