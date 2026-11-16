#!/usr/bin/env python3
"""Check the site's internal links, and report the ones that do not resolve.

MkDocs resolves a relative Markdown link against the directory of the page
that holds it, so a link written as `components/ksp-cli.md` works in
`index.md` and breaks in `architecture/overview.md`. The fix is a prefix, and
a human writing twenty pages will get it wrong at least once.

This script finds every internal link in the site's own pages, resolves it the
way MkDocs does, and reports the ones that land nowhere. It also reports the
links inside the *prepared* reference documents, which are rewritten by
`prepare-docs.py` and therefore live in the same directory as each other.

It checks two things:

1. **A link to a file** - does the target exist?
2. **A link to an anchor** - does the page have an element with that id?

The second check is the one that finds a stale anchor. A heading's id is
derived from its text, so a heading that is renamed leaves every link to it
pointing at nothing, and nothing else in the build notices.

It writes nothing. The fix is a prefix or a renamed target, and a script that
rewrites prose links would be a script that rewrites prose.

Usage:

    scripts/site/check-links.py
    scripts/site/check-links.py --root site/docs
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
# A Markdown link, with the target in the second group. An angle-bracketed
# target and a titled link are both accepted.
LINK = re.compile(r"\[([^\]]*)\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")

# A Markdown heading, which is what an anchor's id is derived from.
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$", re.MULTILINE)


def slug(text: str) -> str:
    """The id Python-Markdown gives a heading.

    This is `markdown.extensions.toc.slugify` verbatim: lower case, with
    punctuation stripped and every run of whitespace collapsed to a single
    hyphen. A heading's id is what an anchor link names, so a link checker
    that does not compute the same slug checks nothing.

    The function is imported rather than reimplemented because the details
    matter. A hand-written version that turned a period into a hyphen
    produced `2-4-macos-is-supported` where Markdown produces
    `24-macos-is-supported`, and reported a correct anchor as broken.
    """
    from markdown.extensions.toc import slugify

    return slugify(text, "-")


def anchors(page: Path) -> set[str]:
    """The ids the page's own headings produce."""
    text = strip_fences(page.read_text(encoding="utf-8"))
    found: set[str] = set()
    for match in HEADING.finditer(text):
        found.add(slug(match.group(2)))
    return found


def strip_fences(text: str) -> str:
    """The text with its fenced code blocks removed."""
    return re.sub(r"^```.*?^```", "", text, flags=re.MULTILINE | re.DOTALL)


def resolve(page: Path, target: str) -> Path | None:
    """The file a link points at, resolved the way MkDocs resolves it.

    MkDocs resolves a relative link against the directory of the page that
    holds it, with no exception for a path that looks like a site-root path.
    A link written `components/ksp-cli.md` in `architecture/overview.md`
    therefore resolves to `architecture/components/ksp-cli.md`, which is why
    every link from a subdirectory needs a `../` prefix.
    """
    if target.startswith(("#", "http://", "https://", "mailto:", "//")):
        return None
    if target.startswith("/"):
        return None
    return (page.parent / target).resolve()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=REPO / "site" / "docs", help="The docs root."
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    broken = 0
    checked = 0
    anchor_cache: dict[Path, set[str]] = {}

    def page_anchors(path: Path) -> set[str]:
        if path not in anchor_cache:
            anchor_cache[path] = anchors(path)
        return anchor_cache[path]

    for page in sorted(root.rglob("*.md")):
        text = page.read_text(encoding="utf-8")
        for match in LINK.finditer(text):
            target = match.group(2)

            # An anchor in the page itself.
            if target.startswith("#"):
                checked += 1
                anchor = target[1:]
                if anchor and anchor not in page_anchors(page):
                    broken += 1
                    line = text[: match.start()].count("\n") + 1
                    print(
                        f"BROKEN {page.relative_to(root)}:{line}: "
                        f"{target} has no matching heading on this page"
                    )
                continue

            resolved = resolve(page, target)
            if resolved is None:
                continue

            checked += 1
            if not resolved.exists():
                broken += 1
                line = text[: match.start()].count("\n") + 1
                print(
                    f"BROKEN {page.relative_to(root)}:{line}: "
                    f"{target} -> {resolved.relative_to(root)}"
                )
                continue

            # An anchor on another page.
            if "#" in target:
                path_part, _, anchor = target.partition("#")
                if path_part:
                    target_page = resolved
                else:
                    target_page = page
                if anchor and target_page.suffix == ".md":
                    if anchor not in page_anchors(target_page):
                        broken += 1
                        line = text[: match.start()].count("\n") + 1
                        print(
                            f"BROKEN {page.relative_to(root)}:{line}: "
                            f"{target} has no matching heading on "
                            f"{target_page.relative_to(root)}"
                        )

    print(f"\nchecked {checked} internal link(s): {broken} broken")
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
