#!/usr/bin/env python3
"""Assemble the site's reference section from the public tree.

The site must publish the project's *own* public documents - the design
specification, the quickstart, the security model, the known defects - and
they live in the public repository, not in the upstream tree. This script
copies them into `site/docs/reference/` and rewrites their relative links so
they resolve inside the site.

Three kinds of rewriting happen, and each one has a rule rather than a
guess:

1. **A link to another reference document** becomes a link to that
   document's page in the site.
2. **A link to a file that is not published** keeps its words, so a reader
   is not sent into a 404. The design specification cites four research
   documents that the public tree does not ship; those citations become
   prose that names the document.
3. **A link to a file that is published but not as a page** - the licence,
   the architecture diagram - is rewritten to the file's location in the
   site.

The script is deterministic and idempotent: running it twice produces the
same tree. It writes only inside the site directory and never touches the
source tree.

Usage:

    scripts/site/prepare-docs.py --source ../keyspout-public
    scripts/site/prepare-docs.py --source ../keyspout-public --check
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent

# The static files the reference documents point at. They live in the public
# tree's `assets/` directory and are copied next to the pages that use them,
# so a relative path in a document resolves inside the site.
ASSETS: dict[str, str] = {
    "logo.svg": "logo.svg",
    "logo.png": "logo.png",
    "logo-mark.svg": "logo-mark.svg",
    "logo-mark.png": "logo-mark.png",
    "keyspout-architecture.html": "keyspout-architecture.html",
    "keyspout-architecture.png": "keyspout-architecture.png",
}

# The documents to publish, and the site page each becomes.
#
# The key is the path in the public tree; the value is the file name inside
# `site/docs/reference/`. The site nav names them, so the names here and the
# nav must agree.
DOCUMENTS: dict[str, str] = {
    "README.md": "overview.md",
    "QUICKSTART.md": "QUICKSTART.md",
    "USER_MANUAL.md": "USER_MANUAL.md",
    "SECURITY.md": "SECURITY.md",
    "CONTEXT-MAP.md": "CONTEXT-MAP.md",
    "DEVELOPMENT.md": "DEVELOPMENT.md",
    "AGENTS.md": "AGENTS.md",
    "LICENSE": "LICENSE.md",
    "docs/keyspout-design-spec.md": "design-spec.md",
    "docs/known-defects.md": "known-defects.md",
    "docs/supply-chain-level.md": "supply-chain-level.md",
    "docs/supply-chain-vetting.md": "supply-chain-vetting.md",
}

# The crate context files, one per bounded context.
CONTEXTS: dict[str, str] = {
    "crates/ksp/CONTEXT.md": "context-ksp.md",
    "crates/ksp-types/CONTEXT.md": "context-ksp-types.md",
    "crates/ksp-record/CONTEXT.md": "context-ksp-record.md",
    "crates/ksp-identity/CONTEXT.md": "context-ksp-identity.md",
    "crates/ksp-backend/CONTEXT.md": "context-ksp-backend.md",
    "crates/ksp-posture/CONTEXT.md": "context-ksp-posture.md",
    "crates/ksp-deletion/CONTEXT.md": "context-ksp-deletion.md",
    "crates/ksp-key-lifecycle/CONTEXT.md": "context-ksp-key-lifecycle.md",
    "scripts/CONTEXT.md": "context-scripts.md",
}

# A link target that resolves to a published page, keyed by the path it is
# written as in the source document.
#
# The keys are the *written* forms, because a link's text decides what it
# resolves to. A source document may write `docs/keyspout-design-spec.md` or
# `./keyspout-design-spec.md` or `keyspout-design-spec.md`, and all three
# mean the same file from their own directory.
PUBLISHED: dict[str, str] = {
    "README.md": "overview.md",
    "QUICKSTART.md": "QUICKSTART.md",
    "USER_MANUAL.md": "USER_MANUAL.md",
    "SECURITY.md": "SECURITY.md",
    "CONTEXT-MAP.md": "CONTEXT-MAP.md",
    "DEVELOPMENT.md": "DEVELOPMENT.md",
    "AGENTS.md": "AGENTS.md",
    "CONTRIBUTING.md": "AGENTS.md",
    "LICENSE": "LICENSE.md",
    "docs/keyspout-design-spec.md": "design-spec.md",
    "docs/known-defects.md": "known-defects.md",
    "docs/supply-chain-level.md": "supply-chain-level.md",
    "docs/supply-chain-vetting.md": "supply-chain-vetting.md",
    "skills/README.md": "skills-README.md",
}

# The research documents the design specification cites. The public tree does
# not ship them, so a citation to one cannot be a link.
#
# Each entry is the *title* to render in place of the link. The citation
# still names the document; it just does not pretend the reader can open it.
UNPUBLISHED: dict[str, str] = {
    "2026-10-18-001-research-agent-secret-manager-access.md":
        "agent-secret-manager access research",
    "keyspout-prior-art-research.md": "prior-art research",
    "keyspout-storage-backends.md": "storage-backend research",
    "keyspout-age-restricted-encryption.md": "age-restricted-encryption research",
    "keyspout-timed-expiry-impossibility.md": "timed-expiry research",
    # A walkthrough transcript and an operator script are shipped in the
    # repository but are not published as site pages. Leaving them as links
    # produced eight broken references the moment the manual and the
    # quickstart both cited them, so the citation keeps its words and stops
    # pointing at a page that does not exist.
    "ksp-op-walkthrough.md": "operator walkthrough",
    "ksp-op.sh": "operator script",
}

LINK = re.compile(r"\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def resolve(source: str, target: str) -> str | None:
    """The repo-relative path a link in `source` points at.

    Returns None when the target does not name a file in the tree, which is
    the case for an anchor or a scheme.
    """
    if target.startswith(("#", "http://", "https://", "mailto:", "//", "/")):
        return None
    base = Path(source).parent
    joined = (base / target).as_posix()
    # `Path` does not collapse `..` on its own; do it by hand so the result
    # is comparable with the repo-relative paths in the tables above.
    parts: list[str] = []
    for part in joined.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


def rewrite(source: str, text: str) -> tuple[str, list[str]]:
    """Rewrite the relative links in one document.

    Returns the rewritten text and the list of links that could not be
    resolved, so the caller can report them rather than publishing a dead
    citation.
    """
    unresolved: list[str] = []

    def replace(match: re.Match[str]) -> str:
        label, target = match.group(1), match.group(2)
        resolved = resolve(source, target)
        if resolved is None:
            return match.group(0)

        name = Path(resolved).name

        # A link to a crate context file becomes a link to its page.
        if resolved in CONTEXTS:
            return f"[{label}]({CONTEXTS[resolved]})"

        # A link to a published document becomes a link to its page.
        if resolved in PUBLISHED:
            return f"[{label}]({PUBLISHED[resolved]})"

        # A link to a research document the public tree does not ship keeps
        # its words, but stops pretending to be a link. The citation still
        # names the document; it just does not send the reader into a 404.
        if name in UNPUBLISHED:
            unresolved.append(f"{source} -> {target}")
            return f"{label} (the {UNPUBLISHED[name]}, not published here)"

        # A link to a file the site publishes as a static asset resolves to
        # the asset itself. The reference documents live one directory below
        # the site root, so the path to an asset goes up one level.
        if name in ASSETS:
            return f"[{label}](../assets/{ASSETS[name]})"

        unresolved.append(f"{source} -> {target}")
        return match.group(0)

    text = LINK.sub(replace, text)

    # An HTML image tag carries the same reference as a Markdown link, and the
    # README uses one for the logo.
    def replace_src(match: re.Match[str]) -> str:
        attribute, value = match.group(1), match.group(2)
        name = Path(value).name
        if name in ASSETS:
            return f'{attribute}="../assets/{ASSETS[name]}"'
        return match.group(0)

    text = re.sub(r'\b(src|href)="([^"]+)"', replace_src, text)

    return text, unresolved

def front_matter(text: str, title: str) -> str:
    """A MkDocs front matter block, unless the document already has one."""
    if text.startswith("---\n"):
        return text
    return f"---\ntitle: {title}\n---\n\n{text}"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=REPO.parent / "keyspout-public",
        help="The public tree to read the documents from.",
    )
    parser.add_argument(
        "--site",
        type=Path,
        default=REPO / "site",
        help="The site directory to write into.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the prepared reference section differs from what would "
        "be written. Writes nothing.",
    )
    args = parser.parse_args(argv)

    site_root = args.site.resolve()
    docs_root = site_root / "docs"
    reference = docs_root / "reference"
    assets_dir = docs_root / "assets"

    source_root = args.source.resolve()
    if not source_root.is_dir():
        print(f"error: {source_root} is not a directory", file=sys.stderr)
        return 2

    prepared: dict[Path, str] = {}
    assets: dict[Path, bytes] = {}
    unresolved: list[str] = []

    for relative, target in list(DOCUMENTS.items()) + list(CONTEXTS.items()):
        origin = source_root / relative
        if not origin.is_file():
            print(f"error: {origin} does not exist", file=sys.stderr)
            return 2
        if Path(target).suffix == ".md":
            title = Path(target).stem.replace("-", " ").title()
            text = origin.read_text(encoding="utf-8")
            text, missing = rewrite(relative, text)
            unresolved.extend(missing)
            prepared[reference / target] = front_matter(text, title)
        else:
            # A file that is not markdown - the licence - is published as it
            # is, with its own front matter so MkDocs gives it a title.
            text = origin.read_text(encoding="utf-8")
            prepared[reference / target] = front_matter(text, "Licence")

    # The skills index, which points back at the README.
    skills_index = source_root / "skills" / "README.md"
    if skills_index.is_file():
        text = skills_index.read_text(encoding="utf-8")
        text, missing = rewrite("skills/README.md", text)
        unresolved.extend(missing)
        prepared[reference / "skills-README.md"] = front_matter(
            text, "Operator skills"
        )

    # The static assets the reference documents point at.
    for name, target in ASSETS.items():
        origin = source_root / "assets" / name
        if origin.is_file():
            assets[assets_dir / target] = origin.read_bytes()

    if unresolved:
        print("unresolved relative links:", file=sys.stderr)
        for item in sorted(set(unresolved)):
            print(f"  {item}", file=sys.stderr)

    if args.check:
        stale = []
        for path, content in prepared.items():
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(path.relative_to(site_root))
        for path in sorted(reference.glob("*.md")):
            if path not in prepared:
                stale.append(path.relative_to(site_root))
        for path, content in assets.items():
            if not path.exists() or path.read_bytes() != content:
                stale.append(path.relative_to(site_root))
        if stale:
            print(
                f"error: the prepared reference section is stale "
                f"({len(stale)} file(s))",
                file=sys.stderr,
            )
            for item in stale:
                print(f"  {item}", file=sys.stderr)
            return 1
        print("the prepared reference section is up to date")
        return 0

    reference.mkdir(parents=True, exist_ok=True)
    for path in sorted(reference.glob("*.md")):
        path.unlink()
    for path, content in prepared.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    assets_dir.mkdir(parents=True, exist_ok=True)
    for path, content in assets.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    print(
        f"prepared {len(prepared)} reference document(s) and "
        f"{len(assets)} asset(s) in {docs_root}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
