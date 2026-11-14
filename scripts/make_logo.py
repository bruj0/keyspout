#!/usr/bin/env python3
"""Build the KeySpout logo SVG: a geometric K mark plus the wordmark.

The mark is the "K" concept, redrawn as exact vector geometry traced from the
generated concept rather than estimated by eye. The wordmark uses Questrial
(SIL Open Font License, in `scripts/fonts/`) and is converted to outlines, so
the SVG needs no installed font to render.

The output keeps the structure of a Fabric.js export: a 1024x768 canvas, one
outer group per element, and a `transform="matrix(...)"` on each. That way the
tooling which produced the original logo handles this one too.

Usage:
    python3 scripts/make_logo.py
    python3 scripts/make_logo.py --out assets/logo.svg
    python3 scripts/make_logo.py --mark-only --mark-scale 2.6 --out assets/logo-mark.svg
    python3 scripts/make_logo.py --with-container

Requires fontTools for the wordmark outlines. The mark itself needs nothing.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# --- Palette --------------------------------------------------------------
# The wordmark gradient steps come from the original logo. The mark colours
# are the teal and charcoal of the K concept.
CHARCOAL = "rgb(39, 46, 50)"
TEAL = "rgb(0, 150, 136)"
GREY = "rgb(214, 218, 220)"
GRADIENT_A = "rgb(255, 150, 79)"
GRADIENT_B = "rgb(255, 190, 148)"

CANVAS_W = 1024
CANVAS_H = 768

# --- The mark -------------------------------------------------------------
# Traced from the generated concept at 1024px, then normalised so the mark
# occupies a 268-unit tall box. Every number below was measured, not guessed.
#
# The bar and the chevron sit side by side in the source, not overlapping:
# the bar occupies x 396..449 and the chevron x 450..628. On this grid the
# bar is x 0..54 and the chevron starts at x 54.
#
# The bar:   x 0..54,   y 0..268
# The chevron: a thick angular stroke whose arms meet at a notch on the left.
#   Traced in its own local space, its outline runs clockwise from the top
#   left of the top arm:
#     (56,0) (79,24) (0,103) (0,163) (79,242) (56,267)
#     (178,267) (45,134) (178,0) and back to (56,0)
#   The notch at (45,134) is where the two arms meet. Shifted right by the
#   bar's width, the notch lands at x 99.
# The container: a rounded rectangle outline, stroke only, drawn under the
#   chevron's right arm so the arm crosses it.
MARK_BAR = "M 0 0 L 54 0 L 54 268 L 0 268 Z"

MARK_CHEVRON = (
    "M 110 0 L 133 24 L 54 103 L 54 163 L 133 242 L 110 267 "
    "L 232 267 L 99 134 L 232 0 Z"
)

# The container outline. In the source it sat at the chevron's right edge,
# where it was almost entirely hidden by the arm and read as a nub. It is
# redrawn here as a rounded rectangle that the chevron's arms cross, sitting
# in the open mouth of the K.
MARK_CONTAINER = (
    "M 140 88 L 194 88 Q 210 88 210 104 "
    "L 210 164 Q 210 180 194 180 "
    "L 140 180 Q 124 180 124 164 "
    "L 124 104 Q 124 88 140 88 Z"
)
MARK_CONTAINER_STROKE = 12
MARK_WIDTH = 236


def _mark_paths(with_container: bool = False) -> list[tuple[str, str, str | None, float]]:
    """Return the mark's shapes.

    Each entry is ``(path_data, fill, stroke, stroke_width)``. The container
    paints first: it is an outline that the chevron crosses, so it has to sit
    under the chevron's arm rather than over it.

    Args:
        with_container: Whether to include the grey container outline. It is
            off by default: at small sizes the chevron covers most of it and
            it reads as an artefact rather than a shape.
    """
    shapes = []
    if with_container:
        shapes.append((MARK_CONTAINER, "none", GREY, MARK_CONTAINER_STROKE))
    shapes.append((MARK_BAR, CHARCOAL, None, 0.0))
    shapes.append((MARK_CHEVRON, TEAL, None, 0.0))
    return shapes


# --- The wordmark ---------------------------------------------------------

def _wordmark_paths(font_path: Path, text: str, cap_height: float) -> tuple[list[str], float, float]:
    """Convert a string to SVG path data using a TTF.

    Font outlines use a y-up coordinate system; SVG uses y-down. The glyphs
    are therefore emitted with a negative y scale, which puts the baseline at
    y=0 and the cap height above it.

    Args:
        font_path: The font file to read.
        text: The string to outline.
        cap_height: The cap height to render at, in user units.

    Returns:
        A tuple of the path data list, the total advance width, and the
        cap height that was used.

    Raises:
        SystemExit: If fontTools is missing or the font lacks a glyph.
    """
    try:
        from fontTools.misc.transform import Transform
        from fontTools.pens.boundsPen import BoundsPen
        from fontTools.pens.svgPathPen import SVGPathPen
        from fontTools.pens.transformPen import TransformPen
        from fontTools.ttLib import TTFont
    except ImportError:
        raise SystemExit(
            "fontTools is not installed. Run:\n"
            "  uv pip install --python <venv> fonttools"
        ) from None

    font = TTFont(str(font_path))
    glyph_set = font.getGlyphSet()
    cmap = font.getBestCmap()

    # Measure the font's own cap height on 'K', so the argument means the same
    # thing whatever font is used.
    probe = cmap.get(ord("K"))
    if probe is None:
        raise SystemExit("font has no glyph for 'K'")
    bounds = BoundsPen(glyph_set)
    glyph_set[probe].draw(bounds)
    font_cap = bounds.bounds[3] - bounds.bounds[1]
    if font_cap <= 0:
        raise SystemExit("cannot measure the font's cap height")
    scale = cap_height / font_cap

    paths: list[str] = []
    x = 0.0
    for char in text:
        glyph_name = cmap.get(ord(char))
        if glyph_name is None:
            raise SystemExit(f"font has no glyph for {char!r}")
        pen = SVGPathPen(glyph_set)
        # Negative y scale: baseline at 0, cap height above it.
        glyph_set[glyph_name].draw(
            TransformPen(pen, Transform(scale, 0, 0, -scale, x, 0))
        )
        paths.append(pen.getCommands())
        x += glyph_set[glyph_name].width * scale
    return paths, x, cap_height


# --- Assembly -------------------------------------------------------------

def _path(
    d: str,
    fill: str,
    stroke: str | None = None,
    stroke_width: float = 0.0,
) -> str:
    """Return one path element.

    The style block matches the original export, and the colour is repeated as
    a presentation attribute: some renderers ignore the style block, and a
    container drawn as an outline must not fill solid.

    Args:
        d: The path data.
        fill: The fill colour, or ``none`` for a stroke-only shape.
        stroke: The stroke colour, or None for no stroke.
        stroke_width: The stroke width in user units.

    Returns:
        The path element.
    """
    stroke_colour = stroke if stroke is not None else "none"
    style = (
        f"stroke: {stroke_colour}; stroke-width: {stroke_width}; "
        "stroke-dasharray: none; stroke-linecap: butt; stroke-dashoffset: 0; "
        "stroke-linejoin: miter; stroke-miterlimit: 4; "
        f"fill: {fill}; fill-rule: nonzero; opacity: 1;"
    )
    return (
        f'<path style="{style}" fill="{fill}" stroke="{stroke_colour}" '
        f'stroke-width="{stroke_width}" d="{d}" stroke-linecap="round"/>'
    )


def build_svg(
    wordmark: str,
    font_path: Path | None,
    mark_scale: float,
    wordmark_height: float,
    gap: float,
    with_container: bool = False,
    mark_only: bool = False,
) -> str:
    """Assemble the full logo SVG.

    Args:
        wordmark: The text to set.
        font_path: The font to outline it with, or None to omit the wordmark.
        mark_scale: Scale factor applied to the mark.
        wordmark_height: Cap height of the wordmark in user units.
        gap: Space between the mark and the wordmark, in user units.
        with_container: Whether to draw the grey container outline.
        mark_only: Draw the mark alone on a square canvas, for an icon.

    Returns:
        The SVG source.
    """
    parts: list[str] = []

    # The mark, on the left of the canvas.
    mark_w = float(MARK_WIDTH)
    mark_h = 268.0

    # The wordmark, to the right of the mark.
    word_paths: list[str] = []
    word_width = 0.0
    cap = 0.0
    if font_path is not None:
        word_paths, word_width, cap = _wordmark_paths(
            font_path, wordmark, wordmark_height
        )

    # Centre the whole lockup on the canvas. The mark-only variant uses a
    # square canvas, so it centres on that instead.
    canvas_w = CANVAS_W
    canvas_h = CANVAS_W if mark_only else CANVAS_H

    total_w = mark_w * mark_scale + gap + word_width
    mark_x = (canvas_w - total_w) / 2
    mark_y = (canvas_h - mark_h * mark_scale) / 2

    if mark_only:
        # The mark alone on a square canvas, for an icon or favicon.
        mark_x = (canvas_w - mark_w * mark_scale) / 2
        mark_y = (canvas_h - mark_h * mark_scale) / 2

    mark_body = "\n".join(
        _path(d, fill, stroke, width)
        for d, fill, stroke, width in _mark_paths(with_container)
    )
    parts.append(
        f'<g transform="matrix({mark_scale} 0 0 {mark_scale} {mark_x:.2f} {mark_y:.2f})" '
        f'id="keyspout-mark">\n{mark_body}\n</g>'
    )

    if font_path is not None and not mark_only:
        # The original splits its gradient across the letters: the first half
        # in the stronger orange, the rest in the paler peach.
        split = max(1, len(word_paths) // 2)
        body = [
            _path(d, GRADIENT_A if index < split else GRADIENT_B)
            for index, d in enumerate(word_paths)
        ]
        word_x = mark_x + mark_w * mark_scale + gap
        # The glyphs sit above the baseline, so the baseline goes below the
        # centre line by half the cap height.
        word_y = canvas_h / 2 + cap / 2
        parts.append(
            f'<g transform="matrix(1 0 0 1 {word_x:.2f} {word_y:.2f})" '
            f'id="keyspout-wordmark">\n' + "\n".join(body) + "\n</g>"
        )

    return (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:xlink="http://www.w3.org/1999/xlink" '
        'version="1.1" '
        f'width="{canvas_w}" height="{canvas_h}" '
        f'viewBox="0 0 {canvas_w} {canvas_h}" '
        'xml:space="preserve">\n'
        "<desc>KeySpout logo</desc>\n"
        "<defs>\n"
        "</defs>\n\n"
        + "\n\n".join(parts)
        + "\n</svg>\n"
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point.

    Args:
        argv: Argument list; defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code.
    """
    here = Path(__file__).parent
    default_font = here / "fonts" / "Questrial-Regular.ttf"

    parser = argparse.ArgumentParser(description="Build the KeySpout logo SVG.")
    parser.add_argument(
        "--out",
        default="keyspout-logo.svg",
        help="Output path for the SVG (default: keyspout-logo.svg)",
    )
    parser.add_argument(
        "--font",
        default=str(default_font) if default_font.exists() else None,
        help="TTF used to outline the wordmark",
    )
    parser.add_argument(
        "--wordmark",
        default="KeySpout",
        help="Wordmark text (default: KeySpout)",
    )
    parser.add_argument(
        "--mark-scale",
        type=float,
        default=0.62,
        help="Scale applied to the mark (default: 0.62)",
    )
    parser.add_argument(
        "--wordmark-height",
        type=float,
        default=84.0,
        help="Cap height of the wordmark (default: 84)",
    )
    parser.add_argument(
        "--gap",
        type=float,
        default=36.0,
        help="Space between mark and wordmark (default: 36)",
    )
    parser.add_argument(
        "--with-container",
        action="store_true",
        help="Draw the grey container outline behind the mark",
    )
    parser.add_argument(
        "--mark-only",
        action="store_true",
        help="Draw the mark alone, for an icon or favicon",
    )
    args = parser.parse_args(argv)

    font_path = Path(args.font) if args.font else None
    if font_path is not None and not font_path.exists():
        print(f"warning: font not found at {font_path}; omitting the wordmark", file=sys.stderr)
        font_path = None

    svg = build_svg(
        wordmark=args.wordmark,
        font_path=font_path,
        mark_scale=args.mark_scale,
        wordmark_height=args.wordmark_height,
        gap=args.gap,
        with_container=args.with_container,
        mark_only=args.mark_only,
    )
    Path(args.out).write_text(svg, encoding="utf-8")
    print(f"wrote {args.out} ({len(svg)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
