#!/usr/bin/env python3
"""Generate the LeakGuard icon set — programmatically, no assets.

Draws one mark (a green shield with a dark check, on black) at
several sizes:

  static/icons/icon-192.png, static/icons/icon-512.png  (PWA)
  extension/icons/icon-16.png, icon-48.png, icon-128.png

Uses Pillow when available; otherwise falls back to a pure-stdlib
PNG writer drawing the same shield by point-in-polygon rasterising.
Run from anywhere:  python3 tools/build_icons.py
Re-running overwrites the icons with identical drawings.
"""

import struct
import sys
import zlib
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
GREEN = (30, 215, 96)      # --green #1ed760
BLACK = (0, 0, 0)
DARK = (18, 18, 18)        # --bg #121212 (check cut)


def shield_points(size):
    """A simple shield outline, as (x, y) fractions of the canvas."""
    return [
        (0.50, 0.08), (0.82, 0.20), (0.82, 0.48),
        (0.82, 0.60), (0.50, 0.92), (0.18, 0.60),
        (0.18, 0.48), (0.18, 0.20),
    ]


def check_points(size):
    """A bold check mark inside the shield, as a polygon."""
    return [
        (0.33, 0.50), (0.45, 0.62), (0.69, 0.34),
        (0.75, 0.40), (0.45, 0.72), (0.27, 0.56),
    ]


def _scale(points, size):
    return [(x * size, y * size) for x, y in points]


def draw_with_pillow(size):
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (size, size), BLACK)
    d = ImageDraw.Draw(img)
    d.polygon(_scale(shield_points(size), size), fill=GREEN)
    d.polygon(_scale(check_points(size), size), fill=DARK)
    return img


def _inside(px, py, poly):
    inside = False
    j = len(poly) - 1
    for i in range(len(poly)):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if ((yi > py) != (yj > py)) and \
                (px < (xj - xi) * (py - yi) / (yj - yi) + xi):
            inside = not inside
        j = i
    return inside


def draw_pixels_stdlib(size):
    """Return rows of RGB bytes — same drawing, no dependencies."""
    shield = _scale(shield_points(size), size)
    check = _scale(check_points(size), size)
    rows = []
    for y in range(size):
        row = bytearray()
        for x in range(size):
            cx, cy = x + 0.5, y + 0.5
            if _inside(cx, cy, check):
                row += bytes(DARK)
            elif _inside(cx, cy, shield):
                row += bytes(GREEN)
            else:
                row += bytes(BLACK)
        rows.append(bytes(row))
    return rows


def write_png_stdlib(path, size):
    rows = draw_pixels_stdlib(size)
    raw = b"".join(b"\x00" + row for row in rows)

    def chunk(kind, data):
        body = kind + data
        return (struct.pack(">I", len(data)) + body
                + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))

    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size,
                                        8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw, 9))
           + chunk(b"IEND", b""))
    path.write_bytes(png)


def main():
    targets = [
        (BASE / "static" / "icons" / "icon-192.png", 192),
        (BASE / "static" / "icons" / "icon-512.png", 512),
        (BASE / "extension" / "icons" / "icon-16.png", 16),
        (BASE / "extension" / "icons" / "icon-48.png", 48),
        (BASE / "extension" / "icons" / "icon-128.png", 128),
    ]
    try:
        import PIL  # noqa: F401
        have_pillow = True
    except Exception:
        have_pillow = False
    for path, size in targets:
        path.parent.mkdir(parents=True, exist_ok=True)
        if have_pillow:
            draw_with_pillow(size).save(path, format="PNG")
        else:
            write_png_stdlib(path, size)
        print("wrote %s (%dx%d, %s)" % (
            path.relative_to(BASE), size, size,
            "pillow" if have_pillow else "stdlib"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
