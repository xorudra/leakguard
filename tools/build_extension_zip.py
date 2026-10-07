#!/usr/bin/env python3
"""Build extension/dist/leakguard-extension.zip — deterministically.

Same input tree → byte-identical zip: entries are sorted by name,
every entry carries the fixed DOS epoch timestamp (1980-01-01),
and compression settings are pinned. Users unzip the result and
"Load unpacked" the folder (see extension/README.md).

The zip contains the extension's files with manifest.json at the
archive root. extension/dist/ itself is never included.

Run from anywhere:  python3 tools/build_extension_zip.py
"""

import sys
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
EXT_DIR = BASE / "extension"
OUT = EXT_DIR / "dist" / "leakguard-extension.zip"
FIXED_DATE = (1980, 1, 1, 0, 0, 0)  # the DOS epoch: earliest legal


def collect_files():
    files = []
    for path in sorted(EXT_DIR.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(EXT_DIR)
        if rel.parts[0] == "dist":
            continue  # never pack the output into itself
        files.append(rel)
    return sorted(files, key=lambda p: p.as_posix())


def build(out_path=OUT):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w",
                         compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as zf:
        for rel in collect_files():
            info = zipfile.ZipInfo(rel.as_posix(), date_time=FIXED_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, (EXT_DIR / rel).read_bytes())
    return out_path


def main():
    out = build()
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
    print("wrote %s (%d files, %d bytes)"
          % (out.relative_to(BASE), len(names), out.stat().st_size))
    for name in names:
        print("  " + name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
