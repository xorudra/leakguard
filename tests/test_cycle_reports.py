"""Phase 149 (Development reporting) — cycle-report guard.

The per-cycle report files in ``docs/cycles/`` are the phase's
deliverable; this test keeps them honest:

  * ``docs/cycles/README.md`` (the index) exists;
  * every report the index links actually exists on disk;
  * every report on disk is linked from the index;
  * every report carries all 19 field labels of the spec's §6
    report format, so a future cycle cannot quietly drop a
    field (write "None" instead — the format's own rule).

Hermetic by design: filesystem reads only — no git, no
network — so it runs identically under local pytest and the
CI unittest discovery.
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CYCLES_DIR = REPO / "docs" / "cycles"
INDEX = CYCLES_DIR / "README.md"

# The 19 labeled fields of the Final spec's §6 report format,
# in order. A report must contain every label (as its section
# heading); the value may legitimately be "None" / "not
# recorded", but the field may not be omitted.
SECTION_6_FIELDS = [
    "CURRENT PHASE",
    "PRIORITY TIER",
    "STATUS",
    "WHAT WAS AUDITED",
    "WHAT WAS IMPLEMENTED",
    "WHAT WAS DELIBERATELY NOT IMPLEMENTED",
    "FILES CREATED",
    "FILES MODIFIED",
    "DATABASE MIGRATIONS",
    "API ROUTES",
    "TESTS ADDED",
    "TESTS RUN",
    "RESULTS",
    "SECURITY CONTROLS",
    "PRIVACY CONTROLS",
    "DEPLOYMENT STATUS",
    "KNOWN LIMITATIONS",
    "RISKS",
    "NEXT PHASE",
]

_LINK_RE = re.compile(r"\(([^)\s]+\.md)\)")


def _linked_reports():
    text = INDEX.read_text(encoding="utf-8")
    names = []
    for target in _LINK_RE.findall(text):
        name = Path(target).name
        if name != INDEX.name and name not in names:
            names.append(name)
    return names


class TestCycleReports(unittest.TestCase):

    def test_index_exists(self):
        self.assertTrue(INDEX.is_file(),
                        "docs/cycles/README.md (the index) is missing")

    def test_every_linked_report_exists(self):
        linked = _linked_reports()
        self.assertTrue(linked, "the index links no report files")
        missing = [name for name in linked
                   if not (CYCLES_DIR / name).is_file()]
        self.assertEqual(missing, [],
                         f"index links reports that do not exist: {missing}")

    def test_every_report_on_disk_is_linked(self):
        linked = set(_linked_reports())
        on_disk = {p.name for p in CYCLES_DIR.glob("*.md")
                   if p.name != INDEX.name}
        self.assertEqual(on_disk - linked, set(),
                         "report files missing from the index: "
                         f"{sorted(on_disk - linked)}")

    def test_every_report_carries_all_section_6_fields(self):
        reports = sorted(p for p in CYCLES_DIR.glob("*.md")
                         if p.name != INDEX.name)
        self.assertTrue(reports, "no cycle reports on disk")
        for path in reports:
            text = path.read_text(encoding="utf-8")
            missing = [label for label in SECTION_6_FIELDS
                       if label not in text]
            self.assertEqual(
                missing, [],
                f"{path.name} is missing §6 fields: {missing}")


if __name__ == "__main__":
    unittest.main()
