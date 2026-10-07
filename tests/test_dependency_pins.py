"""Phase 107 (Dependency security) — pin guard + first scan record.

SCAN RECORD (first recorded vulnerability scan)
-----------------------------------------------
Date: 2026-10-07. Tool: pip-audit 2.10.1. Commands:
  ``pip-audit -r requirements.lock``  (the pinned deployable set)
  ``pip-audit -r requirements.txt``   (ranges resolved, then audited)

Result for requirements.lock — 12 packages scanned, 1 package with
known vulnerabilities: ``cryptography==45.0.7``, 7 unique advisories
(13 entries counting alias duplicates):

  * PYSEC-2026-2141  (CVE-2026-26007, GHSA-r6ph-v2qm-q3c2) — fixed in 46.0.5
  * PYSEC-2026-35    (CVE-2026-34073, GHSA-m959-cc7f-wv43) — fixed in 46.0.6
  * PYSEC-2026-36    (CVE-2026-39892, GHSA-p423-j2cm-9vmq) — fixed in 46.0.7
  * GHSA-537c-gmf6-5ccf (bundled OpenSSL in wheels)        — fixed in 48.0.1
  * PYSEC-2026-3553  (CVE-2026-69249, GHSA-jwv3-5hgf-82ww) — fixed in 49.0.0
  * PYSEC-2026-3554  (CVE-2026-69248, GHSA-m2h6-j472-rp4c) — fixed in 49.0.0
  * PYSEC-2026-3552  (CVE-2026-69247, GHSA-g6cj-pr64-35w5) — fixed in 50.0.0

Result for requirements.txt — 8 packages scanned after resolution;
the resolver selected the same cryptography==45.0.7 (the maximum the
``>=42,<46`` range admits) with the same 7 advisories. All other
packages were clean in both scans.

IMPORTANT: every fixed version is >= 46.0.5, above the ``<46`` cap in
requirements.txt — remediation needs a range change plus a lock
regeneration, not a pin bump alone. Remediation was deliberately NOT
performed by the audit task; it is a separate, parent-approved change.

Re-run cadence: on any dependency change AND monthly.

These tests guard the invariant that makes the scan meaningful: the
lock contains only exact ``==`` pins, and every direct dependency in
requirements.txt is present in the lock — so the scanned set is the
deployable set.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LOCK = REPO / "requirements.lock"
REQUIREMENTS = REPO / "requirements.txt"

PIN_RE = re.compile(
    r"^[A-Za-z0-9_.-]+(\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.!+-]+$")


def _pep503(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _lock_lines():
    lines = []
    for raw in LOCK.read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def _lock_names():
    names = set()
    for line in _lock_lines():
        name = re.split(r"\[|==", line, maxsplit=1)[0]
        names.add(_pep503(name))
    return names


def _requirement_names():
    names = set()
    for raw in REQUIREMENTS.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        name = re.split(r"\[|>=|<=|==|~=|!=|>|<|\s", line, maxsplit=1)[0]
        names.add(_pep503(name))
    return names


def test_lock_contains_only_exact_pins():
    lines = _lock_lines()
    assert lines, "requirements.lock has no pins"
    bad = [line for line in lines if not PIN_RE.match(line)]
    assert bad == [], (
        f"requirements.lock entries that are not exact '==' pins: {bad}")


def test_every_direct_dependency_is_locked():
    missing = _requirement_names() - _lock_names()
    assert missing == set(), (
        f"requirements.txt packages missing from requirements.lock: "
        f"{sorted(missing)} — regenerate the lock so the audited set "
        f"equals the deployable set")
