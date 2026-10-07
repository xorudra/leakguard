"""Finding-set diff (spec Phases 43, 46) — pure functions, no I/O.

A finding's IDENTITY is (identifier_id, provider, source_name): the
same source reporting the same saved detail again is the same
exposure, however the details around it changed. Two completed scan
jobs' finding sets diff into:

* new        — identities only in the CURRENT job (rows from it),
* resolved   — identities only in the PREVIOUS job (rows from it),
* continuing — the count of identities present in both.

"Resolved" is deliberately modest language: the source did not
report the detail in the latest check of the sources we use. It is
never proof the data is gone from the internet.

score_delta(previous, current) is current - previous, or None when
either score is missing (a job that never scored cannot ground a
delta, and inventing one would be a fabrication).
"""

import hashlib


def identity_of(finding):
    """The identity tuple of one finding row/dict."""
    identifier_id = finding.get("identifier_id")
    return (
        str(identifier_id) if identifier_id else None,
        finding.get("provider"),
        finding.get("source_name"),
    )


def identity_key(finding):
    """Stable string form of the identity (dedupe keys, grouping)."""
    identifier_id, provider, source_name = identity_of(finding)
    return "%s|%s|%s" % (identifier_id or "", provider or "",
                         source_name or "")


def identity_hash(finding):
    """SHA-256 hex of the identity key — the dedupe-key component.
    Contains no identifier value (identifier_id is a vault row id)."""
    return hashlib.sha256(
        identity_key(finding).encode("utf-8")).hexdigest()


def _by_identity(findings):
    """identity -> first row carrying it, preserving input order."""
    out = {}
    for finding in findings or ():
        out.setdefault(identity_of(finding), finding)
    return out


def diff_findings(previous, current):
    """Diff two finding sets. Returns
    {"new": [rows], "resolved": [rows], "continuing": int}.

    `new` rows come from `current`, `resolved` rows from
    `previous`, each in first-appearance order."""
    prev = _by_identity(previous)
    cur = _by_identity(current)
    new = [row for key, row in cur.items() if key not in prev]
    resolved = [row for key, row in prev.items() if key not in cur]
    continuing = sum(1 for key in cur if key in prev)
    return {"new": new, "resolved": resolved, "continuing": continuing}


def score_delta(previous_score, current_score):
    """current - previous, or None when either side is unknown."""
    if previous_score is None or current_score is None:
        return None
    return int(current_score) - int(previous_score)
