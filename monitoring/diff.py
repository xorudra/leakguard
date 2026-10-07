"""Finding-set diff (spec Phases 43, 46) + the stored finding
lifecycle writer (spec Phase 25).

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

The diff functions above are pure. The REST of this module is the
one writer of the stored canonical lifecycle state (migration
0012: findings.lifecycle_state / lifecycle_changed_at), which
replaced deriving that state per read:

* apply_lifecycle() runs inside the scan-completion hook
  (monitoring/events.py) with the same previous/current sets the
  diff consumed, and persists each identity's transition:
  first seen -> 'open'; present again after 'resolved' ->
  'reappeared' (and it stays 'reappeared' across later cycles
  until it resolves again); absent from a completed cycle ->
  'resolved'. Only COMPLETED cycles reach the writer — a failed
  or aborted scan never resolves anything.
* resolve_for_broker() is the remediation entry point: when a
  case becomes verified_removed (remediation/verify.py — the only
  caller), the findings whose source matches the case's broker
  move to 'resolved'.

Invariants the writer maintains:
* every row of one identity (across all of the user's jobs)
  carries the SAME lifecycle_state and lifecycle_changed_at;
* lifecycle_changed_at moves ONLY when the state value changes;
* applying the same completed job twice is a no-op, and applying
  a job that a newer completed job has superseded is refused
  (stale) rather than allowed to rewind newer state.
"""

import hashlib
import re
import urllib.parse

from db import pool


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


# ---------------------------------------------------------------------------
# Broker <-> finding matching (shared by events.py's reappearance
# wiring and the lifecycle writer below)
# ---------------------------------------------------------------------------

def _norm_text(value):
    return re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())


def _host_of(url):
    if not url:
        return ""
    host = urllib.parse.urlparse(str(url)).netloc.casefold()
    return host.split("@")[-1].split(":")[0]


def broker_matches_finding(broker, finding):
    """Conservative broker↔finding source match. True when ANY of:
    * the finding's source name IS the broker's name (normalized);
    * the finding's source name IS the broker's slug (normalized);
    * the finding's source URL lives on the broker's own host (the
      host of its opt-out or search URL, or a subdomain of it).
    Anything fuzzier would risk flipping a case — or resolving a
    finding — on a stranger's listing: a missed match costs a
    delay, a wrong match costs the truth of the ledger."""
    source = _norm_text(finding.get("source_name"))
    if source and source in (_norm_text(broker.get("name")),
                             _norm_text(broker.get("slug"))):
        return True
    finding_host = _host_of(finding.get("source_url"))
    if finding_host:
        for url in (broker.get("optout_url"), broker.get("search_url")):
            broker_host = _host_of(url)
            if broker_host and (finding_host == broker_host
                                or finding_host.endswith("." + broker_host)):
                return True
    return False


# ---------------------------------------------------------------------------
# Stored lifecycle writer (Phase 25) — the ONLY code that writes
# findings.lifecycle_state / lifecycle_changed_at.
# ---------------------------------------------------------------------------

LIFECYCLE_STATES = ("open", "resolved", "reappeared")


def _set_identity_state(conn, user_id, identity, state, changed_at):
    """Move EVERY row of one identity to (state, changed_at).
    Rows already carrying exactly that pair are untouched, so a
    no-change application writes nothing and the stamp cannot
    drift."""
    identifier_id, provider, source_name = identity
    conn.execute(
        "UPDATE findings SET lifecycle_state = %s,"
        " lifecycle_changed_at = %s"
        " WHERE user_id = %s"
        " AND identifier_id IS NOT DISTINCT FROM %s"
        " AND provider = %s AND source_name = %s"
        " AND (lifecycle_state IS DISTINCT FROM %s"
        "      OR lifecycle_changed_at IS DISTINCT FROM %s)",
        (state, changed_at, user_id, identifier_id, provider,
         source_name, state, changed_at),
    )


def apply_lifecycle(user_id, job, current, previous):
    """Persist lifecycle transitions for one COMPLETED scan job.

    `job` is the completed job's row (id, finished_at); `current`
    and `previous` are the finding rows of this job and of the
    previous completed job (the sets the completion hook diffed —
    previous is [] for a baseline). Returns
    {"skipped": None | "stale_job", "resolved": [identity, ...],
     "reappeared": [current-job rows that became reappeared]}.

    Transitions (see the module docstring): an identity's prior
    state is read from its rows in OTHER jobs, so remediation's
    resolve_for_broker() is honoured here — a finding remediation
    resolved that shows up in this cycle becomes 'reappeared'
    even though the set diff calls it continuing. A job that a
    newer completed job has already superseded is skipped: its
    diff describes an older world and must not rewind state.
    """
    job_id = str(job["id"])
    with pool.connection() as conn:
        later = conn.execute(
            "SELECT 1 FROM scan_jobs WHERE user_id = %s"
            " AND status = 'done' AND finished_at IS NOT NULL"
            " AND id <> %s AND finished_at > %s LIMIT 1",
            (user_id, job_id, job["finished_at"]),
        ).fetchone()
        if later is not None:
            return {"skipped": "stale_job", "resolved": [],
                    "reappeared": []}
        now = conn.execute("SELECT now() AS now").fetchone()["now"]
        prior_rows = conn.execute(
            "SELECT DISTINCT ON (identifier_id, provider, source_name)"
            " identifier_id, provider, source_name, lifecycle_state,"
            " lifecycle_changed_at FROM findings"
            " WHERE user_id = %s AND job_id <> %s"
            " ORDER BY identifier_id, provider, source_name,"
            " discovered_at DESC, id DESC",
            (user_id, job_id),
        ).fetchall()
    priors = {
        identity_of(row): (row["lifecycle_state"],
                           row["lifecycle_changed_at"])
        for row in prior_rows
    }

    cur = _by_identity(current)
    prev = _by_identity(previous)
    resolved = []
    reappeared = []
    with pool.connection() as conn:
        for identity, row in cur.items():
            prior = priors.get(identity)
            if prior is None:
                # First appearance ever: born 'open', stamped now.
                _set_identity_state(conn, user_id, identity,
                                    "open", now)
            elif prior[0] == "resolved":
                _set_identity_state(conn, user_id, identity,
                                    "reappeared", now)
                reappeared.append(row)
            else:
                # Continuing: the state (and its stamp) carry over
                # unchanged — 'open' stays open, 'reappeared' stays
                # reappeared until it resolves again.
                _set_identity_state(conn, user_id, identity,
                                    prior[0], prior[1])
        for identity in prev:
            if identity in cur:
                continue
            prior = priors.get(identity)
            if prior is not None and prior[0] == "resolved":
                continue  # already resolved; the stamp must not move
            _set_identity_state(conn, user_id, identity,
                                "resolved", now)
            resolved.append(identity)
    return {"skipped": None, "resolved": resolved,
            "reappeared": reappeared}


def resolve_for_broker(user_id, broker):
    """Move every finding of `user_id` whose source matches
    `broker` (broker_matches_finding) to 'resolved'. The
    remediation entry point of the lifecycle writer — called from
    remediation/verify.py at the one moment a case becomes
    verified_removed. Findings already 'resolved' are untouched
    (their stamp is the earlier change). Returns the number of
    identities resolved by this call."""
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT id, identifier_id, provider, source_name,"
            " source_url, lifecycle_state FROM findings"
            " WHERE user_id = %s AND lifecycle_state <> 'resolved'",
            (user_id,),
        ).fetchall()
        now = conn.execute("SELECT now() AS now").fetchone()["now"]
        resolved = 0
        seen = set()
        for row in rows:
            identity = identity_of(row)
            if identity in seen:
                continue
            seen.add(identity)
            if not broker_matches_finding(broker, row):
                continue
            _set_identity_state(conn, user_id, identity,
                                "resolved", now)
            resolved += 1
    return resolved
