"""Data-quality stage over STORED findings (spec Phase 160).

Normalize (scanning/normalize.py) guarantees the shape of a
finding at WRITE time, and the findings table's CHECK
constraints pin the confidence/reliability enums — but nothing
re-examined the rows already stored. A provider payload change,
a normalize change, or a writer bug can leave rows in the table
that no longer match the contract, and duplicates can land
whenever one job stores the same observation twice. This stage
is the periodic second look: it detects, records and surfaces.
It never deletes a finding and never rewrites one — its only
writes are the dq flags on the rows it examined, its own run
ledger (dq_runs) and the per-provider rollup (dq_issue_rollup),
all from migration 0015.

WHAT IT DETECTS.

* duplicate — the same observation stored more than once in
  ONE job. The duplicate key is (job_id, identifier_id,
  provider, source_name, source_url, evidence_ref): one job's
  scan of one identifier yields at most one finding per
  provider/source/URL/evidence payload, so every row past the
  first (by discovered_at, id) under that key is the same
  observation stored again. The key is job-scoped ON PURPOSE:
  the same identity (identifier, provider, source) appearing
  across DIFFERENT jobs is the monitoring design — each cycle
  re-observes the exposure and monitoring/diff.py diffs the
  sets — not duplication.
* malformed — a row violating the normalize contract in ways
  the schema cannot express (see malformed_reasons): details
  not a JSON object, a pwned_count that is not a non-negative
  int, a dns summary that is not {record-type: [strings]},
  exposed_fields holding null/empty/non-string entries, a
  missing or blank source identity, confidence/reliability
  values outside the normalize enums (the CHECK constraints
  should make that last one impossible; the check stays as
  defence in depth for rows that predate or bypass them).
* drift — the same counts grouped per provider into
  dq_issue_rollup, one snapshot per run day. A provider whose
  payload shape changed becomes visible as a step in its
  malformed count between days; flags alone are current truth
  and could not show that.

DISPOSITION — FLAG + REPORT ONLY (the conservative option).
Flagged rows stay fully visible and counted exactly as before:
NO read path (scan results, Action Center counts, profile
scores, the lifecycle writer) filters on dq_duplicate or
dq_malformed in this phase. The flags are an operator signal
surfaced in the admin metrics (the data_quality section), so a
human decides what a flagged cluster means before anything
acts on it; quietly excluding rows would change users' scores
and counts underneath them. When a run leaves any row flagged
malformed, ONE audit row (action 'data_quality.issues',
counts only — no user ids, no finding content) records it;
duplicates alone do not raise the record (a repeated row is a
writer wart, malformed data is the contract breach).

CADENCE + GUARDS. run_once() always runs (tests and operators
call it directly). maybe_run() is the production entry point:
it self-gates against dq_runs so the stage runs at most once
per RUN_INTERVAL however often it is called — the pattern
remediation/source_checks.py set for the daily sweep. The
monitoring scheduler's tick calls maybe_run() after its alert
step, behind the same monitoring_scheduler flag and inside the
same kind of guard: a data-quality failure can never break
the tick that enqueues monitoring scans.
"""

from datetime import datetime, timedelta, timezone

from accounts import audit
from core import logging_setup
from db import pool

RUN_INTERVAL = timedelta(hours=20)

_CONFIDENCE_VALUES = ("exact", "probable", "weak")
_RELIABILITY_VALUES = ("high", "medium", "low")

# The duplicate key, as a PARTITION: rows sharing one job, one
# identifier, one provider/source identity and one evidence
# payload are the same observation. NULLs partition together in
# Postgres (PARTITION BY groups them), which is what
# identifier_id IS NULL / source_url IS NULL rows need.
_DUPLICATE_IDS_SQL = (
    "WITH ranked AS ("
    " SELECT id, ROW_NUMBER() OVER ("
    "   PARTITION BY job_id, identifier_id, provider,"
    "                source_name, source_url, evidence_ref"
    "   ORDER BY discovered_at, id) AS rn"
    " FROM findings)"
    " SELECT id FROM ranked WHERE rn > 1"
)

_FINDING_COLUMNS = (
    "id, provider, source_name, source_url, exposed_fields,"
    " confidence, reliability, details")


def _log(message):
    logging_setup.get_logger().info(message)


# ---------------------------------------------------------------------------
# Malformed detection — the normalize contract, per stored row
# ---------------------------------------------------------------------------

def malformed_reasons(row):
    """The contract violations in one stored finding row (a
    mapping with the _FINDING_COLUMNS fields), as stable reason
    labels. Empty list = the row matches the contract. Pure:
    no database, no clock — the seeded-shape unit tests drive
    this directly."""
    reasons = []

    details = row.get("details")
    if not isinstance(details, dict):
        # jsonb can store arrays/scalars; normalize only ever
        # writes an object. (A NULL details would land here too:
        # the column is NOT NULL, but a stored NULL is exactly
        # the kind of drift this stage exists to catch.)
        reasons.append("details_not_object")
    else:
        pwned = details.get("pwned_count")
        if pwned is not None and (
                isinstance(pwned, bool)
                or not isinstance(pwned, int) or pwned < 0):
            # The password finding's details carry ONLY this
            # count (normalize.password_finding); a string or a
            # float here means the payload shape drifted.
            reasons.append("pwned_count_not_int")
        dns = details.get("dns")
        if dns is not None and (
                not isinstance(dns, dict)
                or any(not isinstance(records, list)
                       or any(not isinstance(r, str)
                              for r in records)
                       for records in dns.values())):
            # normalize.domain_findings stores the DNS snapshot
            # as {record type: [record strings]}.
            reasons.append("dns_summary_shape")

    fields = row.get("exposed_fields")
    if not isinstance(fields, list) or any(
            not isinstance(field, str) or not field.strip()
            for field in fields):
        # text[] columns return a list; NULL or empty entries
        # inside it are invisible to the schema and meaningless
        # to the risk engine that consumes the field names.
        reasons.append("exposed_fields_shape")

    source_name = row.get("source_name")
    if not isinstance(source_name, str) or not source_name.strip():
        reasons.append("source_identity_missing")

    source_url = row.get("source_url")
    if source_url is not None and (
            not isinstance(source_url, str)
            or not source_url.strip()):
        reasons.append("source_url_shape")

    if row.get("confidence") not in _CONFIDENCE_VALUES:
        reasons.append("confidence_value")
    if row.get("reliability") not in _RELIABILITY_VALUES:
        reasons.append("reliability_value")

    return reasons


# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------

def _apply_flags(conn, column, flagged_ids):
    """Set one dq flag column to exactly the computed set: rows
    in the set gain the flag, rows no longer in it lose it (a
    flag is a claim about the row as it stands NOW, recomputed
    every run). Only rows whose value changes are written."""
    ids = [str(fid) for fid in flagged_ids]
    conn.execute(
        "UPDATE findings SET " + column + " = (id = ANY(%s::uuid[]))"
        " WHERE " + column
        + " IS DISTINCT FROM (id = ANY(%s::uuid[]))",
        (ids, ids))


def _flagged_by_provider(conn):
    rows = conn.execute(
        "SELECT provider,"
        " COUNT(*) FILTER (WHERE dq_duplicate) AS duplicates,"
        " COUNT(*) FILTER (WHERE dq_malformed) AS malformed"
        " FROM findings WHERE dq_duplicate OR dq_malformed"
        " GROUP BY provider ORDER BY provider",
    ).fetchall()
    return [{
        "provider": row["provider"],
        "duplicates": int(row["duplicates"]),
        "malformed": int(row["malformed"]),
    } for row in rows]


def run_once(now=None):
    """One data-quality pass over every stored finding. Returns
    the run summary dict (also recorded in dq_runs). Raises only
    on infrastructure failure — production callers (the
    scheduler tick via maybe_run) guard it, like the alerts
    evaluator."""
    now = now or datetime.now(timezone.utc)
    with pool.connection() as conn:
        scanned = int(conn.execute(
            "SELECT COUNT(*) AS n FROM findings").fetchone()["n"])

        duplicate_ids = [row["id"] for row in conn.execute(
            _DUPLICATE_IDS_SQL).fetchall()]

        malformed_ids = []
        for row in conn.execute(
                "SELECT " + _FINDING_COLUMNS + " FROM findings"
        ).fetchall():
            if malformed_reasons(row):
                malformed_ids.append(row["id"])

        _apply_flags(conn, "dq_duplicate", duplicate_ids)
        _apply_flags(conn, "dq_malformed", malformed_ids)

        by_provider = _flagged_by_provider(conn)
        duplicates = sum(p["duplicates"] for p in by_provider)
        malformed = sum(p["malformed"] for p in by_provider)

        # The rollup is a per-day SNAPSHOT of the flags (the
        # drift record), replaced on each run — never an
        # increment, exactly as the flags are recomputed.
        day = now.date()
        conn.execute("DELETE FROM dq_issue_rollup WHERE day = %s",
                     (day,))
        for entry in by_provider:
            for kind, count in (("duplicate", entry["duplicates"]),
                                ("malformed", entry["malformed"])):
                if count:
                    conn.execute(
                        "INSERT INTO dq_issue_rollup"
                        " (provider, day, kind, count)"
                        " VALUES (%s, %s, %s, %s)",
                        (entry["provider"], day, kind, count))

        conn.execute(
            "INSERT INTO dq_runs (ran_at, findings_scanned,"
            " duplicates_flagged, malformed_flagged)"
            " VALUES (%s, %s, %s, %s)",
            (now, scanned, duplicates, malformed))

    summary = {
        "ran_at": now.isoformat(),
        "findings_scanned": scanned,
        "duplicates_flagged": duplicates,
        "malformed_flagged": malformed,
        "by_provider": by_provider,
    }
    _log("data_quality_run scanned=%d duplicates=%d malformed=%d"
         % (scanned, duplicates, malformed))
    if malformed:
        # ONE PII-free audit record per run that leaves malformed
        # rows standing (counts and a provider count only).
        try:
            audit.record(
                None, "system", "data_quality.issues", "findings",
                None, {
                    "malformed_flagged": malformed,
                    "duplicates_flagged": duplicates,
                    "providers_affected": len(by_provider),
                })
        except Exception as exc:  # audit is best-effort by contract
            logging_setup.log_error(
                None, "data quality audit failed: "
                + type(exc).__name__)
    return summary


def maybe_run(now=None):
    """The production entry point: run the pass unless one
    completed within RUN_INTERVAL (the dq_runs ledger is the
    stamp — the source-sweep pattern). Returns the run summary,
    or {"skipped": True, "reason": "ran_recently"}."""
    now = now or datetime.now(timezone.utc)
    with pool.connection() as conn:
        last = conn.execute(
            "SELECT MAX(ran_at) AS last FROM dq_runs").fetchone()
    if last is not None and last["last"] is not None \
            and now - last["last"] < RUN_INTERVAL:
        return {"skipped": True, "reason": "ran_recently"}
    summary = run_once(now)
    summary["skipped"] = False
    return summary


def latest_summary(conn):
    """The admin-metrics view of the stage: the latest run's
    stamp and flag totals, plus that run day's per-provider
    rollup (the drift view). Zeros — with a null last_run_at —
    before the first run."""
    run = conn.execute(
        "SELECT ran_at, duplicates_flagged, malformed_flagged"
        " FROM dq_runs ORDER BY ran_at DESC LIMIT 1",
    ).fetchone()
    if run is None:
        return {"last_run_at": None, "duplicates_flagged": 0,
                "malformed_flagged": 0, "by_provider": []}
    day = run["ran_at"].astimezone(timezone.utc).date()
    rows = conn.execute(
        "SELECT provider, kind, count FROM dq_issue_rollup"
        " WHERE day = %s ORDER BY provider, kind",
        (day,),
    ).fetchall()
    merged = {}
    for row in rows:
        entry = merged.setdefault(
            row["provider"],
            {"provider": row["provider"], "duplicates": 0,
             "malformed": 0})
        if row["kind"] == "duplicate":
            entry["duplicates"] = int(row["count"])
        else:
            entry["malformed"] = int(row["count"])
    return {
        "last_run_at": run["ran_at"].isoformat(),
        "duplicates_flagged": int(run["duplicates_flagged"]),
        "malformed_flagged": int(run["malformed_flagged"]),
        "by_provider": [merged[name] for name in sorted(merged)],
    }
