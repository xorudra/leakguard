"""Removal verification + reappearance (spec Phases 38, 39, 155).

The honesty core of the engine: a case may be called removed ONLY
when a verification check says the data is gone. verify_case runs
the executor's search-presence probe and records EVERY outcome in
verification_checks — gone, still_present and unknown alike — then
applies the transition rules:

  submitted        + gone          -> verified_removed
  submitted        + still_present -> stays submitted (reason still_listed)
  submitted        + unknown       -> no change (a check is not a guess)
  verified_removed + still_present -> reappeared (the data came back)
  verified_removed + gone/unknown  -> stays verified_removed

mark_reappeared() is the same flip driven from outside (a future
scan finding / orchestrator hook): it records the evidence as a
verification check and moves a verified_removed case to reappeared.
Nothing else may set 'reappeared' or 'verified_removed'.

The verified_removed flip is also the one moment findings learn
about a removal: _apply_outcome hands the case to
_resolve_findings(), which moves the broker's findings to
'resolved' in the stored finding lifecycle (Phase 25) through its
single writer (monitoring/diff.py's resolve_for_broker).
"""

from core import errors
from db import pool
from remediation import engine, registry_seed, service

_VERIFIABLE = ("submitted", "verified_removed")
_OUTCOMES = ("still_present", "gone", "unknown")


def _record_check(conn, case_id, method, outcome, evidence_ref):
    conn.execute(
        "INSERT INTO verification_checks"
        " (case_id, method, outcome, evidence_ref)"
        " VALUES (%s, %s, %s, %s)",
        (case_id, method, outcome, evidence_ref),
    )


def _resolve_findings(case):
    """Phase 25: a case that just became verified_removed resolves
    its broker's findings in the stored lifecycle. Best-effort by
    design — the case ledger is already the fact at this point, so
    a lifecycle failure is logged, never raised into the
    verification that already succeeded (the next completed scan
    cycle re-settles the state from the same writer)."""
    try:
        from monitoring import diff as lifecycle

        broker = registry_seed.get_broker(case["broker_slug"])
        if broker is not None:
            lifecycle.resolve_for_broker(str(case["user_id"]), broker)
    except Exception as exc:
        from core import logging_setup

        logging_setup.log_error(
            None, "lifecycle resolve on verified removal failed: "
            + type(exc).__name__)


def _apply_outcome(case, outcome, method, evidence_ref):
    """Record the check and apply the transition table above."""
    status = case["status"]
    flipped = False
    with pool.connection() as conn:
        _record_check(conn, case["id"], method, outcome, evidence_ref)
        if status == "submitted" and outcome == "gone":
            conn.execute(
                "UPDATE remediation_cases"
                " SET status = 'verified_removed', reason = NULL,"
                " updated_at = now() WHERE id = %s",
                (case["id"],),
            )
            flipped = True
        elif status == "submitted" and outcome == "still_present":
            conn.execute(
                "UPDATE remediation_cases SET reason = 'still_listed',"
                " updated_at = now() WHERE id = %s",
                (case["id"],),
            )
        elif status == "verified_removed" and outcome == "still_present":
            conn.execute(
                "UPDATE remediation_cases SET status = 'reappeared',"
                " reason = 'found_again', updated_at = now()"
                " WHERE id = %s",
                (case["id"],),
            )
    if flipped:
        _resolve_findings(case)


def verify_case(user_id, case_id, executor=None):
    """Run a verification check on one of the caller's cases, now.
    Returns {case, outcome}. Cases with nothing to verify (queued,
    needs_human, blocked, failed, reappeared) answer 409."""
    row = service._case_row(user_id, case_id)
    if row["status"] not in _VERIFIABLE:
        raise errors.conflict(
            "not_verifiable",
            "This case has no submitted request to verify yet")
    executor = executor if executor is not None else engine.AgentExecutor()
    broker = registry_seed.get_broker(row["broker_slug"])
    profile = engine.assemble_profile(user_id)
    result = executor.verify_search(profile, broker)
    if isinstance(result, dict):
        outcome = result.get("outcome")
        evidence_ref = result.get("evidence_ref")
        # The executor names the evidence source (search_index /
        # broker_search / none / unconfigured) so the check row
        # records HOW the verdict was reached; stub executors that
        # predate the source map keep the legacy label.
        method = result.get("method") or "search_probe"
    else:  # a bare outcome string is an acceptable executor result
        outcome, evidence_ref, method = result, None, "search_probe"
    if outcome not in _OUTCOMES:
        outcome = "unknown"
    _apply_outcome(row, outcome, method, evidence_ref)
    return {"case": service.public_case(
        service._case_row(user_id, case_id)), "outcome": outcome}


def mark_reappeared(case_id, evidence_ref=None):
    """Flip a verified_removed case to reappeared on external
    evidence (e.g. a scan finding — Stage S8's orchestrator hook).
    Records the evidence as a verification check. Returns True when
    the flip happened; any other status is left untouched."""
    case = engine.load_case(case_id)
    if case is None or case["status"] != "verified_removed":
        return False
    _apply_outcome(case, "still_present", "scan_finding", evidence_ref)
    return True
