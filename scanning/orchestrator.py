"""Scan orchestrator (spec Phases 11, 13, 21–26).

run_scan_job(job_id) executes ONE queued full-profile scan:

1. Load the job and the owner's live identifiers. Plaintext values
   come from the vault's reveal_by_id() — the worker runs server-
   side for the account owner, who granted the 'scanning' consent
   before the job could be created. Values are used in memory only:
   never logged, never persisted outside the vault.
2. Per identifier:
   * email — the email_breach + breach_analytics providers run and
     results normalize into findings.
   * phone / name / address / username — NO provider exists yet
     (Stage S6). The outcome is recorded honestly as
     'no_provider_yet' — never as "clean", never with fake findings.
   * passwords are NEVER part of a job: nothing about a password is
     stored anywhere, so there is nothing to check with. Password
     findings exist only in the interactive anonymous scan.
3. Findings persist, then the profile score is computed from ALL
   email findings with the legacy engine (risk.score_email_profile)
   under this documented mapping:
     breaches  = the union of breach names across the user's email
                 identifiers in this job
     analytics = the analytics dict of the email with the highest
                 provider risk_score (provider risk is per-address;
                 the profile takes its worst address), else None
     pwned     = None (jobs never check passwords)
4. The job row stores score + explanation + a summary (per-
   identifier outcomes, clusters, shared-source correlations,
   degraded flag) and ends 'done'.

Failure semantics (the worker owns retries):
* SOME identifiers failing (provider error) is partial failure: the
  job still completes, summary.degraded is true and each failing
  identifier is marked 'provider_error' with its error kind.
* NO identifier producing a definitive outcome because every
  provider call failed is total failure: ScanFailedError is raised
  and the worker retries with backoff — a transient outage must not
  burn a user's one-click scan.
* Infrastructure failures (database down, vault unconfigured)
  propagate and are retried the same way.
"""

import json

from accounts import identifiers as identifiers_service
from db import pool
from providers import registry as providers_registry
from scanning import correlation, normalize, risk
from vault import store as vault_store


class JobNotFoundError(Exception):
    """The job id does not exist (the worker drops it silently)."""


class ScanFailedError(Exception):
    """Total scan failure — retryable. error_kind is a stable,
    log-safe label (never exception text with user data)."""

    def __init__(self, error_kind):
        super().__init__(error_kind)
        self.error_kind = error_kind


def _provider(capability):
    found = providers_registry.get_registry().get_providers(capability)
    return found[0] if found else None


def _load_job(job_id):
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT id, user_id, status FROM scan_jobs WHERE id = %s",
            (job_id,),
        ).fetchone()
    if row is None:
        raise JobNotFoundError(str(job_id))
    return row


def _scan_email(record, value):
    """Run the email providers for one identifier.
    Returns (findings, outcome, analytics_or_none)."""
    outcome = {
        "identifier_id": record["id"],
        "kind": record["kind"],
        "masked": record["masked"],
        "outcome": "scanned",
        "findings": 0,
        "error_kind": None,
    }
    provider = _provider("email_breach")
    result = provider.check_email(value) if provider is not None else None
    if result is None or result.status != "ok":
        outcome["outcome"] = "provider_error"
        outcome["error_kind"] = (
            getattr(result, "error_kind", None) or "provider_unavailable")
        return [], outcome, None
    analytics = None
    analytics_provider = _provider("breach_analytics")
    if analytics_provider is not None:
        aresult = analytics_provider.breach_analytics(value)
        if aresult.status == "ok":
            analytics = aresult.data
        else:
            outcome["error_kind"] = (
                getattr(aresult, "error_kind", None) or "analytics_error")
    findings = normalize.email_findings(
        provider.info.name, record["id"], record["kind"], value,
        result.data, analytics)
    for finding in findings:
        finding["identifier_masked"] = record["masked"]
    outcome["findings"] = len(findings)
    return findings, outcome, analytics


def _insert_findings(conn, job_id, user_id, findings):
    for f in findings:
        conn.execute(
            "INSERT INTO findings (job_id, user_id, identifier_id,"
            " identifier_kind, provider, source_name, source_url,"
            " source_date, exposed_fields, confidence, reliability,"
            " evidence_ref, remediation_eligible, details)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,"
            " %s, %s::jsonb)",
            (job_id, user_id, f["identifier_id"], f["identifier_kind"],
             f["provider"], f["source_name"], f["source_url"],
             f["source_date"], f["exposed_fields"], f["confidence"],
             f["reliability"], f["evidence_ref"],
             f["remediation_eligible"], json.dumps(f["details"])),
        )


def run_scan_job(job_id):
    """Execute one scan job end to end. On success the job row is
    'done' with score/explanation/summary stored. Raises
    JobNotFoundError, ScanFailedError, or an infrastructure error
    (the worker's retry policy handles the latter two)."""
    job = _load_job(job_id)
    user_id = str(job["user_id"])
    records = identifiers_service.list_identifiers(user_id)

    all_findings = []
    outcomes = []
    analytics_by_email = []
    definitive = False
    degraded = False

    for record in records:
        if record["kind"] != "email":
            outcomes.append({
                "identifier_id": record["id"],
                "kind": record["kind"],
                "masked": record["masked"],
                "outcome": "no_provider_yet",
                "findings": 0,
                "error_kind": None,
            })
            definitive = True
            continue
        value = vault_store.reveal_by_id(record["id"], user_id)
        if value is None:
            outcomes.append({
                "identifier_id": record["id"],
                "kind": record["kind"],
                "masked": record["masked"],
                "outcome": "provider_error",
                "findings": 0,
                "error_kind": "identifier_unreadable",
            })
            degraded = True
            continue
        findings, outcome, analytics = _scan_email(record, value)
        outcomes.append(outcome)
        if outcome["outcome"] == "scanned":
            definitive = True
            all_findings.extend(findings)
            if analytics is not None:
                analytics_by_email.append(analytics)
            if outcome["error_kind"]:
                degraded = True  # analytics failed; findings still real
        else:
            degraded = True

    if not definitive:
        raise ScanFailedError("provider_unavailable")

    # ---- profile score: documented aggregation over email findings
    breach_names = sorted({
        f["source_name"] for f in all_findings
        if f["identifier_kind"] == "email"})
    best_analytics = None
    best_risk = None
    for analytics in analytics_by_email:
        value = analytics.get("risk_score")
        if isinstance(value, (int, float)) and (
                best_risk is None or value > best_risk):
            best_risk = value
            best_analytics = analytics
    score, explanation = risk.score_email_profile(
        breach_names, best_analytics, None)

    corr = correlation.correlate(all_findings)
    summary = {
        "identifiers": outcomes,
        "clusters": corr["clusters"],
        "correlations": corr["correlations"],
        "degraded": degraded,
        "findings_total": len(all_findings),
    }

    with pool.connection() as conn:
        _insert_findings(conn, job_id, user_id, all_findings)
        conn.execute(
            "UPDATE scan_jobs SET status = 'done', score = %s,"
            " score_explanation = %s::jsonb, summary = %s::jsonb,"
            " error_kind = NULL, finished_at = now() WHERE id = %s",
            (score, json.dumps(explanation), json.dumps(summary), job_id),
        )
    return {"job_id": str(job_id), "score": score,
            "findings": len(all_findings), "degraded": degraded}
