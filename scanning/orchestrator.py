"""Scan orchestrator (spec Phases 11, 13, 21–26).

run_scan_job(job_id) executes ONE queued full-profile scan:

1. Load the job and the owner's live identifiers. Plaintext values
   come from the vault's reveal_by_id() — the worker runs server-
   side for the account owner, who granted the 'scanning' consent
   before the job could be created. Values are used in memory only:
   never logged, never persisted outside the vault.
2. Per identifier (Stage S6 added the non-email kinds):
   * email — the email_breach + breach_analytics providers run and
     results normalize into findings.
   * phone / name / address — ONE quoted public-web discovery query
     each; hits are 'weak' candidate mentions, never confirmations.
   * username — public platform presence checks (a registered exact
     handle is 'probable', never proof of identity) + one discovery
     query.
   * domain — ONLY when the domains table says this user verified
     it: a public DNS snapshot + certificate-transparency names
     ('exact' — factual records). Unverified domains are never
     scanned; their outcome is 'domain_unverified'.
   * any other kind — no provider: outcome 'no_provider_yet',
     never "clean", never with fake findings.
   * Discovery politeness budget: at most DISCOVERY_BUDGET web
     discovery queries per job across ALL identifiers (platform and
     DNS checks do not consume it). Identifiers past the budget are
     reported scanned-but-incomplete ('budget_exhausted'), never
     silently treated as fully checked.
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

from accounts import domains as domains_service
from accounts import identifiers as identifiers_service
from db import pool
from providers import registry as providers_registry
from scanning import correlation, normalize, risk
from vault import store as vault_store

# Maximum public-web discovery queries per scan job (Stage S6
# politeness + cost control, spec Phases 20, 66). Platform presence
# checks and DNS lookups do not consume this budget.
DISCOVERY_BUDGET = 6


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


def _base_outcome(record, outcome):
    return {
        "identifier_id": record["id"],
        "kind": record["kind"],
        "masked": record["masked"],
        "outcome": outcome,
        "findings": 0,
        "error_kind": None,
    }


class _DiscoveryBudget:
    """Counts web-discovery queries for one job; take() answers
    whether one more query is allowed."""

    def __init__(self, limit=DISCOVERY_BUDGET):
        self.limit = limit
        self.used = 0

    def take(self):
        if self.used >= self.limit:
            return False
        self.used += 1
        return True


def _discovery_query(kind, value):
    """The one quoted query a discovery-checked identifier gets.
    Phones are searched by their normalized digits (the canonical
    form listings are indexed by); names, addresses and handles are
    searched as saved."""
    if kind == "phone":
        return '"%s"' % vault_store.normalize("phone", value)
    return '"%s"' % str(value).strip().lstrip("@")


def _scan_discovery(record, value, budget):
    """phone / name / address: one quoted public-web query.
    Returns (findings, outcome)."""
    outcome = _base_outcome(record, "scanned")
    provider = _provider("web_discovery")
    if provider is None:
        outcome["outcome"] = "no_provider_yet"
        return [], outcome
    if not budget.take():
        outcome["error_kind"] = "budget_exhausted"
        return [], outcome
    result = provider.search(_discovery_query(record["kind"], value))
    if result.status != "ok":
        outcome["outcome"] = "provider_error"
        outcome["error_kind"] = (
            getattr(result, "error_kind", None) or "provider_unavailable")
        return [], outcome
    findings = normalize.discovery_findings(
        provider.info.name, record["id"], record["kind"], value,
        result.data)
    for finding in findings:
        finding["identifier_masked"] = record["masked"]
    outcome["findings"] = len(findings)
    return findings, outcome


def _scan_username(record, value, budget):
    """username: platform presence checks + one discovery query.
    Either source answering makes the outcome 'scanned'; a failed
    sibling source is reported via error_kind (degraded), exactly
    like a failed analytics call on the email path."""
    outcome = _base_outcome(record, "scanned")
    findings = []
    errors = []
    answered = False

    provider = _provider("username_presence")
    if provider is not None:
        result = provider.check_username(value)
        if result.status == "ok":
            answered = True
            findings.extend(normalize.username_presence_findings(
                provider.info.name, record["id"], value, result.data))
        else:
            errors.append(getattr(result, "error_kind", None)
                          or "provider_unavailable")

    discovery = _provider("web_discovery")
    if discovery is not None:
        if budget.take():
            result = discovery.search(
                _discovery_query("username", value))
            if result.status == "ok":
                answered = True
                findings.extend(normalize.discovery_findings(
                    discovery.info.name, record["id"], "username",
                    value, result.data))
            else:
                errors.append(getattr(result, "error_kind", None)
                              or "provider_unavailable")
        else:
            errors.append("budget_exhausted")

    if not answered and provider is None and discovery is None:
        outcome["outcome"] = "no_provider_yet"
        return [], outcome
    if not answered:
        outcome["outcome"] = "provider_error"
        outcome["error_kind"] = errors[0] if errors else "provider_unavailable"
        return [], outcome
    for finding in findings:
        finding["identifier_masked"] = record["masked"]
    outcome["findings"] = len(findings)
    if errors:
        outcome["error_kind"] = errors[0]
    return findings, outcome


def _scan_domain(record, value, verified_names):
    """domain: public DNS + certificate facts, ONLY for domains the
    owner has verified (the domains table is the gate). An
    unverified domain is never queried — its outcome says why."""
    outcome = _base_outcome(record, "scanned")
    normalized = vault_store.normalize("domain", value)
    if normalized not in verified_names:
        outcome["outcome"] = "domain_unverified"
        return [], outcome
    provider = _provider("domain_dns")
    cert_provider = _provider("domain_certs") or provider
    if provider is None:
        outcome["outcome"] = "no_provider_yet"
        return [], outcome
    snapshot = certs = None
    errors = []
    result = provider.dns_snapshot(normalized)
    if result.status == "ok":
        snapshot = result.data
    else:
        errors.append(getattr(result, "error_kind", None)
                      or "provider_unavailable")
    if cert_provider is not None:
        result = cert_provider.cert_names(normalized)
        if result.status == "ok":
            certs = result.data
        else:
            errors.append(getattr(result, "error_kind", None)
                          or "provider_unavailable")
    if snapshot is None and certs is None:
        outcome["outcome"] = "provider_error"
        outcome["error_kind"] = errors[0] if errors else "provider_unavailable"
        return [], outcome
    findings = normalize.domain_findings(
        provider.info.name, record["id"], normalized, snapshot, certs)
    for finding in findings:
        finding["identifier_masked"] = record["masked"]
    outcome["findings"] = len(findings)
    if errors:
        outcome["error_kind"] = errors[0]
    return findings, outcome


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

    budget = _DiscoveryBudget()
    verified_names = None  # loaded lazily, only if a domain appears

    def absorb(findings, outcome):
        """Fold one identifier's result into the job tallies.
        'scanned', 'no_provider_yet' and 'domain_unverified' are
        definitive outcomes (the identifier was dealt with honestly);
        'provider_error' is not, and degrades the job."""
        nonlocal definitive, degraded
        outcomes.append(outcome)
        if outcome["outcome"] in ("scanned", "no_provider_yet",
                                  "domain_unverified"):
            definitive = True
            all_findings.extend(findings)
            if outcome["error_kind"]:
                degraded = True  # partial data; findings still real
        else:
            degraded = True

    for record in records:
        value = vault_store.reveal_by_id(record["id"], user_id)
        if value is None:
            absorb([], {
                "identifier_id": record["id"],
                "kind": record["kind"],
                "masked": record["masked"],
                "outcome": "provider_error",
                "findings": 0,
                "error_kind": "identifier_unreadable",
            })
            continue
        kind = record["kind"]
        if kind == "email":
            findings, outcome, analytics = _scan_email(record, value)
            absorb(findings, outcome)
            if analytics is not None:
                analytics_by_email.append(analytics)
        elif kind in ("phone", "name", "address"):
            findings, outcome = _scan_discovery(record, value, budget)
            absorb(findings, outcome)
        elif kind == "username":
            findings, outcome = _scan_username(record, value, budget)
            absorb(findings, outcome)
        elif kind == "domain":
            if verified_names is None:
                verified_names = domains_service.verified_domain_names(
                    user_id)
            findings, outcome = _scan_domain(record, value,
                                             verified_names)
            absorb(findings, outcome)
        else:
            absorb([], _base_outcome(record, "no_provider_yet"))

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
        "discovery_queries_used": budget.used,
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
