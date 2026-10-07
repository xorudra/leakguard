"""Search exposure API service (spec Phase 40) — the layer behind
GET /api/search-exposure.

One place that answers "what does a search engine show about me?":
the caller's own public-web DISCOVERY findings (the DuckDuckGo
Discovery hits a scan records for a phone number, name, address or
username), grouped by the saved detail they were found for.

A discovery finding is, by construction (scanning/normalize.py),
a WEAK-confidence public web mention: a page that mentions the
detail. A mention is a lead to review — never proof the page is
about the caller, and this view never presents it as one. The
finding selection pins BOTH markers of that construction: the
provider name and details.match_kind = 'public_web_mention', so
breach findings, platform-presence findings and domain records
never leak into this view.

Authorization by construction (the Stage S3 pattern): the
function takes the session's user id and scopes every query by
it; another user's findings are unreachable. Responses carry the
vault's masked rendering of each detail — never the raw value.

----------------------------------------------------------------
CAP REVIEW (Phase 40) — the 6-queries-per-job discovery cap:
KEEP DISCOVERY_BUDGET = 6 (scanning/orchestrator.py). Reasoning:

* The cap is a POLITENESS budget against a scraped public
  endpoint (DuckDuckGo's HTML results, no API key, no published
  quota), not a cost control. The scarce resource is the
  endpoint's tolerance for automated queries from shared
  datacenter IPs: hammering it risks IP-level blocks that would
  break discovery for every user, not just the heavy one.
* Coverage arithmetic does not justify raising it. A job scans
  the identifiers the user saved; each phone/name/address costs
  exactly ONE quoted query and a username costs one (platform
  presence checks do not consume the budget). Six queries cover
  six non-email details per job — a fuller household profile
  than the product's own UX law targets (details entered once,
  one command). Identifiers past the budget are not skipped
  silently: the job summary reports them 'budget_exhausted'
  (scanned-but-incomplete), and the next scheduled monitoring
  cycle re-checks them — discovery is a recurring watch, not a
  one-shot census.
* The daily ceiling is already governed separately: the P2-D
  provider budget caps DuckDuckGo Discovery at 1,000 calls/day
  platform-wide (providers/usage.py), and the Phase 158 per-user
  budget caps hand-started jobs at 50/user/day, so worst-case
  discovery load is bounded by those two governors no matter
  what this per-job cap is. Raising the per-job cap would only
  let one job crowd out the shared daily budget faster.
* No evidence of under-coverage exists to outweigh that: the
  data-quality stage (Phase 160) and scan summaries show
  budget_exhausted outcomes are the designed, reported path —
  not lost data. Revisit only with measured evidence that real
  profiles routinely exceed six non-email details AND that the
  daily provider budget has headroom to spare.
----------------------------------------------------------------
"""

from db import pool
from scanning.jobs import _public_finding

_DISCOVERY_PROVIDER = "DuckDuckGo Discovery"
_DISCOVERY_MATCH_KIND = "public_web_mention"


def search_exposure(user_id):
    """The caller's discovery findings, grouped by identifier.

    Returns {"identifiers": [ {identifier_id, identifier_kind,
    identifier_masked, findings: [_public_finding, ...]}, ...],
    "total_findings": n}. Identifiers with no discovery findings
    do not appear; a user with none gets an empty list — the
    honest empty state the SPA renders."""
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT f.*, i.masked AS identifier_masked FROM findings f"
            " LEFT JOIN identifiers i ON i.id = f.identifier_id"
            " WHERE f.user_id = %s AND f.provider = %s"
            " AND f.details->>'match_kind' = %s"
            " ORDER BY f.identifier_kind, f.identifier_id,"
            " f.discovered_at DESC, f.id",
            (user_id, _DISCOVERY_PROVIDER, _DISCOVERY_MATCH_KIND),
        ).fetchall()
    groups = {}
    order = []
    for row in rows:
        key = str(row["identifier_id"]) if row["identifier_id"] \
            else "unlinked"
        if key not in groups:
            groups[key] = {
                "identifier_id": (str(row["identifier_id"])
                                  if row["identifier_id"] else None),
                "identifier_kind": row["identifier_kind"],
                "identifier_masked": row.get("identifier_masked"),
                "findings": [],
            }
            order.append(key)
        groups[key]["findings"].append(_public_finding(row))
    return {
        "identifiers": [groups[key] for key in order],
        "total_findings": len(rows),
    }
