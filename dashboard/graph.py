"""Exposure graph API service — the layer behind GET /api/graph
(Stage S14, spec Phase 104).

A READ MODEL over rows that already exist — the caller's latest
completed scan job's findings and their remediation cases — drawn
as a three-layer graph:

    saved detail  ──found in──▶  source  ──removal──▶  broker

Honesty rules (the same discipline as the rest of the platform):

* Only REAL rows become nodes and edges. An identifier is a node
  only when the latest completed scan actually found it somewhere;
  a source is a node only because a finding names it; a broker is
  a node only because a remediation case exists for it. Nothing is
  inferred, padded or drawn "for completeness" — a user with no
  scan and no cases gets an honestly empty graph.
* Identifier nodes carry the vault's MASKED rendering only
  (``b•••@example.com``) — the same display-safe string every list
  view uses. Raw values never leave the vault, here included.
* A source→broker edge exists only when the Stage S8 reappearance
  matcher (monitoring.diff.broker_matches_finding) accepts the
  pair: the source name IS the broker's name or slug, or the
  source URL lives on the broker's own host. Anything fuzzier
  would draw a removal path we cannot back with a case.
* A broker node's status is its most recent case's status — the
  case ledger is the only truth about removal progress.
* The `propagation` section (Phases 104/152) uses that same
  conservative matcher over the caller's latest-scan findings and
  the full broker registry. A broker is listed for a source only
  when the matcher accepts the pair; a matched broker with no case
  is reported as `not_started`. This is an action list — brokers
  LeakGuard can act on for that source — not a claim about every
  place information may have travelled.

Authorization by construction (the Stage S3 pattern): the
function takes the caller's user id and scopes every query by it.
"""

from db import pool
from monitoring import diff as _diff


def _source_key(provider, source_name):
    return "%s|%s" % (provider, source_name)


_PROPAGATION_STATUSES = (
    "verified_removed", "submitted", "in_progress", "needs_human",
    "blocked", "not_started",
)


def _propagation_status(case_status):
    """Normalize a remediation case status for propagation.

    The propagation contract uses `in_progress` for work that has
    been queued, is running, or has reappeared and therefore needs
    another removal cycle. A failed case is grouped as `blocked`
    for the summary, while the entry also carries the exact
    `case_status`, so the normalization never hides the ledger's
    own word.
    """
    if case_status is None:
        return "not_started"
    if case_status in ("queued", "running", "reappeared"):
        return "in_progress"
    if case_status == "failed":
        return "blocked"
    if case_status in _PROPAGATION_STATUSES:
        return case_status
    return "in_progress"


def exposure_graph(user_id):
    """The caller's exposure graph, plus its propagation section.

    Returns {"nodes": [...], "edges": [...], "propagation": {...}}.

    Node shapes (all carry "id" and "type"):
      identifier — {"kind", "label"} where label is MASKED only.
      source     — {"label", "provider"} from the latest scan.
      broker     — {"label", "slug", "status"} from the newest
                   remediation case for that broker.
    Edge shapes: {"from", "to", "kind"} with kind "found_in"
    (identifier→source) or "removal" (source→broker).
    Propagation shapes:
      entries — one per (identifier, source), with only brokers
                accepted by the conservative source matcher and
                each broker's normalized + exact case status.
      rollups — per-identifier counts of those broker associations
                by normalized status, zero-filled for every status.
    """
    with pool.connection() as conn:
        latest = conn.execute(
            "SELECT id FROM scan_jobs"
            " WHERE user_id = %s AND status = 'done'"
            " AND finished_at IS NOT NULL"
            " ORDER BY finished_at DESC, id DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        findings = []
        if latest is not None:
            findings = conn.execute(
                "SELECT identifier_id, provider, source_name, source_url"
                " FROM findings WHERE user_id = %s AND job_id = %s",
                (user_id, latest["id"]),
            ).fetchall()
        case_rows = conn.execute(
            "SELECT c.broker_slug, c.status, b.name AS broker_name,"
            " b.optout_url, b.search_url FROM remediation_cases c"
            " JOIN brokers b ON b.slug = c.broker_slug"
            " WHERE c.user_id = %s"
            " ORDER BY c.created_at DESC, c.id DESC",
            (user_id,),
        ).fetchall()
        broker_registry_rows = conn.execute(
            "SELECT slug, name, optout_url, search_url FROM brokers"
            " WHERE active = true ORDER BY name, slug",
        ).fetchall()
        identifier_ids = sorted(
            {row["identifier_id"] for row in findings
             if row["identifier_id"] is not None},
            key=str)
        identifier_rows = []
        if identifier_ids:
            identifier_rows = conn.execute(
                "SELECT id, kind, masked FROM identifiers"
                " WHERE user_id = %s AND deleted_at IS NULL"
                " AND id = ANY(%s)",
                (user_id, identifier_ids),
            ).fetchall()

    nodes = []
    edges = []

    # --- identifiers (masked labels only) ---
    identifier_node_ids = set()
    ident_nodes = []
    for row in identifier_rows:
        node_id = "identifier:%s" % row["id"]
        identifier_node_ids.add(node_id)
        ident_nodes.append({
            "id": node_id,
            "type": "identifier",
            "kind": row["kind"],
            "label": row["masked"],
        })
    ident_nodes.sort(key=lambda n: (n["kind"], n["label"]))
    nodes.extend(ident_nodes)

    # --- sources (distinct provider/source_name pairs) ---
    source_rows = {}
    for row in findings:
        key = _source_key(row["provider"], row["source_name"])
        source_rows.setdefault(key, row)
    source_nodes = []
    for key in sorted(source_rows,
                      key=lambda k: (source_rows[k]["source_name"],
                                     source_rows[k]["provider"])):
        row = source_rows[key]
        source_nodes.append({
            "id": "source:%s" % key,
            "type": "source",
            "label": row["source_name"],
            "provider": row["provider"],
        })
    nodes.extend(source_nodes)

    # --- brokers (newest case per broker wins) ---
    broker_by_slug = {}
    for row in case_rows:
        broker_by_slug.setdefault(row["broker_slug"], row)
    broker_nodes = []
    for slug in sorted(broker_by_slug,
                       key=lambda s: broker_by_slug[s]["broker_name"]):
        row = broker_by_slug[slug]
        broker_nodes.append({
            "id": "broker:%s" % slug,
            "type": "broker",
            "label": row["broker_name"],
            "slug": slug,
            "status": row["status"],
        })
    nodes.extend(broker_nodes)

    # --- edges: identifier → source ("found in") ---
    found_in = set()
    for row in findings:
        if row["identifier_id"] is None:
            continue
        from_id = "identifier:%s" % row["identifier_id"]
        if from_id not in identifier_node_ids:
            continue
        to_id = "source:%s" % _source_key(row["provider"],
                                          row["source_name"])
        found_in.add((from_id, to_id))
    for from_id, to_id in sorted(found_in):
        edges.append({"from": from_id, "to": to_id, "kind": "found_in"})

    # --- edges: source → broker (the S8 matching rule, reused) ---
    removal = set()
    finding_variants = {}
    for row in findings:
        key = _source_key(row["provider"], row["source_name"])
        finding_variants.setdefault(key, []).append(row)
    for key, variants in finding_variants.items():
        for slug, case in broker_by_slug.items():
            broker = {
                "name": case["broker_name"],
                "slug": slug,
                "optout_url": case["optout_url"],
                "search_url": case["search_url"],
            }
            if any(_diff.broker_matches_finding(
                    broker,
                    {"source_name": v["source_name"],
                     "source_url": v["source_url"]})
                    for v in variants):
                removal.add(("source:%s" % key, "broker:%s" % slug))
    for from_id, to_id in sorted(removal):
        edges.append({"from": from_id, "to": to_id, "kind": "removal"})

    # --- propagation (Phases 104/152) ---
    # For each source in the latest scan, list ONLY registry brokers
    # accepted by the same conservative matcher used for removal
    # edges. A matched broker with no remediation case is honestly
    # "not_started"; an unmatched source gets an empty broker list.
    identifier_by_id = {
        str(row["id"]): row for row in identifier_rows
    }
    case_status_by_slug = {
        slug: row["status"] for slug, row in broker_by_slug.items()
    }
    propagation_entries_by_key = {}
    matched_slugs_by_key = {}
    for row in findings:
        identifier_id = row["identifier_id"]
        if identifier_id is None:
            continue
        identifier_key = str(identifier_id)
        if identifier_key not in identifier_by_id:
            continue
        source_key = _source_key(row["provider"], row["source_name"])
        entry_key = (identifier_key, source_key)
        if entry_key not in propagation_entries_by_key:
            ident = identifier_by_id[identifier_key]
            propagation_entries_by_key[entry_key] = {
                "identifier_id": identifier_key,
                "identifier": {
                    "kind": ident["kind"],
                    "label": ident["masked"],
                },
                "source": {
                    "provider": row["provider"],
                    "name": row["source_name"],
                },
                "brokers": [],
            }
            matched_slugs_by_key[entry_key] = set()
        finding = {
            "source_name": row["source_name"],
            "source_url": row["source_url"],
        }
        for broker_row in broker_registry_rows:
            slug = broker_row["slug"]
            if slug in matched_slugs_by_key[entry_key]:
                continue
            broker = {
                "name": broker_row["name"],
                "slug": slug,
                "optout_url": broker_row["optout_url"],
                "search_url": broker_row["search_url"],
            }
            if _diff.broker_matches_finding(
                    broker, finding):
                matched_slugs_by_key[entry_key].add(slug)
                case_status = case_status_by_slug.get(slug)
                propagation_entries_by_key[entry_key]["brokers"].append({
                    "slug": slug,
                    "name": broker_row["name"],
                    "status": _propagation_status(case_status),
                    "case_status": case_status,
                })
    propagation_entries = []
    for entry_key in sorted(
            propagation_entries_by_key,
            key=lambda key: (
                propagation_entries_by_key[key]["identifier"]["kind"],
                propagation_entries_by_key[key]["identifier"]["label"],
                propagation_entries_by_key[key]["source"]["name"],
                propagation_entries_by_key[key]["source"]["provider"],
            )):
        entry = propagation_entries_by_key[entry_key]
        entry["brokers"].sort(
            key=lambda broker: (broker["name"], broker["slug"]))
        propagation_entries.append(entry)

    rollups_by_identifier = {}
    for entry in propagation_entries:
        identifier_id = entry["identifier_id"]
        if identifier_id not in rollups_by_identifier:
            rollups_by_identifier[identifier_id] = {
                "identifier_id": identifier_id,
                "identifier": entry["identifier"],
                "counts": {
                    status: 0 for status in _PROPAGATION_STATUSES
                },
            }
        counts = rollups_by_identifier[identifier_id]["counts"]
        for broker in entry["brokers"]:
            counts[broker["status"]] += 1
    propagation_rollups = [
        rollups_by_identifier[key]
        for key in sorted(
            rollups_by_identifier,
            key=lambda identifier_id: (
                rollups_by_identifier[identifier_id]["identifier"]["kind"],
                rollups_by_identifier[identifier_id]["identifier"]["label"],
            ))
    ]

    return {
        "nodes": nodes,
        "edges": edges,
        "propagation": {
            "entries": propagation_entries,
            "rollups": propagation_rollups,
        },
    }
