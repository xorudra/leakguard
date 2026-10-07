"""Identity correlation within one scan job (spec Phase 22).

Deliberately conservative — this stage produces exactly two things:

* clusters: findings grouped by identifier. A cluster's id is the
  short form (first 12 hex chars) of the identifier's vault lookup
  HMAC — stable across jobs, meaningless without the lookup key,
  and never the identifier value.
* correlations: shared-source notes. When the SAME source name
  appears under two or more DIFFERENT identifiers of the same user,
  that is worth one explainable note ("the same breach likely
  exposed several of your details at once") with confidence
  "probable" — the shared source is a fact of the results, the
  single-incident reading of it is an inference, and it is labelled
  as one. Weak signals are never silently upgraded to facts, and no
  other correlation type is emitted at this stage.
"""

CLUSTER_ID_LENGTH = 12


def correlate(findings):
    """findings: normalized finding dicts (see normalize.py), each
    carrying identifier_id / identifier_kind / identifier_hmac and
    optionally identifier_masked. Returns
    {"clusters": [...], "correlations": [...]}."""
    by_identifier = {}
    for finding in findings:
        key = finding.get("identifier_id") or finding.get("identifier_hmac")
        if key is None:
            continue
        cluster = by_identifier.get(key)
        if cluster is None:
            hmac_hex = finding.get("identifier_hmac") or ""
            cluster = by_identifier[key] = {
                "cluster_id": hmac_hex[:CLUSTER_ID_LENGTH] or None,
                "identifier_id": finding.get("identifier_id"),
                "identifier_kind": finding.get("identifier_kind"),
                "identifier_masked": finding.get("identifier_masked"),
                "finding_count": 0,
                "sources": [],
            }
        cluster["finding_count"] += 1
        name = finding.get("source_name")
        if name and name not in cluster["sources"]:
            cluster["sources"].append(name)

    by_source = {}
    for finding in findings:
        key = finding.get("identifier_id") or finding.get("identifier_hmac")
        name = finding.get("source_name")
        if key is None or not name:
            continue
        entry = by_source.setdefault(name, {})
        entry[key] = finding.get("identifier_kind")

    correlations = []
    for source_name in sorted(by_source):
        identifiers = by_source[source_name]
        if len(identifiers) < 2:
            continue
        kinds = sorted({k for k in identifiers.values() if k})
        correlations.append({
            "type": "shared_source",
            "source_name": source_name,
            "identifier_kinds": kinds,
            "confidence": "probable",
            "reason": (
                "%s appears in the results for %d of your saved details "
                "(%s) — the same breach likely exposed several of your "
                "details at once."
                % (source_name, len(identifiers), ", ".join(kinds))),
        })

    clusters = sorted(
        by_identifier.values(),
        key=lambda c: (c["identifier_kind"] or "", c["cluster_id"] or ""))
    return {"clusters": clusters, "correlations": correlations}
