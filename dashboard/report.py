"""Exposure & removal report (spec Phase 85) — the layer behind
GET /api/report.

A generated, human-readable document of the caller's own
LeakGuard state: account summary, saved details, exposure,
findings, removal cases, and recent activity, rendered as one
self-contained HTML page the browser can print or save as PDF.

Privacy contract — deliberately stricter than the data export
(accounts/privacy.py), and different from it on purpose:

* MASKED ONLY. Every identifier and the account email appear
  exclusively in their stored masked forms. This module never
  loads a vault key and never decrypts anything — there is no
  code path from the report to a plaintext value. (The export
  is the one password-gated plaintext exit; the report is not
  an export and must never become one.)
* OWNER-SCOPED BY CONSTRUCTION. The builder takes the session's
  public user dict and scopes every read by its id, reusing the
  same owner-scoped services and serializers the dashboard
  uses — the Action Center aggregate (dashboard/service.py) for
  the exposure score and counts, scanning's finding serializer,
  remediation's public case shape, monitoring's timeline — so
  the report can never disagree with the product's own numbers
  or reach another account's rows.
* NEVER PERSISTED. The document is rendered in memory per
  request and streamed out; nothing is written to disk or the
  database, nothing is scheduled, nothing is emailed. The route
  answers with the API cache policy (Cache-Control: no-store,
  set at the app.py response choke point) like every /api/*
  response.
* ESCAPED. Every interpolated value passes through
  html.escape; the page carries no scripts and no external
  assets, so it prints exactly as it reads.
"""

import html

from accounts import identifiers as identifiers_service
from accounts.auth import _iso
from dashboard import service as dashboard_service
from db import pool
from monitoring import service as monitoring_service
from remediation import service as remediation_service
from scanning.jobs import _public_finding

_TIMELINE_LIMIT = 50

# Presentation labels — the same words the app itself uses for
# these states (static/app.js REMOVAL_LABELS), so the document
# and the product never describe one state two ways. The stored
# status and its spec-facing name still ride along from
# remediation's public_case; these labels only render them.
_CASE_LABELS = {
    "queued": "Waiting to run",
    "running": "Working on it",
    "submitted": "Request sent — waiting for the broker",
    "needs_human": "Needs you",
    "blocked": "Blocked by the broker's site",
    "verified_removed": "Removed ✓ (checked — really gone)",
    "reappeared": "Reappeared after removal",
    "failed": "Could not complete",
}

_LIFECYCLE_LABELS = {
    "open": "Open",
    "resolved": "Resolved",
    "reappeared": "Reappeared",
}


def _esc(value):
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _date(iso_value):
    """An ISO timestamp (or None) as a plain YYYY-MM-DD date."""
    if not iso_value:
        return "—"
    return str(iso_value)[:10]


def _latest_findings(user_id):
    """The caller's findings from their latest completed scan —
    the same 'latest' definition the Action Center uses (newest
    done job by finished_at) and the same serializer the scan
    view uses (scanning.jobs._public_finding, via the precedent
    dashboard/search_exposure.py set). [] when no scan has
    completed yet."""
    with pool.connection() as conn:
        job = conn.execute(
            "SELECT id FROM scan_jobs"
            " WHERE user_id = %s AND status = 'done'"
            " AND finished_at IS NOT NULL"
            " ORDER BY finished_at DESC, id DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        if job is None:
            return []
        rows = conn.execute(
            "SELECT f.*, i.masked AS identifier_masked FROM findings f"
            " LEFT JOIN identifiers i ON i.id = f.identifier_id"
            " WHERE f.job_id = %s AND f.user_id = %s"
            " ORDER BY f.discovered_at, f.id",
            (job["id"], user_id),
        ).fetchall()
    return [_public_finding(row) for row in rows]


_CSS = """
body { font-family: Georgia, 'Times New Roman', serif; color: #1a1a1a;
       max-width: 800px; margin: 24px auto; padding: 0 20px;
       line-height: 1.45; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 28px 0 8px; border-bottom: 2px solid #1a1a1a;
     padding-bottom: 4px; }
h3 { font-size: 15px; margin: 16px 0 6px; }
p, li { font-size: 14px; }
.meta { color: #444; font-size: 13px; margin: 2px 0; }
.score { font-size: 40px; font-weight: bold; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 4px; }
th, td { border: 1px solid #999; padding: 5px 8px; font-size: 13px;
         text-align: left; vertical-align: top; }
th { background: #eee; }
.small { font-size: 12px; color: #444; }
.empty { color: #444; font-style: italic; }
footer { margin-top: 36px; border-top: 2px solid #1a1a1a; padding-top: 8px; }
.screen-note { background: #eef4ff; border: 1px solid #99b; padding: 8px 12px;
               font-size: 13px; margin-bottom: 16px; }
@media print {
  body { margin: 0; max-width: none; }
  .screen-note { display: none; }
  tr, .avoid-break { page-break-inside: avoid; }
}
"""


def render_report(user):
    """Render the caller's report as one HTML document (str).

    `user` is the session's public user dict (id, email_masked,
    created_at) — the account summary reads only those masked
    fields; every other section is queried owner-scoped by id.
    """
    user_id = user["id"]
    center = dashboard_service.action_center(user_id)
    exposure = center["exposure"]
    identifiers = identifiers_service.list_identifiers(user_id)
    findings = _latest_findings(user_id)
    cases = remediation_service.list_cases(user_id)
    events = monitoring_service.timeline(user_id, limit=_TIMELINE_LIMIT)

    out = []
    out.append("<!DOCTYPE html>")
    out.append('<html lang="en"><head><meta charset="utf-8">')
    out.append("<title>LeakGuard — Exposure &amp; removal report</title>")
    out.append("<style>" + _CSS + "</style></head><body>")
    out.append('<p class="screen-note">To keep this report: use your '
               "browser's Print command and choose \u201cSave as PDF\u201d. "
               "LeakGuard generated it just now and does not store a "
               "copy.</p>")

    # ---- header + account summary -------------------------------------
    out.append("<h1>Exposure &amp; removal report</h1>")
    out.append(
        '<p class="meta">Account: <strong>%s</strong> · Member since %s '
        "· Generated %s</p>" % (
            _esc(user.get("email_masked")),
            _esc(_date(user.get("created_at"))),
            _esc(_date(_generated_stamp())),
        ))

    # ---- exposure summary ----------------------------------------------
    out.append("<h2>Your exposure at a glance</h2>")
    if exposure["score"] is None:
        out.append(
            '<p class="empty">No completed scan yet. Run a scan from '
            "your LeakGuard home and this report will show your "
            "exposure score, what was found, and what is being "
            "removed.</p>")
    else:
        out.append(
            '<p><span class="score">%s</span> / 100 — %s<br>'
            '<span class="small">Exposure score from your latest '
            "completed scan (%s). Current exposures: %d.</span></p>" % (
                _esc(exposure["score"]),
                _esc(exposure["band"] or ""),
                _esc(_date(exposure["scored_at"])),
                int(exposure["findings_total"]),
            ))
    removed = sum(1 for c in cases if c["status"] == "verified_removed")
    out.append(
        "<p>Saved details being protected: %d · Removal cases: %d "
        "(%d verified removed)</p>" % (
            len(identifiers), len(cases), removed))

    # ---- saved details --------------------------------------------------
    out.append("<h2>Your saved details</h2>")
    out.append(
        '<p class="small">Shown masked, exactly as LeakGuard stores '
        "and displays them. This report never contains your details "
        "in full — for a complete copy of your data, use \u201cDownload "
        "my data\u201d in the Privacy Center (it asks for your password "
        "first).</p>")
    if identifiers:
        out.append("<table><tr><th>Kind</th><th>Detail (masked)</th>"
                   "<th>Added</th></tr>")
        for ident in identifiers:
            out.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                _esc(ident["kind"]), _esc(ident["masked"]),
                _esc(_date(ident["created_at"]))))
        out.append("</table>")
    else:
        out.append('<p class="empty">No saved details yet.</p>')

    # ---- findings --------------------------------------------------------
    out.append("<h2>Findings from your latest scan</h2>")
    if findings:
        by_state = {}
        for finding in findings:
            state = finding["lifecycle_state"]
            by_state[state] = by_state.get(state, 0) + 1
        counts = " · ".join(
            "%s: %d" % (_LIFECYCLE_LABELS.get(state, state), n)
            for state, n in sorted(by_state.items()))
        out.append('<p class="small">%s</p>' % _esc(counts))
        out.append("<table><tr><th>Source</th><th>Data exposed</th>"
                   "<th>Applies to</th><th>Status</th><th>Found</th></tr>")
        for finding in findings:
            fields = ", ".join(finding["exposed_fields"]) or "—"
            applies = finding["identifier_masked"] or "—"
            state_label = _LIFECYCLE_LABELS.get(
                finding["lifecycle_state"], finding["lifecycle_state"])
            out.append(
                "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                "<td>%s</td></tr>" % (
                    _esc(finding["source_name"]), _esc(fields),
                    _esc(applies), _esc(state_label),
                    _esc(_date(finding["discovered_at"]))))
        out.append("</table>")
    else:
        out.append('<p class="empty">No findings to list — either no '
                   "scan has completed yet, or your latest scan found "
                   "nothing.</p>")

    # ---- removal cases ---------------------------------------------------
    out.append("<h2>Removal cases</h2>")
    if cases:
        out.append("<table><tr><th>Broker</th><th>Status</th>"
                   "<th>Last updated</th></tr>")
        for case in cases:
            label = _CASE_LABELS.get(case["status"], case["status"])
            spec = case.get("spec_status") or ""
            status_cell = _esc(label)
            if spec and spec.lower() != case["status"]:
                status_cell += ' <span class="small">(%s)</span>' % _esc(
                    spec)
            out.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                _esc(case["broker_name"]), status_cell,
                _esc(_date(case["updated_at"]))))
        out.append("</table>")
    else:
        out.append('<p class="empty">No removal cases yet. One command '
                   "from your LeakGuard home opens a case with every "
                   "broker.</p>")

    # ---- recent activity ---------------------------------------------------
    out.append("<h2>Recent activity</h2>")
    if events:
        out.append("<ul>")
        for event in events:
            out.append("<li>%s — %s</li>" % (
                _esc(_date(event["at"])), _esc(event["summary"])))
        out.append("</ul>")
    else:
        out.append('<p class="empty">No activity yet.</p>')

    # ---- honest limits -----------------------------------------------------
    out.append("<footer>")
    out.append("<h2>The honest limits</h2>")
    out.append(
        "<ul>"
        "<li><strong>Can be removed:</strong> data brokers, "
        "people-search sites, and Google search results — they must "
        "answer a legal erasure request, and a removal only counts "
        "as done here after LeakGuard has verified the listing is "
        "gone.</li>"
        "<li><strong>Cannot be removed:</strong> a breach dump "
        "already copied to Telegram, dark-web forums or torrents. "
        "No tool can delete every copy — anyone promising that is "
        "lying.</li>"
        "<li><strong>Not a guarantee:</strong> a submitted removal "
        "is tracked, never assumed — ambiguous verification "
        "evidence is reported as unknown, never as removed.</li>"
        "</ul>")
    out.append(
        '<p class="small">This document was generated on demand from '
        "your LeakGuard account and was not stored. It shows masked "
        "details only.</p>")
    out.append("</footer>")
    out.append("</body></html>")
    return "\n".join(out)


def _generated_stamp():
    """The generation moment as an ISO string — rendered through
    accounts.auth._iso, the same formatter every other timestamp
    in the product uses."""
    from datetime import datetime, timezone

    return _iso(datetime.now(timezone.utc))
