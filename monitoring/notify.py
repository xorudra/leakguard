"""Notification ledger + the email lane (spec Phases 44, 45, 99).

create_notification() is the single entry point. It ALWAYS writes
the ledger row first (migration 0006) and only then decides what
"delivery" means for this row:

* dedupe — when a dedupe_key is given and a non-suppressed row with
  the same (user, dedupe_key) exists from the last 7 days, the new
  row is recorded as 'suppressed' and nothing is sent. The window
  check + insert run in ONE transaction under a per-key advisory
  lock, so two workers cannot race the same event into two emails.
* mode "never"            -> 'in_app_only' (recorded, never emailed)
* mode "auto" (default)   -> email only when the user's current
  'notifications' consent is granted; otherwise 'in_app_only'.
* mode "always"           -> email regardless of consent. Reserved
  for user-requested transactional mail (password reset): the user
  asked for THIS email a moment ago; the consent governs alerts.
* lane missing (no BREVO_API_KEY / NOTIFY_FROM_EMAIL) -> the row is
  'unsent_no_lane'. Honesty rule: a notification that could not be
  delivered is recorded as unsent, NEVER as sent.
* lane refuses / errors   -> 'failed'. Only a 2xx from Brevo flips
  a row to 'sent' (with sent_at).

The lane is Brevo's HTTP API (free tier), configured purely by
environment: BREVO_API_KEY, NOTIFY_FROM_EMAIL, NOTIFY_FROM_NAME
(default "LeakGuard"). Dormant until set — with no key the whole
product behaves exactly as before, just with an in-app ledger.

Nothing here logs an email address, a subject, or a body. The one
payload that contains a secret-shaped value is password_reset's
reset_url: it is the delivery content itself (the email carries it
too) and it never reaches a log line.
"""

import hashlib
import json
import os
import urllib.error
import urllib.request

from db import pool

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"
_LANE_TIMEOUT_SECONDS = 15
DEDUPE_WINDOW_DAYS = 7
KINDS = ("new_finding", "finding_resolved", "removal_verified",
         "reappeared", "password_reset", "scan_summary")

# Injectable transport for tests: callable
# (url, headers, body_bytes, timeout) -> (status_code, text).
# None means the real urllib transport below.
TRANSPORT = None


# ---------------------------------------------------------------------------
# Lane configuration + transport
# ---------------------------------------------------------------------------

def lane_configured():
    """True when the email lane has both a key and a sender."""
    return bool(os.environ.get("BREVO_API_KEY")
                and os.environ.get("NOTIFY_FROM_EMAIL"))


def _sender():
    return (os.environ.get("NOTIFY_FROM_EMAIL") or "",
            os.environ.get("NOTIFY_FROM_NAME") or "LeakGuard")


def _urllib_transport(url, headers, body, timeout):
    """POST via urllib. Returns (status, text) for ANY HTTP response
    including 4xx/5xx; raises on transport-level failure."""
    req = urllib.request.Request(url, data=body, headers=dict(headers),
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            text = exc.read().decode("utf-8", "replace")
        except Exception:
            text = ""
        return exc.code, text


def send_email(to, subject, text):
    """One email through the Brevo lane. True ONLY when Brevo
    accepted it (2xx). Any failure — no lane, refused, unreachable —
    is False; the caller records 'failed' / 'unsent_no_lane'."""
    if not lane_configured():
        return False
    from_email, from_name = _sender()
    payload = {
        "sender": {"email": from_email, "name": from_name},
        "to": [{"email": to}],
        "subject": subject,
        "textContent": text,
    }
    headers = {
        "api-key": os.environ.get("BREVO_API_KEY"),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    transport = TRANSPORT or _urllib_transport
    try:
        status, _text = transport(
            BREVO_API_URL, headers,
            json.dumps(payload).encode("utf-8"), _LANE_TIMEOUT_SECONDS)
    except Exception:
        return False
    return 200 <= int(status) < 300


# ---------------------------------------------------------------------------
# Email rendering — plain text, honest wording. Nothing here ever
# claims the wider internet is clean or a removal is proven by an
# email: findings are "in the sources we check", and a disappearance
# is "did not appear in our latest check".
# ---------------------------------------------------------------------------

_FOOTER = (
    "\n\n— LeakGuard\n"
    "LeakGuard checks specific sources (breach databases and public "
    "web mentions). No service can watch the whole internet, and we "
    "won't pretend to.")


def _masked_line(payload):
    masked = payload.get("identifier_masked")
    kind = payload.get("identifier_kind")
    if masked:
        return "Saved detail: %s (%s)\n" % (masked, kind or "detail")
    return ""


def render_email(kind, payload):
    """(subject, plain-text body) for one notification payload."""
    payload = payload or {}
    source = payload.get("source_name") or "a source we check"
    if kind == "new_finding":
        subject = "LeakGuard: new exposure found in %s" % source
        body = (
            "A new exposure turned up in the latest check of the "
            "sources we use.\n\n"
            "Source: %s\n" % source
            + _masked_line(payload)
            + "Confidence: %s\n\n"
            "Open LeakGuard to see what was found and start a "
            "removal. Being listed in a breach or a people-search "
            "source does not automatically mean someone has misused "
            "your data — but it is worth cleaning up." + _FOOTER)
    elif kind == "finding_resolved":
        subject = "LeakGuard: %s no longer lists your detail" % source
        body = (
            "Good news, stated carefully: in our latest check, %s "
            "did not appear for your saved detail this time.\n\n"
            "Source: %s\n" % (source, source)
            + _masked_line(payload)
            + "\nThat is based on the sources we check — it is not "
            "a guarantee about the whole internet, and the source "
            "could list it again. Monitoring keeps watching."
            + _FOOTER)
    elif kind == "scan_summary":
        new_count = int(payload.get("new_count") or 0)
        resolved_count = int(payload.get("resolved_count") or 0)
        subject = "LeakGuard: monitoring check complete"
        lines = ["A scheduled full check of your saved details just "
                 "finished.\n"]
        if payload.get("baseline"):
            lines.append("This was the first completed check, so it "
                         "sets your baseline — later checks are "
                         "compared against it.\n")
        lines.append("New exposures this check: %d" % new_count)
        if payload.get("extra_new_count"):
            lines.append("(%d more are listed in the app — this "
                         "summary covers the totals.)"
                         % int(payload["extra_new_count"]))
        lines.append("No longer appearing: %d" % resolved_count)
        lines.append("Still present: %d"
                     % int(payload.get("continuing_count") or 0))
        if payload.get("score") is not None:
            delta = payload.get("score_delta")
            delta_text = ""
            if delta:
                delta_text = " (%+d since the check before)" % delta
            lines.append("Exposure score: %s / 100%s"
                         % (payload["score"], delta_text))
        body = "\n".join(lines) + _FOOTER
    elif kind == "reappeared":
        broker = payload.get("broker_name") or payload.get(
            "broker_slug") or "A data broker"
        subject = "LeakGuard: a removed listing appears to be back"
        body = (
            "%s had previously been verified as no longer listing "
            "your detail — but the latest check found a matching "
            "listing again (source: %s).\n\n"
            "The removal case in LeakGuard has been reopened as "
            "\"reappeared\". Open LeakGuard to run removal again."
            % (broker, source) + _FOOTER)
    elif kind == "removal_verified":
        broker = payload.get("broker_name") or payload.get(
            "broker_slug") or "A data broker"
        subject = "LeakGuard: removal verified at %s" % broker
        body = (
            "LeakGuard went back and checked %s, and your listing "
            "was no longer there. That check is why this case counts "
            "as removed — a sent request alone never does." % broker
            + _FOOTER)
    elif kind == "password_reset":
        subject = "Reset your LeakGuard password"
        body = (
            "Someone asked to reset the password for this LeakGuard "
            "account. If that was you, open this link within 1 hour "
            "to choose a new password:\n\n%s\n\n"
            "If it wasn't you, ignore this email — your password "
            "has not changed and the link expires on its own."
            % (payload.get("reset_url") or ""))
    else:  # pragma: no cover - kinds are constrained by the schema
        subject = "LeakGuard update"
        body = "Open LeakGuard to see the latest update." + _FOOTER
    return subject, body


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------

def _notifications_consented(user_id):
    from accounts import consents as consents_service

    for entry in consents_service.current_consents(user_id):
        if entry["purpose"] == "notifications":
            return bool(entry["granted"])
    return False


def _recipient_email(user_id):
    """The account email, decrypted server-side for delivery only.
    None when the user is gone or the vault cannot answer."""
    from accounts import auth

    row = auth._get_user_by_id(user_id)
    if row is None:
        return None
    try:
        return auth.reveal_email(row)
    except Exception:
        return None


def _dedupe_lock_key(user_id, dedupe_key):
    digest = hashlib.sha256(
        ("%s|%s" % (user_id, dedupe_key)).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def _insert_row(conn, user_id, kind, dedupe_key, payload, status):
    row = conn.execute(
        "INSERT INTO notifications (user_id, kind, dedupe_key,"
        " payload, status) VALUES (%s, %s, %s, %s::jsonb, %s)"
        " RETURNING id",
        (user_id, kind, dedupe_key, json.dumps(payload or {}), status),
    ).fetchone()
    return str(row["id"])


def create_notification(user_id, kind, payload, dedupe_key=None,
                        mode="auto", email=None):
    """Record one notification and deliver it per the rules in the
    module docstring. Returns {"id", "kind", "status"} with the
    FINAL status. mode is "auto" | "always" | "never"."""
    if kind not in KINDS:
        raise ValueError("unknown notification kind: %r" % (kind,))
    if mode not in ("auto", "always", "never"):
        raise ValueError("unknown delivery mode: %r" % (mode,))
    payload = payload or {}

    # --- decide the pre-delivery status, ledger row first ---------
    pre_status = None
    if mode == "never":
        pre_status = "in_app_only"
    elif mode == "auto" and not _notifications_consented(user_id):
        pre_status = "in_app_only"
    elif not lane_configured():
        pre_status = "unsent_no_lane"

    with pool.connection() as conn:
        if dedupe_key:
            conn.execute("SELECT pg_advisory_xact_lock(%s)",
                         (_dedupe_lock_key(user_id, dedupe_key),))
            dupe = conn.execute(
                "SELECT id FROM notifications"
                " WHERE user_id = %s AND dedupe_key = %s"
                " AND status <> 'suppressed'"
                " AND created_at > now() - (%s || ' days')::interval"
                " LIMIT 1",
                (user_id, dedupe_key, str(DEDUPE_WINDOW_DAYS)),
            ).fetchone()
            if dupe is not None:
                row_id = _insert_row(conn, user_id, kind, dedupe_key,
                                      payload, "suppressed")
                return {"id": row_id, "kind": kind,
                        "status": "suppressed"}
        if pre_status is not None:
            row_id = _insert_row(conn, user_id, kind, dedupe_key,
                                 payload, pre_status)
            return {"id": row_id, "kind": kind, "status": pre_status}
        row_id = _insert_row(conn, user_id, kind, dedupe_key, payload,
                             "pending")

    # --- delivery attempt (outside the ledger transaction) -------
    recipient = email or _recipient_email(user_id)
    subject, text = render_email(kind, payload)
    sent = bool(recipient) and send_email(recipient, subject, text)
    final = "sent" if sent else "failed"
    with pool.connection() as conn:
        if sent:
            conn.execute(
                "UPDATE notifications SET status = 'sent',"
                " sent_at = now() WHERE id = %s", (row_id,))
        else:
            conn.execute(
                "UPDATE notifications SET status = 'failed'"
                " WHERE id = %s", (row_id,))
    return {"id": row_id, "kind": kind, "status": final}
