"""Security response headers (spec Phases 69-70), applied to EVERY
response the server sends — pages, static files, API success and errors.

The CSP is tuned to the actual product: no external resources at all,
scripts/styles served from 'self', images may be inline data URIs (the
favicon is an inline SVG data URI), and the page may not be framed.

Also home of the CSRF guard for state-changing account routes
(Stage S3, spec Phase 5): a request must either carry the
X-Requested-With header (which cross-site forms/fetches cannot set
without a CORS preflight we never grant) or an Origin/Referer whose
host matches our own Host header. SameSite=Lax session cookies are
the first line of defence; this is the second.
"""

import urllib.parse

from core import errors

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self'; "
    "script-src 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)

SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy", CONTENT_SECURITY_POLICY),
    # HSTS (Phase 69 depth): one year + subdomains. The site is
    # HTTPS-only in production (Render terminates TLS and redirects
    # HTTP), so telling browsers to pin HTTPS is pure gain. No
    # `preload` directive: preload is a browser-vendor commitment
    # (hard to reverse) that the owner has not chosen to make.
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
)


def apply_security_headers(handler):
    """Send the security headers on the in-progress response."""
    for name, value in SECURITY_HEADERS:
        handler.send_header(name, value)


def require_csrf(handler):
    """Reject a state-changing request that cannot prove it is
    same-site. Raises ApiError(403, "csrf_failed"); returns None when
    the request is acceptable.

    Accept when EITHER:
      * an X-Requested-With header is present (our own frontend sends
        "X-Requested-With: fetch" on every account API call), OR
      * an Origin or Referer header is present and its host matches
        the request's Host header.
    A present-but-foreign Origin/Referer is an immediate rejection —
    never a fall-through to the other header.
    """
    if handler.headers.get("X-Requested-With"):
        return
    host = (handler.headers.get("Host") or "").strip().lower()
    for name in ("Origin", "Referer"):
        value = handler.headers.get(name)
        if not value:
            continue
        netloc = urllib.parse.urlparse(value).netloc.strip().lower()
        if netloc and host and netloc == host:
            return
        break
    raise errors.forbidden(
        "csrf_failed", "Cross-site request rejected")
