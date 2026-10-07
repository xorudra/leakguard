"""Security response headers (spec Phases 69-70), applied to EVERY
response the server sends — pages, static files, API success and errors.

The CSP is tuned to the actual product: no external resources at all,
scripts/styles served from 'self', images may be inline data URIs (the
favicon is an inline SVG data URI), and the page may not be framed.
"""

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
)


def apply_security_headers(handler):
    """Send the security headers on the in-progress response."""
    for name, value in SECURITY_HEADERS:
        handler.send_header(name, value)
