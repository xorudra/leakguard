"""Structured, privacy-safe logging (spec Phase 75).

One line per HTTP request on stderr:

    ts=2026-10-07T04:30:00.123+00:00 level=INFO request_id=<hex> method=GET path=/api/health status=200 duration_ms=3

PRIVACY RULE: only request_id, method, PATH (never the query string),
status and duration are logged. Request bodies, emails, passwords,
profile fields and broker payloads are NEVER logged — they can contain
exactly the personal data this product exists to protect.
"""

import logging
import sys
import time
from datetime import datetime, timezone

LOGGER_NAME = "leakguard"
_logger = logging.getLogger(LOGGER_NAME)
_configured = False


def setup_logging():
    """Configure the leakguard logger once (stderr, unbuffered-ish)."""
    global _configured
    if _configured:
        return _logger
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False
    _configured = True
    return _logger


def get_logger():
    return setup_logging()


def _ts():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def log_request(request_id, method, path, status, duration_ms=None):
    """Emit the single structured line for a finished request."""
    parts = [
        "ts=" + _ts(),
        "level=INFO",
        "request_id=" + str(request_id or "-"),
        "method=" + str(method or "-"),
        "path=" + str(path or "-"),
        "status=" + str(status if status is not None else "-"),
    ]
    if duration_ms is not None:
        parts.append("duration_ms=" + str(int(duration_ms)))
    get_logger().info(" ".join(parts))


def log_error(request_id, message):
    """Log a server-side failure. `message` must never contain user data —
    exception class names and fixed strings only."""
    get_logger().error(
        "ts=%s level=ERROR request_id=%s error=%s"
        % (_ts(), str(request_id or "-"), str(message))
    )


class Timer:
    """Tiny monotonic timer for request durations."""

    def __init__(self):
        self._start = time.monotonic()

    def elapsed_ms(self):
        return (time.monotonic() - self._start) * 1000.0
