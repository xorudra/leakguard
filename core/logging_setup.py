"""Structured, privacy-safe logging (spec Phase 75).

One line per HTTP request on stderr:

    ts=2026-10-07T04:30:00.123+00:00 level=INFO request_id=<hex> method=GET path=/api/health status=200 duration_ms=3

PRIVACY RULE: only request_id, method, PATH (never the query string),
status and duration are logged. Request bodies, emails, passwords,
profile fields and broker payloads are NEVER logged — they can contain
exactly the personal data this product exists to protect.
"""

import logging
import re
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


_CLASS_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*\Z")


def _ledger_fields(message):
    """Derive the error ledger's (context, error_class) from a
    log_error message. Call sites build messages as
    "<context>: <ErrorClass>" (or "<context> <ErrorClass>"), so the
    context is the text before the first colon — or before the
    trailing class token — and the class is the trailing token when
    it is shaped like one. A heuristic, by design: the ledger only
    needs stable grouping, never the raw message."""
    text = str(message or "").strip()
    if not text:
        return "error", "Error"
    if ":" in text:
        context = text.split(":", 1)[0].strip()
        tail = text.rsplit(":", 1)[1].strip()
        tokens = tail.split()
    else:
        tokens = text.split()
        context = " ".join(tokens[:-1]).strip() if len(tokens) > 1 else text
    candidate = tokens[-1] if tokens else ""
    error_class = candidate if _CLASS_TOKEN.match(candidate or "") \
        else "Error"
    return (context or "error"), error_class


def log_error(request_id, message):
    """Log a server-side failure. `message` must never contain user data —
    exception class names and fixed strings only.

    The line is ALSO mirrored into the error ledger (Phase 76,
    core/error_ledger.py) so failures are countable in the admin
    metrics. The ledger write is best-effort inside record() and
    wrapped again here: tracking must never break the caller."""
    get_logger().error(
        "ts=%s level=ERROR request_id=%s error=%s"
        % (_ts(), str(request_id or "-"), str(message))
    )
    try:
        from core import error_ledger

        context, error_class = _ledger_fields(message)
        error_ledger.record(context, error_class, message,
                            request_id=request_id)
    except Exception:
        pass


class Timer:
    """Tiny monotonic timer for request durations."""

    def __init__(self):
        self._start = time.monotonic()

    def elapsed_ms(self):
        return (time.monotonic() - self._start) * 1000.0
