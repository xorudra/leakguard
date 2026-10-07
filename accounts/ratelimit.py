"""In-memory rate limiting for credential endpoints (spec Phases 4/63).

Login and registration share one limiter: at most MAX_ATTEMPTS
attempts per WINDOW_SECONDS per bucket, where attempts are counted
under TWO buckets at once — the client IP and the target email's
lookup HMAC — so neither a single-source password spray nor a
single-account attack from many sources gets more than the budget.

In-memory by design (the deployment is one small process; the state
resets on restart, which is acceptable for a 15-minute window).

Buckets store attempt timestamps only. Email HMACs are keyed digests,
never addresses; IPs are connection metadata. Nothing here is logged.
"""

import threading
import time

MAX_ATTEMPTS = 10
WINDOW_SECONDS = 15 * 60

_lock = threading.Lock()
_buckets = {}  # bucket key -> [monotonic timestamps]


def _prune(key, now):
    stamps = _buckets.get(key)
    if not stamps:
        return []
    cutoff = now - WINDOW_SECONDS
    stamps = [t for t in stamps if t > cutoff]
    if stamps:
        _buckets[key] = stamps
    else:
        _buckets.pop(key, None)
    return stamps


def allow(bucket_keys):
    """Record one attempt under every bucket key. Returns True when
    the attempt is within budget, False (without recording) when any
    bucket is already at the limit."""
    now = time.monotonic()
    with _lock:
        for key in bucket_keys:
            if len(_prune(key, now)) >= MAX_ATTEMPTS:
                return False
        for key in bucket_keys:
            _buckets.setdefault(key, []).append(now)
        return True


def reset():
    """Drop all buckets (used by tests; also a sane ops escape hatch)."""
    with _lock:
        _buckets.clear()
