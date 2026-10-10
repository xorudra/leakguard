"""Shared in-memory rate limiting (Stage S12, spec Phases 63/71).

One sliding-window limiter for every route class that needs abuse
protection beyond the credential endpoints (login/register keep
their Stage S3 limiter in accounts/ratelimit.py — see below for why
the two coexist).

Design rules:

* KEYS ARE NEVER PERSONAL DATA. A key is (route_class, principal)
  where principal is "ip:<client ip>" or "user:<user uuid>". Never
  an email, never an identifier value. IPs live only in this
  process's memory — nothing is persisted, nothing is logged.
* IN-MEMORY BY DESIGN. The deployment is one small process; state
  resets on restart, which is acceptable for hour-scale windows
  (same trade-off the S3 limiter documented).
* HONEST REJECTIONS. Callers raise the standard structured 429
  (code "rate_limited") and attach Retry-After computed from the
  oldest in-window hit — the number is real, not decorative.

Why login is NOT routed through here: the S3 credential limiter
counts each attempt under TWO buckets atomically (client IP and the
target account's email HMAC), recording only when both buckets have
budget. This module's allow() is deliberately single-key; splitting
the credential check into two allow() calls would record the first
bucket even when the second rejects, changing audited S3 semantics.
Registration keeps the S3 limiter AND gains this module's per-IP cap.
"""

import threading
import time

# route class -> (max attempts, window seconds). Generous for real
# users, hostile to scripts: a human does not quick-scan 30 different
# addresses in an hour from one IP, nor run removal 7 times.
DEFAULT_LIMITS = {
    "anon_scan": (30, 3600),            # POST /api/scan, per IP
    "agent_probe": (30, 3600),          # POST /api/agent/probe, per IP
    "agent_submit": (30, 3600),         # POST /api/agent/submit, per IP
    "forgot_password": (5, 3600),       # POST /api/auth/forgot-password, per IP
    "reset_password": (10, 3600),       # POST /api/auth/reset-password, per IP
    "register": (10, 3600),             # POST /api/auth/register, per IP
    "user_scans": (10, 3600),           # POST /api/scans, per user
    "user_remediation_run": (6, 3600),  # POST /api/remediation/run, per user
}

_lock = threading.Lock()
_buckets = {}  # (route_class, principal) -> [monotonic timestamps]
_limits = dict(DEFAULT_LIMITS)

# Indirection so tests can drive the window with a fake clock.
_clock = time.monotonic


def limit_for(route_class):
    """(limit, window_seconds) currently in force for a route class."""
    return _limits[route_class]


def configure(overrides=None):
    """Replace route-class limits (tests shrink them to reach a 429
    in a handful of requests; production never calls this). Passing
    None restores the shipped defaults. Buckets are NOT cleared —
    tests pair this with reset()."""
    global _limits
    if overrides is None:
        _limits = dict(DEFAULT_LIMITS)
    else:
        _limits = dict(overrides)


def _prune(bucket_key, window_seconds, now):
    stamps = _buckets.get(bucket_key)
    if not stamps:
        return []
    cutoff = now - window_seconds
    stamps = [t for t in stamps if t > cutoff]
    if stamps:
        _buckets[bucket_key] = stamps
    else:
        _buckets.pop(bucket_key, None)
    return stamps


def allow(key, limit, window_seconds):
    """Record one attempt under `key` (a (route_class, principal)
    tuple). Returns True when within budget; when the budget is
    exhausted returns False and records NOTHING, so rejected callers
    cannot extend their own lockout by hammering."""
    now = _clock()
    with _lock:
        if len(_prune(key, window_seconds, now)) >= limit:
            return False
        _buckets.setdefault(key, []).append(now)
        return True


def retry_after(key, limit, window_seconds):
    """Seconds until the oldest in-window attempt ages out and one
    more attempt would fit. 0 when the key is not currently limited.
    Never negative; at least 1 while limited."""
    now = _clock()
    with _lock:
        stamps = _prune(key, window_seconds, now)
        if len(stamps) < limit:
            return 0
        return max(1, int(stamps[0] + window_seconds - now) + 1)


def reset():
    """Drop all buckets (tests; also the ops escape hatch — the S3
    credential limiter's reset() calls this too, so one call clears
    every limiter in the process)."""
    with _lock:
        _buckets.clear()
