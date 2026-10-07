"""Provider contract + the one HTTP helper every adapter shares.

Contract (spec Phase 8):
  * ProviderInfo     — registry metadata: name, category, capabilities,
                       cost model, privacy note, version.
  * ProviderResult   — normalized outcome of any provider call:
                       {status, data, error_kind, latency_ms} where
                       status is "ok" | "error" | "timeout" | "circuit_open".
  * HttpClient       — the single network path for adapters. Explicit
                       timeout, bounded retries (max 2, backoff 0.5s/1.5s,
                       retry ONLY on timeout / 5xx / network errors —
                       never on 4xx), and a per-provider circuit breaker
                       (opens after 3 consecutive failed calls, half-open
                       probe after a 60s cooldown, closes on success).
                       Every completed call is reported to the HealthTracker
                       and to the usage ledger (providers/usage.py), which
                       also enforces the provider's daily call budget:
                       an exhausted provider is refused before any network
                       work with status "error", error_kind
                       "budget_exhausted" — the same honest typed shape a
                       failed call takes, distinct from "circuit_open".

The transport is injectable (a callable url/headers/timeout ->
(status_code, text)) so adapter behaviour is fully testable offline.
Nothing here logs URLs, emails, passwords or hash material — callers
pass data through return values only.
"""

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

DEFAULT_TIMEOUT = 15
MAX_RETRIES = 2
BACKOFF = (0.5, 1.5)
BREAKER_THRESHOLD = 3
BREAKER_COOLDOWN = 60.0


class TransportTimeout(Exception):
    """The transport gave up waiting for a response."""


class TransportNetworkError(Exception):
    """The transport could not reach the provider at all."""


def urllib_transport(url, headers, timeout):
    """Default transport over urllib. Returns (status_code, text) for
    ANY HTTP response including 4xx/5xx (classification is the client's
    job); raises TransportTimeout / TransportNetworkError otherwise."""
    req = urllib.request.Request(url, headers=dict(headers or {}))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return exc.code, body
    except (TimeoutError, socket.timeout):
        raise TransportTimeout("timed out")
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, (TimeoutError, socket.timeout)) or (
                reason is not None and "timed out" in str(reason).lower()):
            raise TransportTimeout("timed out")
        raise TransportNetworkError(str(type(reason).__name__))
    except OSError as exc:
        raise TransportNetworkError(type(exc).__name__)


@dataclass(frozen=True)
class ProviderInfo:
    name: str
    category: str
    capabilities: tuple
    privacy: str
    cost_model: str = "free"
    version: str = "1.0"


@dataclass
class ProviderResult:
    status: str                      # ok | error | timeout | circuit_open
    data: object = None
    error_kind: str = None           # timeout | network | http_4xx |
                                     # http_5xx | bad_response | circuit_open
    latency_ms: float = None


class HttpClient:
    """One instance per provider: timeout/retry policy + circuit
    breaker + health reporting for that provider's calls."""

    def __init__(self, provider_name, health=None, transport=None,
                 sleep=None, clock=None, timeout=DEFAULT_TIMEOUT,
                 max_retries=MAX_RETRIES, backoff=BACKOFF,
                 breaker_threshold=BREAKER_THRESHOLD,
                 breaker_cooldown=BREAKER_COOLDOWN, min_interval=0.0):
        self.provider_name = provider_name
        self.health = health
        self._transport = transport or urllib_transport
        self._sleep = sleep or time.sleep
        self._clock = clock or time.monotonic
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff = tuple(backoff)
        self.breaker_threshold = breaker_threshold
        self.breaker_cooldown = breaker_cooldown
        # Minimum seconds between successive calls to this provider
        # (Stage S6 politeness for public discovery sources). 0 = off,
        # which is every pre-S6 provider's behaviour, unchanged.
        self.min_interval = float(min_interval or 0.0)
        self._lock = threading.Lock()
        self._consecutive_failures = 0
        self._opened_at = None       # clock() reading when the circuit opened
        self._last_call_at = None    # clock() reading of the last call

    # ---------- circuit breaker ----------
    def circuit_state(self):
        with self._lock:
            if self._opened_at is None:
                return "closed"
            if self._clock() - self._opened_at >= self.breaker_cooldown:
                return "half_open"
            return "open"

    def _record_success(self):
        with self._lock:
            self._consecutive_failures = 0
            self._opened_at = None

    def _record_failure(self):
        with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.breaker_threshold:
                self._opened_at = self._clock()

    # ---------- requests ----------
    def get_json(self, url, headers=None):
        return self._request(url, headers, parse="json")

    def get_text(self, url, headers=None):
        return self._request(url, headers, parse="text")

    def get_status(self, url, headers=None):
        """Status-only request (Stage S6 username presence checks):
        ProviderResult.data is the HTTP status code of any completed
        response below 500 — a 404 is a perfectly good answer, so it
        counts as a SUCCESSFUL call for breaker/health purposes.
        5xx (after retries), timeouts and network failures keep the
        usual error semantics, with the last status code in data when
        one was received."""
        return self._request(url, headers, parse="status")

    def _pace(self):
        """Enforce min_interval between calls to this provider. Uses
        the injected clock/sleep, so tests stay instant and honest."""
        if self.min_interval <= 0:
            return
        with self._lock:
            now = self._clock()
            wait = 0.0
            if self._last_call_at is not None:
                wait = self._last_call_at + self.min_interval - now
            self._last_call_at = max(now, now + wait)
        if wait > 0:
            self._sleep(wait)

    def _report(self, ok, latency_ms, error_kind, counted=True):
        if self.health is not None:
            self.health.record(self.provider_name, ok, latency_ms, error_kind)
        if counted:
            # The usage ledger (Phases 66/124): one logical call.
            # Refusals that never reached the provider (circuit
            # open, budget exhausted) pass counted=False — they are
            # health events, not usage. The ledger never raises.
            from . import usage

            usage.record_call(self.provider_name, ok)

    def _budget_exhausted(self):
        from . import usage

        return usage.is_exhausted(self.provider_name)

    def _request(self, url, headers, parse):
        if self._budget_exhausted():
            # Daily call budget spent (Phase 66): refuse before any
            # pacing or network work, until the next UTC day. The
            # refusal surfaces exactly like a provider failure —
            # callers degrade honestly (partial coverage is
            # reported, never silently swallowed).
            self._report(False, 0.0, "budget_exhausted", counted=False)
            return ProviderResult(status="error",
                                  error_kind="budget_exhausted",
                                  latency_ms=0.0)
        if self.circuit_state() == "open":
            self._report(False, 0.0, "circuit_open", counted=False)
            return ProviderResult(status="circuit_open",
                                  error_kind="circuit_open", latency_ms=0.0)
        self._pace()
        start = self._clock()
        attempts = 1 + self.max_retries
        error_kind = None
        status_label = "error"
        last_code = None
        for attempt in range(attempts):
            try:
                code, text = self._transport(url, headers, self.timeout)
            except TransportTimeout:
                error_kind, retryable = "timeout", True
                status_label = "timeout"
            except TransportNetworkError:
                error_kind, retryable = "network", True
                status_label = "error"
            else:
                last_code = code
                if parse == "status" and code < 500:
                    # Any completed non-5xx response answers a
                    # status-only question (200/404/403 alike).
                    latency = (self._clock() - start) * 1000.0
                    self._record_success()
                    self._report(True, latency, None)
                    return ProviderResult(status="ok", data=code,
                                          latency_ms=latency)
                if 200 <= code < 300:
                    latency = (self._clock() - start) * 1000.0
                    if parse == "json":
                        try:
                            data = json.loads(text)
                        except ValueError:
                            self._record_failure()
                            self._report(False, latency, "bad_response")
                            return ProviderResult(
                                status="error", error_kind="bad_response",
                                latency_ms=latency)
                    else:
                        data = text
                    self._record_success()
                    self._report(True, latency, None)
                    return ProviderResult(status="ok", data=data,
                                          latency_ms=latency)
                if code >= 500:
                    error_kind, retryable = "http_5xx", True
                else:
                    error_kind, retryable = "http_4xx", False
                status_label = "error"
            if retryable and attempt < attempts - 1:
                delay = self.backoff[min(attempt, len(self.backoff) - 1)]
                self._sleep(delay)
                continue
            break
        latency = (self._clock() - start) * 1000.0
        self._record_failure()
        self._report(False, latency, error_kind)
        return ProviderResult(status=status_label,
                              data=last_code if parse == "status" else None,
                              error_kind=error_kind,
                              latency_ms=latency)


class Provider:
    """Base class for adapters. Subclasses set `info` (a ProviderInfo)
    and capability methods; the HTTP path is `self.client` (an
    HttpClient) — except fully local providers (the mock), whose
    client is None."""

    info = None
    is_mock = False

    def __init__(self, health=None, client=None):
        self.health = health
        self.client = client

    def health_summary(self):
        """Public-safe health entry for /api/providers/health: counts
        and kinds only, never exception text or endpoints."""
        snap = (self.health.snapshot(self.info.name) if self.health
                else {"successes": 0, "failures": 0,
                      "last_latency_ms": None, "last_error_kind": None,
                      "recent_failure": False})
        if self.is_mock:
            status = "mock"
        elif self.client is not None and self.client.circuit_state() == "open":
            status = "circuit_open"
        elif snap["failures"] > 0 and snap["successes"] == 0:
            status = "down"
        elif snap["recent_failure"]:
            status = "degraded"
        else:
            status = "up"
        return {
            "name": self.info.name,
            "category": self.info.category,
            "capabilities": list(self.info.capabilities),
            "status": status,
            "successes": snap["successes"],
            "failures": snap["failures"],
            "last_latency_ms": snap["last_latency_ms"],
            "last_error_kind": snap["last_error_kind"],
        }
