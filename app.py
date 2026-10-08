#!/usr/bin/env python3
"""
LeakGuard — find leaked personal data and help remove it.

GUI-first (web UI, no CLI). Almost entirely Python standard library, so
it runs anywhere — local machine, Render free tier, any VPS. Since Stage
S2/S3 there are exactly three third-party dependencies (see
requirements.txt: a Postgres driver, AES-GCM cryptography, Argon2id
password hashing) and all are optional at runtime: with no DATABASE_URL
configured the app boots and serves the anonymous features exactly as
before — the database, the encrypted identifier vault (db/, vault/)
and accounts (accounts/) simply stay dormant, and every account route
answers a clean structured 503.

What it does
  * Email breach scan      -> XposedOrNot free API (no key needed)
  * Breach analytics       -> XposedOrNot (risk score, exposed data types)
  * Password breach check  -> Have I Been Pwned Pwned Passwords API.
                              k-anonymity: only the first 5 characters of the
                              SHA-1 hash ever leave this server. The password
                              itself is never stored or logged.
  * Removal centre         -> data-broker list with opt-out links, a deletion
                              request letter generator (India DPDP Act s.12 /
                              GDPR Art. 17 / CCPA), and Google removal links.
                              Progress is tracked in the visitor's browser
                              (localStorage) — nothing is kept server-side.

Honest limit (shown in the UI too): data already copied into breach dumps,
Telegram channels or torrents cannot be deleted. LeakGuard removes data from
the places that legally / practically accept removal: data brokers,
people-search sites and Google search results.
"""

import hashlib
import http.cookies
import json
import os
import re
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import agent as agent_engine
from accounts import accounts_available
from accounts import admin as admin_service
from accounts import api_tokens as api_tokens_service
from accounts import auth as auth_service
from accounts import consents as consents_service
from accounts import domains as domains_service
from accounts import households as households_service
from accounts import identifiers as identifiers_service
from accounts import privacy as privacy_service
from accounts import provider_usage as provider_usage_service
from accounts import ratelimit
from accounts import sessions as sessions_mod
from accounts import webauthn as webauthn_service
from core import context, errors, flags, logging_setup, security
from core import ratelimit as core_ratelimit
from dashboard import graph as graph_service
from dashboard import policy_analyzer as policy_analyzer_service
from dashboard import report as report_service
from dashboard import search_exposure as search_exposure_service
from dashboard import service as action_center_service
from db import pool as db_pool
from monitoring import service as monitoring_service
from providers import registry as providers_registry
from remediation import registry_seed as broker_registry
from remediation import service as remediation_service
from remediation import verify as remediation_verify
from scanning import feedback as feedback_service
from scanning import jobs as scan_jobs_service
from scanning import risk as risk_engine

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
BROKERS_FILE = BASE / "brokers.json"

# Provider usage ledger (Phases 66/124): inject the database
# persister/loader into providers/usage.py's tracker, so provider
# calls are counted against the daily budgets and persisted to
# provider_usage_daily. Every provider call in this process —
# HTTP handlers and the in-process workers/scheduler alike —
# flows through HttpClient, so installing once here covers all
# of them.
provider_usage_service.install()

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
MAX_BODY = 256 * 1024

# RFC 9116 — served at /.well-known/security.txt (Stage S13).
SECURITY_TXT = (
    "Contact: mailto:forapikeyonly2008@gmail.com\n"
    "Expires: 2027-10-07T00:00:00.000Z\n"
    "Canonical: https://leakguard-hh8e.onrender.com/.well-known/security.txt\n"
    "Preferred-Languages: en\n"
)


def _provider(capability):
    """First registered provider declaring `capability`, or None."""
    found = providers_registry.get_registry().get_providers(capability)
    return found[0] if found else None


def check_email_breaches(email):
    """Return (breach_names list, error or None) via the email_breach
    provider. Any provider failure (error, timeout, circuit open)
    degrades to the same user-facing error as before Stage S4 —
    results are never fabricated."""
    provider = _provider("email_breach")
    result = provider.check_email(email) if provider is not None else None
    if result is not None and result.status == "ok":
        return result.data, None
    return None, "Breach database unreachable right now. Try again in a minute."


def breach_analytics(email):
    """Return dict with risk + exposed data types, or None."""
    provider = _provider("breach_analytics")
    if provider is None:
        return None
    result = provider.breach_analytics(email)
    return result.data if result.status == "ok" else None


def check_password_pwned(password):
    """k-anonymity check. Returns count (int) or None on failure.
    Only the 5-char SHA-1 prefix is sent to the password_range
    provider; the suffix match runs locally on its range text."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    provider = _provider("password_range")
    if provider is None:
        return None
    result = provider.check_range(prefix)
    if result.status != "ok" or not isinstance(result.data, str):
        return None
    for line in result.data.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].strip().upper() == suffix:
            try:
                return int(parts[1])
            except ValueError:
                return 0
    return 0


def exposure_score(breaches, analytics, pwned_count):
    """0 = no exposure found, 100 = worst. Deterministic, labelled in UI.

    The arithmetic lives in scanning.risk (Stage S5) — this wrapper
    keeps the legacy entry point so the anonymous scan's output is
    byte-identical while both products share one scoring engine."""
    return risk_engine.score_email_profile(breaches, analytics, pwned_count)[0]


def load_brokers():
    try:
        return json.loads(BROKERS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _versioned_route(path):
    """API versioning (spec Phase 88): /api/v1 is the canonical
    version of the API. Every /api/* route also answers under
    /api/v1/* — the SAME handler, reached by normalizing the prefix
    away here, at the routing layer, before dispatch. The
    unversioned /api/* spelling is a permanent alias of v1 (the
    browser UI uses it), so nothing that works today can break;
    a future breaking change ships as /api/v2 alongside, never as
    a silent change to v1. No route begins with /api/v1 today, so
    the prefix can never shadow a real route."""
    if path == "/api/v1":
        return "/api"
    if path.startswith("/api/v1/"):
        return "/api/" + path[len("/api/v1/"):]
    return path


class Handler(BaseHTTPRequestHandler):
    server_version = "LeakGuard/1.0"

    def log_message(self, fmt, *args):  # stdlib access log stays OFF;
        pass                               # structured logging is in core

    # ---------- request lifecycle ----------
    def handle_one_request(self):
        """Mint a request_id per request, bind it to the context, run the
        request, then emit exactly one structured log line (no bodies,
        no personal data — see core.logging_setup)."""
        self.request_id = context.new_request_id()
        token = context.set_request_id(self.request_id)
        timer = logging_setup.Timer()
        self._response_status = None
        try:
            super().handle_one_request()
        finally:
            try:
                path = urllib.parse.urlparse(getattr(self, "path", "") or "").path
            except Exception:
                path = "-"
            logging_setup.log_request(
                self.request_id, getattr(self, "command", None), path,
                self._response_status, timer.elapsed_ms())
            context.reset_request_id(token)

    def _safe_dispatch(self, fn):
        """Run a route handler, converting failures into structured errors."""
        try:
            return fn()
        except errors.ApiError as err:
            return self._fail(err)
        except Exception as exc:  # never leak internals or user data
            logging_setup.log_error(self.request_id,
                                    "unhandled " + type(exc).__name__)
            try:
                return self._fail(errors.internal_error())
            except Exception:
                return None

    # ---------- helpers ----------
    def _request_id(self):
        return getattr(self, "request_id", None) or context.get_request_id()

    def _send(self, code, body, ctype="application/json", extra_headers=None):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self._response_status = code
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        rid = self._request_id()
        if rid:
            self.send_header("X-Request-Id", rid)
        # Cache policy (spec Phase 67 — deliberate privacy design):
        # API responses are NEVER cached. Every API response —
        # JSON success or error, and the privacy export download —
        # carries Cache-Control: no-store, set here at the single
        # response choke point so no route can forget it. The app
        # shell and static files are NOT covered: they are served
        # without a cache header and stored only by the service
        # worker's explicit shell list (static/sw.js), which never
        # intercepts /api/* at all. No server-side response caching
        # exists anywhere in this app.
        route = urllib.parse.urlparse(self.path or "").path
        if ctype == "application/json" or route.startswith("/api/"):
            self.send_header("Cache-Control", "no-store")
        security.apply_security_headers(self)
        for name, value in extra_headers or ():
            self.send_header(name, value)
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(data)

    def _json(self, code, obj, extra_headers=None):
        self._send(code, json.dumps(obj), "application/json", extra_headers)

    def _fail(self, err):
        """Send an ApiError as the structured error body."""
        return self._send(err.status, errors.error_json(
            err.status, err.code, err.message, self._request_id()),
            "application/json", extra_headers=err.headers)

    def _serve_file(self, path, ctype):
        try:
            data = path.read_bytes()
        except OSError:
            return self._fail(errors.not_found())
        self._send(200, data, ctype)

    # ---------- accounts (Stage S3) ----------
    def _call(self, fn, *args, **kwargs):
        """Run an accounts/db service call, translating a database
        outage into a clean structured 503 instead of a 500. ApiErrors
        pass through untouched."""
        try:
            return fn(*args, **kwargs)
        except errors.ApiError:
            raise
        except Exception as exc:
            if (type(exc).__module__ or "").startswith("psycopg"):
                raise errors.unavailable()
            raise

    def _require_accounts(self):
        """503 unless accounts are configured (DB + vault keys)."""
        if not accounts_available():
            raise errors.unavailable()

    def _client_ip(self):
        # X-Forwarded-For: entries BEFORE the last hop are supplied by
        # the client and are spoofable — proven live 2026-10-07: a
        # request with a fresh fake first entry dodged an exhausted
        # per-IP bucket (200 instead of 429), while the exhausted IP in
        # first position tripped it. The LAST entry is the address the
        # platform edge (Render) actually observed connecting, so key
        # on that. Fall back to the direct peer (local dev, tests).
        xff = self.headers.get("X-Forwarded-For") or ""
        if xff.strip():
            return xff.split(",")[-1].strip()
        return self.client_address[0] if self.client_address else "-"

    def _session_token(self):
        raw = self.headers.get("Cookie") or ""
        try:
            jar = http.cookies.SimpleCookie(raw)
        except Exception:
            return None
        morsel = jar.get(sessions_mod.COOKIE_NAME)
        return morsel.value if morsel is not None else None

    def _current_user(self):
        """The session's user (public dict) or None. Cached per
        request; session validation itself lives in accounts."""
        cached = getattr(self, "_user_cache", None)
        if cached is not None or getattr(self, "_user_loaded", False):
            return cached
        self._user_loaded = True
        token = self._session_token()
        self._user_cache = (
            self._call(sessions_mod.validate_session, token) if token else None
        )
        return self._user_cache

    def _require_user(self):
        """(user, raw_token) for a protected route, else a 401."""
        user = self._current_user()
        if user is None:
            raise errors.unauthorized()
        return user, self._session_token()

    def _bearer_token(self):
        """The raw API token from an Authorization: Bearer header,
        or None. Only the lg_ marker is accepted — anything else is
        not an API token at all."""
        raw = self.headers.get("Authorization") or ""
        if raw.startswith("Bearer "):
            candidate = raw[len("Bearer "):].strip()
            if candidate.startswith(api_tokens_service.TOKEN_MARKER):
                return candidate
        return None

    def _bearer_user(self):
        """The API token's owner (public dict) or None. Cached per
        request, like the session resolution."""
        cached = getattr(self, "_bearer_cache", None)
        if cached is not None or getattr(self, "_bearer_loaded", False):
            return cached
        self._bearer_loaded = True
        raw = self._bearer_token()
        self._bearer_cache = (
            self._call(api_tokens_service.authenticate_token, raw)
            if raw else None
        )
        return self._bearer_cache

    def _require_reader(self):
        """The user for a READ route: the session cookie OR a
        Bearer API token (Stage S13). Tokens are read-only by
        construction — mutation routes never call this; they use
        _require_user (session only), so a Bearer token alone can
        never change anything."""
        user = self._current_user()
        if user is None:
            user = self._bearer_user()
        if user is None:
            raise errors.unauthorized()
        return user

    def _require_admin(self):
        """The session's user, if they are the product owner
        (Stage S11). Everyone else — signed out, or signed in as a
        regular user — gets a 404: the admin surface is invisible,
        not merely forbidden."""
        self._require_accounts()
        user = self._current_user()
        if user is None or not self._call(admin_service.is_admin,
                                          user["id"]):
            raise errors.not_found()
        return user

    def _enforce_rate_limit(self, route_class, principal):
        """Stage S12 shared limiter (core/ratelimit.py). The key is
        (route_class, principal) where principal is "ip:<client ip>"
        or "user:<user id>" — never an email or identifier value.
        Excess raises the standard structured 429 with a real
        Retry-After computed from the window."""
        limit, window = core_ratelimit.limit_for(route_class)
        key = (route_class, principal)
        if not core_ratelimit.allow(key, limit, window):
            raise errors.too_many_requests(
                retry_after=core_ratelimit.retry_after(key, limit, window))

    def _rate_limit_credentials(self, email):
        """Shared register/login limiter: 10 attempts / 15 min per IP
        AND per account email (counted by its lookup HMAC)."""
        digest = auth_service.account_email_hmac(
            auth_service.normalize_email(email))
        keys = ("ip:" + self._client_ip(), "email:" + digest.hex())
        if not ratelimit.allow(keys):
            raise errors.too_many_requests()

    # ---------- routes ----------
    def do_HEAD(self):
        # UptimeRobot and other uptime probes use HEAD; without this the
        # stdlib handler answers 501 and monitors report the site DOWN
        # while GET is perfectly fine (same bug Nexus Local had).
        self._head_only = True
        self.do_GET()

    def do_GET(self):
        return self._safe_dispatch(self._do_GET)

    def _do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        route = _versioned_route(parsed.path)
        if route == "/" or route == "/index.html":
            return self._serve_file(STATIC / "index.html", "text/html; charset=utf-8")
        if route == "/reset":
            # Password-reset landing (Stage S8): the same SPA, which
            # reads ?token= itself and shows the reset form.
            return self._serve_file(STATIC / "index.html", "text/html; charset=utf-8")
        if route == "/signin":
            # Dedicated sign-in page (owner request, 2026-10-08): the
            # same SPA, which app.js puts into sign-in mode for this
            # path — only the auth panel shows, as its own page.
            return self._serve_file(STATIC / "index.html", "text/html; charset=utf-8")
        if route == "/trust":
            # Trust & security page (Stage S13): the same SPA, which
            # unhides its Trust section for this path. Static content
            # — serves with or without a database, like the home page.
            return self._serve_file(STATIC / "index.html", "text/html; charset=utf-8")
        if route in ("/privacy", "/terms", "/support"):
            # Standalone policy, terms and support pages (Batch D2):
            # sections of the same SPA, unhidden by app.js for these
            # paths. Static content — no database is needed to read
            # the rules that govern the service.
            return self._serve_file(STATIC / "index.html", "text/html; charset=utf-8")
        if route == "/local_agent.py":
            # The on-device runner (Phase 178 local-only tool),
            # served as a download so a user can run the removal
            # run from their own connection — brokers that wall
            # the server answer a home IP normally. Bytes only:
            # the server never imports or executes this file.
            try:
                data = (BASE / "local_agent.py").read_bytes()
            except OSError:
                return self._send(404, "not found", "text/plain")
            return self._send(
                200, data, "text/x-python; charset=utf-8",
                extra_headers=[(
                    "Content-Disposition",
                    'attachment; filename="local_agent.py"')])
        if route == "/.well-known/security.txt":
            # RFC 9116 security contact (Stage S13). Static text —
            # served by the app itself, database or not.
            return self._send(200, SECURITY_TXT,
                              "text/plain; charset=utf-8")
        if route == "/static/style.css":
            return self._serve_file(STATIC / "style.css", "text/css; charset=utf-8")
        if route == "/static/app.js":
            return self._serve_file(STATIC / "app.js", "text/javascript; charset=utf-8")
        if route == "/static/manifest.webmanifest":
            # PWA manifest (Stage S14). application/manifest+json is
            # the registered media type for web app manifests.
            return self._serve_file(STATIC / "manifest.webmanifest",
                                    "application/manifest+json; charset=utf-8")
        if route in ("/sw.js", "/static/sw.js"):
            # The service worker FILE lives in static/, but it is
            # also served at /sw.js: a worker's scope is capped at
            # its own path, so only the root-level URL lets it cover
            # the app shell at "/". Same bytes either way.
            return self._serve_file(STATIC / "sw.js",
                                    "text/javascript; charset=utf-8")
        if route == "/static/icons/icon-192.png":
            return self._serve_file(STATIC / "icons" / "icon-192.png",
                                    "image/png")
        if route == "/static/icons/icon-512.png":
            return self._serve_file(STATIC / "icons" / "icon-512.png",
                                    "image/png")
        if route == "/api/brokers":
            # Registry-backed when a database is configured and
            # seeded (Stage S7); brokers.json otherwise. The shape is
            # identical either way — the file stays the fallback so
            # the anonymous page can never break on a database hiccup.
            brokers = broker_registry.list_brokers_public()
            return self._json(200, {
                "brokers": brokers if brokers is not None else load_brokers(),
            })
        if route == "/api/health":
            # db is a coarse status only ("ok" / "disabled" / "error") —
            # never connection details (spec Phase 76 observability).
            return self._json(200, {
                "ok": True,
                "service": "leakguard",
                "db": db_pool.db_status(),
            })
        if route == "/api/providers/health":
            # Public-safe provider summary (spec Phase 10): names,
            # capabilities, outcome counts, error KINDS only — never
            # exception text, endpoints or per-scan data. Health is
            # in-memory; the mode line makes mock fixtures unmissable.
            return self._json(
                200, providers_registry.get_registry().summary())
        if route == "/api/auth/me":
            self._require_accounts()
            user, _token = self._require_user()
            body = dict(user)
            # Lets the frontend show the owner's Admin card — and
            # only the owner's (Stage S11). The gate itself is
            # re-checked server-side on every admin route regardless.
            body["is_admin"] = bool(self._call(
                admin_service.is_admin, user["id"]))
            return self._json(200, body)
        if route == "/api/auth/passkeys":
            # The caller's own passkeys (Batch D1): metadata and
            # display prefixes only — see accounts/webauthn.py.
            self._require_accounts()
            user, _token = self._require_user()
            return self._json(200, {
                "passkeys": self._call(webauthn_service.list_passkeys,
                                       user["id"]),
            })
        if route == "/api/consents":
            self._require_accounts()
            user, _token = self._require_user()
            return self._json(200, {
                "consents": self._call(consents_service.current_consents,
                                       user["id"]),
            })
        if route == "/api/identifiers":
            self._require_accounts()
            user, _token = self._require_user()
            return self._json(200, {
                "identifiers": self._call(
                    identifiers_service.list_identifiers, user["id"]),
            })
        if route == "/api/domains":
            self._require_accounts()
            user, _token = self._require_user()
            return self._json(200, {
                "domains": self._call(
                    domains_service.list_domains, user["id"]),
            })
        if route == "/api/household":
            self._require_accounts()
            user, _token = self._require_user()
            return self._json(200, self._call(
                households_service.get_household, user["id"]))
        if route == "/api/admin/overview":
            # Aggregates ONLY (counts, provider health, db status)
            # — see accounts/admin.py's privacy contract. The gate
            # answers 404 to everyone who is not the owner.
            admin = self._require_admin()
            return self._json(200, self._call(
                admin_service.overview, admin["id"]))
        if route == "/api/admin/audit":
            admin = self._require_admin()
            query = urllib.parse.parse_qs(parsed.query)
            limit = query.get("limit", [None])[0]
            return self._json(200, {
                "audit": self._call(
                    admin_service.list_audit, admin["id"], limit),
            })
        if route == "/api/admin/metrics":
            # Phase 76: the overview's metrics block, standalone —
            # same owner-only 404 gate as every admin route.
            admin = self._require_admin()
            return self._json(200, self._call(
                admin_service.metrics, admin["id"]))
        if route == "/api/tokens":
            # Token management is session-only: a token must never
            # be able to mint or list other tokens.
            self._require_accounts()
            user, _token = self._require_user()
            return self._json(200, {
                "tokens": self._call(api_tokens_service.list_tokens,
                                     user["id"]),
            })
        if route == "/api/scans":
            self._require_accounts()
            user = self._require_reader()
            return self._json(200, {
                "jobs": self._call(scan_jobs_service.list_jobs, user["id"]),
            })
        if route == "/api/monitoring/settings":
            self._require_accounts()
            user, _token = self._require_user()
            return self._json(200, self._call(
                monitoring_service.get_settings, user["id"]))
        if route == "/api/monitoring/timeline":
            self._require_accounts()
            user = self._require_reader()
            return self._json(200, {
                "events": self._call(monitoring_service.timeline,
                                     user["id"]),
            })
        if route == "/api/action-center":
            # The signed-in home (Stage S9): one aggregate read
            # model — exposure, counts, recent activity and the
            # single server-computed next action.
            self._require_accounts()
            user = self._require_reader()
            return self._json(200, self._call(
                action_center_service.action_center, user["id"]))
        if route == "/api/notifications":
            self._require_accounts()
            user = self._require_reader()
            return self._json(200, {
                "notifications": self._call(
                    monitoring_service.list_notifications, user["id"]),
            })
        if route == "/api/search-exposure":
            # Search exposure (spec Phase 40): the caller's own
            # public-web discovery findings — what a search engine
            # shows about them — grouped by saved detail. Read-only,
            # so session OR Bearer token, owner-gated like every
            # account API (dashboard/search_exposure.py).
            self._require_accounts()
            user = self._require_reader()
            return self._json(200, self._call(
                search_exposure_service.search_exposure, user["id"]))
        if route == "/api/report":
            # Exposure & removal report (spec Phase 85): the
            # caller's own state as one generated HTML document
            # (dashboard/report.py). Session-only — it is a
            # personal document, so a read-only Bearer token never
            # suffices — and masked-only by construction: the
            # builder holds no decryption path. Generated on
            # demand, never persisted; the response flows through
            # _send, so the /api/* Cache-Control: no-store policy
            # (Phase 67) covers it like every API response.
            self._require_accounts()
            user, _token = self._require_user()
            return self._send(
                200, self._call(report_service.render_report, user),
                "text/html; charset=utf-8")
        if route == "/api/graph":
            # The exposure map (Stage S14): the caller's own
            # details → where they appeared → removal state, built
            # only from real findings and cases (dashboard/graph.py).
            # Read-only, so session OR Bearer token (the browser
            # extension's token can read it too).
            self._require_accounts()
            user = self._require_reader()
            return self._json(200, self._call(
                graph_service.exposure_graph, user["id"]))
        if route == "/api/remediation/cases":
            self._require_accounts()
            user = self._require_reader()
            return self._json(200, {
                "cases": self._call(remediation_service.list_cases,
                                    user["id"]),
            })
        if route == "/api/remediation/queue":
            self._require_accounts()
            user, _token = self._require_user()
            return self._json(200, {
                "queue": self._call(remediation_service.human_queue,
                                    user["id"]),
            })
        if route.startswith("/api/remediation/cases/"):
            self._require_accounts()
            user = self._require_reader()
            case_id = route[len("/api/remediation/cases/"):]
            try:
                uuid.UUID(case_id)
            except (ValueError, AttributeError, TypeError):
                return self._fail(errors.not_found(
                    "Removal case not found"))
            return self._json(200, {
                "case": self._call(remediation_service.case_detail,
                                   user["id"], case_id),
            })
        if route.startswith("/api/scans/"):
            self._require_accounts()
            user = self._require_reader()
            job_id = route[len("/api/scans/"):]
            try:
                uuid.UUID(job_id)
            except (ValueError, AttributeError, TypeError):
                return self._fail(errors.not_found("Scan not found"))
            return self._json(200, self._call(
                scan_jobs_service.get_job, user["id"], job_id))
        return self._fail(errors.not_found())

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            # Oversize is its own honest answer (413), not a generic
            # "invalid JSON" (Stage S12 request-size guard). Every
            # JSON POST route reads through here, so this one check
            # covers them all.
            raise errors.payload_too_large()
        if length <= 0:
            return None
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return None
        return data if isinstance(data, dict) else None

    def do_POST(self):
        return self._safe_dispatch(self._do_POST)

    def _do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        route = _versioned_route(parsed.path)
        if route.startswith("/api/auth/") or route in (
                "/api/consents", "/api/identifiers", "/api/scans",
                "/api/domains", "/api/remediation/run",
                "/api/household/members", "/api/tokens",
                "/api/privacy/export", "/api/findings/feedback",
                "/api/tools/policy-analyzer") \
                or route.startswith("/api/domains/") \
                or route.startswith("/api/admin/") \
                or route.startswith("/api/remediation/cases/"):
            return self._accounts_post(route)
        if route == "/api/agent/plan":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            profile = {
                "full_name": str(payload.get("full_name", ""))[:120],
                "email": str(payload.get("email", ""))[:200],
                "phone": str(payload.get("phone", ""))[:40],
                "city": str(payload.get("city", ""))[:120],
            }
            if not profile["full_name"] and not profile["email"]:
                return self._fail(errors.bad_request(
                    "missing_profile", "Enter at least a name or an email"))
            return self._json(200, {
                "profile": profile,
                "plan": agent_engine.build_plan(profile),
                "engine": "zero-token deterministic scripts (playbooks + live form probe) — no AI involved",
            })
        if route == "/api/agent/probe":
            self._enforce_rate_limit("agent_probe",
                                     "ip:" + self._client_ip())
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            broker = str(payload.get("broker", ""))[:80]
            profile = payload.get("profile") or {}
            if not isinstance(profile, dict):
                profile = {}
            profile = {k: str(v)[:200] for k, v in profile.items()
                       if k in ("full_name", "email", "phone", "city", "listing_url")}
            if payload.get("deep"):
                result = agent_engine.probe_with_browser_fallback(broker, profile)
            else:
                result = agent_engine.probe_broker(broker, profile)
            return self._json(200, result)
        if route == "/api/agent/submit":
            self._enforce_rate_limit("agent_submit",
                                     "ip:" + self._client_ip())
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            if payload.get("confirm") is not True:
                return self._fail(errors.bad_request(
                    "confirmation_required", "Submission needs explicit confirmation"))
            broker = str(payload.get("broker", ""))[:80]
            action = str(payload.get("form_action", ""))[:1000]
            method = str(payload.get("method", "POST")).upper()
            data = payload.get("payload") or {}
            # SSRF guard: the form action must live on the broker's own host.
            brokers = {b["name"]: b for b in agent_engine.load_brokers()}
            known = brokers.get(broker)
            host = urllib.parse.urlparse(action).netloc.lower()
            allowed = set()
            for b in brokers.values():
                allowed.add(urllib.parse.urlparse(b["optout_url"]).netloc.lower())
            if not known or host not in allowed:
                return self._fail(errors.bad_request(
                    "unknown_broker_host", "Form action is not on a known broker host"))
            if method not in ("GET", "POST") or not isinstance(data, dict) or len(data) > 30:
                return self._fail(errors.bad_request(
                    "bad_submission", "Bad submission"))
            clean = {str(k)[:80]: str(v)[:500] for k, v in data.items()}
            return self._json(200, agent_engine.submit_form(action, method, clean))
        if route != "/api/scan":
            return self._fail(errors.not_found())
        self._enforce_rate_limit("anon_scan", "ip:" + self._client_ip())
        payload = self._read_json_body()
        if payload is None:
            return self._fail(errors.invalid_json())
        email = str(payload.get("email", "")).strip().lower()
        password = payload.get("password") or ""
        if not EMAIL_RE.match(email):
            return self._fail(errors.bad_request(
                "invalid_email", "Enter a valid email address"))
        if not isinstance(password, str) or len(password) > 200:
            return self._fail(errors.bad_request(
                "password_too_long", "Password too long"))

        breaches, err = check_email_breaches(email)
        analytics = breach_analytics(email) if breaches else None
        pwned = check_password_pwned(password) if password else None
        score = exposure_score(breaches, analytics, pwned) if breaches is not None else None
        return self._json(200, {
            "email": email,
            "breaches": breaches,
            "breach_count": len(breaches) if breaches is not None else None,
            "breach_error": err,
            "analytics": analytics,
            "password_pwned_count": pwned,
            "exposure_score": score,
            "sources": ["XposedOrNot (email breaches)", "Have I Been Pwned Pwned Passwords (password, k-anonymity)"],
        })


    # ---------- accounts POST routes (Stage S3) ----------
    def _accounts_post(self, route):
        """All state-changing account routes. Every one passes the
        CSRF guard and the accounts-configured check FIRST; protected
        ones then resolve the session before touching any data, and
        every service call is scoped by the session's user id."""
        if route == "/api/auth/logout":
            security.require_csrf(self)
            token = self._session_token()
            if token and accounts_available():
                try:
                    auth_service.logout(token)
                except Exception:
                    pass  # clearing the cookie matters more
            return self._json(200, {"ok": True}, extra_headers=[
                ("Set-Cookie", sessions_mod.clear_cookie_header())])

        security.require_csrf(self)
        self._require_accounts()

        if route == "/api/admin/replay":
            # Dead-letter replay (Phase 119): an admin ACTION, so
            # it follows the house admin pattern exactly —
            # _require_admin answers 404 to anyone who is not the
            # owner (the surface stays invisible rather than
            # forbidden), and the CSRF guard above has already run.
            admin = self._require_admin()
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            result = self._call(admin_service.replay_dead_letter,
                                admin["id"], payload.get("kind"),
                                payload.get("id"))
            return self._json(200, {"replay": result})

        if route == "/api/auth/register":
            # Emergency control (core/flags.py): the owner can shut
            # registration without touching the rest of the site.
            if not flags.is_enabled("registration"):
                return self._fail(errors.unavailable(
                    "feature_disabled",
                    "Creating an account is paused right now"))
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            # Two caps stack here: the S12 per-IP hourly cap below,
            # and the S3 credential limiter (per IP + per account
            # email, 10/15 min) that register shares with login.
            # Login is NOT routed through core/ratelimit — see that
            # module's docstring for why the S3 two-bucket semantics
            # stay as they are.
            self._enforce_rate_limit("register", "ip:" + self._client_ip())
            self._rate_limit_credentials(payload.get("email"))
            user, token = self._call(
                auth_service.register,
                payload.get("email"), payload.get("password"),
                payload.get("name"))
            return self._json(201, {"user": user}, extra_headers=[
                ("Set-Cookie", sessions_mod.cookie_header(token))])

        if route == "/api/auth/login":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            self._rate_limit_credentials(payload.get("email"))
            result = self._call(
                auth_service.login,
                payload.get("email"), payload.get("password"),
                payload.get("totp_code"))
            if result.get("totp_required"):
                return self._json(200, {"totp_required": True})
            return self._json(200, {"user": result["user"]}, extra_headers=[
                ("Set-Cookie", sessions_mod.cookie_header(result["token"]))])

        if route == "/api/auth/forgot-password":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            # Enumeration-safe: the service is silent about whether
            # the email exists, and this answer NEVER varies. The
            # rate limit is the one exception: an exhausted IP gets
            # the standard 429 like every other route. A 429 reveals
            # nothing about any account (it depends only on the
            # caller's own request count), so enumeration safety is
            # preserved.
            self._enforce_rate_limit("forgot_password",
                                     "ip:" + self._client_ip())
            self._call(auth_service.forgot_password,
                       payload.get("email"))
            return self._json(200, {"ok": True})

        if route == "/api/auth/reset-password":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            self._call(auth_service.reset_password,
                       payload.get("token"), payload.get("new_password"))
            return self._json(200, {"ok": True})

        if route == "/api/auth/passkey/login/options":
            # Passkey sign-in (Batch D1): PUBLIC like password login
            # — the ceremony uses discoverable credentials and the
            # response depends on no account, so it cannot enumerate
            # accounts or passkeys. The session is created by the
            # verify step, exactly as a password login creates it.
            return self._json(200, self._call(
                webauthn_service.authentication_options, self.headers))
        if route == "/api/auth/passkey/login/verify":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            user, token = self._call(
                webauthn_service.complete_authentication,
                payload, self.headers, self._client_ip())
            return self._json(200, {"user": user}, extra_headers=[
                ("Set-Cookie", sessions_mod.cookie_header(token))])

        user, token = self._require_user()

        if route == "/api/auth/passkey/register/options":
            # Enrollment begins with a password re-check inside the
            # service (accounts/webauthn.py), then a challenge bound
            # to this user + session.
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            result = self._call(
                webauthn_service.registration_options, user["id"],
                payload.get("password"), token, self.headers,
                self._client_ip())
            return self._json(200, result)
        if route == "/api/auth/passkey/register/verify":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            result = self._call(
                webauthn_service.complete_registration, user["id"],
                token, payload, self.headers)
            return self._json(201, {"passkey": result})
        if route.startswith("/api/auth/passkeys/") and \
                route.endswith("/revoke"):
            passkey_id = route[len("/api/auth/passkeys/"):-len("/revoke")]
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            result = self._call(
                webauthn_service.revoke_passkey, user["id"],
                passkey_id, payload.get("password"))
            return self._json(200, result)

        if route == "/api/auth/change-password":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            self._call(auth_service.change_password, user["id"],
                       payload.get("current_password"),
                       payload.get("new_password"), token)
            return self._json(200, {"ok": True})
        if route == "/api/auth/delete-account":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            self._call(auth_service.delete_account, user["id"],
                       payload.get("password"))
            return self._json(200, {"ok": True}, extra_headers=[
                ("Set-Cookie", sessions_mod.clear_cookie_header())])
        if route == "/api/auth/totp/enroll":
            result = self._call(auth_service.totp_enroll, user["id"])
            return self._json(200, result)
        if route == "/api/auth/totp/activate":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            result = self._call(auth_service.totp_activate, user["id"],
                                payload.get("code"))
            return self._json(200, result)
        if route == "/api/auth/totp/disable":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            result = self._call(auth_service.totp_disable, user["id"],
                                payload.get("password"), payload.get("code"))
            return self._json(200, result)
        if route == "/api/privacy/export":
            # The only plaintext exit, now behind a password re-check
            # (accounts/privacy.py): the body names the password and
            # the format; the service counts the attempt against the
            # credential rate limiter and verifies before building
            # anything. There is no GET variant any more.
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            body, ctype, filename = self._call(
                privacy_service.export_document, user["id"],
                payload.get("password"), payload.get("format"),
                self._client_ip())
            return self._send(200, body, ctype, extra_headers=[(
                "Content-Disposition",
                'attachment; filename="%s"' % filename)])
        if route == "/api/consents":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            state = self._call(consents_service.set_consent, user["id"],
                               payload.get("purpose"), payload.get("granted"))
            return self._json(200, {"consents": state})
        if route == "/api/identifiers":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            record = self._call(identifiers_service.add_identifier,
                                user["id"], payload.get("kind"),
                                payload.get("value"),
                                payload.get("member_id"))
            return self._json(201, {"identifier": record})
        if route == "/api/household/members":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            member = self._call(households_service.add_member,
                                user["id"], payload.get("label"))
            return self._json(201, {"member": member})
        if route == "/api/tokens":
            # Creating a token is a mutation, hence session + CSRF
            # only (this handler's guard already ran). The 201 body
            # is the ONE time the raw token is ever shown.
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            created = self._call(api_tokens_service.create_token,
                                 user["id"], payload.get("name"))
            return self._json(201, created)
        if route == "/api/domains":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            record = self._call(domains_service.add_domain,
                                user["id"], payload.get("domain"))
            return self._json(201, {"domain": record})
        if route.startswith("/api/domains/") and \
                route.endswith("/verify"):
            domain_id = route[len("/api/domains/"):-len("/verify")]
            try:
                uuid.UUID(domain_id)
            except (ValueError, AttributeError, TypeError):
                return self._fail(errors.not_found("Domain not found"))
            record = self._call(domains_service.verify_domain,
                                user["id"], domain_id)
            return self._json(200, {"domain": record})
        if route == "/api/findings/feedback":
            # False-positive feedback (Phase 156): the verdict is
            # owner-scoped inside the service (a foreign finding id
            # answers 404); 'none' clears the verdict again.
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            verdict = self._call(
                feedback_service.set_verdict, user["id"],
                payload.get("finding_id"), payload.get("verdict"))
            return self._json(200, {"feedback": verdict})
        if route == "/api/tools/policy-analyzer":
            # Privacy policy analyzer (Phase 102): a deterministic
            # keyword checklist over text the signed-in user pastes
            # or one public policy page they name. Nothing is stored;
            # the URL path is SSRF-guarded and capped inside the
            # service (dashboard/policy_analyzer.py).
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            return self._json(200, self._call(
                policy_analyzer_service.analyze_payload, payload))
        if route == "/api/scans":
            # Emergency control: account full scans only — the
            # anonymous Quick Scan (/api/scan) is never flag-gated.
            if not flags.is_enabled("account_scans"):
                return self._fail(errors.unavailable(
                    "feature_disabled",
                    "Full scans are paused right now"))
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            self._enforce_rate_limit("user_scans", "user:" + user["id"])
            job, created = self._call(
                scan_jobs_service.create_job, user["id"],
                payload.get("idempotency_key"))
            return self._json(201 if created else 200, {"job": job})
        if route == "/api/remediation/run":
            # The one command: consent-gated inside the service (403
            # consent_required), then one idempotent case per broker.
            # The worker drains the queue asynchronously.
            if not flags.is_enabled("removal_runs"):
                return self._fail(errors.unavailable(
                    "feature_disabled",
                    "Automatic removal is paused right now"))
            self._enforce_rate_limit("user_remediation_run",
                                     "user:" + user["id"])
            return self._json(200, self._call(
                remediation_service.run_removal, user["id"]))
        if route.startswith("/api/remediation/cases/"):
            case_ref = route[len("/api/remediation/cases/"):]
            for suffix, service_fn in (
                    ("/verify", remediation_verify.verify_case),
                    ("/retry", remediation_service.retry_case)):
                if case_ref.endswith(suffix):
                    case_id = case_ref[:-len(suffix)]
                    try:
                        uuid.UUID(case_id)
                    except (ValueError, AttributeError, TypeError):
                        return self._fail(
                            errors.not_found("Removal case not found"))
                    return self._json(200, self._call(
                        service_fn, user["id"], case_id))
            return self._fail(errors.not_found())
        return self._fail(errors.not_found())

    def do_PUT(self):
        return self._safe_dispatch(self._do_PUT)

    def _do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        route = _versioned_route(parsed.path)
        if route == "/api/monitoring/settings":
            security.require_csrf(self)
            self._require_accounts()
            user, _token = self._require_user()
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            result = self._call(
                monitoring_service.update_settings, user["id"],
                payload.get("cadence_days", monitoring_service.UNSET),
                payload.get("monitoring_paused",
                            monitoring_service.UNSET))
            return self._json(200, result)
        return self._fail(errors.not_found())

    def do_PATCH(self):
        return self._safe_dispatch(self._do_PATCH)

    def _do_PATCH(self):
        parsed = urllib.parse.urlparse(self.path)
        route = _versioned_route(parsed.path)
        prefix = "/api/identifiers/"
        if route.startswith(prefix) and len(route) > len(prefix):
            security.require_csrf(self)
            self._require_accounts()
            user, _token = self._require_user()
            ident = route[len(prefix):]
            try:
                uuid.UUID(ident)
            except (ValueError, AttributeError, TypeError):
                return self._fail(errors.not_found("Identifier not found"))
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            # The one PATCH in the API: (re)assign the identifier to
            # a household member, or back to the owner with null.
            result = self._call(identifiers_service.update_identifier_member,
                                user["id"], ident, payload.get("member_id"))
            return self._json(200, {"identifier": result})
        return self._fail(errors.not_found())

    def do_DELETE(self):
        return self._safe_dispatch(self._do_DELETE)

    def _do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        route = _versioned_route(parsed.path)
        prefix = "/api/tokens/"
        if route.startswith(prefix) and len(route) > len(prefix):
            security.require_csrf(self)
            self._require_accounts()
            user, _token = self._require_user()
            token_id = route[len(prefix):]
            try:
                uuid.UUID(token_id)
            except (ValueError, AttributeError, TypeError):
                return self._fail(errors.not_found("API token not found"))
            result = self._call(api_tokens_service.revoke_token,
                                user["id"], token_id)
            return self._json(200, result)
        prefix = "/api/household/members/"
        if route.startswith(prefix) and len(route) > len(prefix):
            security.require_csrf(self)
            self._require_accounts()
            user, _token = self._require_user()
            member_id = route[len(prefix):]
            try:
                uuid.UUID(member_id)
            except (ValueError, AttributeError, TypeError):
                return self._fail(
                    errors.not_found("Household member not found"))
            result = self._call(households_service.delete_member,
                                user["id"], member_id)
            return self._json(200, result)
        prefix = "/api/identifiers/"
        if route.startswith(prefix) and len(route) > len(prefix):
            security.require_csrf(self)
            self._require_accounts()
            user, _token = self._require_user()
            ident = route[len(prefix):]
            try:
                uuid.UUID(ident)
            except (ValueError, AttributeError, TypeError):
                return self._fail(errors.not_found("Identifier not found"))
            result = self._call(identifiers_service.delete_identifier,
                                user["id"], ident)
            return self._json(200, result)
        prefix = "/api/domains/"
        if route.startswith(prefix) and len(route) > len(prefix):
            security.require_csrf(self)
            self._require_accounts()
            user, _token = self._require_user()
            domain_id = route[len(prefix):]
            try:
                uuid.UUID(domain_id)
            except (ValueError, AttributeError, TypeError):
                return self._fail(errors.not_found("Domain not found"))
            result = self._call(domains_service.delete_domain,
                                user["id"], domain_id)
            return self._json(200, result)
        return self._fail(errors.not_found())


def _startup_migrations():
    """Apply pending DB migrations at boot when a database is configured
    (Stage S2). Guarded: any failure is logged (exception class only)
    and boot continues — a broken database must never take down the
    anonymous scan, which is storage-free by design."""
    try:
        from db import migrate

        applied = migrate.run_migrations_if_configured(db_pool.migration_dsn())
        for name in applied:
            print("LeakGuard: applied DB migration %s" % name)
    except Exception as exc:
        logging_setup.log_error(None, "startup migrations failed: "
                                + type(exc).__name__)


def _startup_worker():
    """Start the in-process scan worker (Stage S5) when a database
    is configured. Guarded exactly like migrations: a worker failure
    must never take the site down."""
    try:
        from scanning import worker

        if worker.start_worker_if_configured():
            print("LeakGuard: scan worker started")
    except Exception as exc:
        logging_setup.log_error(None, "scan worker failed to start: "
                                + type(exc).__name__)


def _startup_broker_seed():
    """Seed the broker registry (Stage S7) from brokers.json when a
    database is configured. Guarded like migrations — the anonymous
    product reads brokers.json directly and never depends on this."""
    try:
        seeded = broker_registry.seed_brokers_if_configured()
        if seeded:
            print("LeakGuard: broker registry seeded (%d brokers)" % seeded)
    except Exception as exc:
        logging_setup.log_error(None, "broker seed failed: "
                                + type(exc).__name__)


def _startup_remediation_worker():
    """Start the in-process remediation worker (Stage S7) when a
    database is configured. Guarded exactly like the scan worker."""
    try:
        from remediation import engine, worker
        from monitoring import notify

        # Authorized-agent email sending (2026-10-08): wire the
        # mail lane into the engine as an injected callable — the
        # remediation package never imports the lane itself. When
        # the lane is not configured the mailer answers False and
        # email cases park for the user, exactly as before.
        def _agent_mailer(to, subject, body, reply_to):
            if not notify.lane_configured():
                return False
            return notify.send_email(to, subject, body,
                                     reply_to=reply_to)

        engine.set_agent_mailer(_agent_mailer)

        if worker.start_worker_if_configured():
            print("LeakGuard: remediation worker started")
    except Exception as exc:
        logging_setup.log_error(None, "remediation worker failed to start: "
                                + type(exc).__name__)


def _startup_monitoring_scheduler():
    """Start the hourly monitoring scheduler (Stage S8) when a
    database is configured. Guarded exactly like the workers."""
    try:
        from monitoring import scheduler

        if scheduler.start_scheduler_if_configured():
            print("LeakGuard: monitoring scheduler started")
    except Exception as exc:
        logging_setup.log_error(None, "monitoring scheduler failed "
                                "to start: " + type(exc).__name__)


def _startup_retention_worker():
    """Start the in-process retention worker (Stage S12) when a
    database is configured. Guarded exactly like the other workers:
    a retention failure must never take the site down."""
    try:
        from core import retention

        if retention.start_retention_if_configured():
            print("LeakGuard: retention worker started")
    except Exception as exc:
        logging_setup.log_error(None, "retention worker failed "
                                "to start: " + type(exc).__name__)


def main():
    logging_setup.setup_logging()
    _startup_migrations()
    _startup_worker()
    _startup_broker_seed()
    _startup_remediation_worker()
    _startup_monitoring_scheduler()
    _startup_retention_worker()
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"LeakGuard running at http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
