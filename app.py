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
from accounts import auth as auth_service
from accounts import consents as consents_service
from accounts import domains as domains_service
from accounts import identifiers as identifiers_service
from accounts import privacy as privacy_service
from accounts import ratelimit
from accounts import sessions as sessions_mod
from core import context, errors, logging_setup, security
from db import pool as db_pool
from providers import registry as providers_registry
from remediation import registry_seed as broker_registry
from remediation import service as remediation_service
from remediation import verify as remediation_verify
from scanning import jobs as scan_jobs_service
from scanning import risk as risk_engine

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
BROKERS_FILE = BASE / "brokers.json"

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
MAX_BODY = 32 * 1024


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
            "application/json")

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
        # Render (and most hosts) sit behind a proxy that sets
        # X-Forwarded-For; its first entry is the client. Fall back to
        # the direct peer (local dev, tests).
        xff = self.headers.get("X-Forwarded-For") or ""
        if xff.strip():
            return xff.split(",")[0].strip()
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
        route = parsed.path
        if route == "/" or route == "/index.html":
            return self._serve_file(STATIC / "index.html", "text/html; charset=utf-8")
        if route == "/static/style.css":
            return self._serve_file(STATIC / "style.css", "text/css; charset=utf-8")
        if route == "/static/app.js":
            return self._serve_file(STATIC / "app.js", "text/javascript; charset=utf-8")
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
            return self._json(200, user)
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
        if route == "/api/scans":
            self._require_accounts()
            user, _token = self._require_user()
            return self._json(200, {
                "jobs": self._call(scan_jobs_service.list_jobs, user["id"]),
            })
        if route == "/api/remediation/cases":
            self._require_accounts()
            user, _token = self._require_user()
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
        if route.startswith("/api/scans/"):
            self._require_accounts()
            user, _token = self._require_user()
            job_id = route[len("/api/scans/"):]
            try:
                uuid.UUID(job_id)
            except (ValueError, AttributeError, TypeError):
                return self._fail(errors.not_found("Scan not found"))
            return self._json(200, self._call(
                scan_jobs_service.get_job, user["id"], job_id))
        if route == "/api/privacy/export":
            self._require_accounts()
            user, _token = self._require_user()
            document = self._call(privacy_service.build_export, user["id"])
            return self._send(
                200, json.dumps(document, indent=2), "application/json",
                extra_headers=[(
                    "Content-Disposition",
                    'attachment; filename="leakguard-export.json"')])
        return self._fail(errors.not_found())

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
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
        if parsed.path.startswith("/api/auth/") or parsed.path in (
                "/api/consents", "/api/identifiers", "/api/scans",
                "/api/domains", "/api/remediation/run") \
                or parsed.path.startswith("/api/domains/") \
                or parsed.path.startswith("/api/remediation/cases/"):
            return self._accounts_post(parsed.path)
        if parsed.path == "/api/agent/plan":
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
        if parsed.path == "/api/agent/probe":
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
        if parsed.path == "/api/agent/submit":
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
        if parsed.path != "/api/scan":
            return self._fail(errors.not_found())
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

        if route == "/api/auth/register":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            self._rate_limit_credentials(payload.get("email"))
            user, token = self._call(
                auth_service.register,
                payload.get("email"), payload.get("password"))
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

        user, token = self._require_user()

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
                                payload.get("value"))
            return self._json(201, {"identifier": record})
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
        if route == "/api/scans":
            payload = self._read_json_body()
            if payload is None:
                return self._fail(errors.invalid_json())
            job, created = self._call(
                scan_jobs_service.create_job, user["id"],
                payload.get("idempotency_key"))
            return self._json(201 if created else 200, {"job": job})
        if route == "/api/remediation/run":
            # The one command: consent-gated inside the service (403
            # consent_required), then one idempotent case per broker.
            # The worker drains the queue asynchronously.
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

    def do_DELETE(self):
        return self._safe_dispatch(self._do_DELETE)

    def _do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        prefix = "/api/identifiers/"
        if parsed.path.startswith(prefix) and len(parsed.path) > len(prefix):
            security.require_csrf(self)
            self._require_accounts()
            user, _token = self._require_user()
            ident = parsed.path[len(prefix):]
            try:
                uuid.UUID(ident)
            except (ValueError, AttributeError, TypeError):
                return self._fail(errors.not_found("Identifier not found"))
            result = self._call(identifiers_service.delete_identifier,
                                user["id"], ident)
            return self._json(200, result)
        prefix = "/api/domains/"
        if parsed.path.startswith(prefix) and len(parsed.path) > len(prefix):
            security.require_csrf(self)
            self._require_accounts()
            user, _token = self._require_user()
            domain_id = parsed.path[len(prefix):]
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

        applied = migrate.run_migrations_if_configured()
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
        from remediation import worker

        if worker.start_worker_if_configured():
            print("LeakGuard: remediation worker started")
    except Exception as exc:
        logging_setup.log_error(None, "remediation worker failed to start: "
                                + type(exc).__name__)


def main():
    logging_setup.setup_logging()
    _startup_migrations()
    _startup_worker()
    _startup_broker_seed()
    _startup_remediation_worker()
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"LeakGuard running at http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
