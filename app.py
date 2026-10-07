#!/usr/bin/env python3
"""
LeakGuard — find leaked personal data and help remove it.

GUI-first (web UI, no CLI). Almost entirely Python standard library, so
it runs anywhere — local machine, Render free tier, any VPS. Since Stage
S2 there are exactly two third-party dependencies (see requirements.txt:
a Postgres driver and AES-GCM cryptography) and both are optional at
runtime: with no DATABASE_URL configured the app boots and serves every
feature exactly as before — the database and the encrypted identifier
vault (db/, vault/) simply stay dormant.

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
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import agent as agent_engine
from core import context, errors, logging_setup, security
from db import pool as db_pool

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
BROKERS_FILE = BASE / "brokers.json"

XON_EMAIL = "https://api.xposedornot.com/v1/check-email/{email}"
XON_ANALYTICS = "https://api.xposedornot.com/v1/breach-analytics?email={email}"
HIBP_RANGE = "https://api.pwnedpasswords.com/range/{prefix}"

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
MAX_BODY = 32 * 1024
UA = {"User-Agent": "LeakGuard/1.0 (+https://github.com/xorudra/leakguard)"}


def _get_json(url, timeout=15):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _get_text(url, timeout=15):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def check_email_breaches(email):
    """Return (breach_names list, error or None)."""
    url = XON_EMAIL.format(email=urllib.parse.quote(email, safe=""))
    try:
        data = _get_json(url)
    except Exception:
        return None, "Breach database unreachable right now. Try again in a minute."
    if isinstance(data, dict) and data.get("Error"):
        return [], None
    breaches = []
    raw = data.get("breaches") if isinstance(data, dict) else None
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, list):
                breaches.extend(str(x) for x in item)
            elif isinstance(item, str):
                breaches.append(item)
    return breaches, None


def breach_analytics(email):
    """Return dict with risk + exposed data types, or None."""
    url = XON_ANALYTICS.format(email=urllib.parse.quote(email, safe=""))
    try:
        data = _get_json(url)
    except Exception:
        return None
    metrics = data.get("BreachMetrics") if isinstance(data, dict) else None
    if not isinstance(metrics, dict):
        return None
    out = {"risk_label": None, "risk_score": None, "exposed_data": [], "passwords_strength": None}
    risk = metrics.get("risk")
    if isinstance(risk, list) and risk and isinstance(risk[0], dict):
        out["risk_label"] = risk[0].get("risk_label")
        out["risk_score"] = risk[0].get("risk_score")
    xposed = metrics.get("xposed_data")
    if isinstance(xposed, list):
        types = []
        def walk(node):
            if isinstance(node, dict):
                name = str(node.get("name", ""))
                if name.startswith("data_"):
                    types.append(name[5:].replace("_", " "))
                for child in node.get("children", []) or []:
                    walk(child)
        for node in xposed:
            walk(node)
        out["exposed_data"] = sorted(set(types))
    if isinstance(metrics.get("passwords_strength"), list) and metrics["passwords_strength"]:
        out["passwords_strength"] = metrics["passwords_strength"][0]
    return out


def check_password_pwned(password):
    """k-anonymity check. Returns count (int) or None on failure."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        text = _get_text(HIBP_RANGE.format(prefix=prefix))
    except Exception:
        return None
    for line in text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].strip().upper() == suffix:
            try:
                return int(parts[1])
            except ValueError:
                return 0
    return 0


def exposure_score(breaches, analytics, pwned_count):
    """0 = no exposure found, 100 = worst. Deterministic, labelled in UI."""
    if analytics and isinstance(analytics.get("risk_score"), (int, float)):
        score = int(analytics["risk_score"])
    elif breaches is not None:
        score = min(100, len(breaches) * 8)
    else:
        score = 0
    if pwned_count:
        score = max(score, 85 if pwned_count > 1000 else 70)
    return max(0, min(100, score))


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

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self._response_status = code
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        rid = self._request_id()
        if rid:
            self.send_header("X-Request-Id", rid)
        security.apply_security_headers(self)
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json")

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
            return self._json(200, {"brokers": load_brokers()})
        if route == "/api/health":
            # db is a coarse status only ("ok" / "disabled" / "error") —
            # never connection details (spec Phase 76 observability).
            return self._json(200, {
                "ok": True,
                "service": "leakguard",
                "db": db_pool.db_status(),
            })
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


def main():
    logging_setup.setup_logging()
    _startup_migrations()
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"LeakGuard running at http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
