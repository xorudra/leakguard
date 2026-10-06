#!/usr/bin/env python3
"""
LeakGuard — find leaked personal data and help remove it.

GUI-first (web UI, no CLI). Zero dependencies: Python standard library only,
so it runs anywhere — local machine, Render free tier, any VPS.

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

    def log_message(self, fmt, *args):  # keep logs clean, never log bodies
        pass

    # ---------- helpers ----------
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self'; script-src 'self'; "
                         "img-src 'self' data:; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json")

    def _serve_file(self, path, ctype):
        try:
            data = path.read_bytes()
        except OSError:
            return self._json(404, {"error": "Not found"})
        self._send(200, data, ctype)

    # ---------- routes ----------
    def do_GET(self):
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
            return self._json(200, {"ok": True, "service": "leakguard"})
        return self._json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/scan":
            return self._json(404, {"error": "Not found"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            return self._json(400, {"error": "Bad request size"})
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return self._json(400, {"error": "Invalid JSON"})
        email = str(payload.get("email", "")).strip().lower()
        password = payload.get("password") or ""
        if not EMAIL_RE.match(email):
            return self._json(400, {"error": "Enter a valid email address"})
        if not isinstance(password, str) or len(password) > 200:
            return self._json(400, {"error": "Password too long"})

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


def main():
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"LeakGuard running at http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
