#!/usr/bin/env python3
"""
LeakGuard browser probe — the layer for opt-out pages that block plain HTTP
scripts (403 / JavaScript walls). Uses Playwright driving a real Chromium.
Still zero tokens: it's a browser, not an AI.

Run standalone (used by agent.py via subprocess so a hung page can never
hang the web server):

    python3 browser_probe.py <url>

Prints one JSON object:
  {via, reachable, status, title, forms[], blockers[], challenge,
   refused[]}
Proxy is taken from the standard http_proxy/https_proxy environment
(credentials are used, never printed).

Domain allowlist (Phase 166): the probe only visits broker domains
(brokers.json + verify_sources.json) plus the operator's local
config list (LEAKGUARD_PROBE_EXTRA_DOMAINS / probe_domains.txt).
Off-list targets are refused before launch; off-list requests or
redirects inside the browser are aborted and recorded in 'refused'.

Local-only status (Phase 178 decision, docs/DOC_REVIEW.md): this
script imports no project code and is never imported by the
server. The single spawn path is agent.py's subprocess call in
its deep-probe chain (used by local_agent.py and, in deep mode,
by the anonymous POST /api/agent/probe route). On the deployed
server Playwright and Chromium are deliberately NOT installed
(they live in requirements-optional.txt, not requirements.txt),
so there probe() reports "Playwright not installed on this
server" instead of launching anything; LEAKGUARD_NO_BROWSER=1
disables the spawn outright. The account remediation engine
never uses this layer — it records the browser step as skipped
on_server (remediation/engine.py).
"""

import json
import os
import sys
import urllib.parse
from pathlib import Path

BASE = Path(__file__).resolve().parent

CHROME_CANDIDATES = [
    os.environ.get("LEAKGUARD_CHROME", ""),
    "/opt/meta-chromium/chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
]

CHALLENGE_MARKERS = [
    "just a moment", "verify you are human", "checking your browser",
    "are you a robot", "human verification", "attention required",
    "please complete the security check", "cf-challenge", "turnstile",
]


# ---------------------------------------------------------------------------
# Domain allowlist (Phase 166) — the local probe only ever visits
# broker domains.
#
# The probe drives a real browser at pages named by data (playbooks /
# API callers), so where it may go is a policy, not a default: a page
# (or a redirect, or a script on the page) must not be able to walk
# the browser onto an arbitrary host. The allowlist is:
#
#   * every broker domain — the hosts in brokers.json (opt-out and
#     alternate URLs) and the listing domains in verify_sources.json;
#   * PLUS the operator's explicit local config list:
#     LEAKGUARD_PROBE_EXTRA_DOMAINS (comma/whitespace separated) and
#     probe_domains.txt next to this script (one domain per line,
#     '#' comments) — the place to add, e.g., a broker's separate
#     privacy-platform domain when its flow legitimately leaves the
#     broker's own host.
#
# Matching is domain-or-subdomain: an entry 'spokeo.com' allows
# 'spokeo.com' and 'people.spokeo.com', never 'evilspokeo.com' or
# 'spokeo.com.evil.example'. Enforcement is two-layered in probe():
# a pre-flight refusal of an off-list target BEFORE any browser
# launches, and a request guard inside the browser context that
# aborts (and records) any request — navigation, redirect hop, or
# subresource — whose host is off the list. Refusals land in the
# result's 'refused' list and in 'blockers', never silently.
# The server never runs this probe (Phase 137): it stays a local,
# subprocess-isolated tool.
# ---------------------------------------------------------------------------

def _normalize_domain(raw):
    """One allowlist/check entry, normalized: bare lowercase host,
    no scheme, path, port, credentials, trailing dot, or leading
    'www.' (so a broker's www host and its bare domain are one
    entry, and subdomains still match via the suffix rule)."""
    host = (raw or "").strip().lower()
    if "://" in host:
        host = urllib.parse.urlparse(host).hostname or host
    host = host.split("/")[0].split(":")[0].rstrip(".")
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if host.startswith("www."):
        host = host[4:]
    return host


def broker_domains():
    """Every domain a broker lives on, from the data files beside
    this script (read as data — this script imports no project
    code): brokers.json opt-out/alternate URL hosts, and the
    listing domains in verify_sources.json."""
    domains = set()
    try:
        brokers = json.loads(
            (BASE / "brokers.json").read_text(encoding="utf-8"))
    except Exception:
        brokers = []
    for broker in brokers if isinstance(brokers, list) else []:
        for key in ("optout_url", "alt_optout_url"):
            host = _normalize_domain(broker.get(key) or "")
            if host:
                domains.add(host)
    try:
        sources = json.loads(
            (BASE / "verify_sources.json").read_text(encoding="utf-8"))
    except Exception:
        sources = {}
    for cfg in (sources or {}).values():
        if isinstance(cfg, dict):
            host = _normalize_domain(cfg.get("domain") or "")
            if host:
                domains.add(host)
            host = _normalize_domain(cfg.get("url") or "")
            if host:
                domains.add(host)
    return domains


def config_domains(environ=None, config_path=None):
    """The explicit local config list: the
    LEAKGUARD_PROBE_EXTRA_DOMAINS environment variable
    (comma/whitespace separated) and probe_domains.txt beside this
    script (one domain per line; blank lines and '#' comments are
    ignored). Missing sources simply contribute nothing."""
    environ = os.environ if environ is None else environ
    domains = set()
    raw = environ.get("LEAKGUARD_PROBE_EXTRA_DOMAINS", "")
    for part in raw.replace(",", " ").split():
        host = _normalize_domain(part)
        if host:
            domains.add(host)
    path = (Path(config_path) if config_path is not None
            else BASE / "probe_domains.txt")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        lines = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        host = _normalize_domain(line)
        if host:
            domains.add(host)
    return domains


def allowed_domains(environ=None, config_path=None):
    """The full probe allowlist: broker domains + local config."""
    return broker_domains() | config_domains(environ, config_path)


def host_allowed(host, allowed):
    """True when `host` is an allowlisted domain or a subdomain of
    one. Suffix tricks ('evilspokeo.com', 'spokeo.com.evil.example')
    do not match: the boundary is a dot or the whole string."""
    host = _normalize_domain(host)
    if not host:
        return False
    return any(host == domain or host.endswith("." + domain)
               for domain in allowed)


def url_allowed(url, allowed):
    """True when `url`'s host passes host_allowed."""
    host = urllib.parse.urlparse(url or "").hostname or ""
    return host_allowed(host, allowed)


def proxy_from_env():
    override = os.environ.get("LEAKGUARD_BROWSER_PROXY", "")
    if override:
        return {"server": override}
    raw = (os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or
           os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY") or "")
    if not raw:
        return None
    p = urllib.parse.urlparse(raw)
    if not p.hostname:
        return None
    server = f"{p.scheme}://{p.hostname}:{p.port}" if p.port else f"{p.scheme}://{p.hostname}"
    out = {"server": server}
    if p.username:
        out["username"] = urllib.parse.unquote(p.username)
    if p.password:
        out["password"] = urllib.parse.unquote(p.password)
    return out


def find_chrome():
    for c in CHROME_CANDIDATES:
        if c and os.path.exists(c):
            return c
    return None


def probe(url, timeout_ms=30000):
    result = {"via": "browser", "reachable": False, "status": None, "title": "",
              "forms": [], "blockers": [], "challenge": False,
              "refused": []}
    # Phase 166 pre-flight: an off-allowlist target is refused
    # before any browser launches (and before Playwright is even
    # imported, so the refusal is deterministic everywhere).
    allowed = allowed_domains()
    target_host = urllib.parse.urlparse(url or "").hostname or ""
    if not host_allowed(target_host, allowed):
        result["refused"].append({
            "url": url, "host": target_host,
            "reason": "not_on_allowlist"})
        result["blockers"].append(
            "Refused: %s is not on the probe domain allowlist — the "
            "local probe only visits broker domains plus the local "
            "config list (LEAKGUARD_PROBE_EXTRA_DOMAINS / "
            "probe_domains.txt)" % (target_host or url))
        return result
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        result["blockers"].append("Playwright not installed on this server")
        return result
    chrome = find_chrome()
    launch_kwargs = {"headless": True, "args": ["--no-sandbox", "--disable-dev-shm-usage"]}
    if chrome:
        launch_kwargs["executable_path"] = chrome
    proxy = proxy_from_env()
    if proxy:
        launch_kwargs["proxy"] = proxy
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(**launch_kwargs)
            # ignore_https_errors: some networks (and this dev VM) route TLS
            # through a MITM egress proxy whose CA Chromium doesn't trust.
            # Probe mode is read-only page inspection; form submission does
            # not go through the browser probe.
            context = browser.new_context(ignore_https_errors=True, user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"))
            # Phase 166 in-browser guard: EVERY request the context
            # makes — the navigation itself, each redirect hop, and
            # every subresource — is checked against the allowlist.
            # An off-list request is aborted and recorded in
            # result["refused"]; aborting the main navigation makes
            # goto raise, which the handler below reports.
            refused_hosts = set()

            def _allowlist_guard(route):
                req_url = route.request.url
                req_host = urllib.parse.urlparse(
                    req_url).hostname or ""
                if host_allowed(req_host, allowed):
                    route.continue_()
                    return
                if req_host not in refused_hosts:
                    refused_hosts.add(req_host)
                    result["refused"].append({
                        "url": req_url, "host": req_host,
                        "reason": "not_on_allowlist"})
                    result["blockers"].append(
                        "Refused a request to %s — not on the probe "
                        "domain allowlist" % req_host)
                route.abort()

            context.route("**/*", _allowlist_guard)
            page = context.new_page()
            try:
                resp = page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                # Belt and braces: if the browser somehow landed
                # off-list anyway (a client-side redirect the route
                # guard could not see), record it — the page's data
                # is not trusted either way.
                landed_host = urllib.parse.urlparse(
                    page.url or "").hostname or ""
                if (landed_host and landed_host != target_host
                        and not host_allowed(landed_host, allowed)
                        and landed_host not in refused_hosts):
                    refused_hosts.add(landed_host)
                    result["refused"].append({
                        "url": page.url, "host": landed_host,
                        "reason": "not_on_allowlist"})
                    result["blockers"].append(
                        "Refused: the page landed on %s — not on "
                        "the probe domain allowlist" % landed_host)
                result["status"] = resp.status if resp else None
                try:
                    page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:
                    pass
                result["title"] = (page.title() or "")[:200]
                result["reachable"] = True
                data = page.evaluate("""() => {
                  const forms = [];
                  document.querySelectorAll('form').forEach(f => {
                    const fields = [];
                    f.querySelectorAll('input, select, textarea').forEach(el => {
                      const t = (el.type || el.tagName).toLowerCase();
                      if (['submit','button','hidden','image'].includes(t)) return;
                      fields.push({name: el.name || el.id || '', type: t,
                                   placeholder: el.placeholder || '', id: el.id || ''});
                    });
                    forms.push({action: f.action || '', method: (f.method || 'GET').toUpperCase(), fields});
                  });
                  const text = (document.body ? document.body.innerText : '').slice(0, 4000).toLowerCase();
                  const html = document.documentElement.innerHTML.toLowerCase();
                  return {forms, text,
                          captcha: html.includes('captcha') || html.includes('recaptcha') || html.includes('hcaptcha'),
                          password: !!document.querySelector('input[type=password]')};
                }""")
                result["forms"] = data.get("forms", [])[:3]
                text = data.get("text", "")
                if any(m in text for m in CHALLENGE_MARKERS) or "just a moment" in result["title"].lower():
                    result["challenge"] = True
                    result["blockers"].append("Bot-check / CAPTCHA challenge page — a human must pass this in a real browser session")
                if data.get("captcha") and not result["challenge"]:
                    result["blockers"].append("CAPTCHA widget on the form — human step required at submit")
                if data.get("password"):
                    result["blockers"].append("Asks for account login — removal must be done signed in")
                if not result["forms"] and not result["challenge"]:
                    result["blockers"].append("Page loaded in a browser but no form was found — the opt-out may start from a search/listing page")
            except Exception as e:
                result["blockers"].append(f"Browser could not load the page ({type(e).__name__}) — site may block this network or be down")
            finally:
                browser.close()
    except Exception as e:
        result["blockers"].append(f"Browser launch failed ({type(e).__name__})")
    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: browser_probe.py <url>"}))
        sys.exit(1)
    print(json.dumps(probe(sys.argv[1])))
