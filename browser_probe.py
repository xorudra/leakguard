#!/usr/bin/env python3
"""
LeakGuard browser probe — the layer for opt-out pages that block plain HTTP
scripts (403 / JavaScript walls). Uses Playwright driving a real Chromium.
Still zero tokens: it's a browser, not an AI.

Run standalone (used by agent.py via subprocess so a hung page can never
hang the web server):

    python3 browser_probe.py <url>

Prints one JSON object:
  {via, reachable, status, title, forms[], blockers[], challenge}
Proxy is taken from the standard http_proxy/https_proxy environment
(credentials are used, never printed).
"""

import json
import os
import sys
import urllib.parse

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
              "forms": [], "blockers": [], "challenge": False}
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
            page = context.new_page()
            try:
                resp = page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
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
