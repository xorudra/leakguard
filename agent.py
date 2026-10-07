#!/usr/bin/env python3
"""
LeakGuard Agent Mode — ZERO-TOKEN removal engine.

No LLM is used anywhere in the default path:
  * Search / plan   — deterministic templates from playbooks.json + brokers.json
  * Form discovery  — plain HTTP fetch + stdlib html.parser; extracts the real
                      form fields, action and blockers (CAPTCHA / login / JS)
                      from the broker's live opt-out page
  * Form filling    — builds the exact POST payload for simple HTML forms and
                      can submit it (guarded: only with submit=True, i.e. the
                      user's explicit per-run action in the GUI)
  * Tracking        — statuses live in the browser (same tracker as v1)

Optional free-lane fallback (OFF unless configured): if a probed page has a
form whose fields cannot be matched to the profile, LeakGuard may ask the
user's OWN free gateway (FreeLLMAPI, env LEAKGUARD_FREE_LANE_URL +
LEAKGUARD_FREE_LANE_KEY + LEAKGUARD_FREE_LANE_MODEL) to classify the fields.
That call goes to free-tier providers the user already runs — it never uses
Claude / Muse tokens. If the gateway is unreachable, the fallback silently
stays off and the script path continues.
"""

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

BASE = Path(__file__).resolve().parent
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126 Safari/537.36 LeakGuard/2.0"}

PROFILE_FIELDS = {
    # semantic field -> regexes matched against input name/id/placeholder/label
    "full_name": [r"full.?name", r"^name$", r"_name$", r"first.?name", r"your.?name"],
    "email": [r"e-?mail"],
    "phone": [r"phone", r"mobile", r"tel"],
    "city": [r"city", r"location", r"address"],
    "listing_url": [r"url", r"listing", r"profile.?link", r"record"],
}


def load_json(name, default):
    try:
        return json.loads((BASE / name).read_text(encoding="utf-8"))
    except Exception:
        return default


def load_brokers():
    return load_json("brokers.json", [])


def load_playbooks():
    data = load_json("playbooks.json", {})
    return data if isinstance(data, dict) else {}


def get_playbook(broker):
    """Playbook for a broker; generic one derived from brokers.json if unmapped."""
    pbs = load_playbooks()
    if broker["name"] in pbs:
        pb = dict(pbs[broker["name"]])
    else:
        pb = {
            "automation": "http_form",
            "needs": ["email_confirm"],
            "flow": [
                "Open the opt-out page",
                "Search your name / paste your listing URL if asked",
                "Fill your name and email",
                "Submit and confirm from the email they send you",
            ],
            "notes": "Generic flow — this broker has no hand-mapped playbook yet.",
        }
    pb["broker"] = broker["name"]
    pb["optout_url"] = broker["optout_url"]
    return pb


def build_plan(profile):
    """Deterministic removal plan for a profile. Zero tokens, zero network."""
    plan = []
    for broker in load_brokers():
        pb = get_playbook(broker)
        plan.append({
            "broker": broker["name"],
            "type": broker["type"],
            "region": broker["region"],
            "optout_url": broker["optout_url"],
            "automation": pb["automation"],
            "needs": pb["needs"],
            "flow": pb["flow"],
            "notes": pb.get("notes", ""),
            "search_url": ("https://www.google.com/search?q=" +
                           urllib.parse.quote(f'"{profile.get("full_name","")}" site:{urllib.parse.urlparse(broker["optout_url"]).netloc}')),
        })
    return plan


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._form = None
        self.has_captcha = False
        self.has_password = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        blob = " ".join(str(v) for v in a.values()).lower()
        if "captcha" in blob or "recaptcha" in blob or "hcaptcha" in blob:
            self.has_captcha = True
        if tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(), "fields": []}
        elif tag in ("input", "select", "textarea") and self._form is not None:
            ftype = (a.get("type") or tag).lower()
            if ftype == "password":
                self.has_password = True
            if ftype not in ("submit", "button", "hidden", "image"):
                self._form["fields"].append({
                    "name": a.get("name") or a.get("id") or "",
                    "type": ftype,
                    "placeholder": a.get("placeholder") or "",
                    "id": a.get("id") or "",
                })

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def match_fields(form_fields, profile):
    """Map profile values onto form fields by name patterns. Returns payload + unmapped."""
    payload, unmapped = {}, []
    for field in form_fields:
        hay = " ".join([field.get("name", ""), field.get("id", ""), field.get("placeholder", "")]).lower()
        matched = None
        for semantic, patterns in PROFILE_FIELDS.items():
            if any(re.search(p, hay) for p in patterns):
                matched = semantic
                break
        if matched and profile.get(matched):
            if field["name"]:
                payload[field["name"]] = profile[matched]
        elif field["name"]:
            unmapped.append(field["name"])
    return payload, unmapped


def probe_broker(broker_name, profile=None):
    """Fetch the broker's live opt-out page and report what's really there.

    Returns dict:reachable, status, forms (with fields), blockers, payload preview.
    """
    profile = profile or {}
    brokers = {b["name"]: b for b in load_brokers()}
    broker = brokers.get(broker_name)
    if not broker:
        return {"broker": broker_name, "error": "Unknown broker"}
    pb = get_playbook(broker)
    url = broker["optout_url"]
    result = {"broker": broker_name, "url": url, "automation": pb["automation"],
              "needs": pb["needs"], "reachable": False, "status": None,
              "forms": [], "blockers": [], "payload_preview": {}}
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result["status"] = resp.status
            result["reachable"] = True
            html = resp.read(512 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        result["blockers"].append(f"Site answered HTTP {e.code} to a script (bot protection or moved page) — use a real browser for this one")
        return result
    except Exception:
        result["blockers"].append("Page unreachable from this server right now")
        return result
    parser = FormParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    if parser.has_captcha:
        result["blockers"].append("CAPTCHA on the page — a human must solve this step")
    if parser.has_password:
        result["blockers"].append("Asks for account login — removal must be done signed in")
    if not parser.forms:
        result["blockers"].append("No plain HTML form found — the form is built by JavaScript; use a real browser for this one")
    for form in parser.forms[:3]:
        payload, unmapped = match_fields(form["fields"], profile)
        result["forms"].append({
            "action": urllib.parse.urljoin(url, form["action"]) if form["action"] else url,
            "method": form["method"],
            "fields": form["fields"],
            "unmapped_fields": unmapped,
        })
        if payload:
            result["payload_preview"] = payload
    result["fillable"] = bool(result["payload_preview"]) and not parser.has_captcha
    return result


RELAY_READER = "https://api.allorigins.win/raw?url={url}"


def relay_probe(url, profile=None):
    """Fetch a page through a public relay reader (a different network than
    this server). Some brokers let the relay through when they 403 the
    server directly (measured: Whitepages). Cloudflare-hardened sites
    challenge the relay too (measured: BeenVerified) — that is reported,
    not hidden. Read-only: forms found here are for inspection/pre-fill;
    submission never goes through a third-party relay."""
    profile = profile or {}
    out = {"via": "relay", "reachable": False, "status": None, "forms": [],
           "blockers": [], "challenge": False, "payload_preview": {}}
    relay_url = RELAY_READER.format(url=urllib.parse.quote(url, safe=""))
    html = None
    # The free relay is intermittent (measured 522s between successes) —
    # retry a few times with backoff before declaring it unreachable.
    import time
    for attempt in range(3):
        req = urllib.request.Request(relay_url, headers=UA)
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                out["status"] = resp.status
                html = resp.read(1024 * 1024).decode("utf-8", "replace")
            break
        except Exception:
            if attempt < 2:
                time.sleep(3 * (attempt + 1))
    if html is None:
        out["blockers"].append("Relay reader could not fetch the page either (free relay is intermittent — retrying the probe often works)")
        return out
    low = html.lower()
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
    out["title"] = title
    if "just a moment" in low[:3000] or "checking your browser" in low[:3000]:
        out["challenge"] = True
        out["blockers"].append("Cloudflare challenge page even via the relay reader — this site only talks to real residential browsers; use the local runner on your own device")
        return out
    out["reachable"] = True
    parser = FormParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    if parser.has_captcha:
        out["blockers"].append("CAPTCHA on the page — a human must solve this step")
    for form in parser.forms[:3]:
        payload, unmapped = match_fields(form["fields"], profile)
        out["forms"].append({
            "action": urllib.parse.urljoin(url, form["action"]) if form["action"] else url,
            "method": form["method"],
            "fields": form["fields"],
            "unmapped_fields": unmapped,
        })
        if payload and not out["payload_preview"]:
            out["payload_preview"] = payload
    if not out["forms"]:
        out["blockers"].append("Relay fetched the page but found no readable form (the form may need JavaScript / a listing search first)")
    return out


def browser_probe(url, timeout=70):
    """Run browser_probe.py in a subprocess (a hung page can never hang the
    server). Returns its dict, or None if the browser layer is unavailable."""
    import subprocess
    script = BASE / "browser_probe.py"
    if not script.exists() or os.environ.get("LEAKGUARD_NO_BROWSER") == "1":
        return None
    try:
        out = subprocess.run(
            ["python3", str(script), url],
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ})
        data = json.loads(out.stdout.strip().splitlines()[-1])
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def probe_with_browser_fallback(broker_name, profile=None):
    """Deep probe chain: HTTP -> relay reader -> real browser.
    Each layer runs only if the previous one could not produce a usable
    form, and every layer's outcome is reported honestly."""
    result = probe_broker(broker_name, profile)
    if result.get("error"):
        return result
    result["via"] = "http"
    # --- layer 2: relay reader (different network) ---
    if not result.get("fillable"):
        relay = relay_probe(result["url"], profile)
        result["relay"] = {"reachable": relay["reachable"], "challenge": relay["challenge"],
                           "status": relay["status"], "title": relay.get("title", "")}
        if relay["reachable"] and relay["forms"]:
            result["via"] = "http+relay"
            result["reachable"] = True
            result["status"] = result.get("status") or relay["status"]
            result["forms"] = relay["forms"]
            if relay["payload_preview"]:
                result["payload_preview"] = relay["payload_preview"]
            result["blockers"] = relay["blockers"]
            result["fillable"] = bool(result["payload_preview"]) and not relay["challenge"]
            if result["fillable"]:
                return result
        else:
            result["blockers"] = list(dict.fromkeys(result.get("blockers", []) + relay["blockers"]))
    # --- layer 3: real browser ---
    b = browser_probe(result["url"])
    if not b:
        result["browser"] = {"available": False}
        return result
    result["browser"] = {"available": True, "reachable": b.get("reachable"),
                         "status": b.get("status"), "title": b.get("title"),
                         "challenge": b.get("challenge")}
    result["via"] = result.get("via", "http") + "+browser"
    if b.get("reachable"):
        result["reachable"] = True
        result["status"] = b.get("status") or result.get("status")
        bforms = []
        for form in b.get("forms", []):
            payload, unmapped = match_fields(form.get("fields", []), profile or {})
            bforms.append({
                "action": form.get("action") or result["url"],
                "method": form.get("method", "GET"),
                "fields": form.get("fields", []),
                "unmapped_fields": unmapped,
            })
            if payload and not result.get("payload_preview"):
                result["payload_preview"] = payload
        if bforms:
            result["forms"] = bforms
        # Browser blockers are the ground truth when the page rendered —
        # UNLESS an earlier layer already got a usable page (e.g. relay):
        # then the browser result is only a secondary note.
        http_blockers = result.get("blockers", [])
        rendered = bool(b.get("forms")) or b.get("challenge")
        if rendered and not (result.get("reachable") and result.get("forms")):
            result["blockers"] = b.get("blockers", [])
        elif rendered:
            result["blockers"] = list(dict.fromkeys(
                http_blockers + ["Browser layer: " + x for x in b.get("blockers", [])]))
        else:
            result["blockers"] = list(dict.fromkeys(http_blockers + b.get("blockers", [])))
        result["fillable"] = bool(result.get("payload_preview")) and not b.get("challenge") \
            and not any("CAPTCHA" in x for x in result.get("blockers", []))
    else:
        result["blockers"] = list(dict.fromkeys(result.get("blockers", []) + b.get("blockers", [])))
    return result


def submit_form(form_action, method, payload, timeout=15):
    """Submit a prepared payload. Only called behind the GUI's explicit
    per-broker 'Submit' action — never automatically."""
    data = urllib.parse.urlencode(payload).encode("utf-8")
    if method == "GET":
        url = form_action + ("&" if "?" in form_action else "?") + data.decode("utf-8")
        req = urllib.request.Request(url, headers=UA)
    else:
        req = urllib.request.Request(form_action, data=data, headers=UA, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"ok": True, "status": resp.status}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code}
    except Exception:
        return {"ok": False, "status": None}


# ---------- optional free-lane fallback (user's own gateway, never Claude) ----------
def free_lane_status():
    url = os.environ.get("LEAKGUARD_FREE_LANE_URL", "").rstrip("/")
    if not url:
        return {"configured": False, "reachable": False}
    try:
        req = urllib.request.Request(url.replace("/v1", "") + "/api/ping", headers=UA)
        with urllib.request.urlopen(req, timeout=4) as resp:
            return {"configured": True, "reachable": resp.status == 200}
    except Exception:
        return {"configured": True, "reachable": False}


def free_lane_classify(fields, profile_keys):
    """Ask the user's free gateway which form field means what.
    Returns {field_name: semantic} or None. Only used when script matching fails."""
    base = os.environ.get("LEAKGUARD_FREE_LANE_URL", "").rstrip("/")
    key = os.environ.get("LEAKGUARD_FREE_LANE_KEY", "")
    model = os.environ.get("LEAKGUARD_FREE_LANE_MODEL", "")
    if not base or not key or not model:
        return None
    prompt = ("Map each form field to one of: " + ", ".join(profile_keys) + ", ignore. "
              "Answer with the JSON object only, no analysis. "
              "JSON like {\"field\":\"semantic\"}. Fields: " + json.dumps(fields))
    # Reasoning models on the free lanes spend part of the budget thinking;
    # 200 tokens was measured to truncate before the JSON (finish=length).
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": 900}).encode("utf-8")
    req = urllib.request.Request(base + "/chat/completions", data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + key})
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        text = data["choices"][0]["message"]["content"] or ""
        return _extract_mapping(text)
    except Exception:
        return None


def _extract_mapping(text):
    """Pull the field->semantic JSON object out of a model reply, even when a
    reasoning model wrapped it in analysis. Tries the last '{' first."""
    starts = [i for i, ch in enumerate(text) if ch == "{"]
    for start in reversed(starts):
        depth = 0
        for end in range(start, len(text)):
            if text[end] == "{":
                depth += 1
            elif text[end] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start:end + 1])
                    except Exception:
                        break
                    if isinstance(obj, dict) and obj:
                        return obj
                    break
    return None
