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
    "full_name": [r"full.?name", r"^name$", r"first.?name", r"your.?name"],
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
              "Reply ONLY with JSON like {\"field\":\"semantic\"}. Fields: " + json.dumps(fields))
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": 200}).encode("utf-8")
    req = urllib.request.Request(base + "/chat/completions", data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + key})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        text = data["choices"][0]["message"]["content"]
        return json.loads(text[text.index("{"):text.rindex("}") + 1])
    except Exception:
        return None
