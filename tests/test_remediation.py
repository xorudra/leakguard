"""Remediation engine tests (Stage S7 — spec Phases 30–39, 153–157,
162, 167).

Layers:

* TestSlugifyChannel — offline: slug derivation + the documented
  channel rule (contact_email -> email, fillable playbook -> form,
  else manual).
* TestLetters — offline: the server-side letter port carries the
  same laws/citations/asks as the anonymous generator.
* TestInterpretProbe — offline: the probe -> transition matrix
  (CAPTCHA/login are human steps, never bypassed; walls block;
  missing profile fields name the field).
* TestRemediationUnavailable — no database: remediation routes
  answer the same 503 as every other account route, and
  /api/brokers still serves the file shape.
* TestRemediationDb — the full flow against a local PostgreSQL
  (pgserver, skips honestly when unavailable): registry seeding,
  the consent gate, idempotent case creation, the worker transition
  matrix with a stub executor, consent withdrawal mid-queue,
  verification + reappearance, retry rules, the human queue, IDOR.

Run:  python3 -m unittest discover -s tests
"""

import base64
import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402
from accounts import ratelimit  # noqa: E402
from remediation import engine as engine_mod  # noqa: E402
from remediation import letters, registry_seed  # noqa: E402
from remediation import verify as verify_mod  # noqa: E402
from remediation import worker as worker_mod  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")


class EnvGuard:
    def __init__(self, keys):
        self.keys = keys

    def __enter__(self):
        self.saved = {k: os.environ.get(k) for k in self.keys}
        for k in self.keys:
            os.environ.pop(k, None)
        return self

    def __exit__(self, *exc):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return False


class ServerMixin:
    @classmethod
    def start_server(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.port

    @classmethod
    def stop_server(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, body=None, cookie=None, headers=None):
        data = None
        hdrs = dict(headers or {})
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        if cookie:
            hdrs["Cookie"] = cookie
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=hdrs, method=method)
        try:
            with OPENER.open(req, timeout=15) as resp:
                return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def request_json(self, *args, **kwargs):
        status, headers, payload = self.request(*args, **kwargs)
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except Exception:
            parsed = None
        return status, headers, parsed

    @staticmethod
    def session_cookie(headers):
        raw = headers.get("Set-Cookie") or ""
        first = raw.split(";")[0].strip()
        return first if first.startswith("lg_session=") else None


# ---------------------------------------------------------------------------
# Offline: slugs + channel derivation
# ---------------------------------------------------------------------------

class TestSlugifyChannel(unittest.TestCase):
    def test_slugify(self):
        self.assertEqual(registry_seed.slugify("Spokeo"), "spokeo")
        self.assertEqual(registry_seed.slugify("Data Axle (InfoUSA)"),
                         "data-axle-infousa")
        self.assertEqual(
            registry_seed.slugify("LexisNexis Risk Solutions"),
            "lexisnexis-risk-solutions")
        self.assertEqual(registry_seed.slugify("Epsilon (Conversant)"),
                         "epsilon-conversant")

    def test_channel_rule(self):
        # 1. a published contact email wins over everything
        self.assertEqual(
            registry_seed.derive_channel(
                {"contact_email": "optout@example.com"},
                {"automation": "http_form"}),
            "email")
        # 2. a fillable playbook flow is a form channel
        self.assertEqual(
            registry_seed.derive_channel({}, {"automation": "http_form"}),
            "form")
        # 3. everything else is manual
        self.assertEqual(
            registry_seed.derive_channel(
                {}, {"automation": "browser_required"}), "manual")
        self.assertEqual(
            registry_seed.derive_channel(
                {}, {"automation": "email_request"}), "manual")
        self.assertEqual(registry_seed.derive_channel({}, None), "manual")


# ---------------------------------------------------------------------------
# Offline: letters
# ---------------------------------------------------------------------------

class TestLetters(unittest.TestCase):
    def test_dpdp_structure_matches_frontend(self):
        body = letters.make_letter("Spokeo", "Rudra Test",
                                   "rudra@example.com", "Pune")
        self.assertIn("Section 12 of India's Digital Personal Data "
                      "Protection Act, 2023", body)
        self.assertIn("erase my personal data", body)
        self.assertIn("Name:  Rudra Test", body)
        self.assertIn("Email: rudra@example.com", body)
        self.assertIn("Location: Pune", body)
        self.assertIn("suppression list", body)

    def test_gdpr_and_ccpa_citations(self):
        gdpr = letters.make_letter("X", "A B", "a@b.co", "Berlin",
                                   law="gdpr")
        self.assertIn("Article 17 of the General Data Protection "
                      "Regulation (GDPR)", gdpr)
        ccpa = letters.make_letter("X", "A B", "a@b.co", "Fresno",
                                   law="ccpa")
        self.assertIn("California Consumer Privacy Act (CCPA)", ccpa)
        self.assertIn("opt out of the sale", ccpa)

    def test_placeholders_when_profile_empty(self):
        body = letters.make_letter("X", "", "", "")
        self.assertIn("[Your full name]", body)
        self.assertIn("[Your email]", body)
        self.assertIn("[Your city, country]", body)

    def test_letter_for_broker(self):
        letter = letters.letter_for_broker(
            {"name": "BeenVerified",
             "contact_email": "optout@beenverified.com"},
            {"full_name": "Rudra Test", "email": "rudra@example.com",
             "phone": "", "city": "Pune"})
        self.assertEqual(letter["to"], "optout@beenverified.com")
        self.assertEqual(letter["subject"],
                         "Request for erasure of my personal data")
        self.assertIn("BeenVerified", letter["body"])
        self.assertIn("Rudra Test", letter["body"])


# ---------------------------------------------------------------------------
# Offline: probe interpretation
# ---------------------------------------------------------------------------

PROFILE = {"full_name": "A B", "email": "a@b.co", "phone": "",
           "city": "Pune"}


def _probe(**kw):
    base = {"reachable": True, "status": 200, "fillable": False,
            "forms": [], "blockers": [], "payload_preview": {}}
    base.update(kw)
    return base


class TestInterpretProbe(unittest.TestCase):
    def test_captcha_is_a_human_step(self):
        probe = _probe(blockers=["CAPTCHA on the page — a human must "
                                 "solve this step"])
        self.assertEqual(engine_mod.interpret_probe(probe, PROFILE),
                         ("needs_human", "captcha"))

    def test_login_is_a_human_step(self):
        probe = _probe(blockers=["Asks for account login — removal "
                                 "must be done signed in"])
        self.assertEqual(engine_mod.interpret_probe(probe, PROFILE),
                         ("needs_human", "login_required"))

    def test_walls_block(self):
        self.assertEqual(
            engine_mod.interpret_probe(
                _probe(reachable=False, status=403), PROFILE),
            ("blocked", "http_403"))
        self.assertEqual(
            engine_mod.interpret_probe(
                _probe(reachable=False, status=None), PROFILE),
            ("blocked", "unreachable"))
        self.assertEqual(
            engine_mod.interpret_probe({"error": "Unknown broker"},
                                       PROFILE),
            ("blocked", "probe_error"))

    # Phase 137 — precedence pins: human-step evidence is checked
    # BEFORE the fillable shortcut, so a page that is somehow both
    # fillable AND walled still routes to a human, never a submit.
    def test_captcha_beats_fillable(self):
        probe = _probe(fillable=True,
                       payload_preview={"email": "a@b.co"},
                       blockers=["CAPTCHA on the page — a human "
                                 "must solve this step"])
        self.assertEqual(engine_mod.interpret_probe(probe, PROFILE),
                         ("needs_human", "captcha"))

    def test_login_wall_beats_fillable(self):
        probe = _probe(fillable=True,
                       payload_preview={"email": "a@b.co"},
                       blockers=["Password field on the form — this "
                                 "broker requires an account login "
                                 "to proceed"])
        self.assertEqual(engine_mod.interpret_probe(probe, PROFILE),
                         ("needs_human", "login_required"))

    def test_http_500_reason(self):
        self.assertEqual(
            engine_mod.interpret_probe(
                _probe(reachable=False, status=500), PROFILE),
            ("blocked", "http_500"))

    def test_garbage_probe_is_probe_error(self):
        self.assertEqual(engine_mod.interpret_probe(None, PROFILE),
                         ("blocked", "probe_error"))
        self.assertEqual(
            engine_mod.interpret_probe("not-a-probe", PROFILE),
            ("blocked", "probe_error"))

    def test_fillable_submits(self):
        probe = _probe(fillable=True, payload_preview={"email": "a@b.co"})
        self.assertEqual(engine_mod.interpret_probe(probe, PROFILE),
                         ("submit", None))

    def test_js_only_form_needs_a_browser(self):
        probe = _probe(blockers=["No plain HTML form found — the form "
                                 "is built by JavaScript"])
        self.assertEqual(engine_mod.interpret_probe(probe, PROFILE),
                         ("needs_human", "browser_required"))

    def test_missing_field_names_the_field(self):
        form = {"action": "https://broker.example/optout",
                "method": "POST",
                "fields": [{"name": "phone", "id": "",
                            "placeholder": "", "type": "tel"}],
                "unmapped_fields": ["phone"]}
        probe = _probe(forms=[form])
        self.assertEqual(engine_mod.interpret_probe(probe, PROFILE),
                         ("needs_human", "missing_field:phone"))

    def test_unmappable_form_blocks(self):
        form = {"action": "https://broker.example/optout",
                "method": "POST",
                "fields": [{"name": "xyz", "id": "",
                            "placeholder": "", "type": "text"}],
                "unmapped_fields": ["xyz"]}
        probe = _probe(forms=[form])
        self.assertEqual(engine_mod.interpret_probe(probe, PROFILE),
                         ("blocked", "form_not_fillable"))


# ---------------------------------------------------------------------------
# Offline: Stage 7.1 executor probe strategy (staged + budgeted)
# ---------------------------------------------------------------------------

def _fast_probe(**kw):
    base = {"broker": "Spokeo", "url": "https://www.spokeo.com/optout",
            "automation": "http_form", "needs": [], "reachable": False,
            "status": None, "forms": [], "blockers": [],
            "payload_preview": {}, "fillable": False}
    base.update(kw)
    return base


_RELAY_FORM = [{
    "action": "https://www.spokeo.com/optout", "method": "POST",
    "fields": [{"name": "email", "type": "email", "id": "",
                "placeholder": ""}],
    "unmapped_fields": [],
}]

_FILLABLE_RELAY = {"via": "relay", "reachable": True, "status": 200,
                   "forms": _RELAY_FORM, "challenge": False,
                   "payload_preview": {"email": "a@b.co"},
                   "blockers": [], "title": ""}


class TestAgentExecutorProbeStrategy(unittest.TestCase):
    """The remediation executor's staged probe: fast first, ONE
    relay escalation only when the fast probe is inconclusive, the
    browser step never attempted from the server, and a soft budget
    that abandons a hung relay and classifies from the best evidence
    via the unchanged interpret_probe. Stage 7.2 gate: a fast probe
    that received a page (HTTP 200) is conclusive even with no form —
    only no-page results (transport failure, HTTP error page) still
    escalate, exactly once."""

    def setUp(self):
        self.agent = engine_mod.agent_engine
        self._saved = {
            name: getattr(self.agent, name)
            for name in ("probe_broker", "relay_probe", "browser_probe",
                         "probe_with_browser_fallback")
        }
        self.browser_calls = []
        self.agent.browser_probe = (
            lambda url: self.browser_calls.append(url))

        def _no_fallback(*args, **kwargs):
            raise AssertionError("the full fallback chain must not run")
        self.agent.probe_with_browser_fallback = _no_fallback

    def tearDown(self):
        for name, fn in self._saved.items():
            setattr(self.agent, name, fn)

    def _executor(self, fast, relay, budget=30.0):
        calls = {"relay": []}
        self.agent.probe_broker = lambda name, profile=None: dict(fast)

        def _relay(url, profile=None):
            calls["relay"].append(url)
            return relay(url, profile) if callable(relay) else relay
        self.agent.relay_probe = _relay
        executor = engine_mod.AgentExecutor(probe_budget_seconds=budget)
        return executor, calls

    def test_fillable_fast_probe_never_escalates(self):
        executor, calls = self._executor(
            _fast_probe(reachable=True, status=200, fillable=True,
                        forms=FILLABLE_FORM,
                        payload_preview={"email": "a@b.co"}),
            relay=_FILLABLE_RELAY)
        result = executor.probe(PROFILE, {"name": "Spokeo"})
        self.assertTrue(result["fillable"])
        self.assertEqual(calls["relay"], [])
        self.assertEqual([t["step"] for t in result["probe_trail"]],
                         ["http"])
        self.assertEqual(self.browser_calls, [])

    def test_captcha_fast_probe_never_escalates(self):
        executor, calls = self._executor(
            _fast_probe(reachable=True, status=200,
                        blockers=["CAPTCHA on the page — a human must "
                                  "solve this step"]),
            relay=_FILLABLE_RELAY)
        result = executor.probe(PROFILE, {"name": "Spokeo"})
        self.assertEqual(calls["relay"], [])
        self.assertEqual(engine_mod.interpret_probe(result, PROFILE),
                         ("needs_human", "captcha"))

    def test_form_found_fast_probe_never_escalates(self):
        form = {"action": "https://www.spokeo.com/optout",
                "method": "POST",
                "fields": [{"name": "xyz", "id": "", "placeholder": "",
                            "type": "text"}],
                "unmapped_fields": ["xyz"]}
        executor, calls = self._executor(
            _fast_probe(reachable=True, status=200, forms=[form]),
            relay=_FILLABLE_RELAY)
        result = executor.probe(PROFILE, {"name": "Spokeo"})
        self.assertEqual(calls["relay"], [])
        self.assertEqual(engine_mod.interpret_probe(result, PROFILE),
                         ("blocked", "form_not_fillable"))

    def test_page_received_without_form_never_escalates(self):
        # Stage 7.2 gate: most brokers answer HTTP 200 with a
        # JS-driven page and no plain HTML form. That result is
        # conclusive — the relay reader fetches the same markup — so
        # even a relay that WOULD have found a form is never called,
        # the case classifies through the existing transitions, and
        # the trail records why no relay was tried.
        executor, calls = self._executor(
            _fast_probe(reachable=True, status=200,
                        blockers=["No plain HTML form found — the form "
                                  "is built by JavaScript; use a real "
                                  "browser for this one"]),
            relay=_FILLABLE_RELAY)
        result = executor.probe(PROFILE, {"name": "Spokeo"})
        self.assertEqual(calls["relay"], [])
        self.assertEqual(engine_mod.interpret_probe(result, PROFILE),
                         ("needs_human", "browser_required"))
        trail = {t["step"]: t for t in result["probe_trail"]}
        self.assertEqual(trail["relay"]["skipped"], "page_received")
        self.assertEqual(self.browser_calls, [])

    def test_error_page_still_escalates_once(self):
        # The gate closes only on a RECEIVED page: an HTTP error
        # page (403 wall) still gets its one relay escalation, which
        # can un-wall it via the reader and reach a fillable form.
        executor, calls = self._executor(
            _fast_probe(status=403,
                        blockers=["Site answered HTTP 403 to a script "
                                  "(bot protection or moved page)"]),
            relay=_FILLABLE_RELAY)
        result = executor.probe(PROFILE, {"name": "Spokeo"})
        self.assertEqual(calls["relay"],
                         ["https://www.spokeo.com/optout"])
        self.assertEqual(result["via"], "http+relay")
        self.assertEqual(engine_mod.interpret_probe(result, PROFILE),
                         ("submit", None))
        self.assertEqual(self.browser_calls, [])

    def test_stage72_defaults(self):
        # Probe budget lowered 50s -> 40s; the worker drains 5-wide
        # (probes are I/O-bound; SKIP LOCKED claims still guarantee
        # no case executes twice).
        self.assertEqual(
            engine_mod.AgentExecutor().probe_budget_seconds, 40.0)
        self.assertEqual(worker_mod.MAX_CONCURRENT, 5)

    def test_hung_relay_is_abandoned_at_budget_unreachable(self):
        def hang(url, profile=None):
            time.sleep(10)
            return _FILLABLE_RELAY
        executor, calls = self._executor(
            _fast_probe(blockers=["Page unreachable from this server "
                                  "right now"]),
            relay=hang, budget=0.3)
        started = time.monotonic()
        result = executor.probe(PROFILE, {"name": "Spokeo"})
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 3.0)  # the 10s hang was abandoned
        self.assertEqual(len(calls["relay"]), 1)
        # Best evidence wins: persistent unreachability is still
        # blocked/unreachable via the unchanged transitions.
        self.assertEqual(engine_mod.interpret_probe(result, PROFILE),
                         ("blocked", "unreachable"))
        trail = {t["step"]: t for t in result["probe_trail"]}
        self.assertEqual(trail["relay"]["outcome"], "budget_exceeded")
        self.assertEqual(trail["browser"]["skipped"], "on_server")
        self.assertEqual(self.browser_calls, [])

    def test_hung_relay_keeps_the_403_classification(self):
        def hang(url, profile=None):
            time.sleep(10)
            return _FILLABLE_RELAY
        executor, calls = self._executor(
            _fast_probe(status=403,
                        blockers=["Site answered HTTP 403 to a script "
                                  "(bot protection or moved page)"]),
            relay=hang, budget=0.3)
        result = executor.probe(PROFILE, {"name": "Spokeo"})
        self.assertEqual(len(calls["relay"]), 1)
        # A 403 seen at any point is still blocked/http_403.
        self.assertEqual(engine_mod.interpret_probe(result, PROFILE),
                         ("blocked", "http_403"))

    def test_budget_spent_means_no_relay_attempt(self):
        executor, calls = self._executor(
            _fast_probe(blockers=["Page unreachable from this server "
                                  "right now"]),
            relay=_FILLABLE_RELAY, budget=0.0)
        result = executor.probe(PROFILE, {"name": "Spokeo"})
        self.assertEqual(calls["relay"], [])
        trail = {t["step"]: t for t in result["probe_trail"]}
        self.assertEqual(trail["relay"]["skipped"], "probe_budget")
        self.assertEqual(trail["browser"]["skipped"], "on_server")
        self.assertEqual(engine_mod.interpret_probe(result, PROFILE),
                         ("blocked", "unreachable"))

    def test_relay_challenge_keeps_fast_probe_evidence(self):
        relay = {"via": "relay", "reachable": False, "status": None,
                 "forms": [], "challenge": True, "payload_preview": {},
                 "blockers": ["Cloudflare challenge page even via the "
                              "relay reader — this site only talks to "
                              "real residential browsers"],
                 "title": ""}
        executor, calls = self._executor(
            _fast_probe(status=403,
                        blockers=["Site answered HTTP 403 to a script "
                                  "(bot protection or moved page)"]),
            relay=relay)
        result = executor.probe(PROFILE, {"name": "Spokeo"})
        self.assertEqual(len(calls["relay"]), 1)
        self.assertFalse(result["fillable"])
        self.assertEqual(engine_mod.interpret_probe(result, PROFILE),
                         ("blocked", "http_403"))

    def test_relay_fillable_form_escalates_to_submit(self):
        executor, calls = self._executor(
            _fast_probe(blockers=["Page unreachable from this server "
                                  "right now"]),
            relay=_FILLABLE_RELAY)
        result = executor.probe(PROFILE, {"name": "Spokeo"})
        self.assertEqual(calls["relay"], ["https://www.spokeo.com/optout"])
        self.assertTrue(result["fillable"])
        self.assertEqual(result["via"], "http+relay")
        self.assertEqual(engine_mod.interpret_probe(result, PROFILE),
                         ("submit", None))
        steps = [t["step"] for t in result["probe_trail"]]
        self.assertEqual(steps, ["http", "relay", "browser"])
        self.assertEqual(result["probe_trail"][2]["skipped"], "on_server")
        self.assertEqual(self.browser_calls, [])


# ---------------------------------------------------------------------------
# No database: clean 503s, file-backed brokers
# ---------------------------------------------------------------------------

class TestRemediationUnavailable(ServerMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._env = EnvGuard(ENV_KEYS).__enter__()
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls._env.__exit__()

    def test_run_is_503_like_other_account_routes(self):
        status, _h, body = self.request_json(
            "POST", "/api/remediation/run", body={}, headers=CSRF)
        self.assertEqual(status, 503, body)

    def test_run_without_csrf_is_403(self):
        status, _h, body = self.request_json(
            "POST", "/api/remediation/run", body={})
        self.assertEqual(status, 403, body)
        self.assertEqual(body["error"]["code"], "csrf_failed")

    def test_cases_and_queue_are_503(self):
        for path in ("/api/remediation/cases", "/api/remediation/queue"):
            status, _h, _b = self.request_json("GET", path)
            self.assertEqual(status, 503, path)

    def test_brokers_fall_back_to_file(self):
        status, _h, body = self.request_json("GET", "/api/brokers")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["brokers"]), 40)


# ---------------------------------------------------------------------------
# Full flow against a local PostgreSQL (pgserver) + stub executor
# ---------------------------------------------------------------------------

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None

FILLABLE_FORM = [{
    "action": "https://www.spokeo.com/optout", "method": "POST",
    "fields": [{"name": "email", "type": "email", "id": "",
                "placeholder": ""}],
    "unmapped_fields": [],
}]


class StubExecutor:
    """Deterministic executor: fillable 200-submit by default, with
    per-broker overrides. Records calls per (broker, profile email)
    so assertions never leak across users."""

    def __init__(self):
        self.probe_by_broker = {}
        self.submit_by_broker = {}
        self.verify_by_broker = {}
        self.submit_calls = []
        self.probe_calls = []

    def probe(self, profile, broker):
        self.probe_calls.append((broker["name"], profile.get("email")))
        if broker["name"] in self.probe_by_broker:
            return self.probe_by_broker[broker["name"]]
        return {"reachable": True, "status": 200, "fillable": True,
                "forms": FILLABLE_FORM, "blockers": [],
                "payload_preview": {"email": profile.get("email", "")},
                "via": "stub"}

    def submit(self, profile, broker, probe):
        self.submit_calls.append((broker["name"], profile.get("email")))
        return self.submit_by_broker.get(
            broker["name"], {"ok": True, "status": 200})

    def verify_search(self, profile, broker):
        return {"outcome": self.verify_by_broker.get(
            broker["name"], "unknown"), "evidence_ref": "stub://search"}

    def submits_for(self, email, broker=None):
        return [b for (b, e) in self.submit_calls
                if e == email and (broker is None or b == broker)]


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestRemediationDb(ServerMixin, unittest.TestCase):
    PASSWORD = "test-password-123"

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._env = EnvGuard.__new__(EnvGuard)
        cls._env.keys = ENV_KEYS
        cls._env.saved = {k: os.environ.get(k) for k in ENV_KEYS}
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-remediation-pg-")
        try:
            cls._pg = _pgserver.get_server(cls._pg_dir)
        except Exception:
            raise unittest.SkipTest("pgserver could not start PostgreSQL")
        os.environ["DATABASE_URL"] = cls._pg.get_uri()
        os.environ["VAULT_MASTER_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        os.environ["VAULT_LOOKUP_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        from db import migrate, pool

        cls.pool = pool
        pool.reset_probe_cache()
        if not pool.db_available():
            cls._teardown_pg()
            raise unittest.SkipTest("local PostgreSQL not reachable")
        migrate.run_migrations()
        cls.seeded = registry_seed.seed_brokers()
        cls.start_server()

    @classmethod
    def _teardown_pg(cls):
        try:
            cls._pg.cleanup()
        except Exception:
            pass
        import shutil

        shutil.rmtree(cls._pg_dir, ignore_errors=True)
        for k, v in cls._env.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls.pool.reset_probe_cache()
        cls._teardown_pg()

    def setUp(self):
        ratelimit.reset()

    # ---------- helpers ----------
    def uniq(self):
        return uuid.uuid4().hex[:12]

    def register(self):
        email = "rem-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": self.PASSWORD, "policy_accepted": True},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"], email

    def add_identifier(self, cookie, kind, value):
        status, _h, body = self.request_json(
            "POST", "/api/identifiers",
            body={"kind": kind, "value": value},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        return body["identifier"]

    def add_full_profile(self, cookie, tag):
        name = "Test Person %s" % tag
        email = "person-%s@example.com" % tag
        self.add_identifier(cookie, "name", name)
        self.add_identifier(cookie, "email", email)
        self.add_identifier(cookie, "address",
                            "%s Test Street, Pune, India" % tag)
        return name, email

    def set_consent(self, cookie, purpose, granted):
        status, _h, body = self.request_json(
            "POST", "/api/consents",
            body={"purpose": purpose, "granted": granted},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)

    def run_removal(self, cookie):
        return self.request_json("POST", "/api/remediation/run",
                                 body={}, headers=CSRF, cookie=cookie)

    def list_cases(self, cookie):
        status, _h, body = self.request_json(
            "GET", "/api/remediation/cases", cookie=cookie)
        self.assertEqual(status, 200, body)
        return body["cases"]

    def case_for(self, cookie, broker_name):
        for case in self.list_cases(cookie):
            if case["broker_name"] == broker_name:
                return case
        self.fail("no case for %s" % broker_name)

    def drain(self, stub):
        worked = 0
        while worked < 500 and worker_mod.run_once(stub):
            worked += 1
        return worked

    def db_row(self, sql, params):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchone()

    # ---------- seeding ----------
    def test_seeding_40_idempotent_channels(self):
        self.assertEqual(self.seeded, 40)
        self.assertEqual(registry_seed.seed_brokers(), 40)  # again
        row = self.db_row("SELECT COUNT(*) AS n FROM brokers", ())
        self.assertEqual(row["n"], 40)
        bv = self.db_row("SELECT channel FROM brokers"
                         " WHERE slug = 'beenverified'", ())
        self.assertEqual(bv["channel"], "email")
        sp = self.db_row("SELECT channel FROM brokers"
                         " WHERE slug = 'spokeo'", ())
        self.assertEqual(sp["channel"], "form")
        wp = self.db_row("SELECT channel FROM brokers"
                         " WHERE slug = 'whitepages'", ())
        # Whitepages gained its published opt-out email
        # (support@whitepages.com, its own privacy policy) in the
        # 2026-10-08 email-coverage pass: manual -> email.
        self.assertEqual(wp["channel"], "email")

    def test_brokers_db_shape_matches_file(self):
        status, _h, body = self.request_json("GET", "/api/brokers")
        self.assertEqual(status, 200)
        file_brokers = json.loads(
            (Path(__file__).resolve().parent.parent
             / "brokers.json").read_text(encoding="utf-8"))
        self.assertEqual(body["brokers"], file_brokers)

    # ---------- the one command ----------
    def test_run_consent_gate_and_idempotent_creation(self):
        cookie, _uid, email = self.register()
        self.add_full_profile(cookie, self.uniq())
        # No consent yet -> 403 consent_required, no cases.
        status, _h, body = self.run_removal(cookie)
        self.assertEqual(status, 403, body)
        self.assertEqual(body["error"]["code"], "consent_required")
        self.assertEqual(self.list_cases(cookie), [])
        # Grant -> one case per broker.
        self.set_consent(cookie, "automated_remediation", True)
        status, _h, body = self.run_removal(cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["cases_created"], 40)
        self.assertEqual(body["cases_total"], 40)
        self.assertEqual(body["by_status"], {"queued": 40})
        # Re-run: nothing new, nothing duplicated.
        status, _h, body = self.run_removal(cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["cases_created"], 0)
        self.assertEqual(body["cases_total"], 40)
        ids = [c["id"] for c in self.list_cases(cookie)]
        self.assertEqual(len(set(ids)), 40)
        # Clean the queue up for other tests.
        self.drain(StubExecutor())

    # ---------- worker transitions ----------
    def test_worker_transition_matrix(self):
        cookie, _uid, _acct = self.register()
        tag = self.uniq()
        name, email = self.add_full_profile(cookie, tag)
        self.set_consent(cookie, "automated_remediation", True)
        self.run_removal(cookie)
        stub = StubExecutor()
        # The CAPTCHA and login legs run on ThatsThem / USPhoneBook:
        # Social Catfish and PeopleFinders gained published removal
        # emails in the 2026-10-08 email-coverage pass and now take
        # the email channel (their cases park at email_send_required
        # like BeenVerified's below) — the form-blocker behaviours
        # are exercised on brokers that remain form-channel.
        stub.probe_by_broker["ThatsThem"] = {
            "reachable": True, "status": 200, "fillable": False,
            "forms": [], "payload_preview": {},
            "blockers": ["CAPTCHA on the page — a human must solve "
                         "this step"]}
        stub.probe_by_broker["USPhoneBook"] = {
            "reachable": True, "status": 200, "fillable": False,
            "forms": [], "payload_preview": {},
            "blockers": ["Asks for account login — removal must be "
                         "done signed in"]}
        stub.probe_by_broker["FastPeopleSearch"] = {
            "reachable": False, "status": 403, "fillable": False,
            "forms": [], "payload_preview": {},
            "blockers": ["Site answered HTTP 403 to a script"]}
        self.drain(stub)

        spokeo = self.case_for(cookie, "Spokeo")
        self.assertEqual(spokeo["status"], "submitted")
        self.assertIsNotNone(spokeo["submitted_at"])
        attempts = self.db_row(
            "SELECT COUNT(*) AS n FROM remediation_attempts"
            " WHERE case_id = %s", (spokeo["id"],))
        self.assertGreaterEqual(attempts["n"], 2)  # probe + submit
        self.assertEqual(stub.submits_for(email, "Spokeo"), ["Spokeo"])

        catfish = self.case_for(cookie, "ThatsThem")
        self.assertEqual(catfish["status"], "needs_human")
        self.assertEqual(catfish["reason"], "captcha")

        pf = self.case_for(cookie, "USPhoneBook")
        self.assertEqual(pf["status"], "needs_human")
        self.assertEqual(pf["reason"], "login_required")

        fps = self.case_for(cookie, "FastPeopleSearch")
        self.assertEqual(fps["status"], "blocked")
        self.assertEqual(fps["reason"], "http_403")

        # Email channel: letter generated, parked for the user, and
        # the queue payload carries the ready-to-send letter with
        # the user's own details in it (it is THEIR letter).
        bv = self.case_for(cookie, "BeenVerified")
        self.assertEqual(bv["status"], "needs_human")
        self.assertEqual(bv["reason"], "email_send_required")
        status, _h, body = self.request_json(
            "GET", "/api/remediation/queue", cookie=cookie)
        self.assertEqual(status, 200)
        queue = {q["broker_name"]: q for q in body["queue"]}
        self.assertIn("BeenVerified", queue)
        item = queue["BeenVerified"]
        self.assertEqual(item["action"], "send_email")
        self.assertEqual(item["to"], "optout@beenverified.com")
        self.assertIn(name, item["body"])
        self.assertIn(email, item["body"])
        self.assertIn("Digital Personal Data Protection Act",
                      item["body"])
        # The CAPTCHA case is in the queue too, pointing at the page.
        self.assertEqual(queue["ThatsThem"]["action"], "open_optout")
        self.assertIn("thatsthem.com",
                      queue["ThatsThem"]["url"])

        # No double submit: the queue is empty; draining again is a
        # no-op and the stub sees no new submits for this user.
        before = len(stub.submits_for(email))
        self.assertFalse(worker_mod.run_once(stub))
        self.assertEqual(len(stub.submits_for(email)), before)

    def test_consent_withdrawn_mid_queue_stops_everything(self):
        cookie, _uid, _acct = self.register()
        _name, email = self.add_full_profile(cookie, self.uniq())
        self.set_consent(cookie, "automated_remediation", True)
        self.run_removal(cookie)
        self.set_consent(cookie, "automated_remediation", False)
        stub = StubExecutor()
        self.drain(stub)
        for case in self.list_cases(cookie):
            self.assertEqual(case["status"], "needs_human", case)
            self.assertEqual(case["reason"], "consent_withdrawn", case)
        self.assertEqual(stub.submits_for(email), [])
        self.assertEqual(
            [c for c in stub.probe_calls if c[1] == email], [])

    def test_missing_field_names_the_field(self):
        cookie, _uid, _acct = self.register()
        tag = self.uniq()
        email = "only-%s@example.com" % tag
        self.add_identifier(cookie, "email", email)  # nothing else
        self.set_consent(cookie, "automated_remediation", True)
        self.run_removal(cookie)
        stub = StubExecutor()
        # The missing-field leg runs on TransUnion: Epsilon gained
        # a published opt-out email in the 2026-10-08 email-coverage
        # pass and now takes the email channel, whose letter flow
        # does not exercise the form-field path this test pins.
        stub.probe_by_broker["TransUnion"] = {
            "reachable": True, "status": 200, "fillable": False,
            "payload_preview": {}, "blockers": [],
            "forms": [{"action": "https://www.transunion.com/optout",
                       "method": "POST",
                       "fields": [{"name": "city", "id": "",
                                   "placeholder": "", "type": "text"}],
                       "unmapped_fields": ["city"]}]}
        self.drain(stub)
        eps = self.case_for(cookie, "TransUnion")
        self.assertEqual(eps["status"], "needs_human")
        self.assertEqual(eps["reason"], "missing_field:city")
        # The queue note names the missing detail in plain words.
        status, _h, body = self.request_json(
            "GET", "/api/remediation/queue", cookie=cookie)
        item = {q["broker_name"]: q
                for q in body["queue"]}["TransUnion"]
        self.assertEqual(item["action"], "open_optout")
        self.assertIn("city", item["note"])

    # ---------- workflow versioning (Phase 31) ----------
    def test_attempts_carry_workflow_version(self):
        # Every attempt records the broker workflow_version at
        # creation (migration 0016); re-mapping a broker (bumping
        # its version) changes only NEW attempts — attempts
        # already written keep the version they ran under.
        cookie, _uid, _acct = self.register()
        self.add_full_profile(cookie, self.uniq())
        self.set_consent(cookie, "automated_remediation", True)
        self.run_removal(cookie)
        stub = StubExecutor()
        stub.probe_by_broker["FastPeopleSearch"] = {
            "fillable": False, "reachable": False, "status": 403,
            "forms": [], "payload_preview": {},
            "via": "http", "probe_trail": [],
            "blockers": ["Site answered HTTP 403 to a script"]}
        self.drain(stub)

        fps = self.case_for(cookie, "FastPeopleSearch")
        self.assertEqual(fps["status"], "blocked")
        # The case detail serializes the attempt trail, versions
        # included (all brokers ship workflow_version 1 today).
        status, _h, body = self.request_json(
            "GET", "/api/remediation/cases/%s" % fps["id"],
            cookie=cookie)
        self.assertEqual(status, 200, body)
        attempts_v1 = body["case"]["attempts"]
        self.assertTrue(attempts_v1)
        self.assertTrue(all(
            a["workflow_version"] == 1 for a in attempts_v1),
            attempts_v1)
        # Anonymous callers hit the reader gate (401); another
        # signed-in user's view of the case is the house 404,
        # never a leak.
        status, _h, _b = self.request_json(
            "GET", "/api/remediation/cases/%s" % fps["id"])
        self.assertEqual(status, 401)
        other_cookie, _ouid, _oacct = self.register()
        status, _h, _b = self.request_json(
            "GET", "/api/remediation/cases/%s" % fps["id"],
            cookie=other_cookie)
        self.assertEqual(status, 404)

        # Re-map the broker: workflow_version 1 -> 7, then retry.
        with self.pool.connection() as conn:
            conn.execute(
                "UPDATE brokers SET workflow_version = 7"
                " WHERE slug = 'fastpeoplesearch'")
        status, _h, body = self.request_json(
            "POST", "/api/remediation/cases/%s/retry" % fps["id"],
            body={}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.drain(stub)

        status, _h, body = self.request_json(
            "GET", "/api/remediation/cases/%s" % fps["id"],
            cookie=cookie)
        attempts = body["case"]["attempts"]
        versions = [a["workflow_version"] for a in attempts]
        self.assertEqual(versions[:len(attempts_v1)],
                         [1] * len(attempts_v1))
        self.assertTrue(len(attempts) > len(attempts_v1))
        self.assertTrue(all(
            v == 7 for v in versions[len(attempts_v1):]), versions)

        # The admin metrics block groups attempts by
        # (broker, version, result) — both generations visible.
        from accounts import admin as admin_mod
        with self.pool.connection() as conn:
            metrics = admin_mod._metrics_block(conn)
        grouped = {(row["broker"], row["workflow_version"],
                    row["result"])
                   for row in
                   metrics["remediation_attempts_by_workflow_version"]}
        self.assertIn(("fastpeoplesearch", 1, "blocked"), grouped)
        self.assertIn(("fastpeoplesearch", 7, "blocked"), grouped)
        # Restore the registry row for any later test in the class.
        with self.pool.connection() as conn:
            conn.execute(
                "UPDATE brokers SET workflow_version = 1"
                " WHERE slug = 'fastpeoplesearch'")

    # ---------- retry + the "I sent it" email flow ----------
    def test_retry_rules_and_letter_confirmation(self):
        cookie, _uid, _acct = self.register()
        self.add_full_profile(cookie, self.uniq())
        self.set_consent(cookie, "automated_remediation", True)
        self.run_removal(cookie)
        stub = StubExecutor()
        self.drain(stub)

        # A submitted case can never be re-run (no double submits).
        spokeo = self.case_for(cookie, "Spokeo")
        status, _h, body = self.request_json(
            "POST", "/api/remediation/cases/%s/retry" % spokeo["id"],
            body={}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"]["code"], "not_retryable")

        # The email case: user sends the letter, presses "I sent it"
        # (retry) -> back to queued; the worker now records it as
        # submitted by the user's own hand.
        bv = self.case_for(cookie, "BeenVerified")
        status, _h, body = self.request_json(
            "POST", "/api/remediation/cases/%s/retry" % bv["id"],
            body={}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], "queued")
        self.drain(stub)
        bv = self.case_for(cookie, "BeenVerified")
        self.assertEqual(bv["status"], "submitted")
        self.assertEqual(bv["reason"], "letter_sent_by_user")
        self.assertIsNotNone(bv["submitted_at"])

    # ---------- authorized-agent email sending (2026-10-08) ------
    def test_agent_send_submits_email_cases(self):
        cookie, _uid, _acct = self.register()
        _name, email = self.add_full_profile(cookie, self.uniq())
        self.set_consent(cookie, "automated_remediation", True)
        self.run_removal(cookie)
        calls = []

        def mailer(to, subject, body, reply_to):
            calls.append({"to": to, "subject": subject,
                          "body": body, "reply_to": reply_to})
            return True

        engine_mod.set_agent_mailer(mailer)
        try:
            self.drain(StubExecutor())
        finally:
            engine_mod.set_agent_mailer(None)
        bv = self.case_for(cookie, "BeenVerified")
        self.assertEqual(bv["status"], "submitted")
        self.assertEqual(bv["reason"], "letter_sent_by_agent")
        self.assertIsNotNone(bv["submitted_at"])
        # BeenVerified and PeopleLooker share this inbox; the
        # BeenVerified case's own letter is the one naming it.
        bv_calls = [c for c in calls
                    if c["to"] == "optout@beenverified.com"
                    and "BeenVerified" in c["body"]]
        self.assertEqual(len(bv_calls), 1)
        # The broker answers the user, not the service.
        self.assertEqual(bv_calls[0]["reply_to"], email)
        self.assertIn("authorized agent", bv_calls[0]["body"])
        # Form-channel brokers are never mailed.
        self.assertFalse(any("spokeo" in c["to"] for c in calls))
        # No double-send: draining again sends nothing new.
        before = len(calls)
        self.drain(StubExecutor())
        self.assertEqual(len(calls), before)

    def test_agent_send_failure_parks_for_user(self):
        cookie, _uid, _acct = self.register()
        self.add_full_profile(cookie, self.uniq())
        self.set_consent(cookie, "automated_remediation", True)
        self.run_removal(cookie)
        engine_mod.set_agent_mailer(
            lambda to, subject, body, reply_to: False)
        try:
            self.drain(StubExecutor())
        finally:
            engine_mod.set_agent_mailer(None)
        bv = self.case_for(cookie, "BeenVerified")
        self.assertEqual(bv["status"], "needs_human")
        self.assertEqual(bv["reason"], "email_send_required")

    def test_agent_send_exception_parks_for_user(self):
        cookie, _uid, _acct = self.register()
        self.add_full_profile(cookie, self.uniq())
        self.set_consent(cookie, "automated_remediation", True)
        self.run_removal(cookie)

        def boom(to, subject, body, reply_to):
            raise RuntimeError("lane exploded")

        engine_mod.set_agent_mailer(boom)
        try:
            self.drain(StubExecutor())
        finally:
            engine_mod.set_agent_mailer(None)
        bv = self.case_for(cookie, "BeenVerified")
        self.assertEqual(bv["status"], "needs_human")
        self.assertEqual(bv["reason"], "email_send_required")

    # ---------- verification + reappearance ----------
    def test_verify_transitions_and_reappearance(self):
        cookie, _uid, _acct = self.register()
        self.add_full_profile(cookie, self.uniq())
        self.set_consent(cookie, "automated_remediation", True)
        self.run_removal(cookie)
        stub = StubExecutor()
        self.drain(stub)

        orig_executor = engine_mod.AgentExecutor
        engine_mod.AgentExecutor = lambda: stub
        try:
            # gone -> verified_removed, with a check row recorded.
            stub.verify_by_broker["Spokeo"] = "gone"
            spokeo = self.case_for(cookie, "Spokeo")
            status, _h, body = self.request_json(
                "POST", "/api/remediation/cases/%s/verify" % spokeo["id"],
                body={}, headers=CSRF, cookie=cookie)
            self.assertEqual(status, 200, body)
            self.assertEqual(body["outcome"], "gone")
            self.assertEqual(body["case"]["status"], "verified_removed")
            checks = self.db_row(
                "SELECT COUNT(*) AS n FROM verification_checks"
                " WHERE case_id = %s AND outcome = 'gone'",
                (spokeo["id"],))
            self.assertEqual(checks["n"], 1)

            # still_present on a submitted case: stays submitted.
            stub.verify_by_broker["Data Axle (InfoUSA)"] = "still_present"
            axle = self.case_for(cookie, "Data Axle (InfoUSA)")
            status, _h, body = self.request_json(
                "POST",
                "/api/remediation/cases/%s/verify" % axle["id"],
                body={}, headers=CSRF, cookie=cookie)
            self.assertEqual(status, 200, body)
            self.assertEqual(body["outcome"], "still_present")
            self.assertEqual(body["case"]["status"], "submitted")
            self.assertEqual(body["case"]["reason"], "still_listed")

            # unknown: nothing changes, nothing is guessed.
            stub.verify_by_broker["Data Axle (InfoUSA)"] = "unknown"
            status, _h, body = self.request_json(
                "POST",
                "/api/remediation/cases/%s/verify" % axle["id"],
                body={}, headers=CSRF, cookie=cookie)
            self.assertEqual(body["outcome"], "unknown")
            self.assertEqual(body["case"]["status"], "submitted")
            self.assertEqual(body["case"]["reason"], "still_listed")

            # Reappearance: the verified case is found again.
            stub.verify_by_broker["Spokeo"] = "still_present"
            status, _h, body = self.request_json(
                "POST", "/api/remediation/cases/%s/verify" % spokeo["id"],
                body={}, headers=CSRF, cookie=cookie)
            self.assertEqual(body["case"]["status"], "reappeared")

            # mark_reappeared: the external-evidence flip.
            # TruthFinder takes the email channel since the
            # 2026-10-08 email-coverage pass: confirm the letter
            # ("I sent it") first so its case is submitted, the
            # state this leg verifies from.
            tf = self.case_for(cookie, "TruthFinder")
            self.assertEqual(tf["status"], "needs_human")
            self.assertEqual(tf["reason"], "email_send_required")
            status, _h, body = self.request_json(
                "POST", "/api/remediation/cases/%s/retry" % tf["id"],
                body={}, headers=CSRF, cookie=cookie)
            self.assertEqual(status, 200, body)
            self.drain(stub)
            self.assertEqual(self.case_for(cookie, "TruthFinder")
                             ["status"], "submitted")
            stub.verify_by_broker["TruthFinder"] = "gone"
            tf = self.case_for(cookie, "TruthFinder")
            self.request_json(
                "POST", "/api/remediation/cases/%s/verify" % tf["id"],
                body={}, headers=CSRF, cookie=cookie)
            self.assertEqual(self.case_for(cookie, "TruthFinder")
                             ["status"], "verified_removed")
            self.assertTrue(verify_mod.mark_reappeared(
                tf["id"], "finding:evidence-1"))
            self.assertEqual(self.case_for(cookie, "TruthFinder")
                             ["status"], "reappeared")
            self.assertFalse(verify_mod.mark_reappeared(
                tf["id"], "finding:evidence-2"))

            # Nothing to verify on a needs_human case.
            bv = self.case_for(cookie, "BeenVerified")
            status, _h, body = self.request_json(
                "POST", "/api/remediation/cases/%s/verify" % bv["id"],
                body={}, headers=CSRF, cookie=cookie)
            self.assertEqual(status, 409, body)
            self.assertEqual(body["error"]["code"], "not_verifiable")
        finally:
            engine_mod.AgentExecutor = orig_executor

    # ---------- Stage 7.1: staged probe escalation ----------
    def test_relay_escalation_submits_and_audits_trail(self):
        cookie, _uid, _acct = self.register()
        _name, email = self.add_full_profile(cookie, self.uniq())
        self.set_consent(cookie, "automated_remediation", True)
        self.run_removal(cookie)
        agent = engine_mod.agent_engine
        saved = {n: getattr(agent, n) for n in
                 ("probe_broker", "relay_probe", "browser_probe",
                  "submit_form", "probe_with_browser_fallback")}
        relay_urls = []
        submit_actions = []
        browser_hits = []
        brokers_by_name = {b["name"]: b for b in agent.load_brokers()}

        def fast(name, profile=None):
            return {"broker": name,
                    "url": brokers_by_name[name]["optout_url"],
                    "automation": "http_form", "needs": [],
                    "reachable": False, "status": None, "forms": [],
                    "blockers": ["Page unreachable from this server "
                                 "right now"],
                    "payload_preview": {}, "fillable": False}

        def relay(url, profile=None):
            relay_urls.append(url)
            return {"via": "relay", "reachable": True, "status": 200,
                    "forms": FILLABLE_FORM, "challenge": False,
                    "payload_preview": {
                        "email": (profile or {}).get("email", "")},
                    "blockers": [], "title": ""}

        def submit(action, method, payload, timeout=15):
            submit_actions.append(action)
            return {"ok": True, "status": 200}

        def _no_fallback(*args, **kwargs):
            raise AssertionError("the full fallback chain must not run")

        agent.probe_broker = fast
        agent.relay_probe = relay
        agent.browser_probe = lambda url: browser_hits.append(url)
        agent.submit_form = submit
        agent.probe_with_browser_fallback = _no_fallback
        try:
            executor = engine_mod.AgentExecutor(probe_budget_seconds=30)
            self.drain(executor)
        finally:
            for n, fn in saved.items():
                setattr(agent, n, fn)

        spokeo = self.case_for(cookie, "Spokeo")
        self.assertEqual(spokeo["status"], "submitted")
        self.assertIsNotNone(spokeo["submitted_at"])
        # The relay path was taken exactly once for Spokeo, the form
        # it found was submitted, and the browser step never ran.
        spokeo_url = brokers_by_name["Spokeo"]["optout_url"]
        self.assertEqual(relay_urls.count(spokeo_url), 1)
        self.assertEqual(browser_hits, [])
        self.assertIn("https://www.spokeo.com/optout", submit_actions)
        # The probe attempt's audit detail carries the whole trail.
        row = self.db_row(
            "SELECT detail FROM remediation_attempts"
            " WHERE case_id = %s AND action = 'probe'",
            (spokeo["id"],))
        detail = row["detail"]
        if isinstance(detail, str):
            detail = json.loads(detail)
        self.assertEqual(detail["via"], "http+relay")
        self.assertEqual([t["step"] for t in detail["trail"]],
                         ["http", "relay", "browser"])
        self.assertEqual(detail["trail"][2]["skipped"], "on_server")

    # ---------- Stage 7.1: concurrent worker ----------
    def test_worker_drains_nine_cases_concurrently(self):
        cookie, uid, _acct = self.register()
        _name, email = self.add_full_profile(cookie, self.uniq())
        self.set_consent(cookie, "automated_remediation", True)
        with self.pool.connection() as conn:
            slugs = [r["slug"] for r in conn.execute(
                "SELECT slug FROM brokers WHERE channel = 'form'"
                " ORDER BY position LIMIT 9").fetchall()]
            self.assertEqual(len(slugs), 9)
            for slug in slugs:
                conn.execute(
                    "INSERT INTO remediation_cases (user_id, broker_slug)"
                    " VALUES (%s, %s)", (uid, slug))

        class SleepingStub(StubExecutor):
            """Probe sleeps 0.3s and tracks live concurrency."""

            def __init__(self):
                super().__init__()
                self._lock = threading.Lock()
                self._current = 0
                self.max_concurrent = 0

            def probe(self, profile, broker):
                with self._lock:
                    self._current += 1
                    self.max_concurrent = max(self.max_concurrent,
                                              self._current)
                try:
                    time.sleep(0.3)
                    return super().probe(profile, broker)
                finally:
                    with self._lock:
                        self._current -= 1

        stub = SleepingStub()
        started = time.monotonic()
        self.assertTrue(worker_mod.start_worker(stub))
        settled = 0
        try:
            deadline = started + 30
            while time.monotonic() < deadline:
                row = self.db_row(
                    "SELECT COUNT(*) AS n FROM remediation_cases"
                    " WHERE user_id = %s AND status = 'submitted'",
                    (uid,))
                settled = row["n"]
                if settled == 9:
                    break
                time.sleep(0.02)
            wall = time.monotonic() - started
        finally:
            worker_mod.stop_worker()
            thread = worker_mod._thread
            if thread is not None:
                thread.join(timeout=15)
        self.assertEqual(settled, 9)
        # Sequential draining would spend 9 x 0.3s in probe sleeps
        # alone; the concurrent drainers must beat 60% of that.
        self.assertLess(wall, 9 * 0.3 * 0.6)
        self.assertGreaterEqual(stub.max_concurrent, 2)
        self.assertEqual(len(stub.submits_for(email)), 9)

    # ---------- IDOR ----------
    def test_idor(self):
        cookie_a, _ua, _ea = self.register()
        self.add_full_profile(cookie_a, self.uniq())
        self.set_consent(cookie_a, "automated_remediation", True)
        self.run_removal(cookie_a)
        case_a = self.list_cases(cookie_a)[0]

        cookie_b, _ub, _eb = self.register()
        self.assertEqual(self.list_cases(cookie_b), [])
        status, _h, body = self.request_json(
            "GET", "/api/remediation/queue", cookie=cookie_b)
        self.assertEqual(body["queue"], [])
        for action in ("verify", "retry"):
            status, _h, body = self.request_json(
                "POST", "/api/remediation/cases/%s/%s"
                % (case_a["id"], action),
                body={}, headers=CSRF, cookie=cookie_b)
            self.assertEqual(status, 404, (action, body))
        # And a random id is the same 404 for the owner too.
        status, _h, body = self.request_json(
            "POST", "/api/remediation/cases/%s/retry" % uuid.uuid4(),
            body={}, headers=CSRF, cookie=cookie_a)
        self.assertEqual(status, 404, body)
        # Owner's case untouched by all of the above.
        self.assertEqual(self.case_for(cookie_a, case_a["broker_name"])
                         ["status"], "queued")
        self.drain(StubExecutor())
