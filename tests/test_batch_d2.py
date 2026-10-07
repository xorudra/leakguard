"""Final-spec Batch D2 tests — privacy-policy analyzer (Phase 102),
propagation analysis (Phases 104/152), and the standalone Privacy /
Terms / Support pages plus Trust additions (Phases 82/83/126/128/
129/130).

Layers:

* TestPolicyAnalyzer — pure: every checklist item fires on a
  fixture written to contain its phrases and stays not_found on a
  control text; weak mentions answer "unclear"; matched phrases are
  never longer than eight words; both/neither input is a 400;
  oversize pasted text is a 413; the URL path goes through the SSRF
  guard (a private resolution is refused before any fetch) and an
  injected fetcher's HTML is stripped of script/style.
* TestPagesNoDb — the four information routes serve the SPA with
  the right sections, and file assertions pin the honest copy
  (no rewards for disclosure, fixed data locations, no invented
  support promise).
* TestPropagationStatus — the case-status normalization, including
  a matched broker with no case -> not_started.
* TestBatchD2Db — pgserver: the analyzer answers 401 without a
  session and 200 for a signed-in user; a source matched to a
  broker with NO case propagates as not_started with a matching
  rollup, and the raw identifier appears nowhere in the payload.

Run:  python3 -m unittest discover -s tests
"""

import base64
import ipaddress
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402
from accounts import ratelimit  # noqa: E402
from core import errors, ssrf  # noqa: E402
from dashboard import graph as graph_service  # noqa: E402
from dashboard import policy_analyzer  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")
ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"

FIXTURE_POLICY = (
    "We do not sell or share your personal information. "
    "We use targeted advertising and tracking technologies. "
    "We retain your personal data for 12 months. "
    "You have the right to access, correct, or delete your information. "
    "Contact us at privacy@example.com. "
    "We use encryption and security measures. "
    "This service is not intended for children under 13. "
    "We may update this privacy policy and will notify you of material changes. "
    "We share information with third parties and service providers that process data."
)
CONTROL_POLICY = "A short note about ordinary account features and billing."


class EnvGuard:
    def __init__(self, keys):
        self.keys = keys

    def __enter__(self):
        self.saved = {k: os.environ.get(k) for k in self.keys}
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
# The analyzer, pure
# ---------------------------------------------------------------------------

class TestPolicyAnalyzer(unittest.TestCase):
    def test_every_check_fires_on_the_fixture(self):
        result = policy_analyzer.analyze_payload({"text": FIXTURE_POLICY})
        self.assertEqual(result["disclaimer"], policy_analyzer.DISCLAIMER)
        self.assertEqual(result["method"],
                         "deterministic_keyword_heuristics")
        by_id = {c["id"]: c for c in result["checks"]}
        self.assertEqual(set(by_id), {
            "sale_sharing", "advertising_tracking", "retention",
            "user_rights", "contact", "security_practices", "children",
            "policy_changes", "third_party_sharing",
        })
        for check_id, check in by_id.items():
            self.assertEqual(check["status"], "found", check_id)
            self.assertTrue(check["matched_phrase"], check_id)
            self.assertLessEqual(
                len(check["matched_phrase"].split()), 8, check_id)
        self.assertGreater(result["stats"]["word_count"], 50)
        self.assertGreater(result["stats"]["average_sentence_words"], 0)

    def test_no_check_fires_on_the_control(self):
        result = policy_analyzer.analyze_payload({"text": CONTROL_POLICY})
        for check in result["checks"]:
            self.assertEqual(check["status"], "not_found", check["id"])
            self.assertIsNone(check["matched_phrase"], check["id"])

    def test_weak_mentions_are_unclear_not_found(self):
        result = policy_analyzer.analyze_payload(
            {"text": "We share updates and use cookies. Contact the team."})
        by_id = {c["id"]: c for c in result["checks"]}
        self.assertEqual(by_id["sale_sharing"]["status"], "unclear")
        self.assertEqual(by_id["advertising_tracking"]["status"], "unclear")
        self.assertEqual(by_id["contact"]["status"], "unclear")

    def test_both_or_neither_input_is_a_400(self):
        for payload in ({}, {"text": "   "},
                        {"text": "x", "url": "https://example.com/p"}):
            with self.assertRaises(errors.ApiError) as ctx:
                policy_analyzer.analyze_payload(payload)
            self.assertEqual(ctx.exception.status, 400, payload)

    def test_oversize_text_is_a_413(self):
        big = "word " * (policy_analyzer.MAX_TEXT_BYTES // 5 + 100)
        with self.assertRaises(errors.ApiError) as ctx:
            policy_analyzer.analyze_payload({"text": big})
        self.assertEqual(ctx.exception.status, 413)

    def test_url_path_uses_the_guarded_fetcher_and_strips_html(self):
        seen = []

        def fetcher(url):
            seen.append(url)
            return 200, (
                "<html><head><style>.x{}</style>"
                "<script>var targeted = 'advertising';</script></head>"
                "<body><h1>Privacy</h1>"
                "<p>We use encryption and security measures.</p>"
                "</body></html>")

        public = [ipaddress.ip_address("93.184.216.34")]
        with mock.patch.object(ssrf, "resolve_host", return_value=public):
            result = policy_analyzer.analyze_payload(
                {"url": "https://example.com/privacy"}, fetcher=fetcher)
        self.assertEqual(seen, ["https://example.com/privacy"])
        self.assertEqual(result["source"],
                         {"type": "url", "host": "example.com"})
        by_id = {c["id"]: c for c in result["checks"]}
        self.assertEqual(by_id["security_practices"]["status"], "found")
        # The script's words never reach the checklist.
        self.assertEqual(by_id["advertising_tracking"]["status"],
                         "not_found")

    def test_url_resolving_to_a_private_address_is_refused(self):
        def fetcher(url):  # pragma: no cover - must never run
            raise AssertionError("fetcher ran for a private address")

        private = [ipaddress.ip_address("10.0.0.5")]
        with mock.patch.object(ssrf, "resolve_host", return_value=private):
            with self.assertRaises(errors.ApiError) as ctx:
                policy_analyzer.analyze_payload(
                    {"url": "https://example.com/privacy"},
                    fetcher=fetcher)
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.code, "policy_url_not_public")


# ---------------------------------------------------------------------------
# Pages, no database
# ---------------------------------------------------------------------------

class TestPagesNoDb(ServerMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._env = EnvGuard(ENV_KEYS).__enter__()
        for key in ENV_KEYS:
            os.environ.pop(key, None)
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls._env.__exit__()

    def test_information_pages_serve(self):
        for path, marker in (
                ("/privacy", b'id="privacyPolicy"'),
                ("/terms", b'id="terms"'),
                ("/support", b'id="supportPage"'),
                ("/trust", b'id="trust"')):
            status, _h, payload = self.request("GET", path)
            self.assertEqual(status, 200, path)
            self.assertIn(marker, payload, path)

    def test_page_copy_is_the_honest_copy(self):
        html = (STATIC / "index.html").read_text("utf-8")
        # Privacy: effective date, processors, regions, export.
        self.assertIn("Effective date: 7 October 2026", html)
        self.assertIn("AWS ap-southeast-1, Singapore", html)
        self.assertIn("Oregon, United States", html)
        self.assertIn("five-character SHA-1 prefix", html)
        # Terms: the standing honest limits.
        self.assertIn("No guarantee of removal", html)
        self.assertIn("cannot be recalled by LeakGuard", html)
        # Support: best effort, no invented response time, never secrets.
        self.assertIn("best-effort basis. There is no promised response time",
                      html)
        self.assertIn("Never post a password", html)
        # Trust additions: disclosure with NO paid bounty + data locations.
        self.assertIn("Responsible disclosure", html)
        self.assertIn("does <strong>not</strong> offer a paid bug bounty",
                      html)
        self.assertIn("Where data lives", html)
        # Footer links to all four pages.
        for href in ('href="/privacy"', 'href="/terms"',
                     'href="/support"', 'href="/trust"'):
            self.assertIn(href, html)

    def test_frontend_wiring(self):
        js = (STATIC / "app.js").read_text("utf-8")
        self.assertIn('"/privacy": "privacyPolicy"', js)
        self.assertIn('"/terms": "terms"', js)
        self.assertIn('"/support": "supportPage"', js)
        self.assertIn('apiJson("/api/tools/policy-analyzer"', js)
        self.assertIn("Brokers LeakGuard can act on for this source", js)
        self.assertIn("renderPropagation", js)
        html = (STATIC / "index.html").read_text("utf-8")
        self.assertIn('id="policyCheckBtn"', html)
        self.assertIn('id="propagationWrap"', html)


# ---------------------------------------------------------------------------
# Propagation status normalization (pure)
# ---------------------------------------------------------------------------

class TestPropagationStatus(unittest.TestCase):
    def test_status_mapping(self):
        mapping = graph_service._propagation_status
        self.assertEqual(mapping(None), "not_started")
        self.assertEqual(mapping("queued"), "in_progress")
        self.assertEqual(mapping("running"), "in_progress")
        self.assertEqual(mapping("reappeared"), "in_progress")
        self.assertEqual(mapping("submitted"), "submitted")
        self.assertEqual(mapping("needs_human"), "needs_human")
        self.assertEqual(mapping("blocked"), "blocked")
        self.assertEqual(mapping("failed"), "blocked")
        self.assertEqual(mapping("verified_removed"), "verified_removed")


# ---------------------------------------------------------------------------
# Database-backed: analyzer auth + propagation not_started
# ---------------------------------------------------------------------------

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestBatchD2Db(ServerMixin, unittest.TestCase):
    PASSWORD = "correct-horse-9"

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._env = EnvGuard(ENV_KEYS).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-batch-d2-pg-")
        try:
            cls._pg = _pgserver.get_server(cls._pg_dir)
        except Exception:
            cls._env.__exit__()
            raise unittest.SkipTest("pgserver could not start PostgreSQL")
        os.environ["DATABASE_URL"] = cls._pg.get_uri()
        os.environ["VAULT_MASTER_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        os.environ["VAULT_LOOKUP_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        from db import migrate, pool
        from remediation import registry_seed

        cls.pool = pool
        pool.reset_probe_cache()
        if not pool.db_available():
            cls._teardown_pg()
            raise unittest.SkipTest("local PostgreSQL not reachable")
        migrate.run_migrations()
        registry_seed.seed_brokers()
        cls.start_server()

    @classmethod
    def _teardown_pg(cls):
        try:
            cls._pg.cleanup()
        except Exception:
            pass
        import shutil

        shutil.rmtree(cls._pg_dir, ignore_errors=True)
        cls._env.__exit__()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls.pool.reset_probe_cache()
        cls._teardown_pg()

    def setUp(self):
        ratelimit.reset()

    def uniq(self):
        return uuid.uuid4().hex[:12]

    def register(self):
        email = "d2-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": self.PASSWORD},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"]

    def test_analyzer_requires_a_session(self):
        # CSRF header present, no session cookie -> 401.
        status, _h, body = self.request_json(
            "POST", "/api/tools/policy-analyzer",
            body={"text": FIXTURE_POLICY}, headers=CSRF)
        self.assertEqual(status, 401, body)
        self.assertEqual(body["error"]["code"], "unauthenticated")

        cookie, _uid = self.register()
        status, _h, body = self.request_json(
            "POST", "/api/tools/policy-analyzer",
            body={"text": FIXTURE_POLICY}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["tool"], "privacy_policy_analyzer")
        found = {c["id"] for c in body["checks"]
                 if c["status"] == "found"}
        self.assertEqual(len(found), 9)

    def test_propagation_not_started_for_a_caseless_match(self):
        cookie, uid = self.register()
        raw_email = "d2-prop-%s@example.com" % self.uniq()
        status, _h, ident = self.request_json(
            "POST", "/api/identifiers",
            body={"kind": "email", "value": raw_email},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, ident)
        identifier_id = ident["identifier"]["id"]
        with self.pool.connection() as conn:
            job_id = str(conn.execute(
                "INSERT INTO scan_jobs (user_id, idempotency_key,"
                " status, score, finished_at) VALUES (%s, %s, 'done',"
                " 10, %s) RETURNING id",
                (uid, uuid.uuid4().hex,
                 datetime.now(timezone.utc))).fetchone()["id"])
            conn.execute(
                "INSERT INTO findings (job_id, user_id, identifier_id,"
                " identifier_kind, provider, source_name, source_url,"
                " confidence, reliability, evidence_ref)"
                " VALUES (%s, %s, %s, 'email', 'FixturePeople',"
                " 'Spokeo', 'https://www.spokeo.com/search',"
                " 'probable', 'medium', 'd2-fixture-ref')",
                (job_id, uid, identifier_id))
        status, _h, body = self.request_json(
            "GET", "/api/graph", cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertNotIn(raw_email, json.dumps(body))  # masked ONLY
        entries = body["propagation"]["entries"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["brokers"], [{
            "slug": "spokeo", "name": "Spokeo",
            "status": "not_started", "case_status": None,
        }])
        rollups = body["propagation"]["rollups"]
        self.assertEqual(len(rollups), 1)
        self.assertEqual(rollups[0]["counts"]["not_started"], 1)
        self.assertEqual(
            sum(rollups[0]["counts"].values()), 1)
