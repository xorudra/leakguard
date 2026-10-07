"""Scanning engine tests (Stage S5 — spec Phases 11, 12, 13, 21–27).

Layers:

* TestRiskEngine — offline: the v2 scorer reproduces the LEGACY
  exposure score exactly (the pre-S5 formula is re-implemented here
  as the reference) across a matrix of inputs, plus the documented
  baselines; explanations name every contributing component;
  finding_risk follows its documented rubric.
* TestNormalize — offline (ephemeral lookup key): finding shape,
  evidence payloads never contain the raw identifier, password
  findings carry a count and nothing else.
* TestCorrelation — offline: per-identifier clusters and the
  shared-source note (and its absence when nothing is shared).
* TestScansUnavailable — no database: scan routes answer 503 after
  the CSRF guard, exactly like the other account routes.
* TestScanningDb — the full flow against a local PostgreSQL
  provisioned with pip `pgserver` (skips honestly when pgserver or
  Postgres is unavailable): consent gate, no-identifiers 400,
  idempotent create, orchestrator end-to-end with mock providers,
  shared-source correlation, IDOR, worker retry -> dead, stale
  requeue. Mock providers only — no network, no real data.

Run:  python3 -m unittest discover -s tests
"""

import base64
import hashlib
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402
from accounts import ratelimit  # noqa: E402
from providers import registry as registry_mod  # noqa: E402
from scanning import correlation, normalize, risk  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")


def legacy_exposure_score(breaches, analytics, pwned_count):
    """The pre-S5 app.exposure_score, copied verbatim as the parity
    reference. Do not 'fix' this — it IS the baseline."""
    if analytics and isinstance(analytics.get("risk_score"), (int, float)):
        score = int(analytics["risk_score"])
    elif breaches is not None:
        score = min(100, len(breaches) * 8)
    else:
        score = 0
    if pwned_count:
        score = max(score, 85 if pwned_count > 1000 else 70)
    return max(0, min(100, score))


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
# Risk engine parity + rubric
# ---------------------------------------------------------------------------

class TestRiskEngine(unittest.TestCase):
    def test_parity_matrix_against_legacy(self):
        breach_sets = [None, [], ["A"], ["A", "B"],
                       ["B%d" % i for i in range(13)],
                       ["B%d" % i for i in range(214)]]
        analytics_sets = [None, {}, {"risk_score": None},
                          {"risk_score": 0}, {"risk_score": 42},
                          {"risk_score": 72}, {"risk_score": 100},
                          {"risk_score": 250}, {"risk_score": "high"}]
        pwned_sets = [None, 0, 1, 999, 1000, 1001, 52372427]
        for breaches in breach_sets:
            for analytics in analytics_sets:
                for pwned in pwned_sets:
                    expected = legacy_exposure_score(breaches, analytics,
                                                     pwned)
                    score, _expl = risk.score_email_profile(
                        breaches, analytics, pwned)
                    self.assertEqual(score, expected,
                                     (breaches and len(breaches),
                                      analytics, pwned))
                    # The app-level wrapper must agree too.
                    self.assertEqual(
                        app.exposure_score(breaches, analytics, pwned),
                        expected)

    def test_documented_baselines(self):
        names = ["B%d" % i for i in range(214)]
        score, _ = risk.score_email_profile(
            names, {"risk_score": 100}, None)
        self.assertEqual(score, 100)               # 214-breach case
        score, _ = risk.score_email_profile(names, None, None)
        self.assertEqual(score, 100)               # count path caps too
        score, _ = risk.score_email_profile([], None, 52372427)
        self.assertEqual(score, 85)                # pwned > 1000 floor
        score, _ = risk.score_email_profile([], None, 500)
        self.assertEqual(score, 70)                # pwned floor
        score, _ = risk.score_email_profile([], None, None)
        self.assertEqual(score, 0)                 # clean
        score, _ = risk.score_email_profile(
            ["MockBreach2024", "MockComboList"], {"risk_score": 72}, None)
        self.assertEqual(score, 72)                # mock analytics shape

    def test_explanation_names_every_component(self):
        score, explanation = risk.score_email_profile(
            ["B%d" % i for i in range(214)], {"risk_score": 100}, None)
        self.assertEqual(score, 100)
        self.assertTrue(explanation)
        self.assertTrue(any("214 known breaches" in e
                            for e in explanation))
        _s, explanation = risk.score_email_profile([], None, 52372427)
        self.assertTrue(any("52,372,427" in e for e in explanation))
        score, explanation = risk.score_email_profile([], None, None)
        self.assertEqual(score, 0)
        self.assertTrue(any("No points" in e for e in explanation))
        # Any positive score explains itself.
        for breaches, analytics, pwned in (
                (["A"], None, None), ([], {"risk_score": 30}, None),
                ([], None, 7)):
            score, explanation = risk.score_email_profile(
                breaches, analytics, pwned)
            self.assertGreater(score, 0)
            self.assertTrue(explanation)

    def test_finding_risk_rubric(self):
        self.assertEqual(risk.finding_risk(["passwords"], "high"), 45)
        self.assertEqual(
            risk.finding_risk(["social security numbers"], "high"), 50)
        self.assertEqual(
            risk.finding_risk(["email addresses", "passwords"], "high"), 50)
        self.assertEqual(risk.finding_risk(["email addresses"], "high"), 5)
        self.assertEqual(risk.finding_risk([], "high"), 5)
        self.assertEqual(
            risk.finding_risk(["credit cards", "passwords"], "medium"), 68)
        # Cap: a pile of fields cannot exceed 90 * reliability.
        many = ["passwords", "credit cards", "bank accounts",
                "social security numbers", "phone numbers"]
        self.assertEqual(risk.finding_risk(many, "high"), 90)
        self.assertEqual(risk.finding_risk(many, "low"), 45)
        # Unknown reliability scales as low, never crashes.
        self.assertEqual(risk.finding_risk(["passwords"], "???"), 22)


# ---------------------------------------------------------------------------
# Normalization + evidence
# ---------------------------------------------------------------------------

class TestNormalize(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._env = EnvGuard(("VAULT_LOOKUP_KEY",)).__enter__()
        os.environ["VAULT_LOOKUP_KEY"] = base64.b64encode(
            b"\x01" * 32).decode()

    @classmethod
    def tearDownClass(cls):
        cls._env.__exit__()

    def test_email_findings_shape(self):
        findings = normalize.email_findings(
            "XposedOrNot", "ident-1", "email", "breached@example.com",
            ["MockBreach2024", "MockComboList"],
            {"exposed_data": ["email addresses", "passwords"]})
        self.assertEqual(len(findings), 2)
        for f in findings:
            self.assertEqual(f["confidence"], "exact")
            self.assertEqual(f["reliability"], "high")
            self.assertEqual(f["exposed_fields"],
                             ["email addresses", "passwords"])
            self.assertFalse(f["remediation_eligible"])
            self.assertEqual(len(f["evidence_ref"]), 64)
            int(f["evidence_ref"], 16)  # valid hex
        names = {f["source_name"] for f in findings}
        self.assertEqual(names, {"MockBreach2024", "MockComboList"})

    def test_evidence_payload_excludes_raw_identifier(self):
        email = "breached@example.com"
        findings = normalize.email_findings(
            "XposedOrNot", "ident-1", "email", email,
            ["MockBreach2024"], {"exposed_data": ["passwords"]})
        f = findings[0]
        payload = normalize.evidence_payload(
            "XposedOrNot", "MockBreach2024", "email", f["identifier_hmac"],
            {"breach": "MockBreach2024", "exposed_fields": ["passwords"]})
        self.assertEqual(normalize.canonical_evidence_ref(payload),
                         f["evidence_ref"])
        blob = json.dumps(payload)
        self.assertNotIn(email, blob)
        self.assertNotIn("breached@", blob)
        # The raw value appears NOWHERE in the finding either.
        self.assertNotIn(email, json.dumps(findings))

    def test_no_analytics_means_no_invented_fields(self):
        findings = normalize.email_findings(
            "XposedOrNot", "ident-1", "email", "x@example.com",
            ["SomeBreach"], None)
        self.assertEqual(findings[0]["exposed_fields"], [])
        self.assertEqual(
            findings[0]["details"]["exposed_data_attribution"], "none")

    def test_password_finding_carries_count_only(self):
        f = normalize.password_finding(
            "Have I Been Pwned Pwned Passwords", None, 52372427)
        self.assertEqual(f["identifier_kind"], "password")
        self.assertEqual(f["exposed_fields"], ["password"])
        self.assertEqual(f["details"], {"pwned_count": 52372427})
        self.assertIsNone(f["identifier_hmac"])
        self.assertEqual(f["reliability"], "high")
        blob = json.dumps(f)
        self.assertNotIn(hashlib.sha1(b"password").hexdigest().upper(),
                         blob)
        self.assertNotIn("suffix", blob.lower())


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def _finding(identifier_id, kind, hmac_hex, source):
    return {"identifier_id": identifier_id, "identifier_kind": kind,
            "identifier_hmac": hmac_hex, "identifier_masked": "x•••",
            "source_name": source}


class TestCorrelation(unittest.TestCase):
    def test_shared_source_note(self):
        findings = [
            _finding("a", "email", "aa" * 32, "SharedFixtureBreach"),
            _finding("b", "email", "bb" * 32, "SharedFixtureBreach"),
            _finding("a", "email", "aa" * 32, "OnlyA"),
        ]
        out = correlation.correlate(findings)
        self.assertEqual(len(out["clusters"]), 2)
        cluster_a = [c for c in out["clusters"]
                     if c["identifier_id"] == "a"][0]
        self.assertEqual(cluster_a["cluster_id"], ("aa" * 32)[:12])
        self.assertEqual(cluster_a["finding_count"], 2)
        self.assertEqual(len(out["correlations"]), 1)
        note = out["correlations"][0]
        self.assertEqual(note["type"], "shared_source")
        self.assertEqual(note["source_name"], "SharedFixtureBreach")
        self.assertEqual(note["identifier_kinds"], ["email"])
        self.assertEqual(note["confidence"], "probable")
        self.assertIn("SharedFixtureBreach", note["reason"])

    def test_no_sharing_no_notes(self):
        findings = [
            _finding("a", "email", "aa" * 32, "OnlyA"),
            _finding("a", "email", "aa" * 32, "AlsoOnlyA"),
        ]
        out = correlation.correlate(findings)
        self.assertEqual(out["correlations"], [])
        self.assertEqual(len(out["clusters"]), 1)


# ---------------------------------------------------------------------------
# No-database layer
# ---------------------------------------------------------------------------

class TestScansUnavailable(ServerMixin, unittest.TestCase):
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

    def test_create_csrf_first_then_503(self):
        status, _h, body = self.request_json(
            "POST", "/api/scans", body={"idempotency_key": "k1"})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "csrf_failed")
        status, _h, body = self.request_json(
            "POST", "/api/scans", body={"idempotency_key": "k1"},
            headers=CSRF)
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "db_unavailable")

    def test_reads_503(self):
        for path in ("/api/scans", "/api/scans/%s" % uuid.uuid4()):
            status, _h, body = self.request_json("GET", path)
            self.assertEqual(status, 503, path)
            self.assertEqual(body["error"]["code"], "db_unavailable", path)


# ---------------------------------------------------------------------------
# Full flow against a local PostgreSQL (pgserver) + mock providers
# ---------------------------------------------------------------------------

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestScanningDb(ServerMixin, unittest.TestCase):
    PASSWORD = "correct-horse-9"

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._env = EnvGuard(ENV_KEYS + ("LEAKGUARD_PROVIDERS",)).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-scanning-pg-")
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
        os.environ["LEAKGUARD_PROVIDERS"] = "mock"
        registry_mod.reset_registry()
        from db import migrate, pool

        cls.pool = pool
        pool.reset_probe_cache()
        if not pool.db_available():
            cls._teardown_pg()
            raise unittest.SkipTest("local PostgreSQL not reachable")
        migrate.run_migrations()
        from scanning import worker

        cls.worker = worker
        cls.start_server()

    @classmethod
    def _teardown_pg(cls):
        try:
            cls._pg.cleanup()
        except Exception:
            pass
        import shutil

        shutil.rmtree(cls._pg_dir, ignore_errors=True)
        registry_mod.reset_registry()
        cls._env.__exit__()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls.pool.reset_probe_cache()
        cls._teardown_pg()

    def setUp(self):
        ratelimit.reset()

    # ---------- helpers ----------
    def unique_email(self):
        return "scan-%s@example.com" % uuid.uuid4().hex[:16]

    def unique_detail_email(self):
        """A globally unique identifier value (the vault allows one
        owner per kind+value) that the mock treats as clean."""
        return "detail-%s@example.com" % uuid.uuid4().hex[:16]

    def register(self):
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": self.unique_email(), "password": self.PASSWORD},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"]

    def add_identifier(self, cookie, kind, value):
        status, _h, body = self.request_json(
            "POST", "/api/identifiers", body={"kind": kind, "value": value},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        return body["identifier"]

    def grant_scanning(self, cookie):
        status, _h, body = self.request_json(
            "POST", "/api/consents",
            body={"purpose": "scanning", "granted": True},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)

    def create_job(self, cookie, key=None):
        return self.request_json(
            "POST", "/api/scans",
            body={"idempotency_key": key or uuid.uuid4().hex},
            headers=CSRF, cookie=cookie)

    def get_job(self, cookie, job_id):
        return self.request_json("GET", "/api/scans/" + job_id, cookie=cookie)

    def run_until_done(self, cookie, job_id):
        """Drive the worker (no thread in tests) until this job is
        terminal; other queued jobs drain along the way."""
        for _ in range(50):
            status, _h, body = self.get_job(cookie, job_id)
            self.assertEqual(status, 200, body)
            if body["job"]["status"] in ("done", "dead"):
                return body
            self.assertTrue(self.worker.run_once(),
                            "worker had nothing to claim")
        self.fail("job never finished")

    def ready_user(self, identifiers):
        cookie, _uid = self.register()
        for kind, value in identifiers:
            self.add_identifier(cookie, kind, value)
        self.grant_scanning(cookie)
        return cookie

    # ---------- API gates ----------
    def test_consent_gate_then_idempotent_create(self):
        cookie, _uid = self.register()
        self.add_identifier(cookie, "email", self.unique_detail_email())
        status, _h, body = self.create_job(cookie, key="gate-1")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "consent_required")

        self.grant_scanning(cookie)
        status, _h, body = self.create_job(cookie, key="gate-1")
        self.assertEqual(status, 201, body)
        job_id = body["job"]["id"]
        self.assertEqual(body["job"]["status"], "queued")

        # Same key again: same job, 200, and still exactly one row.
        status, _h, body = self.create_job(cookie, key="gate-1")
        self.assertEqual(status, 200)
        self.assertEqual(body["job"]["id"], job_id)
        status, _h, body = self.request_json("GET", "/api/scans",
                                             cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual([j["id"] for j in body["jobs"]], [job_id])

    def test_no_identifiers_400(self):
        cookie, _uid = self.register()
        self.grant_scanning(cookie)
        status, _h, body = self.create_job(cookie)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "no_identifiers")

    def test_idor_job_read_and_list(self):
        cookie_a = self.ready_user([("email", self.unique_detail_email())])
        _s, _h, body = self.create_job(cookie_a)
        job_id = body["job"]["id"]

        cookie_b, _uid_b = self.register()
        status, _h, body = self.get_job(cookie_b, job_id)
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")
        status, _h, body = self.request_json("GET", "/api/scans",
                                             cookie=cookie_b)
        self.assertEqual(body["jobs"], [])
        # A random uuid is the same 404 for the owner too.
        status, _h, _b = self.get_job(cookie_a, str(uuid.uuid4()))
        self.assertEqual(status, 404)

    # ---------- orchestrator end-to-end ----------
    def test_orchestrator_e2e_mock_breached_and_phone(self):
        cookie = self.ready_user([
            ("email", "breached@example.com"),
            ("phone", "+91 98100 12345"),
        ])
        _s, _h, body = self.create_job(cookie)
        job_id = body["job"]["id"]
        result = self.run_until_done(cookie, job_id)

        job = result["job"]
        self.assertEqual(job["status"], "done")
        self.assertEqual(job["score"], 72)  # mock analytics risk_score
        self.assertTrue(job["score_explanation"])
        self.assertTrue(any("72" in line
                            for line in job["score_explanation"]))
        self.assertFalse(job["summary"]["degraded"])
        self.assertEqual(job["summary"]["findings_total"], 2)

        outcomes = {o["kind"]: o for o in job["summary"]["identifiers"]}
        self.assertEqual(outcomes["email"]["outcome"], "scanned")
        self.assertEqual(outcomes["email"]["findings"], 2)
        # Stage S6: phones now HAVE a provider (public-web discovery).
        # This number is not the mock fixture number, so the honest
        # result is "scanned" with zero candidate mentions — the S5
        # "no_provider_yet" assertion pinned the pre-S6 world.
        self.assertEqual(outcomes["phone"]["outcome"], "scanned")
        self.assertEqual(outcomes["phone"]["findings"], 0)

        findings = result["findings"]
        self.assertEqual(len(findings), 2)
        self.assertEqual({f["source_name"] for f in findings},
                         {"MockBreach2024", "MockComboList"})
        for f in findings:
            self.assertEqual(f["provider"], "MockProvider")
            self.assertEqual(f["confidence"], "exact")
            self.assertEqual(f["identifier_kind"], "email")
            self.assertEqual(f["identifier_masked"], "b•••@example.com")
            self.assertEqual(f["exposed_fields"],
                             ["email addresses", "passwords"])
            # MockProvider reliability is "low" by design, so the
            # rubric scores (5 + 45) x 0.5 = 25.
            self.assertEqual(f["reliability"], "low")
            self.assertEqual(f["risk"], 25)
            self.assertEqual(len(f["evidence_ref"]), 64)
        # The raw identifier value appears NOWHERE in the response.
        self.assertNotIn("breached@example.com", json.dumps(result))

    def test_clean_email_scores_zero(self):
        # Any non-fixture address is clean in mock mode.
        cookie = self.ready_user([("email", self.unique_detail_email())])
        _s, _h, body = self.create_job(cookie)
        result = self.run_until_done(cookie, body["job"]["id"])
        self.assertEqual(result["job"]["status"], "done")
        self.assertEqual(result["job"]["score"], 0)
        self.assertEqual(result["findings"], [])
        self.assertTrue(any("No points" in line for line in
                            result["job"]["score_explanation"]))

    def test_correlation_shared_source(self):
        cookie = self.ready_user([
            ("email", "shared-a@example.com"),
            ("email", "shared-b@example.com"),
        ])
        _s, _h, body = self.create_job(cookie)
        result = self.run_until_done(cookie, body["job"]["id"])
        job = result["job"]
        self.assertEqual(job["status"], "done")
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual(len(job["summary"]["clusters"]), 2)
        notes = job["summary"]["correlations"]
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["type"], "shared_source")
        self.assertEqual(notes[0]["source_name"], "SharedFixtureBreach")
        self.assertEqual(notes[0]["identifier_kinds"], ["email"])
        self.assertEqual(notes[0]["confidence"], "probable")

    # ---------- worker machinery ----------
    def test_stale_running_job_requeued(self):
        cookie, uid = self.register()
        self.add_identifier(cookie, "email", self.unique_detail_email())
        self.grant_scanning(cookie)
        _s, _h, body = self.create_job(cookie)
        job_id = body["job"]["id"]
        with self.pool.connection() as conn:
            conn.execute(
                "UPDATE scan_jobs SET status = 'running',"
                " started_at = now() - interval '11 minutes'"
                " WHERE id = %s", (job_id,))
        self.assertEqual(self.worker.requeue_stale(), 1)
        status, _h, body = self.get_job(cookie, job_id)
        self.assertEqual(body["job"]["status"], "queued")
        with self.pool.connection() as conn:
            conn.execute("DELETE FROM scan_jobs WHERE id = %s", (job_id,))

    def test_worker_retries_then_dead(self):
        # Drain anything queued so the poison patch can only hit
        # this test's own job.
        while self.worker.run_once():
            pass
        cookie = self.ready_user([("email", self.unique_detail_email())])
        _s, _h, body = self.create_job(cookie)
        job_id = body["job"]["id"]

        from scanning import orchestrator

        original = orchestrator.run_scan_job

        def poison(_job_id):
            raise RuntimeError("boom")

        orchestrator.run_scan_job = poison
        try:
            for attempt in (1, 2, 3):
                self.assertTrue(self.worker.run_once())
                status, _h, body = self.get_job(cookie, job_id)
                job = body["job"]
                self.assertEqual(job["attempts"], attempt)
                self.assertEqual(job["error_kind"], "RuntimeError")
                if attempt < 3:
                    self.assertEqual(job["status"], "failed")
                    with self.pool.connection() as conn:
                        conn.execute(
                            "UPDATE scan_jobs SET next_attempt_at ="
                            " now() - interval '1 second' WHERE id = %s",
                            (job_id,))
                else:
                    self.assertEqual(job["status"], "dead")
        finally:
            orchestrator.run_scan_job = original


if __name__ == "__main__":
    unittest.main()
