"""Action Center tests (Stage S9 — spec Phases 57–62, 67).

Layers:

* TestScoreBand / TestNextAction — offline: the plain-language
  score band, and the next_action priority as a pure decision over
  a hand-built state dict (every branch, including the honest
  enable_removal alternative when the Automatic removal permission
  is off).
* TestActionCenterUnavailable — no database: the route answers the
  same clean 503 as every other account route.
* TestActionCenterDb — the full aggregate against a local
  PostgreSQL provisioned with pip `pgserver` (skips honestly when
  pgserver or Postgres is unavailable) with mock providers and the
  broker registry seeded: states are built through the real API
  (register → identifiers → consents → scan jobs run by the real
  worker → the one removal command), so the aggregate is verified
  against the same rows the rest of the product produces.

No plaintext passwords are printed; test accounts use unique
example.com addresses.

Run:  python3 -m unittest discover -s tests
"""

import base64
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
from dashboard import service as ac_service  # noqa: E402
from providers import registry as registry_mod  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")


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
# Pure pieces: band + the next_action decision
# ---------------------------------------------------------------------------

def _state(**overrides):
    state = {
        "identifiers": 1,
        "latest_job": {"id": "job-1"},
        "scan_in_progress": False,
        "findings_total": 0,
        "removal_pending": False,
        "remediation_on": False,
        "monitoring_on": False,
        "cases": {s: 0 for s in ac_service._CASE_STATUSES},
    }
    state.update(overrides)
    return state


class TestScoreBand(unittest.TestCase):
    def test_bands_match_the_quick_scan_thresholds(self):
        self.assertIsNone(ac_service.score_band(None))
        self.assertEqual(ac_service.score_band(0), "No exposure found")
        self.assertEqual(ac_service.score_band(1), "Some exposure")
        self.assertEqual(ac_service.score_band(34), "Some exposure")
        self.assertEqual(ac_service.score_band(35), "Serious exposure")
        self.assertEqual(ac_service.score_band(69), "Serious exposure")
        self.assertEqual(ac_service.score_band(70), "Critical exposure")
        self.assertEqual(ac_service.score_band(100), "Critical exposure")


class TestNextAction(unittest.TestCase):
    def test_a_add_details_first(self):
        out = ac_service._next_action(_state(identifiers=0))
        self.assertEqual(out["kind"], "add_details")
        self.assertEqual(out["label"], "Add your details to start")

    def test_b_scan_now(self):
        out = ac_service._next_action(_state(latest_job=None))
        self.assertEqual(out["kind"], "scan_now")

    def test_b_first_scan_in_flight_is_scanning_not_scan_now(self):
        out = ac_service._next_action(
            _state(latest_job=None, scan_in_progress=True))
        self.assertEqual(out["kind"], "scanning")

    def test_c_remove_all(self):
        out = ac_service._next_action(_state(
            findings_total=3, removal_pending=True, remediation_on=True))
        self.assertEqual(out["kind"], "remove_all")
        self.assertEqual(out["label"], "Remove my data everywhere")

    def test_c_consent_off_is_enable_removal_never_remove_all(self):
        out = ac_service._next_action(_state(
            findings_total=3, removal_pending=True, remediation_on=False))
        self.assertEqual(out["kind"], "enable_removal")
        self.assertEqual(out["label"], "Turn on automatic removal")

    def test_c_full_coverage_falls_through(self):
        # Findings exist but every broker already has a live case:
        # there is nothing new for the one command to open.
        out = ac_service._next_action(_state(
            findings_total=3, removal_pending=False, remediation_on=True,
            monitoring_on=True))
        self.assertEqual(out["kind"], "all_clear")

    def test_d_review_queue_beats_scanning_and_monitoring(self):
        cases = {s: 0 for s in ac_service._CASE_STATUSES}
        cases["needs_human"] = 2
        out = ac_service._next_action(_state(
            cases=cases, scan_in_progress=True))
        self.assertEqual(out["kind"], "review_queue")
        self.assertEqual(out["label"],
                         "2 removals need one step from you")

    def test_d_review_queue_singular_wording(self):
        cases = {s: 0 for s in ac_service._CASE_STATUSES}
        cases["needs_human"] = 1
        out = ac_service._next_action(_state(cases=cases))
        self.assertEqual(out["label"],
                         "1 removal needs one step from you")

    def test_e_scanning(self):
        out = ac_service._next_action(_state(scan_in_progress=True))
        self.assertEqual(out["kind"], "scanning")

    def test_f_enable_monitoring(self):
        out = ac_service._next_action(_state(monitoring_on=False))
        self.assertEqual(out["kind"], "enable_monitoring")

    def test_g_all_clear_only_when_monitoring_on(self):
        out = ac_service._next_action(_state(monitoring_on=True))
        self.assertEqual(out["kind"], "all_clear")
        self.assertIn("monitoring keeps watch", out["label"])


# ---------------------------------------------------------------------------
# No-database layer
# ---------------------------------------------------------------------------

class TestActionCenterUnavailable(ServerMixin, unittest.TestCase):
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

    def test_action_center_503_without_database(self):
        status, _h, body = self.request_json("GET", "/api/action-center")
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "db_unavailable")


# ---------------------------------------------------------------------------
# Full aggregate against a local PostgreSQL (pgserver) + mock providers
# ---------------------------------------------------------------------------

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


@unittest.skipUnless(_pgserver, "pgserver not installed")
class ActionCenterDbBase(ServerMixin):
    """pgserver provisioning + API helpers shared by the DB test
    classes. NOT a TestCase itself: each subclass gets a FRESH
    database, because the identifier vault enforces one owner per
    identifier value — the mock fixtures (breached@example.com,
    shared-a@, shared-b@) can each be saved by exactly one account
    per database, so findings-scan tests are spread across classes
    to give each fixture a single owner per class."""

    PASSWORD = "correct-horse-9"

    @classmethod
    def setUpClass(cls):
        import tempfile

        keys = ENV_KEYS + ("LEAKGUARD_PROVIDERS",)
        cls._env = EnvGuard(keys).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-action-center-pg-")
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
        from remediation import registry_seed
        from scanning import worker

        cls.pool = pool
        cls.scan_worker = worker
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
    def uniq(self):
        return uuid.uuid4().hex[:12]

    def register(self):
        email = "ac-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": self.PASSWORD, "policy_accepted": True},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"], email

    def add_identifier(self, cookie, kind, value):
        status, _h, body = self.request_json(
            "POST", "/api/identifiers", body={"kind": kind, "value": value},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        return body["identifier"]

    def set_consent(self, cookie, purpose, granted):
        status, _h, body = self.request_json(
            "POST", "/api/consents",
            body={"purpose": purpose, "granted": granted},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)

    def action_center(self, cookie):
        status, _h, body = self.request_json(
            "GET", "/api/action-center", cookie=cookie)
        self.assertEqual(status, 200, body)
        return body

    def create_job(self, cookie):
        status, _h, body = self.request_json(
            "POST", "/api/scans",
            body={"idempotency_key": uuid.uuid4().hex},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        return body["job"]["id"]

    def run_until_done(self, cookie, job_id):
        for _ in range(50):
            status, _h, body = self.request_json(
                "GET", "/api/scans/" + job_id, cookie=cookie)
            self.assertEqual(status, 200, body)
            if body["job"]["status"] in ("done", "dead"):
                return body
            self.assertTrue(self.scan_worker.run_once(),
                            "worker had nothing to claim")
        self.fail("job never finished")

    def scan(self, cookie, identifiers):
        """Identifiers + scanning consent + one completed job."""
        saved = [self.add_identifier(cookie, k, v)
                 for k, v in identifiers]
        self.set_consent(cookie, "scanning", True)
        job = self.create_job(cookie)
        result = self.run_until_done(cookie, job)
        self.assertEqual(result["job"]["status"], "done")
        return saved, result

    def db_exec(self, sql, params=()):
        with self.pool.connection() as conn:
            conn.execute(sql, params)

class TestActionCenterDb(ActionCenterDbBase, unittest.TestCase):
    # ---------- route guards ----------
    def test_unauthenticated_is_401(self):
        status, _h, body = self.request_json("GET", "/api/action-center")
        self.assertEqual(status, 401, body)
        self.assertEqual(body["error"]["code"], "unauthenticated")

    # ---------- branch (a): fresh user ----------
    def test_fresh_user_add_details_and_empty_aggregate(self):
        cookie, _uid, _email = self.register()
        ac = self.action_center(cookie)
        self.assertIsNone(ac["exposure"]["score"])
        self.assertIsNone(ac["exposure"]["band"])
        self.assertIsNone(ac["exposure"]["delta"])
        self.assertIsNone(ac["exposure"]["scored_at"])
        self.assertEqual(ac["exposure"]["findings_total"], 0)
        self.assertEqual(ac["counts"]["identifiers"], 0)
        self.assertEqual(ac["counts"]["cases"],
                         {s: 0 for s in ac_service._CASE_STATUSES})
        self.assertFalse(ac["scan_in_progress"])
        self.assertFalse(ac["monitoring_on"])
        self.assertEqual(ac["next_action"]["kind"], "add_details")
        self.assertEqual(ac["next_action"]["label"],
                         "Add your details to start")
        self.assertEqual(ac["recent"], [])
        self.assertEqual(self.seeded, 40)

    # ---------- branch (b): identifiers, no scan ----------
    def test_scan_now_after_first_identifier(self):
        cookie, _uid, _email = self.register()
        self.add_identifier(cookie, "email",
                            "clean-%s@example.com" % self.uniq())
        ac = self.action_center(cookie)
        self.assertEqual(ac["counts"]["identifiers"], 1)
        self.assertIsNone(ac["exposure"]["score"])
        self.assertEqual(ac["next_action"]["kind"], "scan_now")

    # ---------- branch (c): findings + consent on -> remove_all ----------
    def test_remove_all_and_coverage_completion(self):
        cookie, uid, _email = self.register()
        _saved, result = self.scan(cookie, [("email", "breached@example.com")])
        self.assertEqual(len(result["findings"]), 2)
        self.set_consent(cookie, "automated_remediation", True)

        ac = self.action_center(cookie)
        self.assertEqual(ac["exposure"]["score"], 72)
        self.assertEqual(ac["exposure"]["band"], "Critical exposure")
        self.assertIsNone(ac["exposure"]["delta"])  # only one scan yet
        self.assertEqual(ac["exposure"]["findings_total"], 2)
        self.assertEqual(ac["next_action"]["kind"], "remove_all")
        self.assertEqual(ac["next_action"]["label"],
                         "Remove my data everywhere")
        # Recent activity is the user's own timeline (scan + findings).
        types = [e["type"] for e in ac["recent"]]
        self.assertIn("scan_completed", types)
        self.assertIn("finding_found", types)
        self.assertLessEqual(len(ac["recent"]), 5)

        # The one command: a case per broker. Coverage is now
        # complete, so remove_all must NOT be recommended again.
        status, _h, body = self.request_json(
            "POST", "/api/remediation/run", body={},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["cases_created"], 40)
        ac = self.action_center(cookie)
        self.assertEqual(ac["counts"]["cases"]["queued"], 40)
        self.assertEqual(sum(ac["counts"]["cases"].values()), 40)
        self.assertNotEqual(ac["next_action"]["kind"], "remove_all")
        self.assertEqual(ac["next_action"]["kind"], "enable_monitoring")

    # ---------- branch (c'): findings + consent OFF -> enable_removal ----
    def test_enable_removal_when_consent_off(self):
        cookie, _uid, _email = self.register()
        # shared-a is this class's second findings fixture (one
        # finding, score 8) — breached@ belongs to the remove_all
        # test above; the vault allows one owner per value.
        self.scan(cookie, [("email", "shared-a@example.com")])
        # automated_remediation consent stays OFF.
        ac = self.action_center(cookie)
        self.assertEqual(ac["exposure"]["findings_total"], 1)
        self.assertEqual(ac["next_action"]["kind"], "enable_removal")
        self.assertEqual(ac["next_action"]["label"],
                         "Turn on automatic removal")
        self.assertNotEqual(ac["next_action"]["kind"], "remove_all")

    # ---------- branch (e): a scan is in flight ----------
    def test_scanning_branch(self):
        cookie, _uid, _email = self.register()
        self.scan(cookie, [("email",
                            "clean-%s@example.com" % self.uniq())])
        self.create_job(cookie)  # queued, deliberately never run
        ac = self.action_center(cookie)
        self.assertTrue(ac["scan_in_progress"])
        self.assertEqual(ac["next_action"]["kind"], "scanning")

    # ---------- branch (f): nothing pending, monitoring off ----------
    def test_enable_monitoring_branch(self):
        cookie, _uid, _email = self.register()
        self.scan(cookie, [("email",
                            "clean-%s@example.com" % self.uniq())])
        ac = self.action_center(cookie)
        self.assertFalse(ac["monitoring_on"])
        self.assertEqual(ac["next_action"]["kind"], "enable_monitoring")

    # ---------- branch (g): covered ----------
    def test_all_clear_branch(self):
        cookie, _uid, _email = self.register()
        self.scan(cookie, [("email",
                            "clean-%s@example.com" % self.uniq())])
        self.set_consent(cookie, "monitoring", True)
        ac = self.action_center(cookie)
        self.assertTrue(ac["monitoring_on"])
        self.assertEqual(ac["next_action"]["kind"], "all_clear")
        self.assertIn("covered", ac["next_action"]["label"])

    # ---------- IDOR: B sees none of A ----------
    def test_idor_isolation(self):
        cookie_a, _uid_a, _e = self.register()
        # shared-b is this class's third findings fixture (the
        # vault allows one owner per identifier value).
        self.scan(cookie_a, [("email", "shared-b@example.com"),
                             ("email",
                              "clean-%s@example.com" % self.uniq())])
        self.set_consent(cookie_a, "automated_remediation", True)
        status, _h, _b = self.request_json(
            "POST", "/api/remediation/run", body={},
            headers=CSRF, cookie=cookie_a)
        self.assertEqual(status, 200)
        ac_a = self.action_center(cookie_a)
        self.assertEqual(ac_a["counts"]["identifiers"], 2)
        self.assertGreater(ac_a["exposure"]["findings_total"], 0)
        self.assertEqual(sum(ac_a["counts"]["cases"].values()), 40)

        cookie_b, _uid_b, _e = self.register()
        ac_b = self.action_center(cookie_b)
        self.assertEqual(ac_b["counts"]["identifiers"], 0)
        self.assertIsNone(ac_b["exposure"]["score"])
        self.assertEqual(ac_b["exposure"]["findings_total"], 0)
        self.assertEqual(ac_b["counts"]["cases"],
                         {s: 0 for s in ac_service._CASE_STATUSES})
        self.assertEqual(ac_b["recent"], [])
        self.assertEqual(ac_b["next_action"]["kind"], "add_details")


class TestActionCenterDbHistory(ActionCenterDbBase, unittest.TestCase):
    """A second fresh database for the two tests that need their
    own fixture owners: the score-delta test owns breached@ here,
    and the review-queue test builds its state from a clean scan
    plus the one removal command."""

    # ---------- score delta across two scans ----------
    def test_score_delta_and_band_after_second_scan(self):
        cookie, _uid, _email = self.register()
        saved, result = self.scan(cookie, [("email", "breached@example.com")])
        self.assertEqual(result["job"]["score"], 72)

        # Remove the breached address, save a clean one, scan again.
        status, _h, _b = self.request(
            "DELETE", "/api/identifiers/" + saved[0]["id"],
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200)
        self.add_identifier(cookie, "email",
                            "clean-%s@example.com" % self.uniq())
        job2 = self.create_job(cookie)
        result2 = self.run_until_done(cookie, job2)
        self.assertEqual(result2["job"]["score"], 0)

        ac = self.action_center(cookie)
        self.assertEqual(ac["exposure"]["score"], 0)
        self.assertEqual(ac["exposure"]["band"], "No exposure found")
        self.assertEqual(ac["exposure"]["delta"], -72)
        self.assertEqual(ac["exposure"]["findings_total"], 0)

    # ---------- branch (d): a case needs the human ----------
    def test_review_queue_branch(self):
        cookie, uid, _email = self.register()
        self.scan(cookie, [("email",
                            "clean-%s@example.com" % self.uniq())])
        self.set_consent(cookie, "automated_remediation", True)
        status, _h, body = self.request_json(
            "POST", "/api/remediation/run", body={},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["cases_created"], 40)
        # The worker parked one case on a CAPTCHA (the state the
        # Stage S7 stub-executor tests produce for such brokers).
        # Coverage is complete (40 live cases), so branch (c) is
        # passed and the queue is what needs the user.
        self.db_exec(
            "UPDATE remediation_cases SET status = 'needs_human',"
            " reason = 'captcha' WHERE id = ("
            "  SELECT id FROM remediation_cases WHERE user_id = %s"
            "  ORDER BY created_at, id LIMIT 1)", (uid,))

        ac = self.action_center(cookie)
        self.assertEqual(ac["counts"]["cases"]["needs_human"], 1)
        self.assertEqual(ac["counts"]["cases"]["queued"], 39)
        self.assertEqual(ac["next_action"]["kind"], "review_queue")
        self.assertIn("1 removal", ac["next_action"]["label"])
        self.assertIn("one step from you", ac["next_action"]["label"])
