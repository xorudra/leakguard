"""Stored finding lifecycle tests (spec Phase 25; migration 0012).

The lifecycle state (open / resolved / reappeared) used to be
derived per read from consecutive scan jobs. It is now STORED on
findings (lifecycle_state + lifecycle_changed_at) and written by
exactly one writer — monitoring/diff.py's apply_lifecycle() (scan
completion) and resolve_for_broker() (remediation verified
removal). These tests pin:

* TestBrokerMatcher — offline: the conservative broker<->finding
  matcher both the reappearance wiring and the writer share.
* TestLifecycleFullFlow — the real pipeline (API + worker + mock
  providers): a finding is born 'open' with a stamp; when its
  identifier leaves the profile and a cycle completes without it,
  the stored state becomes 'resolved'; the Action Center count
  and the scan-detail payload read the stored values.
* TestLifecycleTransitions — hand-built completed jobs driven
  through the real completion hook: the full transition matrix
  (open -> resolved -> reappeared -> resolved), the stamp moving
  ONLY on real changes, no-change cycles and idempotent re-runs
  moving nothing, failed/stale jobs changing nothing, readers
  reflecting a value flipped directly in SQL (no derivation left
  on the read path), and a remediation verified removal resolving
  findings — which the next scan then reappears, case included.
* TestLifecycleMigrationUpgrade — migration 0012 applied by the
  real runner on top of a database that already ran 0001-0011:
  the backfill resolves exactly the two expressible classes
  (absent from the latest completed job; name/slug-matched to a
  verified_removed case) and leaves everything else 'open'.

Run:  python3 -m pytest tests/test_finding_lifecycle.py
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
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402
from accounts import ratelimit  # noqa: E402
from dashboard import service as ac_service  # noqa: E402
from monitoring import diff, events  # noqa: E402
from providers import registry as registry_mod  # noqa: E402
from scanning import jobs as jobs_service  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")
LANE_KEYS = ("BREVO_API_KEY", "NOTIFY_FROM_EMAIL", "NOTIFY_FROM_NAME")


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
# Offline: the shared broker matcher
# ---------------------------------------------------------------------------

class TestBrokerMatcher(unittest.TestCase):
    BROKER = {"name": "Spokeo", "slug": "spokeo",
              "optout_url": "https://www.spokeo.com/optout",
              "search_url": "https://www.spokeo.com/search"}

    def test_name_and_slug_match(self):
        self.assertTrue(diff.broker_matches_finding(
            self.BROKER, {"source_name": "Spokeo", "source_url": None}))
        self.assertTrue(diff.broker_matches_finding(
            self.BROKER, {"source_name": "spokeo", "source_url": None}))

    def test_host_and_subdomain_match(self):
        self.assertTrue(diff.broker_matches_finding(
            self.BROKER, {"source_name": "Some Listing Site",
                          "source_url": "https://www.spokeo.com/x"}))
        bare = dict(self.BROKER, optout_url="https://spokeo.com/optout",
                    search_url="https://spokeo.com/search")
        self.assertTrue(diff.broker_matches_finding(
            bare, {"source_name": "Some Listing Site",
                   "source_url": "https://people.spokeo.com/x"}))

    def test_no_match(self):
        self.assertFalse(diff.broker_matches_finding(
            self.BROKER, {"source_name": "TruthFinder",
                          "source_url": "https://truthfinder.com/x"}))
        self.assertFalse(diff.broker_matches_finding(
            self.BROKER, {"source_name": "NotSpokeo",
                          "source_url": "https://notspokeo.com/x"}))
        self.assertFalse(diff.broker_matches_finding(
            self.BROKER, {"source_name": "", "source_url": None}))


# ---------------------------------------------------------------------------
# pgserver harness (the pattern of tests/test_monitoring.py)
# ---------------------------------------------------------------------------

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


class PgClassMixin:
    @classmethod
    def _boot_pg(cls, prefix, providers_mock=False, migrate_fully=True):
        import tempfile

        keys = ENV_KEYS + LANE_KEYS + (("LEAKGUARD_PROVIDERS",)
                                        if providers_mock else ())
        cls._env = EnvGuard(keys).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix=prefix)
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
        for key in LANE_KEYS:
            os.environ.pop(key, None)
        if providers_mock:
            os.environ["LEAKGUARD_PROVIDERS"] = "mock"
            registry_mod.reset_registry()
        from db import migrate, pool

        cls.pool = pool
        cls.migrate = migrate
        pool.reset_probe_cache()
        if not pool.db_available():
            cls._teardown_pg()
            raise unittest.SkipTest("local PostgreSQL not reachable")
        if migrate_fully:
            migrate.run_migrations()

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

    # ----- DB helpers -----
    def db_row(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchone()

    def db_rows(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchall()

    def db_exec(self, sql, params=()):
        with self.pool.connection() as conn:
            conn.execute(sql, params)

    # ----- hand-built scan rows -----
    def insert_job(self, user_id, finished_at, status="done", score=10):
        row = self.db_row(
            "INSERT INTO scan_jobs (user_id, idempotency_key, status,"
            " score, created_at, finished_at)"
            " VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
            (user_id, uuid.uuid4().hex, status, score,
             finished_at, finished_at if status == "done" else None))
        return str(row["id"])

    def insert_finding(self, job_id, user_id, identifier_id,
                       source_name, provider="FixtureProvider",
                       source_url=None):
        row = self.db_row(
            "INSERT INTO findings (job_id, user_id, identifier_id,"
            " identifier_kind, provider, source_name, source_url,"
            " exposed_fields, confidence, reliability, evidence_ref)"
            " VALUES (%s, %s, %s, 'email', %s, %s, %s, '{}', 'exact',"
            " 'high', %s) RETURNING id",
            (job_id, user_id, identifier_id, provider, source_name,
             source_url, "e" * 64))
        return str(row["id"])

    def identity_state(self, user_id, identifier_id, source_name):
        """The ONE (lifecycle_state, lifecycle_changed_at) pair an
        identity carries — asserting every row agrees is part of
        the check (the writer's canonical invariant)."""
        rows = self.db_rows(
            "SELECT DISTINCT lifecycle_state, lifecycle_changed_at"
            " FROM findings WHERE user_id = %s"
            " AND identifier_id IS NOT DISTINCT FROM %s"
            " AND source_name = %s",
            (user_id, identifier_id, source_name))
        self.assertEqual(len(rows), 1,
                         "identity rows disagree: %r" % (rows,))
        return rows[0]["lifecycle_state"], rows[0]["lifecycle_changed_at"]


class AccountMixin:
    PASSWORD = "correct-horse-9"

    def uniq(self):
        return uuid.uuid4().hex[:12]

    def register(self):
        email = "lc-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": self.PASSWORD},
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


# ---------------------------------------------------------------------------
# The real pipeline: born open, resolved by a completed absence
# ---------------------------------------------------------------------------

@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestLifecycleFullFlow(PgClassMixin, AccountMixin, ServerMixin,
                            unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._boot_pg("lg-lifecycle-flow-", providers_mock=True)
        from scanning import worker

        cls.scan_worker = worker
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls.pool.reset_probe_cache()
        cls._teardown_pg()

    def setUp(self):
        ratelimit.reset()

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

    def test_born_open_then_resolved_by_completed_absence(self):
        cookie, uid, _email = self.register()
        clean = "clean-%s@example.com" % self.uniq()
        for kind, value in (("email", clean),
                            ("email", "shared-b@example.com")):
            self.add_identifier(cookie, kind, value)
        self.set_consent(cookie, "scanning", True)
        phone = self.add_identifier(cookie, "phone", "+91 99999 99999")

        job1 = self.create_job(cookie)
        result = self.run_until_done(cookie, job1)
        self.assertEqual(len(result["findings"]), 2)
        for finding in result["findings"]:
            self.assertEqual(finding["lifecycle_state"], "open")
            self.assertIsNotNone(finding["lifecycle_changed_at"])
        self.assertEqual(
            ac_service.action_center(uid)["exposure"]["findings_total"],
            2)
        state, stamp1 = self.identity_state(
            uid, phone["id"], "people-fixture.example.com")
        self.assertEqual(state, "open")
        self.assertIsNotNone(stamp1)

        # The phone identifier leaves the profile; the next
        # COMPLETED cycle does not report it -> resolved, stamped.
        status, _h, _b = self.request(
            "DELETE", "/api/identifiers/" + phone["id"],
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200)
        job2 = self.create_job(cookie)
        self.run_until_done(cookie, job2)

        state, stamp2 = self.identity_state(
            uid, phone["id"], "people-fixture.example.com")
        self.assertEqual(state, "resolved")
        self.assertIsNotNone(stamp2)
        self.assertGreaterEqual(stamp2, stamp1)
        # Scan detail for the OLD job reads the stored canonical
        # state too — the phone finding now reports resolved there.
        detail = jobs_service.get_job(uid, job1)
        by_source = {f["source_name"]: f for f in detail["findings"]}
        self.assertEqual(
            by_source["people-fixture.example.com"]["lifecycle_state"],
            "resolved")
        # The Action Center no longer counts it as a current
        # exposure; the still-present breach finding still counts.
        self.assertEqual(
            ac_service.action_center(uid)["exposure"]["findings_total"],
            1)


# ---------------------------------------------------------------------------
# Hand-built cycles: the full transition matrix
# ---------------------------------------------------------------------------

@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestLifecycleTransitions(PgClassMixin, AccountMixin, ServerMixin,
                               unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._boot_pg("lg-lifecycle-matrix-")
        from remediation import registry_seed

        registry_seed.seed_brokers()
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls.pool.reset_probe_cache()
        cls._teardown_pg()

    def setUp(self):
        ratelimit.reset()

    def _user_with_identifier(self):
        cookie, uid, _email = self.register()
        ident = self.add_identifier(
            cookie, "email", "matrix-%s@example.com" % self.uniq())
        return uid, ident["id"]

    def test_transition_matrix(self):
        uid, ident = self._user_with_identifier()
        now = datetime.now(timezone.utc)
        day = timedelta(days=1)

        def cycle(finished_at, sources):
            job_id = self.insert_job(uid, finished_at)
            for source in sources:
                self.insert_finding(job_id, uid, ident, source)
            events.handle_scan_completed(job_id)
            return job_id

        # Cycle 1 (baseline): A and B are born open, stamped.
        cycle(now - 6 * day, ["BreachAlpha", "BreachBeta"])
        state_a, stamp_a1 = self.identity_state(uid, ident, "BreachAlpha")
        state_b, stamp_b1 = self.identity_state(uid, ident, "BreachBeta")
        self.assertEqual((state_a, state_b), ("open", "open"))
        self.assertIsNotNone(stamp_a1)
        self.assertIsNotNone(stamp_b1)

        # Cycle 2: B absent from a completed cycle -> resolved.
        cycle(now - 5 * day, ["BreachAlpha"])
        state_b, stamp_b2 = self.identity_state(uid, ident, "BreachBeta")
        self.assertEqual(state_b, "resolved")
        self.assertGreater(stamp_b2, stamp_b1)
        # A continues: same state, stamp unmoved.
        self.assertEqual(self.identity_state(uid, ident, "BreachAlpha"),
                         ("open", stamp_a1))

        # Cycle 3: nothing changes -> no stamp moves anywhere.
        job3 = cycle(now - 4 * day, ["BreachAlpha"])
        self.assertEqual(self.identity_state(uid, ident, "BreachAlpha"),
                         ("open", stamp_a1))
        self.assertEqual(self.identity_state(uid, ident, "BreachBeta"),
                         ("resolved", stamp_b2))

        # Cycle 4: B is back after resolving -> reappeared.
        cycle(now - 3 * day, ["BreachAlpha", "BreachBeta"])
        state_b, stamp_b4 = self.identity_state(uid, ident, "BreachBeta")
        self.assertEqual(state_b, "reappeared")
        self.assertGreater(stamp_b4, stamp_b2)

        # Cycle 5: B still there -> stays reappeared, stamp unmoved.
        cycle(now - 2 * day, ["BreachAlpha", "BreachBeta"])
        self.assertEqual(self.identity_state(uid, ident, "BreachBeta"),
                         ("reappeared", stamp_b4))

        # Cycle 6: B gone again -> resolved again, stamp moves.
        job6 = cycle(now - 1 * day, ["BreachAlpha"])
        state_b, stamp_b6 = self.identity_state(uid, ident, "BreachBeta")
        self.assertEqual(state_b, "resolved")
        self.assertGreater(stamp_b6, stamp_b4)

        # Re-running the same completion is a no-op for the state.
        out = events.handle_scan_completed(job6)
        self.assertTrue(out["skipped"])
        self.assertEqual(self.identity_state(uid, ident, "BreachBeta"),
                         ("resolved", stamp_b6))
        self.assertEqual(self.identity_state(uid, ident, "BreachAlpha"),
                         ("open", stamp_a1))
        self.assertIsNotNone(job3)  # (built above; silence linters)

    def test_failed_and_stale_jobs_change_nothing(self):
        uid, ident = self._user_with_identifier()
        now = datetime.now(timezone.utc)
        day = timedelta(days=1)

        job1 = self.insert_job(uid, now - 3 * day)
        self.insert_finding(job1, uid, ident, "BreachAlpha")
        events.handle_scan_completed(job1)
        before = self.identity_state(uid, ident, "BreachAlpha")
        self.assertEqual(before[0], "open")

        # A failed job never reaches the diff: the hook refuses it
        # and nothing resolves. (A failed job carries no findings
        # in the real flow — the orchestrator inserts findings only
        # in the transaction that marks the job done.)
        failed = self.insert_job(uid, now - 2 * day, status="failed")
        out = events.handle_scan_completed(failed)
        self.assertEqual(out.get("reason"), "job_not_done")
        self.assertEqual(self.identity_state(uid, ident, "BreachAlpha"),
                         before)

        # A stale completed job (an older world, processed late)
        # must not rewind the state the newer cycles settled: a
        # NEWER completed job exists by the time it is processed.
        job2 = self.insert_job(uid, now - 1 * day)
        self.insert_finding(job2, uid, ident, "BreachAlpha")
        events.handle_scan_completed(job2)
        self.assertEqual(self.identity_state(uid, ident, "BreachAlpha"),
                         before)
        stale = self.insert_job(uid, now - 2 * day - timedelta(hours=12))
        out = events.handle_scan_completed(stale)  # empty finding set
        self.assertFalse(out["skipped"])  # the hook ran...
        self.assertEqual(self.identity_state(uid, ident, "BreachAlpha"),
                         before)  # ...but the writer refused the rewind

    def test_readers_reflect_the_stored_value(self):
        uid, ident = self._user_with_identifier()
        now = datetime.now(timezone.utc)
        job1 = self.insert_job(uid, now - timedelta(days=1))
        self.insert_finding(job1, uid, ident, "BreachAlpha")
        self.insert_finding(job1, uid, ident, "BreachBeta")
        events.handle_scan_completed(job1)
        self.assertEqual(
            ac_service.action_center(uid)["exposure"]["findings_total"],
            2)

        # Flip the column directly in SQL: both readers must now
        # report the flipped value — proof no derivation remains.
        self.db_exec(
            "UPDATE findings SET lifecycle_state = 'resolved'"
            " WHERE user_id = %s AND source_name = 'BreachAlpha'",
            (uid,))
        detail = jobs_service.get_job(uid, job1)
        by_source = {f["source_name"]: f for f in detail["findings"]}
        self.assertEqual(by_source["BreachAlpha"]["lifecycle_state"],
                         "resolved")
        self.assertEqual(by_source["BreachBeta"]["lifecycle_state"],
                         "open")
        self.assertEqual(
            ac_service.action_center(uid)["exposure"]["findings_total"],
            1)

        self.db_exec(
            "UPDATE findings SET lifecycle_state = 'reappeared'"
            " WHERE user_id = %s AND source_name = 'BreachAlpha'",
            (uid,))
        detail = jobs_service.get_job(uid, job1)
        by_source = {f["source_name"]: f for f in detail["findings"]}
        self.assertEqual(by_source["BreachAlpha"]["lifecycle_state"],
                         "reappeared")
        self.assertEqual(
            ac_service.action_center(uid)["exposure"]["findings_total"],
            2)

    def test_remediation_verified_removal_resolves_then_reappears(self):
        from remediation import verify

        class GoneExecutor:
            def verify_search(self, profile, broker):
                return {"outcome": "gone",
                        "evidence_ref": "stub://gone",
                        "method": "search_index"}

        uid, ident = self._user_with_identifier()
        now = datetime.now(timezone.utc)
        job1 = self.insert_job(uid, now - timedelta(days=2))
        self.insert_finding(job1, uid, ident, "Spokeo")
        self.insert_finding(job1, uid, ident, "OtherBreach")
        events.handle_scan_completed(job1)
        self.assertEqual(self.identity_state(uid, ident, "Spokeo")[0],
                         "open")

        case = self.db_row(
            "INSERT INTO remediation_cases (user_id, broker_slug,"
            " status) VALUES (%s, 'spokeo', 'submitted') RETURNING id",
            (uid,))
        result = verify.verify_case(uid, str(case["id"]),
                                    executor=GoneExecutor())
        self.assertEqual(result["case"]["status"], "verified_removed")
        # The broker's finding is resolved by the verification;
        # the unrelated finding is untouched.
        state, stamp = self.identity_state(uid, ident, "Spokeo")
        self.assertEqual(state, "resolved")
        self.assertIsNotNone(stamp)
        self.assertEqual(self.identity_state(uid, ident, "OtherBreach")[0],
                         "open")
        self.assertEqual(
            ac_service.action_center(uid)["exposure"]["findings_total"],
            1)

        # The next completed cycle finds the listing again: the
        # stored lifecycle reappears AND the case flips back.
        job2 = self.insert_job(uid, now - timedelta(days=1))
        self.insert_finding(job2, uid, ident, "Spokeo")
        self.insert_finding(job2, uid, ident, "OtherBreach")
        out = events.handle_scan_completed(job2)
        self.assertEqual(self.identity_state(uid, ident, "Spokeo")[0],
                         "reappeared")
        row = self.db_row(
            "SELECT status FROM remediation_cases WHERE id = %s",
            (case["id"],))
        self.assertEqual(row["status"], "reappeared")
        self.assertEqual(out["reappeared"], 1)


# ---------------------------------------------------------------------------
# Migration 0012 on a database that already ran 0001-0011
# ---------------------------------------------------------------------------

@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestLifecycleMigrationUpgrade(PgClassMixin, AccountMixin,
                                    ServerMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._boot_pg("lg-lifecycle-upgrade-", migrate_fully=False)
        # Apply 0001-0011 exactly as the runner would, leaving the
        # database one migration behind.
        legacy = [p for p in cls.migrate.migration_files()
                  if p.name[:4] < "0012"]
        assert len(legacy) == 11, [p.name for p in legacy]
        with cls.pool.connection() as conn:
            cls.migrate.applied_migrations(conn)
            for path in legacy:
                conn.execute(path.read_text(encoding="utf-8"))
                conn.execute(
                    "INSERT INTO schema_migrations (name) VALUES (%s)",
                    (path.name,))
            # 0017 (sign-up name, 2026-10-08) is pre-applied out of
            # order: current auth code writes users.name_ciphertext
            # when this class's fixture registers, and 0017 is
            # independent of the 0012 backfill under test — the
            # runner in the test must still apply exactly 0012-0016.
            path17 = [p for p in cls.migrate.migration_files()
                      if p.name.startswith("0017")][0]
            conn.execute(path17.read_text(encoding="utf-8"))
            conn.execute(
                "INSERT INTO schema_migrations (name) VALUES (%s)",
                (path17.name,))
        from remediation import registry_seed

        registry_seed.seed_brokers()
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls.pool.reset_probe_cache()
        cls._teardown_pg()

    def setUp(self):
        ratelimit.reset()

    def _verified_case(self, user_id, slug, updated_at):
        self.db_exec(
            "INSERT INTO remediation_cases (user_id, broker_slug,"
            " status, updated_at) VALUES (%s, %s, 'verified_removed',"
            " %s)",
            (user_id, slug, updated_at))

    def test_backfill_resolves_only_the_expressible_classes(self):
        cookie, uid, _email = self.register()
        ident = self.add_identifier(
            cookie, "email", "legacy-%s@example.com" % self.uniq())
        iid = ident["id"]
        now = datetime.now(timezone.utc)
        job_a = self.insert_job(uid, now - timedelta(days=3))
        job_b = self.insert_job(uid, now - timedelta(days=1))

        # Present in the latest completed job -> stays open.
        self.insert_finding(job_a, uid, iid, "BreachX")
        self.insert_finding(job_b, uid, iid, "BreachX")
        # Absent from the latest completed job -> resolved, stamped
        # with that job's finished_at (the first absent cycle).
        self.insert_finding(job_a, uid, iid, "BreachY")
        # Present in the latest job but name-matched to a
        # verified_removed case -> resolved via the case, stamped
        # with the case's updated_at.
        self.insert_finding(job_b, uid, iid, "TruthFinder")
        case_stamp = now - timedelta(days=2)
        self._verified_case(uid, "truthfinder", case_stamp)
        # Matched to a verified case only via the broker's HOST —
        # not expressible in SQL -> stays open, honestly.
        self.insert_finding(job_b, uid, iid, "Fixture Weekly",
                            source_url="https://www.spokeo.com/listing")
        self._verified_case(uid, "spokeo", case_stamp)
        # Only ever seen by a failed job -> open.
        failed = self.insert_job(uid, now - timedelta(days=2),
                                 status="failed")
        self.insert_finding(failed, uid, iid, "BreachF")

        applied = self.migrate.run_migrations()
        # 0012 is the migration under test; 0013 (error ledger,
        # Phase 76), 0014 (provider usage, Phases 66/124),
        # 0015 (data-quality flags + ledgers, Phase 160) and
        # 0016 (attempt workflow versions, Phase 31) are later
        # additive migrations the runner also applies — they
        # touch no findings lifecycle state (0015 adds
        # default-false dq flag columns only; 0016 adds a
        # nullable column to remediation_attempts only).
        # 0017 was pre-applied in setUpClass (see there).
        self.assertEqual(applied, ["0012_finding_lifecycle.sql",
                                   "0013_error_events.sql",
                                   "0014_provider_usage.sql",
                                   "0015_data_quality.sql",
                                   "0016_attempt_workflow_version.sql"])

        self.assertEqual(self.identity_state(uid, iid, "BreachX"),
                         ("open", None))
        state, stamp = self.identity_state(uid, iid, "BreachY")
        self.assertEqual(state, "resolved")
        self.assertEqual(stamp, now - timedelta(days=1))
        state, stamp = self.identity_state(uid, iid, "TruthFinder")
        self.assertEqual(state, "resolved")
        self.assertEqual(stamp, case_stamp)
        self.assertEqual(self.identity_state(uid, iid, "Fixture Weekly"),
                         ("open", None))
        self.assertEqual(self.identity_state(uid, iid, "BreachF"),
                         ("open", None))

        # Fresh rows default to 'open' with no stamp, and the
        # runner is idempotent afterwards.
        job_c = self.insert_job(uid, now)
        self.insert_finding(job_c, uid, iid, "BreachZ")
        self.assertEqual(self.identity_state(uid, iid, "BreachZ"),
                         ("open", None))
        self.assertEqual(self.migrate.run_migrations(), [])


if __name__ == "__main__":
    unittest.main()
