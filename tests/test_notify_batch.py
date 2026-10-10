"""Batch notification writer + completion-hook fallback tests
(the inbox rule, 2026-10-08).

The contract pinned here:

* notify.create_notifications_batch records PER-FINDING notices
  (new_finding / finding_resolved) as 'in_app_only' in ONE
  transaction — one advisory lock, one dedupe select, one
  multi-row INSERT, however many items. Email for a monitoring
  cycle is the once-per-cycle scan_summary digest via
  create_notification; a finding never means an email (a
  214-finding cycle would otherwise send ~215 emails against
  the Brevo free tier's 300/day).
* Dedupe matches the single-row path: an existing non-suppressed
  row with the same key inside the 7-day window suppresses the
  repeat, a stale or already-suppressed row does not, and a key
  repeated inside one batch suppresses its later copies.
* When the batch raises, monitoring.events falls back to the
  per-item create_notification loop (mode "auto") so the cycle's
  ledger is still written — these tests pin both paths.

Against a local PostgreSQL provisioned with pip `pgserver`
(skips honestly when unavailable). No real email: the lane
transport is a recording fake.

Run:  python3 -m unittest discover -s tests
"""

import base64
import json
import os
import sys
import unittest
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import pool  # noqa: E402
from monitoring import events, notify  # noqa: E402

ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")
LANE_KEYS = ("BREVO_API_KEY", "NOTIFY_FROM_EMAIL", "NOTIFY_FROM_NAME")

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


class _RecordingConnection:
    """Proxy that records the SQL of every execute() call."""

    def __init__(self, real, record):
        self._real = real
        self._record = record

    def execute(self, sql, *args, **kwargs):
        self._record.append(sql)
        return self._real.execute(sql, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._real, name)


@contextmanager
def _recording_pool(record):
    original = pool.connection

    @contextmanager
    def wrapped(dsn=None):
        with original(dsn) as conn:
            yield _RecordingConnection(conn, record)

    pool.connection = wrapped
    try:
        yield
    finally:
        pool.connection = original


class _FakeTransport:
    """Recording stand-in for the Brevo lane."""

    def __init__(self):
        self.calls = []

    def __call__(self, url, headers, body, timeout):
        self.calls.append(json.loads(body.decode("utf-8")))
        return 201, "{}"


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestNotifyBatchDb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._saved_env = {k: os.environ.get(k)
                          for k in ENV_KEYS + LANE_KEYS}
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-batch-")
        try:
            cls._pg = _pgserver.get_server(cls._pg_dir)
        except Exception:
            raise unittest.SkipTest("pgserver could not start PostgreSQL")
        os.environ["DATABASE_URL"] = cls._pg.get_uri()
        os.environ["VAULT_MASTER_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        os.environ["VAULT_LOOKUP_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        pool.reset_probe_cache()
        if not pool.db_available():
            cls.tearDownClass()
            raise unittest.SkipTest("local PostgreSQL not reachable")
        from db import migrate

        migrate.run_migrations()

    @classmethod
    def tearDownClass(cls):
        try:
            cls._pg.cleanup()
        except Exception:
            pass
        import shutil

        shutil.rmtree(cls._pg_dir, ignore_errors=True)
        pool.reset_probe_cache()
        for key, value in cls._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def setUp(self):
        self._lane_saved = {k: os.environ.get(k) for k in LANE_KEYS}
        os.environ["BREVO_API_KEY"] = "test-brevo-key"
        os.environ["NOTIFY_FROM_EMAIL"] = "alerts@leakguard.example"
        os.environ.pop("NOTIFY_FROM_NAME", None)
        self.transport = _FakeTransport()
        notify.TRANSPORT = self.transport

    def tearDown(self):
        notify.TRANSPORT = None
        for k, v in self._lane_saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # ----- fixture helpers -----
    def _db(self, sql, params=()):
        with pool.connection() as conn:
            return conn.execute(sql, params)

    def _make_user(self):
        row = self._db(
            "INSERT INTO users (email_hmac, email_ciphertext,"
            " email_masked, password_hash) VALUES (%s, %s, %s, %s)"
            " RETURNING id",
            (os.urandom(32), os.urandom(32),
             "b•••@example.com", "x" * 32)).fetchone()
        return str(row["id"])

    def _rows(self, user_id, kind=None):
        if kind:
            return self._db(
                "SELECT * FROM notifications WHERE user_id = %s"
                " AND kind = %s ORDER BY created_at, id",
                (user_id, kind)).fetchall()
        return self._db(
            "SELECT * FROM notifications WHERE user_id = %s"
            " ORDER BY created_at, id", (user_id,)).fetchall()

    def _seed_row(self, user_id, kind, dedupe_key, status, age_days=0):
        self._db(
            "INSERT INTO notifications (user_id, kind, dedupe_key,"
            " payload, status, created_at) VALUES (%s, %s, %s,"
            " '{}'::jsonb, %s, now() - (%s || ' days')::interval)",
            (user_id, kind, dedupe_key, status, str(age_days)))

    @staticmethod
    def _item(kind, key, source="FixtureBreach"):
        return {"kind": kind, "payload": {"source_name": source},
                "dedupe_key": key}

    # ----- the batch writer -----
    def test_batch_writes_every_item_in_app_only(self):
        uid = self._make_user()
        items = ([self._item("new_finding", "new:%d" % i)
                  for i in range(3)]
                 + [self._item("finding_resolved", "resolved:%d" % i)
                    for i in range(2)]
                 + [self._item("new_finding", None)])
        out = notify.create_notifications_batch(uid, items)
        self.assertEqual(len(out), len(items))
        self.assertEqual([r["kind"] for r in out],
                         [i["kind"] for i in items])
        self.assertTrue(all(r["status"] == "in_app_only" for r in out))
        rows = self._rows(uid)
        self.assertEqual(len(rows), len(items))
        self.assertTrue(all(r["status"] == "in_app_only" for r in rows))
        self.assertEqual({r["id"] for r in out},
                         {str(r["id"]) for r in rows})
        # Ledger-only: the lane is never touched by the batch.
        self.assertEqual(self.transport.calls, [])

    def test_batch_dedupe_suppresses_only_dupes(self):
        uid = self._make_user()
        self._seed_row(uid, "new_finding", "new:live", "sent")
        self._seed_row(uid, "new_finding", "new:stale", "sent",
                       age_days=30)
        self._seed_row(uid, "new_finding", "new:quiet", "suppressed")
        items = [
            self._item("new_finding", "new:live"),   # live dupe
            self._item("new_finding", "new:stale"),  # outside window
            self._item("new_finding", "new:quiet"),  # only suppressed
            self._item("new_finding", "new:twice"),  # first copy wins
            self._item("new_finding", "new:twice"),  # intra-batch dupe
            self._item("finding_resolved", None),    # keyless
        ]
        out = notify.create_notifications_batch(uid, items)
        self.assertEqual(
            [r["status"] for r in out],
            ["suppressed", "in_app_only", "in_app_only",
             "in_app_only", "suppressed", "in_app_only"])
        rows = self._rows(uid)
        self.assertEqual(len(rows), 3 + len(items))
        twice = [r for r in rows if r["dedupe_key"] == "new:twice"]
        self.assertEqual(sorted(r["status"] for r in twice),
                         ["in_app_only", "suppressed"])
        self.assertEqual(self.transport.calls, [])

    def test_batch_insert_is_a_single_statement(self):
        uid = self._make_user()
        for n in (4, 12):
            items = [self._item("new_finding", "bulk-%d-%d" % (n, i))
                     for i in range(n)]
            record = []
            with _recording_pool(record):
                out = notify.create_notifications_batch(uid, items)
            self.assertEqual(len(out), n)
            inserts = [s for s in record
                       if s.lstrip().upper().startswith("INSERT")]
            self.assertEqual(len(inserts), 1,
                             "batch of %d issued %d INSERT statements"
                             % (n, len(inserts)))
            # Lock + dedupe select + the one insert: nothing else,
            # whatever the batch size.
            self.assertEqual(len(record), 3)

    def test_batch_validates_kinds_and_accepts_empty(self):
        uid = self._make_user()
        self.assertEqual(notify.create_notifications_batch(uid, []), [])
        with self.assertRaises(ValueError):
            notify.create_notifications_batch(
                uid, [self._item("not_a_kind", "k")])
        self.assertEqual(self._rows(uid), [])

    # ----- the hook: batch by default, per-item on failure -----
    def _insert_job(self, user_id, finished_at, score=10):
        row = self._db(
            "INSERT INTO scan_jobs (user_id, idempotency_key, status,"
            " score, finished_at) VALUES (%s, %s, 'done', %s, %s)"
            " RETURNING id",
            (user_id, uuid.uuid4().hex, score, finished_at)).fetchone()
        return str(row["id"])

    def _insert_identifier(self, user_id):
        row = self._db(
            "INSERT INTO identifiers (user_id, kind, hmac_lookup,"
            " ciphertext, masked) VALUES (%s, 'email', %s, %s, %s)"
            " RETURNING id",
            (user_id, os.urandom(32), os.urandom(32),
             "b•••@example.com")).fetchone()
        return str(row["id"])

    def _insert_finding(self, job_id, user_id, identifier_id, source):
        self._db(
            "INSERT INTO findings (job_id, user_id, identifier_id,"
            " identifier_kind, provider, source_name, exposed_fields,"
            " confidence, reliability, evidence_ref)"
            " VALUES (%s, %s, %s, 'email', 'FixtureProvider', %s,"
            " '{}', 'exact', 'high', %s)",
            (job_id, user_id, identifier_id, source, "e" * 64))

    def test_hook_falls_back_to_per_item_when_batch_raises(self):
        from accounts import auth, consents

        user, _token = auth.register(
            "batch-%s@example.com" % uuid.uuid4().hex[:12],
            "correct-horse-9", policy_accepted=True)
        uid = user["id"]
        consents.set_consent(uid, "notifications", True)
        ident = self._insert_identifier(uid)
        now = datetime.now(timezone.utc)
        job0 = self._insert_job(uid, now - timedelta(days=1))
        events.handle_scan_completed(job0)  # baseline: summary only
        job1 = self._insert_job(uid, now)
        self._insert_finding(job1, uid, ident, "FixtureBreach")

        original = notify.create_notifications_batch

        def _boom(user_id, items):
            raise RuntimeError("batch unavailable")

        notify.create_notifications_batch = _boom
        try:
            with self.assertLogs("leakguard", level="ERROR") as logs:
                out = events.handle_scan_completed(job1)
        finally:
            notify.create_notifications_batch = original
        self.assertFalse(out["skipped"])
        # The fallback is logged at error level, class name only.
        self.assertTrue(any("RuntimeError" in line
                            for line in logs.output), logs.output)
        news = self._rows(uid, "new_finding")
        self.assertEqual(len(news), 1)
        # The fallback is the OLD per-item path: mode "auto" with
        # consent + lane delivers by email and records 'sent' —
        # which is exactly what proves the fallback, not the
        # batch, wrote this row.
        self.assertEqual(news[0]["status"], "sent")
        summaries = self._rows(uid, "scan_summary")
        self.assertEqual(len(summaries), 2)
        self.assertTrue(all(r["status"] == "sent" for r in summaries))
        # Fallback cycle emails: the finding + its summary (the
        # baseline summary was the first call).
        self.assertEqual(len(self.transport.calls), 3)


if __name__ == "__main__":
    unittest.main()
