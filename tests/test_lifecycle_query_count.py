"""Query-count regression for the set-based lifecycle writer
(P2-B; the Phase 25 follow-up).

The first lifecycle writer issued one UPDATE per identity: a
cycle with N identities cost N database round trips, which over
the production Oregon→Singapore link (~200 ms RTT) made a
214-identity cycle take up to a minute to converge (recorded in
docs/cycles/2026-10-07-p1b-phase-25-lifecycle.md). The writer is
now set-based — apply_lifecycle issues a CONSTANT number of
statements per cycle:

    3 reads   (stale-job check, cycle clock, priors map)
  + 1 UPDATE  (every transition: births, reappearances,
               resolutions — they share the cycle's stamp)
  + 1 UPDATE  (continuing identities' prior pairs carried over)
  = 5 statements, however many identities the cycle holds.

BOUND ASSERTED BELOW: <= 6 executes for a whole apply (the 5 by
construction, +1 slack), AND the count for a doubled cycle is
EXACTLY the count for the single cycle — the O(N) loop is gone.
Semantics are pinned by tests/test_finding_lifecycle.py (the
unmodified contract); this file additionally checks the outcomes
of every transition class at scale, including identities whose
identifier_id is NULL (the nullable component of the identity).

Run:  python3 -m pytest tests/test_lifecycle_query_count.py
"""

import base64
import os
import sys
import unittest
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import pool  # noqa: E402
from monitoring import diff  # noqa: E402

ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY",
            "LEAKGUARD_PROVIDERS")

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None

NOW = datetime.now(timezone.utc)
OLD_STAMP = NOW - timedelta(days=5)
PREV_DONE = NOW - timedelta(days=2)
CUR_DONE = NOW - timedelta(days=1)

# Class sizes at scale 1 (doubled at scale 2). Distinct identities
# touched by one apply: 45 at scale 1, 90 at scale 2.
CLASSES = {
    "birth": 10,          # only in the current job -> open + stamp
    "reappear": 6,        # prior resolved, present -> reappeared
    "cont_open": 12,      # continuing, prior (open, OLD_STAMP)
    "cont_reapp": 4,      # continuing, prior (reappeared, OLD_STAMP)
    "resolve": 8,         # previous only -> resolved + stamp
    "already": 3,         # previous only, already resolved -> untouched
    "null_birth": 1,      # identifier_id NULL, current only
    "null_resolve": 1,    # identifier_id NULL, previous only
}


class _CountingConnection:
    """Proxy that counts execute() calls on a real connection."""

    def __init__(self, real, counter):
        self._real = real
        self._counter = counter

    def execute(self, *args, **kwargs):
        self._counter[0] += 1
        return self._real.execute(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._real, name)


@contextmanager
def _counting_pool(counter):
    original = pool.connection

    @contextmanager
    def wrapped(dsn=None):
        with original(dsn) as conn:
            yield _CountingConnection(conn, counter)

    pool.connection = wrapped
    try:
        yield
    finally:
        pool.connection = original


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestApplyLifecycleQueryCount(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._saved_env = {k: os.environ.get(k) for k in ENV_KEYS}
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-qcount-")
        try:
            cls._pg = _pgserver.get_server(cls._pg_dir)
        except Exception:
            raise unittest.SkipTest("pgserver could not start PostgreSQL")
        os.environ["DATABASE_URL"] = cls._pg.get_uri()
        os.environ["VAULT_MASTER_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        os.environ["VAULT_LOOKUP_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        os.environ.pop("LEAKGUARD_PROVIDERS", None)
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

    # ----- fixture builders -----
    def _db(self, sql, params=()):
        with pool.connection() as conn:
            return conn.execute(sql, params)

    def _make_user(self):
        row = self._db(
            "INSERT INTO users (email_hmac, email_ciphertext,"
            " email_masked, password_hash) VALUES (%s, %s, %s, %s)"
            " RETURNING id",
            (os.urandom(32), os.urandom(32),
             "q•••@example.com", "x" * 32)).fetchone()
        user_id = str(row["id"])
        row = self._db(
            "INSERT INTO identifiers (user_id, kind, hmac_lookup,"
            " ciphertext, masked) VALUES (%s, 'email', %s, %s, %s)"
            " RETURNING id",
            (user_id, os.urandom(32), os.urandom(32),
             "q•••@example.com")).fetchone()
        return user_id, str(row["id"])

    def _insert_job(self, user_id, finished_at):
        row = self._db(
            "INSERT INTO scan_jobs (user_id, idempotency_key, status,"
            " score, created_at, finished_at)"
            " VALUES (%s, %s, 'done', 10, %s, %s) RETURNING id",
            (user_id, uuid.uuid4().hex, finished_at,
             finished_at)).fetchone()
        return str(row["id"])

    def _insert_finding(self, job_id, user_id, identifier_id, source):
        self._db(
            "INSERT INTO findings (job_id, user_id, identifier_id,"
            " identifier_kind, provider, source_name, source_url,"
            " exposed_fields, confidence, reliability, evidence_ref)"
            " VALUES (%s, %s, %s, 'email', 'FixtureProvider', %s,"
            " NULL, '{}', 'exact', 'high', %s)",
            (job_id, user_id, identifier_id, source, "e" * 64))

    def _set_prior(self, user_id, identifier_id, sources, state, stamp):
        self._db(
            "UPDATE findings SET lifecycle_state = %s,"
            " lifecycle_changed_at = %s WHERE user_id = %s"
            " AND identifier_id IS NOT DISTINCT FROM %s"
            " AND source_name = ANY(%s)",
            (state, stamp, user_id, identifier_id, sources))

    def _pair(self, user_id, identifier_id, source):
        rows = self._db(
            "SELECT DISTINCT lifecycle_state, lifecycle_changed_at"
            " FROM findings WHERE user_id = %s"
            " AND identifier_id IS NOT DISTINCT FROM %s"
            " AND source_name = %s",
            (user_id, identifier_id, source)).fetchall()
        self.assertEqual(len(rows), 1,
                         "identity rows disagree for %s: %r"
                         % (source, rows))
        return rows[0]["lifecycle_state"], rows[0]["lifecycle_changed_at"]

    def _scenario(self, scale):
        """Build previous+current jobs for one fresh user and run
        one counted apply. Returns (counter, result, probe) where
        probe(source, identifier=...) reads an identity's pair."""
        user_id, ident = self._make_user()
        n = {k: v * scale for k, v in CLASSES.items()}
        src = {}
        for name, count in n.items():
            src[name] = ["%s-%02d" % (name, i) for i in range(count)]

        prev_job = self._insert_job(user_id, PREV_DONE)
        cur_job = self._insert_job(user_id, CUR_DONE)
        in_prev = (src["reappear"] + src["cont_open"] + src["cont_reapp"]
                   + src["resolve"] + src["already"])
        in_cur = (src["birth"] + src["reappear"] + src["cont_open"]
                  + src["cont_reapp"])
        for source in in_prev:
            self._insert_finding(prev_job, user_id, ident, source)
        for source in in_cur:
            self._insert_finding(cur_job, user_id, ident, source)
        for source in src["null_birth"]:
            self._insert_finding(cur_job, user_id, None, source)
        for source in src["null_resolve"]:
            self._insert_finding(prev_job, user_id, None, source)
        # Stored priors the classifier must honour.
        self._set_prior(user_id, ident, src["cont_open"],
                        "open", OLD_STAMP)
        self._set_prior(user_id, ident, src["cont_reapp"],
                        "reappeared", OLD_STAMP)
        self._set_prior(user_id, ident, src["reappear"],
                        "resolved", OLD_STAMP)
        self._set_prior(user_id, ident, src["already"],
                        "resolved", OLD_STAMP)

        previous = self._db(
            "SELECT * FROM findings WHERE job_id = %s",
            (prev_job,)).fetchall()
        current = self._db(
            "SELECT * FROM findings WHERE job_id = %s",
            (cur_job,)).fetchall()
        job_row = {"id": cur_job, "finished_at": CUR_DONE}

        counter = [0]
        with _counting_pool(counter):
            result = diff.apply_lifecycle(user_id, job_row, current,
                                          previous)

        def probe(source, identifier=ident):
            return self._pair(user_id, identifier, source)

        return counter[0], result, probe, src, n

    # ----- the regression test -----
    def test_statement_count_is_constant_and_bounded(self):
        count1, result1, probe, src, n = self._scenario(1)

        # Every transition class landed as the contract requires.
        for source in src["birth"] + src["null_birth"]:
            state, stamp = probe(source, None) \
                if source in src["null_birth"] else probe(source)
            self.assertEqual(state, "open")
            self.assertIsNotNone(stamp)
        for source in src["reappear"]:
            state, stamp = probe(source)
            self.assertEqual(state, "reappeared")
            self.assertGreater(stamp, OLD_STAMP)
        for source in src["resolve"] + src["null_resolve"]:
            state, stamp = probe(source, None) \
                if source in src["null_resolve"] else probe(source)
            self.assertEqual(state, "resolved")
            self.assertIsNotNone(stamp)
        for source in src["cont_open"]:
            self.assertEqual(probe(source), ("open", OLD_STAMP))
        for source in src["cont_reapp"]:
            self.assertEqual(probe(source), ("reappeared", OLD_STAMP))
        for source in src["already"]:
            self.assertEqual(probe(source), ("resolved", OLD_STAMP))
        self.assertEqual(len(result1["resolved"]),
                         n["resolve"] + n["null_resolve"])
        self.assertEqual(len(result1["reappeared"]), n["reappear"])

        # The bound: 5 statements by construction (3 reads + 2
        # writes); <= 6 asserted. A per-identity writer would have
        # issued 3 + 45 here.
        self.assertLessEqual(count1, 6,
                             "apply_lifecycle issued %d statements"
                             " for 45 identities" % count1)

        # Double the identities: the count must not move at all.
        count2, _r2, _p2, _s2, _n2 = self._scenario(2)
        self.assertEqual(count2, count1,
                         "statement count grew with identity count:"
                         " %d (45 identities) -> %d (90 identities)"
                         % (count1, count2))


if __name__ == "__main__":
    unittest.main()
