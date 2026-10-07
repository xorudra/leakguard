"""LeakGuard performance benchmarks (spec Phases 115/116).

Runs the real app (ThreadingHTTPServer + app.Handler) against a
throwaway pgserver PostgreSQL with MOCK providers, so timings
measure LeakGuard's own code and SQL — never the network or a
real provider's latency. Every number this script prints is
labeled with that environment; none of it is production
hardware (production is a Render free instance talking to Neon
in Singapore — see docs/PERFORMANCE.md for the recorded run and
the documented single-instance ceiling).

Sections:
  (e) cold migration run on an empty database (timed first,
      while the bench database is still empty);
  (a) anonymous POST /api/scan handler latency (mock providers;
      sample size kept inside the production anon_scan rate
      budget of 30/hour/IP — the handler is what is measured);
  (b) authenticated API read latency (scan detail, action
      center, monitoring timeline);
  (c) scan-worker throughput over mock-provider jobs
      (jobs/sec and finding-rows/sec);
  (d) apply_lifecycle wall time vs identity count — the
      set-based writer's scaling curve (P2-B);
  (f) load: 20 threads x 5 anonymous scans (the per-IP limiter
      is expected to answer most with 429 — that ceiling is the
      designed behavior and is reported, not hidden), then
      8 threads x 25 authenticated reads for an app-level
      concurrency figure.

Usage:  python3 tools/bench.py
"""

import base64
import json
import os
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
PASSWORD = "bench-pass-1234"  # throwaway bench account only


def pct(values, q):
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(q * len(ordered)))
    return ordered[idx]


def summarize(name, lat_ms, extra=""):
    print("  %-28s n=%-4d mean=%8.2f ms  p50=%8.2f  p95=%8.2f"
          "  min=%8.2f  max=%8.2f  %s"
          % (name, len(lat_ms), statistics.mean(lat_ms),
             pct(lat_ms, 0.50), pct(lat_ms, 0.95),
             min(lat_ms), max(lat_ms), extra))
    return {"n": len(lat_ms), "mean": statistics.mean(lat_ms),
            "p50": pct(lat_ms, 0.50), "p95": pct(lat_ms, 0.95)}


class Client:
    def __init__(self, base):
        self.base = base
        self.cookie = None

    def call(self, method, path, body=None):
        data = None
        headers = dict(CSRF)
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.cookie:
            headers["Cookie"] = self.cookie
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=headers, method=method)
        started = time.perf_counter()
        try:
            with OPENER.open(req, timeout=30) as resp:
                payload = resp.read()
                status = resp.status
                set_cookie = resp.headers.get("Set-Cookie") or ""
        except urllib.error.HTTPError as e:
            payload = e.read()
            status = e.code
            set_cookie = e.headers.get("Set-Cookie") or ""
        except Exception:
            # Transport failure (e.g. connection reset under a
            # burst — the listen backlog overflowing). Recorded
            # as status -1 so load phases count it instead of
            # silently losing the attempt in a dead thread.
            return -1, None, (time.perf_counter() - started) * 1000.0
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if set_cookie.startswith("lg_session="):
            self.cookie = set_cookie.split(";")[0].strip()
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except Exception:
            parsed = None
        return status, parsed, elapsed_ms


def main():
    import tempfile

    import pgserver

    pg_dir = tempfile.mkdtemp(prefix="lg-bench-")
    pg = pgserver.get_server(pg_dir)
    os.environ["DATABASE_URL"] = pg.get_uri()
    os.environ["VAULT_MASTER_KEY"] = base64.b64encode(
        os.urandom(32)).decode()
    os.environ["VAULT_LOOKUP_KEY"] = base64.b64encode(
        os.urandom(32)).decode()
    for key in ("BREVO_API_KEY", "NOTIFY_FROM_EMAIL",
                "NOTIFY_FROM_NAME", "MIGRATION_DATABASE_URL"):
        os.environ.pop(key, None)
    os.environ["LEAKGUARD_PROVIDERS"] = "mock"

    import app  # noqa: F401  (import after env is set)
    from db import migrate, pool
    from providers import registry as registry_mod

    registry_mod.reset_registry()
    pool.reset_probe_cache()
    results = {}

    print("== (e) cold migration run (empty database) ==")
    started = time.perf_counter()
    applied = migrate.run_migrations()
    mig_s = time.perf_counter() - started
    print("  applied %d migrations in %.2f s" % (len(applied), mig_s))
    results["migrations"] = (len(applied), mig_s)

    server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % port
    anon = Client(base)

    print("== (a) anonymous POST /api/scan (mock providers) ==")
    lat = []
    for _ in range(25):
        status, _body, ms = anon.call(
            "POST", "/api/scan", {"email": "breached@example.com"})
        assert status == 200, status
        lat.append(ms)
    results["anon_scan"] = summarize("POST /api/scan", lat)

    print("== setup: account, identifiers, one completed scan ==")
    user = Client(base)
    email = "bench-%s@example.com" % uuid.uuid4().hex[:12]
    status, body, _ = user.call("POST", "/api/auth/register",
                                {"email": email, "password": PASSWORD})
    assert status == 201, (status, body)
    for value in ("breached@example.com", "shared-a@example.com"):
        status, body, _ = user.call(
            "POST", "/api/identifiers",
            {"kind": "email", "value": value})
        assert status == 201, (status, body)
    status, body, _ = user.call(
        "POST", "/api/consents",
        {"purpose": "scanning", "granted": True})
    assert status == 200, (status, body)

    from scanning import worker

    def run_job(client):
        status, body, _ = client.call(
            "POST", "/api/scans",
            {"idempotency_key": uuid.uuid4().hex})
        assert status == 201, (status, body)
        job_id = body["job"]["id"]
        for _ in range(50):
            status, body, _ = client.call("GET", "/api/scans/" + job_id)
            if body["job"]["status"] in ("done", "dead"):
                return job_id, body
            assert worker.run_once(), "worker had nothing to claim"
        raise RuntimeError("job never finished")

    job_id, job_body = run_job(user)
    findings_in_job = len(job_body["findings"])
    print("  setup job findings: %d" % findings_in_job)

    print("== (b) authenticated API reads ==")
    for name, path in (
            ("GET /api/scans/<id>", "/api/scans/" + job_id),
            ("GET /api/action-center", "/api/action-center"),
            ("GET /api/monitoring/timeline",
             "/api/monitoring/timeline")):
        lat = []
        for _ in range(30):
            status, _body, ms = user.call("GET", path)
            assert status == 200, (path, status)
            lat.append(ms)
        results[name] = summarize(name, lat)

    print("== (c) scan-worker throughput (mock providers) ==")
    # Identifiers are globally unique across accounts (a value
    # saved by one account cannot be saved by another), and the
    # user_scans budget is 10 jobs/hour/user with the setup job
    # already spent — so throughput is measured on 9 further
    # jobs for the setup user, each re-scanning the same two
    # identifiers (the same finding rows per job as the setup).
    # The wall clock spans the full pipeline: API job creation,
    # status polling, and the in-process worker's run_once.
    started = time.perf_counter()
    jobs_done = 0
    for _ in range(9):
        run_job(user)
        jobs_done += 1
    wall = time.perf_counter() - started
    total_findings = jobs_done * findings_in_job
    print("  %d jobs in %.2f s -> %.2f jobs/sec, %d finding rows"
          " -> %.1f findings/sec"
          % (jobs_done, wall, jobs_done / wall, total_findings,
             total_findings / wall))
    results["worker"] = (jobs_done, wall, total_findings)

    print("== (d) apply_lifecycle vs identity count ==")
    from monitoring import diff

    def lifecycle_point(total):
        uid_row = _one(
            "INSERT INTO users (email_hmac, email_ciphertext,"
            " email_masked, password_hash) VALUES (%s, %s, %s, %s)"
            " RETURNING id",
            (os.urandom(32), os.urandom(32), "b•••@example.com",
             "x" * 32))
        uid = str(uid_row["id"])
        ident_row = _one(
            "INSERT INTO identifiers (user_id, kind, hmac_lookup,"
            " ciphertext, masked) VALUES (%s, 'email', %s, %s, %s)"
            " RETURNING id",
            (uid, os.urandom(32), os.urandom(32), "b•••@example.com"))
        ident = str(ident_row["id"])
        now = datetime.now(timezone.utc)
        old = now - timedelta(days=5)
        prev_id = _insert_job(uid, now - timedelta(days=2))
        cur_id = _insert_job(uid, now - timedelta(days=1))
        half = total // 2
        for i in range(total):
            _insert_finding(prev_id, uid, ident, "Src%05d" % i)
        _exec("UPDATE findings SET lifecycle_state = 'open',"
              " lifecycle_changed_at = %s WHERE user_id = %s",
              (old, uid))
        for i in range(half):
            _insert_finding(cur_id, uid, ident, "Src%05d" % i)
        for i in range(half):
            _insert_finding(cur_id, uid, ident, "New%05d" % i)
        previous = _rows("SELECT * FROM findings WHERE job_id = %s",
                         (prev_id,))
        current = _rows("SELECT * FROM findings WHERE job_id = %s",
                        (cur_id,))
        started = time.perf_counter()
        diff.apply_lifecycle(uid, {"id": cur_id,
                                   "finished_at":
                                   now - timedelta(days=1)},
                             current, previous)
        return (time.perf_counter() - started) * 1000.0

    def _exec(sql, params=()):
        with pool.connection() as conn:
            return conn.execute(sql, params)

    def _one(sql, params=()):
        return _exec(sql, params).fetchone()

    def _rows(sql, params=()):
        return _exec(sql, params).fetchall()

    def _insert_job(uid, finished_at):
        return str(_one(
            "INSERT INTO scan_jobs (user_id, idempotency_key,"
            " status, score, created_at, finished_at)"
            " VALUES (%s, %s, 'done', 10, %s, %s) RETURNING id",
            (uid, uuid.uuid4().hex, finished_at,
             finished_at))["id"])

    def _insert_finding(job_id, uid, ident, source):
        _exec("INSERT INTO findings (job_id, user_id, identifier_id,"
              " identifier_kind, provider, source_name, exposed_fields,"
              " confidence, reliability, evidence_ref)"
              " VALUES (%s, %s, %s, 'email', 'FixtureProvider', %s,"
              " '{}', 'exact', 'high', %s)",
              (job_id, uid, ident, source, "e" * 64))

    lifecycle_results = {}
    for total in (10, 100, 500):
        samples = sorted(lifecycle_point(total) for _ in range(3))
        lifecycle_results[total] = samples[1]
        print("  identities=%-5d apply_lifecycle median %.2f ms"
              " (3 runs: %s)"
              % (total, samples[1],
                 ", ".join("%.2f" % s for s in samples)))
    results["lifecycle"] = lifecycle_results

    print("== (f1) load: 20 threads x 5 anonymous scans ==")
    # Section (a) already spent 25 of this process's 30/hour
    # per-IP anon_scan budget. Clear the limiter buckets so this
    # phase measures a FRESH window (the equivalent of a new hour
    # or a new client IP); the 30-per-hour ceiling itself is
    # production configuration and stays in force.
    from core import ratelimit as core_ratelimit

    with core_ratelimit._lock:
        core_ratelimit._buckets.clear()
    outcomes = []
    lock = threading.Lock()

    def scan_worker_thread():
        client = Client(base)
        for _ in range(5):
            status, _body, ms = client.call(
                "POST", "/api/scan",
                {"email": "breached@example.com"})
            with lock:
                outcomes.append((status, ms))

    started = time.perf_counter()
    threads = [threading.Thread(target=scan_worker_thread)
               for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.perf_counter() - started
    ok = [ms for s, ms in outcomes if s == 200]
    limited = sum(1 for s, _ in outcomes if s == 429)
    errors = sum(1 for s, _ in outcomes if s >= 500)
    resets = sum(1 for s, _ in outcomes if s == -1)
    print("  %d attempts in %.2f s (%.1f req/s overall); 200 x %d,"
          " 429 x %d, 5xx x %d, transport-reset x %d"
          % (len(outcomes), wall, len(outcomes) / wall, len(ok),
             limited, errors, resets))
    if ok:
        print("  successful scans: p50 %.2f ms, p95 %.2f ms"
              % (pct(ok, 0.50), pct(ok, 0.95)))
    results["load_anon"] = (len(outcomes), wall, len(ok), limited,
                            errors, resets)

    print("== (f2) load: 8 threads x 25 authenticated reads ==")
    read_outcomes = []

    def read_worker_thread():
        client = user  # shared session cookie; reads are stateless
        for i in range(25):
            path = ("/api/action-center" if i % 2 == 0
                    else "/api/monitoring/timeline")
            status, _body, ms = client.call("GET", path)
            with lock:
                read_outcomes.append((status, ms))

    started = time.perf_counter()
    threads = [threading.Thread(target=read_worker_thread)
               for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.perf_counter() - started
    read_ms = [ms for s, ms in read_outcomes if s > 0]
    read_errors = sum(1 for s, _ in read_outcomes if s >= 500)
    read_resets = sum(1 for s, _ in read_outcomes if s == -1)
    print("  %d reads in %.2f s (%.1f req/s); p50 %.2f ms,"
          " p95 %.2f ms; 5xx x %d, transport-reset x %d"
          % (len(read_outcomes), wall, len(read_outcomes) / wall,
             pct(read_ms, 0.50), pct(read_ms, 0.95), read_errors,
             read_resets))
    results["load_reads"] = (len(read_outcomes), wall, read_errors,
                             read_resets)

    server.shutdown()
    pg.cleanup()
    print("\nbench complete")
    return results


if __name__ == "__main__":
    main()
