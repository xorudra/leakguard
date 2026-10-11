// LeakGuard load test (Launch Safety Standard item 34, 2026-10-11).
//
// Run ONLY against a local instance or staging — NEVER production:
// the profile is small, but production is a single free instance
// shared with real users, and load there proves nothing the local
// run doesn't.
//
//   # boot a local instance first (mock providers, scratch DB):
//   DATABASE_URL=postgresql://postgres:@/postgres?host=<pgdata> \
//   LEAKGUARD_PROVIDERS=mock PORT=8765 python3 app.py
//
//   k6 run -e BASE_URL=http://127.0.0.1:8765 tools/load_test.js
//
// Profile (<= 50 VUs, ~2.5 min): ramp to 10, hold at 20, brief
// spike to 50, ramp down. Read-only public surface only — the
// anonymous scan POST is deliberately excluded: it is rate-limited
// per IP by design (30/hour), so from one machine it measures the
// limiter, not the app (tools/bench.py phase f1 already proved the
// limiter sheds with clean 429s and zero 5xx).
//
// Thresholds (the item-34 contract): failed requests < 1%,
// p95 latency < 1000 ms on this local profile.

import http from "k6/http";
import { check, sleep } from "k6";

const BASE = __ENV.BASE_URL || "http://127.0.0.1:8765";

export const options = {
  stages: [
    { duration: "30s", target: 10 },
    { duration: "60s", target: 20 },
    { duration: "30s", target: 50 },
    { duration: "30s", target: 0 },
  ],
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<1000"],
  },
};

const PATHS = ["/", "/privacy", "/api/health", "/api/brokers"];

export default function () {
  for (const path of PATHS) {
    const res = http.get(BASE + path);
    check(res, { "status is 200": (r) => r.status === 200 });
  }
  sleep(1);
}
