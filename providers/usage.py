"""Provider usage ledger + daily call budgets (spec Phases 66, 124).

WHY THIS EXISTS. Every provider LeakGuard calls is free (owner
rule), so "cost control" here is not spend — spend is ₹0 and stays
₹0. It is CALL VOLUME against finite free tiers: if one provider
absorbs unbounded calls, the free tier is what runs out, silently,
and coverage degrades with no signal. Phase 124's gap was that
nothing counted calls per provider per day; Phase 66's gap was
that nothing enforced a limit or tracked per-user volume. This
module is both: a daily usage rollup (persisted to
provider_usage_daily, migration 0014) and the daily budget each
provider is allowed to absorb before the provider layer refuses
further calls for the rest of the UTC day.

BUDGETS — OPERATOR-SET, NOT PUBLISHED QUOTAS. None of the keyless
APIs below publishes a numeric daily quota (their terms are
fair-use / rate-limit based), so every value in BUDGETS is an
operator-set SAFETY budget, chosen from the call arithmetic in
its comment to sit comfortably above this product's real traffic
on a single free instance — never a number copied from a pricing
page, because there isn't one. If a provider later publishes a
real quota, replace the value and say so in the comment.

Brevo is deliberately ABSENT: the provider layer never sends
email. Brevo's published free-plan cap (300 emails/day) binds the
notification lane (monitoring/notify.py), and that lane's volume
is already governed by design (P2-B: email is the once-per-cycle
scan_summary digest, never per-finding) — it is not a provider
call and does not belong in this table.

COUNTING RULES. One logical provider call = one HttpClient
request outcome (retries inside a request collapse into it, the
same granularity HealthTracker reports). Calls that never reached
the provider are NOT counted: a circuit-open refusal and a
budget refusal are visible in HealthTracker (error kinds
circuit_open / budget_exhausted) but are not usage. Mock
providers make no network calls and never appear here.

PER-USER TRACKING. Signed-in scan work is already attributed:
scan_jobs carries user_id, and the admin metrics block reports
today's per-user volume in aggregate (jobs, distinct users, max
jobs per user — counts only, per that module's privacy contract).
Anonymous traffic has NO user identity in this product by design
and this module invents none: anonymous volume is governed by
the per-IP rate limits (core/ratelimit.py), which is the honest
control for identity-free traffic.

ARCHITECTURE. providers/ is a leaf package (tests/
test_architecture.py): this module imports NO project code. The
database side is injected — accounts/provider_usage.py installs
a `persister` (flush these delta rows) and a `loader` (read back
one provider-day's persisted call count) at process start
(app.py), the same inversion the transport injection uses in
base.py. Counts accumulate in memory and flush in batches; a
process restart loses at most one unflushed batch, and the
loader re-seeds today's persisted counts on first use so a
restart does not reset budget enforcement.

FAIL-OPEN, ALWAYS. Tracking and enforcement must never break a
provider call: every public function here swallows its own
failures. If usage cannot be determined, the call proceeds —
the budget is a safety valve against runaway volume, not a
correctness gate, and an outage of the ledger must not become
an outage of scanning.
"""

import threading
from datetime import datetime, timezone

# Daily call budgets per provider (UTC day). Operator-set safety
# budgets — see the module docstring. The arithmetic:
#
# * XposedOrNot — 2 calls per email identifier per scan job
#   (check + analytics) plus anonymous quick scans (per-IP rate
#   limited). 5,000/day ≈ thousands of scans — far above real
#   traffic, low enough to catch a runaway loop within a day.
# * Have I Been Pwned Pwned Passwords — 1 call per interactive
#   password check. Same reasoning: 5,000/day.
# * DuckDuckGo Discovery — politeness binds hardest here: the
#   discovery budget already caps a scan job at 6 queries with a
#   1 s minimum interval, and this is a public HTML endpoint we
#   are guests on. 1,000/day is generous for real traffic and
#   keeps the product a polite citizen.
# * Username Platforms — one check_username is 13 platform
#   probes (one HTTP call each through the shared client), so
#   the budget is in probes: 20,000/day ≈ 1,500 username
#   identifiers.
# * Domain Intel — one domain identifier costs ~5 calls (four
#   DNS record types + certificate names; TXT lookups extra).
#   10,000/day ≈ 2,000 domain identifiers.
BUDGETS = {
    "XposedOrNot": 5000,
    "Have I Been Pwned Pwned Passwords": 5000,
    "DuckDuckGo Discovery": 1000,
    "Username Platforms": 20000,
    "Domain Intel": 10000,
}

# Flush the in-memory counts to the ledger once this many calls
# are pending (admin metrics and the alert evaluator also flush
# before reading, so the batch size only bounds crash loss).
FLUSH_EVERY = 25


def budget_for(provider):
    """The provider's daily call budget, or None when the
    provider has no budget (untracked names, mock providers):
    no budget means no enforcement and no seeding queries."""
    return BUDGETS.get(provider)


def _utc_today():
    return datetime.now(timezone.utc).date()


class UsageTracker:
    """Thread-safe in-memory daily counts + batched persistence.

    Counts live in two places per (provider, day): `_persisted`
    (what the ledger already holds — seeded lazily via the
    loader, folded forward on every successful flush) and
    `_session` (this process's unflushed deltas). calls_today is
    the sum, which is what budget enforcement compares against.
    """

    def __init__(self, flush_every=FLUSH_EVERY, today_fn=None):
        self.flush_every = flush_every
        self._today_fn = today_fn or _utc_today
        self._lock = threading.Lock()
        self._session = {}     # (provider, day) -> [calls, ok, fail]
        self._persisted = {}   # (provider, day) -> [calls, ok, fail]
        self._seeded = set()   # (provider, day) already loader-seeded
        self._persister = None
        self._loader = None

    # ---------- injected persistence (accounts/provider_usage) --

    def set_persister(self, fn):
        """fn(rows) persists delta rows [(provider, day, calls,
        successes, failures), ...]; truthy return = written."""
        self._persister = fn

    def set_loader(self, fn):
        """fn(provider, day) -> (calls, successes, failures) the
        ledger already holds for that provider-day, or None."""
        self._loader = fn

    # ---------- test support ----------

    def set_today_fn(self, fn):
        self._today_fn = fn

    def reset(self):
        """Drop all in-memory counts and seed state (the injected
        hooks stay installed)."""
        with self._lock:
            self._session.clear()
            self._persisted.clear()
            self._seeded.clear()

    # ---------- counting ----------

    def today(self):
        return self._today_fn()

    def record(self, provider, ok):
        """Count one real provider call. In-memory only on the
        hot path; flushes when the pending batch fills. Never
        raises."""
        try:
            day = self._today_fn()
            with self._lock:
                entry = self._session.setdefault(
                    (provider, day), [0, 0, 0])
                entry[0] += 1
                entry[1 if ok else 2] += 1
                pending = sum(e[0] for e in self._session.values())
            if pending >= self.flush_every:
                self.flush()
        except Exception:
            pass

    def _seed(self, provider, day):
        """Load the persisted counts for one provider-day, once.
        Any failure seeds zeros (fail-open) and is not retried:
        an undercount weakens enforcement for a day; a retry loop
        on the call path would be worse."""
        key = (provider, day)
        with self._lock:
            if key in self._seeded:
                return
            self._seeded.add(key)
        if self._loader is None:
            return
        try:
            row = self._loader(provider, day)
        except Exception:
            row = None
        if row is None:
            return
        try:
            counts = [int(row[0]), int(row[1]), int(row[2])]
        except Exception:
            return
        with self._lock:
            base = self._persisted.setdefault(key, [0, 0, 0])
            base[0] += counts[0]
            base[1] += counts[1]
            base[2] += counts[2]

    def counts(self, provider, day=None):
        """(calls, successes, failures) for a provider-day:
        persisted + this process's session counts."""
        day = day or self._today_fn()
        self._seed(provider, day)
        key = (provider, day)
        with self._lock:
            base = self._persisted.get(key, (0, 0, 0))
            sess = self._session.get(key, (0, 0, 0))
            return (base[0] + sess[0], base[1] + sess[1],
                    base[2] + sess[2])

    def calls_today(self, provider):
        return self.counts(provider)[0]

    def is_exhausted(self, provider):
        """True when the provider has a budget and today's call
        count has reached it. No budget -> never exhausted (and
        no seeding work). Any internal failure -> False: the
        budget must never be what breaks a scan."""
        try:
            budget = budget_for(provider)
            if budget is None:
                return False
            return self.calls_today(provider) >= budget
        except Exception:
            return False

    # ---------- persistence ----------

    def flush(self):
        """Write the pending deltas through the persister.
        Returns True when everything pending was written (or
        nothing was pending). On failure the deltas are merged
        back and retried on a later flush. Never raises."""
        with self._lock:
            rows = [(provider, day, e[0], e[1], e[2])
                    for (provider, day), e in self._session.items()
                    if e[0] > 0]
            if not rows:
                return True
            self._session.clear()
        if self._persister is None:
            self._merge_back(rows)
            return False
        try:
            written = bool(self._persister(rows))
        except Exception:
            written = False
        if not written:
            self._merge_back(rows)
            return False
        with self._lock:
            for provider, day, calls, succ, fail in rows:
                base = self._persisted.setdefault(
                    (provider, day), [0, 0, 0])
                base[0] += calls
                base[1] += succ
                base[2] += fail
                # The flush just persisted this provider-day, so
                # it counts as seeded even without a loader.
                self._seeded.add((provider, day))
        return True

    def _merge_back(self, rows):
        with self._lock:
            for provider, day, calls, succ, fail in rows:
                entry = self._session.setdefault(
                    (provider, day), [0, 0, 0])
                entry[0] += calls
                entry[1] += succ
                entry[2] += fail


# The process-wide tracker. HttpClient records into it (via
# record_call below); app.py installs the persistence hooks at
# startup through accounts/provider_usage.install().
tracker = UsageTracker()


def record_call(provider, ok):
    tracker.record(provider, ok)


def is_exhausted(provider):
    return tracker.is_exhausted(provider)


def flush():
    return tracker.flush()
