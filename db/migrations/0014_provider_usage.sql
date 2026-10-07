-- 0014_provider_usage.sql — the provider usage ledger (spec
-- Phases 66 + 124).
--
-- provider_usage_daily: one rollup row per provider per UTC day —
-- how many calls the provider layer actually made, and how they
-- ended (successes / failures). The writer is providers/usage.py
-- (in-memory counts, flushed in batches) through the persistence
-- glue in accounts/provider_usage.py; the upsert against the
-- (provider, day) primary key increments the counters, exactly
-- like the error ledger's rollup (0013). Only REAL provider calls
-- are counted: a call the circuit breaker or the daily budget
-- refused never reached the provider, so it is not a call; the
-- mock providers make no network calls and are never counted.
--
-- The daily CALL BUDGETS themselves live in code
-- (providers/usage.py BUDGETS — named constants with their
-- rationale), not in this table: a budget is an operator policy
-- decision that belongs in reviewable source, while this table
-- is the measured fact the budget is compared against (admin
-- metrics + the Phase 77 provider_budget alert rule).
--
-- No retention prune: the table grows by one row per provider
-- per day (single digits), and the history IS the cost record
-- Phase 124 exists to keep.

CREATE TABLE IF NOT EXISTS provider_usage_daily (
    provider   text NOT NULL,
    day        date NOT NULL,
    calls      integer NOT NULL DEFAULT 0,
    successes  integer NOT NULL DEFAULT 0,
    failures   integer NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT provider_usage_daily_pk PRIMARY KEY (provider, day)
);
