-- 0015_data_quality.sql — the findings data-quality stage (spec
-- Phase 160): per-row flags on findings + the run ledger and the
-- per-provider issue rollup the stage writes.
--
-- The stage (scanning/data_quality.py) DETECTS and RECORDS; it
-- never deletes or rewrites a finding. Its output is:
--
--   findings.dq_duplicate / findings.dq_malformed
--       Per-row flags, recomputed from the stored data on every
--       run (a flag is a claim about the row as it stands now,
--       so a later run can also clear one). No read path filters
--       on them in this phase — they are an operator signal
--       surfaced through the admin metrics, not a visibility
--       change. Two booleans rather than one flags column: each
--       is queried and counted independently, and the pair stays
--       greppable in SQL without array gymnastics.
--
--   dq_runs
--       One row per completed run: when it ran, how many stored
--       findings it examined, and how many rows carry each flag
--       after the run. This is also the stage's self-gate: the
--       scheduler tick asks for a run at most ~daily by reading
--       MAX(ran_at) (the source-sweep pattern, remediation/
--       source_checks.py), and the admin metrics read the latest
--       row as "last run".
--
--   dq_issue_rollup
--       One row per provider per run-day per issue kind: how many
--       of that provider's rows are currently flagged. Flags
--       alone are current truth, not a time series — the rollup
--       is what makes DRIFT visible (a provider whose payload
--       shape changed shows up as a step in its malformed count
--       from one day to the next). The writer REPLACES the day's
--       rows on each run (a snapshot, not an increment), exactly
--       as the flags themselves are recomputed.
--
-- No retention prune: dq_runs is one row a day and the rollup is
-- a handful of providers x 2 kinds a day — the history is the
-- drift record Phase 160 exists to keep, like the provider
-- usage ledger (0014).

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS dq_duplicate boolean NOT NULL
    DEFAULT false;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS dq_malformed boolean NOT NULL
    DEFAULT false;

CREATE TABLE IF NOT EXISTS dq_runs (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ran_at             timestamptz NOT NULL DEFAULT now(),
    findings_scanned   integer NOT NULL DEFAULT 0,
    duplicates_flagged integer NOT NULL DEFAULT 0,
    malformed_flagged  integer NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dq_issue_rollup (
    provider   text NOT NULL,
    day        date NOT NULL,
    kind       text NOT NULL CHECK (kind IN ('duplicate', 'malformed')),
    count      integer NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT dq_issue_rollup_pk PRIMARY KEY (provider, day, kind)
);
