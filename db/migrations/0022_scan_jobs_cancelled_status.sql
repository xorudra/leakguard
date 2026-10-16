-- 0022_scan_jobs_cancelled_status.sql — scan_jobs gains the
-- terminal 'cancelled' status (security audit 2026-10-16,
-- scanning.worker-no-liveness-or-consent-recheck).
--
-- The worker now re-checks owner liveness and lane consent at
-- execution time; a job whose owner was deleted or withdrew
-- consent after queueing ends 'cancelled' (error_kind carries
-- the reason) instead of running — or failing through the retry
-- budget into 'dead', which an admin replay could resurrect.
-- 0003's status CHECK did not know the word, so it is widened
-- here. The constraint keeps 0003's auto-generated name.
--
-- Reversible: set any 'cancelled' rows to 'dead', then re-add
-- the constraint with 0003's original five values.

ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_status_check;

ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_status_check
    CHECK (status IN ('queued', 'running', 'done',
                      'failed', 'dead', 'cancelled'));
