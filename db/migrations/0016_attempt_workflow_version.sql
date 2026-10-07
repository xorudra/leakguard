-- 0016_attempt_workflow_version.sql — remediation attempts record
-- the broker workflow version they ran under (spec Phase 31).
--
-- brokers.workflow_version (migration 0005) moves only when a
-- broker's flow is deliberately re-mapped, but until now an attempt
-- row could not say WHICH version produced it — so re-mapping a
-- broker silently rewrote the meaning of its audit history, and
-- per-version failure modes were invisible. From this migration
-- on, the engine's single attempt writer (remediation/engine.py
-- _insert_attempt) stamps every new attempt with the broker's
-- workflow_version at creation time, resolved through the case's
-- broker, so attempts can be grouped by (broker, version, result)
-- and a re-map's effect is measurable instead of anecdotal.
--
-- Rows written before this migration stay NULL: the version they
-- ran under is genuinely unknown, and backfilling them with the
-- current version would fabricate history.

ALTER TABLE remediation_attempts
    ADD COLUMN IF NOT EXISTS workflow_version integer NULL;

CREATE INDEX IF NOT EXISTS remediation_attempts_version_idx
    ON remediation_attempts (workflow_version);
