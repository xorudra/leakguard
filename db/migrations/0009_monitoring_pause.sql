-- 0009_monitoring_pause.sql — a monitoring pause switch
-- (Final spec Batch B, spec Phase 142).
--
-- Pause is NOT consent withdrawal: the 'monitoring' consent row
-- stays exactly as the user set it (append-only, 0002), and the
-- consent history keeps showing permission granted. The pause is a
-- separate, reversible operational state — "keep watching me, just
-- not right now" — stored next to the cadence it accompanies. The
-- scheduler skips paused users entirely; resuming is one settings
-- update, and nothing about the consent trail changes either way.

ALTER TABLE user_settings
    ADD COLUMN IF NOT EXISTS monitoring_paused boolean NOT NULL
    DEFAULT false;
