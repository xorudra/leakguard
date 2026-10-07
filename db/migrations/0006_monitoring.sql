-- 0006_monitoring.sql — monitoring settings + notifications
-- (Stage S8, spec Phases 41–47, 99, 158–160).
--
-- Privacy / honesty rules baked into the schema:
--   * user_settings holds ONLY the monitoring cadence. Whether
--     monitoring runs at all is the 'monitoring' consent's business
--     (append-only consents table, 0002) — a cadence is never a
--     permission.
--   * notifications is the delivery LEDGER: every notification the
--     system decided to create is a row, including the ones that
--     were never emailed. status is the honest outcome —
--     'unsent_no_lane' when no email lane is configured, 'failed'
--     when the lane refused, 'in_app_only' when the user never
--     granted the notifications consent, 'suppressed' when the
--     7-day dedupe window swallowed a repeat. A notification may
--     only say 'sent' after the lane accepted it (spec rule: never
--     claim delivery that did not happen).
--   * dedupe_key identifies a logical event ('new:<finding hash>',
--     'summary:<job id>', ...) so repeats within 7 days collapse.
--     The 7-day window cannot be expressed in an index predicate
--     (now() is not immutable), so the window is enforced in code
--     inside a transaction (monitoring/notify.py); the plain index
--     below just makes that check fast.
--   * password_reset payloads carry the reset URL — it IS the
--     delivery content. It is never logged, and the notifications
--     API projection redacts it (monitoring/service.py).

CREATE TABLE IF NOT EXISTS user_settings (
    user_id              uuid PRIMARY KEY REFERENCES users(id),
    monitor_cadence_days integer NOT NULL DEFAULT 7
                         CHECK (monitor_cadence_days IN (7, 14, 30)),
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS notifications (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users(id),
    kind       text NOT NULL
               CHECK (kind IN ('new_finding', 'finding_resolved',
                               'removal_verified', 'reappeared',
                               'password_reset', 'scan_summary')),
    dedupe_key text NULL,
    payload    jsonb NOT NULL DEFAULT '{}',
    status     text NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending', 'sent', 'failed',
                                 'suppressed', 'unsent_no_lane',
                                 'in_app_only')),
    created_at timestamptz NOT NULL DEFAULT now(),
    sent_at    timestamptz NULL
);

CREATE INDEX IF NOT EXISTS notifications_user_created_idx
    ON notifications (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS notifications_dedupe_idx
    ON notifications (user_id, dedupe_key, created_at DESC);
