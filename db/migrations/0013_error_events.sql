-- 0013_error_events.sql — the server-side error ledger (spec
-- Phase 76) + the engineering-alert notification kind (Phase 77).
--
-- error_events: one row per DISTINCT server-side error per hour
-- bucket, with an occurrence counter. An "error" is identified by
-- (context, error_class, message_hash): context is a short label
-- of the call site, error_class the exception class name, and
-- message_hash the sha256 of the message — NEVER the raw message,
-- because log messages can sit next to user data; the hash lets
-- identical failures dedupe and be counted without storing text.
-- bucket_start is the hour the occurrences belong to
-- (date_trunc('hour', now())); the UNIQUE constraint over the
-- four columns is what the writer upserts against
-- (core/error_ledger.py). created_at is the FIRST occurrence in
-- the bucket, last_seen_at the most recent one. Retention prunes
-- rows older than 30 days (core/retention.py).

CREATE TABLE IF NOT EXISTS error_events (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    bucket_start     timestamptz NOT NULL
                     DEFAULT date_trunc('hour', now()),
    context          text NOT NULL,
    error_class      text NOT NULL,
    message_hash     text NOT NULL,
    request_id       text NULL,
    occurrence_count integer NOT NULL DEFAULT 1,
    CONSTRAINT error_events_dedupe_unique
        UNIQUE (context, error_class, message_hash, bucket_start)
);

CREATE INDEX IF NOT EXISTS error_events_created_idx
    ON error_events (created_at);

CREATE INDEX IF NOT EXISTS error_events_bucket_idx
    ON error_events (bucket_start);

-- Phase 77: engineering alerts are delivered to the owner through
-- the notification ledger like everything else, so 'engineering_alert'
-- joins the allowed kinds. (The constraint name is the one Postgres
-- gave the inline CHECK in 0006 — verified against pg_constraint.)
ALTER TABLE notifications
    DROP CONSTRAINT IF EXISTS notifications_kind_check;

ALTER TABLE notifications
    ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('new_finding', 'finding_resolved',
                    'removal_verified', 'reappeared',
                    'password_reset', 'scan_summary',
                    'engineering_alert'));
