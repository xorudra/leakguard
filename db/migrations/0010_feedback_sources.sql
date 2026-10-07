-- 0010_feedback_sources.sql — false-positive feedback + broker
-- source change detection (Final spec Batch C, spec Phases 156,
-- 32, 125).
--
-- finding_feedback: one row per (user, finding) verdict. 'not_me'
-- means "this exposure is not about me" — the finding row itself is
-- never edited or deleted (it is evidence of what a source said);
-- the verdict lives alongside it and every surface that counts or
-- alerts on findings consults it through ONE helper
-- (scanning/feedback.py), so the scan view, the Action Center and
-- the monitoring alerts cannot drift apart. 'confirmed' is the
-- explicit "yes, this is me". No row = no opinion.
--
-- broker_source_checks: the latest probe of each broker's opt-out
-- page (remediation/source_checks.py) — status + a SHA-256 of the
-- body, capped at 64KB by the fetcher. Only the hash is kept, never
-- the page: a changed hash means the broker touched its opt-out
-- page and a human should re-check the playbook. The table doubles
-- as the sweep's own 24h stamp (max(checked_at)).

CREATE TABLE IF NOT EXISTS finding_feedback (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id),
    finding_id  uuid NOT NULL REFERENCES findings(id),
    verdict     text NOT NULL CHECK (verdict IN ('not_me', 'confirmed')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, finding_id)
);

CREATE INDEX IF NOT EXISTS finding_feedback_user_idx
    ON finding_feedback (user_id);

CREATE TABLE IF NOT EXISTS broker_source_checks (
    slug         text PRIMARY KEY,
    url          text NOT NULL,
    status       integer NULL,
    content_hash text NULL,
    state        text NOT NULL
                 CHECK (state IN ('ok', 'changed', 'unreachable')),
    checked_at   timestamptz NOT NULL DEFAULT now()
);
