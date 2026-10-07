-- 0003_scans.sql — full-profile scan jobs + normalized findings
-- (Stage S5, spec Phases 11, 12, 21).
--
-- Privacy rules baked into the schema:
--   * scan_jobs carry NO identifier values — a job is just a user id,
--     an idempotency key and lifecycle state. The worker resolves the
--     user's identifiers through the vault at run time.
--   * findings NEVER store the identifier value either: identifier_id
--     points at the vault row (whose value stays envelope-encrypted),
--     and evidence_ref is a SHA-256 over a canonical payload whose only
--     identifier component is the vault lookup HMAC (see
--     scanning/normalize.py). Password findings store a pwned COUNT in
--     details — never a password, never any part of a hash.
--   * Jobs are idempotent per (user_id, idempotency_key): one click =
--     one job, however many times the request is retried.

CREATE TABLE IF NOT EXISTS scan_jobs (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           uuid NOT NULL REFERENCES users(id),
    idempotency_key   text NOT NULL,
    status            text NOT NULL DEFAULT 'queued'
                      CHECK (status IN ('queued', 'running', 'done',
                                        'failed', 'dead')),
    attempts          integer NOT NULL DEFAULT 0,
    next_attempt_at   timestamptz NULL,
    error_kind        text NULL,
    score             integer NULL,
    score_explanation jsonb NULL,
    summary           jsonb NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    started_at        timestamptz NULL,
    finished_at       timestamptz NULL,
    UNIQUE (user_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS scan_jobs_user_created_idx
    ON scan_jobs (user_id, created_at DESC);

-- The worker's claim scan: queued jobs, plus failed jobs whose
-- backoff has expired, oldest first.
CREATE INDEX IF NOT EXISTS scan_jobs_claim_idx
    ON scan_jobs (status, created_at);

CREATE TABLE IF NOT EXISTS findings (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id                uuid NOT NULL REFERENCES scan_jobs(id),
    user_id               uuid NOT NULL REFERENCES users(id),
    identifier_id         uuid NULL REFERENCES identifiers(id),
    identifier_kind       text NOT NULL,
    provider              text NOT NULL,
    source_name           text NOT NULL,
    source_url            text NULL,
    source_date           date NULL,
    discovered_at         timestamptz NOT NULL DEFAULT now(),
    exposed_fields        text[] NOT NULL DEFAULT '{}',
    confidence            text NOT NULL
                          CHECK (confidence IN ('exact', 'probable', 'weak')),
    reliability           text NOT NULL
                          CHECK (reliability IN ('high', 'medium', 'low')),
    status                text NOT NULL DEFAULT 'open',
    evidence_ref          text NOT NULL,
    remediation_eligible  boolean NOT NULL DEFAULT false,
    details               jsonb NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS findings_job_idx
    ON findings (job_id);

CREATE INDEX IF NOT EXISTS findings_user_discovered_idx
    ON findings (user_id, discovered_at DESC);

CREATE INDEX IF NOT EXISTS findings_identifier_idx
    ON findings (identifier_id);
