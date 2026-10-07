-- 0005_remediation.sql — broker registry + remediation engine v2
-- (Stage S7, spec Phases 30–39, 153–157, 167).
--
-- Privacy / honesty rules baked into the schema:
--   * brokers is a REGISTRY: public facts about data brokers (their
--     opt-out pages, channels, workflow versions). Seeded idempotently
--     from brokers.json + playbooks.json by remediation/registry_seed.py;
--     brokers.json stays the anonymous flow's source and the fallback
--     when no database is configured.
--   * remediation_cases carry NO identifier values — just the user id,
--     the broker slug and lifecycle state. The worker assembles the
--     profile from the vault at run time (Stage S2/S3 pattern).
--   * A case is NEVER proof of removal. The status only reaches
--     'verified_removed' through a verification_checks row whose
--     outcome is 'gone' (spec rule 8: submission is not removal).
--   * 'LIVE CASE' — the idempotency unit of the whole engine — is a
--     case whose status is NOT IN ('verified_removed', 'failed'):
--     queued, running, submitted, needs_human, blocked and reappeared
--     cases are all still in play, so at most one live case may exist
--     per (user_id, broker_slug). A verified-removed or failed case is
--     closed history: a fresh case may be opened for that broker
--     (e.g. when data reappears) without violating the index.
--   * remediation_attempts is the audit trail: EVERY engine action
--     (probe, letter, submit, consent check, routing) appends a row.
--     The erasure letter for email-channel brokers lives in the
--     attempt detail jsonb — it is the user's own letter, shown only
--     to them in their human-action queue; it is never logged.

CREATE TABLE IF NOT EXISTS brokers (
    slug              text PRIMARY KEY,
    name              text NOT NULL,
    category          text NOT NULL,
    region            text NOT NULL,
    optout_url        text NOT NULL,
    alt_optout_url    text NULL,
    search_url        text NULL,
    method_notes      text NOT NULL DEFAULT '',
    contact_email     text NULL,
    contact_email_alt text NULL,
    channel           text NOT NULL DEFAULT 'manual'
                      CHECK (channel IN ('form', 'email', 'manual')),
    workflow_version  integer NOT NULL DEFAULT 1,
    position          integer NOT NULL DEFAULT 0,
    active            boolean NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS remediation_cases (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES users(id),
    broker_slug  text NOT NULL REFERENCES brokers(slug),
    finding_id   uuid NULL REFERENCES findings(id),
    status       text NOT NULL DEFAULT 'queued'
                 CHECK (status IN ('queued', 'running', 'submitted',
                                   'needs_human', 'verified_removed',
                                   'reappeared', 'failed', 'blocked')),
    reason       text NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    submitted_at timestamptz NULL
);

-- At most one LIVE case per (user, broker) — see the definition above.
CREATE UNIQUE INDEX IF NOT EXISTS remediation_cases_live_unique
    ON remediation_cases (user_id, broker_slug)
    WHERE status NOT IN ('verified_removed', 'failed');

CREATE INDEX IF NOT EXISTS remediation_cases_user_idx
    ON remediation_cases (user_id, created_at);

-- The worker's claim scan: queued cases, oldest first.
CREATE INDEX IF NOT EXISTS remediation_cases_claim_idx
    ON remediation_cases (status, created_at);

CREATE TABLE IF NOT EXISTS remediation_attempts (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id    uuid NOT NULL REFERENCES remediation_cases(id),
    attempt_no integer NOT NULL,
    action     text NOT NULL,
    result     text NOT NULL,
    detail     jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS remediation_attempts_case_idx
    ON remediation_attempts (case_id, attempt_no);

CREATE TABLE IF NOT EXISTS verification_checks (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id      uuid NOT NULL REFERENCES remediation_cases(id),
    checked_at   timestamptz NOT NULL DEFAULT now(),
    method       text NOT NULL,
    outcome      text NOT NULL
                 CHECK (outcome IN ('still_present', 'gone', 'unknown')),
    evidence_ref text NULL
);

CREATE INDEX IF NOT EXISTS verification_checks_case_idx
    ON verification_checks (case_id, checked_at);
