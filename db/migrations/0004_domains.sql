-- 0004_domains.sql — user domains + ownership verification
-- (Stage S6, spec Phases 19, 58).
--
-- A domain is monitored ONLY after its owner proves control: adding
-- a domain issues a random verify_token; the owner publishes it as
-- the TXT record of _leakguard.<domain>; verification reads that
-- record back through DNS-over-HTTPS and compares in constant time.
-- Until then the row sits pending and the scan orchestrator refuses
-- to look at the domain at all (outcome "domain_unverified").
--
-- Domain names are NOT secret (they are public infrastructure), so
-- the domain itself is stored in plaintext, normalized. The matching
-- vault identifier (kind 'domain', added in S6) stays envelope-
-- encrypted like every other identifier; this table is the
-- verification ledger keyed by (user_id, domain).
-- Soft deletion via deleted_at, with a partial unique index so a
-- removed domain can be added again later.

CREATE TABLE IF NOT EXISTS domains (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id),
    domain      text NOT NULL,
    verify_token text NOT NULL,
    verified    boolean NOT NULL DEFAULT false,
    verified_at timestamptz NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS domains_live_unique
    ON domains (user_id, domain)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS domains_user_created_idx
    ON domains (user_id, created_at);
