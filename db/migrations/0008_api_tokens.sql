-- 0008_api_tokens.sql — personal API tokens (Stage S13, spec
-- Phases 126–132).
--
-- A token lets the owner's own scripts READ their LeakGuard data
-- (action center, scans, removal cases, notifications, timeline)
-- without a browser session. Privacy rules baked into the schema:
--   * Only the SHA-256 digest of the raw token is stored — the
--     same at-rest rule as session tokens (0002) — so a database
--     leak yields no usable token. The raw value is returned to the
--     owner exactly once, at creation.
--   * `prefix` is the first 8 characters of the raw token (the
--     "lg_" marker plus 5 characters): enough for the owner to
--     tell their tokens apart in a list, useless for logging in.
--   * scopes exists for the future; the only scope today is
--     'read', and tokens never authorize mutations regardless.
--   * user_id cascades on delete so the retention worker's hard
--     purge of a deleted account (core/retention.py) removes the
--     account's tokens with everything else it owns.

CREATE TABLE IF NOT EXISTS api_tokens (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         text NOT NULL,
    token_hash   bytea NOT NULL UNIQUE,
    prefix       text NOT NULL,
    scopes       text[] NOT NULL DEFAULT '{read}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz NULL,
    revoked_at   timestamptz NULL
);

CREATE INDEX IF NOT EXISTS api_tokens_user_idx
    ON api_tokens (user_id, created_at DESC);
