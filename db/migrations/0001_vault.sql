-- 0001_vault.sql — encrypted identifier vault (Stage S2, spec Phase 3).
--
-- One row per monitored identifier (email / phone / name / address /
-- username) belonging to a user. The plaintext value is NEVER stored:
--   * hmac_lookup  — HMAC-SHA256 (lookup key) over kind + normalized
--                    value; the only way a row can be found by value.
--   * ciphertext   — envelope-encrypted value (AES-256-GCM, per-record
--                    DEK wrapped by the master key; see vault/crypto.py
--                    for the v1 byte layout). Useless without the master
--                    key, which lives only in the environment.
--   * masked       — display-safe rendering ("r•••@example.com"),
--                    computed at write time so list views never decrypt.
-- user_id is nullable for now; accounts arrive in Stage S3 and will own
-- these rows (foreign key added then, once a users table exists).
-- Soft deletion via deleted_at: erased identifiers leave no live row,
-- and the partial unique index frees the (kind, hmac) pair for a
-- future re-add while history stays auditable.

CREATE TABLE IF NOT EXISTS identifiers (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NULL,
    kind        text NOT NULL,
    hmac_lookup bytea NOT NULL,
    ciphertext  bytea NOT NULL,
    masked      text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz NULL
);

CREATE INDEX IF NOT EXISTS identifiers_hmac_lookup_idx
    ON identifiers (hmac_lookup);

-- At most one LIVE row per (kind, identifier). Soft-deleted rows do not
-- block re-adding the same identifier later.
CREATE UNIQUE INDEX IF NOT EXISTS identifiers_live_unique
    ON identifiers (kind, hmac_lookup)
    WHERE deleted_at IS NULL;
