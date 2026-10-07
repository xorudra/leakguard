-- 0011_passkeys.sql — WebAuthn passkeys (Batch D1, spec Phase 4:
-- the optional stronger authentication method alongside Argon2id
-- passwords and TOTP).
--
-- Privacy / security rules baked into the schema:
--   * A passkey's PUBLIC key is all that is ever stored — the
--     private key never leaves the user's authenticator, so this
--     table holds nothing that can sign in as anyone. public keys
--     are stored in their COSE encoding (parsed and validated at
--     registration and at every assertion).
--   * The credential id is not a secret in WebAuthn, but lookups
--     still go through credential_id_hash (SHA-256, UNIQUE): the
--     raw id is only ever compared byte-for-byte server-side and
--     API responses show an 8-character display prefix, never the
--     full id — the same minimize-exposure rule as API tokens
--     (0008).
--   * Challenges are single-use rows: only the SHA-256 of the
--     random challenge is stored, each row carries its ceremony
--     purpose, an expiry, and a consumed_at stamp that the verify
--     step sets atomically — a challenge can never be replayed.
--     Registration challenges are additionally bound to the user
--     and to a hash of the session that requested them.
--   * Revocation is a timestamp (revoked_at), checked on every
--     sign-in; rows are never deleted by user action.
--   * user_id cascades on delete so the retention worker's hard
--     purge of a deleted account removes the account's passkeys
--     and challenges with everything else it owns (retention also
--     deletes both tables explicitly, in FK-safe order).

CREATE TABLE IF NOT EXISTS passkey_credentials (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id      bytea NOT NULL,
    credential_id_hash bytea NOT NULL UNIQUE,
    public_key_cose    bytea NOT NULL,
    sign_count         bigint NOT NULL DEFAULT 0,
    aaguid             bytea NULL,
    transports         text[] NULL,
    nickname           text NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    last_used_at       timestamptz NULL,
    revoked_at         timestamptz NULL
);

CREATE INDEX IF NOT EXISTS passkey_credentials_user_idx
    ON passkey_credentials (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_hash bytea NOT NULL UNIQUE,
    purpose        text NOT NULL
                   CHECK (purpose IN ('registration', 'authentication')),
    user_id        uuid NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash   bytea NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz NULL
);

CREATE INDEX IF NOT EXISTS webauthn_challenges_expiry_idx
    ON webauthn_challenges (expires_at);
