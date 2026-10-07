-- 0002_accounts.sql — accounts, sessions, consents, password-reset
-- tokens (Stage S3, spec Phases 4, 5, 6).
--
-- Privacy rules baked into the schema:
--   * A user's email is NEVER stored in plaintext: email_hmac is the
--     keyed HMAC (vault lookup key, label "account_email") used to find
--     the row, email_ciphertext is the envelope-encrypted value
--     (vault/crypto.py v1 layout), email_masked is the display form.
--   * Passwords are Argon2id hashes (text, PHC string) — never raw.
--   * Session tokens are stored ONLY as SHA-256 digests; the raw token
--     exists solely in the user's cookie.
--   * TOTP secrets are envelope-encrypted like identifier values.
--
-- users.email uniqueness is a PARTIAL unique index over live rows
-- (deleted_at IS NULL) — the same pattern 0001 used for identifiers —
-- so an address can be registered again after its account is deleted,
-- while two live accounts can never share one email.

CREATE TABLE IF NOT EXISTS users (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email_hmac              bytea NOT NULL,
    email_ciphertext        bytea NOT NULL,
    email_masked            text NOT NULL,
    password_hash           text NOT NULL,
    totp_secret_ciphertext  bytea NULL,
    totp_enabled            boolean NOT NULL DEFAULT false,
    totp_last_step          bigint NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    deleted_at              timestamptz NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_live_unique
    ON users (email_hmac)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS users_email_hmac_idx
    ON users (email_hmac);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash   bytea PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES users(id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sessions_user_idx
    ON sessions (user_id);

-- Consent is append-only history: every grant/withdrawal appends a new
-- row with the next version for that (user, purpose); the current
-- state is the highest version. UNIQUE(user_id, purpose, version)
-- makes concurrent appends fail loudly instead of forking history.
CREATE TABLE IF NOT EXISTS consents (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users(id),
    purpose    text NOT NULL,
    version    integer NOT NULL,
    granted    boolean NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, purpose, version)
);

CREATE INDEX IF NOT EXISTS consents_user_purpose_idx
    ON consents (user_id, purpose, version DESC);

-- Password-reset tokens: TABLE ONLY in Stage S3. There is deliberately
-- no endpoint yet — reset emails arrive with the notifications stage
-- (S8); shipping the table now avoids a later migration reshuffle.
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash bytea NOT NULL UNIQUE,
    user_id    uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz NULL
);

CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx
    ON password_reset_tokens (user_id);

-- Stage S2 deliberately left identifiers.user_id as a bare uuid column
-- ("foreign key added then, once a users table exists") — add it now.
ALTER TABLE identifiers
    ADD CONSTRAINT identifiers_user_id_fk
    FOREIGN KEY (user_id) REFERENCES users(id);
