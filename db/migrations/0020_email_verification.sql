-- 0020_email_verification.sql — email-ownership verification for
-- registration (security audit 2026-10-16, findings
-- leakguard.accounts.register-unverified-email-prehijack and
-- leakguard.accounts.register-admin-email-impersonation).
--
-- Registration no longer mints a session on the strength of a
-- typed password alone: a new account starts UNVERIFIED and cannot
-- sign in until it redeems a single-use token mailed to the
-- address (the password_reset_tokens pattern: digest-only storage).
--
-- email_verified defaults TRUE so every account that already
-- exists — created before verification existed — keeps signing in
-- exactly as today; only rows inserted by the new register() are
-- written unverified (explicit false at insert). Verification
-- gates NEW registrations only.
--
-- The same change admits the transactional security kinds the
-- fixes notify through ('email_verification',
-- 'registration_attempt', 'totp_activated', 'totp_cleared') to the
-- notifications kind CHECK (pattern from 0013).

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_verified boolean NOT NULL
        DEFAULT true;

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash bytea NOT NULL UNIQUE,
    user_id    uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz NULL
);

CREATE INDEX IF NOT EXISTS email_verification_tokens_user_idx
    ON email_verification_tokens (user_id);

ALTER TABLE notifications
    DROP CONSTRAINT IF EXISTS notifications_kind_check;

ALTER TABLE notifications
    ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('new_finding', 'finding_resolved',
                    'removal_verified', 'reappeared',
                    'password_reset', 'scan_summary',
                    'engineering_alert', 'email_verification',
                    'registration_attempt', 'totp_activated',
                    'totp_cleared'));
