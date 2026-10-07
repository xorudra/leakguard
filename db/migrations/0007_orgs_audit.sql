-- 0007_orgs_audit.sql — households (family profiles) + the audit
-- log (Stage S11, spec Phases 57–62, 106–114).
--
-- Privacy rules baked into the schema:
--   * A household groups the people whose details ONE account
--     protects. A household member is a LABEL the owner types
--     ("Mum", "Dad") — never an identifier value, never an email,
--     never credentials. Members cannot log in; they exist only so
--     identifiers can say whose they are.
--   * identifiers.member_id is nullable: NULL means "the account
--     owner themself". Deleting a member SETs member_id NULL
--     (ON DELETE SET NULL) — identifiers are never deleted or
--     orphaned with a member.
--   * audit_log.detail is PII-free BY CONSTRUCTION: call sites pass
--     counts, enums and ids only — never identifier values, emails
--     or secrets — and accounts/audit.py filters detail down to
--     plain scalars as a second line of defence. actor_user_id
--     deliberately carries NO foreign key, so the log stays intact
--     and truthful even after an account is deleted.

CREATE TABLE IF NOT EXISTS households (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id uuid NOT NULL UNIQUE REFERENCES users(id),
    name          text NOT NULL DEFAULT 'My household',
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS household_members (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    household_id uuid NOT NULL REFERENCES households(id)
                 ON DELETE CASCADE,
    label        text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS household_members_household_idx
    ON household_members (household_id, created_at);

ALTER TABLE identifiers
    ADD COLUMN IF NOT EXISTS member_id uuid NULL
    REFERENCES household_members(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS identifiers_member_idx
    ON identifiers (member_id) WHERE member_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS audit_log (
    id            bigserial PRIMARY KEY,
    actor_user_id uuid NULL,
    actor_kind    text NOT NULL
                  CHECK (actor_kind IN ('user', 'admin', 'system')),
    action        text NOT NULL,
    target_kind   text NULL,
    target_id     text NULL,
    detail        jsonb NOT NULL DEFAULT '{}',
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_log_created_idx
    ON audit_log (created_at DESC);

CREATE INDEX IF NOT EXISTS audit_log_actor_idx
    ON audit_log (actor_user_id, created_at DESC);
