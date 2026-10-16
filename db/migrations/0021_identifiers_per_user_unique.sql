-- 0021_identifiers_per_user_unique.sql — identifier uniqueness is
-- PER-USER, not global (security audit 2026-10-16, finding
-- leakguard.vault.identifier-existence-oracle-and-squatting-409).
--
-- 0001's global partial unique index on (kind, hmac_lookup) made
-- one account's saved value every other account's 409: the
-- response confirmed the value existed SOMEWHERE (a cross-account
-- existence oracle for emails/phones/usernames) and let an
-- unverified squatter block the real owner from ever saving —
-- and scanning — their own identifier.
--
-- Uniqueness now scopes to the owner: (user_id, kind, hmac_lookup)
-- for account rows. Legacy unowned rows (user_id NULL, from the
-- pre-accounts vault) keep a global uniqueness of their own so
-- the claim path in accounts/identifiers.py still finds at most
-- one claimable row per value. The plain (kind, hmac_lookup)
-- lookup index 0001 also created stays for HMAC lookups.
--
-- Reversible: DROP INDEX identifiers_live_user_unique,
-- identifiers_live_unowned_unique; recreate identifiers_live_unique
-- as in 0001 (only valid while no duplicate live values exist).

DROP INDEX IF EXISTS identifiers_live_unique;

CREATE UNIQUE INDEX IF NOT EXISTS identifiers_live_user_unique
    ON identifiers (user_id, kind, hmac_lookup)
    WHERE deleted_at IS NULL AND user_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS identifiers_live_unowned_unique
    ON identifiers (kind, hmac_lookup)
    WHERE deleted_at IS NULL AND user_id IS NULL;
