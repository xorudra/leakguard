-- 0017_user_name.sql — optional display name collected at sign-up
-- (owner request, 2026-10-08: "when we click Create a free account
-- it should ask name too").
--
-- Privacy rule, same as the account email: the name is personal
-- data, so it is stored ONLY as vault ciphertext (name_ciphertext,
-- encrypted under VAULT_MASTER_KEY by accounts/auth.py). There is
-- deliberately no plaintext or masked name column — the API
-- decrypts it for the signed-in owner only, and account deletion /
-- retention purge take it with the rest of the users row.
-- NULL = accounts created before this migration (or via paths
-- that do not collect a name); the API returns name: null for them.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS name_ciphertext bytea NULL;
