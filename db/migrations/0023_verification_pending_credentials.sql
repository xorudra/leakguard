-- 0023: bind pending credentials to the verification token
-- (run-3 hunt, 2026-10-16).
--
-- Run-2's re-register fix replaced the pending account's
-- password_hash in place — but the replacement was not bound to
-- any token: anyone who knew the address could re-register
-- AGAIN and flip the password that the victim's already-issued
-- token would activate on redemption (last-writer-wins on a
-- shared row). The credential a verification activates now
-- travels WITH the token that was minted for it: the
-- re-registrant's hash (and name ciphertext) are stored on the
-- token row, verify_email requires the redeemer to present
-- that same password, and applies the stored hash in the same
-- update that flips email_verified. Tokens minted before this
-- migration carry NULLs and redeem under the old rules.
ALTER TABLE email_verification_tokens
    ADD COLUMN IF NOT EXISTS pending_password_hash text;
ALTER TABLE email_verification_tokens
    ADD COLUMN IF NOT EXISTS pending_name_ciphertext bytea;
