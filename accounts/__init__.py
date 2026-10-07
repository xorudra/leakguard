"""Accounts, sessions, consent and the Privacy Center (Stage S3 —
spec Phases 4, 5, 6, 48, 49, 50).

Design rules for everything in this package:

* Authorization by construction: every protected query is scoped by
  the session's user_id; there is no code path that reads another
  user's rows. Unknown-or-foreign object ids answer 404, never 403.
* The account email follows the vault's privacy scheme (Stage S2):
  stored only as a keyed HMAC (label "account_email") plus an
  envelope-encrypted ciphertext plus a masked rendering.
* Passwords are Argon2id hashes; session tokens are stored only as
  SHA-256 digests; TOTP secrets are envelope-encrypted.
* Nothing personal is logged: log lines carry user ids and event
  names only — never emails, passwords, codes or secrets.
* Everything here is dormant unless the database + vault keys are
  configured; the anonymous Quick Scan never touches this package.
"""

from vault import store as _vault_store


def accounts_available():
    """True when accounts can actually serve: database configured and
    both vault keys present and well-formed. Route handlers check this
    first and answer a clean structured 503 when it is False."""
    return _vault_store.vault_configured()
