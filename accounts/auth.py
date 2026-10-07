"""Account service (spec Phases 4 & 5): register / login / logout /
change password / delete account, plus TOTP enrollment management.

Every function here takes already-validated input plus — for
protected operations — the authenticated user's id, and scopes every
query by it. Handlers never pass user ids from request data.

Logging rule: events may be logged with user ids only. Emails,
passwords, TOTP codes and secrets are never logged, never returned
except where a function's contract says so (the owner-only data
export in accounts/privacy.py, and the one-time TOTP enroll URI).
"""

import re

from accounts import passwords, sessions, totp
from core import errors
from db import pool
from vault import crypto, store as vault_store

ACCOUNT_EMAIL_LABEL = "account_email"
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")

_USER_COLUMNS = (
    "id, email_hmac, email_ciphertext, email_masked, password_hash,"
    " totp_secret_ciphertext, totp_enabled, totp_last_step,"
    " created_at, updated_at, deleted_at"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_email(email):
    """Canonical account email: the vault's email normalization."""
    return vault_store.normalize("email", "" if email is None else email)


def account_email_hmac(normalized_email):
    """Lookup digest for an account email — the vault's HMAC recipe
    with the dedicated "account_email" label."""
    return vault_store.hmac_with_label(ACCOUNT_EMAIL_LABEL, normalized_email)


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def public_user(row):
    """The only user shape the API ever returns."""
    return {
        "id": str(row["id"]),
        "email_masked": row["email_masked"],
        "totp_enabled": bool(row["totp_enabled"]),
        "created_at": _iso(row["created_at"]),
    }


def _master_key():
    return crypto.load_key_from_env("VAULT_MASTER_KEY")


def reveal_email(row):
    """Decrypt the account email. For owner-only flows: the data
    export, and internal login-time use. Never log the result."""
    return crypto.decrypt_value(_master_key(), bytes(row["email_ciphertext"]))


def _get_user_by_email(normalized_email):
    digest = account_email_hmac(normalized_email)
    with pool.connection() as conn:
        return conn.execute(
            "SELECT " + _USER_COLUMNS + " FROM users"
            " WHERE email_hmac = %s AND deleted_at IS NULL",
            (digest,),
        ).fetchone()


def _get_user_by_id(user_id):
    with pool.connection() as conn:
        return conn.execute(
            "SELECT " + _USER_COLUMNS + " FROM users"
            " WHERE id = %s AND deleted_at IS NULL",
            (user_id,),
        ).fetchone()


def _invalid_credentials():
    # One identical error for unknown email, wrong password and wrong
    # TOTP code — the response must never reveal which part failed
    # (no account enumeration, spec Phase 65).
    return errors.unauthorized(
        "invalid_credentials", "Invalid email or password")


def _validate_password(password):
    if not isinstance(password, str) or len(password) < passwords.MIN_PASSWORD_LENGTH:
        raise errors.bad_request(
            "weak_password",
            "Password must be at least %d characters"
            % passwords.MIN_PASSWORD_LENGTH)


# ---------------------------------------------------------------------------
# Register / login / logout
# ---------------------------------------------------------------------------

def register(email, password):
    """Create an account + consent defaults + a first session.
    Returns (public_user, raw_session_token)."""
    normalized = normalize_email(email)
    if not EMAIL_RE.match(normalized):
        raise errors.bad_request("invalid_email", "Enter a valid email address")
    _validate_password(password)
    digest = account_email_hmac(normalized)
    from accounts import consents

    try:
        with pool.connection() as conn:
            existing = conn.execute(
                "SELECT id FROM users WHERE email_hmac = %s"
                " AND deleted_at IS NULL",
                (digest,),
            ).fetchone()
            if existing is not None:
                raise errors.conflict(
                    "email_taken",
                    "An account with this email already exists")
            row = conn.execute(
                "INSERT INTO users (email_hmac, email_ciphertext,"
                " email_masked, password_hash)"
                " VALUES (%s, %s, %s, %s) RETURNING " + _USER_COLUMNS,
                (
                    digest,
                    crypto.encrypt_value(_master_key(), normalized),
                    vault_store.mask("email", normalized),
                    passwords.hash_password(password),
                ),
            ).fetchone()
            consents.seed_defaults(conn, row["id"])
    except errors.ApiError:
        raise
    except Exception as exc:
        if type(exc).__name__ == "UniqueViolation":
            raise errors.conflict(
                "email_taken", "An account with this email already exists")
        raise
    token = sessions.create_session(row["id"])
    return public_user(row), token


def login(email, password, totp_code=None):
    """Verify credentials. Returns either {"totp_required": True}
    (credentials right, second factor still needed — NO session yet)
    or {"user": public_user, "token": raw_session_token}."""
    normalized = normalize_email(email)
    row = _get_user_by_email(normalized)
    if row is None:
        # Burn the same Argon2 time as a real verify: no timing oracle.
        passwords.verify_password(passwords.DUMMY_HASH, password or "")
        raise _invalid_credentials()
    if not passwords.verify_password(row["password_hash"], password or ""):
        raise _invalid_credentials()
    if passwords.needs_rehash(row["password_hash"]):
        with pool.connection() as conn:
            conn.execute(
                "UPDATE users SET password_hash = %s, updated_at = now()"
                " WHERE id = %s",
                (passwords.hash_password(password), row["id"]),
            )
    if row["totp_enabled"]:
        if not totp_code:
            return {"totp_required": True}
        secret = crypto.decrypt_value(
            _master_key(), bytes(row["totp_secret_ciphertext"]))
        matched = totp.verify(
            secret, str(totp_code), last_accepted_step=row["totp_last_step"])
        if matched is None:
            raise _invalid_credentials()
        with pool.connection() as conn:
            conn.execute(
                "UPDATE users SET totp_last_step = %s, updated_at = now()"
                " WHERE id = %s",
                (matched, row["id"]),
            )
    token = sessions.create_session(row["id"])
    return {"user": public_user(row), "token": token}


def logout(raw_token):
    sessions.revoke_session(raw_token)


# ---------------------------------------------------------------------------
# Password change & account deletion
# ---------------------------------------------------------------------------

def change_password(user_id, current_password, new_password, keep_token):
    """Verify the current password, set the new one, and revoke every
    OTHER session (the caller's current session survives)."""
    row = _get_user_by_id(user_id)
    if row is None:
        raise errors.unauthorized()
    if not passwords.verify_password(row["password_hash"], current_password or ""):
        raise errors.unauthorized(
            "invalid_credentials", "Current password is incorrect")
    _validate_password(new_password)
    with pool.connection() as conn:
        conn.execute(
            "UPDATE users SET password_hash = %s, updated_at = now()"
            " WHERE id = %s",
            (passwords.hash_password(new_password), user_id),
        )
    sessions.revoke_all_sessions(user_id, except_token=keep_token)


def delete_account(user_id, password):
    """Soft-delete the account: the user row, ALL of the user's
    identifiers, and every session. Consent history stays as an
    audit record but is unreachable — the user can no longer log in.
    """
    row = _get_user_by_id(user_id)
    if row is None:
        raise errors.unauthorized()
    if not passwords.verify_password(row["password_hash"], password or ""):
        raise errors.unauthorized(
            "invalid_credentials", "Password is incorrect")
    with pool.connection() as conn:
        conn.execute(
            "UPDATE users SET deleted_at = now(), updated_at = now()"
            " WHERE id = %s",
            (user_id,),
        )
        conn.execute(
            "UPDATE identifiers SET deleted_at = now(), updated_at = now()"
            " WHERE user_id = %s AND deleted_at IS NULL",
            (user_id,),
        )
    sessions.revoke_all_sessions(user_id)


# ---------------------------------------------------------------------------
# TOTP management (authenticated)
# ---------------------------------------------------------------------------

def totp_enroll(user_id):
    """Start enrollment: generate a secret, store it ENCRYPTED and
    still disabled. Returns the one-time otpauth URI + a masked hint.
    The full secret is only ever visible inside this one response."""
    row = _get_user_by_id(user_id)
    if row is None:
        raise errors.unauthorized()
    if row["totp_enabled"]:
        raise errors.bad_request(
            "totp_already_enabled",
            "Two-factor authentication is already on — disable it first")
    secret = totp.generate_secret()
    with pool.connection() as conn:
        conn.execute(
            "UPDATE users SET totp_secret_ciphertext = %s,"
            " totp_enabled = false, totp_last_step = NULL,"
            " updated_at = now() WHERE id = %s",
            (crypto.encrypt_value(_master_key(), secret), user_id),
        )
    return {
        "otpauth_uri": totp.otpauth_uri(secret, reveal_email(row)),
        "secret_hint": totp.secret_hint(secret),
    }


def totp_activate(user_id, code):
    """Activate TOTP after the user proves their authenticator works.
    The activating code's step becomes the last accepted step, so the
    same code cannot immediately be replayed at login."""
    row = _get_user_by_id(user_id)
    if row is None:
        raise errors.unauthorized()
    if row["totp_enabled"] or not row["totp_secret_ciphertext"]:
        raise errors.bad_request(
            "totp_not_enrolled",
            "Start two-factor setup first")
    secret = crypto.decrypt_value(
        _master_key(), bytes(row["totp_secret_ciphertext"]))
    matched = totp.verify(secret, str(code or ""), last_accepted_step=None)
    if matched is None:
        raise errors.bad_request(
            "invalid_code", "That code did not match — try again")
    with pool.connection() as conn:
        conn.execute(
            "UPDATE users SET totp_enabled = true, totp_last_step = %s,"
            " updated_at = now() WHERE id = %s",
            (matched, user_id),
        )
    return {"totp_enabled": True}


def totp_disable(user_id, password, code):
    """Disable TOTP. Requires BOTH the account password and a fresh
    valid code (with the usual replay protection)."""
    row = _get_user_by_id(user_id)
    if row is None:
        raise errors.unauthorized()
    if not passwords.verify_password(row["password_hash"], password or ""):
        raise errors.unauthorized(
            "invalid_credentials", "Password is incorrect")
    if not row["totp_enabled"] or not row["totp_secret_ciphertext"]:
        raise errors.bad_request(
            "totp_not_enabled", "Two-factor authentication is not on")
    secret = crypto.decrypt_value(
        _master_key(), bytes(row["totp_secret_ciphertext"]))
    matched = totp.verify(
        secret, str(code or ""), last_accepted_step=row["totp_last_step"])
    if matched is None:
        raise errors.bad_request(
            "invalid_code", "That code did not match — try again")
    with pool.connection() as conn:
        conn.execute(
            "UPDATE users SET totp_enabled = false,"
            " totp_secret_ciphertext = NULL, totp_last_step = NULL,"
            " updated_at = now() WHERE id = %s",
            (user_id,),
        )
    return {"totp_enabled": False}
