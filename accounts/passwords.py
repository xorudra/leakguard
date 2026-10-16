"""Password hashing (spec Phase 4): Argon2id via argon2-cffi.

Only PHC-format hash strings ("$argon2id$v=19$...") are ever stored.
The plaintext password exists only for the duration of one request.

argon2-cffi is imported lazily so importing this module never fails;
hashing is only reachable when accounts are configured, and
requirements.txt carries the dependency.

breached_count() below is the k-anonymity breach screen (audit
2026-10-16, leakguard.accounts.register-weak-password-no-breach-
screening): the same lane the visitor password checker uses, so a
password already circulating in breach dumps is refused at
registration / change / reset. Only the first 5 characters of the
password's SHA-1 ever leave the server.
"""

import hashlib

# A real Argon2id hash of a throwaway value. Login attempts for an
# UNKNOWN email verify against this dummy so they cost the same time
# as a wrong-password attempt on a real account — blunting the timing
# side channel that would otherwise enumerate registered emails.
DUMMY_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$bPmg6l3145jcMCzZoYhtQg"
    "$T4QakFQ63EmxkH1rgn5HZiujIfuMzW+3TUkuK7t8mvc"
)

MIN_PASSWORD_LENGTH = 10


def _hasher():
    from argon2 import PasswordHasher

    return PasswordHasher()  # argon2-cffi defaults ARE Argon2id


def breached_count(password):
    """How many times this password appears in the HIBP Pwned
    Passwords corpus, via the registry's password_range providers
    (k-anonymity: only the SHA-1 prefix is sent; the suffix match
    is computed here). None when the lane cannot answer (provider
    down, budget exhausted, registry unavailable) — callers FAIL
    OPEN on None: screening is defence in depth behind the length
    floor and the credential rate limiter, and the lane's
    availability must never decide who can register."""
    try:
        from providers import registry as provider_registry

        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        reg = provider_registry.get_registry()
        for provider in reg.get_providers("password_range"):
            result = provider.check_range(prefix)
            if result.status != "ok" or not result.data:
                continue
            for line in str(result.data).splitlines():
                parts = line.strip().split(":")
                if len(parts) != 2:
                    continue
                if parts[0].strip().upper() == suffix:
                    try:
                        return int(parts[1])
                    except ValueError:
                        return 1
            return 0
    except Exception:
        return None
    return None


def hash_password(password):
    """Hash a plaintext password for storage (PHC string)."""
    return _hasher().hash(password)


def verify_password(stored_hash, password):
    """True iff `password` matches the stored Argon2id hash. Any
    malformed hash or mismatch is simply False — never an exception
    leaking which part failed."""
    if not stored_hash or not isinstance(password, str):
        return False
    try:
        return _hasher().verify(stored_hash, password)
    except Exception:  # VerifyMismatchError, InvalidHashError, ...
        return False


def needs_rehash(stored_hash):
    """True when the stored hash uses outdated parameters and should
    be re-created at the next successful login."""
    if not stored_hash:
        return False
    try:
        return _hasher().check_needs_rehash(stored_hash)
    except Exception:
        return False
