"""Password hashing (spec Phase 4): Argon2id via argon2-cffi.

Only PHC-format hash strings ("$argon2id$v=19$...") are ever stored.
The plaintext password exists only for the duration of one request.

argon2-cffi is imported lazily so importing this module never fails;
hashing is only reachable when accounts are configured, and
requirements.txt carries the dependency.
"""

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
