"""TOTP two-factor codes (spec Phase 4) — RFC 6238, stdlib only.

Secrets are 20 random bytes, base32-encoded for authenticator apps.
Codes are 6 digits over 30-second steps, HMAC-SHA1 per the RFC.

REPLAY PROTECTION: verify() takes the user's last accepted step and
refuses any code whose step is not strictly newer. A code that has
logged in once can therefore never log in again — even inside its
validity window, and even if the user is tricked into re-entering it.
Callers persist the returned step after every successful verification.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

ISSUER = "LeakGuard"
DIGITS = 6
PERIOD = 30
WINDOW = 1  # accept the previous and next step (clock skew)


def generate_secret():
    """A fresh base32 TOTP secret (padding stripped, app-compatible)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _secret_bytes(secret):
    text = str(secret or "").strip().upper()
    padding = "=" * (-len(text) % 8)
    return base64.b32decode(text + padding)


def otpauth_uri(secret, account_label):
    """The standard enrollment URI. Shown to the user ONCE at enroll
    time (it necessarily contains the secret) and never stored in
    plaintext or served again afterwards."""
    label = urllib.parse.quote("%s:%s" % (ISSUER, account_label))
    params = urllib.parse.urlencode({
        "secret": secret,
        "issuer": ISSUER,
        "digits": DIGITS,
        "period": PERIOD,
        "algorithm": "SHA1",
    })
    return "otpauth://totp/%s?%s" % (label, params)


def secret_hint(secret):
    """A masked hint so the user can recognize their secret later
    without us revealing it: first 4 characters + bullets."""
    text = str(secret or "")
    return (text[:4] + "••••") if len(text) > 4 else "••••"


def current_step(now=None):
    if now is None:
        now = time.time()
    return int(now // PERIOD)


def code_for_step(secret, step):
    """The 6-digit code for one step (also used by tests)."""
    digest = hmac.new(
        _secret_bytes(secret), struct.pack(">Q", int(step)), hashlib.sha1
    ).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return "%0*d" % (DIGITS, value % (10 ** DIGITS))


def generate_code(secret, step=None):
    """The code for `step` (default: the current step)."""
    if step is None:
        step = current_step()
    return code_for_step(secret, step)


def verify(secret, code, last_accepted_step=None, now=None):
    """Verify a user-supplied code.

    Returns the matched step (int) on success — the caller MUST
    persist it as the user's new last-accepted step — or None on any
    failure: wrong code, malformed code, or a REPLAYED step (matched
    step <= last_accepted_step).
    """
    if not secret or not isinstance(code, str):
        return None
    code = code.strip()
    if len(code) != DIGITS or not code.isdigit():
        return None
    step_now = current_step(now)
    matched = None
    for candidate in range(step_now - WINDOW, step_now + WINDOW + 1):
        if hmac.compare_digest(code_for_step(secret, candidate), code):
            matched = candidate
            break
    if matched is None:
        return None
    if last_accepted_step is not None and matched <= int(last_accepted_step):
        return None  # replay — this step already authenticated once
    return matched
