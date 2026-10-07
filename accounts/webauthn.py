"""WebAuthn passkeys (spec Phase 4 — the optional stronger
authentication method, Batch D1).

Passkeys are an ADDITIONAL way in. Password + TOTP login is
untouched, and no account ever needs a passkey: enrollment is
opt-in from the Privacy Center, and password sign-in keeps working
for accounts that have passkeys.

What the server stores is only what a relying party may store: the
credential's PUBLIC key (COSE encoding), its id, a signature
counter and the owner's nickname for it. The private key never
leaves the user's authenticator, so nothing in these tables can
sign in as anyone — and nothing here is a secret worth logging:
credential ids are looked up by SHA-256 hash and API responses
carry only an 8-character display prefix (the API-token rule).

Security decisions, all deliberate:

* ATTESTATION: only format "none" is accepted. Any other format
  (packed, tpm, fido-u2f, android-key, ...) is rejected by name —
  this server does not pretend to verify attestation statements it
  has not implemented. Options therefore request attestation
  "none", which is what browsers return for it.
* ALGORITHMS: ES256 (COSE -7, P-256) and RS256 (COSE -257,
  RSA >= 2048-bit). Anything else is rejected at registration.
* FLAGS: user presence (UP) is required in both ceremonies. User
  verification (UV) is REQUIRED for sign-in — a passkey sign-in
  replaces the password entirely, so the authenticator must prove
  a person unlocked it (fingerprint / face / PIN), not merely that
  a key exists. Enrollment asks for UV "preferred" rather than
  requiring it: enrollment is already behind a session plus a
  password re-check, and the UV rule bites at every sign-in.
* TOTP: a passkey sign-in does not additionally demand a TOTP
  code. The UV-required ceremony is itself possession + user
  verification in one step; stacking TOTP on top would make
  passkeys strictly worse than the password path they replace for
  the users who enabled both.
* SIGN COUNTERS: if either the stored or the presented counter is
  non-zero, the presented one must be strictly greater —
  a regression means a cloned authenticator and the sign-in fails
  like any other bad assertion. Authenticators that always report
  0 (both sides zero) are accepted, as the spec allows.
* CHALLENGES: 32 random bytes, stored only as SHA-256, 5-minute
  expiry, consumed atomically on first use (a failed ceremony
  burns its challenge — retry means a fresh one). Registration
  challenges are bound to the account AND to a hash of the session
  that requested them; sign-in challenges are user-less because
  the credential itself identifies the account (discoverable
  credentials — the sign-in ceremony never asks for an email, so
  it cannot reveal whether any account or passkey exists).
* FAILURES: every sign-in failure — unknown credential, bad
  signature, wrong origin, expired challenge, revoked key,
  counter regression — returns the ONE generic 401, so the
  ceremony is not an oracle for which check failed. Registration
  failures (an already-authenticated context) may be specific.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from accounts import audit, auth, cbor, passwords, ratelimit, sessions
from core import errors
from db import pool

RP_NAME = "LeakGuard"
CHALLENGE_TTL = timedelta(minutes=5)
_TIMEOUT_MS = 60000
_MAX_NICKNAME = 60
_MAX_CREDENTIAL_ID = 1024
_MAX_CLIENT_DATA = 16 * 1024
_MAX_ATTESTATION_OBJECT = 64 * 1024
_MAX_SIGNATURE = 1024
_KNOWN_TRANSPORTS = ("usb", "nfc", "ble", "internal", "hybrid",
                     "smart-card")

PURPOSE_REGISTRATION = "registration"
PURPOSE_AUTHENTICATION = "authentication"

_FLAG_UP = 0x01
_FLAG_UV = 0x04
_FLAG_AT = 0x40
_FLAG_ED = 0x80

# Attestation formats this server can verify: exactly one.
_SUPPORTED_ATTESTATION = "none"


class _PasskeyFailure(Exception):
    """An internal 'this ceremony failed verification' signal.
    Converted to the ceremony-appropriate ApiError by the public
    functions — never escapes this module."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _b64url_encode(raw):
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


def _b64url_decode(text, max_bytes):
    """Strict base64url decode of a client-supplied string.
    Raises _PasskeyFailure on anything malformed or oversized."""
    if not isinstance(text, str) or not text or len(text) > 4 * max_bytes + 8:
        raise _PasskeyFailure("malformed base64url")
    try:
        raw = base64.b64decode(
            text.encode("ascii") + b"=" * (-len(text) % 4),
            altchars=b"-_", validate=True)
    except Exception:
        raise _PasskeyFailure("malformed base64url")
    if len(raw) > max_bytes:
        raise _PasskeyFailure("value too large")
    return raw


def _sha256(raw):
    return hashlib.sha256(raw).digest()


# ---------------------------------------------------------------------------
# RP configuration (relying-party id + expected origin)
# ---------------------------------------------------------------------------

_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


def rp_config(headers):
    """Resolve (rp_id, expected_origin) for this request.

    Priority: the explicit environment overrides
    LEAKGUARD_WEBAUTHN_ORIGIN / LEAKGUARD_WEBAUTHN_RP_ID win (set
    them in production if the derivation ever needs pinning).
    Otherwise the origin is derived from the request's Origin
    header — trusted only when it names the very host this request
    was sent to (the same-host rule core/security.py applies for
    CSRF), or when an env origin pins the answer anyway. With no
    Origin header at all, the Host header is used with https
    assumed (production is HTTPS-only; http is derived solely for
    localhost development). An RP id is a bare hostname, never a
    URL, and is always the origin's host unless overridden.
    """
    env_origin = (os.environ.get("LEAKGUARD_WEBAUTHN_ORIGIN") or "")
    env_origin = env_origin.strip().rstrip("/").lower()
    env_rp = (os.environ.get("LEAKGUARD_WEBAUTHN_RP_ID") or "")
    env_rp = env_rp.strip().lower()

    origin = None
    raw_origin = headers.get("Origin") if headers is not None else None
    if raw_origin:
        parsed = urllib.parse.urlparse(str(raw_origin).strip())
        if parsed.scheme in ("https", "http") and parsed.netloc:
            origin = "%s://%s" % (parsed.scheme, parsed.netloc.lower())
    if env_origin:
        origin = env_origin
    if origin is None:
        host = (headers.get("Host") or "").strip().lower() \
            if headers is not None else ""
        if not host:
            raise errors.unavailable(
                "webauthn_unavailable",
                "Passkeys are not available on this address")
        hostname = host.rsplit(":", 1)[0].strip("[]")
        scheme = "http" if hostname in _LOCAL_HOSTS else "https"
        origin = "%s://%s" % (scheme, host)
    else:
        host = (headers.get("Host") or "").strip().lower() \
            if headers is not None else ""
        netloc = urllib.parse.urlparse(origin).netloc
        if netloc != host and not env_origin:
            # An Origin that does not name this host is not a
            # derivation source — fall back to the host itself.
            hostname = host.rsplit(":", 1)[0].strip("[]")
            scheme = "http" if hostname in _LOCAL_HOSTS else "https"
            origin = "%s://%s" % (scheme, host) if host else origin
    parsed = urllib.parse.urlparse(origin)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" and hostname not in _LOCAL_HOSTS:
        raise errors.unavailable(
            "webauthn_unavailable",
            "Passkeys need a secure (https) address")
    rp_id = env_rp or hostname
    if not rp_id:
        raise errors.unavailable(
            "webauthn_unavailable",
            "Passkeys are not available on this address")
    return rp_id, origin


# ---------------------------------------------------------------------------
# Challenges
# ---------------------------------------------------------------------------

def _create_challenge(purpose, user_id=None, session_hash=None):
    raw = secrets.token_bytes(32)
    now = datetime.now(timezone.utc)
    with pool.connection() as conn:
        conn.execute(
            "INSERT INTO webauthn_challenges"
            " (challenge_hash, purpose, user_id, session_hash, expires_at)"
            " VALUES (%s, %s, %s, %s, %s)",
            (_sha256(raw), purpose, user_id, session_hash,
             now + CHALLENGE_TTL),
        )
    return raw


def _consume_challenge(raw, purpose, user_id=None, session_hash=None):
    """Atomically consume a challenge: exists, right purpose,
    unexpired, never used, and bound to this user/session where the
    ceremony requires binding. Raises _PasskeyFailure otherwise.
    The single UPDATE ... WHERE consumed_at IS NULL is what makes
    concurrent replays lose."""
    digest = _sha256(raw)
    with pool.connection() as conn:
        row = conn.execute(
            "UPDATE webauthn_challenges SET consumed_at = now()"
            " WHERE challenge_hash = %s AND purpose = %s"
            " AND consumed_at IS NULL AND expires_at > now()"
            " RETURNING user_id, session_hash",
            (digest, purpose),
        ).fetchone()
    if row is None:
        raise _PasskeyFailure("challenge unknown, expired or used")
    if row["user_id"] is not None and (
            user_id is None or str(row["user_id"]) != str(user_id)):
        raise _PasskeyFailure("challenge bound to another user")
    if row["session_hash"] is not None:
        if session_hash is None or not hmac.compare_digest(
                bytes(row["session_hash"]), bytes(session_hash)):
            raise _PasskeyFailure("challenge bound to another session")


# ---------------------------------------------------------------------------
# WebAuthn data parsing
# ---------------------------------------------------------------------------

def _parse_client_data(raw, expected_type, expected_origin):
    """Parse + validate clientDataJSON. Returns the raw challenge
    bytes it carries. Raises _PasskeyFailure on any mismatch."""
    if len(raw) > _MAX_CLIENT_DATA:
        raise _PasskeyFailure("clientDataJSON too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        raise _PasskeyFailure("clientDataJSON is not JSON")
    if not isinstance(data, dict):
        raise _PasskeyFailure("clientDataJSON is not an object")
    if data.get("type") != expected_type:
        raise _PasskeyFailure("wrong ceremony type")
    if data.get("origin") != expected_origin:
        raise _PasskeyFailure("origin mismatch")
    return _b64url_decode(data.get("challenge"), 64)


class _AuthData:
    __slots__ = ("rp_id_hash", "flags", "sign_count", "aaguid",
                 "credential_id", "cose_bytes", "raw")


def _parse_auth_data(raw, expect_attested):
    """Parse authenticator data (WebAuthn §6.1). Raises
    _PasskeyFailure on truncation or malformed structure."""
    if len(raw) < 37:
        raise _PasskeyFailure("authenticator data too short")
    parsed = _AuthData()
    parsed.raw = raw
    parsed.rp_id_hash = raw[:32]
    parsed.flags = raw[32]
    parsed.sign_count = int.from_bytes(raw[33:37], "big")
    parsed.aaguid = None
    parsed.credential_id = None
    parsed.cose_bytes = None
    offset = 37
    if parsed.flags & _FLAG_AT:
        if len(raw) < offset + 18:
            raise _PasskeyFailure("attested credential data truncated")
        parsed.aaguid = raw[offset:offset + 16]
        offset += 16
        cred_len = int.from_bytes(raw[offset:offset + 2], "big")
        offset += 2
        if cred_len == 0 or cred_len > _MAX_CREDENTIAL_ID:
            raise _PasskeyFailure("credential id length out of range")
        if len(raw) < offset + cred_len:
            raise _PasskeyFailure("credential id truncated")
        parsed.credential_id = raw[offset:offset + cred_len]
        offset += cred_len
        # The COSE key is one CBOR item; decode_one bounds it and
        # tells us exactly where it ends.
        try:
            _key, offset = cbor.decode_one(raw, offset)
        except cbor.CborError:
            raise _PasskeyFailure("COSE key is not valid CBOR")
        parsed.cose_bytes = raw[37 + 18 + cred_len:offset]
    elif expect_attested:
        raise _PasskeyFailure("no attested credential data")
    if parsed.flags & _FLAG_ED:
        # Extension data follows as one more CBOR item; its content
        # is never used, but it must be well-formed.
        try:
            _ext, offset = cbor.decode_one(raw, offset)
        except cbor.CborError:
            raise _PasskeyFailure("extension data is not valid CBOR")
    if offset != len(raw):
        raise _PasskeyFailure("trailing bytes in authenticator data")
    return parsed


def _check_rp_and_presence(parsed, rp_id, require_uv):
    if not hmac.compare_digest(parsed.rp_id_hash, _sha256(rp_id.encode("utf-8"))):
        raise _PasskeyFailure("rpIdHash mismatch")
    if not parsed.flags & _FLAG_UP:
        raise _PasskeyFailure("user presence flag missing")
    if require_uv and not parsed.flags & _FLAG_UV:
        raise _PasskeyFailure("user verification flag missing")


def _public_key_from_cose(cose_bytes):
    """Parse a COSE public key into a cryptography public-key
    object. Only ES256 / P-256 and RS256 / RSA>=2048 are accepted.
    Raises _PasskeyFailure on anything else."""
    try:
        key = cbor.decode(cose_bytes)
    except cbor.CborError:
        raise _PasskeyFailure("COSE key is not valid CBOR")
    if not isinstance(key, dict):
        raise _PasskeyFailure("COSE key is not a map")
    kty = key.get(1)
    alg = key.get(3)
    if kty == 2:  # EC2
        if alg != -7:
            raise _PasskeyFailure("unsupported EC algorithm")
        if key.get(-1) != 1:  # curve 1 = P-256
            raise _PasskeyFailure("unsupported curve")
        x, y = key.get(-2), key.get(-3)
        if not (isinstance(x, bytes) and len(x) == 32
                and isinstance(y, bytes) and len(y) == 32):
            raise _PasskeyFailure("EC coordinates malformed")
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"),
            ec.SECP256R1())
        try:
            return ("ec", numbers.public_key())
        except ValueError:
            raise _PasskeyFailure("EC point is not on the curve")
    if kty == 3:  # RSA
        if alg != -257:
            raise _PasskeyFailure("unsupported RSA algorithm")
        n, e = key.get(-1), key.get(-2)
        if not (isinstance(n, bytes) and isinstance(e, bytes)
                and 0 < len(e) <= 8):
            raise _PasskeyFailure("RSA parameters malformed")
        numbers = rsa.RSAPublicNumbers(
            int.from_bytes(e, "big"), int.from_bytes(n, "big"))
        try:
            public = numbers.public_key()
        except ValueError:
            raise _PasskeyFailure("RSA parameters malformed")
        if public.key_size < 2048:
            raise _PasskeyFailure("RSA key too small")
        return ("rsa", public)
    raise _PasskeyFailure("unsupported key type")


def _verify_signature(kind, public_key, signature, signed_bytes):
    try:
        if kind == "ec":
            public_key.verify(signature, signed_bytes,
                              ec.ECDSA(hashes.SHA256()))
        else:
            public_key.verify(signature, signed_bytes,
                              padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise _PasskeyFailure("signature does not verify")
    except Exception:
        raise _PasskeyFailure("signature malformed")


def _response_parts(payload, *names):
    """Pull the response object and its named base64url fields out
    of a ceremony payload, with shape + size validation."""
    if not isinstance(payload, dict):
        raise _PasskeyFailure("payload is not an object")
    response = payload.get("response")
    if not isinstance(response, dict):
        raise _PasskeyFailure("payload has no response object")
    return response, {
        name: _b64url_decode(response.get(name), cap)
        for name, cap in names
    }


# ---------------------------------------------------------------------------
# Public shapes
# ---------------------------------------------------------------------------

def _public_passkey(row):
    """The only passkey shape the API returns: metadata and an
    8-character display prefix of the credential id — never the
    full id, never the public key."""
    return {
        "id": str(row["id"]),
        "id_prefix": _b64url_encode(bytes(row["credential_id"]))[:8],
        "nickname": row["nickname"],
        "created_at": auth._iso(row["created_at"]),
        "last_used_at": auth._iso(row["last_used_at"]),
    }


# ---------------------------------------------------------------------------
# Registration (authenticated session + password re-auth)
# ---------------------------------------------------------------------------

def _live_credentials(user_id):
    with pool.connection() as conn:
        return conn.execute(
            "SELECT id, credential_id, nickname, created_at, last_used_at"
            " FROM passkey_credentials"
            " WHERE user_id = %s AND revoked_at IS NULL"
            " ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()


def registration_options(user_id, password, session_token, headers,
                         client_ip):
    """Begin enrollment: password re-auth (counted by the same
    credential rate limiter as login/export, so this can never
    become a password oracle on a stolen session), then a fresh
    challenge bound to this user + session."""
    rp_id, _origin = rp_config(headers)
    row = auth._get_user_by_id(user_id)
    if row is None:
        raise errors.unauthorized()
    buckets = ("ip:" + str(client_ip),
               "email:" + bytes(row["email_hmac"]).hex())
    if not ratelimit.allow(buckets):
        raise errors.too_many_requests()
    if not passwords.verify_password(row["password_hash"], password):
        raise errors.unauthorized(
            "invalid_credentials", "Invalid email or password")
    challenge = _create_challenge(
        PURPOSE_REGISTRATION, user_id=user_id,
        session_hash=sessions._token_hash(session_token))
    user_handle = uuid.UUID(str(user_id)).bytes
    return {
        "challenge": _b64url_encode(challenge),
        "rp": {"name": RP_NAME, "id": rp_id},
        "user": {
            "id": _b64url_encode(user_handle),
            "name": row["email_masked"],
            "displayName": row["email_masked"],
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257},
        ],
        "excludeCredentials": [
            {"type": "public-key",
             "id": _b64url_encode(bytes(cred["credential_id"]))}
            for cred in _live_credentials(user_id)
        ],
        "authenticatorSelection": {
            "residentKey": "preferred",
            "userVerification": "preferred",
        },
        "timeout": _TIMEOUT_MS,
        "attestation": _SUPPORTED_ATTESTATION,
    }


def _registration_failure(code, message):
    return errors.bad_request(code, message)


def complete_registration(user_id, session_token, payload, headers):
    """Finish enrollment: validate the ceremony (challenge, origin,
    RP hash, presence flag, attestation format 'none', COSE key)
    and store the credential. Registration happens inside an
    authenticated session, so failures may say what went wrong."""
    rp_id, origin = rp_config(headers)
    try:
        response, parts = _response_parts(
            payload,
            ("clientDataJSON", _MAX_CLIENT_DATA),
            ("attestationObject", _MAX_ATTESTATION_OBJECT),
        )
        raw_id = _b64url_decode(payload.get("rawId"), _MAX_CREDENTIAL_ID)
        if payload.get("id") != _b64url_encode(raw_id):
            raise _PasskeyFailure("credential id mismatch")
        raw_challenge = _parse_client_data(
            parts["clientDataJSON"], "webauthn.create", origin)
        _consume_challenge(
            raw_challenge, PURPOSE_REGISTRATION, user_id=user_id,
            session_hash=sessions._token_hash(session_token))
        try:
            attestation = cbor.decode(parts["attestationObject"])
        except cbor.CborError:
            raise _PasskeyFailure("attestation object is not valid CBOR")
        if not isinstance(attestation, dict):
            raise _PasskeyFailure("attestation object is not a map")
        fmt = attestation.get("fmt")
        if fmt != _SUPPORTED_ATTESTATION:
            label = fmt if isinstance(fmt, str) and 0 < len(fmt) <= 32 \
                and all(32 <= ord(c) < 127 for c in fmt) else "unknown"
            raise _registration_failure(
                "attestation_format_unsupported",
                "This passkey's attestation format (%s) is not "
                "supported — LeakGuard accepts passkeys created "
                "without attestation" % label)
        auth_data_raw = attestation.get("authData")
        if not isinstance(auth_data_raw, bytes):
            raise _PasskeyFailure("attestation has no authenticator data")
        parsed = _parse_auth_data(auth_data_raw, expect_attested=True)
        _check_rp_and_presence(parsed, rp_id, require_uv=False)
        if not hmac.compare_digest(parsed.credential_id, raw_id):
            raise _PasskeyFailure("credential id mismatch")
        _public_key_from_cose(parsed.cose_bytes)  # validate only; stored raw
    except _PasskeyFailure as exc:
        raise _registration_failure("passkey_registration_failed", str(exc))
    nickname = payload.get("nickname")
    if not isinstance(nickname, str) or not nickname.strip():
        raise _registration_failure(
            "nickname_required", "Give the passkey a name first")
    nickname = nickname.strip()[:_MAX_NICKNAME]
    transports = payload.get("transports")
    if isinstance(transports, list):
        transports = [t for t in transports
                      if isinstance(t, str) and t in _KNOWN_TRANSPORTS][:6]
    else:
        transports = None
    try:
        with pool.connection() as conn:
            row = conn.execute(
                "INSERT INTO passkey_credentials"
                " (user_id, credential_id, credential_id_hash,"
                " public_key_cose, sign_count, aaguid, transports, nickname)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
                " RETURNING id, credential_id, nickname, created_at,"
                " last_used_at",
                (user_id, parsed.credential_id,
                 _sha256(parsed.credential_id), parsed.cose_bytes,
                 parsed.sign_count, parsed.aaguid, transports, nickname),
            ).fetchone()
    except Exception as exc:
        if type(exc).__name__ == "UniqueViolation":
            raise errors.conflict(
                "passkey_exists", "That passkey is already added")
        raise
    audit.record(user_id, "user", "auth.passkey_registered",
                 "passkey", row["id"])
    return _public_passkey(row)


# ---------------------------------------------------------------------------
# Management (session + CSRF in the handler; revoke re-auths)
# ---------------------------------------------------------------------------

def list_passkeys(user_id):
    return [_public_passkey(row) for row in _live_credentials(user_id)]


def revoke_passkey(user_id, passkey_id, password):
    """Revoke one of the caller's own passkeys. Password re-auth —
    the same pattern as account deletion and the data export: a
    stolen session alone cannot strip the account's stronger
    sign-in method. A foreign or unknown id answers 404."""
    row = auth._get_user_by_id(user_id)
    if row is None:
        raise errors.unauthorized()
    if not passwords.verify_password(row["password_hash"], password):
        raise errors.unauthorized(
            "invalid_credentials", "Password is incorrect")
    try:
        uuid.UUID(str(passkey_id))
    except (ValueError, AttributeError, TypeError):
        raise errors.not_found("Passkey not found")
    with pool.connection() as conn:
        updated = conn.execute(
            "UPDATE passkey_credentials SET revoked_at = now()"
            " WHERE id = %s AND user_id = %s AND revoked_at IS NULL"
            " RETURNING id",
            (passkey_id, user_id),
        ).fetchone()
    if updated is None:
        raise errors.not_found("Passkey not found")
    audit.record(user_id, "user", "auth.passkey_revoked",
                 "passkey", passkey_id)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Authentication (public, discoverable credentials)
# ---------------------------------------------------------------------------

def authentication_options(headers):
    """Begin sign-in: a fresh user-less challenge. Nothing in the
    response depends on any account, so the ceremony cannot reveal
    whether an account — or a passkey — exists."""
    rp_id, _origin = rp_config(headers)
    challenge = _create_challenge(PURPOSE_AUTHENTICATION)
    return {
        "challenge": _b64url_encode(challenge),
        "rpId": rp_id,
        "timeout": _TIMEOUT_MS,
        "userVerification": "required",
        "allowCredentials": [],
    }


def _generic_failure():
    # ONE identical failure for every assertion problem (see the
    # module docstring): the ceremony must not be an oracle.
    return errors.unauthorized(
        "passkey_failed",
        "Passkey sign-in failed — try again or use your password")


def complete_authentication(payload, headers, client_ip):
    """Finish sign-in: validate the assertion end to end and, on
    success, create the same server-side session a password login
    creates. Returns (public_user, raw_session_token)."""
    if not ratelimit.allow(("ip:" + str(client_ip),)):
        raise errors.too_many_requests()
    rp_id, origin = rp_config(headers)
    try:
        response, parts = _response_parts(
            payload,
            ("clientDataJSON", _MAX_CLIENT_DATA),
            ("authenticatorData", _MAX_ATTESTATION_OBJECT),
            ("signature", _MAX_SIGNATURE),
        )
        raw_id = _b64url_decode(payload.get("rawId"), _MAX_CREDENTIAL_ID)
        if payload.get("id") != _b64url_encode(raw_id):
            raise _PasskeyFailure("credential id mismatch")
        with pool.connection() as conn:
            cred = conn.execute(
                "SELECT id, user_id, credential_id, public_key_cose,"
                " sign_count FROM passkey_credentials"
                " WHERE credential_id_hash = %s AND revoked_at IS NULL",
                (_sha256(raw_id),),
            ).fetchone()
        if cred is None or not hmac.compare_digest(
                bytes(cred["credential_id"]), raw_id):
            raise _PasskeyFailure("unknown credential")
        user_row = auth._get_user_by_id(cred["user_id"])
        if user_row is None:  # soft-deleted account: sessions refuse too
            raise _PasskeyFailure("account unavailable")
        raw_challenge = _parse_client_data(
            parts["clientDataJSON"], "webauthn.get", origin)
        _consume_challenge(raw_challenge, PURPOSE_AUTHENTICATION)
        parsed = _parse_auth_data(parts["authenticatorData"],
                                  expect_attested=False)
        _check_rp_and_presence(parsed, rp_id, require_uv=True)
        kind, public_key = _public_key_from_cose(bytes(cred["public_key_cose"]))
        signed = parts["authenticatorData"] + _sha256(parts["clientDataJSON"])
        _verify_signature(kind, public_key, parts["signature"], signed)
        stored_count = int(cred["sign_count"])
        if parsed.sign_count != 0 or stored_count != 0:
            if parsed.sign_count <= stored_count:
                raise _PasskeyFailure("signature counter regressed")
    except _PasskeyFailure:
        raise _generic_failure()
    with pool.connection() as conn:
        conn.execute(
            "UPDATE passkey_credentials SET sign_count = %s,"
            " last_used_at = now() WHERE id = %s",
            (parsed.sign_count, cred["id"]),
        )
    token = sessions.create_session(cred["user_id"])
    audit.record(cred["user_id"], "user", "auth.passkey_login",
                 "user", cred["user_id"])
    return auth.public_user(user_row), token
