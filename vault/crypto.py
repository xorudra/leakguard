"""Envelope encryption for the identifier vault (spec Phase 3).

Algorithm: AES-256-GCM throughout (cryptography library).
For each record:
  1. A fresh random 32-byte data-encryption key (DEK) is generated.
  2. The value is encrypted under the DEK with a fresh random nonce.
  3. The DEK is encrypted ("wrapped") under the master key with its
     own fresh random nonce.
Rotating the master key later only requires re-wrapping DEKs, never
re-encrypting values.

Serialized form — format v1 (byte layout):

    offset  size  content
    ------  ----  -----------------------------------------------
    0       1     format version (0x01)
    1       12    wrap nonce (AES-GCM nonce for the DEK wrap)
    13      48    wrapped DEK (32-byte DEK + 16-byte GCM tag)
    61      12    data nonce (AES-GCM nonce for the value)
    73      rest  ciphertext (value bytes + 16-byte GCM tag)

Any tampering — version, nonces, wrapped DEK or ciphertext — makes
decryption raise (GCM authentication), which callers must treat as
"record unreadable", never as an empty value.

Keys are 32 raw bytes. In the environment they travel base64-encoded
(VAULT_MASTER_KEY / VAULT_LOOKUP_KEY); this module works with raw
bytes and provides load_key_from_env() for the env path. Key material
is never logged or included in exception messages.
"""

import base64
import os

_VERSION = 1
_KEY_LEN = 32
_NONCE_LEN = 12
_TAG_LEN = 16
_WRAPPED_DEK_LEN = _KEY_LEN + _TAG_LEN  # 48
_HEADER_LEN = 1 + _NONCE_LEN + _WRAPPED_DEK_LEN + _NONCE_LEN  # 73


class VaultCryptoError(Exception):
    """Encryption/decryption failure (tamper, wrong key, bad format)."""


class VaultKeyError(VaultCryptoError):
    """Missing or malformed key material in the environment."""


def _aesgcm(key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(key)


def _check_key(key, what):
    if not isinstance(key, (bytes, bytearray)) or len(key) != _KEY_LEN:
        raise VaultKeyError("%s must be exactly %d bytes" % (what, _KEY_LEN))
    return bytes(key)


def validate_key(key, what="key"):
    """Public wrapper: assert a raw key is exactly 32 bytes."""
    return _check_key(key, what)


def decode_key(encoded, what="key"):
    """Decode a base64 environment value into a raw 32-byte key."""
    if not encoded:
        raise VaultKeyError("%s is not set" % what)
    try:
        raw = base64.b64decode(str(encoded).strip(), validate=True)
    except Exception:
        raise VaultKeyError("%s is not valid base64" % what)
    return _check_key(raw, what)


def load_key_from_env(env_name):
    """Load and validate a 32-byte key from a base64 env variable."""
    return decode_key(os.environ.get(env_name), env_name)


def encrypt_value(master_key, plaintext):
    """Encrypt a string under the master key (envelope). Returns bytes
    in the v1 layout documented above."""
    master_key = _check_key(master_key, "master key")
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be str")
    dek = os.urandom(_KEY_LEN)
    wrap_nonce = os.urandom(_NONCE_LEN)
    wrapped_dek = _aesgcm(master_key).encrypt(wrap_nonce, dek, None)
    data_nonce = os.urandom(_NONCE_LEN)
    ciphertext = _aesgcm(dek).encrypt(data_nonce, plaintext.encode("utf-8"), None)
    return (
        bytes([_VERSION])
        + wrap_nonce
        + wrapped_dek
        + data_nonce
        + ciphertext
    )


def decrypt_value(master_key, blob):
    """Decrypt bytes produced by encrypt_value(). Returns the string.
    Raises VaultCryptoError on any tampering, truncation, wrong key or
    unknown format version."""
    master_key = _check_key(master_key, "master key")
    if not isinstance(blob, (bytes, bytearray)):
        raise VaultCryptoError("ciphertext must be bytes")
    blob = bytes(blob)
    if len(blob) < _HEADER_LEN + _TAG_LEN:
        raise VaultCryptoError("ciphertext is truncated")
    if blob[0] != _VERSION:
        raise VaultCryptoError("unknown ciphertext version")
    wrap_nonce = blob[1:13]
    wrapped_dek = blob[13:61]
    data_nonce = blob[61:73]
    ciphertext = blob[73:]
    try:
        dek = _aesgcm(master_key).decrypt(wrap_nonce, wrapped_dek, None)
        raw = _aesgcm(dek).decrypt(data_nonce, ciphertext, None)
    except Exception:
        raise VaultCryptoError("ciphertext failed authentication")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise VaultCryptoError("decrypted value is not valid UTF-8")
