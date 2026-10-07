"""Offline vault tests (Stage S2 — spec Phase 3).

Pure-function coverage only: envelope encryption roundtrip + tamper
detection, lookup-HMAC determinism/separation, normalization and
masking. No database, no network, and only EPHEMERAL keys generated
inside the test process (never the production key files).

Run:  python3 -m unittest discover -s tests
"""

import base64
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vault import crypto, store  # noqa: E402

MASTER_KEY = os.urandom(32)
OTHER_KEY = os.urandom(32)
LOOKUP_KEY = os.urandom(32)


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


class TestEnvelopeCrypto(unittest.TestCase):
    def test_roundtrip(self):
        blob = crypto.encrypt_value(MASTER_KEY, "someone@example.com")
        self.assertEqual(blob[0], 1)  # v1 format byte
        self.assertEqual(
            crypto.decrypt_value(MASTER_KEY, blob), "someone@example.com")

    def test_roundtrip_unicode_and_empty(self):
        for value in ("", "Grüße ß", "x" * 5000):
            blob = crypto.encrypt_value(MASTER_KEY, value)
            self.assertEqual(crypto.decrypt_value(MASTER_KEY, blob), value)

    def test_fresh_dek_and_nonces(self):
        a = crypto.encrypt_value(MASTER_KEY, "same value")
        b = crypto.encrypt_value(MASTER_KEY, "same value")
        self.assertNotEqual(a, b)  # random DEK + nonces per record
        self.assertEqual(crypto.decrypt_value(MASTER_KEY, a), "same value")
        self.assertEqual(crypto.decrypt_value(MASTER_KEY, b), "same value")

    def test_tampered_ciphertext_rejected(self):
        blob = bytearray(crypto.encrypt_value(MASTER_KEY, "victim@example.com"))
        blob[-1] ^= 0x01  # flip one bit in the ciphertext/tag
        with self.assertRaises(crypto.VaultCryptoError):
            crypto.decrypt_value(MASTER_KEY, bytes(blob))

    def test_tampered_wrapped_dek_rejected(self):
        blob = bytearray(crypto.encrypt_value(MASTER_KEY, "victim@example.com"))
        blob[20] ^= 0x01  # inside the wrapped-DEK region (bytes 13..60)
        with self.assertRaises(crypto.VaultCryptoError):
            crypto.decrypt_value(MASTER_KEY, bytes(blob))

    def test_tampered_version_rejected(self):
        blob = bytearray(crypto.encrypt_value(MASTER_KEY, "victim@example.com"))
        blob[0] = 0x7F
        with self.assertRaises(crypto.VaultCryptoError):
            crypto.decrypt_value(MASTER_KEY, bytes(blob))

    def test_truncated_rejected(self):
        blob = crypto.encrypt_value(MASTER_KEY, "victim@example.com")
        with self.assertRaises(crypto.VaultCryptoError):
            crypto.decrypt_value(MASTER_KEY, blob[:40])

    def test_wrong_master_key_rejected(self):
        blob = crypto.encrypt_value(MASTER_KEY, "victim@example.com")
        with self.assertRaises(crypto.VaultCryptoError):
            crypto.decrypt_value(OTHER_KEY, blob)

    def test_key_validation(self):
        with self.assertRaises(crypto.VaultKeyError):
            crypto.encrypt_value(b"too short", "x")
        with self.assertRaises(crypto.VaultKeyError):
            crypto.decode_key("not base64 !!!")
        with self.assertRaises(crypto.VaultKeyError):
            crypto.decode_key(b64(b"31 bytes is not enough......")[:40])
        self.assertEqual(crypto.decode_key(b64(MASTER_KEY)), MASTER_KEY)


class TestLookupHmac(unittest.TestCase):
    def test_deterministic(self):
        a = store.lookup_hmac("email", "person@example.com", LOOKUP_KEY)
        b = store.lookup_hmac("email", "person@example.com", LOOKUP_KEY)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 32)  # SHA-256 digest

    def test_kind_separation(self):
        as_email = store.lookup_hmac("email", "same-string", LOOKUP_KEY)
        as_username = store.lookup_hmac("username", "same-string", LOOKUP_KEY)
        self.assertNotEqual(as_email, as_username)

    def test_normalization_equivalence(self):
        messy = store.lookup_hmac("email", "  Person@Example.COM ", LOOKUP_KEY)
        clean = store.lookup_hmac("email", "person@example.com", LOOKUP_KEY)
        self.assertEqual(messy, clean)

    def test_distinct_values_distinct_digests(self):
        a = store.lookup_hmac("email", "a@example.com", LOOKUP_KEY)
        b = store.lookup_hmac("email", "b@example.com", LOOKUP_KEY)
        self.assertNotEqual(a, b)

    def test_lookup_key_from_env(self):
        old = os.environ.get("VAULT_LOOKUP_KEY")
        os.environ["VAULT_LOOKUP_KEY"] = b64(LOOKUP_KEY)
        try:
            via_env = store.lookup_hmac("email", "person@example.com")
            explicit = store.lookup_hmac(
                "email", "person@example.com", LOOKUP_KEY)
            self.assertEqual(via_env, explicit)
        finally:
            if old is None:
                os.environ.pop("VAULT_LOOKUP_KEY", None)
            else:
                os.environ["VAULT_LOOKUP_KEY"] = old


class TestNormalize(unittest.TestCase):
    def test_email(self):
        self.assertEqual(
            store.normalize("email", "  Foo@Bar.COM "), "foo@bar.com")

    def test_phone_digits_and_intl_prefix(self):
        self.assertEqual(
            store.normalize("phone", "+91 98765 43210"), "919876543210")
        self.assertEqual(
            store.normalize("phone", "0091 98765 43210"), "919876543210")
        self.assertEqual(
            store.normalize("phone", "(020) 7946 0958"), "02079460958")

    def test_name_whitespace_and_case(self):
        self.assertEqual(
            store.normalize("name", "  Jane   Marie \t Doe "), "jane marie doe")
        self.assertEqual(
            store.normalize("username", "  Cool  Handle "), "cool handle")

    def test_address(self):
        self.assertEqual(
            store.normalize("address", " 12,  MG   Road "), "12, mg road")

    def test_unknown_kind(self):
        with self.assertRaises(ValueError):
            store.normalize("passport", "X123")


class TestMask(unittest.TestCase):
    def test_email(self):
        self.assertEqual(
            store.mask("email", "rudra@example.com"), "r•••@example.com")
        self.assertEqual(
            store.mask("email", "  A@Example.com "), "a•••@example.com")

    def test_phone(self):
        self.assertEqual(store.mask("phone", "+91 98765 43210"), "•••10")
        self.assertEqual(store.mask("phone", "123"), "•••23")

    def test_others_first_character(self):
        self.assertEqual(store.mask("name", "Rudra Singh"), "R•••")
        self.assertEqual(store.mask("username", "shadow"), "s•••")
        self.assertEqual(store.mask("address", "12 MG Road"), "1•••")

    def test_mask_never_contains_the_value(self):
        masked = store.mask("email", "secretperson@example.com")
        self.assertNotIn("secretperson", masked)
        self.assertNotIn("98765", store.mask("phone", "+91 98765 43210"))


class TestNotConfigured(unittest.TestCase):
    def test_put_raises_cleanly_without_env(self):
        saved = {k: os.environ.pop(k, None) for k in
                 ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")}
        try:
            self.assertFalse(store.vault_configured())
            with self.assertRaises(store.VaultNotConfiguredError):
                store.put("email", "a@b.com")
            with self.assertRaises(store.VaultNotConfiguredError):
                store.get_by_lookup("email", "a@b.com")
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v


if __name__ == "__main__":
    unittest.main()
