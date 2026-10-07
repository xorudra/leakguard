"""Encrypted identifier vault (Stage S2 — spec Phase 3).

Stores monitored identifiers (email, phone, name, address, username)
without ever persisting plaintext:

* Lookup is by keyed HMAC (HMAC-SHA256, lookup key) over the kind and
  the normalized value — the database can find a row by value without
  being able to read or brute-force-reveal values on its own.
* Values are envelope-encrypted (AES-256-GCM): a fresh random data
  key per record encrypts the value; the data key is wrapped by the
  master key. Keys come from the environment (VAULT_MASTER_KEY,
  VAULT_LOOKUP_KEY, base64-encoded 32 bytes) and are never logged.
* List/display flows use the pre-computed masked rendering; plaintext
  comes back only through the explicit vault.store.reveal().
"""
