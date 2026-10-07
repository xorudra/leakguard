"""Minimal CBOR (RFC 8949) codec — just enough for WebAuthn.

WebAuthn payloads (the attestation object and the COSE public key
inside authenticator data) are CBOR. Pulling in a general CBOR
library for two small structures would break the project's
stdlib-plus-three-dependencies rule, so this module implements the
subset the ceremonies actually use, with strict bounds because
every byte it decodes is attacker-controlled:

* definite-length items only — indefinite-length maps/strings are
  rejected outright (real authenticators do not emit them here);
* input size, nesting depth and container size are capped;
* duplicate map keys are rejected (a COSE key with two `alg`
  entries is ambiguous, never legitimate);
* trailing bytes after the top-level item are an error;
* map keys must be scalars (int / text / bytes / bool / None) —
  the key types COSE and attestation objects actually use.

Supported for decoding: unsigned/negative integers, byte and text
strings, arrays, maps, tags (unwrapped — the value is returned),
booleans, null, and 16/32/64-bit floats. The encoder covers the
same scalar/container types, which is all the test fixtures and
any future server-side CBOR need.
"""

import struct

MAX_INPUT_BYTES = 256 * 1024
MAX_DEPTH = 16
MAX_CONTAINER_ITEMS = 1024


class CborError(ValueError):
    """Any malformed or out-of-bounds CBOR input."""


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

def _read_argument(data, offset, ai):
    """Resolve an item's argument (a count or value) from the
    additional-information nibble. Returns (argument, next_offset)."""
    if ai < 24:
        return ai, offset
    if ai == 24:
        width = 1
    elif ai == 25:
        width = 2
    elif ai == 26:
        width = 4
    elif ai == 27:
        width = 8
    elif ai == 31:
        raise CborError("indefinite-length items are not accepted")
    else:  # 28, 29, 30 are reserved
        raise CborError("reserved additional information")
    if offset + width > len(data):
        raise CborError("truncated input")
    return int.from_bytes(data[offset:offset + width], "big"), offset + width


def _decode_item(data, offset, depth):
    """Decode one item starting at offset. Returns (value, next)."""
    if depth > MAX_DEPTH:
        raise CborError("nesting too deep")
    if offset >= len(data):
        raise CborError("truncated input")
    initial = data[offset]
    major = initial >> 5
    ai = initial & 0x1F
    offset += 1

    if major == 7:  # simple values and floats
        if ai == 20:
            return False, offset
        if ai == 21:
            return True, offset
        if ai in (22, 23):  # null / undefined
            return None, offset
        if ai == 25:
            if offset + 2 > len(data):
                raise CborError("truncated input")
            value = struct.unpack(">e", data[offset:offset + 2])[0]
            return value, offset + 2
        if ai == 26:
            if offset + 4 > len(data):
                raise CborError("truncated input")
            value = struct.unpack(">f", data[offset:offset + 4])[0]
            return value, offset + 4
        if ai == 27:
            if offset + 8 > len(data):
                raise CborError("truncated input")
            value = struct.unpack(">d", data[offset:offset + 8])[0]
            return value, offset + 8
        raise CborError("unsupported simple value")

    argument, offset = _read_argument(data, offset, ai)

    if major == 0:
        return argument, offset
    if major == 1:
        return -1 - argument, offset
    if major == 2:
        end = offset + argument
        if end > len(data):
            raise CborError("truncated input")
        return bytes(data[offset:end]), end
    if major == 3:
        end = offset + argument
        if end > len(data):
            raise CborError("truncated input")
        try:
            return data[offset:end].decode("utf-8"), end
        except UnicodeDecodeError:
            raise CborError("invalid UTF-8 in text string")
    if major == 4:
        if argument > MAX_CONTAINER_ITEMS:
            raise CborError("container too large")
        items = []
        for _ in range(argument):
            value, offset = _decode_item(data, offset, depth + 1)
            items.append(value)
        return items, offset
    if major == 5:
        if argument > MAX_CONTAINER_ITEMS:
            raise CborError("container too large")
        result = {}
        for _ in range(argument):
            key, offset = _decode_item(data, offset, depth + 1)
            if not isinstance(key, (int, str, bytes, bool, float, type(None))):
                raise CborError("unsupported map key type")
            if key in result:
                raise CborError("duplicate map key")
            value, offset = _decode_item(data, offset, depth + 1)
            result[key] = value
        return result, offset
    if major == 6:  # tag: unwrap, the tagged value is what matters
        return _decode_item(data, offset, depth + 1)
    raise CborError("unknown major type")  # unreachable, major is 3 bits


def decode(data):
    """Decode exactly one CBOR item from `data` (bytes) and require
    it to consume the whole input. Raises CborError on anything
    malformed or out of bounds."""
    if not isinstance(data, (bytes, bytearray)):
        raise CborError("CBOR input must be bytes")
    if len(data) > MAX_INPUT_BYTES:
        raise CborError("input too large")
    value, offset = _decode_item(bytes(data), 0, 0)
    if offset != len(data):
        raise CborError("trailing bytes after CBOR item")
    return value


def decode_one(data, offset=0):
    """Decode one item starting at `offset` inside a larger buffer
    (authenticator data embeds a COSE key mid-structure). Returns
    (value, next_offset). Same bounds as decode()."""
    if not isinstance(data, (bytes, bytearray)):
        raise CborError("CBOR input must be bytes")
    if len(data) > MAX_INPUT_BYTES:
        raise CborError("input too large")
    if offset < 0 or offset > len(data):
        raise CborError("offset out of range")
    return _decode_item(bytes(data), offset, 0)


# ---------------------------------------------------------------------------
# Encoding (fixtures / symmetry — the server never sends CBOR)
# ---------------------------------------------------------------------------

def _encode_head(major, argument):
    if argument < 24:
        return bytes([(major << 5) | argument])
    if argument <= 0xFF:
        return bytes([(major << 5) | 24, argument])
    if argument <= 0xFFFF:
        return bytes([(major << 5) | 25]) + argument.to_bytes(2, "big")
    if argument <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + argument.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + argument.to_bytes(8, "big")


def encode(value):
    """Encode a Python value to CBOR bytes. Supports None, bool,
    int, float, bytes, str, list/tuple and dict (scalar keys)."""
    if value is None:
        return b"\xf6"
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if isinstance(value, int):
        if value >= 0:
            return _encode_head(0, value)
        return _encode_head(1, -1 - value)
    if isinstance(value, float):
        return b"\xfb" + struct.pack(">d", value)
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        return _encode_head(2, len(raw)) + raw
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _encode_head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        out = [_encode_head(4, len(value))]
        for item in value:
            out.append(encode(item))
        return b"".join(out)
    if isinstance(value, dict):
        out = [_encode_head(5, len(value))]
        for key, item in value.items():
            out.append(encode(key))
            out.append(encode(item))
        return b"".join(out)
    raise CborError("cannot encode %s" % type(value).__name__)
