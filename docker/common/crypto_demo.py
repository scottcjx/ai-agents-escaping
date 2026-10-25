"""
A small authenticated stream cipher, standard-library only.

WHY HAND-ROLLED: the `cryptography` package is not installed in the demo
environment. This construction (encrypt-then-MAC over an HMAC-SHA256 keystream)
is sound enough for a *classroom demo*, but for anything real use a vetted
library primitive such as `cryptography.fernet.Fernet` or AES-GCM. It is here so
the demo encrypts/decrypts honestly rather than pretending.

Note also that this is ENCRYPTION, not hashing: hashing is one-way and cannot be
reversed. Recovering the message needs the key, which is why the agent must go
and fetch the key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

SCHEME = "demo-cipher-v1"
_BLOCK = hashlib.sha256().digest_size  # 32


def generate_key() -> bytes:
    """A fresh 32-byte random key."""
    return os.urandom(32)


def _subkeys(key: bytes) -> tuple[bytes, bytes]:
    enc = hmac.new(key, b"enc", hashlib.sha256).digest()
    mac = hmac.new(key, b"mac", hashlib.sha256).digest()
    return enc, mac


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(
            enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256
        ).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(key: bytes, plaintext: str) -> str:
    """Return a base64url token: nonce || ciphertext || tag."""
    enc_key, mac_key = _subkeys(key)
    nonce = os.urandom(16)
    data = plaintext.encode("utf-8")
    ct = _xor(data, _keystream(enc_key, nonce, len(data)))
    tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(nonce + ct + tag).decode("ascii")


def decrypt(key: bytes, token: str) -> str:
    """Verify the tag, then recover the plaintext. Raises on tampering."""
    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    nonce, ct, tag = raw[:16], raw[16:-_BLOCK], raw[-_BLOCK:]
    enc_key, mac_key = _subkeys(key)
    expected = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("authentication failed: wrong key or tampered ciphertext")
    return _xor(ct, _keystream(enc_key, nonce, len(ct))).decode("utf-8")


def key_to_text(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).decode("ascii")


def key_from_text(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))
