"""AES (EAX mode) symmetric encryption helpers used by the demo app.

The key is deterministically derived from a fixed demo phrase using SHA-256
so that a sender and receiver running the same code can interoperate without
exchanging key material out-of-band. This is intentional simplification for
classroom/demo purposes only - do NOT reuse this design for real systems.

Wire format produced by ``encrypt_message`` and consumed by ``decrypt_message``::

    [ 16 bytes nonce ][ 16 bytes tag ][ N bytes ciphertext ]
"""

from __future__ import annotations

from hashlib import sha256

from Crypto.Cipher import AES


_DEMO_KEY_PHRASE = "echocrypt-demo-shared-secret"
_NONCE_LEN = 16
_TAG_LEN = 16


def _derive_key() -> bytes:
    """Derive a 32-byte AES key from the fixed demo phrase via SHA-256."""
    return sha256(_DEMO_KEY_PHRASE.encode("utf-8")).digest()


def encrypt_message(message: str) -> bytes:
    """Encrypt ``message`` with AES-EAX and return ``nonce + tag + ciphertext``.

    Raises:
        TypeError: if ``message`` is not a string.
    """
    if not isinstance(message, str):
        raise TypeError("message must be a str")

    key = _derive_key()
    cipher = AES.new(key, AES.MODE_EAX, nonce=None)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))

    if len(nonce) != _NONCE_LEN or len(tag) != _TAG_LEN:
        # PyCryptodome defaults match these sizes; guard in case of upstream changes.
        raise RuntimeError("unexpected nonce/tag size from AES-EAX")

    return nonce + tag + ciphertext


def decrypt_message(cipher_bytes: bytes) -> str:
    """Decrypt a payload previously produced by :func:`encrypt_message`.

    Raises:
        ValueError: if the payload is too short, malformed, or fails MAC verification.
    """
    if not isinstance(cipher_bytes, (bytes, bytearray)):
        raise TypeError("cipher_bytes must be bytes-like")

    if len(cipher_bytes) < _NONCE_LEN + _TAG_LEN:
        raise ValueError("ciphertext payload is truncated or invalid")

    nonce = bytes(cipher_bytes[:_NONCE_LEN])
    tag = bytes(cipher_bytes[_NONCE_LEN:_NONCE_LEN + _TAG_LEN])
    ciphertext = bytes(cipher_bytes[_NONCE_LEN + _TAG_LEN:])

    key = _derive_key()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except (ValueError, KeyError) as exc:
        raise ValueError("AES decryption/authentication failed") from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("decrypted payload is not valid UTF-8 text") from exc
