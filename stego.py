"""LSB audio steganography over PCM samples.

Layout written into the LSBs of consecutive samples::

    [ 32-bit big-endian payload length in bytes ][ payload bytes ]

Each byte expands to 8 LSB-modified samples (MSB-first). The first 32 samples
encode the length header so the extractor knows how many subsequent samples
to read.

The functions accept and return 1-D NumPy integer arrays. Callers are
responsible for converting stereo audio to mono before embedding.
"""

from __future__ import annotations

import numpy as np


_LENGTH_HEADER_BITS = 32  # uint32 big-endian length prefix


def _bytes_to_bits(data: bytes) -> np.ndarray:
    """Expand ``data`` into a flat numpy array of 0/1 bits, MSB-first per byte."""
    if len(data) == 0:
        return np.zeros(0, dtype=np.uint8)
    arr = np.frombuffer(data, dtype=np.uint8)
    bits = np.unpackbits(arr, bitorder="big")
    return bits.astype(np.uint8)


def _bits_to_bytes(bits: np.ndarray) -> bytes:
    """Pack a flat 0/1 bit array back into bytes (MSB-first per byte)."""
    if bits.size == 0:
        return b""
    if bits.size % 8 != 0:
        raise ValueError("bit array length must be a multiple of 8")
    packed = np.packbits(bits.astype(np.uint8), bitorder="big")
    return packed.tobytes()


def _set_lsb(samples: np.ndarray, bits: np.ndarray) -> np.ndarray:
    """Return a copy of ``samples`` with the LSB of the first ``len(bits)`` set."""
    if bits.size > samples.size:
        raise ValueError("bit stream longer than available samples")
    out = samples.copy()
    # Operate in int64 to avoid sign/overflow issues with int16 PCM samples.
    region = out[: bits.size].astype(np.int64)
    region = (region & ~np.int64(1)) | bits.astype(np.int64)
    out[: bits.size] = region.astype(samples.dtype)
    return out


def _get_lsb(samples: np.ndarray, count: int) -> np.ndarray:
    """Return the LSB of the first ``count`` samples as a 0/1 uint8 array."""
    if count > samples.size:
        raise ValueError("requested more LSBs than available samples")
    region = samples[:count].astype(np.int64)
    return (region & np.int64(1)).astype(np.uint8)


def embed_data(audio_samples: np.ndarray, secret_bytes: bytes) -> np.ndarray:
    """Embed ``secret_bytes`` into the LSBs of ``audio_samples``.

    Args:
        audio_samples: 1-D integer numpy array of PCM samples (mono).
        secret_bytes: payload to hide (e.g. AES nonce+tag+ciphertext).

    Returns:
        A new numpy array, same dtype/shape as ``audio_samples``, with the
        payload encoded in the LSBs of leading samples.

    Raises:
        TypeError: on bad input types.
        ValueError: if the payload is too large to fit.
    """
    if not isinstance(audio_samples, np.ndarray):
        raise TypeError("audio_samples must be a numpy.ndarray")
    if audio_samples.ndim != 1:
        raise ValueError("audio_samples must be 1-D (mono)")
    if not np.issubdtype(audio_samples.dtype, np.integer):
        raise TypeError("audio_samples must be an integer dtype (PCM)")
    if not isinstance(secret_bytes, (bytes, bytearray)):
        raise TypeError("secret_bytes must be bytes-like")

    payload = bytes(secret_bytes)
    payload_len = len(payload)

    total_bits = _LENGTH_HEADER_BITS + payload_len * 8
    if total_bits > audio_samples.size:
        raise ValueError(
            f"audio capacity exceeded: need {total_bits} samples, "
            f"have {audio_samples.size}"
        )

    length_header = np.array([payload_len], dtype=">u4").tobytes()  # 4 bytes BE
    header_bits = _bytes_to_bits(length_header)
    payload_bits = _bytes_to_bits(payload)
    bit_stream = np.concatenate([header_bits, payload_bits])

    return _set_lsb(audio_samples, bit_stream)


def extract_data(audio_samples: np.ndarray) -> bytes:
    """Recover bytes previously hidden by :func:`embed_data`.

    Raises:
        TypeError/ValueError: on bad inputs or implausible/corrupt headers.
    """
    if not isinstance(audio_samples, np.ndarray):
        raise TypeError("audio_samples must be a numpy.ndarray")
    if audio_samples.ndim != 1:
        raise ValueError("audio_samples must be 1-D (mono)")
    if not np.issubdtype(audio_samples.dtype, np.integer):
        raise TypeError("audio_samples must be an integer dtype (PCM)")

    if audio_samples.size < _LENGTH_HEADER_BITS:
        raise ValueError("audio is too short to contain a length header")

    header_bits = _get_lsb(audio_samples, _LENGTH_HEADER_BITS)
    header_bytes = _bits_to_bytes(header_bits)
    payload_len = int(np.frombuffer(header_bytes, dtype=">u4")[0])

    max_payload_bytes = (audio_samples.size - _LENGTH_HEADER_BITS) // 8
    if payload_len < 0 or payload_len > max_payload_bytes:
        raise ValueError(
            "embedded length header is invalid or audio is corrupted"
        )

    payload_bit_count = payload_len * 8
    region = audio_samples[
        _LENGTH_HEADER_BITS : _LENGTH_HEADER_BITS + payload_bit_count
    ]
    payload_bits = (region.astype(np.int64) & np.int64(1)).astype(np.uint8)
    return _bits_to_bytes(payload_bits)
