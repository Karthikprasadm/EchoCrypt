"""Audio recording / loading / saving helpers.

Recording uses ``sounddevice`` against the host machine's default input device;
WAV I/O uses ``scipy.io.wavfile``. Stereo input is downmixed to mono (mean of
channels) so that downstream LSB stego always operates on a 1-D sample array.
"""

from __future__ import annotations

from typing import Tuple

import numpy as np
from scipy.io import wavfile


DEFAULT_SAMPLE_RATE = 44100
DEFAULT_DURATION_SECONDS = 3


def record_audio(
    filename: str = "sender.wav",
    duration: int = DEFAULT_DURATION_SECONDS,
    fs: int = DEFAULT_SAMPLE_RATE,
) -> str:
    """Record ``duration`` seconds of mono int16 audio to ``filename``.

    Imports ``sounddevice`` lazily so the rest of the app can run on machines
    without the PortAudio runtime installed (e.g. headless servers).

    Returns the resolved filename written.
    """
    try:
        import sounddevice as sd
    except (ImportError, OSError) as exc:
        raise RuntimeError(
            "sounddevice is unavailable on this machine; "
            "install PortAudio or upload a WAV file instead"
        ) from exc

    if duration <= 0:
        raise ValueError("duration must be positive")

    try:
        recording = sd.rec(
            int(duration * fs),
            samplerate=fs,
            channels=1,
            dtype="int16",
        )
        sd.wait()
    except Exception as exc:  # noqa: BLE001 - surface device errors uniformly
        raise RuntimeError(f"audio recording failed: {exc}") from exc

    samples = np.asarray(recording, dtype=np.int16).reshape(-1)
    save_audio(filename, samples, fs)
    return filename


def load_audio(filename: str) -> Tuple[int, np.ndarray]:
    """Load a WAV file and return ``(sample_rate, mono_int_samples)``.

    Stereo audio is downmixed to mono. Floating-point WAVs are converted to
    int16 (scaled from the [-1.0, 1.0] range) so that LSB stego can operate on
    integer samples.
    """
    try:
        sample_rate, data = wavfile.read(filename)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"could not read WAV file '{filename}': {exc}") from exc

    if data.ndim > 1:
        # Downmix to mono by averaging channels in a wider dtype to avoid overflow.
        data = data.astype(np.int64).mean(axis=1)

    if np.issubdtype(data.dtype, np.floating):
        clipped = np.clip(data, -1.0, 1.0)
        data = (clipped * np.iinfo(np.int16).max).astype(np.int16)
    elif data.dtype == np.uint8:
        # 8-bit PCM is unsigned with bias 128; recenter to int16-equivalent range.
        data = (data.astype(np.int16) - 128) * 256
    else:
        data = data.astype(np.int16, copy=False)

    return int(sample_rate), np.ascontiguousarray(data)


def save_audio(filename: str, data: np.ndarray, fs: int) -> str:
    """Write ``data`` to ``filename`` as a WAV file at sample rate ``fs``."""
    if not isinstance(data, np.ndarray):
        raise TypeError("data must be a numpy.ndarray")
    if fs <= 0:
        raise ValueError("sample rate must be positive")

    if not np.issubdtype(data.dtype, np.integer) and not np.issubdtype(
        data.dtype, np.floating
    ):
        raise TypeError("data dtype must be integer or floating PCM")

    wavfile.write(filename, fs, data)
    return filename
