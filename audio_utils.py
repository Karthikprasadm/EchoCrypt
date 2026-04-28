"""Audio recording / loading / saving helpers.

Recording uses ``sounddevice`` against the host machine's default input device;
WAV I/O uses ``scipy.io.wavfile``. Stereo input is downmixed to mono (mean of
channels) so that downstream LSB stego always operates on a 1-D sample array.
"""

from __future__ import annotations

import re
from typing import Tuple

import numpy as np
from scipy.io import wavfile


DEFAULT_SAMPLE_RATE = 44100
DEFAULT_DURATION_SECONDS = 3


def _is_likely_virtual_or_alias(name: str) -> bool:
    lowered = name.lower()
    blocked_tokens = (
        "mapper",
        "default",
        "primary sound capture driver",
        "steam streaming",
        "virtual",
        "cable input",
    )
    return any(token in lowered for token in blocked_tokens)


def _is_likely_output_or_loopback(name: str) -> bool:
    lowered = name.lower()
    blocked_tokens = (
        "speaker",
        "output",
        "stereo mix",
        "loopback",
        "hdmi",
        "line out",
    )
    return any(token in lowered for token in blocked_tokens)


def _normalize_device_name(name: str) -> str:
    # Collapse repeated spaces and strip trailing numeric alias fragments.
    cleaned = " ".join(name.split()).strip()
    parts = cleaned.split()
    while parts and parts[-1].isdigit():
        parts.pop()
    return " ".join(parts).strip() or cleaned


def _is_alias_artifact(name: str) -> bool:
    lowered = name.lower().strip()
    # Common PortAudio alias suffixes like "Microphone Array 1 0".
    if re.search(r"\b\d+\s+\d+\b$", lowered):
        return True
    return False


def _is_likely_real_mic(name: str) -> bool:
    lowered = name.lower()
    positive_tokens = ("microphone", "mic", "array", "input")
    return any(token in lowered for token in positive_tokens)


def _analyze_signal(samples: np.ndarray) -> tuple[float, float]:
    """Return (peak, rms) on float-normalized samples."""
    if samples.size == 0:
        return 0.0, 0.0
    abs_samples = np.abs(samples)
    peak = float(np.max(abs_samples))
    rms = float(np.sqrt(np.mean(samples * samples)))
    return peak, rms


def _normalize_int16(samples: np.ndarray) -> np.ndarray:
    """Normalize quiet int16 recordings; raise on near-silent input."""
    float_samples = samples.astype(np.float32) / np.iinfo(np.int16).max
    peak, rms = _analyze_signal(float_samples)

    # If almost no microphone signal arrived, fail fast with a clear message.
    if peak < 0.0025 or rms < 0.0008:
        raise RuntimeError(
            "No microphone signal detected. Check system input device, "
            "microphone permission, and mute settings."
        )

    target_peak = 0.9
    max_gain = 8.0
    gain = min(max_gain, target_peak / max(peak, 1e-8))
    if gain <= 1.02:
        return samples

    boosted = np.clip(float_samples * gain, -1.0, 1.0)
    return (boosted * np.iinfo(np.int16).max).astype(np.int16)


def record_audio(
    filename: str = "sender.wav",
    duration: int = DEFAULT_DURATION_SECONDS,
    fs: int = DEFAULT_SAMPLE_RATE,
    device: int | None = None,
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
            device=device,
        )
        sd.wait()
    except Exception as exc:  # noqa: BLE001 - surface device errors uniformly
        raise RuntimeError(f"audio recording failed: {exc}") from exc

    samples = np.asarray(recording, dtype=np.int16).reshape(-1)
    samples = _normalize_int16(samples)
    save_audio(filename, samples, fs)
    return filename


def list_input_devices() -> list[dict[str, str | int]]:
    """Return available input-capable PortAudio devices for selection in UI."""
    try:
        import sounddevice as sd
    except (ImportError, OSError):
        return []

    devices: list[dict[str, str | int]] = []
    fallback_devices: list[dict[str, str | int]] = []
    seen_normalized: set[str] = set()
    for idx, dev in enumerate(sd.query_devices()):
        if int(dev.get("max_input_channels", 0)) > 0:
            name = str(dev.get("name", f"Input device {idx}"))
            norm = _normalize_device_name(name).lower()
            item = {"id": idx, "name": _normalize_device_name(name)}
            fallback_devices.append(item)
            if _is_likely_output_or_loopback(name):
                continue
            if _is_likely_virtual_or_alias(name):
                continue
            if _is_alias_artifact(name):
                continue
            if not _is_likely_real_mic(name):
                continue
            if norm in seen_normalized:
                continue
            seen_normalized.add(norm)
            if not _is_likely_virtual_or_alias(name):
                devices.append(item)
    # If filtering removed everything, fall back to full list.
    if devices:
        return devices

    # Fallback: still deduplicate obvious duplicates for display quality.
    unique_fallback: list[dict[str, str | int]] = []
    seen_fallback: set[str] = set()
    for item in fallback_devices:
        norm = _normalize_device_name(str(item["name"])).lower()
        if norm in seen_fallback:
            continue
        seen_fallback.add(norm)
        unique_fallback.append({"id": item["id"], "name": _normalize_device_name(str(item["name"]))})
    return unique_fallback


def test_input_device(
    duration: float = 1.5,
    fs: int = DEFAULT_SAMPLE_RATE,
    device: int | None = None,
) -> dict[str, float | bool]:
    """Record a short sample and report whether signal is present."""
    try:
        import sounddevice as sd
    except (ImportError, OSError) as exc:
        raise RuntimeError(
            "sounddevice is unavailable on this machine; cannot test server microphone."
        ) from exc

    if duration <= 0:
        raise ValueError("duration must be positive")

    try:
        recording = sd.rec(
            int(duration * fs),
            samplerate=fs,
            channels=1,
            dtype="int16",
            device=device,
        )
        sd.wait()
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"microphone test failed: {exc}") from exc

    samples = np.asarray(recording, dtype=np.int16).reshape(-1)
    float_samples = samples.astype(np.float32) / np.iinfo(np.int16).max
    peak, rms = _analyze_signal(float_samples)
    return {
        "ok": bool(peak >= 0.0025 and rms >= 0.0008),
        "peak": peak,
        "rms": rms,
    }


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
