"""Flask app wiring together recording, AES encryption, and LSB stego.

Run with::

    pip install -r requirements.txt
    python app.py

Then open http://localhost:5000 in a browser.
"""

from __future__ import annotations

import os
from pathlib import Path

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from werkzeug.utils import secure_filename

import audio_utils
import crypto as crypto_mod
import stego


BASE_DIR = Path(__file__).resolve().parent


def _resolve_upload_dir() -> Path:
    """Pick a writable storage path for generated audio files.

    - Local development: use project ./uploads
    - Vercel serverless: use /tmp (runtime-writable)
    """
    if os.environ.get("VERCEL"):
        return Path("/tmp/echocrypt_uploads")
    return BASE_DIR / "uploads"


UPLOADS_DIR = _resolve_upload_dir()
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

SENDER_WAV = "sender.wav"
ENCODED_WAV = "encoded.wav"
ALLOWED_UPLOAD_EXTS = {".wav"}
FINGERPRINT_PASSWORD = "1234"  # simulated fingerprint per spec
MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB safety cap

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.secret_key = "echocrypt-demo-secret-key"  # only used for flash messages


def _uploads_path(name: str) -> Path:
    return UPLOADS_DIR / name


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/sender", methods=["GET"])
def sender_page():
    sender_exists = _uploads_path(SENDER_WAV).exists()
    encoded_exists = _uploads_path(ENCODED_WAV).exists()
    return render_template(
        "sender.html",
        sender_exists=sender_exists,
        encoded_exists=encoded_exists,
        sender_url=url_for("download", filename=SENDER_WAV) if sender_exists else None,
        encoded_url=url_for("download", filename=ENCODED_WAV) if encoded_exists else None,
    )


@app.route("/receiver", methods=["GET"])
def receiver_page():
    return render_template("receiver.html")


@app.route("/record", methods=["POST"])
def record_route():
    """Record a fresh sender.wav from the server's default input device."""
    try:
        duration = int(request.form.get("duration", "3"))
    except ValueError:
        duration = 3
    duration = max(1, min(duration, 10))

    target = _uploads_path(SENDER_WAV)
    try:
        device_raw = (request.form.get("device_id") or "").strip()
        device_id = int(device_raw) if device_raw else None
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid server microphone selection."}), 400

    try:
        audio_utils.record_audio(
            filename=str(target),
            duration=duration,
            fs=audio_utils.DEFAULT_SAMPLE_RATE,
            device=device_id,
        )
    except RuntimeError as exc:
        return (
            jsonify({"ok": False, "error": str(exc)}),
            500,
        )

    return jsonify(
        {
            "ok": True,
            "message": f"Recorded {duration}s of audio.",
            "audio_url": url_for("download", filename=SENDER_WAV),
        }
    )


@app.route("/audio_devices", methods=["GET"])
def audio_devices_route():
    """Expose server-side input devices for local microphone selection."""
    return jsonify({"ok": True, "devices": audio_utils.list_input_devices()})


@app.route("/test_mic", methods=["POST"])
def test_mic_route():
    """Test selected microphone input and report signal presence."""
    mode = (request.form.get("mode") or "").strip().lower()

    if mode == "server":
        try:
            device_raw = (request.form.get("device_id") or "").strip()
            device_id = int(device_raw) if device_raw else None
        except ValueError:
            return jsonify({"ok": False, "error": "Invalid server microphone selection."}), 400

        try:
            result = audio_utils.test_input_device(
                duration=1.5,
                fs=audio_utils.DEFAULT_SAMPLE_RATE,
                device=device_id,
            )
        except RuntimeError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

        if not result["ok"]:
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": (
                            "Selected server mic has very low/no signal. "
                            f"(peak={result['peak']:.4f}, rms={result['rms']:.4f})"
                        ),
                    }
                ),
                400,
            )

        return jsonify(
            {
                "ok": True,
                "message": (
                    "Server microphone test passed "
                    f"(peak={result['peak']:.4f}, rms={result['rms']:.4f})."
                ),
            }
        )

    return jsonify({"ok": False, "error": "Unsupported test mode."}), 400


@app.route("/upload_sender_audio", methods=["POST"])
def upload_sender_audio_route():
    """Accept browser-recorded WAV and store it as sender.wav.

    This route is intended for serverless hosting (e.g. Vercel) where
    server-side microphone capture via sounddevice is unavailable.
    """
    upload = request.files.get("audio")
    if upload is None or upload.filename == "":
        return jsonify({"ok": False, "error": "No audio file uploaded."}), 400

    safe_name = secure_filename(upload.filename) or "recorded.wav"
    ext = os.path.splitext(safe_name)[1].lower()
    if ext and ext not in ALLOWED_UPLOAD_EXTS:
        return jsonify({"ok": False, "error": "Please upload a .wav file."}), 400

    target = _uploads_path(SENDER_WAV)
    try:
        upload.save(target)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"Could not save audio: {exc}"}), 500

    # Validate that the saved file is a readable WAV for the stego pipeline.
    try:
        audio_utils.load_audio(str(target))
    except ValueError as exc:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        return jsonify({"ok": False, "error": f"Invalid WAV data: {exc}"}), 400

    return jsonify(
        {
            "ok": True,
            "message": "Browser recording uploaded as sender.wav.",
            "audio_url": url_for("download", filename=SENDER_WAV),
        }
    )


@app.route("/encrypt_embed", methods=["POST"])
def encrypt_embed_route():
    """Encrypt the secret and embed it inside sender.wav, producing encoded.wav."""
    secret_text = (request.form.get("message") or "").strip()
    if not secret_text:
        flash("Please type a secret message before embedding.", "error")
        return redirect(url_for("sender_page"))

    sender_path = _uploads_path(SENDER_WAV)
    if not sender_path.exists():
        flash("Record a voice clip first - sender.wav is missing.", "error")
        return redirect(url_for("sender_page"))

    try:
        cipher_bytes = crypto_mod.encrypt_message(secret_text)
    except Exception as exc:  # noqa: BLE001
        flash(f"Encryption failed: {exc}", "error")
        return redirect(url_for("sender_page"))

    try:
        sample_rate, samples = audio_utils.load_audio(str(sender_path))
    except ValueError as exc:
        flash(f"Could not read recorded audio: {exc}", "error")
        return redirect(url_for("sender_page"))

    try:
        encoded_samples = stego.embed_data(samples, cipher_bytes)
    except ValueError as exc:
        flash(
            f"Audio is too short to hide that message: {exc}. "
            f"Try a longer recording or a shorter secret.",
            "error",
        )
        return redirect(url_for("sender_page"))
    except Exception as exc:  # noqa: BLE001
        flash(f"Embedding failed: {exc}", "error")
        return redirect(url_for("sender_page"))

    encoded_path = _uploads_path(ENCODED_WAV)
    try:
        audio_utils.save_audio(str(encoded_path), encoded_samples, sample_rate)
    except Exception as exc:  # noqa: BLE001
        flash(f"Could not save encoded audio: {exc}", "error")
        return redirect(url_for("sender_page"))

    flash("Message embedded successfully into encoded.wav.", "success")
    return redirect(url_for("sender_page"))


@app.route("/upload_decrypt", methods=["POST"])
def upload_decrypt_route():
    """Authenticate, extract LSB payload, decrypt, and display the message."""
    password = (request.form.get("password") or "").strip()
    if password != FINGERPRINT_PASSWORD:
        return render_template(
            "receiver.html",
            error="Access Denied: fingerprint did not match.",
            access_denied=True,
        )

    upload = request.files.get("audio")
    if upload is None or upload.filename == "":
        return render_template(
            "receiver.html",
            error="Please choose a WAV file to decrypt.",
        )

    safe_name = secure_filename(upload.filename) or "upload.wav"
    ext = os.path.splitext(safe_name)[1].lower()
    if ext not in ALLOWED_UPLOAD_EXTS:
        return render_template(
            "receiver.html",
            error="Only .wav files are supported.",
        )

    saved_path = _uploads_path(f"received_{safe_name}")
    try:
        upload.save(saved_path)
    except Exception as exc:  # noqa: BLE001
        return render_template(
            "receiver.html",
            error=f"Could not save uploaded file: {exc}",
        )

    try:
        _sample_rate, samples = audio_utils.load_audio(str(saved_path))
    except ValueError as exc:
        return render_template(
            "receiver.html",
            error=f"Could not read audio: {exc}",
        )

    try:
        cipher_bytes = stego.extract_data(samples)
    except ValueError as exc:
        return render_template(
            "receiver.html",
            error=f"Extraction failed: {exc}",
        )

    try:
        message = crypto_mod.decrypt_message(cipher_bytes)
    except ValueError as exc:
        return render_template(
            "receiver.html",
            error=f"Decryption failed: {exc}",
        )

    return render_template(
        "receiver.html",
        message=message,
        success=True,
    )


@app.route("/download/<path:filename>")
def download(filename: str):
    """Serve generated/recorded audio out of the uploads directory."""
    safe = secure_filename(filename)
    if not safe:
        return "Invalid filename", 400
    file_path = _uploads_path(safe)
    if not file_path.exists():
        return "Not found", 404
    return send_from_directory(UPLOADS_DIR, safe, as_attachment=False)


@app.errorhandler(413)
def too_large(_err):
    flash("Uploaded file is too large (limit 25 MB).", "error")
    return redirect(url_for("receiver_page"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
