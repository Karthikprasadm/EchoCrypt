"""Flask app wiring together recording, AES encryption, and LSB stego.

Run with::

    pip install -r requirements.txt
    python app.py

Then open http://localhost:5000 in a browser.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from flask import (
    Flask,
    flash,
    has_request_context,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    send_from_directory,
    url_for,
)
from werkzeug.utils import secure_filename

import audio_utils
import crypto as crypto_mod
import stego
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    AuthenticatorTransport,
    AuthenticationCredential,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


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
WEBAUTHN_CREDENTIAL_STORE = BASE_DIR / "webauthn_credentials.json"
WEBAUTHN_CREDENTIAL_LOCK = BASE_DIR / "webauthn_credentials.lock"
WEBAUTHN_RP_NAME = "EchoCrypt Receiver"
WEBAUTHN_RP_ID = os.environ.get("WEBAUTHN_RP_ID")
WEBAUTHN_RP_ORIGIN = os.environ.get("WEBAUTHN_RP_ORIGIN")
WEBAUTHN_USER_ID = b"echocrypt-demo-user"
WEBAUTHN_USER_NAME = "receiver"
WEBAUTHN_USER_DISPLAY_NAME = "EchoCrypt Receiver User"
WEBAUTHN_SESSION_TTL_SECONDS = 5 * 60
_WEBAUTHN_THREAD_LOCK = threading.RLock()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.secret_key = "echocrypt-demo-secret-key"  # only used for flash messages

# WebAuthn state files must be writable on serverless platforms.
WEBAUTHN_CREDENTIAL_STORE = UPLOADS_DIR / "webauthn_credentials.json"
WEBAUTHN_CREDENTIAL_LOCK = UPLOADS_DIR / "webauthn_credentials.lock"


def _uploads_path(name: str) -> Path:
    return UPLOADS_DIR / name


def _effective_webauthn_rp() -> tuple[str, str]:
    """Resolve RP ID/origin from env or current request host."""
    if WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGIN:
        return WEBAUTHN_RP_ID, WEBAUTHN_RP_ORIGIN
    if has_request_context():
        host = request.host.split(":", 1)[0]
        if host in {"127.0.0.1", "::1"}:
            host = "localhost"
        return host, request.host_url.rstrip("/")
    return "localhost", "http://localhost:5000"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padded = data + "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _required_b64url_field(data: dict, field_name: str) -> bytes:
    """Decode a required base64url field, rejecting null/missing values."""
    value = data.get(field_name)
    if value is None:
        raise ValueError(f"Missing required field: {field_name}")
    if not isinstance(value, str):
        raise ValueError(f"Invalid field type for {field_name}; expected string")
    if not value:
        raise ValueError(f"Empty required field: {field_name}")
    return _b64url_decode(value)


def _parse_transport_values(values: list[str] | None) -> list[AuthenticatorTransport] | None:
    if not values:
        return None
    parsed: list[AuthenticatorTransport] = []
    for item in values:
        try:
            parsed.append(AuthenticatorTransport(item))
        except Exception:
            continue
    return parsed or None


def _registration_credential_from_payload(payload: dict) -> RegistrationCredential:
    response = payload.get("response") or {}
    return RegistrationCredential(
        id=str(payload.get("id", "")),
        raw_id=_required_b64url_field(payload, "rawId"),
        response=AuthenticatorAttestationResponse(
            client_data_json=_required_b64url_field(response, "clientDataJSON"),
            attestation_object=_required_b64url_field(response, "attestationObject"),
            transports=_parse_transport_values(response.get("transports")),
        ),
    )


def _authentication_credential_from_payload(payload: dict) -> AuthenticationCredential:
    response = payload.get("response") or {}
    user_handle_raw = response.get("userHandle")
    user_handle = _b64url_decode(str(user_handle_raw)) if user_handle_raw else None
    return AuthenticationCredential(
        id=str(payload.get("id", "")),
        raw_id=_required_b64url_field(payload, "rawId"),
        response=AuthenticatorAssertionResponse(
            client_data_json=_required_b64url_field(response, "clientDataJSON"),
            authenticator_data=_required_b64url_field(response, "authenticatorData"),
            signature=_required_b64url_field(response, "signature"),
            user_handle=user_handle,
        ),
    )


@contextmanager
def _webauthn_store_lock():
    """Cross-process lock for WebAuthn credential store updates."""
    # In-process lock avoids Windows msvcrt thread deadlock behavior.
    with _WEBAUTHN_THREAD_LOCK:
        WEBAUTHN_CREDENTIAL_LOCK.parent.mkdir(parents=True, exist_ok=True)
        with open(WEBAUTHN_CREDENTIAL_LOCK, "a+b") as lock_file:
            if os.name == "nt":
                import msvcrt  # pylint: disable=import-outside-toplevel

                lock_file.seek(0)
                lock_file.write(b"0")
                lock_file.flush()
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl  # pylint: disable=import-outside-toplevel

                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _load_webauthn_store_unlocked() -> dict:
    if not WEBAUTHN_CREDENTIAL_STORE.exists():
        return {"credentials": []}
    try:
        raw = json.loads(WEBAUTHN_CREDENTIAL_STORE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"credentials": []}
    if not isinstance(raw, dict):
        return {"credentials": []}
    creds = raw.get("credentials")
    if not isinstance(creds, list):
        return {"credentials": []}
    return {"credentials": creds}


def _save_webauthn_store_unlocked(store: dict) -> None:
    WEBAUTHN_CREDENTIAL_STORE.write_text(
        json.dumps(store, indent=2),
        encoding="utf-8",
    )


def _load_webauthn_store() -> dict:
    with _webauthn_store_lock():
        return _load_webauthn_store_unlocked()


def _save_webauthn_store(store: dict) -> None:
    with _webauthn_store_lock():
        _save_webauthn_store_unlocked(store)


def _credential_descriptors() -> list[PublicKeyCredentialDescriptor]:
    store = _load_webauthn_store()
    descriptors: list[PublicKeyCredentialDescriptor] = []
    for cred in store["credentials"]:
        try:
            cred_id = _b64url_decode(cred["credential_id"])
        except (KeyError, TypeError, ValueError):
            continue
        descriptors.append(PublicKeyCredentialDescriptor(id=cred_id))
    return descriptors


def _find_credential_by_id(credential_id_bytes: bytes) -> dict | None:
    wanted = _b64url_encode(credential_id_bytes)
    store = _load_webauthn_store()
    for cred in store["credentials"]:
        if cred.get("credential_id") == wanted:
            return cred
    return None


def _upsert_credential(record: dict) -> None:
    store = _load_webauthn_store()
    updated = False
    for idx, cred in enumerate(store["credentials"]):
        if cred.get("credential_id") == record["credential_id"]:
            store["credentials"][idx] = record
            updated = True
            break
    if not updated:
        store["credentials"].append(record)
    _save_webauthn_store(store)


def _clear_webauthn_credentials() -> None:
    _save_webauthn_store({"credentials": []})


def _verify_and_update_sign_count_atomic(
    credential: AuthenticationCredential,
    expected_challenge: bytes,
) -> tuple[dict | None, str | None]:
    """Atomically verify assertion and persist updated sign_count."""
    rp_id, rp_origin = _effective_webauthn_rp()
    credential_id_b64 = _b64url_encode(credential.raw_id)
    with _webauthn_store_lock():
        store = _load_webauthn_store_unlocked()
        target_idx = None
        for idx, cred in enumerate(store["credentials"]):
            if cred.get("credential_id") == credential_id_b64:
                target_idx = idx
                break
        if target_idx is None:
            return None, "Credential not recognized."

        stored = store["credentials"][target_idx]
        try:
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_rp_id=rp_id,
                expected_origin=rp_origin,
                credential_public_key=_b64url_decode(stored["public_key"]),
                credential_current_sign_count=int(stored.get("sign_count", 0)),
                require_user_verification=True,
            )
        except Exception as exc:  # noqa: BLE001
            return None, f"Biometric verification failed: {exc}"

        stored["sign_count"] = int(verification.new_sign_count)
        store["credentials"][target_idx] = stored
        _save_webauthn_store_unlocked(store)
        return stored, None


def _set_webauthn_challenge(challenge: bytes, challenge_type: str) -> None:
    session["webauthn_challenge"] = _b64url_encode(challenge)
    session["webauthn_challenge_type"] = challenge_type
    session["webauthn_challenge_issued_at"] = int(time.time())


def _pop_expected_challenge(challenge_type: str) -> bytes | None:
    ch_type = session.get("webauthn_challenge_type")
    challenge_b64 = session.get("webauthn_challenge")
    issued_at = session.get("webauthn_challenge_issued_at")
    session.pop("webauthn_challenge", None)
    session.pop("webauthn_challenge_type", None)
    session.pop("webauthn_challenge_issued_at", None)
    if ch_type != challenge_type or not challenge_b64 or not issued_at:
        return None
    if int(time.time()) - int(issued_at) > WEBAUTHN_SESSION_TTL_SECONDS:
        return None
    try:
        return _b64url_decode(challenge_b64)
    except ValueError:
        return None


def _mark_biometric_verified() -> None:
    session["biometric_verified_at"] = int(time.time())


def _has_recent_biometric_verification() -> bool:
    verified_at = session.get("biometric_verified_at")
    if not verified_at:
        return False
    age = int(time.time()) - int(verified_at)
    return age <= WEBAUTHN_SESSION_TTL_SECONDS


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
    has_registered_credential = bool(_load_webauthn_store()["credentials"])
    rp_id, _rp_origin = _effective_webauthn_rp()
    return render_template(
        "receiver.html",
        has_registered_credential=has_registered_credential,
        biometric_recently_verified=_has_recent_biometric_verification(),
        rp_id=rp_id,
    )


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


@app.route("/webauthn/register/options", methods=["POST"])
def webauthn_register_options_route():
    """Issue WebAuthn registration options for platform authenticator."""
    rp_id, _rp_origin = _effective_webauthn_rp()
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=WEBAUTHN_RP_NAME,
        user_id=WEBAUTHN_USER_ID,
        user_name=WEBAUTHN_USER_NAME,
        user_display_name=WEBAUTHN_USER_DISPLAY_NAME,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=_credential_descriptors(),
    )
    _set_webauthn_challenge(options.challenge, "registration")
    return jsonify({"ok": True, "options": json.loads(options_to_json(options))})


@app.route("/webauthn/register/verify", methods=["POST"])
def webauthn_register_verify_route():
    """Verify WebAuthn attestation and persist credential public key."""
    expected_challenge = _pop_expected_challenge("registration")
    if not expected_challenge:
        return jsonify({"ok": False, "error": "Registration challenge missing/expired."}), 400

    payload = request.get_json(silent=True) or {}
    rp_id, rp_origin = _effective_webauthn_rp()
    try:
        credential = _registration_credential_from_payload(payload)
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=rp_origin,
            require_user_verification=True,
        )
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"Registration verification failed: {exc}"}), 400

    record = {
        "credential_id": _b64url_encode(verification.credential_id),
        "public_key": _b64url_encode(verification.credential_public_key),
        "sign_count": int(verification.sign_count),
    }
    _upsert_credential(record)
    return jsonify({"ok": True, "message": "Biometric credential registered successfully."})


@app.route("/webauthn/auth/options", methods=["POST"])
def webauthn_auth_options_route():
    """Issue WebAuthn authentication request options."""
    allow_credentials = _credential_descriptors()
    if not allow_credentials:
        return jsonify({"ok": False, "error": "No registered biometric credential found."}), 400

    rp_id, _rp_origin = _effective_webauthn_rp()
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    _set_webauthn_challenge(options.challenge, "authentication")
    return jsonify({"ok": True, "options": json.loads(options_to_json(options))})


@app.route("/webauthn/auth/verify", methods=["POST"])
def webauthn_auth_verify_route():
    """Verify WebAuthn assertion and mark current session as biometric-verified."""
    expected_challenge = _pop_expected_challenge("authentication")
    if not expected_challenge:
        return jsonify({"ok": False, "error": "Authentication challenge missing/expired."}), 400

    payload = request.get_json(silent=True) or {}
    try:
        credential = _authentication_credential_from_payload(payload)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"Invalid authentication payload: {exc}"}), 400

    _stored, err = _verify_and_update_sign_count_atomic(
        credential=credential,
        expected_challenge=expected_challenge,
    )
    if err:
        return jsonify({"ok": False, "error": err}), 400
    _mark_biometric_verified()
    return jsonify({"ok": True, "message": "Biometric verification successful."})


@app.route("/webauthn/clear", methods=["POST"])
def webauthn_clear_route():
    """Clear all registered WebAuthn credentials for demo reset/testing."""
    _clear_webauthn_credentials()
    session.pop("biometric_verified_at", None)
    return jsonify({"ok": True, "message": "Biometric credentials cleared."})


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
    rp_id, _rp_origin = _effective_webauthn_rp()
    password = (request.form.get("password") or "").strip()
    biometric_only = (request.form.get("biometric_only") or "").strip() in {"1", "true", "on"}
    password_ok = password == FINGERPRINT_PASSWORD
    biometric_ok = _has_recent_biometric_verification()
    if biometric_only:
        authorized = biometric_ok
    else:
        authorized = password_ok or biometric_ok

    if not authorized:
        return render_template(
            "receiver.html",
            error=(
                "Access Denied: biometric verification is required."
                if biometric_only
                else "Access Denied: use fingerprint password fallback or verify "
                "with biometric first."
            ),
            access_denied=True,
            has_registered_credential=bool(_load_webauthn_store()["credentials"]),
            biometric_recently_verified=biometric_ok,
            rp_id=rp_id,
            biometric_only=biometric_only,
        )

    upload = request.files.get("audio")
    if upload is None or upload.filename == "":
        return render_template(
            "receiver.html",
            error="Please choose a WAV file to decrypt.",
            has_registered_credential=bool(_load_webauthn_store()["credentials"]),
            biometric_recently_verified=biometric_ok,
            rp_id=rp_id,
            biometric_only=biometric_only,
        )

    safe_name = secure_filename(upload.filename) or "upload.wav"
    ext = os.path.splitext(safe_name)[1].lower()
    if ext not in ALLOWED_UPLOAD_EXTS:
        return render_template(
            "receiver.html",
            error="Only .wav files are supported.",
            has_registered_credential=bool(_load_webauthn_store()["credentials"]),
            biometric_recently_verified=biometric_ok,
            rp_id=rp_id,
            biometric_only=biometric_only,
        )

    saved_path = _uploads_path(f"received_{safe_name}")
    try:
        upload.save(saved_path)
    except Exception as exc:  # noqa: BLE001
        return render_template(
            "receiver.html",
            error=f"Could not save uploaded file: {exc}",
            has_registered_credential=bool(_load_webauthn_store()["credentials"]),
            biometric_recently_verified=biometric_ok,
            rp_id=rp_id,
            biometric_only=biometric_only,
        )

    try:
        _sample_rate, samples = audio_utils.load_audio(str(saved_path))
    except ValueError as exc:
        return render_template(
            "receiver.html",
            error=f"Could not read audio: {exc}",
            has_registered_credential=bool(_load_webauthn_store()["credentials"]),
            biometric_recently_verified=biometric_ok,
            rp_id=rp_id,
            biometric_only=biometric_only,
        )

    try:
        cipher_bytes = stego.extract_data(samples)
    except ValueError as exc:
        return render_template(
            "receiver.html",
            error=f"Extraction failed: {exc}",
            has_registered_credential=bool(_load_webauthn_store()["credentials"]),
            biometric_recently_verified=biometric_ok,
            rp_id=rp_id,
            biometric_only=biometric_only,
        )

    try:
        message = crypto_mod.decrypt_message(cipher_bytes)
    except ValueError as exc:
        return render_template(
            "receiver.html",
            error=f"Decryption failed: {exc}",
            has_registered_credential=bool(_load_webauthn_store()["credentials"]),
            biometric_recently_verified=biometric_ok,
            rp_id=rp_id,
            biometric_only=biometric_only,
        )

    return render_template(
        "receiver.html",
        message=message,
        success=True,
        has_registered_credential=bool(_load_webauthn_store()["credentials"]),
        biometric_recently_verified=biometric_ok,
        rp_id=rp_id,
        biometric_only=biometric_only,
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