"""Stress test for atomic WebAuthn credential store updates.

This test does not require real WebAuthn credentials. It validates that the
file lock used by app._webauthn_store_lock prevents lost updates when many
threads concurrently read-modify-write the same sign_count value.
"""

from __future__ import annotations

import tempfile
import threading
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app as app_module


def main() -> int:
    workers = 20
    loops_per_worker = 200
    expected = workers * loops_per_worker

    with tempfile.TemporaryDirectory() as tmp:
        store_path = Path(tmp) / "webauthn_credentials.json"
        lock_path = Path(tmp) / "webauthn_credentials.lock"

        # Redirect module globals to isolated temporary files.
        app_module.WEBAUTHN_CREDENTIAL_STORE = store_path
        app_module.WEBAUTHN_CREDENTIAL_LOCK = lock_path

        app_module._save_webauthn_store(
            {
                "credentials": [
                    {
                        "credential_id": "test-credential",
                        "public_key": "test-public-key",
                        "sign_count": 0,
                    }
                ]
            }
        )

        def worker() -> None:
            for _ in range(loops_per_worker):
                with app_module._webauthn_store_lock():
                    store = app_module._load_webauthn_store_unlocked()
                    cred = store["credentials"][0]
                    cred["sign_count"] = int(cred.get("sign_count", 0)) + 1
                    store["credentials"][0] = cred
                    app_module._save_webauthn_store_unlocked(store)

        threads = [threading.Thread(target=worker) for _ in range(workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        final_store = app_module._load_webauthn_store()
        final_count = int(final_store["credentials"][0]["sign_count"])
        print(f"final sign_count={final_count}, expected={expected}")
        if final_count != expected:
            print("FAIL: lost update detected")
            return 1

        print("PASS: lock prevented lost updates under concurrency")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
