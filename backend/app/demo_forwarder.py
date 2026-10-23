"""Send one synthetic, end-to-end encrypted event through the local API."""

import base64
import getpass
import json
import os
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.crypto import CRYPTO_ALGORITHM, canonical_associated_data

API_ROOT = os.environ.get("SECURELOGPATH_API_ROOT", "http://127.0.0.1:8000/api/v1")


def request_json(url: str, *, method: str = "GET", token: str | None = None,
                 body: bytes | None = None, headers: dict[str, str] | None = None) -> dict:
    request_headers = {"Accept": "application/json", **(headers or {})}
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    request = Request(url, data=body, headers=request_headers, method=method)
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def login_and_get_public_key() -> tuple[str, dict]:
    username = input("Forwarder username: ").strip()
    password = getpass.getpass("Forwarder password: ")
    login = request_json(
        f"{API_ROOT}/auth/login",
        method="POST",
        body=json.dumps({"username": username, "password": password}).encode("utf-8"),
    )
    token = login["access_token"]
    key = request_json(f"{API_ROOT}/crypto/public-key", token=token)
    return token, key


def encrypted_demo_line(public_key_document: dict) -> bytes:
    log_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    envelope = {
        "schema_version": 1,
        "log_id": log_id,
        "timestamp": timestamp,
        "source_asset_id": "demo-forwarder-01",
        "destination_asset_id": "demo-web-01",
    }
    plaintext = json.dumps(
        {
            "event_type": "demo_http_request",
            "source_ip": "192.0.2.44",
            "destination_ip": "198.51.100.20",
            "payload": "UNION SELECT username, password FROM demo_users",
        },
        separators=(",", ":"),
    ).encode("utf-8")
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, canonical_associated_data(envelope))
    public_key = serialization.load_pem_public_key(
        public_key_document["public_key_pem"].encode("ascii")
    )
    wrapped_key = public_key.encrypt(
        data_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    envelope["crypto"] = {
        "algorithm": CRYPTO_ALGORITHM,
        "key_id": public_key_document["key_id"],
        "wrapped_data_key": base64.b64encode(wrapped_key).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return (json.dumps(envelope, separators=(",", ":")) + "\n").encode("utf-8")


def upload_jsonl(token: str, content: bytes) -> dict:
    boundary = f"----securelogpath-{uuid4().hex}"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="demo.jsonl"\r\n'
        "Content-Type: application/x-ndjson\r\n\r\n"
    ).encode("ascii") + content + f"\r\n--{boundary}--\r\n".encode("ascii")
    request = Request(
        f"{API_ROOT}/ingestion/uploads",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Idempotency-Key": str(uuid4()),
        },
        method="POST",
    )
    with urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> None:
    try:
        token, public_key = login_and_get_public_key()
        result = upload_jsonl(token, encrypted_demo_line(public_key))
        job_id = result["job_id"]
        print(f"Upload accepted. Job ID: {job_id}")
        for _ in range(60):
            job = request_json(f"{API_ROOT}/ingestion/jobs/{job_id}", token=token)
            if job["status"] in {"completed", "completed_with_errors", "failed", "interrupted"}:
                print(
                    "Job status: {status}; accepted: {accepted_lines}; rejected: {rejected_lines}".format(
                        **job
                    )
                )
                if job["line_errors"]:
                    print("Safe line error codes:", ", ".join(e["error_code"] for e in job["line_errors"]))
                return
            time.sleep(0.5)
        print(f"Job is still processing. Check job ID {job_id} in the API docs.")
    except HTTPError as error:
        # Do not print credentials, bearer tokens, or request bodies.
        print(f"API request failed with HTTP {error.code}; verify the Forwarder account and API readiness.")
    except (URLError, KeyError, ValueError, OSError):
        print("Could not complete the demo upload; verify API readiness and Forwarder credentials.")


if __name__ == "__main__":
    main()
