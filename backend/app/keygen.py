"""Create a local-only RSA key for the Compose demonstration environment."""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main() -> None:
    target = Path(
        os.environ.get(
            "INGESTION_PRIVATE_KEY_PATH", "/run/secrets/ingestion_private_key.pem"
        )
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        print("Ingestion private key already exists; it was left unchanged.")
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    try:
        file_descriptor = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
    except FileExistsError:
        print("Ingestion private key already exists; it was left unchanged.")
        return
    try:
        with os.fdopen(file_descriptor, "wb") as private_file:
            private_file.write(private_pem)
            private_file.flush()
            os.fsync(private_file.fileno())
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass  # Windows applies access control through the host directory ACL.
        print("Created a local RSA-2048 ingestion key in the ignored secrets folder.")
    except OSError:
        try:
            target.unlink()
        except OSError:
            pass
        raise


if __name__ == "__main__":
    main()
