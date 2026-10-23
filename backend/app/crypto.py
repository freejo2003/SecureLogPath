"""Reviewed RSA-OAEP/AES-GCM primitives for the ingestion data path."""

import base64
import binascii
from functools import lru_cache
import json
import os
from pathlib import Path
import re
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.ingestion_schemas import EncryptedLogEnvelope, SensitiveBundle

CRYPTO_ALGORITHM = "RSA-OAEP-256+A256GCM"
DEFAULT_KEY_ID = "siem-key-2026-01"
DEFAULT_PRIVATE_KEY_PATH = "/run/secrets/ingestion_private_key.pem"


class IngestionCryptoError(Exception):
    """An expected, safe-to-report ingestion cryptography failure."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def active_key_id() -> str:
    key_id = os.environ.get("INGESTION_KEY_ID", DEFAULT_KEY_ID)
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", key_id):
        raise IngestionCryptoError("key_configuration_invalid")
    return key_id


def _private_key_path() -> Path:
    return Path(os.environ.get("INGESTION_PRIVATE_KEY_PATH", DEFAULT_PRIVATE_KEY_PATH))


@lru_cache(maxsize=4)
def _load_private_key(path: str, modified_ns: int, size: int) -> rsa.RSAPrivateKey:
    del modified_ns, size  # These values are part of the cache key for rotation.
    try:
        key_data = Path(path).read_bytes()
        key = serialization.load_pem_private_key(key_data, password=None)
    except (OSError, ValueError, TypeError):
        raise IngestionCryptoError("key_unavailable") from None
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise IngestionCryptoError("key_configuration_invalid")
    return key


def get_private_key() -> rsa.RSAPrivateKey:
    path = _private_key_path()
    try:
        stat = path.stat()
    except OSError:
        raise IngestionCryptoError("key_unavailable") from None
    return _load_private_key(str(path), stat.st_mtime_ns, stat.st_size)


def public_key_document() -> dict[str, str]:
    public_key = get_private_key().public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return {
        "key_id": active_key_id(),
        "algorithm": CRYPTO_ALGORITHM,
        "rsa_oaep_hash": "SHA-256",
        "content_encryption": "AES-256-GCM",
        "public_key_pem": pem,
    }


def ensure_crypto_ready() -> None:
    get_private_key()
    active_key_id()


def canonical_associated_data(raw_envelope: dict[str, Any]) -> bytes:
    fields = (
        "schema_version",
        "log_id",
        "timestamp",
        "source_asset_id",
        "destination_asset_id",
    )
    metadata = {field: raw_envelope[field] for field in fields if field in raw_envelope}
    return json.dumps(
        metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _decode_base64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise IngestionCryptoError("invalid_base64") from None


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def decrypt_sensitive_bundle(
    raw_envelope: dict[str, Any], envelope: EncryptedLogEnvelope
) -> SensitiveBundle:
    crypto = envelope.crypto
    if crypto.algorithm != CRYPTO_ALGORITHM:
        raise IngestionCryptoError("unsupported_crypto")
    if crypto.key_id != active_key_id():
        raise IngestionCryptoError("unknown_key_id")

    wrapped_key = _decode_base64(crypto.wrapped_data_key)
    nonce = _decode_base64(crypto.nonce)
    ciphertext = _decode_base64(crypto.ciphertext)
    private_key = get_private_key()
    if len(wrapped_key) != private_key.key_size // 8:
        raise IngestionCryptoError("invalid_wrapped_key")
    if len(nonce) != 12:
        raise IngestionCryptoError("invalid_nonce")
    if len(ciphertext) < 16:
        raise IngestionCryptoError("invalid_ciphertext")

    try:
        data_key = private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError:
        raise IngestionCryptoError("invalid_wrapped_key") from None
    if len(data_key) != 32:
        raise IngestionCryptoError("invalid_data_key")
    try:
        plaintext = AESGCM(data_key).decrypt(
            nonce, ciphertext, canonical_associated_data(raw_envelope)
        )
    except InvalidTag:
        raise IngestionCryptoError("authentication_failed") from None
    except ValueError:
        raise IngestionCryptoError("invalid_ciphertext") from None

    try:
        decoded = json.loads(
            plaintext.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
        if not isinstance(decoded, dict):
            raise ValueError("bundle must be an object")
        return SensitiveBundle.model_validate(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise IngestionCryptoError("invalid_sensitive_bundle") from None
