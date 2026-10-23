"""Strict envelope and decrypted-bundle contracts for encrypted JSONL."""

from datetime import datetime
import ipaddress
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CryptoEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    algorithm: Literal["RSA-OAEP-256+A256GCM"]
    key_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    wrapped_data_key: str = Field(min_length=1, max_length=8192)
    nonce: str = Field(min_length=1, max_length=64)
    ciphertext: str = Field(min_length=1, max_length=2_000_000)


class EncryptedLogEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    log_id: UUID
    timestamp: datetime
    source_asset_id: str | None = Field(
        default=None, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    )
    destination_asset_id: str | None = Field(
        default=None, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"
    )
    crypto: CryptoEnvelope

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value

    @field_validator("source_asset_id", "destination_asset_id")
    @classmethod
    def validate_asset_id(cls, value: str | None) -> str | None:
        return value


class SensitiveBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    payload: str = Field(default="", max_length=65_536)
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    event_type: str = Field(
        default="security_event",
        min_length=1,
        max_length=100,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip(cls, value: str | None) -> str | None:
        if value is not None:
            ipaddress.ip_address(value)
        return value


class UploadResponse(BaseModel):
    job_id: UUID
    status: str
    total_lines: int
    accepted_lines: int
    rejected_lines: int
    submitted_at: datetime
    replayed_idempotent_request: bool = False


class IngestionLineError(BaseModel):
    line_number: int
    error_code: str


class IngestionJobResponse(BaseModel):
    job_id: UUID
    status: str
    source_filename: str
    submitted_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    total_lines: int
    accepted_lines: int
    rejected_lines: int
    safe_error_code: str | None
    line_errors: list[IngestionLineError]
