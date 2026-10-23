"""Bounded encrypted JSONL intake and in-process batch processing."""

import hashlib
import json
import re
from typing import Any, Callable
from uuid import UUID, uuid4

from pydantic import ValidationError
from psycopg import Connection, errors
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from algorithms.kmp_matcher import find_all
from app.crypto import IngestionCryptoError, decrypt_sensitive_bundle
from app.ingestion_schemas import EncryptedLogEnvelope
from app.repositories import record_audit_event


class UploadContractError(Exception):
    def __init__(self, status_code: int, code: str):
        self.status_code = status_code
        self.code = code
        super().__init__(code)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _line_error_code(raw: Any, error: Exception) -> str:
    if isinstance(error, UnicodeDecodeError):
        return "invalid_utf8"
    if isinstance(error, json.JSONDecodeError):
        return "invalid_json"
    if isinstance(raw, dict):
        if raw.get("schema_version") != 1:
            return "unsupported_schema_version"
        crypto = raw.get("crypto")
        if isinstance(crypto, dict) and crypto.get("algorithm") != "RSA-OAEP-256+A256GCM":
            return "unsupported_crypto"
    return "invalid_envelope"


def parse_jsonl(content: bytes, max_lines: int) -> tuple[list[tuple[int, dict[str, Any]]], list[tuple[int, str]], int]:
    if not content:
        raise UploadContractError(400, "empty_upload")
    raw_lines = content.split(b"\n")
    if raw_lines and raw_lines[-1] == b"":  # A final newline terminates the last JSONL record.
        raw_lines.pop()
    if len(raw_lines) > max_lines:
        raise UploadContractError(413, "too_many_lines")

    records: list[tuple[int, dict[str, Any]]] = []
    errors_by_line: list[tuple[int, str]] = []
    seen_log_ids: set[UUID] = set()
    for line_number, raw_line in enumerate(raw_lines, start=1):
        raw_line = raw_line.removesuffix(b"\r")
        if not raw_line.strip():
            errors_by_line.append((line_number, "empty_line"))
            continue
        value: Any = None
        try:
            text = raw_line.decode("utf-8", errors="strict")
            value = json.loads(text, object_pairs_hook=_unique_object)
            if not isinstance(value, dict):
                errors_by_line.append((line_number, "invalid_envelope"))
                continue
            envelope = EncryptedLogEnvelope.model_validate(value)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, ValidationError) as exc:
            errors_by_line.append((line_number, _line_error_code(value, exc)))
            continue

        if envelope.log_id in seen_log_ids:
            errors_by_line.append((line_number, "duplicate_log_id"))
            continue
        seen_log_ids.add(envelope.log_id)
        records.append((line_number, value))
    return records, errors_by_line, len(raw_lines)


def sanitize_filename(filename: str | None) -> str:
    name = (filename or "upload.jsonl").replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(char for char in name if ord(char) >= 32 and ord(char) != 127)
    return (name.strip() or "upload.jsonl")[:255]


def content_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def load_enabled_signatures(connection: Connection) -> list[dict[str, Any]]:
    with connection.cursor(row_factory=dict_row) as cursor:
        return cursor.execute(
            """
            SELECT signature_id, pattern, category, severity, rule_version
            FROM detection_signatures WHERE enabled = TRUE ORDER BY signature_id
            """
        ).fetchall()


def create_ingestion_job(
    connection: Connection,
    *,
    job_id: UUID,
    owner_id: UUID,
    filename: str,
    digest: str,
    idempotency_key: str | None,
    total_lines: int,
    initial_errors: list[tuple[int, str]],
) -> tuple[dict[str, Any], bool]:
    if idempotency_key:
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
            (str(owner_id), idempotency_key),
        )
        with connection.cursor(row_factory=dict_row) as cursor:
            existing = cursor.execute(
                """
                SELECT id, status, total_lines, accepted_lines, rejected_lines,
                       content_sha256, submitted_at
                FROM ingestion_jobs WHERE submitted_by = %s AND idempotency_key = %s
                """,
                (owner_id, idempotency_key),
            ).fetchone()
        if existing:
            if existing["content_sha256"] != digest:
                raise UploadContractError(409, "idempotency_key_reused")
            return existing, False

    with connection.cursor(row_factory=dict_row) as cursor:
        job = cursor.execute(
            """
            INSERT INTO ingestion_jobs
                (id, submitted_by, status, total_lines, rejected_lines,
                 source_filename, content_sha256, idempotency_key)
            VALUES (%s, %s, 'queued', %s, %s, %s, %s, %s)
            RETURNING id, status, total_lines, accepted_lines, rejected_lines,
                      content_sha256, submitted_at
            """,
            (
                job_id,
                owner_id,
                total_lines,
                len(initial_errors),
                filename,
                digest,
                idempotency_key,
            ),
        ).fetchone()
    for line_number, code in initial_errors:
        connection.execute(
            """
            INSERT INTO ingestion_job_line_errors (job_id, line_number, error_code)
            VALUES (%s, %s, %s)
            """,
            (job_id, line_number, code),
        )
    record_audit_event(
        connection,
        actor_id=owner_id,
        action="ingestion.upload_submitted",
        outcome="success",
        target_type="ingestion_job",
        target_id=str(job_id),
        safe_metadata={"line_count": total_lines, "file_sha256": digest},
    )
    return job, True


def get_ingestion_job(connection: Connection, job_id: UUID) -> dict[str, Any] | None:
    with connection.cursor(row_factory=dict_row) as cursor:
        return cursor.execute(
            """
            SELECT id, submitted_by, source_filename, status, submitted_at,
                   started_at, finished_at, total_lines, accepted_lines,
                   rejected_lines, safe_error_code
            FROM ingestion_jobs WHERE id = %s
            """,
            (job_id,),
        ).fetchone()


def get_job_line_errors(connection: Connection, job_id: UUID) -> list[dict[str, Any]]:
    with connection.cursor(row_factory=dict_row) as cursor:
        return cursor.execute(
            """
            SELECT line_number, error_code FROM ingestion_job_line_errors
            WHERE job_id = %s ORDER BY line_number LIMIT 5000
            """,
            (job_id,),
        ).fetchall()


def process_ingestion_job(
    job_id: UUID,
    records: list[tuple[int, dict[str, Any]]],
    initial_errors: list[tuple[int, str]],
    actor_id: UUID,
    connection_factory: Callable[[], Connection],
) -> None:
    """Decrypt, detect, and persist each valid line without logging plaintext."""
    accepted = 0
    line_errors: list[tuple[int, str]] = list(initial_errors)

    def save_line_error(line_number: int, code: str) -> None:
        with connection_factory() as error_connection:
            with error_connection.transaction():
                error_connection.execute(
                    """
                    INSERT INTO ingestion_job_line_errors (job_id, line_number, error_code)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (job_id, line_number) DO UPDATE SET error_code = EXCLUDED.error_code
                    """,
                    (job_id, line_number, code),
                )
                error_connection.execute(
                    "UPDATE ingestion_jobs SET rejected_lines = rejected_lines + 1 WHERE id = %s",
                    (job_id,),
                )

    try:
        with connection_factory() as connection:
            connection.execute(
                """
                UPDATE ingestion_jobs SET status = 'processing', started_at = now()
                WHERE id = %s AND status = 'queued'
                """,
                (job_id,),
            )
            signatures = load_enabled_signatures(connection)

        for line_number, raw_envelope in records:
            try:
                envelope = EncryptedLogEnvelope.model_validate(raw_envelope)
                bundle = decrypt_sensitive_bundle(raw_envelope, envelope)
                normalized_payload = bundle.payload.casefold()
                matches = []
                for signature in signatures:
                    offsets = find_all(signature["pattern"].casefold(), normalized_payload)
                    if offsets:
                        matches.append((signature, offsets))

                encrypted_bundle = json.dumps(
                    envelope.crypto.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                try:
                    with connection_factory() as connection:
                        with connection.transaction():
                            connection.execute(
                                """
                                INSERT INTO security_log_id_registry
                                    (log_id, occurred_at, ingestion_job_id)
                                VALUES (%s, %s, %s)
                                """,
                                (envelope.log_id, envelope.timestamp, job_id),
                            )
                            connection.execute(
                                """
                                INSERT INTO security_logs
                                    (occurred_at, log_id, schema_version, source_asset_id,
                                     destination_asset_id, event_type,
                                     encrypted_sensitive_bundle, safe_metadata,
                                     ingestion_job_id, key_id)
                                VALUES (%s, %s, 1, %s, %s, %s, %s, %s, %s, %s)
                                """,
                                (
                                    envelope.timestamp,
                                    envelope.log_id,
                                    envelope.source_asset_id,
                                    envelope.destination_asset_id,
                                    bundle.event_type,
                                    encrypted_bundle,
                                    Jsonb({"event_type": bundle.event_type}),
                                    job_id,
                                    envelope.crypto.key_id,
                                ),
                            )
                            for signature, offsets in matches:
                                connection.execute(
                                    """
                                    INSERT INTO alerts
                                        (id, occurred_at, log_id, signature_id, category,
                                         severity, explanation, safe_metadata,
                                         source_asset_id, destination_asset_id)
                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                    """,
                                    (
                                        uuid4(),
                                        envelope.timestamp,
                                        envelope.log_id,
                                        signature["signature_id"],
                                        signature["category"],
                                        signature["severity"],
                                        f"Configured signature {signature['signature_id']} matched {len(offsets)} time(s).",
                                        Jsonb(
                                            {
                                                "match_offsets": offsets,
                                                "rule_version": signature["rule_version"],
                                                "normalization": "casefold",
                                            }
                                        ),
                                        envelope.source_asset_id,
                                        envelope.destination_asset_id,
                                    ),
                                )
                            connection.execute(
                                "UPDATE ingestion_jobs SET accepted_lines = accepted_lines + 1 WHERE id = %s",
                                (job_id,),
                            )
                    accepted += 1
                except errors.UniqueViolation:
                    line_errors.append((line_number, "duplicate_log_id"))
                    save_line_error(line_number, "duplicate_log_id")
            except IngestionCryptoError as exc:
                line_errors.append((line_number, exc.code))
                save_line_error(line_number, exc.code)
            except (ValueError, ValidationError):
                line_errors.append((line_number, "invalid_envelope"))
                save_line_error(line_number, "invalid_envelope")

        rejected = len(line_errors)
        final_status = "completed_with_errors" if rejected else "completed"
        with connection_factory() as connection:
            with connection.transaction():
                for line_number, code in line_errors:
                    connection.execute(
                        """
                        INSERT INTO ingestion_job_line_errors (job_id, line_number, error_code)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (job_id, line_number) DO UPDATE SET error_code = EXCLUDED.error_code
                        """,
                        (job_id, line_number, code),
                    )
                connection.execute(
                    """
                    UPDATE ingestion_jobs
                    SET status = %s, accepted_lines = %s, rejected_lines = %s,
                        finished_at = now(), safe_error_code = NULL
                    WHERE id = %s
                    """,
                    (final_status, accepted, rejected, job_id),
                )
                record_audit_event(
                    connection,
                    actor_id=actor_id,
                    action="ingestion.processing_finished",
                    outcome="success" if rejected == 0 else "failure",
                    target_type="ingestion_job",
                    target_id=str(job_id),
                    safe_metadata={"accepted_lines": accepted, "rejected_lines": rejected},
                )
    except Exception:
        # Never log exception text here: it can contain data from a failed record.
        try:
            with connection_factory() as connection:
                connection.execute(
                    """
                    UPDATE ingestion_jobs
                    SET status = 'failed', rejected_lines = GREATEST(total_lines - accepted_lines, 0),
                        finished_at = now(), safe_error_code = 'processing_failed'
                    WHERE id = %s AND status NOT IN ('completed', 'completed_with_errors')
                    """,
                    (job_id,),
                )
                record_audit_event(
                    connection,
                    actor_id=actor_id,
                    action="ingestion.processing_finished",
                    outcome="failure",
                    target_type="ingestion_job",
                    target_id=str(job_id),
                    safe_metadata={"reason_code": "processing_failed"},
                )
        except Exception:
            pass
