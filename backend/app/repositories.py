"""Database operations for users and security audit events."""

from typing import Any
from uuid import UUID

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


def get_user_by_username(connection: Connection, username: str) -> dict[str, Any] | None:
    with connection.cursor(row_factory=dict_row) as cursor:
        return cursor.execute(
            """
            SELECT id, username, password_hash, role, is_active, created_at
            FROM app_users WHERE username = %s
            """,
            (username,),
        ).fetchone()


def get_user_by_id(connection: Connection, user_id: UUID) -> dict[str, Any] | None:
    with connection.cursor(row_factory=dict_row) as cursor:
        return cursor.execute(
            """
            SELECT id, username, password_hash, role, is_active, created_at
            FROM app_users WHERE id = %s
            """,
            (user_id,),
        ).fetchone()


def create_user(
    connection: Connection, *, user_id: UUID, username: str, password_hash: str, role: str
) -> dict[str, Any]:
    with connection.cursor(row_factory=dict_row) as cursor:
        return cursor.execute(
            """
            INSERT INTO app_users (id, username, password_hash, role)
            VALUES (%s, %s, %s, %s)
            RETURNING id, username, role, is_active, created_at
            """,
            (user_id, username, password_hash, role),
        ).fetchone()


def record_audit_event(
    connection: Connection,
    *,
    action: str,
    outcome: str,
    actor_id: UUID | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    safe_metadata: dict[str, Any] | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO audit_events
            (actor_id, action, target_type, target_id, outcome, safe_metadata)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            actor_id,
            action,
            target_type,
            target_id,
            outcome,
            Jsonb(safe_metadata or {}),
        ),
    )

