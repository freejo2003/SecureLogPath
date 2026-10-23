"""Small, ordered SQL migration runner for the single-instance demo service."""

from pathlib import Path

from psycopg import Connection

_module_root = Path(__file__).resolve().parents[1]
_project_root = _module_root.parent
_candidates = (
    _project_root / "database" / "migrations",
    _module_root / "database" / "migrations",
)
MIGRATIONS_DIR = next((path for path in _candidates if path.is_dir()), _candidates[0])


def apply_migrations(connection: Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    applied = {
        row[0]
        for row in connection.execute("SELECT version FROM schema_migrations").fetchall()
    }

    for migration_path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        version = migration_path.name
        if version in applied:
            continue
        sql = migration_path.read_text(encoding="utf-8")
        with connection.transaction():
            connection.execute(sql, prepare=False)
            connection.execute(
                "INSERT INTO schema_migrations (version) VALUES (%s)", (version,)
            )

