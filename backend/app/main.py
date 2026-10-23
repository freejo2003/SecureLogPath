"""Minimal API shell for the Phase 1 Compose foundation."""

import os

import psycopg
from fastapi import FastAPI, HTTPException

app = FastAPI(title="SecureLogPath API", version="0.1.0")


def database_connection() -> psycopg.Connection:
    return psycopg.connect(
        host=os.environ["DATABASE_HOST"],
        port=int(os.environ.get("DATABASE_PORT", "5432")),
        dbname=os.environ["DATABASE_NAME"],
        user=os.environ["DATABASE_USER"],
        password=os.environ["DATABASE_PASSWORD"],
        connect_timeout=3,
    )


@app.get("/health/live", include_in_schema=False)
def liveness() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready", include_in_schema=False)
def readiness() -> dict[str, str]:
    try:
        with database_connection() as connection:
            connection.execute("SELECT 1")
    except Exception:
        raise HTTPException(status_code=503, detail="Database is not ready") from None
    return {"status": "ready"}
