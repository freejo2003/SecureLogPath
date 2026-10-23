"""Backend foundation: database migrations, bootstrap auth, and role checks."""

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import os
import re
from typing import Annotated, Callable
from uuid import UUID, uuid4

import jwt
import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from pwdlib import PasswordHash
from psycopg import errors
from psycopg.types.json import Jsonb

from app.migrations import apply_migrations
from app.repositories import (
    create_user,
    get_user_by_id,
    get_user_by_username,
    record_audit_event,
)
from app.schemas import LoginRequest, TokenResponse, UserCreateRequest, UserResponse

TOKEN_TTL_SECONDS = 30 * 60
JWT_ALGORITHM = "HS256"
password_hash = PasswordHash.recommended()
DUMMY_PASSWORD_HASH = password_hash.hash("not-a-real-user-password")
bearer_scheme = HTTPBearer(auto_error=False)


def database_connection() -> psycopg.Connection:
    return psycopg.connect(
        host=os.environ["DATABASE_HOST"],
        port=int(os.environ.get("DATABASE_PORT", "5432")),
        dbname=os.environ["DATABASE_NAME"],
        user=os.environ["DATABASE_USER"],
        password=os.environ["DATABASE_PASSWORD"],
        connect_timeout=3,
    )


def signing_secret() -> str:
    secret = os.environ.get("JWT_SIGNING_SECRET", "")
    if len(secret) < 32 or secret.lower().startswith("replace-"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured",
        )
    return secret


def bootstrap_admin() -> None:
    username = os.environ.get("BOOTSTRAP_ADMIN_USERNAME", "").strip().lower()
    password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "")
    if (
        not username
        or len(password) < 12
        or password.lower().startswith("replace-")
        or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{2,79}", username)
    ):
        return

    with database_connection() as connection:
        if get_user_by_username(connection, username):
            return
        user_id = uuid4()
        create_user(
            connection,
            user_id=user_id,
            username=username,
            password_hash=password_hash.hash(password),
            role="admin",
        )
        record_audit_event(
            connection,
            actor_id=user_id,
            action="user.bootstrap_admin",
            outcome="success",
            target_type="user",
            target_id=str(user_id),
        )


@asynccontextmanager
async def lifespan(_: FastAPI):
    with database_connection() as connection:
        apply_migrations(connection)
        connection.execute(
            """
            UPDATE ingestion_jobs
            SET status = 'interrupted', finished_at = now(),
                safe_error_code = 'worker_interrupted'
            WHERE status IN ('submitted', 'queued', 'processing')
            """
        )
    bootstrap_admin()
    yield


app = FastAPI(title="SecureLogPath API", version="0.2.0", lifespan=lifespan)
api = APIRouter(prefix="/api/v1")


def audit_denial(action: str, reason_code: str, actor_id: UUID | None = None) -> None:
    try:
        with database_connection() as connection:
            record_audit_event(
                connection,
                actor_id=actor_id,
                action=action,
                outcome="denied",
                safe_metadata={"reason_code": reason_code},
            )
    except Exception:
        # Do not expose database details or credentials through auth failures.
        pass


def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(bearer_scheme)
    ],
) -> UserResponse:
    action = "auth.access"
    if credentials is None or credentials.scheme.lower() != "bearer":
        audit_denial(action, "missing_bearer_token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    secret = signing_secret()
    try:
        payload = jwt.decode(
            credentials.credentials,
            secret,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "exp", "iat"]},
        )
        user_id = UUID(payload["sub"])
    except (InvalidTokenError, ValueError, KeyError):
        audit_denial(action, "invalid_or_expired_token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    with database_connection() as connection:
        user = get_user_by_id(connection, user_id)
    if user is None or not user["is_active"]:
        audit_denial(action, "inactive_or_unknown_user", user_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return UserResponse(**user)


def require_roles(*roles: str) -> Callable[..., UserResponse]:
    def dependency(
        user: Annotated[UserResponse, Depends(get_current_user)],
    ) -> UserResponse:
        if user.role not in roles:
            audit_denial("auth.role_denied", "insufficient_role", user.id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return user

    return dependency


@app.get("/health/live", include_in_schema=False)
@app.get("/api/health/live", include_in_schema=False)
def liveness() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready", include_in_schema=False)
@app.get("/api/health/ready", include_in_schema=False)
def readiness() -> dict[str, str]:
    try:
        with database_connection() as connection:
            connection.execute("SELECT 1")
    except Exception:
        raise HTTPException(status_code=503, detail="Database is not ready") from None
    return {"status": "ready"}


@api.post("/auth/login", response_model=TokenResponse)
def login(request: LoginRequest) -> TokenResponse:
    secret = signing_secret()
    invalid_credentials = False
    token = ""
    with database_connection() as connection:
        user = get_user_by_username(connection, request.username)
        stored_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
        password_matches = password_hash.verify(request.password, stored_hash)
        if user is None or not user["is_active"] or not password_matches:
            record_audit_event(
                connection,
                action="auth.login",
                outcome="denied",
                safe_metadata={"reason_code": "invalid_credentials"},
            )
            invalid_credentials = True
        else:
            now = datetime.now(timezone.utc)
            token = jwt.encode(
                {
                    "sub": str(user["id"]),
                    "iat": now,
                    "exp": now + timedelta(seconds=TOKEN_TTL_SECONDS),
                },
                secret,
                algorithm=JWT_ALGORITHM,
            )
            record_audit_event(
                connection,
                actor_id=user["id"],
                action="auth.login",
                outcome="success",
                target_type="user",
                target_id=str(user["id"]),
            )
    if invalid_credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenResponse(access_token=token, expires_in=TOKEN_TTL_SECONDS)


@api.get("/auth/me", response_model=UserResponse)
def who_am_i(
    user: Annotated[UserResponse, Depends(get_current_user)],
) -> UserResponse:
    return user


@api.post("/admin/users", response_model=UserResponse, status_code=201)
def add_user(
    request: UserCreateRequest,
    admin: Annotated[UserResponse, Depends(require_roles("admin"))],
) -> UserResponse:
    user_id = uuid4()
    try:
        with database_connection() as connection:
            created = create_user(
                connection,
                user_id=user_id,
                username=request.username,
                password_hash=password_hash.hash(request.password),
                role=request.role,
            )
            record_audit_event(
                connection,
                actor_id=admin.id,
                action="user.create",
                outcome="success",
                target_type="user",
                target_id=str(user_id),
                safe_metadata={"role": request.role},
            )
    except errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Username already exists") from None
    return UserResponse(**created)


app.include_router(api)
