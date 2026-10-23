"""Backend foundation: database migrations, bootstrap auth, and role checks."""

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import os
import re
from threading import BoundedSemaphore
from typing import Annotated, Callable, Any
from uuid import UUID, uuid4

import jwt
import psycopg
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from pwdlib import PasswordHash
from psycopg import errors
from psycopg.types.json import Jsonb

from app.migrations import apply_migrations
from app.crypto import IngestionCryptoError, ensure_crypto_ready, public_key_document
from app.ingestion import (
    UploadContractError,
    content_sha256,
    create_ingestion_job,
    get_ingestion_job,
    get_job_line_errors,
    parse_jsonl,
    process_ingestion_job,
    sanitize_filename,
)
from app.ingestion_schemas import IngestionJobResponse, UploadResponse
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


def configured_limit(name: str, default: int, hard_maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return min(max(value, 1), hard_maximum)


INGESTION_SLOTS = BoundedSemaphore(
    configured_limit("MAX_CONCURRENT_INGESTIONS", 2, 8)
)


def process_job_and_release_slot(*args: Any) -> None:
    try:
        process_ingestion_job(*args)
    finally:
        INGESTION_SLOTS.release()


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


@api.get("/crypto/public-key")
def get_ingestion_public_key(
    response: Response,
    _: Annotated[UserResponse, Depends(require_roles("forwarder"))],
) -> dict[str, str]:
    try:
        key = public_key_document()
    except IngestionCryptoError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ingestion encryption key is unavailable",
        ) from None
    response.headers["Cache-Control"] = "no-store"
    return key


@api.post(
    "/ingestion/uploads",
    response_model=UploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def submit_ingestion_upload(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    idempotency_key: Annotated[
        str | None, Header(alias="Idempotency-Key", max_length=128)
    ] = None,
    forwarder: UserResponse = Depends(require_roles("forwarder")),
) -> UploadResponse:
    maximum_bytes = configured_limit("MAX_UPLOAD_BYTES", 2_097_152, 8_388_608)
    maximum_lines = configured_limit("MAX_UPLOAD_LINES", 5_000, 20_000)
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > maximum_bytes + 65_536:
        raise HTTPException(status_code=413, detail="upload_too_large")
    if not file.filename or not file.filename.lower().endswith(".jsonl"):
        raise HTTPException(status_code=415, detail="unsupported_file_type")
    media_type = (file.content_type or "").split(";", 1)[0].strip().lower()
    if media_type and media_type not in {
        "application/json",
        "application/jsonl",
        "application/x-ndjson",
        "application/octet-stream",
    }:
        raise HTTPException(status_code=415, detail="unsupported_media_type")
    if idempotency_key is not None and not re.fullmatch(
        r"[A-Za-z0-9._:-]{1,128}", idempotency_key
    ):
        raise HTTPException(status_code=400, detail="invalid_idempotency_key")
    try:
        ensure_crypto_ready()
    except IngestionCryptoError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ingestion encryption key is unavailable",
        ) from None

    content = await file.read(maximum_bytes + 1)
    if len(content) > maximum_bytes:
        raise HTTPException(status_code=413, detail="upload_too_large")
    try:
        records, line_errors, total_lines = parse_jsonl(content, maximum_lines)
    except UploadContractError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from None

    if not INGESTION_SLOTS.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="ingestion_capacity_reached")

    job_id = uuid4()
    try:
        with database_connection() as connection:
            job, created = create_ingestion_job(
                connection,
                job_id=job_id,
                owner_id=forwarder.id,
                filename=sanitize_filename(file.filename),
                digest=content_sha256(content),
                idempotency_key=idempotency_key,
                total_lines=total_lines,
                initial_errors=line_errors,
            )
    except UploadContractError as exc:
        INGESTION_SLOTS.release()
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from None
    except Exception:
        INGESTION_SLOTS.release()
        raise
    if created:
        background_tasks.add_task(
            process_job_and_release_slot,
            job["id"],
            records,
            line_errors,
            forwarder.id,
            database_connection,
        )
    else:
        INGESTION_SLOTS.release()
    return UploadResponse(
        job_id=job["id"],
        status=job["status"],
        total_lines=job["total_lines"],
        accepted_lines=job["accepted_lines"],
        rejected_lines=job["rejected_lines"],
        submitted_at=job["submitted_at"],
        replayed_idempotent_request=not created,
    )


@api.get("/ingestion/jobs/{job_id}", response_model=IngestionJobResponse)
def read_ingestion_job(
    job_id: UUID,
    user: Annotated[
        UserResponse,
        Depends(require_roles("forwarder", "analyst", "admin")),
    ],
) -> IngestionJobResponse:
    with database_connection() as connection:
        job = get_ingestion_job(connection, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Ingestion job not found")
        if job["submitted_by"] != user.id and user.role not in {"analyst", "admin"}:
            audit_denial("ingestion.job_read", "job_not_owned", user.id)
            raise HTTPException(status_code=404, detail="Ingestion job not found")
        line_errors = get_job_line_errors(connection, job_id)
    return IngestionJobResponse(
        job_id=job["id"],
        status=job["status"],
        source_filename=job["source_filename"],
        submitted_at=job["submitted_at"],
        started_at=job["started_at"],
        finished_at=job["finished_at"],
        total_lines=job["total_lines"],
        accepted_lines=job["accepted_lines"],
        rejected_lines=job["rejected_lines"],
        safe_error_code=job["safe_error_code"],
        line_errors=line_errors,
    )


app.include_router(api)
