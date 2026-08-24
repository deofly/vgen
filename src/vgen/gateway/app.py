"""FastAPI application for the VGen Gateway v1 control plane."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import secrets
import sqlite3
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from vgen.crypto import (
    HPKE_ALGORITHM,
    HpkeCiphertext,
    b64url_decode,
    b64url_encode,
    canonical_json,
    verify_device_certificate,
    verify_http_request,
    verify_key_manifest,
    verify_maintenance_intent,
    verify_message,
)
from vgen.protocol.errors import ErrorCode, VGenError, error_envelope, get_error_spec
from vgen.protocol.ids import new_id as protocol_new_id
from vgen.protocol.ids import validate_id
from vgen.protocol.user_enrollment import verify_user_registration_claim

from .artifacts import ArtifactStore, LocalArtifactStore, OssArtifactStore
from .database import GatewayDatabase, row_dict
from .openapi import idempotency_cache_mode, install_openapi_contract
from .releases import (
    PublicReleaseManifest,
    ReleaseCatalog,
    ReleaseManifestInvalid,
    ReleaseNotFound,
)
from .repository import GatewayRepository, RepositoryError
from .schemas import (
    AllocationApproval,
    ApplicationCreate,
    AttemptFinish,
    AttemptHeartbeat,
    BootstrapRequest,
    BrokerCreate,
    BrokerDeviceAttach,
    BrokerHeartbeat,
    ChallengeRequest,
    CommandComplete,
    DeviceEnrollmentRequest,
    DeviceRecoveryChallengeRequest,
    DeviceRecoveryCompleteRequest,
    EnrollmentDecision,
    HealthResponse,
    InviteClaim,
    InviteCreate,
    LeaseRequest,
    PoolCreate,
    RateProposal,
    ServiceEnrollmentRequest,
    SessionRequest,
    StatusResponse,
    TaskCommit,
    TaskPreflight,
    TaskPreflightResult,
    TaskPrepare,
    TaskRekey,
    UsageReversalCreate,
    UserEnrollmentRequest,
    WorkerCreate,
    WorkerEnrollmentClaimRequest,
    WorkerEnrollmentDecision,
    WorkerHeartbeat,
    WorkerInviteCreate,
    WorkerLeave,
    WorkerMaintenanceCancel,
    WorkerMaintenanceClaim,
    WorkerMaintenanceCommit,
    WorkerMaintenanceComplete,
    WorkerMaintenanceCreate,
    WorkerMaintenanceHeartbeat,
    WorkerManagerSet,
    WorkerOffer,
    WorkspaceCreate,
    WorkspaceKeyEnvelopeGrant,
    WorkspaceKeyRotationCreate,
    WorkspaceRecipientAdmissionCreate,
)

logger = logging.getLogger("vgen.gateway")
bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True, slots=True)
class Principal:
    principal_type: str
    principal_id: str
    user_id: str | None
    scopes: frozenset[str]
    session_id: str


@dataclass(slots=True)
class _RateBucket:
    tokens: float
    updated_at: float


class _TokenBucketRateLimiter:
    """Small process-local abuse backstop with strictly bounded memory.

    Nginx is the first public rate-limit layer. This limiter still protects a
    directly reached development Gateway and survives proxy misconfiguration
    without writing attacker-controlled buckets to SQLite.
    """

    def __init__(
        self,
        *,
        max_buckets: int = 10_000,
        idle_seconds: float = 900.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_buckets <= 0 or idle_seconds <= 0:
            raise ValueError("rate limiter bounds must be positive")
        self._max_buckets = max_buckets
        self._idle_seconds = idle_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: OrderedDict[tuple[str, str], _RateBucket] = OrderedDict()

    @property
    def bucket_count(self) -> int:
        with self._lock:
            return len(self._buckets)

    def check(
        self,
        category: str,
        client_id: str,
        *,
        capacity: int,
        refill_per_second: float,
    ) -> tuple[bool, float]:
        if capacity <= 0 or refill_per_second <= 0:
            raise ValueError("rate limit policy must be positive")
        stamp = self._clock()
        key = (category, client_id[:255])
        with self._lock:
            cutoff = stamp - self._idle_seconds
            while self._buckets:
                oldest_key = next(iter(self._buckets))
                if self._buckets[oldest_key].updated_at > cutoff:
                    break
                self._buckets.popitem(last=False)

            bucket = self._buckets.pop(key, None)
            if bucket is None:
                bucket = _RateBucket(float(capacity), stamp)
            else:
                elapsed = max(0.0, stamp - bucket.updated_at)
                bucket.tokens = min(
                    float(capacity), bucket.tokens + elapsed * refill_per_second
                )
                bucket.updated_at = stamp

            allowed = bucket.tokens >= 1.0
            if allowed:
                bucket.tokens -= 1.0
                retry_after = 0.0
            else:
                retry_after = (1.0 - bucket.tokens) / refill_per_second
            self._buckets[key] = bucket
            while len(self._buckets) > self._max_buckets:
                self._buckets.popitem(last=False)
            return allowed, retry_after


_PUBLIC_RATE_LIMITS: dict[str, tuple[int, float]] = {
    # Category: (short burst capacity, sustained tokens per second).
    "bootstrap": (5, 5 / 60),
    "device_recovery": (10, 10 / 60),
    "session_challenge": (30, 120 / 60),
    "public_enrollment": (15, 30 / 60),
}
_PUBLIC_AUTH_MAX_BODY_BYTES = 64 * 1024


def _public_rate_limit_category(path: str) -> str | None:
    if path == "/api/v1/auth/bootstrap":
        return "bootstrap"
    if path in {
        "/api/v1/auth/device-recovery/challenges",
        "/api/v1/auth/device-recovery/complete",
    }:
        return "device_recovery"
    if path in {"/api/v1/auth/challenges", "/api/v1/auth/sessions"}:
        return "session_challenge"
    if path in {
        "/api/v1/auth/enroll",
        "/api/v1/devices/enroll",
        "/api/v1/auth/services/enroll",
        "/api/v1/worker-enrollments/claim",
        "/api/v1/enrollments/claim",
    }:
        return "public_enrollment"
    return None


def _declared_content_length(request: Request) -> int | None:
    raw = request.headers.get("Content-Length")
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("invalid_content_length") from exc
    if value < 0:
        raise ValueError("invalid_content_length")
    return value


async def _cache_bounded_body(request: Request, *, max_bytes: int) -> bool:
    """Read a small control request once, including chunked request bodies.

    Content-Length is only a fast rejection hint. Counting the ASGI chunks is
    the authoritative application boundary and prevents a chunked request or
    a misleading length header from reaching request.body() unbounded later.
    """

    body = bytearray()
    total = 0
    async for chunk in request.stream():
        chunk_size = len(chunk)
        if chunk_size > max_bytes - total:
            return False
        body.extend(chunk)
        total += chunk_size
    # Starlette deliberately uses this cache in Request.body() and in the
    # wrapped receive channel passed through BaseHTTPMiddleware.
    request._body = bytes(body)  # type: ignore[attr-defined]
    return True


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", None) or protocol_new_id("request")


def _error_response(
    code: ErrorCode,
    request: Request,
    *,
    details: dict[str, Any] | None = None,
    task_id: str | None = None,
    attempt_id: str | None = None,
    status_code: int | None = None,
    retry_after_ms: int | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    response_headers = {"X-Request-ID": _request_id(request), **(headers or {})}
    return JSONResponse(
        error_envelope(
            code,
            request_id=_request_id(request),
            details=details,
            task_id=task_id,
            attempt_id=attempt_id,
            retry_after_ms=retry_after_ms,
        ),
        status_code=status_code or get_error_spec(code).http_status,
        headers=response_headers,
    )


_CAPABILITY_FIELD_NAMES = frozenset(
    {
        "authorization",
        "access_key_id",
        "access_key_secret",
        "credentials",
        "invite_uri",
        "join_uri",
        "secret",
        "security_token",
        "session_token",
        "signed_url",
        "ticket",
        "token",
        "url",
        "vgen_artifact_ticket",
    }
)


def _contains_capability_material(value: Any, *, field_name: str = "") -> bool:
    """Fail closed before a replay record can persist a bearer capability."""

    normalized = field_name.lower().replace("-", "_")
    if normalized in _CAPABILITY_FIELD_NAMES and value not in (None, "", [], {}):
        return True
    if isinstance(value, dict):
        return any(
            _contains_capability_material(child, field_name=str(key))
            for key, child in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_capability_material(child) for child in value)
    if isinstance(value, str):
        lowered = value.lower()
        return (
            "/api/v1/artifacts/transfer/" in lowered
            or "x-oss-signature=" in lowered
            or lowered.startswith("bearer ")
        )
    return False


def _safe_idempotency_headers(headers: dict[str, str]) -> dict[str, str]:
    """Persist only response metadata that can never carry credentials."""

    allowed = {"cache-control", "content-type", "etag", "retry-after"}
    return {key: value for key, value in headers.items() if key.lower() in allowed}


def _idempotency_storage_body(mode: str, status: int, body: bytes) -> bytes | None:
    """Build a capability-free replay recipe, or decline to cache it."""

    if status == 204:
        return b""

    try:
        value = json.loads(body) if body else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    existing_recipe = value.get("_vgen_replay") if isinstance(value, dict) else None
    if isinstance(existing_recipe, dict) and existing_recipe.get("kind") == mode:
        if _contains_capability_material(value):
            return None
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    if 200 <= status < 300 and mode == "task_prepare":
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("id"), str)
            or not isinstance(value.get("attempt_id"), str)
        ):
            return None
        value = {
            "_vgen_replay": {
                "version": 1,
                "kind": "task_prepare",
                "task_id": value["id"],
                "attempt_id": value["attempt_id"],
                "allocation_id": (
                    value.get("allocation", {}).get("id")
                    if isinstance(value.get("allocation"), dict)
                    else None
                ),
            }
        }
    elif 200 <= status < 300 and mode == "worker_lease" and status != 204:
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("attempt_id"), str)
            or not isinstance(value.get("lease_id"), str)
        ):
            return None
        value = {
            "_vgen_replay": {
                "version": 1,
                "kind": "worker_lease",
                "attempt_id": value["attempt_id"],
                "lease_id": value["lease_id"],
                "fencing_token": value.get("fencing_token"),
            }
        }
    elif 200 <= status < 300 and mode == "maintenance_create":
        if not isinstance(value, dict) or not isinstance(value.get("id"), str):
            return None
        value = {
            "_vgen_replay": {
                "version": 1,
                "kind": "maintenance_create",
                "job_id": value["id"],
            }
        }
    elif 200 <= status < 300 and mode == "maintenance_claim" and status != 204:
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("id"), str)
            or not isinstance(value.get("fencing_token"), int)
        ):
            return None
        value = {
            "_vgen_replay": {
                "version": 1,
                "kind": "maintenance_claim",
                "job_id": value["id"],
                "fencing_token": value["fencing_token"],
            }
        }
    if _contains_capability_material(value):
        return None
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def create_app(
    *,
    database_path: str | None = None,
    bootstrap_code: str | None = None,
    docs_enabled: bool | None = None,
    require_request_signatures: bool | None = None,
    artifact_root: str | None = None,
    artifact_ticket_key: bytes | None = None,
    artifact_store_override: ArtifactStore | None = None,
    release_root: str | None = None,
    release_public_base_url: str | None = None,
    serve_release_files: bool | None = None,
    sweep_interval_seconds: float | None = None,
    max_control_body_bytes: int | None = None,
) -> FastAPI:
    """Create an isolated Gateway app.

    Passing the DB path and bootstrap code is intended for tests and embedded
    deployments. Production processes should use the corresponding VGEN_*
    environment variables.
    """

    db_path = database_path or os.getenv("VGEN_GATEWAY_DB_PATH", "./data/vgen-gateway.db")
    configured_bootstrap = bootstrap_code or os.getenv("VGEN_GATEWAY_BOOTSTRAP_CODE")
    if not configured_bootstrap:
        raise RuntimeError("VGEN_GATEWAY_BOOTSTRAP_CODE must be configured")
    expose_docs = (
        docs_enabled if docs_enabled is not None else os.getenv("VGEN_GATEWAY_DOCS", "1") != "0"
    )
    verify_mutations = (
        require_request_signatures
        if require_request_signatures is not None
        else os.getenv("VGEN_REQUIRE_REQUEST_SIGNATURES", "1") != "0"
    )
    sweep_interval = (
        sweep_interval_seconds
        if sweep_interval_seconds is not None
        else float(os.getenv("VGEN_GATEWAY_SWEEP_SECONDS", "10"))
    )
    if sweep_interval <= 0:
        raise RuntimeError("VGEN_GATEWAY_SWEEP_SECONDS must be positive")
    control_body_limit = (
        max_control_body_bytes
        if max_control_body_bytes is not None
        else int(os.getenv("VGEN_GATEWAY_MAX_CONTROL_BODY_BYTES", str(16 * 1024**2)))
    )
    if control_body_limit <= 0:
        raise RuntimeError("VGEN_GATEWAY_MAX_CONTROL_BODY_BYTES must be positive")
    rate_limiter = _TokenBucketRateLimiter()

    configured_release_root = release_root or os.getenv("VGEN_RELEASE_ROOT")
    configured_release_public_base_url = release_public_base_url or os.getenv(
        "VGEN_RELEASE_PUBLIC_BASE_URL", "/releases"
    )
    configured_serve_release_files = (
        serve_release_files
        if serve_release_files is not None
        else os.getenv("VGEN_RELEASE_SERVE_FILES", "0").strip().lower()
        in {"1", "true", "yes", "on"}
    )
    release_catalog = ReleaseCatalog(
        configured_release_root,
        public_base_url=configured_release_public_base_url,
        serve_files=configured_serve_release_files,
    )

    configured_artifact_store = os.getenv("VGEN_ARTIFACT_STORE", "").strip().lower()
    if artifact_store_override is not None:
        artifact_store = artifact_store_override
    elif configured_artifact_store == "oss":
        artifact_store = OssArtifactStore.from_environment()
    elif configured_artifact_store == "local" and os.getenv(
        "VGEN_ALLOW_LOCAL_ARTIFACT_STORE", ""
    ) == "1":
        resolved_artifact_root = artifact_root or os.getenv(
            "VGEN_ARTIFACT_ROOT", "./data/artifacts"
        )
        ticket_key = artifact_ticket_key
        if ticket_key is None:
            configured_ticket_key = os.getenv("VGEN_ARTIFACT_TICKET_KEY")
            ticket_key = (
                hashlib.sha256(configured_ticket_key.encode()).digest()
                if configured_ticket_key
                else secrets.token_bytes(32)
            )
        artifact_store = LocalArtifactStore(resolved_artifact_root, ticket_key)
    else:
        raise RuntimeError(
            "VGEN_ARTIFACT_STORE=oss is required for production; local artifact storage "
            "requires the explicit development-only VGEN_ALLOW_LOCAL_ARTIFACT_STORE=1 opt-in"
        )
    db = GatewayDatabase(db_path)
    repository = GatewayRepository(db)

    async def sweep_control_plane() -> None:
        while True:
            await asyncio.sleep(sweep_interval)
            try:
                repository.sweep_expired()
            except Exception:
                # The Gateway remains available and retries on the next tick.
                # No task content or key material is included in this log.
                logger.exception("gateway expiry sweep failed")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        repository.sweep_expired()
        sweep_task = asyncio.create_task(sweep_control_plane(), name="vgen-gateway-expiry-sweeper")
        try:
            yield
        finally:
            sweep_task.cancel()
            with suppress(asyncio.CancelledError):
                await sweep_task
            db.close()

    app = FastAPI(
        title="VGen Gateway",
        description="Open, encrypted GPU workflow control-plane API.",
        version="1.0.0",
        license_info={
            "name": "Apache License 2.0",
            "identifier": "Apache-2.0",
        },
        docs_url="/docs" if expose_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if expose_docs else None,
        lifespan=lifespan,
    )
    app.state.db = db
    app.state.repository = repository
    app.state.artifact_store = artifact_store
    app.state.release_catalog = release_catalog
    app.state.bootstrap_code = configured_bootstrap
    app.state.control_body_limit = control_body_limit
    app.state.public_rate_limiter = rate_limiter

    def external_ticket(ticket: dict[str, Any], request: Request) -> dict[str, Any]:
        value = dict(ticket)
        if str(value.get("url", "")).startswith("/"):
            value["url"] = str(request.base_url).rstrip("/") + str(value["url"])
        return value

    def output_tickets(
        artifacts: list[dict[str, Any]], request: Request, *, ttl_seconds: int = 3600
    ) -> list[dict[str, Any]]:
        values: list[dict[str, Any]] = []
        for index, output in enumerate(artifacts):
            executor_output_name = "primary" if index == 0 else f"output-{index + 1}"
            raw = external_ticket(
                artifact_store.issue_ticket(
                    output["id"],
                    method="PUT",
                    ttl_seconds=ttl_seconds,
                    max_bytes=100 * 1024**3,
                ).to_dict(),
                request,
            )
            values.append(
                {
                    **raw,
                    "ticket": raw,
                    "artifact_id": output["id"],
                    "name": executor_output_name,
                    "executor_output_name": executor_output_name,
                    "store_type": artifact_store.store_type,
                    "object_ref": output["id"],
                    "kind": output["kind"],
                    "artifact": output,
                }
            )
        return values

    def input_upload_tickets(task_id: str, request: Request) -> list[dict[str, Any]]:
        values: list[dict[str, Any]] = []
        artifacts = [
            row_dict(row, json_columns={"media_metadata"})
            for row in db.fetchall(
                """SELECT * FROM artifacts
                   WHERE task_id=? AND direction='input' AND state='pending'
                   ORDER BY created_at""",
                (task_id,),
            )
        ]
        for artifact in artifacts:
            raw = external_ticket(
                artifact_store.issue_ticket(
                    artifact["id"],
                    method="PUT",
                    ttl_seconds=300,
                    max_bytes=int(artifact["encrypted_size"]),
                ).to_dict(),
                request,
            )
            values.append(
                {
                    **raw,
                    "ticket": raw,
                    "artifact_id": artifact["id"],
                    "store_type": artifact_store.store_type,
                    "object_ref": artifact["id"],
                    "kind": artifact["kind"],
                    "expected_size": artifact["encrypted_size"],
                }
            )
        return values

    def lease_download_tickets(
        artifacts: list[dict[str, Any]], request: Request, *, ttl_seconds: int
    ) -> list[dict[str, Any]]:
        values: list[dict[str, Any]] = []
        for artifact in artifacts:
            if artifact["store_type"] != artifact_store.store_type or artifact["state"] not in (
                "uploaded",
                "available",
            ):
                continue
            raw = external_ticket(
                artifact_store.issue_ticket(
                    artifact["id"],
                    method="GET",
                    ttl_seconds=ttl_seconds,
                    max_bytes=int(artifact.get("encrypted_size") or 0),
                ).to_dict(),
                request,
            )
            raw["expected_size"] = int(artifact.get("encrypted_size") or 0)
            content_digest = artifact.get("content_digest")
            if isinstance(content_digest, str) and content_digest.startswith("sha256:"):
                raw["expected_sha256"] = content_digest.removeprefix("sha256:")
            values.append(
                {
                    **raw,
                    "ticket": raw,
                    "artifact_id": artifact["id"],
                    "name": artifact["kind"],
                    "store_type": artifact_store.store_type,
                    "object_ref": artifact["id"],
                }
            )
        return values

    def maintenance_artifact_ticket(
        job: dict[str, Any],
        request: Request,
        *,
        method: str,
    ) -> dict[str, Any]:
        artifact = job.get("artifact")
        if not isinstance(artifact, dict):
            raise VGenError(ErrorCode.ARTIFACT_NOT_FOUND)
        remaining = max(1, math.ceil(float(job["expires_at"]) - time.time()))
        ttl_seconds = min(3600, remaining)
        raw = external_ticket(
            artifact_store.issue_ticket(
                str(artifact["id"]),
                method=method,
                ttl_seconds=ttl_seconds,
                max_bytes=int(artifact["expected_size"]),
            ).to_dict(),
            request,
        )
        raw["expected_size"] = int(artifact["expected_size"])
        raw["expected_sha256"] = str(artifact["expected_sha256"])
        return raw

    def maintenance_create_view(job: dict[str, Any], request: Request) -> dict[str, Any]:
        value = dict(job)
        if value.get("kind") == "worker_update" and value.get("state") == "awaiting_upload":
            value["upload_ticket"] = maintenance_artifact_ticket(value, request, method="PUT")
        return value

    def maintenance_claim_view(job: dict[str, Any], request: Request) -> dict[str, Any]:
        value = dict(job)
        if value.get("kind") == "worker_update":
            value["artifact_download_ticket"] = maintenance_artifact_ticket(
                value, request, method="GET"
            )
        return value

    def prepared_task_view(
        task_id: str, attempt_id: str, allocation_id: str
    ) -> dict[str, Any] | None:
        task_row = db.fetchone("SELECT * FROM tasks WHERE id=?", (task_id,))
        attempt = db.fetchone(
            "SELECT * FROM task_attempts WHERE id=? AND task_id=?", (attempt_id, task_id)
        )
        if task_row is None or attempt is None:
            return None
        worker = db.fetchone("SELECT * FROM workers WHERE id=?", (attempt["worker_id"],))
        allocation = db.fetchone(
            """SELECT a.id AS allocation_id,a.owner_consent_at AS allocation_owner_consent_at,
                      a.allocation_proof,a.approved_by_user_id AS allocation_approved_by
               FROM worker_allocations a
               WHERE a.id=? AND a.worker_id=? AND a.pool_id=?""",
            (allocation_id, attempt["worker_id"], task_row["pool_id"]),
        )
        if worker is None or allocation is None or not allocation["allocation_proof"]:
            return None
        owner = db.fetchone(
            "SELECT root_signing_public_key FROM users WHERE id=?", (worker["owner_user_id"],)
        )
        approver = db.fetchone(
            "SELECT root_signing_public_key FROM users WHERE id=?",
            (allocation["allocation_approved_by"],),
        )
        if owner is None or approver is None:
            return None
        try:
            proof = json.loads(allocation["allocation_proof"])
            rate_snapshot = json.loads(attempt["rate_snapshot"] or "{}")
        except json.JSONDecodeError:
            return None
        task = row_dict(task_row, json_columns={"public_requirements"})
        task["worker"] = {
            "id": worker["id"],
            "encryption_public_key": worker["encryption_public_key"],
            "signing_public_key": worker["signing_public_key"],
            "certificate": worker["certificate"],
            "owner_root_signing_public_key": owner["root_signing_public_key"],
            "executor_type": worker["executor_type"],
            "executor_version": worker["executor_version"],
        }
        task["allocation"] = {
            "id": allocation["allocation_id"],
            "owner_consent_at": allocation["allocation_owner_consent_at"],
            "proof": proof,
            "admin_user_id": allocation["allocation_approved_by"],
            "admin_root_signing_public_key": approver["root_signing_public_key"],
        }
        task["rate_card_id"] = rate_snapshot.get("rate_card_id")
        task["attempt_id"] = attempt_id
        task["content_attempt_id"] = attempt_id
        task["key_version"] = int(task_row["content_key_version"])
        task["fencing_token"] = int(attempt["fencing_token"])
        return task

    def leased_attempt_view(
        attempt_id: str, lease_id: str, worker_id: str, fencing_token: int
    ) -> tuple[dict[str, Any], float] | None:
        row = db.fetchone(
            """SELECT l.*,a.task_id,a.state AS attempt_state,t.*
               FROM leases l JOIN task_attempts a ON a.id=l.attempt_id
               JOIN tasks t ON t.id=a.task_id
               WHERE l.id=? AND l.attempt_id=? AND l.worker_id=?
                 AND l.fencing_token=? AND l.released_at IS NULL AND l.expires_at>?""",
            (lease_id, attempt_id, worker_id, fencing_token, time.time()),
        )
        if row is None or row["attempt_state"] not in ("leased", "running"):
            return None
        key = db.fetchone(
            """SELECT envelope,key_version FROM key_envelopes
               WHERE task_id=? AND recipient_type='worker' AND recipient_id=?
                 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1""",
            (row["task_id"], worker_id),
        )
        content_attempt = db.fetchone(
            "SELECT id FROM task_attempts WHERE task_id=? ORDER BY attempt_number LIMIT 1",
            (row["task_id"],),
        )
        if key is None or content_attempt is None:
            return None
        requirements = json.loads(row["public_requirements"] or "{}")
        value = {
            "lease_id": lease_id,
            "attempt_id": attempt_id,
            "content_attempt_id": content_attempt["id"],
            "task_id": row["task_id"],
            "fencing_token": fencing_token,
            "expires_at": float(row["expires_at"]),
            "workspace_id": row["workspace_id"],
            "executor_type": row["executor_type"],
            "payload_format": requirements.get("payload_format", "opaque/v1"),
            "operation": requirements.get("operation", "unknown"),
            "key_version": int(key["key_version"]),
            "workflow_ref": row["workflow_ref"],
            "workflow_digest": row["workflow_digest"],
            "encrypted_payload": row["encrypted_payload"],
            "encrypted_tdk_envelope": key["envelope"],
        }
        return value, float(row["expires_at"])

    def replay_capability_free_response(
        *,
        mode: str,
        cached_body: bytes,
        cached_status: int,
        request: Request,
        session: sqlite3.Row,
    ) -> Response:
        """Materialize fresh capabilities for a previously completed mutation."""

        if cached_status == 204 or mode == "plain":
            return Response(content=cached_body, status_code=cached_status)
        try:
            value = json.loads(cached_body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _error_response(ErrorCode.INTERNAL_ERROR, request)
        if not isinstance(value, dict):
            return _error_response(ErrorCode.INTERNAL_ERROR, request)
        if mode == "task_prepare" and 200 <= cached_status < 300:
            recipe = value.get("_vgen_replay", {})
            task_id = str(recipe.get("task_id", ""))
            attempt_id = str(recipe.get("attempt_id", ""))
            allocation_id = str(recipe.get("allocation_id", ""))
            repository.sweep_expired()
            task = db.fetchone(
                "SELECT state,reservation_expires_at FROM tasks WHERE id=?", (task_id,)
            )
            if task is None:
                return _error_response(ErrorCode.TASK_STATE_CONFLICT, request, task_id=task_id)
            if (
                task["state"] == "expired"
                or float(task["reservation_expires_at"] or 0) <= time.time()
            ):
                return _error_response(ErrorCode.RESERVATION_EXPIRED, request, task_id=task_id)
            if task["state"] != "prepared":
                return _error_response(ErrorCode.TASK_STATE_CONFLICT, request, task_id=task_id)
            value = prepared_task_view(task_id, attempt_id, allocation_id)
            if value is None:
                return _error_response(ErrorCode.INTERNAL_ERROR, request, task_id=task_id)
            value["artifact_tickets"] = input_upload_tickets(task_id, request)
        elif mode == "worker_lease" and 200 <= cached_status < 300:
            recipe = value.get("_vgen_replay", {})
            attempt_id = str(recipe.get("attempt_id", ""))
            worker_id = str(session["principal_id"])
            if session["principal_type"] != "worker" or worker_id != session["principal_id"]:
                return _error_response(ErrorCode.PERMISSION_DENIED, request, attempt_id=attempt_id)
            lease_id = str(recipe.get("lease_id", ""))
            fencing_token = int(recipe.get("fencing_token", -1))
            leased = leased_attempt_view(attempt_id, lease_id, worker_id, fencing_token)
            if leased is None:
                return _error_response(ErrorCode.LEASE_LOST, request, attempt_id=attempt_id)
            value, lease_expires_at = leased
            ttl_seconds = max(1, min(3600, math.ceil(lease_expires_at - time.time())))
            artifacts = [
                row_dict(row, json_columns={"media_metadata"})
                for row in db.fetchall(
                    "SELECT * FROM artifacts WHERE task_id=? AND direction='input' ORDER BY created_at",
                    (value["task_id"],),
                )
            ]
            value["artifacts"] = artifacts
            value["artifact_download_tickets"] = lease_download_tickets(
                artifacts, request, ttl_seconds=ttl_seconds
            )
            outputs = [
                row_dict(row, json_columns={"media_metadata"})
                for row in db.fetchall(
                    """SELECT * FROM artifacts
                       WHERE attempt_id=? AND direction='output' AND state='pending'
                       ORDER BY created_at""",
                    (attempt_id,),
                )
            ]
            value["output_upload_tickets"] = output_tickets(
                outputs, request, ttl_seconds=ttl_seconds
            )
        elif mode == "maintenance_create" and 200 <= cached_status < 300:
            recipe = value.get("_vgen_replay", {})
            job_id = str(recipe.get("job_id", ""))
            if session["principal_type"] != "device" or not session["user_id"]:
                return _error_response(ErrorCode.PERMISSION_DENIED, request)
            issued = db.fetchone(
                """SELECT id FROM worker_maintenance_jobs
                   WHERE id=? AND issued_by_user_id=? AND issued_by_device_id=?""",
                (job_id, session["user_id"], session["principal_id"]),
            )
            if issued is None:
                return _error_response(ErrorCode.PERMISSION_DENIED, request)
            try:
                job = repository.get_worker_maintenance(
                    job_id=job_id, owner_user_id=session["user_id"]
                )
            except RepositoryError:
                return _error_response(ErrorCode.WORKER_MAINTENANCE_JOB_NOT_FOUND, request)
            value = maintenance_create_view(job, request)
        elif mode == "maintenance_claim" and 200 <= cached_status < 300:
            recipe = value.get("_vgen_replay", {})
            job_id = str(recipe.get("job_id", ""))
            fencing_token = int(recipe.get("fencing_token", -1))
            if session["principal_type"] != "worker":
                return _error_response(ErrorCode.PERMISSION_DENIED, request)
            job = repository.active_worker_maintenance_lease(
                job_id=job_id,
                worker_id=session["principal_id"],
                session_id=session["id"],
                fencing_token=fencing_token,
            )
            if job is None:
                return _error_response(ErrorCode.LEASE_LOST, request)
            value = maintenance_claim_view(job, request)
        return JSONResponse(value, status_code=cached_status)

    # Upgrade-time hygiene: old alpha builds persisted complete prepare/lease
    # responses. Scrub them before serving a request, and delete every response
    # from a route that is now explicitly non-cacheable.
    for stale in db.fetchall("SELECT rowid,* FROM idempotency_records"):
        stale_mode = idempotency_cache_mode(stale["path"])
        safe_body = (
            None
            if stale_mode == "disabled"
            else _idempotency_storage_body(
                stale_mode, int(stale["response_status"]), bytes(stale["response_body"])
            )
        )
        if safe_body is None:
            db.execute("DELETE FROM idempotency_records WHERE rowid=?", (stale["rowid"],))
        else:
            try:
                stale_headers = json.loads(stale["response_headers"])
            except json.JSONDecodeError:
                stale_headers = {}
            db.execute(
                "UPDATE idempotency_records SET response_headers=?,response_body=? WHERE rowid=?",
                (
                    json.dumps(_safe_idempotency_headers(stale_headers), separators=(",", ":")),
                    safe_body,
                    stale["rowid"],
                ),
            )

    async def verify_mutation_signature(
        request: Request, session: sqlite3.Row, *, body: bytes | None = None
    ) -> None:
        if not verify_mutations or request.method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
            return
        if session["principal_type"] == "device":
            key_row = db.fetchone(
                "SELECT signing_public_key FROM devices WHERE id=? AND status='active'",
                (session["principal_id"],),
            )
        elif session["principal_type"] == "worker":
            key_row = db.fetchone(
                "SELECT signing_public_key FROM workers WHERE id=? AND status!='revoked'",
                (session["principal_id"],),
            )
        elif session["principal_type"] == "service":
            key_row = db.fetchone(
                "SELECT signing_public_key FROM services WHERE id=? AND status='active'",
                (session["principal_id"],),
            )
        else:
            key_row = None
        if key_row is None:
            raise VGenError(ErrorCode.SIGNATURE_INVALID, request_id=_request_id(request))
        public_key = b64url_decode(key_row["signing_public_key"], expected_length=32)
        # Worker signing keys intentionally share the constrained DeviceKeys
        # key-id derivation until a separate service-key profile is introduced.
        key_digest = hashlib.sha256(b"vgen-device-key-id-v1\x00" + public_key).digest()
        expected_key_id = "devkey_" + b64url_encode(key_digest[:20])
        raw_path = request.url.path
        if request.url.query:
            raw_path += "?" + request.url.query
        verify_http_request(
            public_key,
            method=request.method,
            path=raw_path,
            body=await request.body() if body is None else body,
            headers=request.headers,
            expected_key_id=expected_key_id,
            nonce_is_fresh=lambda nonce, created: db.claim_request_nonce(
                principal_type=session["principal_type"],
                principal_id=session["principal_id"],
                nonce=nonce,
                signature_created_at=created,
            ),
        )

    @app.middleware("http")
    async def request_controls(request: Request, call_next):
        request.state.request_id = protocol_new_id("request")
        method = request.method.upper()
        rate_category = _public_rate_limit_category(request.url.path)
        request_body_limit = (
            min(control_body_limit, _PUBLIC_AUTH_MAX_BODY_BYTES)
            if rate_category is not None
            else control_body_limit
        )
        is_control_mutation = (
            method in {"POST", "PUT", "PATCH", "DELETE"}
            and request.url.path.startswith("/api/v1/")
            and not request.url.path.startswith("/api/v1/artifacts/transfer/")
        )
        if is_control_mutation:
            try:
                declared_length = _declared_content_length(request)
            except ValueError:
                return _error_response(
                    ErrorCode.VALIDATION_FAILED,
                    request,
                    details={"reason": "invalid_content_length"},
                    status_code=400,
                )
            if declared_length is not None and declared_length > request_body_limit:
                return _error_response(
                    ErrorCode.REQUEST_BODY_TOO_LARGE,
                    request,
                    details={"max_bytes": request_body_limit},
                )
        protocol_exempt = (
            request.url.path in {
                "/healthz",
                "/api/v1/health",
                "/docs",
                "/openapi.json",
            }
            or request.url.path.startswith("/docs/")
            or request.url.path.startswith("/api/v1/artifacts/transfer/")
            or request.url.path.startswith("/api/v1/releases/")
        )
        if (
            request.url.path.startswith("/api/v1/")
            and not protocol_exempt
            and request.headers.get("Vgen-Protocol-Version") != "1"
        ):
            return _error_response(
                ErrorCode.PROTOCOL_VERSION_UNSUPPORTED,
                request,
                # Do not reflect an arbitrary request-header value. Error
                # details are public metadata and may be captured by clients
                # or observability systems.
                details={"supported": ["1"]},
            )
        if method == "POST" and rate_category is not None:
            client_id = request.client.host if request.client is not None else "unknown"
            capacity, refill_per_second = _PUBLIC_RATE_LIMITS[rate_category]
            allowed, retry_after = rate_limiter.check(
                rate_category,
                client_id,
                capacity=capacity,
                refill_per_second=refill_per_second,
            )
            if not allowed:
                retry_seconds = max(1, math.ceil(retry_after))
                return _error_response(
                    ErrorCode.RATE_LIMITED,
                    request,
                    details={"category": rate_category},
                    retry_after_ms=retry_seconds * 1000,
                    headers={
                        "Retry-After": str(retry_seconds),
                        "Cache-Control": "no-store",
                    },
                )
        if is_control_mutation and rate_category is None:
            # Protected routes reject a missing/expired bearer before reading
            # as much as the 16 MiB legal key-rotation body. Public enrollment
            # routes are separately capped at 64 KiB and rate limited above.
            authorization = request.headers.get("Authorization", "")
            if not authorization.lower().startswith("bearer "):
                return _error_response(ErrorCode.AUTHENTICATION_REQUIRED, request)
            pre_authenticated_session = db.resolve_session(authorization[7:].strip())
            if pre_authenticated_session is None:
                return _error_response(ErrorCode.SESSION_EXPIRED, request)
            try:
                validate_session_subject(pre_authenticated_session)
            except VGenError as exc:
                return _error_response(
                    exc.code,
                    request,
                    details=exc.details,
                    retry_after_ms=exc.retry_after_ms,
                )
            request.state.pre_authenticated_session = pre_authenticated_session
        if is_control_mutation and not await _cache_bounded_body(
            request, max_bytes=request_body_limit
        ):
            return _error_response(
                ErrorCode.REQUEST_BODY_TOO_LARGE,
                request,
                details={"max_bytes": request_body_limit},
            )
        idempotency_key = request.headers.get("Idempotency-Key")
        cache_mode = idempotency_cache_mode(request.url.path)
        safe_to_cache = cache_mode != "disabled"
        record = None
        request_hash = ""
        principal_key = "anonymous"
        if idempotency_key and method in {"POST", "PUT", "PATCH", "DELETE"} and safe_to_cache:
            body = await request.body()
            request_hash = hashlib.sha256(body).hexdigest()
            auth = request.headers.get("Authorization", "")
            principal_key = hashlib.sha256(auth.encode()).hexdigest() if auth else "anonymous"
            record = db.get_idempotency(principal_key, method, request.url.path, idempotency_key)
            if record:
                if not secrets.compare_digest(record["request_hash"], request_hash):
                    return _error_response(
                        ErrorCode.IDEMPOTENCY_CONFLICT,
                        request,
                        details={"path": request.url.path},
                    )
                authorization = request.headers.get("Authorization", "")
                if not authorization.lower().startswith("bearer "):
                    return _error_response(ErrorCode.AUTHENTICATION_REQUIRED, request)
                session = getattr(request.state, "pre_authenticated_session", None)
                if session is None:
                    session = db.resolve_session(authorization[7:].strip())
                if session is None:
                    return _error_response(ErrorCode.SESSION_EXPIRED, request)
                try:
                    validate_session_subject(session)
                    await verify_mutation_signature(request, session, body=body)
                except VGenError as exc:
                    return JSONResponse(
                        exc.to_envelope()
                        if exc.request_id
                        else error_envelope(
                            exc.code,
                            request_id=_request_id(request),
                            details=exc.details,
                            origin=exc.origin,
                        ),
                        status_code=exc.http_status,
                        headers={"X-Request-ID": _request_id(request)},
                    )
                replayed = replay_capability_free_response(
                    mode=cache_mode,
                    cached_body=bytes(record["response_body"]),
                    cached_status=int(record["response_status"]),
                    request=request,
                    session=session,
                )
                headers = {
                    **dict(replayed.headers),
                    **json.loads(record["response_headers"]),
                }
                headers["X-Request-ID"] = _request_id(request)
                headers["Idempotency-Replayed"] = "true"
                return Response(
                    content=replayed.body,
                    status_code=replayed.status_code,
                    headers=headers,
                )
        response = await call_next(request)
        response.headers["X-Request-ID"] = _request_id(request)
        if cache_mode == "disabled":
            response.headers["Cache-Control"] = "no-store"
        if (
            idempotency_key
            and method in {"POST", "PUT", "PATCH", "DELETE"}
            and safe_to_cache
            # Persist only successful mutations and deterministic conflicts.
            # Validation/not-found responses can contain attacker-controlled
            # route or schema locations and are safe to recompute on retry.
            and (200 <= response.status_code < 300 or response.status_code == 409)
        ):
            body = b"".join([chunk async for chunk in response.body_iterator])
            response_headers = {
                key: value
                for key, value in response.headers.items()
                if key.lower() not in {"content-length", "transfer-encoding"}
            }
            storage_body = _idempotency_storage_body(cache_mode, response.status_code, body)
            if storage_body is not None:
                db.put_idempotency(
                    principal_key,
                    method,
                    request.url.path,
                    idempotency_key,
                    request_hash,
                    response.status_code,
                    _safe_idempotency_headers(response_headers),
                    storage_body,
                )
            response_headers["X-Request-ID"] = _request_id(request)
            return Response(
                content=body, status_code=response.status_code, headers=response_headers
            )
        return response

    @app.exception_handler(VGenError)
    async def typed_error(request: Request, exc: VGenError) -> JSONResponse:
        envelope = error_envelope(
            exc.code,
            request_id=exc.request_id or _request_id(request),
            task_id=exc.task_id,
            attempt_id=exc.attempt_id,
            details=exc.details,
            retry_after_ms=exc.retry_after_ms,
            origin=exc.origin,
        )
        return JSONResponse(
            envelope, status_code=exc.http_status, headers={"X-Request-ID": _request_id(request)}
        )

    @app.exception_handler(RepositoryError)
    async def repository_error(request: Request, exc: RepositoryError) -> JSONResponse:
        try:
            code = ErrorCode(exc.code)
        except ValueError:
            code = ErrorCode.VALIDATION_FAILED
        details = dict(exc.details or {})
        if exc.name != code.name:
            details["reason"] = exc.name
        return _error_response(
            code,
            request,
            details=details,
            status_code=exc.http_status if code is ErrorCode.VALIDATION_FAILED else None,
        )

    @app.exception_handler(RequestValidationError)
    async def request_validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Pydantic locations can contain arbitrary extra-field names supplied
        # by the caller. Return only a bounded count so error envelopes never
        # become a plaintext reflection or persistence channel.
        return _error_response(
            ErrorCode.VALIDATION_FAILED,
            request,
            details={"reason": "request_validation_failed", "error_count": len(exc.errors()[:20])},
        )

    @app.exception_handler(sqlite3.IntegrityError)
    async def sqlite_integrity(request: Request, exc: sqlite3.IntegrityError) -> JSONResponse:
        logger.info("rejected conflicting write request_id=%s", _request_id(request))
        return _error_response(
            ErrorCode.VALIDATION_FAILED,
            request,
            details={"reason": "resource_conflict"},
            status_code=409,
        )

    @app.exception_handler(Exception)
    async def internal_error(request: Request, exc: Exception) -> JSONResponse:
        # Exception messages and tracebacks can embed request bodies, upstream
        # responses, signed URLs, or decrypted values. Keep the production log
        # record diagnostic but content-free at this trust boundary.
        logger.error(
            "gateway request failed request_id=%s error_type=%s",
            _request_id(request),
            type(exc).__name__,
        )
        return _error_response(ErrorCode.INTERNAL_ERROR, request)

    async def current_principal(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> Principal:
        if credentials is None:
            raise VGenError(ErrorCode.AUTHENTICATION_REQUIRED, request_id=_request_id(request))
        row = getattr(request.state, "pre_authenticated_session", None)
        if row is None:
            row = db.resolve_session(credentials.credentials)
        if row is None:
            raise VGenError(ErrorCode.SESSION_EXPIRED, request_id=_request_id(request))
        validate_session_subject(row)
        scopes = frozenset(json.loads(row["scopes"]))
        await verify_mutation_signature(request, row)
        return Principal(
            row["principal_type"], row["principal_id"], row["user_id"], scopes, row["id"]
        )

    def user_principal(principal: Principal = Depends(current_principal)) -> Principal:
        if principal.principal_type != "device" or not principal.user_id:
            raise VGenError(ErrorCode.PERMISSION_DENIED)
        return principal

    def operator_principal(principal: Principal = Depends(user_principal)) -> Principal:
        row = db.fetchone(
            "SELECT is_operator FROM users WHERE id=? AND status='active'",
            (principal.user_id,),
        )
        if row is None or int(row["is_operator"]) != 1:
            raise VGenError(ErrorCode.PERMISSION_DENIED)
        return principal

    def task_principal(principal: Principal = Depends(current_principal)) -> Principal:
        if principal.principal_type not in {"device", "service"}:
            raise VGenError(ErrorCode.PERMISSION_DENIED)
        return principal

    def require_scope(principal: Principal, scope: str) -> None:
        if "*" not in principal.scopes and scope not in principal.scopes:
            raise VGenError(ErrorCode.SCOPE_REQUIRED, details={"required_scope": scope})

    # --------------------------------------------------------------- health/auth

    def validate_device_chain(
        *,
        device_id: str,
        certificate: dict[str, Any],
        root_signing_public_key: str,
        device_signing_public_key: str,
        device_encryption_public_key: str,
    ) -> None:
        try:
            root_key = b64url_decode(root_signing_public_key, expected_length=32)
            valid = verify_device_certificate(certificate, root_key)
            cert_payload = certificate["payload"]
            fields_match = (
                cert_payload["device_id"] == device_id
                and cert_payload["signing_public_key"] == device_signing_public_key
                and cert_payload["encryption_public_key"] == device_encryption_public_key
            )
        except (KeyError, TypeError, ValueError):
            valid = False
            fields_match = False
        if not validate_id(device_id, "device") or not valid or not fields_match:
            raise VGenError(ErrorCode.DEVICE_CERTIFICATE_INVALID)

    def validate_session_subject(session: sqlite3.Row) -> None:
        """Revalidate the persisted principal certificate on every session use.

        A caller cannot extend a device certificate by omitting it from a
        challenge request. Worker owner certificates are checked when the
        Worker is registered and Worker revocation is enforced by session
        resolution plus the Worker status lookup in request signing.
        """

        if session["principal_type"] == "service":
            service = db.fetchone(
                "SELECT id FROM services WHERE id=? AND status='active'",
                (session["principal_id"],),
            )
            if service is None:
                raise VGenError(ErrorCode.SESSION_EXPIRED)
            return
        if session["principal_type"] == "worker":
            worker = db.fetchone(
                "SELECT id FROM workers WHERE id=? AND status!='revoked'",
                (session["principal_id"],),
            )
            if worker is None:
                raise VGenError(ErrorCode.SESSION_EXPIRED)
            return
        device = db.fetchone(
            "SELECT * FROM devices WHERE id=? AND status='active'",
            (session["principal_id"],),
        )
        if device is None or not device["certificate"]:
            raise VGenError(ErrorCode.DEVICE_CERTIFICATE_INVALID)
        user = db.fetchone(
            "SELECT * FROM users WHERE id=? AND status='active'", (device["user_id"],)
        )
        if user is None:
            raise VGenError(ErrorCode.DEVICE_CERTIFICATE_INVALID)
        try:
            certificate = json.loads(device["certificate"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise VGenError(ErrorCode.DEVICE_CERTIFICATE_INVALID) from exc
        validate_device_chain(
            device_id=device["id"],
            certificate=certificate,
            root_signing_public_key=user["root_signing_public_key"],
            device_signing_public_key=device["signing_public_key"],
            device_encryption_public_key=device["encryption_public_key"],
        )

    def validate_worker_owner_certificate(
        *, owner_user_id: str, payload: WorkerCreate
    ) -> dict[str, Any]:
        user = db.fetchone(
            "SELECT root_signing_public_key FROM users WHERE id=? AND status='active'",
            (owner_user_id,),
        )
        if user is None:
            raise VGenError(ErrorCode.PERMISSION_DENIED)
        try:
            signed = json.loads(payload.certificate)
            manifest = signed["manifest"]
            root_public = b64url_decode(user["root_signing_public_key"], expected_length=32)
            worker_signing = b64url_decode(payload.signing_public_key, expected_length=32)
            b64url_decode(payload.encryption_public_key, expected_length=32)
            expected_worker_key_id = "devkey_" + b64url_encode(
                hashlib.sha256(b"vgen-device-key-id-v1\x00" + worker_signing).digest()[:20]
            )
            issued_at = manifest["issued_at"]
            valid = (
                isinstance(issued_at, int)
                and not isinstance(issued_at, bool)
                and issued_at <= int(time.time()) + 300
                and verify_key_manifest(signed, root_public)
                and manifest.get("version") == 1
                and manifest.get("kind") == "vgen-worker-owner-certificate"
                and manifest.get("owner_root_key_id") == signed.get("signer_key_id")
                and manifest.get("worker_key_id") == expected_worker_key_id
                and manifest.get("worker_signing_public_key") == payload.signing_public_key
                and manifest.get("worker_encryption_public_key") == payload.encryption_public_key
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            valid = False
        if not valid:
            raise VGenError(
                ErrorCode.DEVICE_CERTIFICATE_INVALID,
                details={"reason": "worker_owner_certificate_invalid"},
            )
        return signed

    def validate_maintenance_authorization(
        *,
        broker_id: str,
        worker_id: str,
        payload: WorkerMaintenanceCreate,
        principal: Principal,
    ) -> tuple[dict[str, Any], dict[str, Any], int, str]:
        if principal.principal_type != "device" or not principal.user_id:
            raise VGenError(ErrorCode.PERMISSION_DENIED)
        spec = payload.spec.model_dump(mode="json")
        authorization = payload.authorization.model_dump(mode="json")
        intent_payload = authorization["payload"]
        if (
            intent_payload["worker_id"] != worker_id
            or intent_payload["broker_id"] != broker_id
            or intent_payload["device_id"] != principal.principal_id
            or intent_payload["action"] != payload.spec.kind
        ):
            raise VGenError(
                ErrorCode.SIGNATURE_INVALID,
                details={"reason": "maintenance_intent_subject_mismatch"},
            )
        device = db.fetchone(
            """SELECT d.certificate,u.root_signing_public_key
               FROM devices d JOIN users u ON u.id=d.user_id
               WHERE d.id=? AND d.user_id=? AND d.status='active' AND u.status='active'""",
            (principal.principal_id, principal.user_id),
        )
        if device is None or not device["certificate"]:
            raise VGenError(ErrorCode.DEVICE_CERTIFICATE_INVALID)
        try:
            stored_certificate = json.loads(device["certificate"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise VGenError(ErrorCode.DEVICE_CERTIFICATE_INVALID) from exc
        if canonical_json(stored_certificate) != canonical_json(
            authorization["device_certificate"]
        ):
            raise VGenError(
                ErrorCode.SIGNATURE_INVALID,
                details={"reason": "maintenance_device_certificate_mismatch"},
            )
        if not verify_maintenance_intent(
            authorization,
            str(device["root_signing_public_key"]),
            expected_worker_id=worker_id,
            expected_broker_id=broker_id,
            expected_kind=payload.spec.kind,
            expected_spec=spec,
        ):
            raise VGenError(
                ErrorCode.SIGNATURE_INVALID,
                details={"reason": "maintenance_intent_invalid"},
            )
        expires_at = int(intent_payload["expires_at"])
        ttl_seconds = max(1, expires_at - int(time.time()))
        if not db.claim_request_nonce(
            principal_type="maintenance_intent",
            principal_id=principal.principal_id,
            nonce=str(intent_payload["nonce"]),
            signature_created_at=int(intent_payload["issued_at"]),
            ttl_seconds=ttl_seconds,
        ):
            raise VGenError(ErrorCode.REPLAY_DETECTED)
        return spec, authorization, expires_at, str(intent_payload["spec_digest"])

    @app.get("/healthz", tags=["system"], response_model=HealthResponse)
    def health() -> dict[str, bool]:
        return {"ok": True}

    # Compatibility-only alias for pre-0.9.0 Windows installers. Keep it out
    # of the current API contract and never restore the former database/status
    # payload here; operational details belong to authenticated /api/v1/status.
    @app.get(
        "/api/v1/health",
        response_model=HealthResponse,
        include_in_schema=False,
    )
    def legacy_health() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/api/v1/status", tags=["system"], response_model=StatusResponse)
    def status(principal: Principal = Depends(operator_principal)) -> dict[str, Any]:
        return db.health()

    def public_release_manifest(
        request: Request,
        response: Response,
        *,
        channel: str | None = None,
        version: str | None = None,
    ) -> dict[str, Any]:
        try:
            manifest = (
                release_catalog.channel(channel)
                if channel is not None
                else release_catalog.version(version or "")
            )
        except ReleaseNotFound as exc:
            raise VGenError(
                ErrorCode.ARTIFACT_NOT_FOUND,
                request_id=_request_id(request),
            ) from exc
        except ReleaseManifestInvalid as exc:
            # A malformed operator-published manifest is a deployment fault.
            # Do not reflect its contents or parser error into a public response.
            logger.error(
                "gateway public release manifest rejected request_id=%s",
                _request_id(request),
            )
            raise VGenError(
                ErrorCode.INTERNAL_ERROR,
                request_id=_request_id(request),
            ) from exc
        response.headers["ETag"] = f'"sha256-{manifest["manifest_sha256"]}"'
        response.headers["Cache-Control"] = (
            "public, max-age=0, must-revalidate"
            if channel is not None
            else "public, max-age=31536000, immutable"
        )
        return manifest

    @app.get(
        "/api/v1/releases/channels/{channel}",
        tags=["release"],
        response_model=PublicReleaseManifest,
    )
    def release_channel_manifest(
        channel: str,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        return public_release_manifest(request, response, channel=channel)

    @app.get(
        "/api/v1/releases/versions/{version}",
        tags=["release"],
        response_model=PublicReleaseManifest,
        response_model_exclude_none=True,
    )
    def release_version_manifest(
        version: str,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        return public_release_manifest(request, response, version=version)

    @app.get(
        "/releases/{version}/{filename}",
        include_in_schema=False,
    )
    def release_file(version: str, filename: str, request: Request) -> Response:
        try:
            artifact = release_catalog.file(version, filename)
        except ReleaseNotFound as exc:
            raise VGenError(
                ErrorCode.ARTIFACT_NOT_FOUND,
                request_id=_request_id(request),
            ) from exc
        except ReleaseManifestInvalid as exc:
            logger.error(
                "gateway public release artifact rejected request_id=%s",
                _request_id(request),
            )
            raise VGenError(
                ErrorCode.ARTIFACT_INTEGRITY_FAILED,
                request_id=_request_id(request),
            ) from exc
        return FileResponse(
            artifact.path,
            media_type=artifact.content_type,
            filename=artifact.filename,
            headers={
                "Cache-Control": "public, max-age=31536000, immutable",
                "ETag": f'"sha256-{artifact.sha256}"',
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.api_route(
        "/api/v1/artifacts/transfer/{artifact_id}",
        methods=["GET", "PUT"],
        tags=["artifact"],
        include_in_schema=False,
    )
    async def artifact_transfer(artifact_id: str, request: Request) -> Response:
        if not validate_id(artifact_id, "artifact"):
            raise VGenError(ErrorCode.ARTIFACT_NOT_FOUND)
        ticket = request.headers.get("Vgen-Artifact-Ticket", "")
        if not ticket:
            raise VGenError(ErrorCode.PERMISSION_DENIED)
        verified = artifact_store.verify_ticket(ticket, method=request.method)
        if not secrets.compare_digest(verified.artifact_id, artifact_id):
            raise VGenError(ErrorCode.PERMISSION_DENIED)
        if request.method == "PUT":
            try:
                declared_length = _declared_content_length(request)
            except ValueError as exc:
                raise VGenError(
                    ErrorCode.VALIDATION_FAILED,
                    request_id=_request_id(request),
                    details={"reason": "invalid_content_length"},
                ) from exc
            if declared_length is not None and declared_length > verified.max_bytes:
                raise VGenError(
                    ErrorCode.REQUEST_BODY_TOO_LARGE,
                    request_id=_request_id(request),
                    details={"max_bytes": verified.max_bytes},
                )
            if not db.claim_transfer_ticket(ticket, verified.artifact_id):
                raise VGenError(ErrorCode.REPLAY_DETECTED)
            size, digest = await artifact_store.put_chunks(
                verified.artifact_id,
                request.stream(),
                max_bytes=verified.max_bytes,
            )
            repository.mark_artifact_uploaded(
                artifact_id=verified.artifact_id,
                size=size,
                digest=digest,
            )
            return Response(status_code=204)
        handle = artifact_store.open(verified.artifact_id)
        return StreamingResponse(
            handle,
            media_type="application/octet-stream",
            headers={
                "Cache-Control": "private, no-store",
                "Content-Disposition": f'attachment; filename="{verified.artifact_id}.ciphertext"',
            },
        )

    @app.post("/api/v1/auth/bootstrap", tags=["auth"])
    def bootstrap(payload: BootstrapRequest, request: Request) -> dict[str, Any]:
        if not secrets.compare_digest(payload.bootstrap_code, app.state.bootstrap_code):
            raise VGenError(ErrorCode.AUTHENTICATION_REQUIRED, request_id=_request_id(request))
        cert_payload = payload.device_certificate.get("payload", {})
        device_signing_public_key = payload.device_signing_public_key or cert_payload.get(
            "signing_public_key", ""
        )
        device_encryption_public_key = payload.device_encryption_public_key or cert_payload.get(
            "encryption_public_key", ""
        )
        for value in (
            payload.root_signing_public_key,
            payload.root_encryption_public_key,
            device_signing_public_key,
            device_encryption_public_key,
        ):
            try:
                b64url_decode(value, expected_length=32)
            except ValueError as exc:
                raise VGenError(
                    ErrorCode.VALIDATION_FAILED, details={"reason": "invalid_public_key"}
                ) from exc
        validate_device_chain(
            device_id=payload.device_id,
            certificate=payload.device_certificate,
            root_signing_public_key=payload.root_signing_public_key,
            device_signing_public_key=device_signing_public_key,
            device_encryption_public_key=device_encryption_public_key,
        )
        try:
            registration = payload.model_dump(exclude={"bootstrap_code", "root_key_id"})
            registration["device_signing_public_key"] = device_signing_public_key
            registration["device_encryption_public_key"] = device_encryption_public_key
            user, device = db.bootstrap_operator(**registration)
        except ValueError as exc:
            raise VGenError(ErrorCode.PERMISSION_DENIED, details={"reason": str(exc)}) from exc
        token, session = db.create_session(
            principal_type="device",
            principal_id=device["id"],
            user_id=user["id"],
            scopes=["*"],
        )
        return {
            "user": row_dict(user),
            "device": row_dict(device),
            "session": {"id": session["id"], "token": token, "expires_at": session["expires_at"]},
            "session_token": token,
            "expires_at": session["expires_at"],
            "user_id": user["id"],
            "device_id": device["id"],
        }

    @app.post("/api/v1/auth/enroll", tags=["auth"])
    def enroll_user(payload: UserEnrollmentRequest) -> dict[str, Any]:
        claim = payload.claim.model_dump(mode="json")
        if claim.get("invite_id") != payload.invite_id or not verify_user_registration_claim(
            claim, payload.proof_signature
        ):
            raise VGenError(ErrorCode.SIGNATURE_INVALID)
        user, device, enrollment = repository.enroll_user(
            invite_id=payload.invite_id,
            secret=payload.secret,
            claim=claim,
            proof_signature=payload.proof_signature,
        )
        return {
            "user": user,
            "device": device,
            "enrollment": enrollment,
            "login_required": True,
        }

    @app.post("/api/v1/devices/enroll", tags=["auth"])
    def enroll_device(payload: DeviceEnrollmentRequest) -> dict[str, Any]:
        cert_payload = payload.device_certificate.get("payload", {})
        device_signing_public_key = payload.device_signing_public_key or str(
            cert_payload.get("signing_public_key", "")
        )
        device_encryption_public_key = payload.device_encryption_public_key or str(
            cert_payload.get("encryption_public_key", "")
        )
        validate_device_chain(
            device_id=payload.device_id,
            certificate=payload.device_certificate,
            root_signing_public_key=payload.root_signing_public_key,
            device_signing_public_key=device_signing_public_key,
            device_encryption_public_key=device_encryption_public_key,
        )
        # The root-signed DeviceCertificate establishes which User authorized
        # both Device keys.  A second signature binds possession of the new
        # Device signing key to this one-time invite.  The Device must still
        # complete the ordinary challenge exchange for every later session.
        try:
            proof_ok = verify_message(
                b64url_decode(device_signing_public_key, expected_length=32),
                canonical_json(
                    {
                        "version": 1,
                        "invite_id": payload.invite_id,
                        "device_id": payload.device_id,
                    }
                ),
                b64url_decode(payload.proof_signature, expected_length=64),
                context=b"vgen-device-enrollment-v1",
            )
        except ValueError as exc:
            raise VGenError(ErrorCode.SIGNATURE_INVALID) from exc
        if not proof_ok:
            raise VGenError(ErrorCode.SIGNATURE_INVALID)
        user, device, enrollment = repository.enroll_device(
            invite_id=payload.invite_id,
            secret=payload.secret,
            root_signing_public_key=payload.root_signing_public_key,
            root_encryption_public_key=payload.root_encryption_public_key,
            device_id=payload.device_id,
            device_name=payload.device_name,
            device_signing_public_key=device_signing_public_key,
            device_encryption_public_key=device_encryption_public_key,
            device_certificate=payload.device_certificate,
        )
        result = {
            "user_id": user["id"],
            "device_id": device["id"],
            "enrollment": enrollment,
        }
        if enrollment["state"] == "active":
            result["login_required"] = True
        else:
            result["approval_required"] = True
        return result

    @app.post("/api/v1/auth/device-recovery/challenges", tags=["auth"])
    def device_recovery_challenge(
        payload: DeviceRecoveryChallengeRequest,
    ) -> dict[str, Any]:
        if not validate_id(payload.device_id, "device"):
            raise VGenError(ErrorCode.VALIDATION_FAILED, details={"field": "device_id"})
        try:
            b64url_decode(payload.root_signing_public_key, expected_length=32)
        except ValueError as exc:
            raise VGenError(
                ErrorCode.VALIDATION_FAILED, details={"reason": "invalid_public_key"}
            ) from exc
        user = db.fetchone(
            """SELECT id FROM users
               WHERE root_signing_public_key=? AND status='active'""",
            (payload.root_signing_public_key,),
        )
        if user is None or db.fetchone("SELECT 1 FROM devices WHERE id=?", (payload.device_id,)):
            # Keep both unknown roots and reused device IDs indistinguishable.
            raise VGenError(ErrorCode.AUTHENTICATION_REQUIRED)
        challenge_id, challenge_value = db.create_device_recovery_challenge(
            user_id=user["id"], device_id=payload.device_id
        )
        return {
            "challenge_id": challenge_id,
            "challenge": challenge_value,
            "expires_in": 120,
        }

    @app.post("/api/v1/auth/device-recovery/complete", tags=["auth"])
    def complete_device_recovery(
        payload: DeviceRecoveryCompleteRequest,
    ) -> dict[str, Any]:
        user = db.fetchone(
            """SELECT * FROM users
               WHERE root_signing_public_key=? AND root_encryption_public_key=?
                 AND status='active'""",
            (payload.root_signing_public_key, payload.root_encryption_public_key),
        )
        if user is None:
            raise VGenError(ErrorCode.AUTHENTICATION_REQUIRED)
        challenge_row = db.get_device_recovery_challenge(
            challenge_id=payload.challenge_id,
            user_id=user["id"],
            device_id=payload.device_id,
        )
        if challenge_row is None:
            raise VGenError(ErrorCode.REPLAY_DETECTED)
        validate_device_chain(
            device_id=payload.device_id,
            certificate=payload.device_certificate,
            root_signing_public_key=payload.root_signing_public_key,
            device_signing_public_key=payload.device_signing_public_key,
            device_encryption_public_key=payload.device_encryption_public_key,
        )
        proof = canonical_json(
            {
                "version": 1,
                "challenge_id": payload.challenge_id,
                "challenge": challenge_row["challenge_value"],
                "device_id": payload.device_id,
                "device_name": payload.device_name,
                "device_signing_public_key": payload.device_signing_public_key,
                "device_encryption_public_key": payload.device_encryption_public_key,
                "root_signing_public_key": payload.root_signing_public_key,
                "root_encryption_public_key": payload.root_encryption_public_key,
            }
        )
        try:
            root_ok = verify_message(
                b64url_decode(payload.root_signing_public_key, expected_length=32),
                proof,
                b64url_decode(payload.root_signature, expected_length=64),
                context=b"vgen-device-recovery-root-v1",
            )
            device_ok = verify_message(
                b64url_decode(payload.device_signing_public_key, expected_length=32),
                proof,
                b64url_decode(payload.device_signature, expected_length=64),
                context=b"vgen-device-recovery-device-v1",
            )
        except ValueError as exc:
            raise VGenError(ErrorCode.SIGNATURE_INVALID) from exc
        if not root_ok or not device_ok:
            raise VGenError(ErrorCode.SIGNATURE_INVALID)
        device = repository.register_recovered_device(
            user_id=user["id"],
            challenge_id=payload.challenge_id,
            device_id=payload.device_id,
            device_name=payload.device_name,
            device_signing_public_key=payload.device_signing_public_key,
            device_encryption_public_key=payload.device_encryption_public_key,
            device_certificate=payload.device_certificate,
        )
        token, session = db.create_session(
            principal_type="device",
            principal_id=device["id"],
            user_id=user["id"],
            scopes=["*"],
        )
        return {
            "user_id": user["id"],
            "device_id": device["id"],
            "session_token": token,
            "expires_at": session["expires_at"],
        }

    @app.post("/api/v1/auth/services/enroll", tags=["auth"])
    def enroll_service(payload: ServiceEnrollmentRequest) -> dict[str, Any]:
        claim = {
            "version": 1,
            "invite_id": payload.invite_id,
            "name": payload.name,
            "signing_public_key": payload.signing_public_key,
            "encryption_public_key": payload.encryption_public_key,
        }
        try:
            b64url_decode(payload.encryption_public_key, expected_length=32)
            proof_ok = verify_message(
                b64url_decode(payload.signing_public_key, expected_length=32),
                canonical_json(claim),
                b64url_decode(payload.proof_signature, expected_length=64),
                context=b"vgen-service-enrollment-v1",
            )
        except ValueError as exc:
            raise VGenError(ErrorCode.SIGNATURE_INVALID) from exc
        if not proof_ok:
            raise VGenError(ErrorCode.SIGNATURE_INVALID)
        service, enrollment = repository.enroll_service(
            invite_id=payload.invite_id,
            secret=payload.secret,
            name=payload.name,
            signing_public_key=payload.signing_public_key,
            encryption_public_key=payload.encryption_public_key,
        )
        return {"service": service, "enrollment": enrollment}

    @app.post("/api/v1/auth/challenges", tags=["auth"])
    def challenge(payload: ChallengeRequest) -> dict[str, Any]:
        principal_id = {
            "device": payload.device_id,
            "service": payload.service_id,
            "worker": payload.worker_id,
        }[payload.principal_type]
        if not principal_id:
            raise VGenError(ErrorCode.VALIDATION_FAILED, details={"field": "principal_id"})
        if payload.principal_type == "device":
            subject = db.fetchone(
                "SELECT id FROM devices WHERE id=? AND status='active'", (principal_id,)
            )
        elif payload.principal_type == "worker":
            subject = db.fetchone(
                "SELECT id FROM workers WHERE id=? AND status!='revoked'", (principal_id,)
            )
        else:
            subject = db.fetchone(
                "SELECT id FROM services WHERE id=? AND status='active'", (principal_id,)
            )
        if subject is None:
            # Do not disclose whether an arbitrary device ID exists.
            raise VGenError(ErrorCode.AUTHENTICATION_REQUIRED)
        challenge_id, challenge_value = db.create_challenge(payload.principal_type, principal_id)
        return {
            "challenge_id": challenge_id,
            "challenge": challenge_value,
            "principal_type": payload.principal_type,
            "expires_in": 120,
        }

    @app.post("/api/v1/auth/sessions", tags=["auth"])
    def create_session(payload: SessionRequest) -> dict[str, Any]:
        principal_id = {
            "device": payload.device_id,
            "service": payload.service_id,
            "worker": payload.worker_id,
        }[payload.principal_type]
        if not principal_id:
            raise VGenError(ErrorCode.VALIDATION_FAILED, details={"field": "principal_id"})
        if payload.principal_type == "device":
            subject = db.fetchone(
                "SELECT * FROM devices WHERE id=? AND status='active'", (principal_id,)
            )
        elif payload.principal_type == "worker":
            subject = db.fetchone(
                "SELECT * FROM workers WHERE id=? AND status!='revoked'", (principal_id,)
            )
        else:
            subject = db.fetchone(
                "SELECT * FROM services WHERE id=? AND status='active'", (principal_id,)
            )
        if subject is None:
            raise VGenError(ErrorCode.AUTHENTICATION_REQUIRED)
        if payload.principal_type == "device":
            user = db.fetchone(
                "SELECT * FROM users WHERE id=? AND status='active'", (subject["user_id"],)
            )
            if user is None or (
                payload.root_signing_public_key
                and payload.root_signing_public_key != user["root_signing_public_key"]
            ):
                raise VGenError(ErrorCode.DEVICE_CERTIFICATE_INVALID)
            try:
                stored_certificate = json.loads(subject["certificate"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise VGenError(ErrorCode.DEVICE_CERTIFICATE_INVALID) from exc
            if payload.device_certificate is not None and canonical_json(
                payload.device_certificate
            ) != canonical_json(stored_certificate):
                raise VGenError(ErrorCode.DEVICE_CERTIFICATE_INVALID)
            validate_device_chain(
                device_id=subject["id"],
                certificate=stored_certificate,
                root_signing_public_key=user["root_signing_public_key"],
                device_signing_public_key=subject["signing_public_key"],
                device_encryption_public_key=subject["encryption_public_key"],
            )
        challenge_row = db.get_challenge(
            payload.challenge_id,
            payload.principal_type,
            principal_id,
        )
        if challenge_row is None:
            raise VGenError(ErrorCode.REPLAY_DETECTED)
        try:
            signature_ok = verify_message(
                b64url_decode(subject["signing_public_key"], expected_length=32),
                challenge_row["challenge_value"].encode(),
                b64url_decode(payload.signature, expected_length=64),
            )
        except ValueError as exc:
            raise VGenError(ErrorCode.SIGNATURE_INVALID) from exc
        if not signature_ok:
            raise VGenError(ErrorCode.SIGNATURE_INVALID)
        if not db.consume_challenge(payload.challenge_id, payload.principal_type, principal_id):
            raise VGenError(ErrorCode.REPLAY_DETECTED)
        if payload.principal_type == "device":
            scopes = ["*"]
            session_user_id = subject["user_id"]
        elif payload.principal_type == "worker":
            scopes = [
                "worker:lease",
                "worker:heartbeat",
                "worker:complete",
                "worker:maintenance:lease",
                "worker:maintenance:report",
            ]
            session_user_id = subject["owner_user_id"]
        else:
            scopes = json.loads(subject["scopes"] or "[]")
            session_user_id = None
        token, session = db.create_session(
            principal_type=payload.principal_type,
            principal_id=subject["id"],
            user_id=session_user_id,
            scopes=scopes,
        )
        return {
            "id": session["id"],
            "token": token,
            "session_token": token,
            "expires_at": session["expires_at"],
            "user_id": session_user_id,
            "device_id": subject["id"] if payload.principal_type == "device" else None,
            "worker_id": subject["id"] if payload.principal_type == "worker" else None,
            "service_id": subject["id"] if payload.principal_type == "service" else None,
            "principal_type": payload.principal_type,
        }

    @app.post("/api/v1/devices/{device_id}/revoke", tags=["auth"])
    def revoke_device(
        device_id: str, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        return repository.revoke_device(device_id=device_id, user_id=principal.user_id)

    # ------------------------------------------------------- workspace and broker

    @app.post("/api/v1/workspaces", tags=["workspace"])
    def create_workspace(
        payload: WorkspaceCreate, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        return repository.create_workspace(user_id=principal.user_id, **payload.model_dump())

    @app.get("/api/v1/workspaces", tags=["workspace"])
    def list_workspaces(principal: Principal = Depends(user_principal)) -> list[dict[str, Any]]:
        return repository.list_workspaces(principal.user_id)

    @app.get("/api/v1/workspaces/{workspace_id}/members", tags=["workspace"])
    def list_workspace_members(
        workspace_id: str,
        include_revoked: bool = False,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        return repository.list_workspace_members(
            workspace_id=workspace_id,
            user_id=principal.user_id,
            include_revoked=include_revoked,
        )

    def validate_workspace_key_grant(
        *,
        workspace_id: str,
        payload: WorkspaceKeyEnvelopeGrant,
        principal: Principal,
        rotation_id: str | None = None,
        recipient_set_digest: str | None = None,
    ) -> None:
        try:
            wrapped = HpkeCiphertext.from_dict(payload.envelope)
            envelope_digest = hashlib.sha256(canonical_json(payload.envelope)).hexdigest()
        except (KeyError, TypeError, ValueError) as exc:
            raise VGenError(
                ErrorCode.VALIDATION_FAILED, details={"reason": "invalid_hpke_envelope"}
            ) from exc
        if (
            payload.algorithm != HPKE_ALGORITHM
            or wrapped.algorithm != HPKE_ALGORITHM
            or len(wrapped.ciphertext) != 48
        ):
            raise VGenError(
                ErrorCode.VALIDATION_FAILED, details={"reason": "invalid_workspace_key_ciphertext"}
            )
        user = db.fetchone(
            "SELECT root_signing_public_key FROM users WHERE id=? AND status='active'",
            (principal.user_id,),
        )
        recipient = repository.workspace_key_recipient(
            workspace_id=workspace_id,
            user_id=principal.user_id,
            recipient_type=payload.recipient_type,
            recipient_id=payload.recipient_id,
        )
        try:
            signed = payload.signed_manifest
            manifest = signed["manifest"]
            issued_at = manifest["issued_at"]
            timestamp_valid = (
                isinstance(issued_at, int)
                and not isinstance(issued_at, bool)
                and issued_at > 0
                and issued_at <= int(time.time()) + 300
                and (rotation_id is not None or int(time.time()) - 600 <= issued_at)
            )
            expected_fields = {
                "version",
                "kind",
                "workspace_id",
                "recipient_type",
                "recipient_id",
                "key_version",
                "algorithm",
                "envelope_sha256",
                "signer_root_key_id",
                "recipient_public_key_sha256",
                "recipient_admission_sha256",
                "recipient_binding_digest",
                "issued_at",
            }
            if rotation_id is not None:
                expected_fields.update({"rotation_id", "recipient_set_digest"})
            manifest_valid = (
                timestamp_valid
                and set(manifest) == expected_fields
                and user is not None
                and verify_key_manifest(
                    signed,
                    b64url_decode(user["root_signing_public_key"], expected_length=32),
                )
                and manifest.get("version") == 1
                and manifest.get("kind") == "vgen-workspace-key-envelope"
                and manifest.get("workspace_id") == workspace_id
                and manifest.get("recipient_type") == payload.recipient_type
                and manifest.get("recipient_id") == payload.recipient_id
                and manifest.get("key_version") == payload.key_version
                and manifest.get("algorithm") == payload.algorithm
                and manifest.get("envelope_sha256") == envelope_digest
                and manifest.get("signer_root_key_id") == signed.get("signer_key_id")
                and manifest.get("recipient_public_key_sha256")
                == recipient["recipient_key_sha256"]
                and manifest.get("recipient_admission_sha256")
                == recipient["admission_digest"]
                and manifest.get("recipient_binding_digest")
                == recipient["recipient_binding_digest"]
                and (
                    rotation_id is None
                    or (
                        manifest.get("rotation_id") == rotation_id
                        and manifest.get("recipient_set_digest") == recipient_set_digest
                    )
                )
            )
        except (KeyError, TypeError, ValueError):
            manifest_valid = False
        if not manifest_valid:
            raise VGenError(ErrorCode.SIGNATURE_INVALID)

    @app.get(
        "/api/v1/workspaces/{workspace_id}/key-rotation/recipients",
        tags=["crypto"],
    )
    def workspace_key_rotation_recipients(
        workspace_id: str,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        return repository.workspace_key_rotation_recipients(
            workspace_id=workspace_id, user_id=principal.user_id
        )

    @app.post(
        "/api/v1/workspaces/{workspace_id}/recipient-admissions",
        tags=["crypto"],
    )
    def put_workspace_recipient_admission(
        workspace_id: str,
        payload: WorkspaceRecipientAdmissionCreate,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        return repository.put_workspace_recipient_admission(
            workspace_id=workspace_id,
            owner_user_id=principal.user_id,
            **payload.model_dump(mode="json"),
        )

    @app.get(
        "/api/v1/workspaces/{workspace_id}/recipient-admissions/{subject_user_id}",
        tags=["crypto"],
    )
    def get_workspace_recipient_admission(
        workspace_id: str,
        subject_user_id: str,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        return repository.workspace_recipient_admission(
            workspace_id=workspace_id,
            owner_user_id=principal.user_id,
            subject_user_id=subject_user_id,
        )

    @app.post("/api/v1/workspaces/{workspace_id}/key-rotations", tags=["crypto"])
    def rotate_workspace_key(
        workspace_id: str,
        payload: WorkspaceKeyRotationCreate,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        repository.require_owner(workspace_id, principal.user_id)
        for grant in payload.envelopes:
            validate_workspace_key_grant(
                workspace_id=workspace_id,
                payload=grant,
                principal=principal,
                rotation_id=payload.rotation_id,
                recipient_set_digest=payload.recipient_set_digest,
            )
        return repository.rotate_workspace_key(
            workspace_id=workspace_id,
            user_id=principal.user_id,
            **payload.model_dump(),
        )

    @app.get(
        "/api/v1/workspaces/{workspace_id}/key-recipients/{recipient_type}/{recipient_id}",
        tags=["crypto"],
    )
    def workspace_key_recipient(
        workspace_id: str,
        recipient_type: str,
        recipient_id: str,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        if recipient_type not in {"user_recovery", "device", "service"}:
            raise VGenError(ErrorCode.VALIDATION_FAILED, details={"field": "recipient_type"})
        return repository.workspace_key_recipient(
            workspace_id=workspace_id,
            user_id=principal.user_id,
            recipient_type=recipient_type,
            recipient_id=recipient_id,
        )

    @app.post("/api/v1/workspaces/{workspace_id}/key-envelopes", tags=["crypto"])
    def grant_workspace_key(
        workspace_id: str,
        payload: WorkspaceKeyEnvelopeGrant,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        validate_workspace_key_grant(
            workspace_id=workspace_id, payload=payload, principal=principal
        )
        return repository.grant_workspace_key(
            workspace_id=workspace_id,
            user_id=principal.user_id,
            **payload.model_dump(),
        )

    @app.get(
        "/api/v1/workspaces/{workspace_id}/key-envelopes/{recipient_type}/{recipient_id}",
        tags=["crypto"],
    )
    def get_workspace_key_envelopes(
        workspace_id: str,
        recipient_type: str,
        recipient_id: str,
        key_version: int | None = Query(default=None, ge=1),
        principal: Principal = Depends(current_principal),
    ) -> dict[str, Any]:
        if principal.principal_type == "service" and not (
            {"task:submit", "task:read"} & principal.scopes
        ):
            raise VGenError(
                ErrorCode.SCOPE_REQUIRED,
                details={"required_scope": "task:submit or task:read"},
            )
        if principal.principal_type not in {"device", "service"}:
            raise VGenError(ErrorCode.PERMISSION_DENIED)
        items = repository.workspace_key_envelopes(
            workspace_id=workspace_id,
            principal_type=principal.principal_type,
            principal_id=principal.principal_id,
            user_id=principal.user_id,
            recipient_type=recipient_type,
            recipient_id=recipient_id,
            key_version=key_version,
        )
        return {"items": items}

    @app.post("/api/v1/workspaces/{workspace_id}/pools", tags=["workspace"])
    def create_pool(
        workspace_id: str, payload: PoolCreate, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        return repository.create_pool(
            workspace_id=workspace_id, user_id=principal.user_id, **payload.model_dump()
        )

    @app.get("/api/v1/workspaces/{workspace_id}/pools", tags=["workspace"])
    def list_pools(
        workspace_id: str, principal: Principal = Depends(user_principal)
    ) -> list[dict[str, Any]]:
        return repository.list_pools(workspace_id=workspace_id, user_id=principal.user_id)

    @app.post("/api/v1/brokers", tags=["broker"])
    def create_broker(
        payload: BrokerCreate, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        broker = repository.create_broker(owner_user_id=principal.user_id, name=payload.name)
        if payload.device_id:
            broker["broker_device"] = repository.attach_broker_device(
                broker_id=broker["id"],
                device_id=payload.device_id,
                owner_user_id=principal.user_id,
            )
        return broker

    @app.get("/api/v1/brokers", tags=["broker"])
    def list_brokers(principal: Principal = Depends(user_principal)) -> list[dict[str, Any]]:
        return repository.list_brokers(owner_user_id=principal.user_id)

    @app.post("/api/v1/brokers/{broker_id}/devices", tags=["broker"])
    def attach_broker_device(
        broker_id: str, payload: BrokerDeviceAttach, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        return repository.attach_broker_device(
            broker_id=broker_id,
            device_id=payload.device_id,
            owner_user_id=principal.user_id,
        )

    @app.post("/api/v1/broker-devices/{broker_device_id}/heartbeat", tags=["broker"])
    def broker_heartbeat(
        broker_device_id: str,
        payload: BrokerHeartbeat,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        require_scope(principal, "broker:heartbeat")
        return repository.broker_device_heartbeat(
            broker_device_id=broker_device_id,
            user_id=principal.user_id,
            broker_id=payload.broker_id,
            runtime_version=payload.runtime_version,
            protocol_version=payload.protocol_version,
            build_commit=payload.build_commit,
            journal_pending=payload.journal_pending,
        )

    @app.get("/api/v1/broker-devices/{broker_device_id}/commands", tags=["broker"])
    def broker_commands(
        broker_device_id: str,
        principal: Principal = Depends(user_principal),
        after: str = "",
    ) -> dict[str, Any]:
        require_scope(principal, "broker:commands")
        items = repository.broker_commands(
            broker_device_id=broker_device_id,
            user_id=principal.user_id,
            after=after,
        )
        return {"items": items}

    @app.post(
        "/api/v1/broker-devices/{broker_device_id}/commands/{command_id}/complete", tags=["broker"]
    )
    def broker_command_complete(
        broker_device_id: str,
        command_id: str,
        payload: CommandComplete,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        require_scope(principal, "broker:commands")
        return repository.complete_broker_command(
            broker_device_id=broker_device_id,
            command_id=command_id,
            user_id=principal.user_id,
            **payload.model_dump(),
        )

    # ----------------------------------------------------------- invite / apply

    @app.post("/api/v1/workspaces/{workspace_id}/invites", tags=["enrollment"])
    def create_invite(
        workspace_id: str, payload: InviteCreate, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        enrollment, secret = repository.create_invite(
            issuer_user_id=principal.user_id,
            workspace_id=workspace_id,
            pool_id=None,
            **payload.model_dump(),
        )
        return {
            "enrollment": enrollment,
            "invite_uri": f"vgen://join/{enrollment['id']}#{secret}",
            "secret": secret,
        }

    @app.post(
        "/api/v1/workspaces/{workspace_id}/worker-invites",
        tags=["worker-enrollment"],
    )
    def create_worker_invite(
        workspace_id: str,
        payload: WorkerInviteCreate,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        result, secret = repository.create_worker_invite(
            issuer_user_id=principal.user_id,
            workspace_id=workspace_id,
            **payload.model_dump(mode="json"),
        )
        enrollment = result["enrollment"]
        return {
            **result,
            "invite_uri": f"vgen://join/{enrollment['id']}#{secret}",
        }

    @app.post("/api/v1/worker-enrollments/claim", tags=["worker-enrollment"])
    def claim_worker_invite(payload: WorkerEnrollmentClaimRequest) -> dict[str, Any]:
        data = payload.model_dump(mode="json")
        data["claim"] = payload.claim.model_dump(mode="json")
        return repository.claim_worker_invite(**data)

    @app.get(
        "/api/v1/worker-enrollments/{enrollment_id}",
        tags=["worker-enrollment"],
    )
    def worker_enrollment_status(
        enrollment_id: str,
        request: Request,
        response: Response,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Vary"] = (
            "Authorization, Content-Digest, Signature-Input, Signature"
        )
        if credentials is not None:
            session = db.resolve_session(credentials.credentials)
            if session is None:
                raise VGenError(ErrorCode.SESSION_EXPIRED, request_id=_request_id(request))
            validate_session_subject(session)
            if session["principal_type"] != "device" or not session["user_id"]:
                raise VGenError(ErrorCode.PERMISSION_DENIED, request_id=_request_id(request))
            return repository.worker_enrollment_status(
                enrollment_id=enrollment_id,
                admin_user_id=session["user_id"],
            )

        material = repository.worker_enrollment_signing_material(enrollment_id)
        raw_path = request.url.path
        if request.url.query:
            raw_path += "?" + request.url.query
        verify_http_request(
            b64url_decode(material["signing_public_key"], expected_length=32),
            method="GET",
            path=raw_path,
            body=b"",
            headers=request.headers,
            expected_key_id=material["worker_key_id"],
            nonce_is_fresh=lambda nonce, created: db.claim_request_nonce(
                principal_type="worker_enrollment",
                principal_id=enrollment_id,
                nonce=nonce,
                signature_created_at=created,
            ),
        )
        return repository.worker_enrollment_status(
            enrollment_id=enrollment_id,
            worker_key_id=material["worker_key_id"],
        )

    @app.post(
        "/api/v1/worker-enrollments/{enrollment_id}/decision",
        tags=["worker-enrollment"],
    )
    def decide_worker_enrollment(
        enrollment_id: str,
        payload: WorkerEnrollmentDecision,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        return repository.decide_worker_enrollment(
            enrollment_id=enrollment_id,
            admin_user_id=principal.user_id,
            **payload.model_dump(mode="json"),
        )

    @app.post("/api/v1/applications", tags=["enrollment"])
    def create_application(
        payload: ApplicationCreate, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        return repository.apply(
            subject_user_id=principal.user_id,
            subject_device_id=principal.principal_id,
            **payload.model_dump(mode="json"),
        )

    @app.post("/api/v1/enrollments/claim", tags=["enrollment"])
    def claim_invite(
        payload: InviteClaim, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        device = db.fetchone(
            "SELECT signing_public_key FROM devices WHERE id=? AND status='active'",
            (principal.principal_id,),
        )
        if device is None:
            raise VGenError(ErrorCode.AUTHENTICATION_REQUIRED)
        claim = payload.claim.model_dump(mode="json")
        if claim.get("invite_id") != payload.invite_id or not verify_user_registration_claim(
            claim, payload.proof_signature
        ):
            raise VGenError(ErrorCode.SIGNATURE_INVALID)
        return repository.claim_invite(
            subject_user_id=principal.user_id,
            subject_device_id=principal.principal_id,
            subject_key_fingerprint=hashlib.sha256(
                device["signing_public_key"].encode()
            ).hexdigest(),
            invite_id=payload.invite_id,
            secret=payload.secret,
            claim=claim,
            proof_signature=payload.proof_signature,
        )

    @app.post("/api/v1/enrollments/{enrollment_id}/decision", tags=["enrollment"])
    def decide_enrollment(
        enrollment_id: str,
        payload: EnrollmentDecision,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        enrollment = repository.enrollment(enrollment_id)
        if payload.approve and enrollment.get("kind") in {"user", "workspace_member"}:
            if payload.signed_admission is None:
                raise VGenError(
                    ErrorCode.SIGNATURE_INVALID,
                    details={"reason": "owner_signed_recipient_admission_required"},
                )
            repository.put_workspace_recipient_admission(
                workspace_id=str(enrollment["workspace_id"]),
                owner_user_id=principal.user_id,
                enrollment_id=enrollment_id,
                signed_admission=payload.signed_admission,
            )
        return repository.decide_enrollment(
            enrollment_id=enrollment_id,
            admin_user_id=principal.user_id,
            approve=payload.approve,
        )

    @app.post("/api/v1/enrollments/{enrollment_id}/revoke", tags=["enrollment"])
    def revoke_enrollment(
        enrollment_id: str, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        return repository.revoke_enrollment(
            enrollment_id=enrollment_id, admin_user_id=principal.user_id
        )

    @app.get("/api/v1/workspaces/{workspace_id}/enrollments", tags=["enrollment"])
    def list_enrollments(
        workspace_id: str,
        principal: Principal = Depends(user_principal),
        state: str | None = None,
    ) -> list[dict[str, Any]]:
        return repository.list_enrollments(
            workspace_id=workspace_id,
            user_id=principal.user_id,
            state=state,
        )

    @app.get("/api/v1/workspaces/{workspace_id}/audit", tags=["workspace"])
    def list_audit(
        workspace_id: str,
        principal: Principal = Depends(user_principal),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[dict[str, Any]]:
        return repository.list_audit(
            workspace_id=workspace_id,
            user_id=principal.user_id,
            limit=limit,
        )

    # -------------------------------------------------------------- worker/rates

    @app.post("/api/v1/workers", tags=["worker"])
    def create_worker(
        payload: WorkerCreate, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        validate_worker_owner_certificate(owner_user_id=principal.user_id, payload=payload)
        # Registration returns no bearer secret. The Worker proves possession
        # of its signing key through /auth/challenges before receiving a
        # short-lived session, which keeps idempotency records non-sensitive.
        return repository.create_worker(owner_user_id=principal.user_id, **payload.model_dump())

    @app.get("/api/v1/workers", tags=["worker"])
    def list_workers(
        principal: Principal = Depends(user_principal),
        workspace_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return repository.list_workers(user_id=principal.user_id, workspace_id=workspace_id)

    @app.post("/api/v1/workers/{worker_id}/manager", tags=["worker"])
    def set_worker_manager(
        worker_id: str,
        payload: WorkerManagerSet,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        return repository.set_worker_manager(
            worker_id=worker_id,
            owner_user_id=principal.user_id,
            actor_device_id=principal.principal_id,
            broker_id=payload.broker_id,
        )

    @app.post(
        "/api/v1/brokers/{broker_id}/workers/{worker_id}/maintenance-jobs",
        tags=["worker-maintenance"],
    )
    def create_worker_maintenance(
        broker_id: str,
        worker_id: str,
        payload: WorkerMaintenanceCreate,
        request: Request,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        spec, authorization, expires_at, spec_digest = validate_maintenance_authorization(
            broker_id=broker_id,
            worker_id=worker_id,
            payload=payload,
            principal=principal,
        )
        job = repository.create_worker_maintenance(
            broker_id=broker_id,
            worker_id=worker_id,
            user_id=principal.user_id,
            device_id=principal.principal_id,
            kind=payload.spec.kind,
            spec=spec,
            spec_digest=spec_digest,
            authorization=authorization,
            expires_at=expires_at,
            artifact_store_type=artifact_store.store_type,
        )
        return maintenance_create_view(job, request)

    @app.get(
        "/api/v1/workers/{worker_id}/maintenance-jobs",
        tags=["worker-maintenance"],
    )
    def list_worker_maintenance(
        worker_id: str,
        principal: Principal = Depends(user_principal),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[dict[str, Any]]:
        return repository.list_worker_maintenance(
            worker_id=worker_id, owner_user_id=principal.user_id, limit=limit
        )

    @app.get("/api/v1/maintenance-jobs/{job_id}", tags=["worker-maintenance"])
    def get_worker_maintenance(
        job_id: str, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        return repository.get_worker_maintenance(
            job_id=job_id, owner_user_id=principal.user_id
        )

    @app.post("/api/v1/maintenance-jobs/{job_id}/commit", tags=["worker-maintenance"])
    def commit_worker_maintenance(
        job_id: str,
        payload: WorkerMaintenanceCommit,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        del payload
        artifact = repository.maintenance_artifact_for_commit(
            job_id=job_id,
            user_id=principal.user_id,
            device_id=principal.principal_id,
        )
        if artifact["state"] == "pending" and artifact_store.store_type != "local":
            if artifact["store_type"] != artifact_store.store_type:
                raise VGenError(ErrorCode.STORAGE_UNAVAILABLE)
            size, digest = artifact_store.observe_upload(
                artifact["id"], max_bytes=int(artifact["expected_size"])
            )
            repository.mark_artifact_uploaded(
                artifact_id=artifact["id"], size=size, digest=digest
            )
        return repository.commit_worker_maintenance(
            job_id=job_id,
            user_id=principal.user_id,
            device_id=principal.principal_id,
        )

    @app.post("/api/v1/maintenance-jobs/{job_id}/cancel", tags=["worker-maintenance"])
    def cancel_worker_maintenance(
        job_id: str,
        payload: WorkerMaintenanceCancel,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        del payload
        return repository.cancel_worker_maintenance(
            job_id=job_id,
            owner_user_id=principal.user_id,
            actor_device_id=principal.principal_id,
        )

    @app.get("/api/v1/workspaces/{workspace_id}/worker-allocations", tags=["worker"])
    def list_allocations(
        workspace_id: str, principal: Principal = Depends(user_principal)
    ) -> list[dict[str, Any]]:
        return repository.list_allocations(workspace_id=workspace_id, user_id=principal.user_id)

    @app.get("/api/v1/worker-allocations/{allocation_id}", tags=["worker"])
    def get_allocation(
        allocation_id: str, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        return repository.get_allocation(allocation_id=allocation_id, user_id=principal.user_id)

    @app.post("/api/v1/workers/{worker_id}/offer", tags=["worker"])
    def offer_worker(
        worker_id: str, payload: WorkerOffer, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        return repository.offer_worker(
            worker_id=worker_id, owner_user_id=principal.user_id, **payload.model_dump()
        )

    @app.post("/api/v1/worker-allocations/{allocation_id}/approve", tags=["worker"])
    def approve_allocation(
        allocation_id: str,
        payload: AllocationApproval,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        return repository.approve_allocation(
            allocation_id=allocation_id,
            admin_user_id=principal.user_id,
            proof=payload.proof,
        )

    @app.post("/api/v1/workers/{worker_id}/leave", tags=["worker"])
    def leave_worker(
        worker_id: str, payload: WorkerLeave, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        return repository.leave_worker(
            worker_id=worker_id,
            owner_user_id=principal.user_id,
            force=payload.force,
        )

    @app.post("/api/v1/workers/{worker_id}/revoke", tags=["worker"])
    def revoke_worker(
        worker_id: str, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        return repository.leave_worker(
            worker_id=worker_id, owner_user_id=principal.user_id, force=True
        )

    def require_worker(principal: Principal, worker_id: str) -> None:
        if principal.principal_type != "worker" or principal.principal_id != worker_id:
            raise VGenError(ErrorCode.PERMISSION_DENIED)

    @app.post(
        "/api/v1/workers/{worker_id}/maintenance-jobs/claim",
        tags=["worker-maintenance"],
        response_model=None,
    )
    def claim_worker_maintenance(
        worker_id: str,
        payload: WorkerMaintenanceClaim,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> dict[str, Any] | Response:
        require_worker(principal, worker_id)
        require_scope(principal, "worker:maintenance:lease")
        job = repository.claim_worker_maintenance(
            worker_id=worker_id,
            session_id=principal.session_id,
            ttl_seconds=payload.ttl_seconds,
        )
        if job is None:
            return Response(status_code=204)
        return maintenance_claim_view(job, request)

    @app.post(
        "/api/v1/workers/{worker_id}/maintenance-jobs/{job_id}/heartbeat",
        tags=["worker-maintenance"],
    )
    def heartbeat_worker_maintenance(
        worker_id: str,
        job_id: str,
        payload: WorkerMaintenanceHeartbeat,
        principal: Principal = Depends(current_principal),
    ) -> dict[str, Any]:
        require_worker(principal, worker_id)
        require_scope(principal, "worker:maintenance:report")
        data = payload.model_dump(mode="json")
        progress = data.pop("progress")
        return repository.heartbeat_worker_maintenance(
            job_id=job_id,
            worker_id=worker_id,
            session_id=principal.session_id,
            progress=progress,
            **data,
        )

    @app.post(
        "/api/v1/workers/{worker_id}/maintenance-jobs/{job_id}/complete",
        tags=["worker-maintenance"],
    )
    def complete_worker_maintenance(
        worker_id: str,
        job_id: str,
        payload: WorkerMaintenanceComplete,
        principal: Principal = Depends(current_principal),
    ) -> dict[str, Any]:
        require_worker(principal, worker_id)
        require_scope(principal, "worker:maintenance:report")
        return repository.complete_worker_maintenance(
            job_id=job_id,
            worker_id=worker_id,
            session_id=principal.session_id,
            **payload.model_dump(mode="json"),
        )

    @app.post("/api/v1/workers/{worker_id}/heartbeat", tags=["worker"])
    def worker_heartbeat(
        worker_id: str, payload: WorkerHeartbeat, principal: Principal = Depends(current_principal)
    ) -> dict[str, Any]:
        require_worker(principal, worker_id)
        require_scope(principal, "worker:heartbeat")
        return repository.worker_heartbeat(worker_id=worker_id, capabilities=payload.capabilities)

    @app.post("/api/v1/workers/{worker_id}/rates", tags=["usage"])
    def propose_rate(
        worker_id: str, payload: RateProposal, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        return repository.propose_rate(
            worker_id=worker_id, user_id=principal.user_id, **payload.model_dump()
        )

    @app.post("/api/v1/rates/{rate_id}/approve", tags=["usage"])
    def approve_rate(
        rate_id: str, principal: Principal = Depends(user_principal)
    ) -> dict[str, Any]:
        return repository.approve_rate(rate_id=rate_id, admin_user_id=principal.user_id)

    # ----------------------------------------------------------- tasks / leases

    @app.post(
        "/api/v1/tasks/preflight",
        tags=["task"],
        response_model=TaskPreflightResult,
        summary="Check task scheduling readiness without reserving a Worker",
    )
    def preflight_task(
        payload: TaskPreflight,
        principal: Principal = Depends(task_principal),
    ) -> dict[str, Any]:
        if principal.principal_type == "service":
            require_scope(principal, "task:submit")
        return repository.preflight_task(
            user_id=principal.user_id,
            principal_type=principal.principal_type,
            principal_id=principal.principal_id,
            workspace_id=payload.workspace_id,
            pool_id=payload.pool_id,
            executor_type=payload.executor_type,
            public_requirements=payload.public_requirements,
        )

    @app.post("/api/v1/tasks/prepare", tags=["task"])
    def prepare_task(
        payload: TaskPrepare,
        request: Request,
        principal: Principal = Depends(task_principal),
    ) -> dict[str, Any]:
        if principal.principal_type == "service":
            require_scope(principal, "task:submit")
        data = payload.model_dump()
        input_descriptors = data.pop("input_artifacts")
        prepared = repository.prepare_task(
            user_id=principal.user_id,
            principal_type=principal.principal_type,
            principal_id=principal.principal_id,
            **data,
        )
        repository.reserve_input_artifacts(
            task_id=prepared["id"],
            artifacts=input_descriptors,
            store_type=artifact_store.store_type,
        )
        prepared["artifact_tickets"] = input_upload_tickets(prepared["id"], request)
        return prepared

    @app.post("/api/v1/tasks/{task_id}/commit", tags=["task"])
    def commit_task(
        task_id: str, payload: TaskCommit, principal: Principal = Depends(task_principal)
    ) -> dict[str, Any]:
        if principal.principal_type == "service":
            require_scope(principal, "task:submit")
        data = payload.model_dump()
        if data["artifacts"]:
            raise VGenError(
                ErrorCode.VALIDATION_FAILED,
                task_id=task_id,
                details={"reason": "artifacts_must_be_reserved_during_prepare"},
            )
        task_row = db.fetchone("SELECT * FROM tasks WHERE id=?", (task_id,))
        if task_row is not None:
            repository.require_task_consumer(
                task_row,
                principal_type=principal.principal_type,
                principal_id=principal.principal_id,
                user_id=principal.user_id,
            )
        receipts = {item["artifact_id"]: item for item in data.pop("artifact_receipts")}
        if len(receipts) != len(payload.artifact_receipts):
            raise VGenError(
                ErrorCode.VALIDATION_FAILED,
                details={"reason": "duplicate_artifact_receipt"},
            )
        pending_inputs = db.fetchall(
            """SELECT * FROM artifacts
               WHERE task_id=? AND direction='input' AND state='pending'""",
            (task_id,),
        )
        if artifact_store.store_type != "local" and len(receipts) != len(pending_inputs):
            raise VGenError(
                ErrorCode.VALIDATION_FAILED,
                details={"reason": "artifact_receipts_required"},
            )
        for artifact in pending_inputs:
            receipt = receipts.get(artifact["id"])
            if receipt is None:
                continue
            expected_size = int(artifact["encrypted_size"])
            if int(receipt["encrypted_size"]) != expected_size:
                raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
            observed_size, _ = artifact_store.observe_upload(
                artifact["id"], max_bytes=expected_size
            )
            if observed_size != expected_size:
                raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
            repository.mark_artifact_uploaded(
                artifact_id=artifact["id"],
                size=expected_size,
                digest=str(receipt["content_digest"]).removeprefix("sha256:"),
            )
        return repository.commit_task(
            task_id=task_id,
            user_id=principal.user_id,
            principal_type=principal.principal_type,
            principal_id=principal.principal_id,
            **data,
        )

    @app.get("/api/v1/tasks/page", tags=["task"])
    def list_task_page(
        workspace_id: str,
        principal: Principal = Depends(task_principal),
        state: str | None = None,
        sort: Literal["created", "updated", "priority", "state"] = "created",
        order: Literal["asc", "desc"] = "desc",
        limit: int = Query(default=20, ge=1, le=100),
        cursor: str | None = None,
    ) -> dict[str, Any]:
        if principal.principal_type == "service":
            require_scope(principal, "task:read")
        return repository.list_task_page(
            workspace_id=workspace_id,
            user_id=principal.user_id,
            principal_type=principal.principal_type,
            principal_id=principal.principal_id,
            state=state,
            sort=sort,
            order=order,
            limit=limit,
            cursor=cursor,
        )

    @app.get("/api/v1/tasks/{task_id}", tags=["task"])
    def get_task(
        task_id: str,
        request: Request,
        principal: Principal = Depends(task_principal),
    ) -> dict[str, Any]:
        if principal.principal_type == "service":
            require_scope(principal, "task:read")
        task = repository.get_task(
            task_id=task_id,
            user_id=principal.user_id,
            principal_type=principal.principal_type,
            principal_id=principal.principal_id,
        )
        for artifact in task["artifacts"]:
            if (
                artifact["direction"] == "output"
                and artifact["state"] == "available"
                and artifact["store_type"] == artifact_store.store_type
            ):
                artifact["download_ticket"] = external_ticket(
                    artifact_store.issue_ticket(
                        artifact["id"],
                        method="GET",
                        ttl_seconds=300,
                        max_bytes=int(artifact.get("encrypted_size") or 100 * 1024**3),
                    ).to_dict(),
                    request,
                )
        return task

    @app.get("/api/v1/tasks", tags=["task"])
    def list_tasks(
        workspace_id: str,
        principal: Principal = Depends(task_principal),
        state: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[dict[str, Any]]:
        if principal.principal_type == "service":
            require_scope(principal, "task:read")
        return repository.list_tasks(
            workspace_id=workspace_id,
            user_id=principal.user_id,
            principal_type=principal.principal_type,
            principal_id=principal.principal_id,
            state=state,
            limit=limit,
        )

    @app.post("/api/v1/tasks/{task_id}/cancel", tags=["task"])
    def cancel_task(task_id: str, principal: Principal = Depends(task_principal)) -> dict[str, Any]:
        if principal.principal_type == "service":
            require_scope(principal, "task:cancel")
        return repository.cancel_task(
            task_id=task_id,
            user_id=principal.user_id,
            principal_type=principal.principal_type,
            principal_id=principal.principal_id,
        )

    @app.post("/api/v1/tasks/{task_id}/retry", tags=["task"])
    def retry_task(task_id: str, principal: Principal = Depends(task_principal)) -> dict[str, Any]:
        if principal.principal_type == "service":
            require_scope(principal, "task:submit")
        return repository.prepare_retry(
            task_id=task_id,
            user_id=principal.user_id,
            principal_type=principal.principal_type,
            principal_id=principal.principal_id,
        )

    @app.post("/api/v1/tasks/{task_id}/rekey", tags=["task"])
    def rekey_task(
        task_id: str,
        payload: TaskRekey,
        principal: Principal = Depends(task_principal),
    ) -> dict[str, Any]:
        if principal.principal_type == "service":
            require_scope(principal, "task:submit")
        return repository.commit_rekey(
            task_id=task_id,
            user_id=principal.user_id,
            principal_type=principal.principal_type,
            principal_id=principal.principal_id,
            **payload.model_dump(),
        )

    @app.get("/api/v1/tasks/{task_id}/reader-envelope", tags=["task"])
    def get_reader_envelope(
        task_id: str, principal: Principal = Depends(task_principal)
    ) -> dict[str, Any]:
        if principal.principal_type == "service" and not (
            {"task:submit", "task:read"} & principal.scopes
        ):
            raise VGenError(
                ErrorCode.SCOPE_REQUIRED,
                details={"required_scope": "task:submit or task:read"},
            )
        return repository.reader_envelope(
            task_id=task_id,
            user_id=principal.user_id,
            principal_type=principal.principal_type,
            principal_id=principal.principal_id,
        )

    @app.post("/api/v1/workers/{worker_id}/lease", tags=["worker"], response_model=None)
    def lease(
        worker_id: str,
        payload: LeaseRequest,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> Response | dict[str, Any]:
        require_worker(principal, worker_id)
        require_scope(principal, "worker:lease")
        value = repository.lease(worker_id=worker_id, ttl_seconds=payload.ttl_seconds)
        if value is None:
            return Response(status_code=204)
        value["artifact_download_tickets"] = lease_download_tickets(
            value["artifacts"], request, ttl_seconds=payload.ttl_seconds
        )
        outputs = repository.reserve_output_artifacts(
            task_id=value["task_id"],
            attempt_id=value["attempt_id"],
            count=int(value.pop("output_count", 1)),
            store_type=artifact_store.store_type,
        )
        value["output_upload_tickets"] = output_tickets(outputs, request)
        return value

    @app.post("/api/v1/attempts/{attempt_id}/artifact-tickets", tags=["worker"])
    def refresh_artifact_tickets(
        attempt_id: str,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> dict[str, Any]:
        if principal.principal_type != "worker":
            raise VGenError(ErrorCode.PERMISSION_DENIED)
        require_scope(principal, "worker:complete")
        outputs = repository.refresh_output_artifacts(
            attempt_id=attempt_id,
            worker_id=principal.principal_id,
        )
        return {"output_upload_tickets": output_tickets(outputs, request)}

    @app.post("/api/v1/attempts/{attempt_id}/heartbeat", tags=["worker"])
    def attempt_heartbeat(
        attempt_id: str,
        payload: AttemptHeartbeat,
        principal: Principal = Depends(current_principal),
    ) -> dict[str, Any]:
        if principal.principal_type != "worker":
            raise VGenError(ErrorCode.PERMISSION_DENIED)
        require_scope(principal, "worker:heartbeat")
        return repository.heartbeat_attempt(
            attempt_id=attempt_id,
            worker_id=principal.principal_id,
            **payload.model_dump(),
        )

    @app.post("/api/v1/attempts/{attempt_id}/finish", tags=["worker"])
    def attempt_finish(
        attempt_id: str, payload: AttemptFinish, principal: Principal = Depends(current_principal)
    ) -> dict[str, Any]:
        if principal.principal_type != "worker":
            raise VGenError(ErrorCode.PERMISSION_DENIED)
        require_scope(principal, "worker:complete")
        attempt = db.fetchone(
            """SELECT a.task_id,t.state AS task_state
               FROM task_attempts a JOIN tasks t ON t.id=a.task_id
               WHERE a.id=? AND a.worker_id=?""",
            (attempt_id, principal.principal_id),
        )
        worker = db.fetchone(
            "SELECT signing_public_key FROM workers WHERE id=?", (principal.principal_id,)
        )
        if attempt is None or worker is None or not payload.worker_signature:
            raise VGenError(
                ErrorCode.USAGE_REPORT_INVALID, details={"reason": "worker_signature_missing"}
            )
        signed_report = {
            "attempt_id": attempt_id,
            "task_id": attempt["task_id"],
            "worker_id": principal.principal_id,
            **payload.model_dump(exclude={"worker_signature"}),
        }
        try:
            report_valid = verify_message(
                b64url_decode(worker["signing_public_key"], expected_length=32),
                canonical_json(signed_report),
                b64url_decode(payload.worker_signature, expected_length=64),
                context=b"vgen-worker-finish-v1",
            )
        except ValueError:
            report_valid = False
        if not report_valid:
            raise VGenError(
                ErrorCode.USAGE_REPORT_INVALID, details={"reason": "worker_signature_invalid"}
            )
        if payload.succeeded and attempt["task_state"] != "cancelled":
            for reported in payload.output_artifacts:
                if not reported.artifact_id:
                    continue
                artifact = db.fetchone(
                    """SELECT * FROM artifacts
                       WHERE id=? AND attempt_id=? AND direction='output'""",
                    (reported.artifact_id, attempt_id),
                )
                if (
                    artifact is not None
                    and reported.encrypted_size is not None
                    and reported.content_digest is not None
                ):
                    if reported.encrypted_size > 100 * 1024**3:
                        raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
                    digest = reported.content_digest.removeprefix("sha256:")
                    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                        raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
                    observed_size, _ = artifact_store.observe_upload(
                        artifact["id"], max_bytes=reported.encrypted_size
                    )
                    if observed_size != reported.encrypted_size:
                        raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
                    repository.mark_artifact_uploaded(
                        artifact_id=artifact["id"],
                        size=reported.encrypted_size,
                        digest=digest,
                    )
        return repository.finish_attempt(
            attempt_id=attempt_id,
            worker_id=principal.principal_id,
            **payload.model_dump(),
        )

    @app.get("/api/v1/workspaces/{workspace_id}/usage", tags=["usage"])
    def usage(
        workspace_id: str,
        principal: Principal = Depends(task_principal),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> list[dict[str, Any]]:
        if principal.principal_type == "service":
            require_scope(principal, "usage:read")
        return repository.usage(
            workspace_id=workspace_id,
            user_id=principal.user_id,
            principal_type=principal.principal_type,
            principal_id=principal.principal_id,
            limit=limit,
        )

    @app.post(
        "/api/v1/workspaces/{workspace_id}/usage/{entry_id}/reversal",
        tags=["usage"],
    )
    def reverse_usage_charge(
        workspace_id: str,
        entry_id: str,
        payload: UsageReversalCreate,
        principal: Principal = Depends(user_principal),
    ) -> dict[str, Any]:
        return repository.reverse_usage_charge(
            workspace_id=workspace_id,
            ledger_id=entry_id,
            user_id=principal.user_id,
            reason_code=payload.reason_code.value,
        )

    install_openapi_contract(app)
    return app
