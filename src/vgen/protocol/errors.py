"""Canonical VGen errors.

The six-digit numeric code is the stable machine contract. HTTP status, human
message, retry policy, and the component which detected the failure are
metadata and may be rendered differently by a CLI or SDK.

Only values returned by :func:`sanitize_details` are allowed into public error
responses. This deliberately drops secrets and truncates unbounded upstream
data at the protocol boundary.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any


class RetryAction(StrEnum):
    NONE = "none"
    SAME_WORKER = "same_worker"
    ANOTHER_WORKER = "another_worker"
    LATER = "later"
    REKEY_REQUIRED = "rekey_required"
    RESUME_UPLOAD = "resume_upload"


class ErrorOrigin(StrEnum):
    CLIENT = "client"
    GATEWAY = "gateway"
    BROKER = "broker"
    WORKER = "worker"
    EXECUTOR = "executor"
    STORAGE = "storage"


class Responsibility(StrEnum):
    CONSUMER = "consumer"
    PROVIDER = "provider"
    PLATFORM = "platform"
    UNKNOWN = "unknown"


class ErrorCode(IntEnum):
    # 10xxxx: authentication / session
    AUTHENTICATION_REQUIRED = 100001
    SESSION_EXPIRED = 100002
    SIGNATURE_INVALID = 100003
    REPLAY_DETECTED = 100004

    # 11xxxx: user / device
    DEVICE_REVOKED = 110001
    DEVICE_CERTIFICATE_INVALID = 110002

    # 12xxxx: authorization
    PERMISSION_DENIED = 120001
    SCOPE_REQUIRED = 120002

    # 20xxxx: workspace / membership
    WORKSPACE_NOT_FOUND = 200001
    WORKSPACE_MEMBERSHIP_REQUIRED = 200002

    # 21xxxx: logical broker / broker device
    BROKER_DEVICE_OFFLINE = 210001
    BROKER_NOT_FOUND = 210002
    BROKER_DEVICE_NOT_FOUND = 210003
    BROKER_COMMAND_NOT_FOUND = 210004

    # 22xxxx: worker
    NO_ELIGIBLE_WORKER = 220001
    WORKER_OFFLINE = 220002
    WORKER_DRAINING = 220003
    WORKER_REVOKED = 220004
    WORKER_NOT_FOUND = 220005
    WORKER_MAINTENANCE_JOB_NOT_FOUND = 220006
    WORKER_MAINTENANCE_STATE_CONFLICT = 220007

    # 23xxxx: pool / allocation
    POOL_NOT_FOUND = 230001
    WORKER_ALLOCATION_REQUIRED = 230002
    WORKER_ALLOCATION_NOT_APPROVED = 230003
    ALLOCATION_PROOF_INVALID = 230004
    WORKER_ALLOCATION_NOT_FOUND = 230005

    # 24xxxx: invite / application / enrollment
    INVITE_INVALID_OR_EXPIRED = 240001
    ENROLLMENT_APPROVAL_REQUIRED = 240002
    ENROLLMENT_CLOSED = 240003
    INVITE_ALREADY_USED = 240004
    ENROLLMENT_NOT_FOUND = 240005

    # 30xxxx: task
    TASK_STATE_CONFLICT = 300001
    TASK_NOT_FOUND = 300002
    TASK_COMMIT_EXPIRED = 300003

    # 31xxxx: attempt / lease / rekey
    LEASE_LOST = 310001
    REKEY_REQUIRED = 310002
    RESERVATION_EXPIRED = 310003
    FENCING_TOKEN_STALE = 310004

    # 32xxxx: workflow / executor
    EXECUTOR_UNAVAILABLE = 320001
    UNSUPPORTED_PAYLOAD = 320002
    DEPENDENCY_MISSING = 320003
    EXECUTION_TIMEOUT = 320004
    GPU_OUT_OF_MEMORY = 320005
    WORKFLOW_NOT_FOUND = 320006
    WORKFLOW_SIGNATURE_INVALID = 320007
    EXECUTION_CANCELLED = 320008

    # 33xxxx: artifact / storage
    INPUT_DOWNLOAD_FAILED = 330001
    OUTPUT_UPLOAD_FAILED = 330002
    ARTIFACT_NOT_FOUND = 330003
    ARTIFACT_INTEGRITY_FAILED = 330004

    # 34xxxx: Worker maintenance / model delivery / runtime update
    SOURCE_NOT_ALLOWED = 340002
    DISK_SPACE_INSUFFICIENT = 340003
    PATH_CONFLICT = 340004
    DIGEST_MISMATCH = 340005
    DOWNLOAD_INTERRUPTED = 340006
    GATED_CREDENTIAL_UNAVAILABLE = 340007
    MAINTENANCE_POLICY_DENIED = 340008
    MANIFEST_UNTRUSTED = 340009
    MAINTENANCE_LEASE_LOST = 340010
    UPDATE_INCOMPATIBLE = 340011
    UPDATE_DOWNGRADE_DENIED = 340012
    UPDATE_ACTIVATION_FAILED = 340013
    CAPABILITY_ARCHIVE_INVALID = 340014
    CAPABILITY_VERSION_CONFLICT = 340015
    CAPABILITY_EXECUTABLE_CONTENT = 340016
    CAPABILITY_RELEASE_INVALID = 340017
    CAPABILITY_COMPILE_INVALID = 340018

    # 40xxxx: crypto / key envelope
    DECRYPTION_FAILED = 400001
    KEY_VERSION_UNAVAILABLE = 400002
    KEY_MANIFEST_INVALID = 400003
    RECIPIENT_KEY_UNAVAILABLE = 400004
    KEY_RECIPIENT_NOT_FOUND = 400005

    # 50xxxx: usage / rate / future quota
    USAGE_REPORT_INVALID = 500001
    RATE_NOT_APPROVED = 500002
    RATE_NOT_FOUND = 500003

    # 60xxxx: protocol / validation
    VALIDATION_FAILED = 600001
    IDEMPOTENCY_CONFLICT = 600002
    PROTOCOL_VERSION_UNSUPPORTED = 600003
    REQUEST_BODY_TOO_LARGE = 600004
    RATE_LIMITED = 600005

    # 70xxxx: network / external dependency
    GATEWAY_UNREACHABLE = 700001
    STORAGE_UNAVAILABLE = 700002
    EXTERNAL_DEPENDENCY_UNAVAILABLE = 700003

    # 90xxxx: internal
    INTERNAL_ERROR = 900001


@dataclass(frozen=True, slots=True)
class ErrorSpec:
    code: ErrorCode
    message: str
    http_status: int
    origin: ErrorOrigin
    retry_action: RetryAction = RetryAction.NONE
    responsibility: Responsibility = Responsibility.UNKNOWN
    default_retry_after_ms: int | None = None

    @property
    def retryable(self) -> bool:
        return self.retry_action is not RetryAction.NONE


def _spec(
    code: ErrorCode,
    message: str,
    http_status: int,
    origin: ErrorOrigin,
    *,
    retry: RetryAction = RetryAction.NONE,
    responsibility: Responsibility = Responsibility.UNKNOWN,
    retry_after_ms: int | None = None,
) -> ErrorSpec:
    return ErrorSpec(
        code=code,
        message=message,
        http_status=http_status,
        origin=origin,
        retry_action=retry,
        responsibility=responsibility,
        default_retry_after_ms=retry_after_ms,
    )


_ERROR_SPECS = (
    _spec(
        ErrorCode.AUTHENTICATION_REQUIRED,
        "Authentication is required.",
        401,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.SESSION_EXPIRED,
        "The session has expired.",
        401,
        ErrorOrigin.GATEWAY,
        retry=RetryAction.LATER,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.SIGNATURE_INVALID,
        "The request signature is invalid.",
        401,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.REPLAY_DETECTED,
        "The request has already been used.",
        409,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.DEVICE_REVOKED,
        "The device has been revoked.",
        403,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.DEVICE_CERTIFICATE_INVALID,
        "The device certificate is invalid.",
        401,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.PERMISSION_DENIED,
        "Permission is denied.",
        403,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.SCOPE_REQUIRED,
        "The session does not include the required scope.",
        403,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.WORKSPACE_NOT_FOUND,
        "The workspace was not found.",
        404,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.WORKSPACE_MEMBERSHIP_REQUIRED,
        "Workspace membership is required.",
        403,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.BROKER_DEVICE_OFFLINE,
        "The broker device is offline.",
        503,
        ErrorOrigin.BROKER,
        retry=RetryAction.LATER,
        responsibility=Responsibility.PLATFORM,
        retry_after_ms=5_000,
    ),
    _spec(
        ErrorCode.BROKER_NOT_FOUND,
        "The logical broker was not found.",
        404,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.BROKER_DEVICE_NOT_FOUND,
        "The broker device was not found.",
        404,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.BROKER_COMMAND_NOT_FOUND,
        "The broker command was not found.",
        404,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.NO_ELIGIBLE_WORKER,
        "No eligible worker is currently available.",
        503,
        ErrorOrigin.GATEWAY,
        retry=RetryAction.LATER,
        responsibility=Responsibility.PLATFORM,
        retry_after_ms=5_000,
    ),
    _spec(
        ErrorCode.WORKER_OFFLINE,
        "The worker is offline.",
        503,
        ErrorOrigin.WORKER,
        retry=RetryAction.ANOTHER_WORKER,
        responsibility=Responsibility.PROVIDER,
    ),
    _spec(
        ErrorCode.WORKER_DRAINING,
        "The worker is draining and cannot accept new work.",
        409,
        ErrorOrigin.WORKER,
        retry=RetryAction.ANOTHER_WORKER,
        responsibility=Responsibility.PROVIDER,
    ),
    _spec(
        ErrorCode.WORKER_REVOKED,
        "The worker has been revoked.",
        403,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.PROVIDER,
    ),
    _spec(
        ErrorCode.WORKER_NOT_FOUND,
        "The worker was not found.",
        404,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.WORKER_MAINTENANCE_JOB_NOT_FOUND,
        "The worker maintenance job was not found.",
        404,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.WORKER_MAINTENANCE_STATE_CONFLICT,
        "The worker maintenance job is not in the required state.",
        409,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.POOL_NOT_FOUND,
        "The pool was not found.",
        404,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.WORKER_ALLOCATION_REQUIRED,
        "The worker is not allocated to this pool.",
        403,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.WORKER_ALLOCATION_NOT_APPROVED,
        "The worker allocation is awaiting approval.",
        409,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.ALLOCATION_PROOF_INVALID,
        "The Workspace allocation proof is invalid.",
        422,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.WORKER_ALLOCATION_NOT_FOUND,
        "The worker allocation was not found.",
        404,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.INVITE_INVALID_OR_EXPIRED,
        "The invite is invalid or has expired.",
        400,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.ENROLLMENT_APPROVAL_REQUIRED,
        "The enrollment is awaiting approval.",
        202,
        ErrorOrigin.GATEWAY,
        retry=RetryAction.LATER,
        responsibility=Responsibility.CONSUMER,
        retry_after_ms=5_000,
    ),
    _spec(
        ErrorCode.ENROLLMENT_CLOSED,
        "Enrollment is closed.",
        403,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.INVITE_ALREADY_USED,
        "The invite has already been used.",
        409,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.ENROLLMENT_NOT_FOUND,
        "The enrollment was not found.",
        404,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.TASK_STATE_CONFLICT,
        "The task is not in the required state.",
        409,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.TASK_NOT_FOUND,
        "The task was not found.",
        404,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.TASK_COMMIT_EXPIRED,
        "The prepared task can no longer be committed.",
        409,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.LEASE_LOST,
        "The task lease is no longer valid.",
        409,
        ErrorOrigin.GATEWAY,
        retry=RetryAction.ANOTHER_WORKER,
        responsibility=Responsibility.PLATFORM,
    ),
    _spec(
        ErrorCode.REKEY_REQUIRED,
        "The task key must be wrapped for a replacement worker.",
        409,
        ErrorOrigin.GATEWAY,
        retry=RetryAction.REKEY_REQUIRED,
        responsibility=Responsibility.PLATFORM,
    ),
    _spec(
        ErrorCode.RESERVATION_EXPIRED,
        "The worker reservation has expired.",
        409,
        ErrorOrigin.GATEWAY,
        retry=RetryAction.LATER,
        responsibility=Responsibility.PLATFORM,
    ),
    _spec(
        ErrorCode.FENCING_TOKEN_STALE,
        "The fencing token is stale.",
        409,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.PROVIDER,
    ),
    _spec(
        ErrorCode.EXECUTOR_UNAVAILABLE,
        "The executor is unavailable.",
        503,
        ErrorOrigin.EXECUTOR,
        retry=RetryAction.SAME_WORKER,
        responsibility=Responsibility.PROVIDER,
    ),
    _spec(
        ErrorCode.UNSUPPORTED_PAYLOAD,
        "The executor does not support this payload.",
        422,
        ErrorOrigin.EXECUTOR,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.DEPENDENCY_MISSING,
        "An executor dependency is missing.",
        503,
        ErrorOrigin.EXECUTOR,
        responsibility=Responsibility.PROVIDER,
    ),
    _spec(
        ErrorCode.EXECUTION_TIMEOUT,
        "The executor timed out.",
        504,
        ErrorOrigin.EXECUTOR,
        retry=RetryAction.ANOTHER_WORKER,
        responsibility=Responsibility.PROVIDER,
    ),
    _spec(
        ErrorCode.GPU_OUT_OF_MEMORY,
        "The worker GPU does not have enough memory.",
        503,
        ErrorOrigin.EXECUTOR,
        retry=RetryAction.ANOTHER_WORKER,
        responsibility=Responsibility.PROVIDER,
    ),
    _spec(
        ErrorCode.WORKFLOW_NOT_FOUND,
        "The workflow was not found.",
        404,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.WORKFLOW_SIGNATURE_INVALID,
        "The workflow signature is invalid.",
        422,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.EXECUTION_CANCELLED,
        "The execution was cancelled.",
        409,
        ErrorOrigin.EXECUTOR,
        responsibility=Responsibility.UNKNOWN,
    ),
    _spec(
        ErrorCode.INPUT_DOWNLOAD_FAILED,
        "An input artifact could not be downloaded.",
        502,
        ErrorOrigin.WORKER,
        retry=RetryAction.SAME_WORKER,
        responsibility=Responsibility.PLATFORM,
    ),
    _spec(
        ErrorCode.OUTPUT_UPLOAD_FAILED,
        "An output artifact could not be uploaded.",
        502,
        ErrorOrigin.WORKER,
        retry=RetryAction.RESUME_UPLOAD,
        responsibility=Responsibility.PLATFORM,
    ),
    _spec(
        ErrorCode.ARTIFACT_NOT_FOUND,
        "The artifact was not found.",
        404,
        ErrorOrigin.STORAGE,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.ARTIFACT_INTEGRITY_FAILED,
        "Artifact integrity verification failed.",
        422,
        ErrorOrigin.STORAGE,
        responsibility=Responsibility.PLATFORM,
    ),
    _spec(
        ErrorCode.SOURCE_NOT_ALLOWED,
        "The model source is not allowed by the local Worker policy.",
        403,
        ErrorOrigin.WORKER,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.DISK_SPACE_INSUFFICIENT,
        "The Worker does not have enough disk space for this maintenance task.",
        507,
        ErrorOrigin.WORKER,
        responsibility=Responsibility.PROVIDER,
    ),
    _spec(
        ErrorCode.PATH_CONFLICT,
        "A protected local model or runtime path conflicts with this maintenance task.",
        409,
        ErrorOrigin.WORKER,
        responsibility=Responsibility.PROVIDER,
    ),
    _spec(
        ErrorCode.DIGEST_MISMATCH,
        "The downloaded maintenance content does not match its authorized digest.",
        422,
        ErrorOrigin.WORKER,
        responsibility=Responsibility.PLATFORM,
    ),
    _spec(
        ErrorCode.DOWNLOAD_INTERRUPTED,
        "The maintenance download was interrupted.",
        503,
        ErrorOrigin.WORKER,
        retry=RetryAction.LATER,
        responsibility=Responsibility.PLATFORM,
        retry_after_ms=5_000,
    ),
    _spec(
        ErrorCode.GATED_CREDENTIAL_UNAVAILABLE,
        "This model requires a Worker-local credential or manual action.",
        409,
        ErrorOrigin.WORKER,
        responsibility=Responsibility.PROVIDER,
    ),
    _spec(
        ErrorCode.MAINTENANCE_POLICY_DENIED,
        "The local Worker maintenance policy denied this task.",
        403,
        ErrorOrigin.WORKER,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.MANIFEST_UNTRUSTED,
        "The Worker update package or workflow manifest is not trusted.",
        422,
        ErrorOrigin.WORKER,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.MAINTENANCE_LEASE_LOST,
        "The Worker maintenance lease is no longer valid.",
        409,
        ErrorOrigin.GATEWAY,
        retry=RetryAction.LATER,
        responsibility=Responsibility.PLATFORM,
    ),
    _spec(
        ErrorCode.UPDATE_INCOMPATIBLE,
        "The Worker update package is incompatible with this runtime.",
        422,
        ErrorOrigin.WORKER,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.UPDATE_DOWNGRADE_DENIED,
        "Worker runtime downgrades and same-version reinstalls are not allowed remotely.",
        409,
        ErrorOrigin.WORKER,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.UPDATE_ACTIVATION_FAILED,
        "The updated Worker runtime did not activate and was rolled back.",
        500,
        ErrorOrigin.WORKER,
        responsibility=Responsibility.PROVIDER,
    ),
    _spec(
        ErrorCode.CAPABILITY_ARCHIVE_INVALID,
        "The workflow capability archive is invalid or cannot be compiled.",
        422,
        ErrorOrigin.WORKER,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.CAPABILITY_VERSION_CONFLICT,
        "This immutable workflow version already exists with different content.",
        409,
        ErrorOrigin.WORKER,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.CAPABILITY_EXECUTABLE_CONTENT,
        "The workflow capability archive contains executable content.",
        422,
        ErrorOrigin.WORKER,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.CAPABILITY_RELEASE_INVALID,
        "An existing local workflow capability release is invalid.",
        422,
        ErrorOrigin.WORKER,
        responsibility=Responsibility.PROVIDER,
    ),
    _spec(
        ErrorCode.CAPABILITY_COMPILE_INVALID,
        "The workflow capability graph or parameter mapping cannot be compiled.",
        422,
        ErrorOrigin.WORKER,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.DECRYPTION_FAILED,
        "The encrypted content could not be decrypted.",
        422,
        ErrorOrigin.CLIENT,
        responsibility=Responsibility.UNKNOWN,
    ),
    _spec(
        ErrorCode.KEY_VERSION_UNAVAILABLE,
        "The required key version is unavailable.",
        409,
        ErrorOrigin.CLIENT,
        retry=RetryAction.REKEY_REQUIRED,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.KEY_MANIFEST_INVALID,
        "The key manifest signature is invalid.",
        422,
        ErrorOrigin.CLIENT,
        responsibility=Responsibility.PLATFORM,
    ),
    _spec(
        ErrorCode.RECIPIENT_KEY_UNAVAILABLE,
        "No key envelope exists for this recipient.",
        403,
        ErrorOrigin.CLIENT,
        retry=RetryAction.REKEY_REQUIRED,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.KEY_RECIPIENT_NOT_FOUND,
        "The key recipient was not found.",
        404,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.USAGE_REPORT_INVALID,
        "The usage report is invalid.",
        422,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.PROVIDER,
    ),
    _spec(
        ErrorCode.RATE_NOT_APPROVED,
        "The worker rate has not been approved.",
        409,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.RATE_NOT_FOUND,
        "The rate card was not found.",
        404,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.VALIDATION_FAILED,
        "Request validation failed.",
        422,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.IDEMPOTENCY_CONFLICT,
        "The idempotency key was used for a different request.",
        409,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.PROTOCOL_VERSION_UNSUPPORTED,
        "The protocol version is not supported.",
        400,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.REQUEST_BODY_TOO_LARGE,
        "The request body is too large.",
        413,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.CONSUMER,
    ),
    _spec(
        ErrorCode.RATE_LIMITED,
        "Too many requests were sent in a short period.",
        429,
        ErrorOrigin.GATEWAY,
        retry=RetryAction.LATER,
        responsibility=Responsibility.CONSUMER,
        retry_after_ms=1_000,
    ),
    _spec(
        ErrorCode.GATEWAY_UNREACHABLE,
        "The gateway could not be reached.",
        503,
        ErrorOrigin.CLIENT,
        retry=RetryAction.LATER,
        responsibility=Responsibility.PLATFORM,
        retry_after_ms=5_000,
    ),
    _spec(
        ErrorCode.STORAGE_UNAVAILABLE,
        "Artifact storage is unavailable.",
        503,
        ErrorOrigin.STORAGE,
        retry=RetryAction.LATER,
        responsibility=Responsibility.PLATFORM,
        retry_after_ms=5_000,
    ),
    _spec(
        ErrorCode.EXTERNAL_DEPENDENCY_UNAVAILABLE,
        "An external dependency is unavailable.",
        503,
        ErrorOrigin.GATEWAY,
        retry=RetryAction.LATER,
        responsibility=Responsibility.PLATFORM,
        retry_after_ms=5_000,
    ),
    _spec(
        ErrorCode.INTERNAL_ERROR,
        "An internal error occurred.",
        500,
        ErrorOrigin.GATEWAY,
        responsibility=Responsibility.PLATFORM,
    ),
)

ERROR_REGISTRY: Mapping[ErrorCode, ErrorSpec] = MappingProxyType(
    {spec.code: spec for spec in _ERROR_SPECS}
)

_SENSITIVE_KEY_PARTS = frozenset(
    {
        "authorization",
        "bearer",
        "credential",
        "mnemonic",
        "passphrase",
        "private",
        "prompt",
        "recovery",
        "secret",
        "signed_url",
        "token",
        "upstream_body",
        "upstream_response",
    }
)


def _key_is_sensitive(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _sanitize_value(value: Any, depth: int) -> Any:
    if depth >= 4:
        return "<truncated>"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else "<non-finite-number>"
    if isinstance(value, str):
        if "://" in value and "?" in value:
            return "<redacted-url>"
        return value[:512]
    if isinstance(value, bytes):
        return f"<binary:{len(value)} bytes>"
    if isinstance(value, Mapping):
        return sanitize_details(value, _depth=depth + 1)
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_sanitize_value(item, depth + 1) for item in list(value)[:32]]
    return str(value)[:512]


def sanitize_details(
    details: Mapping[str, Any] | None,
    *,
    _depth: int = 0,
) -> dict[str, Any]:
    """Return bounded, JSON-safe details with secret-bearing fields removed."""

    if not details:
        return {}
    sanitized: dict[str, Any] = {}
    for key, value in list(details.items())[:32]:
        public_key = str(key)[:128]
        if _key_is_sensitive(public_key):
            sanitized[public_key] = "<redacted>"
        else:
            sanitized[public_key] = _sanitize_value(value, _depth)
    return sanitized


def get_error_spec(code: ErrorCode | int) -> ErrorSpec:
    try:
        normalized = ErrorCode(code)
    except ValueError as exc:
        raise ValueError(f"unknown VGen error code: {code}") from exc
    return ERROR_REGISTRY[normalized]


def error_envelope(
    code: ErrorCode | int,
    *,
    request_id: str | None = None,
    task_id: str | None = None,
    attempt_id: str | None = None,
    details: Mapping[str, Any] | None = None,
    retry_after_ms: int | None = None,
    origin: ErrorOrigin | str | None = None,
) -> dict[str, Any]:
    """Build the canonical JSON response body for a registered error."""

    spec = get_error_spec(code)
    resolved_origin = ErrorOrigin(origin) if origin is not None else spec.origin
    after_ms = spec.default_retry_after_ms if retry_after_ms is None else retry_after_ms
    return {
        "error": {
            "code": int(spec.code),
            "name": spec.code.name,
            "message": spec.message,
            "origin": resolved_origin.value,
            "retry": {
                "allowed": spec.retryable,
                "action": spec.retry_action.value,
                "after_ms": after_ms,
            },
            "responsibility": spec.responsibility.value,
            "request_id": request_id,
            "task_id": task_id,
            "attempt_id": attempt_id,
            "details": sanitize_details(details),
        }
    }


class VGenError(Exception):
    """Typed error which can be rendered without exposing its internal cause."""

    def __init__(
        self,
        code: ErrorCode | int,
        *,
        request_id: str | None = None,
        task_id: str | None = None,
        attempt_id: str | None = None,
        details: Mapping[str, Any] | None = None,
        retry_after_ms: int | None = None,
        origin: ErrorOrigin | str | None = None,
    ) -> None:
        self.spec = get_error_spec(code)
        self.request_id = request_id
        self.task_id = task_id
        self.attempt_id = attempt_id
        self.details = sanitize_details(details)
        self.retry_after_ms = retry_after_ms
        self.origin = ErrorOrigin(origin) if origin is not None else self.spec.origin
        super().__init__(self.spec.message)

    @property
    def code(self) -> ErrorCode:
        return self.spec.code

    @property
    def http_status(self) -> int:
        return self.spec.http_status

    def to_envelope(self) -> dict[str, Any]:
        return error_envelope(
            self.code,
            request_id=self.request_id,
            task_id=self.task_id,
            attempt_id=self.attempt_id,
            details=self.details,
            retry_after_ms=self.retry_after_ms,
            origin=self.origin,
        )


def _validate_registry() -> None:
    if len(ERROR_REGISTRY) != len(ErrorCode):
        missing = set(ErrorCode) - set(ERROR_REGISTRY)
        raise RuntimeError(f"error registry is incomplete: {sorted(missing)}")
    for code, spec in ERROR_REGISTRY.items():
        numeric = int(code)
        if not 100_000 <= numeric <= 999_999:
            raise RuntimeError(f"error code must contain six digits: {numeric}")
        if spec.default_retry_after_ms is not None and not spec.retryable:
            raise RuntimeError(f"non-retryable error has retry delay: {code.name}")


_validate_registry()
