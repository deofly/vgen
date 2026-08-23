"""Stable OpenAPI contract annotations for the public Gateway v1 API."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from vgen.protocol.errors import ErrorCode, ErrorOrigin, Responsibility, RetryAction

MUTATION_METHODS = frozenset({"post", "put", "patch", "delete"})
PROTOCOL_EXEMPT_PATHS = frozenset({"/healthz"})
PROTOCOL_EXEMPT_PREFIXES = ("/api/v1/releases/",)
IDEMPOTENCY_DISABLED_EXACT_PATHS = frozenset(
    {
        # Keep the historical alias closed too, even though the current public
        # route is /api/v1/auth/bootstrap.
        "/api/v1/bootstrap",
        "/api/v1/devices/enroll",
        "/api/v1/enrollments/claim",
        "/api/v1/worker-enrollments/claim",
        # A readiness snapshot must be recomputed rather than replayed after
        # Worker liveness, capacity, capabilities, or rate approval changes.
        "/api/v1/tasks/preflight",
    }
)
IDEMPOTENCY_DISABLED_PREFIXES = (
    "/api/v1/auth/",
    "/api/v1/artifacts/transfer/",
)
_INVITE_PATH = re.compile(r"^/api/v1/workspaces/[^/]+/invites(?:/.*)?$")
_WORKER_INVITE_PATH = re.compile(r"^/api/v1/workspaces/[^/]+/worker-invites$")
_ARTIFACT_TICKET_PATH = re.compile(r"^/api/v1/attempts/[^/]+/artifact-tickets$")
_LEASE_PATH = re.compile(r"^/api/v1/workers/[^/]+/lease$")
_MAINTENANCE_CREATE_PATH = re.compile(
    r"^/api/v1/brokers/[^/]+/workers/[^/]+/maintenance-jobs$"
)
_MAINTENANCE_CLAIM_PATH = re.compile(
    r"^/api/v1/workers/[^/]+/maintenance-jobs/claim$"
)
ERROR_HTTP_STATUSES = (400, 401, 403, 404, 409, 413, 422, 429, 500, 502, 503, 504, 507)


def idempotency_cache_mode(path: str) -> str:
    """Return the response-cache policy for an actual or templated API path.

    Sensitive capability issuers are disabled by route, not by the presence of
    a particular response field. Task prepare and Worker lease use a redacted
    recipe whose capabilities are freshly minted when a response is replayed.
    """

    if (
        path in IDEMPOTENCY_DISABLED_EXACT_PATHS
        or path.startswith(IDEMPOTENCY_DISABLED_PREFIXES)
        or _INVITE_PATH.fullmatch(path)
        or _WORKER_INVITE_PATH.fullmatch(path)
        or _ARTIFACT_TICKET_PATH.fullmatch(path)
    ):
        return "disabled"
    if path == "/api/v1/tasks/prepare":
        return "task_prepare"
    if _LEASE_PATH.fullmatch(path):
        return "worker_lease"
    if _MAINTENANCE_CREATE_PATH.fullmatch(path):
        return "maintenance_create"
    if _MAINTENANCE_CLAIM_PATH.fullmatch(path):
        return "maintenance_claim"
    return "plain"


def _header_parameter(
    name: str,
    description: str,
    *,
    required: bool,
    schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "in": "header",
        "required": required,
        "description": description,
        "schema": schema or {"type": "string", "minLength": 1},
    }


def _components() -> dict[str, Any]:
    retry_actions = [action.value for action in RetryAction]
    origins = [origin.value for origin in ErrorOrigin]
    responsibilities = [responsibility.value for responsibility in Responsibility]
    error_codes = [int(code) for code in ErrorCode]
    error_names = [code.name for code in ErrorCode]
    return {
        "securitySchemes": {
            "VGenSession": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "VGen short-lived session",
                "description": (
                    "A key-bound, short-lived Gateway session obtained from the challenge "
                    "exchange. Protected mutations also require the VGen HTTP signature headers."
                ),
            },
            "VGenWorkerEnrollmentSignature": {
                "type": "apiKey",
                "in": "header",
                "name": "Signature",
                "description": (
                    "Pending Workers authenticate enrollment status reads with the locally "
                    "generated Worker signing key. Content-Digest and Signature-Input are "
                    "required, and the signature nonce is replay protected."
                ),
            }
        },
        "parameters": {
            "VgenProtocolVersion": _header_parameter(
                "Vgen-Protocol-Version",
                "Required public protocol major version.",
                required=True,
                schema={"type": "string", "enum": ["1"]},
            ),
            "ContentDigest": _header_parameter(
                "Content-Digest",
                "RFC 9530 SHA-256 digest of the exact request body covered by Signature.",
                required=True,
            ),
            "SignatureInput": _header_parameter(
                "Signature-Input",
                "RFC 9421 signature parameters for the VGen sig1 profile.",
                required=True,
            ),
            "Signature": _header_parameter(
                "Signature",
                "RFC 9421 Ed25519 HTTP message signature named sig1.",
                required=True,
            ),
            "WorkerEnrollmentContentDigest": _header_parameter(
                "Content-Digest",
                (
                    "Required only when the Worker claim-key signature alternative is used; "
                    "omit when authenticating with a Workspace issuer session."
                ),
                required=False,
            ),
            "WorkerEnrollmentSignatureInput": _header_parameter(
                "Signature-Input",
                (
                    "Required only when the Worker claim-key signature alternative is used; "
                    "omit when authenticating with a Workspace issuer session."
                ),
                required=False,
            ),
            "WorkerEnrollmentSignature": _header_parameter(
                "Signature",
                (
                    "Required only when the Worker claim-key signature alternative is used; "
                    "omit when authenticating with a Workspace issuer session."
                ),
                required=False,
            ),
            "IdempotencyKey": _header_parameter(
                "Idempotency-Key",
                (
                    "Opaque retry key scoped to principal, method, and path. Reuse only for "
                    "an identical request whose response may have been lost. Secret-bearing "
                    "authentication, Invite issuance/claim, and artifact capability operations "
                    "intentionally do not persist replay responses."
                ),
                required=False,
                schema={"type": "string", "minLength": 1, "maxLength": 512},
            ),
        },
        "schemas": {
            "VGenPublicRequirements": {
                "type": "object",
                "additionalProperties": False,
                "description": (
                    "Closed, non-sensitive scheduling facts. Prompt text, filenames, private "
                    "workflow parameters, and arbitrary metadata are forbidden."
                ),
                "properties": {
                    "operation": {
                        "type": "string",
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$",
                    },
                    "payload_format": {
                        "type": "string",
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,119}$",
                    },
                    "executor_min_version": {
                        "type": "string",
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$",
                    },
                    "runtime_min_version": {
                        "type": "string",
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$",
                    },
                    "min_vram_bytes": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 1 << 60,
                    },
                    "min_ram_bytes": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 1 << 60,
                    },
                    "model_digests": {
                        "type": "array",
                        "maxItems": 128,
                        "uniqueItems": True,
                        "items": {
                            "type": "string",
                            "pattern": r"^(?:sha256:)?[0-9a-fA-F]{64}$",
                        },
                    },
                    "output_count": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 8,
                    },
                },
            },
            "VGenArtifactMediaMetadata": {
                "type": "object",
                "additionalProperties": False,
                "description": (
                    "Closed, bounded media facts safe for Gateway scheduling and usage. "
                    "Free-form descriptions and prompt-derived text are forbidden."
                ),
                "properties": {
                    "filename": {
                        "type": "string",
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$",
                    },
                    "media_type": {
                        "type": "string",
                        "pattern": (
                            r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}/"
                            r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}$"
                        ),
                    },
                    "width": _nullable_bounded_integer(1, 131_072),
                    "height": _nullable_bounded_integer(1, 131_072),
                    "frames": _nullable_bounded_integer(0, 10_000_000),
                    "duration_ms": _nullable_bounded_integer(0, 604_800_000),
                    "denoise_steps": _nullable_bounded_integer(0, 100_000),
                    "output_count": _nullable_bounded_integer(1, 8),
                },
            },
            "VGenRetry": {
                "type": "object",
                "additionalProperties": False,
                "required": ["allowed", "action", "after_ms"],
                "properties": {
                    "allowed": {"type": "boolean"},
                    "action": {"type": "string", "enum": retry_actions},
                    "after_ms": {"type": ["integer", "null"], "minimum": 0},
                },
            },
            "VGenError": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "code",
                    "name",
                    "message",
                    "origin",
                    "retry",
                    "responsibility",
                    "request_id",
                    "task_id",
                    "attempt_id",
                    "details",
                ],
                "properties": {
                    "code": {"type": "integer", "enum": error_codes},
                    "name": {"type": "string", "enum": error_names},
                    "message": {"type": "string"},
                    "origin": {"type": "string", "enum": origins},
                    "retry": {"$ref": "#/components/schemas/VGenRetry"},
                    "responsibility": {"type": "string", "enum": responsibilities},
                    "request_id": {"type": ["string", "null"]},
                    "task_id": {"type": ["string", "null"]},
                    "attempt_id": {"type": ["string", "null"]},
                    "details": {"type": "object", "additionalProperties": True},
                },
            },
            "ErrorEnvelope": {
                "type": "object",
                "additionalProperties": False,
                "required": ["error"],
                "properties": {"error": {"$ref": "#/components/schemas/VGenError"}},
            },
        },
        "responses": {
            f"VGenError{status}": _error_response(status) for status in ERROR_HTTP_STATUSES
        },
    }


def _parameter_ref(name: str) -> dict[str, str]:
    return {"$ref": f"#/components/parameters/{name}"}


def _nullable_bounded_integer(minimum: int, maximum: int) -> dict[str, Any]:
    return {
        "type": ["integer", "null"],
        "minimum": minimum,
        "maximum": maximum,
    }


def _close_public_metadata_schemas(components: dict[str, Any]) -> None:
    """Make the frozen schema match runtime's closed plaintext-safe dictionaries."""

    schemas = components.get("schemas", {})
    for model_name in ("TaskPrepare", "TaskPreflight"):
        task_model = schemas.get(model_name, {})
        task_model.get("properties", {})["public_requirements"] = {
            "$ref": "#/components/schemas/VGenPublicRequirements"
        }
    for model_name in ("ArtifactPrepare", "OutputArtifact"):
        model = schemas.get(model_name, {})
        model.get("properties", {})["media_metadata"] = {
            "$ref": "#/components/schemas/VGenArtifactMediaMetadata"
        }


def _append_parameter(operation: dict[str, Any], name: str) -> None:
    reference = _parameter_ref(name)
    parameters = operation.setdefault("parameters", [])
    if reference not in parameters:
        parameters.append(reference)


def _uses_session(operation: dict[str, Any]) -> bool:
    return any(
        "HTTPBearer" in requirement or "VGenSession" in requirement
        for requirement in operation.get("security", [])
        if isinstance(requirement, dict)
    )


def _normalize_security(operation: dict[str, Any]) -> None:
    normalized: list[dict[str, Any]] = []
    for requirement in operation.get("security", []):
        if not isinstance(requirement, dict):
            continue
        value = dict(requirement)
        if "HTTPBearer" in value:
            value["VGenSession"] = value.pop("HTTPBearer")
        normalized.append(value)
    if normalized:
        operation["security"] = normalized


def _error_response(status: int) -> dict[str, Any]:
    headers: dict[str, Any] = {
        "X-Request-ID": {
            "description": "Opaque request correlation identifier.",
            "schema": {"type": "string"},
        }
    }
    if status == 429:
        headers["Retry-After"] = {
            "description": "Seconds until the client should retry the rate-limited request.",
            "schema": {"type": "integer", "minimum": 1},
        }
    return {
        "description": f"VGen {status} business error.",
        "headers": headers,
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorEnvelope"}}},
    }


def _add_request_id_header(response: dict[str, Any]) -> None:
    headers = response.setdefault("headers", {})
    headers.setdefault(
        "X-Request-ID",
        {
            "description": "Opaque request correlation identifier.",
            "schema": {"type": "string"},
        },
    )


def harden_openapi(schema: dict[str, Any]) -> dict[str, Any]:
    """Return a copy annotated with VGen's real authentication/error contract."""

    hardened = deepcopy(schema)
    hardened["x-vgen-protocol-major"] = 1
    components = hardened.setdefault("components", {})
    additions = _components()
    for section, values in additions.items():
        components.setdefault(section, {}).update(values)
    _close_public_metadata_schemas(components)
    components.get("securitySchemes", {}).pop("HTTPBearer", None)

    for path, path_item in hardened.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method not in {"get", "post", "put", "patch", "delete"} or not isinstance(
                operation, dict
            ):
                continue
            protected = _uses_session(operation)
            _normalize_security(operation)
            worker_enrollment_status = (
                path == "/api/v1/worker-enrollments/{enrollment_id}" and method == "get"
            )
            if worker_enrollment_status:
                operation["security"] = [
                    {"VGenSession": []},
                    {"VGenWorkerEnrollmentSignature": []},
                ]
                for name in (
                    "WorkerEnrollmentContentDigest",
                    "WorkerEnrollmentSignatureInput",
                    "WorkerEnrollmentSignature",
                ):
                    _append_parameter(operation, name)
                operation["x-vgen-authentication-alternatives"] = [
                    "Workspace issuer Device session",
                    "Worker claim-key HTTP message signature",
                ]
                operation["x-vgen-conditional-required-headers"] = {
                    "VGenSession": ["Authorization"],
                    "VGenWorkerEnrollmentSignature": [
                        "Content-Digest",
                        "Signature-Input",
                        "Signature",
                    ],
                }
                operation["x-vgen-response-cache"] = "no-store"
            if (
                path not in PROTOCOL_EXEMPT_PATHS
                and not path.startswith(PROTOCOL_EXEMPT_PREFIXES)
                and path.startswith("/api/v1/")
            ):
                _append_parameter(operation, "VgenProtocolVersion")
            if method in MUTATION_METHODS:
                cache_mode = idempotency_cache_mode(path)
                idempotency_supported = protected and cache_mode != "disabled"
                operation["x-vgen-idempotency-supported"] = idempotency_supported
                if idempotency_supported:
                    _append_parameter(operation, "IdempotencyKey")
                    if cache_mode in {
                        "task_prepare",
                        "worker_lease",
                        "maintenance_create",
                        "maintenance_claim",
                    }:
                        operation["x-vgen-idempotency-replay"] = (
                            "The Gateway persists only a capability-free response recipe. "
                            "A replay validates current Task/Attempt state and returns newly "
                            "issued short-lived artifact tickets for the original resource."
                        )
                else:
                    if path == "/api/v1/tasks/preflight":
                        operation["x-vgen-idempotency-exception"] = (
                            "Response replay caching is disabled because readiness is a live, "
                            "non-reserving snapshot that must be recomputed."
                        )
                    else:
                        operation["x-vgen-idempotency-exception"] = (
                            "Response replay caching is disabled because this operation carries "
                            "or issues authentication, Invite, or artifact capability secrets."
                        )
            if protected and method in MUTATION_METHODS:
                for name in ("ContentDigest", "SignatureInput", "Signature"):
                    _append_parameter(operation, name)
                operation["x-vgen-required-headers"] = [
                    "Vgen-Protocol-Version",
                    "Authorization",
                    "Content-Digest",
                    "Signature-Input",
                    "Signature",
                ]

            responses = operation.setdefault("responses", {})
            for response in responses.values():
                if isinstance(response, dict):
                    _add_request_id_header(response)
            for status in ERROR_HTTP_STATUSES:
                responses[str(status)] = {"$ref": f"#/components/responses/VGenError{status}"}

    # FastAPI's default validation shapes do not match the runtime exception
    # handler, which always emits ErrorEnvelope with code 600001.
    referenced = str(hardened.get("paths", {}))
    if "HTTPValidationError" not in referenced and "ValidationError" not in referenced:
        schemas = components.get("schemas", {})
        schemas.pop("HTTPValidationError", None)
        schemas.pop("ValidationError", None)
    return hardened


def install_openapi_contract(app: FastAPI) -> None:
    """Install a lazy contract generator after all routes have been registered."""

    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema is None:
            generated = get_openapi(
                title=app.title,
                version=app.version,
                openapi_version=app.openapi_version,
                summary=app.summary,
                description=app.description,
                routes=app.routes,
                tags=app.openapi_tags,
                servers=app.servers,
                terms_of_service=app.terms_of_service,
                contact=app.contact,
                license_info=app.license_info,
                separate_input_output_schemas=app.separate_input_output_schemas,
                external_docs=getattr(app, "external_docs", None),
            )
            app.openapi_schema = harden_openapi(generated)
        return app.openapi_schema

    app.openapi = custom_openapi  # type: ignore[method-assign]
