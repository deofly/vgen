from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from vgen.gateway.app import create_app
from vgen.protocol.errors import ErrorCode


def _headers(operation: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for parameter in operation.get("parameters", []):
        reference = parameter.get("$ref", "")
        if reference:
            result[reference.rsplit("/", 1)[-1]] = parameter
    return result


def test_openapi_describes_v1_headers_security_and_error_envelope(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap-only",
        artifact_root=str(tmp_path / "artifacts"),
    )
    try:
        schema = app.openapi()
    finally:
        app.state.db.close()

    assert schema["openapi"].startswith("3.1.")
    assert schema["x-vgen-protocol-major"] == 1
    assert "VGenSession" in schema["components"]["securitySchemes"]
    assert "HTTPBearer" not in schema["components"]["securitySchemes"]
    assert "HTTPValidationError" not in schema["components"]["schemas"]
    assert "ValidationError" not in schema["components"]["schemas"]

    health = schema["paths"]["/api/v1/health"]["get"]
    assert "VgenProtocolVersion" not in _headers(health)
    assert "security" not in health

    public_write = schema["paths"]["/api/v1/auth/challenges"]["post"]
    assert set(_headers(public_write)) == {"VgenProtocolVersion"}
    assert "security" not in public_write
    assert public_write["x-vgen-idempotency-supported"] is False

    device_enrollment = schema["paths"]["/api/v1/devices/enroll"]["post"]
    assert device_enrollment["x-vgen-idempotency-supported"] is False
    assert "IdempotencyKey" not in _headers(device_enrollment)

    protected_read = schema["paths"]["/api/v1/workspaces"]["get"]
    assert protected_read["security"] == [{"VGenSession": []}]
    assert set(_headers(protected_read)) == {"VgenProtocolVersion"}

    protected_write = schema["paths"]["/api/v1/workspaces"]["post"]
    assert protected_write["security"] == [{"VGenSession": []}]
    assert set(_headers(protected_write)) == {
        "VgenProtocolVersion",
        "ContentDigest",
        "SignatureInput",
        "Signature",
        "IdempotencyKey",
    }
    assert protected_write["x-vgen-required-headers"] == [
        "Vgen-Protocol-Version",
        "Authorization",
        "Content-Digest",
        "Signature-Input",
        "Signature",
    ]
    assert schema["components"]["parameters"]["IdempotencyKey"]["required"] is False
    assert protected_write["x-vgen-idempotency-supported"] is True

    invite_write = schema["paths"]["/api/v1/workspaces/{workspace_id}/invites"]["post"]
    assert invite_write["x-vgen-idempotency-supported"] is False
    assert "IdempotencyKey" not in _headers(invite_write)
    claim_write = schema["paths"]["/api/v1/enrollments/claim"]["post"]
    assert claim_write["x-vgen-idempotency-supported"] is False
    assert "IdempotencyKey" not in _headers(claim_write)
    ticket_refresh = schema["paths"]["/api/v1/attempts/{attempt_id}/artifact-tickets"]["post"]
    assert ticket_refresh["x-vgen-idempotency-supported"] is False
    assert "IdempotencyKey" not in _headers(ticket_refresh)

    prepare = schema["paths"]["/api/v1/tasks/prepare"]["post"]
    lease = schema["paths"]["/api/v1/workers/{worker_id}/lease"]["post"]
    maintenance_create = schema["paths"][
        "/api/v1/brokers/{broker_id}/workers/{worker_id}/maintenance-jobs"
    ]["post"]
    maintenance_claim = schema["paths"][
        "/api/v1/workers/{worker_id}/maintenance-jobs/claim"
    ]["post"]
    for capability_reissuing_operation in (
        prepare,
        lease,
        maintenance_create,
        maintenance_claim,
    ):
        assert capability_reissuing_operation["x-vgen-idempotency-supported"] is True
        assert "IdempotencyKey" in _headers(capability_reissuing_operation)
        assert (
            "newly issued short-lived artifact tickets"
            in capability_reissuing_operation["x-vgen-idempotency-replay"]
        )

    for status in ("400", "401", "403", "404", "409", "422", "500", "502", "503", "504"):
        response = protected_write["responses"][status]
        assert response == {"$ref": f"#/components/responses/VGenError{status}"}
        shared_response = schema["components"]["responses"][f"VGenError{status}"]
        assert shared_response["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/ErrorEnvelope"
        }
        assert "X-Request-ID" in shared_response["headers"]

    error_schema = schema["components"]["schemas"]["VGenError"]
    assert set(error_schema["properties"]["code"]["enum"]) == {int(code) for code in ErrorCode}
    assert set(error_schema["properties"]["name"]["enum"]) == {code.name for code in ErrorCode}

    public_requirements = schema["components"]["schemas"]["VGenPublicRequirements"]
    assert public_requirements["additionalProperties"] is False
    assert "runtime_min_version" in public_requirements["properties"]
    assert (
        schema["components"]["schemas"]["TaskPrepare"]["properties"]["public_requirements"]["$ref"]
        == "#/components/schemas/VGenPublicRequirements"
    )
    assert (
        schema["components"]["schemas"]["TaskPreflight"]["properties"][
            "public_requirements"
        ]["$ref"]
        == "#/components/schemas/VGenPublicRequirements"
    )
    preflight = schema["paths"]["/api/v1/tasks/preflight"]["post"]
    assert preflight["x-vgen-idempotency-supported"] is False
    assert "live" in preflight["x-vgen-idempotency-exception"]
    media_metadata = schema["components"]["schemas"]["VGenArtifactMediaMetadata"]
    assert media_metadata["additionalProperties"] is False
    for model_name in ("ArtifactPrepare", "OutputArtifact"):
        assert (
            schema["components"]["schemas"][model_name]["properties"]["media_metadata"]["$ref"]
            == "#/components/schemas/VGenArtifactMediaMetadata"
        )


def test_openapi_generation_is_deterministic(tmp_path) -> None:
    schemas = []
    for index in range(2):
        app = create_app(
            database_path=str(tmp_path / f"gateway-{index}.db"),
            bootstrap_code=f"test-bootstrap-{index}",
            artifact_root=str(tmp_path / f"artifacts-{index}"),
        )
        try:
            schemas.append(app.openapi())
        finally:
            app.state.db.close()
    assert schemas[0] == schemas[1]


def test_runtime_validation_and_protocol_errors_match_error_envelope(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap-only",
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        invalid = client.post(
            "/api/v1/auth/challenges",
            headers={"Vgen-Protocol-Version": "1"},
            json={"unexpected": True},
        )
        assert invalid.status_code == 422
        assert invalid.json()["error"]["code"] == int(ErrorCode.VALIDATION_FAILED)
        assert invalid.json()["error"]["details"] == {
            "reason": "request_validation_failed",
            "error_count": 1,
        }
        assert invalid.headers["X-Request-ID"] == invalid.json()["error"]["request_id"]

        wrong_protocol = client.post(
            "/api/v1/auth/challenges",
            json={"principal_type": "device", "device_id": "dev_untrusted"},
        )
        assert wrong_protocol.status_code == 400
        assert wrong_protocol.json()["error"]["code"] == int(ErrorCode.PROTOCOL_VERSION_UNSUPPORTED)

        secret_enrollment = client.post(
            "/api/v1/devices/enroll",
            headers={
                "Vgen-Protocol-Version": "1",
                "Idempotency-Key": "must-not-cache-secret-response",
            },
            json={"unexpected": True},
        )
        assert secret_enrollment.status_code == 422
        cached = app.state.db.fetchone("SELECT COUNT(*) AS count FROM idempotency_records")
        assert cached["count"] == 0


def test_invalid_mutation_cannot_reflect_or_cache_private_field_names(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap-only",
        artifact_root=str(tmp_path / "artifacts"),
    )
    private_marker = "PRIVATE_PROMPT_SHOULD_NOT_PERSIST_7d19"
    with TestClient(app) as client:
        invalid = client.post(
            "/api/v1/auth/challenges",
            headers={
                "Vgen-Protocol-Version": "1",
                "Idempotency-Key": "invalid-body-must-not-cache",
            },
            json={private_marker: True},
        )
        assert invalid.status_code == 422
        assert private_marker not in invalid.text
        assert (
            app.state.db.fetchone("SELECT COUNT(*) AS count FROM idempotency_records")["count"] == 0
        )
        assert private_marker.encode() not in (tmp_path / "gateway.db").read_bytes()
