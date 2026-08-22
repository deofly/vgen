from __future__ import annotations

import json
from argparse import Namespace
from dataclasses import replace

import httpx
import pytest

import vgen.cli.main as cli_main
from vgen.cli.client import GatewayClient, VgenClientError, cli_exit_code
from vgen.cli.profile import GatewayProfile, ProfileError, ProfileStore
from vgen.cli.session_store import StoredSession


def test_profile_roundtrip_and_binding(tmp_path) -> None:
    store = ProfileStore(tmp_path / "profiles.yaml")
    store.put(GatewayProfile(name="local", endpoint="http://127.0.0.1:8000/"))
    assert store.get().endpoint == "http://127.0.0.1:8000"
    store.update_binding(
        "local",
        user_id="usr_1",
        default_workspace="ws_1",
        default_pool="pol_1",
        home_broker_id="brk_1",
        home_broker_device_id="bdev_1",
    )
    assert store.get("local").user_id == "usr_1"
    assert store.get("local").default_pool == "pol_1"
    assert store.get("local").home_broker_device_id == "bdev_1"


def test_profile_can_bind_an_explicit_service_principal(tmp_path) -> None:
    store = ProfileStore(tmp_path / "profiles.yaml")
    store.put(GatewayProfile(name="api", endpoint="https://gateway.example"))
    bound = store.update_binding(
        "api",
        principal_type="service",
        service_id="svc_test",
        service_key_ref="prod-api",
        default_workspace="wsp_test",
    )
    assert bound.principal_type == "service"
    assert store.get("api").service_id == "svc_test"
    assert store.get("api").service_key_ref == "prod-api"


def test_endpoint_set_verifies_identity_and_preserves_all_bindings(
    tmp_path, monkeypatch, capsys
) -> None:
    store = ProfileStore(tmp_path / "profiles.yaml")
    original = GatewayProfile(
        name="home",
        endpoint="https://old-gateway.example",
        user_id="usr_same",
        device_id="dev_same",
        default_workspace="wsp_keep",
        default_pool="pol_keep",
        home_broker_id="brk_keep",
        key_ref="personal",
    )
    store.put(original)

    class HealthyClient:
        def __init__(self, profile) -> None:
            assert profile.endpoint == "https://new-gateway.example"

        def health(self):
            return {"ok": True}

        def close(self) -> None:
            pass

    class IdentityStore:
        def load(self, alias):
            assert alias == "personal"
            return object()

    deleted: list[str] = []

    class Sessions:
        def delete(self, profile_name):
            deleted.append(profile_name)

    monkeypatch.setattr(cli_main, "ProfileStore", lambda: store)
    monkeypatch.setattr(cli_main, "GatewayClient", HealthyClient)
    monkeypatch.setattr(cli_main, "DeviceIdentityStore", IdentityStore)
    monkeypatch.setattr(cli_main, "SessionStore", Sessions)
    monkeypatch.setattr(
        cli_main,
        "authenticate_device_session",
        lambda profile, _identity: StoredSession(
            token="verified",
            expires_at=4_000_000_000,
            user_id="usr_same",
            device_id="dev_same",
        ),
    )

    cli_main._profile_command(
        Namespace(
            profile_action="endpoint-set",
            profile="home",
            endpoint="https://new-gateway.example",
        )
    )

    updated = store.get("home")
    assert updated == replace(original, endpoint="https://new-gateway.example")
    assert deleted == ["home"]
    response = json.loads(capsys.readouterr().out)
    assert response["verified"] is True
    assert response["next"] == "vgen broker service-refresh --profile home"


def test_endpoint_set_refuses_a_different_gateway_identity(tmp_path, monkeypatch) -> None:
    store = ProfileStore(tmp_path / "profiles.yaml")
    original = GatewayProfile(
        name="home",
        endpoint="https://old-gateway.example",
        user_id="usr_expected",
        device_id="dev_expected",
    )
    store.put(original)

    class HealthyClient:
        def __init__(self, _profile) -> None:
            pass

        def health(self):
            return {"ok": True}

        def close(self) -> None:
            pass

    monkeypatch.setattr(cli_main, "ProfileStore", lambda: store)
    monkeypatch.setattr(cli_main, "GatewayClient", HealthyClient)
    monkeypatch.setattr(
        cli_main,
        "DeviceIdentityStore",
        type("IdentityStore", (), {"load": lambda self, alias: object()}),
    )
    monkeypatch.setattr(
        cli_main,
        "authenticate_device_session",
        lambda profile, _identity: StoredSession(
            token="wrong",
            expires_at=4_000_000_000,
            user_id="usr_other",
            device_id="dev_expected",
        ),
    )

    with pytest.raises(ValueError, match="different User"):
        cli_main._profile_command(
            Namespace(
                profile_action="endpoint-set",
                profile="home",
                endpoint="https://new-gateway.example",
            )
        )
    assert store.get("home") == original


def test_service_profile_requires_exactly_one_local_credential_source() -> None:
    with pytest.raises(ProfileError, match="exactly one"):
        GatewayProfile(
            "api",
            "https://gateway.example",
            principal_type="service",
            service_id="svc_test",
        )
    with pytest.raises(ProfileError, match="exactly one"):
        GatewayProfile(
            "api",
            "https://gateway.example",
            principal_type="service",
            service_id="svc_test",
            service_key_ref="prod-api",
            service_credentials_file="/tmp/service.json",
        )


def test_client_synthesizes_unreachable_error() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    client = GatewayClient(
        GatewayProfile(name="local", endpoint="http://127.0.0.1:8000"),
        transport=httpx.MockTransport(fail),
    )
    try:
        client.health()
    except VgenClientError as exc:
        assert exc.code == 700001
        assert exc.retry_action == "later"
        assert exc.exit_code == 5
    else:
        raise AssertionError("transport error was not converted")


def test_client_parses_numeric_error_envelope() -> None:
    def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            json={
                "error": {
                    "code": 310002,
                    "name": "REKEY_REQUIRED",
                    "message": "Task key must be rewrapped.",
                    "retry": {"allowed": True, "action": "rekey_required"},
                    "details": {"task_id": "tsk_1"},
                }
            },
        )

    client = GatewayClient(
        GatewayProfile(name="local", endpoint="http://127.0.0.1:8000"),
        transport=httpx.MockTransport(respond),
    )
    try:
        client.request("POST", "/api/v1/tasks/tsk_1/commit", json_body={})
    except VgenClientError as exc:
        assert exc.code == 310002
        assert exc.retry_action == "rekey_required"
    else:
        raise AssertionError("Gateway error was not raised")


def test_client_signs_canonical_query_and_refreshes_expired_session() -> None:
    signed: list[tuple[str, str, bytes]] = []
    tokens: list[str] = []

    def signer(method: str, path: str, body: bytes) -> dict[str, str]:
        signed.append((method, path, body))
        return {"Signature": f"test-{len(signed)}"}

    def respond(request: httpx.Request) -> httpx.Response:
        tokens.append(request.headers.get("Authorization", ""))
        if len(tokens) == 1:
            return httpx.Response(
                401,
                json={
                    "error": {
                        "code": 100002,
                        "name": "SESSION_EXPIRED",
                        "message": "expired",
                        "retry": {"action": "later"},
                    }
                },
            )
        return httpx.Response(200, json={"ok": True})

    client = GatewayClient(
        GatewayProfile(name="local", endpoint="http://127.0.0.1:8000"),
        session_token="old",
        signer=signer,
        token_refresher=lambda: "new",
        transport=httpx.MockTransport(respond),
    )
    assert client.request("GET", "/api/v1/tasks", params={"limit": 5}) == {"ok": True}
    assert tokens == ["Bearer old", "Bearer new"]
    assert signed == [
        ("GET", "/api/v1/tasks?limit=5", b""),
        ("GET", "/api/v1/tasks?limit=5", b""),
    ]


def test_client_uses_fixed_worker_maintenance_routes_and_bodies() -> None:
    requests: list[tuple[str, str, object | None]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        requests.append((request.method, request.url.path, body))
        return httpx.Response(200, json={"id": "mtj_example"})

    client = GatewayClient(
        GatewayProfile(name="local", endpoint="http://127.0.0.1:8000"),
        transport=httpx.MockTransport(respond),
    )
    authorization = {
        "payload": {"kind": "vgen-worker-maintenance-intent"},
        "device_certificate": {},
        "signature": "signed",
    }
    spec = {
        "kind": "worker_update",
        "target_version": "0.2.0",
        "artifact_sha256": "a" * 64,
        "artifact_size": 123,
        "apply": "on_idle",
    }
    try:
        client.set_worker_manager("wrk_example", "brk_home")
        client.create_worker_maintenance(
            broker_id="brk_home",
            worker_id="wrk_example",
            spec=spec,
            authorization=authorization,
            idempotency_key="maintenance-example",
        )
        client.commit_worker_maintenance("mtj_example")
        client.list_worker_maintenance("wrk_example")
        client.get_worker_maintenance("mtj_example")
        client.cancel_worker_maintenance("mtj_example")
    finally:
        client.close()

    assert requests == [
        (
            "POST",
            "/api/v1/workers/wrk_example/manager",
            {"broker_id": "brk_home"},
        ),
        (
            "POST",
            "/api/v1/brokers/brk_home/workers/wrk_example/maintenance-jobs",
            {"spec": spec, "authorization": authorization},
        ),
        ("POST", "/api/v1/maintenance-jobs/mtj_example/commit", {}),
        ("GET", "/api/v1/workers/wrk_example/maintenance-jobs", None),
        ("GET", "/api/v1/maintenance-jobs/mtj_example", None),
        ("POST", "/api/v1/maintenance-jobs/mtj_example/cancel", {}),
    ]


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://localhost.evil.example",
        "http://127.0.0.1.evil.example",
        "https://user:secret@gateway.example",
        "https://gateway.example/api",
        "https://gateway.example?token=secret",
        "https://gateway.example#fragment",
        "https://",
    ],
)
def test_gateway_profile_rejects_unsafe_endpoint(endpoint: str) -> None:
    with pytest.raises(ProfileError):
        GatewayProfile("unsafe", endpoint)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://localhost:8000/",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
        "https://gateway.example",
    ],
)
def test_gateway_profile_accepts_secure_origin(endpoint: str) -> None:
    profile = GatewayProfile("safe", endpoint)
    assert profile.endpoint == endpoint.rstrip("/")


@pytest.mark.parametrize(
    ("code", "retry_action", "expected"),
    [
        (120001, "none", 3),
        (200001, "none", 4),
        (220001, "later", 5),
        (300001, "none", 4),
        (310002, "rekey_required", 5),
        (320003, "none", 6),
        (330001, "none", 7),
        (340008, "none", 6),
        (340006, "later", 5),
        (400001, "none", 7),
        (500002, "none", 8),
        (600001, "none", 2),
        (700001, "later", 5),
        (900001, "none", 1),
    ],
)
def test_cli_exit_code_contract(code: int, retry_action: str, expected: int) -> None:
    assert cli_exit_code(code, retry_action=retry_action) == expected
