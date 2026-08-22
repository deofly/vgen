from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import vgen.cli.auth as auth_module
from vgen.cli.identity_store import DeviceIdentity
from vgen.cli.profile import GatewayProfile
from vgen.crypto import (
    DeviceKeys,
    IdentityKeys,
    b64url_decode,
    b64url_encode,
    issue_device_certificate,
    verify_message,
)
from vgen.protocol import new_id


def _identity() -> DeviceIdentity:
    root = IdentityKeys(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())
    device = DeviceKeys.generate()
    device_id = new_id("device")
    certificate = issue_device_certificate(root, device, device_id=device_id)
    return DeviceIdentity(
        alias="default",
        root_key_id=root.root_key_id,
        root_signing_public_key=b64url_encode(root.signing_public_bytes()),
        root_encryption_public_key=b64url_encode(root.encryption_public_bytes()),
        root_keys=root,
        device_id=device_id,
        device_keys=device,
        certificate=certificate,
    )


def test_login_uses_gateway_device_schema_and_certificate(monkeypatch) -> None:
    identity = _identity()
    profile = GatewayProfile("local", "http://127.0.0.1:8000")
    calls: list[tuple[str, dict]] = []

    class FakeClient:
        def __init__(self, _profile) -> None:
            pass

        def request(self, method, path, *, json_body, auth):
            assert method == "POST"
            assert auth is False
            calls.append((path, json_body))
            if path.endswith("/challenges"):
                return {"challenge_id": "chl_test", "challenge": "signed-challenge"}
            return {
                "session_token": "short-session",
                "expires_at": 4_000_000_000,
                "user_id": "usr_test",
                "device_id": identity.device_id,
            }

        def close(self) -> None:
            pass

    stored: list[object] = []
    bindings: list[dict] = []

    class FakeSessionStore:
        def save(self, profile_name, session) -> None:
            stored.append((profile_name, session))

    class FakeProfileStore:
        def update_binding(self, profile_name, **values) -> None:
            bindings.append({"profile": profile_name, **values})

    monkeypatch.setattr(auth_module, "GatewayClient", FakeClient)
    monkeypatch.setattr(auth_module, "SessionStore", FakeSessionStore)
    monkeypatch.setattr(auth_module, "ProfileStore", FakeProfileStore)

    session = auth_module.login_session(profile, identity)

    assert session.token == "short-session"
    assert calls[0] == (
        "/api/v1/auth/challenges",
        {"principal_type": "device", "device_id": identity.device_id},
    )
    session_body = calls[1][1]
    assert "principal_id" not in session_body
    assert session_body["device_id"] == identity.device_id
    assert session_body["device_certificate"] == identity.certificate.to_dict()
    assert session_body["root_key_id"] == identity.root_key_id
    assert verify_message(
        identity.device_keys.signing_public_key,
        b"signed-challenge",
        b64url_decode(session_body["signature"], expected_length=64),
    )
    assert stored and bindings == [
        {"profile": "local", "user_id": "usr_test", "device_id": identity.device_id}
    ]


def test_worker_login_proves_worker_key_possession(monkeypatch) -> None:
    keys = DeviceKeys.generate()
    profile = GatewayProfile("local", "http://127.0.0.1:8000")
    calls: list[tuple[str, dict]] = []

    class FakeClient:
        def __init__(self, _profile) -> None:
            pass

        def request(self, method, path, *, json_body, auth):
            assert method == "POST"
            assert auth is False
            calls.append((path, json_body))
            if path.endswith("/challenges"):
                return {"challenge_id": "chl_worker", "challenge": "worker-challenge"}
            return {
                "session_token": "worker-session",
                "expires_at": 4_000_000_000,
                "worker_id": "wrk_test",
            }

        def close(self) -> None:
            pass

    monkeypatch.setattr(auth_module, "GatewayClient", FakeClient)
    session = auth_module.login_worker_session(profile, "wrk_test", keys)

    assert session["token"] == "worker-session"
    assert calls[0][1] == {"principal_type": "worker", "worker_id": "wrk_test"}
    body = calls[1][1]
    assert body["worker_id"] == "wrk_test"
    assert verify_message(
        keys.signing_public_key,
        b"worker-challenge",
        b64url_decode(body["signature"], expected_length=64),
    )


def test_service_login_uses_service_schema_and_own_key(monkeypatch) -> None:
    keys = DeviceKeys.generate()
    profile = GatewayProfile("local", "http://127.0.0.1:8000")
    calls: list[tuple[str, dict]] = []

    class FakeClient:
        def __init__(self, _profile) -> None:
            pass

        def request(self, method, path, *, json_body, auth):
            assert method == "POST"
            assert auth is False
            calls.append((path, json_body))
            if path.endswith("/challenges"):
                return {"challenge_id": "chl_service", "challenge": "service-challenge"}
            return {
                "session_token": "service-session",
                "expires_at": 4_000_000_000,
                "service_id": "svc_test",
            }

        def close(self) -> None:
            pass

    monkeypatch.setattr(auth_module, "GatewayClient", FakeClient)
    session = auth_module.login_service_session(profile, "svc_test", keys)

    assert session == {
        "token": "service-session",
        "expires_at": 4_000_000_000.0,
        "service_id": "svc_test",
    }
    assert calls[0][1] == {"principal_type": "service", "service_id": "svc_test"}
    body = calls[1][1]
    assert body["principal_type"] == "service"
    assert body["service_id"] == "svc_test"
    assert "device_id" not in body and "user_id" not in body
    assert verify_message(
        keys.signing_public_key,
        b"service-challenge",
        b64url_decode(body["signature"], expected_length=64),
    )
