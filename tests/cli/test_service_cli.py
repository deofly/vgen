from __future__ import annotations

import argparse
import json

import vgen.cli.main as cli_main
from vgen.cli.profile import GatewayProfile
from vgen.cli.service_credentials import ServiceCredentials, StoredServiceSession
from vgen.cli.workspace_authorities import PinnedInvite, WorkspaceAuthorityPin
from vgen.crypto import (
    DeviceKeys,
    b64url_decode,
    b64url_encode,
    canonical_json,
    identity_init,
    verify_message,
)


def test_service_enroll_proves_new_key_and_never_prints_secret_or_session(
    monkeypatch, capsys
) -> None:
    original = GatewayProfile("team", "https://gateway.example", default_workspace="wsp_old")
    profiles = {"team": original}
    requests: list[dict] = []
    saved = []
    sessions = []
    authority_pins = []
    issuer = identity_init().keys

    class FakeProfileStore:
        def get(self, name=None):
            assert name in {None, "team"}
            return profiles["team"]

        def update_binding(self, name, **updates):
            raw = vars(profiles[name]).copy()
            raw.update(updates)
            raw.pop("name", None)
            profiles[name] = GatewayProfile(name=name, **raw)
            return profiles[name]

    class FakeClient:
        def __init__(self, profile):
            assert profile.name == "team"

        def request(self, method, path, *, json_body, auth):
            assert method == "POST"
            assert path == "/api/v1/auth/services/enroll"
            assert auth is False
            requests.append(json_body)
            return {
                "service": {
                    "id": "svc_test",
                    "workspace_id": "wsp_test",
                    "name": "build-api",
                    "scopes": ["task:submit", "task:read"],
                    "status": "active",
                },
                "enrollment": {
                    "id": "enr_test",
                    "state": "active",
                    "issuer_user_id": "usr_owner",
                },
            }

        def close(self):
            pass

    class FakeCredentialStore:
        def save(self, account, credentials, *, file_path, overwrite):
            saved.append((account, credentials, file_path, overwrite))

    class FakeSessionStore:
        def save(self, profile_name, session):
            sessions.append((profile_name, session))

    class FakeAuthorityStore:
        def pin(self, **values):
            authority_pins.append(values)

        def pin_owner(self, **values):
            authority_pins.append(values)

    monkeypatch.setattr(cli_main, "ProfileStore", FakeProfileStore)
    monkeypatch.setattr(cli_main, "GatewayClient", FakeClient)
    monkeypatch.setattr(cli_main, "ServiceCredentialStore", FakeCredentialStore)
    monkeypatch.setattr(cli_main, "ServiceSessionStore", FakeSessionStore)
    monkeypatch.setattr(cli_main, "WorkspaceAuthorityStore", FakeAuthorityStore)
    monkeypatch.setattr(
        cli_main,
        "_read_invite",
        lambda: PinnedInvite(
            invite_id="enr_test",
            secret="invite-secret-value",
            authority=WorkspaceAuthorityPin(
                workspace_id="wsp_test",
                user_id="usr_owner",
                root_signing_public_key=b64url_encode(issuer.signing_public_bytes()),
                root_key_id=issuer.root_key_id,
                source="signed_invite_fragment",
            ),
        ),
    )
    monkeypatch.setattr(
        cli_main,
        "login_service_session",
        lambda profile, service_id, keys: {
            "token": "must-not-print",
            "expires_at": 4_000_000_000,
            "service_id": service_id,
        },
    )
    cli_main._service_command(
        argparse.Namespace(
            service_action="enroll",
            invite_stdin=True,
            name="build-api",
            credentials_account="prod",
            credentials_file=None,
            overwrite=False,
            use=True,
            profile="team",
        )
    )

    body = requests[0]
    claim = {
        key: body[key]
        for key in (
            "version",
            "invite_id",
            "name",
            "signing_public_key",
            "encryption_public_key",
        )
    }
    assert verify_message(
        b64url_decode(body["signing_public_key"], expected_length=32),
        canonical_json(claim),
        b64url_decode(body["proof_signature"], expected_length=64),
        context=b"vgen-service-enrollment-v1",
    )
    assert saved[0][0] == "prod"
    assert saved[0][1].service_id == "svc_test"
    assert sessions[0][0] == "team"
    assert profiles["team"].principal_type == "service"
    assert profiles["team"].service_id == "svc_test"
    assert authority_pins[0]["workspace_id"] == "wsp_test"

    output = capsys.readouterr().out
    decoded = json.loads(output)
    assert decoded["service_id"] == "svc_test"
    assert "invite-secret-value" not in output
    assert "must-not-print" not in output
    assert "private" not in output


def test_service_parser_exposes_lifecycle_without_accepting_keys_on_command_line() -> None:
    parser = cli_main.build_parser()
    enroll = parser.parse_args(
        [
            "service",
            "enroll",
            "--invite-stdin",
            "--name",
            "automation",
            "--credentials-file",
            "/tmp/service.json",
        ]
    )
    assert enroll.command == "service"
    assert enroll.credentials_file.name == "service.json"
    for action in ("login", "logout", "show", "key-sync", "revoke-local"):
        parsed = parser.parse_args(["service", action])
        assert parsed.service_action == action


def test_generic_client_uses_only_service_credentials_for_service_profile(monkeypatch) -> None:
    profile = GatewayProfile(
        "api",
        "https://gateway.example",
        principal_type="service",
        service_id="svc_test",
        service_key_ref="production",
    )
    credentials = ServiceCredentials.generate(
        service_id="svc_test",
        workspace_id="wsp_test",
        name="automation",
        scopes=["task:read"],
        enrollment_id="enr_test",
        device_keys=DeviceKeys.generate(),
    )
    captured = {}

    class FakeProfileStore:
        def get(self, name=None):
            assert name == "api"
            return profile

    class FakeCredentialStore:
        def load(self, account, *, file_path):
            assert account == "production"
            assert file_path is None
            return credentials

    class FakeSessionStore:
        def load(self, profile_name, service_id):
            assert (profile_name, service_id) == ("api", "svc_test")
            return StoredServiceSession("service-session", 4_000_000_000, "svc_test")

    class FakeGatewayClient:
        def __init__(self, selected, **kwargs):
            captured["profile"] = selected
            captured.update(kwargs)

    class ForbiddenDeviceStore:
        def load(self, *_args, **_kwargs):
            raise AssertionError("a Service profile must not load a User Device key")

    monkeypatch.setattr(cli_main, "ProfileStore", FakeProfileStore)
    monkeypatch.setattr(cli_main, "ServiceCredentialStore", FakeCredentialStore)
    monkeypatch.setattr(cli_main, "ServiceSessionStore", FakeSessionStore)
    monkeypatch.setattr(cli_main, "GatewayClient", FakeGatewayClient)
    monkeypatch.setattr(cli_main, "DeviceIdentityStore", ForbiddenDeviceStore)

    cli_main._client("api")

    assert captured["profile"] is profile
    assert captured["session_token"] == "service-session"
    signature_headers = captured["signer"]("POST", "/api/v1/tasks/prepare", b"{}")
    assert credentials.device_keys.key_id in signature_headers["Signature-Input"]
