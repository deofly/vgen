from __future__ import annotations

import json
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from vgen.cli.identity_store import DeviceIdentityStore
from vgen.cli.main import build_parser, dispatch
from vgen.cli.worker_enrollment import (
    WorkerEnrollmentError,
    enroll_worker_from_invite,
    require_pending_worker_claim,
    sign_worker_claim,
    verify_worker_claim,
    worker_approval_code,
    worker_claim_payload,
)
from vgen.cli.workspace_authorities import decorate_invite_uri, parse_pinned_invite_uri
from vgen.crypto import (
    b64url_decode,
    sign_key_manifest,
    verify_allocation_proof,
    verify_key_manifest,
)
from vgen.worker.credentials import WorkerCredentials, WorkerIdentity, load_worker_credentials_file


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


def _invite():  # type: ignore[no-untyped-def]
    _, owner = DeviceIdentityStore(MemorySecrets()).initialize()
    uri = decorate_invite_uri(
        "vgen://join/inv_credential_free#one-time-secret-with-enough-entropy",
        workspace_id="wsp_shared",
        issuer_user_id="usr_owner",
        identity=owner.root_keys,
    )
    return owner, parse_pinned_invite_uri(uri)


def test_worker_claim_signature_binds_every_public_registration_field() -> None:
    identity = WorkerIdentity.generate()
    claim = worker_claim_payload(
        identity,
        invite_id="inv_test",
        name="GPU 1",
        executor_type="comfyui",
        executor_version="1.1.0",
        capabilities={"gpu_count": 1},
        capacity=1,
    )
    signature = sign_worker_claim(identity, claim)
    assert verify_worker_claim(claim, signature)

    changed = dict(claim)
    changed["name"] = "Gateway substituted Worker"
    assert not verify_worker_claim(changed, signature)


def test_pending_claim_is_reverified_before_owner_certificate_signing() -> None:
    identity = WorkerIdentity.generate()
    claim = worker_claim_payload(
        identity,
        invite_id="inv_test",
        name="GPU 1",
        executor_type="comfyui",
        executor_version="1.1.0",
        capabilities={},
        capacity=1,
    )
    response = {
        "enrollment": {
            "id": "inv_test",
            "workspace_id": "wsp_shared",
            "issuer_user_id": "usr_owner",
            "state": "pending",
            "claim": claim,
            "proof_signature": sign_worker_claim(identity, claim),
        }
    }
    assert require_pending_worker_claim(
        response,
        enrollment_id="inv_test",
        workspace_id="wsp_shared",
        issuer_user_id="usr_owner",
        approval_code=worker_approval_code(claim),
    )["worker_key_id"] == identity.key_id

    substituted = WorkerIdentity.generate()
    substituted_claim = worker_claim_payload(
        substituted,
        invite_id="inv_test",
        name="Gateway substituted Worker",
        executor_type="comfyui",
        executor_version="1.1.0",
        capabilities={},
        capacity=1,
    )
    substituted_response = {
        "enrollment": {
            **response["enrollment"],
            "claim": substituted_claim,
            "proof_signature": sign_worker_claim(substituted, substituted_claim),
        }
    }
    with pytest.raises(WorkerEnrollmentError, match="verification code does not match"):
        require_pending_worker_claim(
            substituted_response,
            enrollment_id="inv_test",
            workspace_id="wsp_shared",
            issuer_user_id="usr_owner",
            approval_code=worker_approval_code(claim),
        )

    response["enrollment"]["claim"] = {**claim, "capacity": 2}
    with pytest.raises(WorkerEnrollmentError, match="invalid pending"):
        require_pending_worker_claim(
            response,
            enrollment_id="inv_test",
            workspace_id="wsp_shared",
            issuer_user_id="usr_owner",
            approval_code=worker_approval_code(claim),
        )


def test_credential_free_claim_generates_keys_locally_polls_with_signature_and_writes_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner, invite = _invite()
    captured_claim: dict[str, object] = {}
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST" and request.url.path.endswith("/claim"):
            body = json.loads(request.content)
            assert body["secret"] == invite.secret
            captured_claim.update(body["claim"])
            assert verify_worker_claim(body["claim"], body["proof_signature"])
            return httpx.Response(
                200,
                json={
                    "enrollment": {
                        "id": invite.invite_id,
                        "workspace_id": "wsp_shared",
                        "issuer_user_id": "usr_owner",
                        "worker_key_id": body["claim"]["worker_key_id"],
                        "state": "pending",
                    }
                },
            )
        assert request.method == "GET"
        assert request.headers.get("Signature")
        certificate = sign_key_manifest(
            owner.root_keys,
            {
                "version": 1,
                "kind": "vgen-worker-owner-certificate",
                "owner_root_key_id": owner.root_key_id,
                "worker_key_id": captured_claim["worker_key_id"],
                "worker_signing_public_key": captured_claim["signing_public_key"],
                "worker_encryption_public_key": captured_claim["encryption_public_key"],
                "issued_at": 1_800_000_000,
            },
        )
        return httpx.Response(
            200,
            json={
                "enrollment": {
                    "id": invite.invite_id,
                    "workspace_id": "wsp_shared",
                    "issuer_user_id": "usr_owner",
                    "worker_key_id": captured_claim["worker_key_id"],
                    "state": "active",
                },
                "worker": {
                    "id": "wrk_aaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "signing_public_key": captured_claim["signing_public_key"],
                    "encryption_public_key": captured_claim["encryption_public_key"],
                    "certificate": json.dumps(certificate),
                },
            },
        )

    monkeypatch.setattr(
        "vgen.cli.worker_enrollment.login_worker_session",
        lambda profile, worker_id, keys: {
            "token": "short-worker-session",
            "expires_at": 1_800_000_100,
        },
    )
    identity_path = tmp_path / "worker-identity.json"
    credentials_path = tmp_path / "worker-credentials.json"
    result = enroll_worker_from_invite(
        gateway_url="https://gateway.example",
        invite=invite,
        name="Fresh Windows GPU",
        identity_file=identity_path,
        credentials_file=credentials_path,
        interval=0.001,
        timeout=10,
        transport=httpx.MockTransport(handler),
        sleep=lambda _: None,
    )

    assert result.worker_id == "wrk_aaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert stat.S_IMODE(identity_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(credentials_path.stat().st_mode) == 0o600
    credentials = load_worker_credentials_file(credentials_path)
    assert isinstance(credentials, WorkerCredentials)
    assert credentials.worker_id == result.worker_id
    assert credentials.owner_root_signing_public_key == owner.root_signing_public_key
    assert invite.secret.encode() not in identity_path.read_bytes()
    assert invite.secret.encode() not in credentials_path.read_bytes()
    assert [request.method for request in requests] == ["POST", "GET"]


def test_claim_refuses_existing_credentials_before_contacting_gateway(tmp_path: Path) -> None:
    _, invite = _invite()
    credentials = tmp_path / "worker-credentials.json"
    credentials.write_text("do-not-replace", encoding="utf-8")
    credentials.chmod(0o600)
    with pytest.raises(WorkerEnrollmentError, match="already exist"):
        enroll_worker_from_invite(
            gateway_url="https://gateway.example",
            invite=invite,
            name="GPU",
            identity_file=tmp_path / "identity.json",
            credentials_file=credentials,
        )
    assert credentials.read_text(encoding="utf-8") == "do-not-replace"


def test_worker_add_creates_invite_waits_and_approves_atomically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, owner = DeviceIdentityStore(MemorySecrets()).initialize()
    worker_identity = WorkerIdentity.generate()
    claim = worker_claim_payload(
        worker_identity,
        invite_id="inv_test",
        name="Windows GPU",
        executor_type="comfyui",
        executor_version="1.1.0",
        capabilities={},
        capacity=1,
    )
    pending = {
        "enrollment": {
            "id": "inv_test",
            "workspace_id": "wsp_shared",
            "pool_id": "pol_shared",
            "issuer_user_id": "usr_owner",
            "state": "pending",
            "claim": claim,
            "proof_signature": sign_worker_claim(worker_identity, claim),
        },
        "allocation": {
            "id": "wal_pending",
            "workspace_id": "wsp_shared",
            "pool_id": "pol_shared",
            "worker_id": "wrk_aaaaaaaaaaaaaaaaaaaaaaaaaa",
            "owner_consent_at": 1_700_000_000.125,
        },
    }

    class ApprovalClient:
        profile = SimpleNamespace(
            name="home",
            endpoint="https://gateway.example",
            default_workspace="wsp_shared",
            default_pool=None,
            user_id="usr_owner",
            home_broker_id="brk_home",
        )

        def __init__(self) -> None:
            self.decision: dict[str, Any] | None = None

        def request(
            self,
            method: str,
            path: str,
            *,
            json_body: dict[str, Any] | None = None,
            idempotency_key: str | None = None,
        ) -> dict[str, Any]:
            del idempotency_key
            if method == "GET" and path == "/api/v1/workspaces/wsp_shared/pools":
                return [{"id": "pol_shared", "name": "Shared GPUs"}]
            if method == "POST" and path == "/api/v1/workspaces/wsp_shared/worker-invites":
                assert json_body is not None
                assert json_body["method"] == "invite_approval"
                assert json_body["pool_id"] == "pol_shared"
                assert json_body["manager_broker_id"] == "brk_home"
                return {
                    "invite_uri": "vgen://join/inv_test#one-time-secret-with-enough-entropy",
                    "enrollment": {
                        "id": "inv_test",
                        "workspace_id": "wsp_shared",
                        "issuer_user_id": "usr_owner",
                        "pool_id": "pol_shared",
                    },
                }
            if method == "GET":
                assert path == "/api/v1/worker-enrollments/inv_test"
                return pending
            assert path == "/api/v1/worker-enrollments/inv_test/decision"
            self.decision = dict(json_body or {})
            return {"enrollment": {"id": "inv_test", "state": "active"}}

        def close(self) -> None:
            pass

    client = ApprovalClient()
    monkeypatch.setattr("vgen.cli.main._client", lambda profile: client)
    monkeypatch.setattr(
        "vgen.cli.main._profile_and_identity",
        lambda profile: (client.profile, owner),
    )
    monkeypatch.setattr("builtins.input", lambda prompt: worker_approval_code(claim))
    dispatch(
        build_parser().parse_args(
            [
                "worker",
                "add",
                "--name",
                "Windows GPU",
                "--pool",
                "Shared GPUs",
            ]
        )
    )

    assert client.decision is not None
    assert client.decision["approve"] is True
    certificate = json.loads(client.decision["owner_certificate"])
    assert verify_key_manifest(
        certificate,
        b64url_decode(owner.root_signing_public_key, expected_length=32),
    )
    assert certificate["manifest"]["worker_key_id"] == worker_identity.key_id
    assert verify_allocation_proof(
        client.decision["allocation_proof"],
        b64url_decode(owner.root_signing_public_key, expected_length=32),
    )
    proof = client.decision["allocation_proof"]["payload"]
    assert proof["allocation_id"] == "wal_pending"
    assert proof["worker_id"] == "wrk_aaaaaaaaaaaaaaaaaaaaaaaaaa"
