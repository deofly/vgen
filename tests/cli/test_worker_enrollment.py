from __future__ import annotations

import json
import stat
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from vgen.cli.client import VgenClientError
from vgen.cli.identity_store import DeviceIdentityStore
from vgen.cli.main import build_parser, dispatch
from vgen.cli.worker_enrollment import (
    WorkerEnrollmentError,
    enroll_worker_from_invite,
    prepare_existing_worker_credentials,
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


def test_existing_worker_credential_is_refreshed_and_pinned_after_fresh_login(
    tmp_path: Path,
) -> None:
    credentials_path = tmp_path / "worker-credentials.json"
    original = WorkerCredentials("wrk_existing", WorkerIdentity.generate().device_keys, "old")
    credentials_path.write_bytes(original.to_bytes())
    credentials_path.chmod(0o600)

    result = prepare_existing_worker_credentials(
        gateway_url="https://GATEWAY.example:443/",
        credentials_file=credentials_path,
        session_login=lambda _profile, worker_id, _keys: {
            "token": "fresh",
            "worker_id": worker_id,
        },
    )

    assert result.status == "reused"
    refreshed = load_worker_credentials_file(credentials_path)
    assert refreshed.session_token == "fresh"
    assert refreshed.gateway_url == "https://gateway.example"


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (
            VgenClientError(
                700001,
                "GATEWAY_UNREACHABLE",
                "offline",
                retry_action="later",
            ),
            "network recovers",
        ),
        (
            VgenClientError(900001, "INTERNAL_ERROR", "broken", status_code=503),
            "network recovers",
        ),
        (
            VgenClientError(
                100001,
                "AUTHENTICATION_REQUIRED",
                "misclassified upstream failure",
                status_code=503,
            ),
            "network recovers",
        ),
        (
            VgenClientError(
                600005,
                "RATE_LIMITED",
                "slow down",
                retry_action="later",
                status_code=429,
            ),
            "Retry-After",
        ),
        (
            VgenClientError(
                100001,
                "AUTHENTICATION_REQUIRED",
                "misclassified rate limit",
                retry_action="later",
                status_code=429,
            ),
            "Retry-After",
        ),
        (
            VgenClientError(100003, "SIGNATURE_INVALID", "invalid", status_code=401),
            "did not confirm",
        ),
    ],
)
def test_existing_worker_transient_or_ambiguous_failure_never_changes_credentials(
    tmp_path: Path,
    error: VgenClientError,
    message: str,
) -> None:
    credentials_path = tmp_path / "worker-credentials.json"
    credentials = WorkerCredentials(
        "wrk_existing",
        WorkerIdentity.generate().device_keys,
        "old",
        gateway_url="https://gateway.example",
    )
    credentials_path.write_bytes(credentials.to_bytes())
    credentials_path.chmod(0o600)
    before = credentials_path.read_bytes()

    def fail(_profile: object, _worker_id: str, _keys: object) -> Mapping[str, object]:
        raise error

    with pytest.raises(WorkerEnrollmentError, match=message):
        prepare_existing_worker_credentials(
            gateway_url="https://gateway.example",
            credentials_file=credentials_path,
            session_login=fail,
        )
    assert credentials_path.read_bytes() == before


def test_only_same_pinned_gateway_auth_rejection_authorizes_reenrollment(
    tmp_path: Path,
) -> None:
    credentials_path = tmp_path / "worker-credentials.json"
    credentials = WorkerCredentials(
        "wrk_existing",
        WorkerIdentity.generate().device_keys,
        "old",
        gateway_url="https://gateway.example",
    )
    credentials_path.write_bytes(credentials.to_bytes())
    credentials_path.chmod(0o600)
    before = credentials_path.read_bytes()

    def rejected(_profile: object, _worker_id: str, _keys: object) -> Mapping[str, object]:
        raise VgenClientError(
            100001,
            "AUTHENTICATION_REQUIRED",
            "rejected",
            status_code=401,
        )

    result = prepare_existing_worker_credentials(
        gateway_url="https://gateway.example",
        credentials_file=credentials_path,
        session_login=rejected,
    )
    assert result.status == "reenrollment_required"
    assert credentials_path.read_bytes() == before

    with pytest.raises(WorkerEnrollmentError, match="different Gateway"):
        prepare_existing_worker_credentials(
            gateway_url="https://other.example",
            credentials_file=credentials_path,
            session_login=lambda *_args: pytest.fail("mismatched Gateway must not be contacted"),
        )
    assert credentials_path.read_bytes() == before


def test_unpinned_auth_rejection_is_ambiguous_but_explicit_reenroll_keeps_canonical(
    tmp_path: Path,
) -> None:
    credentials_path = tmp_path / "worker-credentials.json"
    credentials = WorkerCredentials("wrk_legacy", WorkerIdentity.generate().device_keys, "old")
    credentials_path.write_bytes(credentials.to_bytes())
    credentials_path.chmod(0o600)
    before = credentials_path.read_bytes()

    def rejected(_profile: object, _worker_id: str, _keys: object) -> Mapping[str, object]:
        raise VgenClientError(100001, "AUTHENTICATION_REQUIRED", "rejected", status_code=401)

    with pytest.raises(WorkerEnrollmentError, match="older Worker credential"):
        prepare_existing_worker_credentials(
            gateway_url="https://gateway.example",
            credentials_file=credentials_path,
            session_login=rejected,
        )
    result = prepare_existing_worker_credentials(
        gateway_url="https://gateway.example",
        credentials_file=credentials_path,
        force_reenroll=True,
    )
    assert result.status == "reenrollment_required"
    assert credentials_path.read_bytes() == before


def test_explicit_reenroll_allows_private_corrupt_content_without_changing_it(
    tmp_path: Path,
) -> None:
    credentials_path = tmp_path / "worker-credentials.json"
    credentials_path.write_bytes(b"corrupt-but-private\n")
    credentials_path.chmod(0o600)

    result = prepare_existing_worker_credentials(
        gateway_url="https://gateway.example",
        credentials_file=credentials_path,
        force_reenroll=True,
    )

    assert result.status == "reenrollment_required"
    assert result.worker_id == "unknown"
    assert credentials_path.read_bytes() == b"corrupt-but-private\n"


@pytest.mark.parametrize("unsafe_kind", ["symlink", "broad_permissions"])
def test_reenrollment_rejects_unsafe_canonical_before_contacting_gateway(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    actual = tmp_path / "actual-worker-credentials.json"
    actual.write_bytes(b"private\n")
    actual.chmod(0o600)
    credentials_path = tmp_path / "worker-credentials.json"
    if unsafe_kind == "symlink":
        credentials_path.symlink_to(actual)
    else:
        credentials_path.write_bytes(b"broad\n")
        credentials_path.chmod(0o644)

    with pytest.raises(WorkerEnrollmentError, match="storage is unsafe"):
        prepare_existing_worker_credentials(
            gateway_url="https://gateway.example",
            credentials_file=credentials_path,
            force_reenroll=True,
        )

    _, invite = _invite()
    identity_path = tmp_path / "must-not-be-created.json"
    with pytest.raises(WorkerEnrollmentError, match="storage is unsafe"):
        enroll_worker_from_invite(
            gateway_url="https://gateway.example",
            invite=invite,
            name="Replacement",
            identity_file=identity_path,
            credentials_file=credentials_path,
            replace_existing_credentials=True,
            transport=httpx.MockTransport(
                lambda _request: pytest.fail("unsafe credential must fail before transport")
            ),
        )
    assert not identity_path.exists()


def test_failed_reenrollment_keeps_canonical_credential_byte_for_byte(tmp_path: Path) -> None:
    _, invite = _invite()
    credentials_path = tmp_path / "worker-credentials.json"
    original = WorkerCredentials(
        "wrk_revoked",
        WorkerIdentity.generate().device_keys,
        "old",
        gateway_url="https://gateway.example",
    )
    credentials_path.write_bytes(original.to_bytes())
    credentials_path.chmod(0o600)
    before = credentials_path.read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "enrollment": {
                    "id": invite.invite_id,
                    "workspace_id": "wsp_shared",
                    "issuer_user_id": "usr_owner",
                    "worker_key_id": body["claim"]["worker_key_id"],
                    "state": "rejected",
                }
            },
        )

    with pytest.raises(WorkerEnrollmentError, match="state 'rejected'"):
        enroll_worker_from_invite(
            gateway_url="https://gateway.example",
            invite=invite,
            name="Replacement",
            identity_file=tmp_path / "replacement-identity.json",
            credentials_file=credentials_path,
            replace_existing_credentials=True,
            transport=httpx.MockTransport(handler),
        )
    assert credentials_path.read_bytes() == before


def test_interrupted_reenrollment_keeps_canonical_and_reuses_pending_identity(
    tmp_path: Path,
) -> None:
    _, invite = _invite()
    credentials_path = tmp_path / "worker-credentials.json"
    original = WorkerCredentials(
        "wrk_revoked",
        WorkerIdentity.generate().device_keys,
        "old",
        gateway_url="https://gateway.example",
    )
    credentials_path.write_bytes(original.to_bytes())
    credentials_path.chmod(0o600)
    before = credentials_path.read_bytes()
    identity_path = tmp_path / ".worker-reenrollment-identity.json"
    claimed_key_ids: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        claimed_key_ids.append(body["claim"]["worker_key_id"])
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

    for _attempt in range(2):
        with pytest.raises(WorkerEnrollmentError, match="requires administrator approval"):
            enroll_worker_from_invite(
                gateway_url="https://gateway.example",
                invite=invite,
                name="Replacement",
                identity_file=identity_path,
                credentials_file=credentials_path,
                replace_existing_credentials=True,
                wait=False,
                transport=httpx.MockTransport(handler),
            )
        assert credentials_path.read_bytes() == before
        assert identity_path.is_file()

    assert len(claimed_key_ids) == 2
    assert claimed_key_ids[0] == claimed_key_ids[1]


def test_successful_reenrollment_replaces_canonical_only_after_session_and_keeps_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner, invite = _invite()
    credentials_path = tmp_path / "worker-credentials.json"
    original = WorkerCredentials(
        "wrk_revoked",
        WorkerIdentity.generate().device_keys,
        "old",
        gateway_url="https://gateway.example",
    )
    credentials_path.write_bytes(original.to_bytes())
    credentials_path.chmod(0o600)
    before = credentials_path.read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        claim = body["claim"]
        certificate = sign_key_manifest(
            owner.root_keys,
            {
                "version": 1,
                "kind": "vgen-worker-owner-certificate",
                "owner_root_key_id": owner.root_key_id,
                "worker_key_id": claim["worker_key_id"],
                "worker_signing_public_key": claim["signing_public_key"],
                "worker_encryption_public_key": claim["encryption_public_key"],
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
                    "worker_key_id": claim["worker_key_id"],
                    "state": "active",
                },
                "worker": {
                    "id": "wrk_bbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "signing_public_key": claim["signing_public_key"],
                    "encryption_public_key": claim["encryption_public_key"],
                    "certificate": json.dumps(certificate),
                },
            },
        )

    canonical_during_login: list[bytes] = []

    def login(_profile: object, worker_id: str, _keys: object) -> Mapping[str, object]:
        canonical_during_login.append(credentials_path.read_bytes())
        return {"token": "new-session", "worker_id": worker_id}

    monkeypatch.setattr("vgen.cli.worker_enrollment.login_worker_session", login)
    result = enroll_worker_from_invite(
        gateway_url="https://gateway.example",
        invite=invite,
        name="Replacement",
        identity_file=tmp_path / "replacement-identity.json",
        credentials_file=credentials_path,
        replace_existing_credentials=True,
        transport=httpx.MockTransport(handler),
    )

    assert canonical_during_login == [before]
    assert result.previous_credentials_archive is not None
    assert result.previous_credentials_archive.read_bytes() == before
    replacement = load_worker_credentials_file(credentials_path)
    assert replacement.worker_id == "wrk_bbbbbbbbbbbbbbbbbbbbbbbbbb"
    assert replacement.session_token == "new-session"
    assert replacement.gateway_url == "https://gateway.example"


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
