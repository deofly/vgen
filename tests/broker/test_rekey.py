from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from vgen.broker.journal import BrokerJournal
from vgen.broker.rekey import BrokerRekeyError, BrokerRekeyHandler
from vgen.cli.client import VgenClientError
from vgen.cli.workspace_authorities import WorkspaceAuthorityStore
from vgen.crypto import (
    DeviceKeys,
    HpkeCiphertext,
    b64url_encode,
    build_allocation_proof_payload,
    device_key_id,
    identity_init,
    sign_allocation_proof,
    sign_key_manifest,
    task_aad,
    unwrap_task_key,
    wrap_task_key_for_workspace,
)


class MemoryWorkspaceKeys:
    def __init__(self, workspace_id: str, version: int, key: bytes) -> None:
        self.workspace_id = workspace_id
        self.version = version
        self.key = key

    def load(self, workspace_id: str, version: int = 1) -> bytes:
        assert (workspace_id, version) == (self.workspace_id, self.version)
        return self.key


class MemoryKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))


def pinned_authorities(values: dict[tuple[str, str], dict[str, Any]]) -> WorkspaceAuthorityStore:
    retry = next(value for (method, path), value in values.items() if path.endswith("/retry"))
    allocation = retry["allocation"]
    store = WorkspaceAuthorityStore(backend=MemoryKeyring())
    store.pin(
        workspace_id=retry["workspace_id"],
        user_id=allocation["admin_user_id"],
        root_signing_public_key=allocation["admin_root_signing_public_key"],
        root_key_id=allocation["proof"]["payload"]["approver_root_key_id"],
        source="test",
    )
    return store


class FakeGateway:
    def __init__(self, values: dict[tuple[str, str], dict[str, Any]]) -> None:
        self.values = values
        self.calls: list[dict[str, Any]] = []
        self.fail_rekey: VgenClientError | None = None

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        idempotency_key: str | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "method": method,
                "path": path,
                "json_body": json_body,
                "idempotency_key": idempotency_key,
            }
        )
        if path.endswith("/rekey") and self.fail_rekey is not None:
            raise self.fail_rekey
        return self.values[(method, path)]


def rekey_fixture() -> tuple[
    dict[str, Any], dict[tuple[str, str], dict[str, Any]], bytes, bytes, DeviceKeys
]:
    workspace_id = "wsp_test"
    pool_id = "pol_test"
    task_id = "tsk_test"
    content_attempt_id = "atm_original"
    retry_attempt_id = "atm_retry"
    worker_id = "wrk_replacement"
    allocation_id = "wal_test"
    key_version = 1
    workspace_key = b"w" * 32
    task_key = b"t" * 32

    owner = identity_init().keys
    worker_keys = DeviceKeys.generate()
    worker_signing = b64url_encode(worker_keys.signing_public_bytes())
    worker_encryption = b64url_encode(worker_keys.encryption_public_bytes())
    certificate = sign_key_manifest(
        owner,
        {
            "version": 1,
            "kind": "vgen-worker-owner-certificate",
            "owner_root_key_id": owner.root_key_id,
            "worker_key_id": device_key_id(worker_keys.signing_public_bytes()),
            "worker_signing_public_key": worker_signing,
            "worker_encryption_public_key": worker_encryption,
            "issued_at": int(time.time()),
        },
    )
    consent_at = time.time() - 30
    proof_payload = build_allocation_proof_payload(
        allocation_id=allocation_id,
        workspace_id=workspace_id,
        pool_id=pool_id,
        worker_id=worker_id,
        worker_signing_public_key=worker_signing,
        worker_encryption_public_key=worker_encryption,
        worker_certificate=certificate,
        owner_consent_at=consent_at,
        approver_root_key_id=owner.root_key_id,
    )
    proof = sign_allocation_proof(owner, proof_payload)
    reader = wrap_task_key_for_workspace(
        workspace_key,
        task_key,
        aad=task_aad(
            workspace_id=workspace_id,
            task_id=task_id,
            attempt_id=content_attempt_id,
            key_version=key_version,
        ),
    )
    worker = {
        "id": worker_id,
        "signing_public_key": worker_signing,
        "encryption_public_key": worker_encryption,
        "owner_root_signing_public_key": b64url_encode(owner.signing_public_bytes()),
        "certificate": certificate,
    }
    retry = {
        "task_id": task_id,
        "workspace_id": workspace_id,
        "pool_id": pool_id,
        "key_version": key_version,
        "attempt_id": retry_attempt_id,
        "worker": worker,
        "allocation": {
            "id": allocation_id,
            "owner_consent_at": consent_at,
            "proof": proof,
            "admin_user_id": "usr_admin",
            "admin_root_signing_public_key": b64url_encode(owner.signing_public_bytes()),
        },
    }
    command = {
        "id": "bcm_test",
        "command_type": "task_rekey",
        "payload": {
            "version": 1,
            "task_id": task_id,
            "workspace_id": workspace_id,
            "key_version": key_version,
            "source_attempt_id": content_attempt_id,
            "reason": "lease_expired",
        },
    }
    values = {
        ("GET", f"/api/v1/tasks/{task_id}"): {
            "id": task_id,
            "workspace_id": workspace_id,
            "state": "rekey_required",
        },
        ("GET", f"/api/v1/tasks/{task_id}/reader-envelope"): {
            "task_id": task_id,
            "workspace_id": workspace_id,
            "key_version": key_version,
            "content_attempt_id": content_attempt_id,
            "reader_envelope": json.dumps(reader.to_dict(), separators=(",", ":")),
        },
        ("POST", f"/api/v1/tasks/{task_id}/retry"): retry,
        ("POST", f"/api/v1/tasks/{task_id}/rekey"): {
            "task_id": task_id,
            "state": "committed",
            "worker_id": worker_id,
        },
    }
    return command, values, workspace_key, task_key, worker_keys


def test_broker_rekeys_without_persisting_task_key(tmp_path: Path) -> None:
    command, values, workspace_key, task_key, worker_keys = rekey_fixture()
    client = FakeGateway(values)
    journal_path = tmp_path / "broker.db"
    journal = BrokerJournal(journal_path)
    handler = BrokerRekeyHandler(
        client,  # type: ignore[arg-type]
        journal,
        workspace_keys=MemoryWorkspaceKeys("wsp_test", 1, workspace_key),  # type: ignore[arg-type]
        workspace_authorities=pinned_authorities(values),
    )

    result = handler(command)

    assert result == {
        "status": "rekeyed",
        "task_id": "tsk_test",
        "attempt_id": "atm_retry",
        "worker_id": "wrk_replacement",
        "task_state": "committed",
    }
    mutation = next(call for call in client.calls if call["path"].endswith("/rekey"))
    wrapped = HpkeCiphertext.from_dict(json.loads(mutation["json_body"]["worker_tdk_envelope"]))
    assert (
        unwrap_task_key(
            worker_keys.encryption_private_key,
            wrapped,
            aad=task_aad(
                workspace_id="wsp_test",
                task_id="tsk_test",
                attempt_id="atm_retry",
                key_version=1,
            ),
        )
        == task_key
    )
    assert [call["path"].rsplit("/", 1)[-1] for call in client.calls] == [
        "tsk_test",
        "reader-envelope",
        "retry",
        "rekey",
    ]
    retry_call = next(call for call in client.calls if call["path"].endswith("/retry"))
    assert retry_call["idempotency_key"] == "broker-retry:bcm_test:0"
    assert mutation["idempotency_key"] == "broker-rekey:bcm_test:atm_retry"
    journal.close()
    raw_journal = journal_path.read_bytes()
    assert task_key not in raw_journal
    assert workspace_key not in raw_journal
    assert b64url_encode(task_key).encode() not in raw_journal


def test_expired_rekey_reservation_advances_only_public_retry_generation(
    tmp_path: Path,
) -> None:
    command, values, workspace_key, _, _ = rekey_fixture()
    client = FakeGateway(values)
    client.fail_rekey = VgenClientError(
        310003,
        "RESERVATION_EXPIRED",
        "reservation expired",
        status_code=409,
    )
    journal = BrokerJournal(tmp_path / "broker.db")
    handler = BrokerRekeyHandler(
        client,  # type: ignore[arg-type]
        journal,
        workspace_keys=MemoryWorkspaceKeys("wsp_test", 1, workspace_key),  # type: ignore[arg-type]
        workspace_authorities=pinned_authorities(values),
    )

    with pytest.raises(VgenClientError, match="reservation expired"):
        handler(command)

    assert journal.get_state("command:bcm_test") == {
        "retry_generation": 1,
        "last_attempt_id": "atm_retry",
    }
    journal.close()


def test_invalid_workspace_allocation_never_receives_task_key(tmp_path: Path) -> None:
    command, values, workspace_key, _, _ = rekey_fixture()
    retry = values[("POST", "/api/v1/tasks/tsk_test/retry")]
    retry["allocation"]["proof"]["payload"]["pool_id"] = "pol_attacker"
    client = FakeGateway(values)
    journal = BrokerJournal(tmp_path / "broker.db")
    handler = BrokerRekeyHandler(
        client,  # type: ignore[arg-type]
        journal,
        workspace_keys=MemoryWorkspaceKeys("wsp_test", 1, workspace_key),  # type: ignore[arg-type]
        workspace_authorities=pinned_authorities(values),
    )

    with pytest.raises(BrokerRekeyError, match="allocation proof is invalid"):
        handler(command)

    assert not any(call["path"].endswith("/rekey") for call in client.calls)
    journal.close()
