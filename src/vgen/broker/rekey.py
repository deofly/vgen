"""End-to-end task-key rewrapping for an optional Home Broker.

The Gateway command contains identifiers and scheduling metadata only.  The
Workspace Data Key and recovered Task Data Key stay in process memory and are
never written to the Broker journal.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from vgen.cli.client import GatewayClient, VgenClientError
from vgen.cli.workspace_authorities import WorkspaceAuthorityError, WorkspaceAuthorityStore
from vgen.cli.workspace_keys import WorkspaceKeyStore
from vgen.crypto import (
    HPKE_ALGORITHM,
    PayloadCiphertext,
    b64url_decode,
    build_allocation_proof_payload,
    device_key_id,
    task_aad,
    unwrap_task_key_for_workspace,
    verify_allocation_proof,
    verify_key_manifest,
    wrap_task_key,
)
from vgen.protocol.errors import VGenError

from .journal import BrokerJournal


class BrokerRekeyError(RuntimeError):
    """A safe, non-secret command validation or cryptographic failure."""


class BrokerRekeyHandler:
    """Handle ``task_rekey`` commands issued to a Broker Device.

    Network mutations use command/attempt-derived idempotency keys.  A restart
    therefore resumes the same Gateway reservation instead of creating a
    second attempt.  Only a retry generation counter and public resource IDs
    are persisted locally.
    """

    _RETRYABLE_TASK_STATES = frozenset({"failed", "rekey_required", "expired"})
    _ALREADY_HANDLED_STATES = frozenset(
        {"committed", "queued", "reserved", "running", "succeeded", "cancelled"}
    )

    def __init__(
        self,
        client: GatewayClient,
        journal: BrokerJournal,
        *,
        workspace_keys: WorkspaceKeyStore | None = None,
        workspace_authorities: WorkspaceAuthorityStore | None = None,
    ) -> None:
        self.client = client
        self.journal = journal
        self.workspace_keys = workspace_keys or WorkspaceKeyStore()
        self.workspace_authorities = workspace_authorities or WorkspaceAuthorityStore()

    def __call__(self, command: Mapping[str, Any]) -> dict[str, Any]:
        command_type = str(command.get("command_type") or "")
        if command_type != "task_rekey":
            return {"status": "unsupported", "command_type": command_type}
        command_id = self._required_string(command, "id")
        payload = command.get("payload")
        if not isinstance(payload, Mapping):
            raise BrokerRekeyError("Broker rekey command payload is invalid")
        if self._required_integer(payload, "version") != 1:
            raise BrokerRekeyError("Broker rekey command version is unsupported")
        task_id = self._required_string(payload, "task_id")
        workspace_id = self._required_string(payload, "workspace_id")
        key_version = self._required_integer(payload, "key_version")

        task = self.client.request("GET", f"/api/v1/tasks/{task_id}")
        if not isinstance(task, Mapping):
            raise BrokerRekeyError("Gateway task response is invalid")
        task_state = str(task.get("state") or "")
        if task_state in self._ALREADY_HANDLED_STATES:
            return {"status": "not_needed", "task_id": task_id, "task_state": task_state}
        if task_state not in self._RETRYABLE_TASK_STATES:
            raise BrokerRekeyError("Task is not in a rekeyable state")
        if str(task.get("workspace_id") or "") != workspace_id:
            raise BrokerRekeyError("Broker command Workspace does not match the task")

        # Fetch and validate the immutable reader envelope before reserving a
        # replacement Worker.  Loading the WDK may prompt the OS Keychain, but
        # neither key is added to the journal or command completion result.
        workspace_key = self.workspace_keys.load(workspace_id, key_version)
        reader = self.client.request("GET", f"/api/v1/tasks/{task_id}/reader-envelope")
        if not isinstance(reader, Mapping):
            raise BrokerRekeyError("Gateway reader envelope response is invalid")
        self._verify_reader(
            reader,
            task_id=task_id,
            workspace_id=workspace_id,
            key_version=key_version,
        )

        command_state_key = f"command:{command_id}"
        command_state = self.journal.get_state(command_state_key, {})
        raw_generation = (
            command_state.get("retry_generation", 0) if isinstance(command_state, Mapping) else 0
        )
        generation = (
            raw_generation
            if isinstance(raw_generation, int)
            and not isinstance(raw_generation, bool)
            and raw_generation >= 0
            else 0
        )
        retry = self.client.request(
            "POST",
            f"/api/v1/tasks/{task_id}/retry",
            json_body={},
            idempotency_key=f"broker-retry:{command_id}:{generation}",
        )
        if not isinstance(retry, Mapping):
            raise BrokerRekeyError("Gateway retry response is invalid")
        worker = retry.get("worker")
        if not isinstance(worker, Mapping):
            raise BrokerRekeyError("Gateway retry response has no replacement Worker")
        self._verify_retry(
            retry,
            task_id=task_id,
            workspace_id=workspace_id,
            key_version=key_version,
            worker=worker,
        )
        self._verify_worker_certificate(worker)
        self._verify_allocation(retry, worker=worker)

        content_attempt_id = self._required_string(reader, "content_attempt_id")
        reader_aad = task_aad(
            workspace_id=workspace_id,
            task_id=task_id,
            attempt_id=content_attempt_id,
            key_version=key_version,
        )
        try:
            raw_reader_envelope = reader["reader_envelope"]
            reader_envelope = PayloadCiphertext.from_dict(
                json.loads(raw_reader_envelope)
                if isinstance(raw_reader_envelope, str)
                else raw_reader_envelope
            )
            task_data_key = unwrap_task_key_for_workspace(
                workspace_key, reader_envelope, aad=reader_aad
            )
        except (KeyError, TypeError, ValueError, VGenError, json.JSONDecodeError) as exc:
            raise BrokerRekeyError("Task reader envelope is invalid") from exc

        attempt_id = self._required_string(retry, "attempt_id")
        replacement_worker_id = self._required_string(worker, "id")
        try:
            worker_public_key = b64url_decode(
                self._required_string(worker, "encryption_public_key"),
                expected_length=32,
            )
            worker_envelope = wrap_task_key(
                worker_public_key,
                task_data_key,
                aad=task_aad(
                    workspace_id=workspace_id,
                    task_id=task_id,
                    attempt_id=attempt_id,
                    key_version=key_version,
                ),
            )
        except (TypeError, ValueError) as exc:
            raise BrokerRekeyError("Replacement Worker encryption key is invalid") from exc

        try:
            committed = self.client.request(
                "POST",
                f"/api/v1/tasks/{task_id}/rekey",
                json_body={
                    "replacement_worker_id": replacement_worker_id,
                    "worker_tdk_envelope": json.dumps(
                        worker_envelope.to_dict(), separators=(",", ":")
                    ),
                    "key_algorithm": HPKE_ALGORITHM,
                },
                idempotency_key=f"broker-rekey:{command_id}:{attempt_id}",
            )
        except VgenClientError as exc:
            if exc.code == 310003:
                # The deterministic retry response now names an expired
                # reservation.  Advance only a non-secret local generation so
                # the next poll may create a fresh Attempt.
                self.journal.set_state(
                    command_state_key,
                    {"retry_generation": generation + 1, "last_attempt_id": attempt_id},
                )
            raise
        if not isinstance(committed, Mapping):
            raise BrokerRekeyError("Gateway rekey response is invalid")

        self.journal.set_state(
            command_state_key,
            {
                "retry_generation": generation,
                "last_attempt_id": attempt_id,
                "completed": True,
            },
        )
        return {
            "status": "rekeyed",
            "task_id": task_id,
            "attempt_id": attempt_id,
            "worker_id": replacement_worker_id,
            "task_state": str(committed.get("state") or "committed"),
        }

    @staticmethod
    def _required_string(value: Mapping[str, Any], key: str) -> str:
        item = value.get(key)
        if not isinstance(item, str) or not item:
            raise BrokerRekeyError(f"Broker rekey field {key} is missing")
        return item

    @staticmethod
    def _required_integer(value: Mapping[str, Any], key: str) -> int:
        item = value.get(key)
        if not isinstance(item, int) or isinstance(item, bool) or item < 1:
            raise BrokerRekeyError(f"Broker rekey field {key} is invalid")
        return item

    @classmethod
    def _verify_reader(
        cls,
        reader: Mapping[str, Any],
        *,
        task_id: str,
        workspace_id: str,
        key_version: int,
    ) -> None:
        if (
            str(reader.get("task_id") or "") != task_id
            or str(reader.get("workspace_id") or "") != workspace_id
            or reader.get("key_version") != key_version
        ):
            raise BrokerRekeyError("Gateway reader envelope metadata does not match the command")

    @classmethod
    def _verify_retry(
        cls,
        retry: Mapping[str, Any],
        *,
        task_id: str,
        workspace_id: str,
        key_version: int,
        worker: Mapping[str, Any],
    ) -> None:
        if (
            str(retry.get("task_id") or "") != task_id
            or str(retry.get("workspace_id") or "") != workspace_id
            or retry.get("key_version") != key_version
            or not retry.get("attempt_id")
            or not worker.get("id")
        ):
            raise BrokerRekeyError("Gateway retry metadata does not match the command")

    @classmethod
    def _verify_worker_certificate(cls, worker: Mapping[str, Any]) -> None:
        raw_certificate = worker.get("certificate")
        try:
            certificate = (
                json.loads(raw_certificate) if isinstance(raw_certificate, str) else raw_certificate
            )
            root_key = b64url_decode(
                cls._required_string(worker, "owner_root_signing_public_key"),
                expected_length=32,
            )
            signing_public_key = cls._required_string(worker, "signing_public_key")
            manifest = certificate["manifest"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BrokerRekeyError("Replacement Worker owner certificate is malformed") from exc
        if not isinstance(certificate, Mapping) or not verify_key_manifest(certificate, root_key):
            raise BrokerRekeyError("Replacement Worker owner certificate is invalid")
        try:
            expected = {
                "kind": "vgen-worker-owner-certificate",
                "owner_root_key_id": certificate.get("signer_key_id"),
                "worker_key_id": device_key_id(
                    b64url_decode(signing_public_key, expected_length=32)
                ),
                "worker_signing_public_key": signing_public_key,
                "worker_encryption_public_key": worker.get("encryption_public_key"),
            }
        except ValueError as exc:
            raise BrokerRekeyError("Replacement Worker owner certificate is malformed") from exc
        if not isinstance(manifest, Mapping) or any(
            manifest.get(key) != item for key, item in expected.items()
        ):
            raise BrokerRekeyError("Replacement Worker certificate does not bind its keys")

    def _verify_allocation(self, retry: Mapping[str, Any], *, worker: Mapping[str, Any]) -> None:
        allocation = retry.get("allocation")
        if not isinstance(allocation, Mapping):
            raise BrokerRekeyError("Gateway retry response has no allocation proof")
        proof = allocation.get("proof")
        if not isinstance(proof, Mapping):
            raise BrokerRekeyError("Gateway allocation proof is malformed")
        try:
            admin_user_id = self._required_string(allocation, "admin_user_id")
            root_public_text = self._required_string(allocation, "admin_root_signing_public_key")
            root_key = b64url_decode(root_public_text, expected_length=32)
            payload = proof["payload"]
            self.workspace_authorities.require(
                workspace_id=self._required_string(retry, "workspace_id"),
                user_id=admin_user_id,
                presented_root_signing_public_key=root_public_text,
                presented_root_key_id=str(payload["approver_root_key_id"]),
            )
            expected = build_allocation_proof_payload(
                allocation_id=self._required_string(allocation, "id"),
                workspace_id=self._required_string(retry, "workspace_id"),
                pool_id=self._required_string(retry, "pool_id"),
                worker_id=self._required_string(worker, "id"),
                worker_signing_public_key=self._required_string(worker, "signing_public_key"),
                worker_encryption_public_key=self._required_string(worker, "encryption_public_key"),
                worker_certificate=worker["certificate"],
                owner_consent_at=float(allocation["owner_consent_at"]),
                approver_root_key_id=str(payload["approver_root_key_id"]),
                issued_at=int(payload["issued_at"]),
            )
        except (KeyError, TypeError, ValueError, WorkspaceAuthorityError) as exc:
            raise BrokerRekeyError("Gateway allocation proof is malformed") from exc
        if not verify_allocation_proof(proof, root_key, expected=expected):
            raise BrokerRekeyError("Replacement Worker allocation proof is invalid")
