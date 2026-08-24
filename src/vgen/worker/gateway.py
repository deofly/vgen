"""Authenticated Gateway v1 adapter for the generic Worker Core."""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from vgen.artifacts import ArtifactDescriptor, TransferTicket
from vgen.crypto import (
    HpkeCiphertext,
    PayloadCiphertext,
    b64url_encode,
    canonical_json,
    decrypt_payload,
    sign_http_request,
    sign_message,
    task_aad,
    unwrap_task_key,
)
from vgen.executors import ProgressEvent, RetryAction, UsageMetrics
from vgen.protocol import ErrorCode, VGenError, get_error_spec

from .core import GatewayRequestError, GatewayUnavailableError, LeaseLostError
from .credentials import WorkerCredentials
from .models import (
    ArtifactInput,
    ArtifactOutputTarget,
    ExecutionLease,
    ExecutorPayload,
    HeartbeatDirective,
    LeaseCryptoContext,
    LeaseReference,
    WorkerFailureReport,
    WorkerResult,
)

_FINISH_SIGNATURE_CONTEXT = b"vgen-worker-finish-v1"


def _canonical_failure_responsibility(code: ErrorCode | int) -> str:
    if int(code) == int(ErrorCode.EXECUTION_CANCELLED):
        return "consumer"
    responsibility = get_error_spec(code).responsibility.value
    return "platform" if responsibility == "unknown" else responsibility


@dataclass(frozen=True, slots=True)
class _OutputCommit:
    artifact_id: str
    kind: str
    store_type: str
    object_ref: str


class GatewayV1Client:
    """HTTP Message Signature client plus E2EE lease materializer.

    Signed URLs and encryption material are held in memory only and are never
    included in exceptions.  All mutation bodies are serialized before signing
    so the exact bytes covered by RFC 9421 are the bytes sent on the wire.
    """

    def __init__(
        self,
        base_url: str,
        credentials: WorkerCredentials,
        *,
        session: requests.Session | None = None,
        timeout: tuple[float, float] = (10.0, 30.0),
        lease_ttl_seconds: int = 60,
        allow_http: bool = False,
        report_progress: bool = False,
        session_token_provider: Callable[[], str] | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Gateway URL must be an absolute HTTP(S) URL.")
        localhost = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        if parsed.scheme != "https" and not (allow_http or localhost):
            raise ValueError("Remote Gateway URLs must use HTTPS.")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Gateway URL must not contain credentials, query, or fragment.")
        if not 15 <= lease_ttl_seconds <= 300:
            raise ValueError("Lease TTL must be between 15 and 300 seconds.")
        self._base_url = base_url.rstrip("/")
        self._credentials = credentials
        self._session = session or requests.Session()
        self._timeout = timeout
        self._lease_ttl_seconds = lease_ttl_seconds
        self._report_progress = report_progress
        self._session_token_provider = session_token_provider
        self._session_token_cache = credentials.session_token
        self._session_expires_at: float | None = None
        self._last_provider_token: str | None = None
        self._pending_lease_idempotency: str | None = None
        self._pending_maintenance_idempotency: str | None = None
        self._output_commits: dict[str, dict[str, _OutputCommit]] = {}

    @property
    def worker_id(self) -> str:
        return self._credentials.worker_id

    def announce(self, capabilities: Mapping[str, Any]) -> Mapping[str, Any]:
        value = self._request(
            "POST",
            f"/api/v1/workers/{self.worker_id}/heartbeat",
            {"capabilities": dict(capabilities)},
        )
        return _require_object(value, "worker heartbeat response")

    def claim_maintenance(self, *, ttl_seconds: int = 60) -> Mapping[str, Any] | None:
        """Claim one idle-only maintenance job for this Worker.

        The stable idempotency key is retained until a response arrives.  A
        network retry can therefore recover the same lease instead of creating
        an ambiguous second claim.
        """

        if not 15 <= ttl_seconds <= 300:
            raise ValueError("Maintenance TTL must be between 15 and 300 seconds.")
        if self._pending_maintenance_idempotency is None:
            self._pending_maintenance_idempotency = (
                "worker-maintenance-claim-" + secrets.token_urlsafe(24)
            )
        value = self._request(
            "POST",
            f"/api/v1/workers/{self.worker_id}/maintenance-jobs/claim",
            {"ttl_seconds": ttl_seconds},
            idempotency_key=self._pending_maintenance_idempotency,
            allow_empty=True,
        )
        self._pending_maintenance_idempotency = None
        if value is None:
            return None
        return _require_object(value, "maintenance claim response")

    def heartbeat_maintenance(
        self,
        job_id: str,
        *,
        fencing_token: int,
        ttl_seconds: int = 60,
        state: str = "running",
        progress: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        body: dict[str, Any] = {
            "fencing_token": int(fencing_token),
            "ttl_seconds": int(ttl_seconds),
            "state": state,
        }
        if progress is not None:
            body["progress"] = dict(progress)
        value = self._request(
            "POST",
            f"/api/v1/workers/{self.worker_id}/maintenance-jobs/{job_id}/heartbeat",
            body,
        )
        return _require_object(value, "maintenance heartbeat response")

    def complete_maintenance(
        self,
        job_id: str,
        *,
        fencing_token: int,
        succeeded: bool,
        result: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        value = self._request(
            "POST",
            f"/api/v1/workers/{self.worker_id}/maintenance-jobs/{job_id}/complete",
            {
                "fencing_token": int(fencing_token),
                "succeeded": bool(succeeded),
                "result": dict(result),
            },
            idempotency_key=f"worker-maintenance-complete-{job_id}-{fencing_token}",
        )
        return _require_object(value, "maintenance completion response")

    def maintenance_artifact_ticket(self, job: Mapping[str, Any]) -> TransferTicket:
        """Materialize the short-lived update wheel ticket from a claim."""

        raw = job.get("artifact_download_ticket")
        if not isinstance(raw, Mapping):
            raise VGenError(
                ErrorCode.VALIDATION_FAILED,
                details={"field": "artifact_download_ticket"},
            )
        entry = dict(raw)
        nested = entry.get("ticket")
        ticket_value = dict(nested) if isinstance(nested, Mapping) else entry
        raw_url = ticket_value.get("url")
        if isinstance(raw_url, str) and raw_url.startswith("/"):
            ticket_value["url"] = urljoin(self._base_url + "/", raw_url)
        artifact = job.get("artifact")
        store_type = artifact.get("store_type") if isinstance(artifact, Mapping) else None
        if store_type not in {"local", "oss", "s3"}:
            raise VGenError(
                ErrorCode.SOURCE_NOT_ALLOWED,
                details={"reason": "maintenance_artifact_store_not_allowed"},
            )
        if store_type == "local" and not _same_origin(
            str(ticket_value.get("url") or ""), self._base_url
        ):
            raise VGenError(
                ErrorCode.SOURCE_NOT_ALLOWED,
                details={"reason": "local_maintenance_ticket_origin_mismatch"},
            )
        # Gateway maintenance tickets use max_bytes in their storage-neutral
        # representation; the Worker transfer contract calls it expected_size.
        if ticket_value.get("expected_size") is None:
            if isinstance(artifact, Mapping):
                ticket_value["expected_size"] = artifact.get("expected_size")
                ticket_value["expected_sha256"] = artifact.get("expected_sha256")
            elif ticket_value.get("max_bytes") is not None:
                ticket_value["expected_size"] = ticket_value.get("max_bytes")
        return _transfer_ticket({"ticket": ticket_value})

    def refresh_session(self) -> float:
        """Replace an expired Worker session using a signed one-time challenge."""

        challenge_value = self._public_request(
            "/api/v1/auth/challenges",
            {"principal_type": "worker", "worker_id": self.worker_id},
        )
        challenge = _require_object(challenge_value, "worker challenge response")
        challenge_id = _required_string(challenge, "challenge_id")
        plaintext = _required_string(challenge, "challenge")
        signature = b64url_encode(
            sign_message(
                self._credentials.device_keys.signing_private_key,
                plaintext.encode("utf-8"),
            )
        )
        session_value = self._public_request(
            "/api/v1/auth/sessions",
            {
                "principal_type": "worker",
                "worker_id": self.worker_id,
                "challenge_id": challenge_id,
                "signature": signature,
            },
        )
        session = _require_object(session_value, "worker session response")
        if session.get("principal_type") != "worker" or session.get("worker_id") != self.worker_id:
            raise VGenError(
                ErrorCode.PROTOCOL_VERSION_UNSUPPORTED,
                details={"reason": "worker_session_subject_mismatch"},
            )
        token = session.get("session_token") or session.get("token")
        if not isinstance(token, str) or not token:
            raise VGenError(
                ErrorCode.PROTOCOL_VERSION_UNSUPPORTED,
                details={"reason": "worker_session_token_missing"},
            )
        expires_at = _optional_number(session.get("expires_at"))
        if expires_at is None:
            raise VGenError(
                ErrorCode.PROTOCOL_VERSION_UNSUPPORTED,
                details={"reason": "worker_session_expiry_missing"},
            )
        self._session_token_cache = token
        self._session_expires_at = expires_at
        return expires_at

    def poll_lease(self) -> ExecutionLease | None:
        if self._pending_lease_idempotency is None:
            self._pending_lease_idempotency = "worker-lease-" + secrets.token_urlsafe(24)
        value = self._request(
            "POST",
            f"/api/v1/workers/{self.worker_id}/lease",
            {"ttl_seconds": self._lease_ttl_seconds},
            idempotency_key=self._pending_lease_idempotency,
            allow_empty=True,
        )
        self._pending_lease_idempotency = None
        if value is None:
            return None
        wire = _require_object(value, "lease response")
        reference = _reference_from_wire(wire, self.worker_id)
        try:
            return self.materialize_lease(wire)
        except VGenError as exc:
            spec = get_error_spec(exc.code)
            failure = WorkerFailureReport(
                code=exc.code,
                name=exc.code.name,
                message=spec.message,
                retry_action=RetryAction(spec.retry_action.value),
                responsibility=_canonical_failure_responsibility(exc.code),
                occurred_after_start=False,
                details=exc.details,
            )
            self.fail(reference, failure)
            raise

    def materialize_lease(self, wire: Mapping[str, Any]) -> ExecutionLease:
        reference = _reference_from_wire(wire, self.worker_id)
        workspace_id = _required_string(wire, "workspace_id")
        key_version = _required_positive_int(wire, "key_version")
        content_attempt_id = (
            _required_string(wire, "content_attempt_id")
            if "content_attempt_id" in wire
            else reference.attempt_id
        )
        key_wrap_aad = task_aad(
            workspace_id=workspace_id,
            task_id=reference.task_id,
            attempt_id=reference.attempt_id,
            artifact_id="payload",
            key_version=key_version,
        )
        try:
            wrapped_key = HpkeCiphertext.from_dict(
                _json_object(wire.get("encrypted_tdk_envelope"), "encrypted_tdk_envelope")
            )
            task_data_key = unwrap_task_key(
                self._credentials.device_keys.encryption_private_key,
                wrapped_key,
                aad=key_wrap_aad,
            )
            encrypted_payload = PayloadCiphertext.from_dict(
                _json_object(wire.get("encrypted_payload"), "encrypted_payload")
            )
            content_aad = task_aad(
                workspace_id=workspace_id,
                task_id=reference.task_id,
                attempt_id=content_attempt_id,
                artifact_id="payload",
                key_version=key_version,
            )
            plaintext_payload = decrypt_payload(
                task_data_key,
                encrypted_payload,
                aad=content_aad,
            )
        except VGenError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise VGenError(
                ErrorCode.VALIDATION_FAILED,
                details={"field": "encrypted_lease"},
            ) from exc

        try:
            inputs = _parse_inputs(wire)
            outputs, commits = _parse_outputs(wire)
            lease = ExecutionLease(
                reference=reference,
                payload=ExecutorPayload(
                    executor_type=_required_string(wire, "executor_type"),
                    payload_format=_required_string(wire, "payload_format"),
                    operation=_required_string(wire, "operation"),
                    workflow_digest=_required_string(wire, "workflow_digest"),
                    data=plaintext_payload,
                ),
                inputs=inputs,
                outputs=outputs,
                crypto=LeaseCryptoContext(
                    workspace_id=workspace_id,
                    content_attempt_id=content_attempt_id,
                    key_version=key_version,
                    task_data_key=task_data_key,
                ),
                expires_at=_optional_number(wire.get("expires_at")),
                timeout_seconds=float(wire.get("timeout_seconds", 3600.0)),
            )
        except VGenError:
            raise
        except (TypeError, ValueError) as exc:
            raise VGenError(
                ErrorCode.VALIDATION_FAILED,
                details={"field": "execution_lease"},
            ) from exc
        self._output_commits[reference.attempt_id] = commits
        return lease

    def heartbeat(
        self,
        reference: LeaseReference,
        progress: ProgressEvent,
    ) -> HeartbeatDirective:
        value = self._attempt_heartbeat(reference, started=False, progress=progress)
        return HeartbeatDirective(
            cancelled=bool(value.get("cancelled", False)),
            lease_expires_at=_optional_number(value.get("expires_at")),
        )

    def mark_started(self, reference: LeaseReference) -> HeartbeatDirective:
        value = self._attempt_heartbeat(reference, started=True)
        return HeartbeatDirective(
            cancelled=bool(value.get("cancelled", False)),
            lease_expires_at=_optional_number(value.get("expires_at")),
        )

    def renew_output_tickets(
        self,
        reference: LeaseReference,
        artifact_ids: frozenset[str],
    ) -> Mapping[str, TransferTicket]:
        value = self._request(
            "POST",
            f"/api/v1/attempts/{reference.attempt_id}/artifact-tickets",
            {},
        )
        response = _require_object(value, "artifact ticket response")
        raw_tickets = response.get("output_upload_tickets")
        if not isinstance(raw_tickets, list):
            raise VGenError(
                ErrorCode.PROTOCOL_VERSION_UNSUPPORTED,
                details={"field": "output_upload_tickets"},
            )
        renewed: dict[str, TransferTicket] = {}
        for raw_entry in raw_tickets:
            entry = _require_object(raw_entry, "output ticket")
            artifact_id = _required_string(entry, "artifact_id")
            if artifact_id in artifact_ids:
                renewed[artifact_id] = _transfer_ticket(entry)
        return renewed

    def _attempt_heartbeat(
        self,
        reference: LeaseReference,
        *,
        started: bool,
        progress: ProgressEvent | None = None,
    ) -> Mapping[str, Any]:
        payload: dict[str, Any] = {
            "fencing_token": reference.fencing_token,
            "started": started,
            "ttl_seconds": self._lease_ttl_seconds,
        }
        if progress is not None and self._report_progress:
            payload["progress"] = {
                "fraction": progress.fraction,
                "stage": progress.stage[:64],
            }
        value = self._request(
            "POST",
            f"/api/v1/attempts/{reference.attempt_id}/heartbeat",
            payload,
        )
        return _require_object(value, "attempt heartbeat response")

    def complete(self, reference: LeaseReference, result: WorkerResult) -> None:
        output_artifacts: list[dict[str, Any]] = []
        for artifact in result.artifacts:
            output_artifacts.append(
                {
                    "artifact_id": artifact.artifact_id,
                    "kind": artifact.kind,
                    "store_type": artifact.store_type,
                    "object_ref": artifact.object_ref,
                    "content_digest": artifact.sha256,
                    "encrypted_size": artifact.size_bytes,
                    "media_metadata": {
                        "media_type": artifact.media_type,
                        "filename": artifact.filename,
                        **dict(artifact.metadata),
                    },
                }
            )
        body = {
            "fencing_token": reference.fencing_token,
            "succeeded": True,
            "output_artifacts": output_artifacts,
            "metrics": _usage_metrics(result.usage),
            "failure_code": None,
            "responsibility": "none",
            "safe_failure_details": {},
        }
        self._finish(reference, body)

    def fail(self, reference: LeaseReference, failure: WorkerFailureReport) -> None:
        body = {
            "fencing_token": reference.fencing_token,
            "succeeded": False,
            "output_artifacts": [],
            "metrics": _usage_metrics(failure.usage),
            "failure_code": int(failure.code),
            # The Gateway validates this assertion against its immutable error
            # registry; derive it here rather than trusting executor metadata.
            "responsibility": _canonical_failure_responsibility(failure.code),
            "safe_failure_details": dict(failure.details),
        }
        self._finish(reference, body)

    def _finish(self, reference: LeaseReference, body: dict[str, Any]) -> None:
        signed = {
            "attempt_id": reference.attempt_id,
            "task_id": reference.task_id,
            "worker_id": reference.worker_id,
            **body,
        }
        body["worker_signature"] = b64url_encode(
            sign_message(
                self._credentials.device_keys.signing_private_key,
                canonical_json(signed),
                context=_FINISH_SIGNATURE_CONTEXT,
            )
        )
        self._request(
            "POST",
            f"/api/v1/attempts/{reference.attempt_id}/finish",
            body,
            idempotency_key=(f"worker-finish-{reference.attempt_id}-{reference.fencing_token}"),
        )
        self._output_commits.pop(reference.attempt_id, None)

    def _request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str | None = None,
        allow_empty: bool = False,
        _allow_session_refresh: bool = True,
    ) -> Any:
        body = canonical_json(dict(payload))
        signature = sign_http_request(
            self._credentials.device_keys,
            method=method,
            path=path,
            body=body,
        )
        headers = {
            "Authorization": f"Bearer {self._session_token()}",
            "Content-Type": "application/json",
            "Vgen-Protocol-Version": "1",
            **signature.to_headers(),
        }
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        try:
            response = self._session.request(
                method,
                self._base_url + path,
                data=body,
                headers=headers,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            raise GatewayUnavailableError() from exc
        if response.status_code == 204 and allow_empty:
            return None
        if response.status_code >= 400:
            if (
                _allow_session_refresh
                and _response_error_code(response) is ErrorCode.SESSION_EXPIRED
            ):
                self.refresh_session()
                return self._request(
                    method,
                    path,
                    payload,
                    idempotency_key=idempotency_key,
                    allow_empty=allow_empty,
                    _allow_session_refresh=False,
                )
            _raise_gateway_error(response)
        try:
            return response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise VGenError(
                ErrorCode.PROTOCOL_VERSION_UNSUPPORTED,
                details={"reason": "invalid_json_response"},
            ) from exc

    def _session_token(self) -> str:
        if self._session_token_provider is not None:
            try:
                provided = self._session_token_provider()
            except Exception as exc:
                raise VGenError(ErrorCode.SESSION_EXPIRED) from exc
            if not isinstance(provided, str) or not provided:
                raise VGenError(ErrorCode.SESSION_EXPIRED)
            if provided != self._last_provider_token:
                self._session_token_cache = provided
                self._session_expires_at = None
                self._last_provider_token = provided
        if self._session_expires_at is not None and time.time() >= self._session_expires_at - 30:
            self.refresh_session()
        return self._session_token_cache

    def _public_request(self, path: str, payload: Mapping[str, Any]) -> Any:
        body = canonical_json(dict(payload))
        try:
            response = self._session.request(
                "POST",
                self._base_url + path,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Vgen-Protocol-Version": "1",
                },
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            raise GatewayUnavailableError() from exc
        if response.status_code >= 400:
            _raise_gateway_error(response)
        try:
            return response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise VGenError(
                ErrorCode.PROTOCOL_VERSION_UNSUPPORTED,
                details={"reason": "invalid_json_response"},
            ) from exc


def _raise_gateway_error(response: requests.Response) -> None:
    try:
        value = response.json()
        raw_error = value.get("error", {}) if isinstance(value, Mapping) else {}
        code = ErrorCode(int(raw_error.get("code", ErrorCode.INTERNAL_ERROR)))
        request_id = raw_error.get("request_id")
        retry = raw_error.get("retry")
        retry_after = retry.get("after_ms") if isinstance(retry, Mapping) else None
    except (TypeError, ValueError, json.JSONDecodeError):
        code = ErrorCode.INTERNAL_ERROR
        request_id = response.headers.get("X-Request-ID")
        retry_after = None
    if code in {ErrorCode.LEASE_LOST, ErrorCode.FENCING_TOKEN_STALE}:
        raise LeaseLostError()
    raise GatewayRequestError(code, request_id=request_id, retry_after_ms=retry_after)


def _response_error_code(response: requests.Response) -> ErrorCode | None:
    try:
        value = response.json()
        raw_error = value.get("error", {}) if isinstance(value, Mapping) else {}
        return ErrorCode(int(raw_error.get("code")))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _reference_from_wire(wire: Mapping[str, Any], worker_id: str) -> LeaseReference:
    try:
        return LeaseReference(
            lease_id=_required_string(wire, "lease_id"),
            task_id=_required_string(wire, "task_id"),
            attempt_id=_required_string(wire, "attempt_id"),
            worker_id=worker_id,
            fencing_token=_required_positive_int(wire, "fencing_token"),
        )
    except (TypeError, ValueError) as exc:
        raise VGenError(
            ErrorCode.VALIDATION_FAILED,
            details={"field": "lease_reference"},
        ) from exc


def _parse_inputs(wire: Mapping[str, Any]) -> tuple[ArtifactInput, ...]:
    artifact_values = wire.get("artifacts", [])
    ticket_values = wire.get("artifact_download_tickets", [])
    if not isinstance(artifact_values, list) or not isinstance(ticket_values, list):
        raise VGenError(ErrorCode.VALIDATION_FAILED, details={"field": "input_tickets"})
    artifacts = {
        str(value.get("id") or value.get("artifact_id")): value
        for value in artifact_values
        if isinstance(value, Mapping)
    }
    inputs: list[ArtifactInput] = []
    for index, raw_entry in enumerate(ticket_values):
        entry = _require_object(raw_entry, "input ticket")
        artifact_id = str(entry.get("artifact_id", ""))
        artifact = artifacts.get(artifact_id, entry.get("artifact", entry))
        artifact = _require_object(artifact, "input artifact")
        ticket = _transfer_ticket(entry)
        metadata = artifact.get("media_metadata", {})
        metadata = dict(metadata) if isinstance(metadata, Mapping) else {}
        filename = _safe_filename(
            entry.get("filename") or metadata.get("filename"),
            fallback=f"input-{index:02d}.bin",
        )
        descriptor = ArtifactDescriptor(
            artifact_id=artifact_id or _required_string(artifact, "id"),
            filename=filename,
            media_type=str(
                entry.get("media_type") or metadata.get("media_type") or "application/octet-stream"
            ),
            metadata=metadata,
        )
        inputs.append(
            ArtifactInput(
                name=str(entry.get("name") or artifact.get("kind") or f"input_{index}"),
                artifact=descriptor,
                download=ticket,
            )
        )
    if len(inputs) != len(artifacts):
        raise VGenError(
            ErrorCode.STORAGE_UNAVAILABLE,
            details={"reason": "missing_input_ticket"},
        )
    return tuple(inputs)


def _parse_outputs(
    wire: Mapping[str, Any],
) -> tuple[tuple[ArtifactOutputTarget, ...], dict[str, _OutputCommit]]:
    values = wire.get("output_upload_tickets", [])
    if not isinstance(values, list) or not values:
        raise VGenError(ErrorCode.VALIDATION_FAILED, details={"field": "output_tickets"})
    outputs: list[ArtifactOutputTarget] = []
    commits: dict[str, _OutputCommit] = {}
    for index, raw_entry in enumerate(values):
        entry = _require_object(raw_entry, "output ticket")
        artifact = _require_object(entry.get("artifact", entry), "output artifact")
        artifact_id = str(
            entry.get("artifact_id") or artifact.get("artifact_id") or artifact.get("id") or ""
        )
        if not artifact_id:
            raise VGenError(
                ErrorCode.VALIDATION_FAILED,
                details={"field": "output_artifact_id"},
            )
        metadata = artifact.get("media_metadata", {})
        metadata = dict(metadata) if isinstance(metadata, Mapping) else {}
        filename = _safe_filename(
            entry.get("filename") or artifact.get("filename") or metadata.get("filename"),
            fallback=f"output-{index:02d}.bin",
        )
        name = str(entry.get("name") or artifact.get("name") or "primary")
        descriptor = ArtifactDescriptor(
            artifact_id=artifact_id,
            filename=filename,
            media_type=str(
                entry.get("media_type") or artifact.get("media_type") or "application/octet-stream"
            ),
            metadata=metadata,
        )
        if name == f"output_{index}":
            name = "primary" if index == 0 else f"output-{index + 1}"
        outputs.append(
            ArtifactOutputTarget(
                name=name,
                artifact=descriptor,
                upload=_transfer_ticket(entry),
                kind=str(entry.get("kind") or artifact.get("kind") or "output"),
                store_type=_required_string(entry, "store_type"),
                object_ref=_required_string(entry, "object_ref"),
            )
        )
        commits[artifact_id] = _OutputCommit(
            artifact_id=artifact_id,
            kind=str(entry.get("kind") or artifact.get("kind") or "output"),
            store_type=_required_string(entry, "store_type"),
            object_ref=_required_string(entry, "object_ref"),
        )
    return tuple(outputs), commits


def _transfer_ticket(entry: Mapping[str, Any]) -> TransferTicket:
    raw_ticket = entry.get("ticket", entry)
    ticket = _require_object(raw_ticket, "transfer ticket")
    try:
        return TransferTicket(
            url=_required_string(ticket, "url"),
            method=_required_string(ticket, "method"),
            headers=(
                {str(key): str(value) for key, value in ticket.get("headers", {}).items()}
                if isinstance(ticket.get("headers", {}), Mapping)
                else {}
            ),
            endpoint=(None if ticket.get("endpoint") is None else str(ticket["endpoint"])),
            credentials=(
                {str(key): str(value) for key, value in ticket.get("credentials", {}).items()}
                if isinstance(ticket.get("credentials", {}), Mapping)
                else {}
            ),
            expires_at=_optional_number(ticket.get("expires_at")),
            expected_size=(
                None if ticket.get("expected_size") is None else int(ticket["expected_size"])
            ),
            expected_sha256=(
                None if ticket.get("expected_sha256") is None else str(ticket["expected_sha256"])
            ),
            media_type=(None if ticket.get("media_type") is None else str(ticket["media_type"])),
        )
    except (TypeError, ValueError) as exc:
        raise VGenError(
            ErrorCode.VALIDATION_FAILED,
            details={"field": "transfer_ticket"},
        ) from exc


def _usage_metrics(usage: UsageMetrics) -> dict[str, Any]:
    value: dict[str, Any] = {
        "executor_wall_ms": usage.executor_wall_ms,
        "gpu_count": usage.gpu_count,
        "input_bytes": usage.input_bytes,
        "output_bytes": usage.output_bytes,
    }
    for name in ("gpu_active_ms", "frames", "duration_ms", "denoise_steps"):
        item = getattr(usage, name)
        if item is not None:
            value[name] = item
    if usage.native:
        value["native"] = dict(usage.native)
    return value


def _json_object(value: Any, field: str) -> Mapping[str, Any]:
    try:
        decoded = json.loads(value) if isinstance(value, str) else value
    except json.JSONDecodeError as exc:
        raise VGenError(ErrorCode.VALIDATION_FAILED, details={"field": field}) from exc
    if not isinstance(decoded, Mapping):
        raise VGenError(ErrorCode.VALIDATION_FAILED, details={"field": field})
    return decoded


def _require_object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise VGenError(ErrorCode.VALIDATION_FAILED, details={"field": label})
    return value


def _required_string(value: Mapping[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise VGenError(ErrorCode.VALIDATION_FAILED, details={"field": key})
    return item


def _required_positive_int(value: Mapping[str, Any], key: str) -> int:
    try:
        item = int(value.get(key, 0))
    except (TypeError, ValueError) as exc:
        raise VGenError(ErrorCode.VALIDATION_FAILED, details={"field": key}) from exc
    if item < 1:
        raise VGenError(ErrorCode.VALIDATION_FAILED, details={"field": key})
    return item


def _optional_number(value: Any) -> float | None:
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError) as exc:
        raise VGenError(
            ErrorCode.VALIDATION_FAILED,
            details={"field": "numeric_value"},
        ) from exc


def _same_origin(first: str, second: str) -> bool:
    def origin(value: str) -> tuple[str, str, int] | None:
        try:
            parsed = urlparse(value)
            if not parsed.scheme or not parsed.hostname or parsed.username or parsed.password:
                return None
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            return None
        return parsed.scheme.lower(), parsed.hostname.casefold(), port

    left = origin(first)
    return left is not None and left == origin(second)


def _safe_filename(value: Any, *, fallback: str) -> str:
    if isinstance(value, str) and value and Path(value).name == value:
        return value
    return fallback
