"""Credential-free Worker enrollment helpers.

The public Windows installer contains no Worker identity.  A fresh Worker key
pair is generated on the Windows host, then an out-of-band, one-use Invite URI
authorizes a pending enrollment.  The Invite secret is intentionally accepted
only as an in-memory value; callers must obtain it from a hidden prompt or
stdin, never from an argv option.

The Gateway endpoints consumed here are the v0.3 Worker enrollment contract.
They are kept separate from Workspace membership claim because credentials for
different principal kinds must never be interchangeable.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vgen.crypto import (
    b64url_decode,
    b64url_encode,
    canonical_json,
    device_key_id,
    sign_http_request,
    sign_message,
    verify_key_manifest,
    verify_message,
)
from vgen.worker.credentials import (
    WorkerCredentials,
    WorkerIdentity,
    WorkerIdentityStore,
    save_worker_credentials_file,
)

from .auth import login_worker_session
from .client import GatewayClient
from .profile import GatewayProfile
from .workspace_authorities import PinnedInvite

WORKER_ENROLLMENT_CONTEXT = b"vgen-worker-enrollment-v1"
WORKER_APPROVAL_CODE_CONTEXT = b"vgen-worker-enrollment-approval-code-v1\x00"
TERMINAL_ENROLLMENT_STATES = frozenset({"active", "expired", "rejected", "revoked"})


class WorkerEnrollmentError(ValueError):
    """A safe enrollment error which never contains Invite or key material."""


@dataclass(frozen=True, slots=True)
class WorkerEnrollmentResult:
    worker_id: str
    enrollment_id: str
    credentials_path: Path
    state: str

    def public_dict(self) -> dict[str, str]:
        return {
            "worker_id": self.worker_id,
            "enrollment_id": self.enrollment_id,
            "state": self.state,
            "credentials": str(self.credentials_path),
            "next": "Continue with the reviewed Windows Worker setup.",
        }


def worker_claim_payload(
    identity: WorkerIdentity,
    *,
    invite_id: str,
    name: str,
    executor_type: str,
    executor_version: str,
    capabilities: Mapping[str, Any] | None,
    capacity: int,
) -> dict[str, Any]:
    """Build the exact public claim signed by the new Worker key."""

    clean_name = name.strip()
    clean_executor = executor_type.strip()
    if not invite_id or not clean_name or not clean_executor:
        raise WorkerEnrollmentError("Invite, Worker name, and Executor type are required.")
    if not 1 <= capacity <= 64:
        raise WorkerEnrollmentError("Worker capacity must be between 1 and 64.")
    info = identity.public_info()
    return {
        "version": 1,
        "kind": "vgen-worker-enrollment-claim",
        "invite_id": invite_id,
        "worker_key_id": identity.key_id,
        "name": clean_name,
        "signing_public_key": info["signing_public_key"],
        "encryption_public_key": info["encryption_public_key"],
        "executor_type": clean_executor,
        "executor_version": executor_version.strip(),
        "capabilities": dict(capabilities or {}),
        "capacity": capacity,
    }


def sign_worker_claim(identity: WorkerIdentity, claim: Mapping[str, Any]) -> str:
    return b64url_encode(
        sign_message(
            identity.device_keys.signing_private_key,
            canonical_json(dict(claim)),
            context=WORKER_ENROLLMENT_CONTEXT,
        )
    )


def verify_worker_claim(claim: Mapping[str, Any], signature: str) -> bool:
    """Verify key possession before an owner signs a Worker certificate."""

    try:
        signing_public_key = b64url_decode(str(claim["signing_public_key"]), expected_length=32)
        b64url_decode(str(claim["encryption_public_key"]), expected_length=32)
        expected_key_id = device_key_id(signing_public_key)
        valid_shape = (
            claim.get("version") == 1
            and claim.get("kind") == "vgen-worker-enrollment-claim"
            and claim.get("worker_key_id") == expected_key_id
            and isinstance(claim.get("invite_id"), str)
            and bool(claim.get("invite_id"))
            and isinstance(claim.get("name"), str)
            and bool(str(claim.get("name")).strip())
            and isinstance(claim.get("executor_type"), str)
            and bool(str(claim.get("executor_type")).strip())
            and isinstance(claim.get("executor_version"), str)
            and isinstance(claim.get("capabilities"), dict)
            and isinstance(claim.get("capacity"), int)
            and not isinstance(claim.get("capacity"), bool)
            and 1 <= int(claim["capacity"]) <= 64
        )
        return bool(
            valid_shape
            and verify_message(
                signing_public_key,
                canonical_json(dict(claim)),
                b64url_decode(signature, expected_length=64),
                context=WORKER_ENROLLMENT_CONTEXT,
            )
        )
    except (KeyError, TypeError, ValueError):
        return False


def worker_approval_code(claim: Mapping[str, Any]) -> str:
    """Return a human-comparable code bound to the complete Worker claim.

    The code is public fingerprint material, not a credential.  It is shown on
    the Windows host and independently supplied to the approving administrator,
    so a Gateway cannot silently substitute a different Worker key or claim.
    """

    digest = hashlib.sha256(
        WORKER_APPROVAL_CODE_CONTEXT + canonical_json(dict(claim))
    ).hexdigest()[:20].upper()
    return "-".join(digest[index : index + 4] for index in range(0, len(digest), 4))


def _normalized_approval_code(value: str) -> str:
    compact = "".join(character for character in value.strip().upper() if character != "-")
    if len(compact) != 20 or any(character not in "0123456789ABCDEF" for character in compact):
        raise WorkerEnrollmentError(
            "Worker verification code must contain five groups of four hexadecimal characters."
        )
    return "-".join(compact[index : index + 4] for index in range(0, 20, 4))


def require_pending_worker_claim(
    response: Mapping[str, Any],
    *,
    enrollment_id: str,
    workspace_id: str,
    issuer_user_id: str,
    approval_code: str,
) -> dict[str, Any]:
    """Validate the pending claim returned to the approving owner.

    This check is deliberately repeated in the CLI even though the Gateway is
    expected to verify the signature.  Otherwise a compromised Gateway could
    substitute a different Worker key immediately before certificate signing.
    """

    enrollment = response.get("enrollment")
    if not isinstance(enrollment, Mapping):
        raise WorkerEnrollmentError("Gateway returned no Worker enrollment.")
    claim = enrollment.get("claim")
    proof_signature = enrollment.get("proof_signature")
    if (
        str(enrollment.get("id")) != enrollment_id
        or str(enrollment.get("workspace_id")) != workspace_id
        or str(enrollment.get("issuer_user_id")) != issuer_user_id
        or enrollment.get("state") != "pending"
        or not isinstance(claim, Mapping)
        or str(claim.get("invite_id")) != enrollment_id
        or not isinstance(proof_signature, str)
        or not verify_worker_claim(claim, proof_signature)
    ):
        raise WorkerEnrollmentError("Gateway returned an invalid pending Worker claim.")
    expected_code = worker_approval_code(claim)
    if not secrets.compare_digest(
        expected_code,
        _normalized_approval_code(approval_code),
    ):
        raise WorkerEnrollmentError(
            "Worker verification code does not match; refusing to sign this Worker key."
        )
    return dict(claim)


def _enrollment_signer(identity: WorkerIdentity) -> Callable[[str, str, bytes], dict[str, str]]:
    def sign(method: str, path: str, body: bytes) -> dict[str, str]:
        return sign_http_request(
            identity.device_keys,
            method=method,
            path=path,
            body=body,
        ).to_headers()

    return sign


def _validate_enrollment_response(
    response: Mapping[str, Any],
    *,
    invite: PinnedInvite,
    identity: WorkerIdentity,
) -> tuple[str, str]:
    enrollment = response.get("enrollment")
    if not isinstance(enrollment, Mapping):
        raise WorkerEnrollmentError("Gateway returned no Worker enrollment.")
    enrollment_id = str(enrollment.get("id") or "")
    state = str(enrollment.get("state") or "")
    if (
        enrollment_id != invite.invite_id
        or str(enrollment.get("workspace_id")) != invite.authority.workspace_id
        or str(enrollment.get("issuer_user_id")) != invite.authority.user_id
        or not state
    ):
        raise WorkerEnrollmentError("Gateway Worker enrollment does not match the trusted Invite.")
    worker_key_id = enrollment.get("worker_key_id")
    if worker_key_id is not None and str(worker_key_id) != identity.key_id:
        raise WorkerEnrollmentError("Gateway Worker enrollment changed the local Worker key.")
    return enrollment_id, state


def _validate_active_worker(
    response: Mapping[str, Any],
    *,
    invite: PinnedInvite,
    identity: WorkerIdentity,
) -> str:
    worker = response.get("worker")
    if not isinstance(worker, Mapping):
        raise WorkerEnrollmentError("Approved enrollment returned no Worker registration.")
    info = identity.public_info()
    try:
        certificate_value = worker.get("certificate")
        certificate = (
            json.loads(certificate_value)
            if isinstance(certificate_value, str)
            else certificate_value
        )
        root_public = b64url_decode(
            invite.authority.root_signing_public_key,
            expected_length=32,
        )
        manifest = certificate["manifest"]
        valid = (
            isinstance(certificate, Mapping)
            and verify_key_manifest(certificate, root_public)
            and certificate.get("signer_key_id") == invite.authority.root_key_id
            and manifest.get("version") == 1
            and manifest.get("kind") == "vgen-worker-owner-certificate"
            and manifest.get("owner_root_key_id") == invite.authority.root_key_id
            and manifest.get("worker_key_id") == identity.key_id
            and manifest.get("worker_signing_public_key") == info["signing_public_key"]
            and manifest.get("worker_encryption_public_key") == info["encryption_public_key"]
            and worker.get("signing_public_key") == info["signing_public_key"]
            and worker.get("encryption_public_key") == info["encryption_public_key"]
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        valid = False
    worker_id = str(worker.get("id") or "")
    if not valid or not worker_id:
        raise WorkerEnrollmentError("Approved Worker certificate is invalid.")
    return worker_id


def enroll_worker_from_invite(
    *,
    gateway_url: str,
    invite: PinnedInvite,
    name: str,
    identity_file: Path,
    credentials_file: Path,
    executor_type: str = "comfyui",
    executor_version: str = "1.1.0",
    capabilities: Mapping[str, Any] | None = None,
    capacity: int = 1,
    wait: bool = True,
    interval: float = 2.0,
    timeout: float = 1800.0,
    overwrite_identity: bool = False,
    transport: Any | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> WorkerEnrollmentResult:
    """Claim, wait for approval, authenticate, and persist Worker credentials."""

    if interval <= 0 or timeout <= 0:
        raise WorkerEnrollmentError("Enrollment interval and timeout must be positive.")
    credentials_target = credentials_file.expanduser()
    if credentials_target.exists() or credentials_target.is_symlink():
        raise WorkerEnrollmentError("Worker credentials already exist; refusing to replace them.")
    identity_store = WorkerIdentityStore()
    identity_target = identity_file.expanduser()
    if identity_target.exists() or identity_target.is_symlink():
        identity = identity_store.load("bootstrap", file_path=identity_file)
    else:
        identity = identity_store.generate(
            "bootstrap",
            file_path=identity_file,
            overwrite=overwrite_identity,
        )

    claim = worker_claim_payload(
        identity,
        invite_id=invite.invite_id,
        name=name,
        executor_type=executor_type,
        executor_version=executor_version,
        capabilities=capabilities,
        capacity=capacity,
    )
    print(
        f"Worker verification code: {worker_approval_code(claim)}",
        file=sys.stderr,
    )
    print(
        "Send this code to the Workspace administrator through a trusted channel.",
        file=sys.stderr,
    )
    profile = GatewayProfile(name="worker-enrollment", endpoint=gateway_url)
    client = GatewayClient(
        profile,
        signer=_enrollment_signer(identity),
        transport=transport,
    )
    try:
        response = client.request(
            "POST",
            "/api/v1/worker-enrollments/claim",
            json_body={
                "invite_id": invite.invite_id,
                "secret": invite.secret,
                "claim": claim,
                "proof_signature": sign_worker_claim(identity, claim),
            },
            idempotency_key=f"worker-enrollment:{invite.invite_id}:{identity.key_id}",
            auth=False,
        )
        if not isinstance(response, Mapping):
            raise WorkerEnrollmentError("Gateway returned an invalid Worker enrollment response.")
        enrollment_id, state = _validate_enrollment_response(
            response,
            invite=invite,
            identity=identity,
        )
        if state not in TERMINAL_ENROLLMENT_STATES:
            print(
                "Worker Invite claimed; waiting for Workspace administrator approval...",
                file=sys.stderr,
            )
        deadline = time.monotonic() + timeout
        while state not in TERMINAL_ENROLLMENT_STATES:
            if not wait:
                raise WorkerEnrollmentError("Worker enrollment requires administrator approval.")
            if time.monotonic() >= deadline:
                raise TimeoutError("Worker enrollment approval did not finish before the timeout.")
            sleep(min(interval, max(0.0, deadline - time.monotonic())))
            response = client.request(
                "GET",
                f"/api/v1/worker-enrollments/{enrollment_id}",
            )
            if not isinstance(response, Mapping):
                raise WorkerEnrollmentError(
                    "Gateway returned an invalid Worker enrollment response."
                )
            _, state = _validate_enrollment_response(
                response,
                invite=invite,
                identity=identity,
            )
        if state != "active":
            raise WorkerEnrollmentError(f"Worker enrollment finished with state '{state}'.")
        worker_id = _validate_active_worker(response, invite=invite, identity=identity)
    finally:
        client.close()

    session = login_worker_session(profile, worker_id, identity.device_keys)
    credentials = WorkerCredentials(
        worker_id=worker_id,
        device_keys=identity.device_keys,
        session_token=str(session["token"]),
        owner_root_signing_public_key=invite.authority.root_signing_public_key,
    )
    save_worker_credentials_file(credentials_target, credentials)
    return WorkerEnrollmentResult(
        worker_id=worker_id,
        enrollment_id=enrollment_id,
        credentials_path=credentials_target.resolve(),
        state=state,
    )


def public_claim_digest(claim: Mapping[str, Any]) -> str:
    """Return a log-safe digest for admin review and audit records."""

    return "sha256:" + hashlib.sha256(canonical_json(dict(claim))).hexdigest()
