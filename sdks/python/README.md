# VGen Python SDK

English | [简体中文](README.zh-CN.md)

`vgen-sdk` provides the credential, signing, and end-to-end encryption primitives needed by a
VGen API Service. It is an independent package: it does not import or install the VGen CLI,
Gateway, Broker, or Worker.

The first release intentionally contains no HTTP client and no workflow builder. Your application
keeps control of its HTTP stack while this package handles the protocol operations that should not
be reimplemented casually.

## Install

From this repository:

```bash
python -m pip install ./sdks/python
```

Runtime dependencies are limited to `cryptography` and `PyNaCl`.

## Supported protocol operations

- Read and write the existing `vgen-service-credentials` version 1 format.
- Generate compatible Ed25519/X25519 Service keys and `devkey_...` key IDs.
- Sign Service authentication challenges and build challenge/session request bodies.
- Sign exact HTTP request bytes with VGen's constrained RFC 9421 profile.
- Verify root-signed key manifests, Worker owner certificates, and Workspace allocation proofs
  against trust roots supplied by the application.
- Encrypt small payloads with XChaCha20-Poly1305-IETF.
- Wrap task keys for Workers and Service readers with RFC 9180 HPKE Base mode using X25519,
  HKDF-SHA256, and ChaCha20-Poly1305.
- Provide low-level Workspace key and Workspace reader primitives for protocol compatibility.
- Build canonical task and Workspace AAD.

The wire formats and cryptographic outputs are tested against the same compatibility vectors used
by the existing VGen implementation and the Java SDK.

## Load Service credentials

An administrator can create the Service and its credential file with the existing VGen management
flow. The application then loads only that file; it does not need a CLI Profile or user Device
identity.

```python
from vgen_sdk import ServiceCredentials

credentials = ServiceCredentials.load("/run/secrets/vgen-service.json")

print(credentials.service_id)
print(credentials.workspace_id)
print(credentials.scopes)
```

On POSIX systems, `load()` requires mode `0600` and rejects symbolic links. `save()` writes a new
file atomically with mode `0600`:

```python
credentials.save("/run/secrets/vgen-service-copy.json")
```

Do not log, commit, or transmit the credential file. It contains both private keys.

## Authenticate a Service

The SDK only builds request bodies. Send them with your normal HTTP client.

```python
from vgen_sdk import (
    build_service_challenge_request,
    build_service_session_request,
)

challenge_request = build_service_challenge_request(credentials)
# POST /api/v1/auth/challenges with challenge_request
challenge_response = {
    "challenge_id": "ses_...",
    "challenge": "...",
    "principal_type": "service",
}

session_request = build_service_session_request(credentials, challenge_response)
# POST /api/v1/auth/sessions with session_request
```

The session response contains a short-lived Bearer token. Keep it in memory and never print it.

## Sign a mutation request

Sign the exact bytes that will be sent. The `path` must include the raw query string, in the same
order and encoding used on the wire.

```python
from vgen_sdk import canonical_json, sign_http_request

body = canonical_json({"worker_tdk_envelope": "..."})
task_id = "tsk_aaaaaaaaaaaaaaaaaaaaaaaaaa"
signature_headers = sign_http_request(
    credentials.keys,
    method="POST",
    path=f"/api/v1/tasks/{task_id}/commit",
    body=body,
).to_headers()

headers = {
    "Authorization": f"Bearer {session_token}",
    "Content-Type": "application/json",
    "Vgen-Protocol-Version": "1",
    "Idempotency-Key": "order-123",
    **signature_headers,
}
```

Do not let the HTTP library reserialize `body` after signing it.

## Service reader envelope boundary

The current Gateway does not provision a Workspace Data Key to a Service. A Service must therefore
HPKE-wrap the Task Data Key a second time to its own X25519 public key. The Gateway stores that
`reader_envelope` as opaque data; the Service later opens it with its own private key.

The Workspace key functions remain available only as low-level compatibility primitives for a
caller that already obtained an independently authorized Workspace envelope. Their presence does
not make Service Workspace-key provisioning available.

## Verify the prepared Worker and allocation

Never wrap a task key until both statements pass. The Owner and Workspace root keys below must come
from application-managed trust configuration; do not take them from the untrusted prepare response.

```python
from vgen_sdk import (
    build_allocation_proof_payload,
    verify_allocation_proof,
    verify_worker_owner_certificate,
)

worker = prepared["worker"]
if not verify_worker_owner_certificate(worker, trusted_worker_owner_root_key):
    raise ValueError("untrusted Worker owner certificate")

allocation = prepared["allocation"]
proof = allocation["proof"]
expected_allocation = build_allocation_proof_payload(
    allocation_id=allocation["id"],
    workspace_id=credentials.workspace_id,
    pool_id=pool_id,
    worker_id=worker["id"],
    worker_signing_public_key=worker["signing_public_key"],
    worker_encryption_public_key=worker["encryption_public_key"],
    worker_certificate=worker["certificate"],
    owner_consent_at=float(allocation["owner_consent_at"]),
    approver_root_key_id=proof["payload"]["approver_root_key_id"],
    issued_at=int(proof["payload"]["issued_at"]),
)
if not verify_allocation_proof(
    proof,
    trusted_workspace_admin_root_key,
    expected=expected_allocation,
):
    raise ValueError("untrusted Workspace allocation")
```

## Encrypt a prepared task

Use IDs returned by `POST /api/v1/tasks/prepare`. Payload and reader AAD use
`content_attempt_id`; the Worker key wrap uses the current `attempt_id`.

```python
import json

from vgen_sdk import (
    HPKE_ALGORITHM,
    b64url_decode,
    encrypt_payload,
    generate_task_data_key,
    task_aad,
    unwrap_task_key,
    wrap_task_key,
)

task_key = generate_task_data_key()
content_attempt_id = prepared.get("content_attempt_id") or prepared["attempt_id"]
key_version = int(prepared["key_version"])

content_aad = task_aad(
    workspace_id=credentials.workspace_id,
    task_id=prepared["id"],
    attempt_id=content_attempt_id,
    key_version=key_version,
)
worker_wrap_aad = task_aad(
    workspace_id=credentials.workspace_id,
    task_id=prepared["id"],
    attempt_id=prepared["attempt_id"],
    key_version=key_version,
)

plaintext = json.dumps(
    {
        "workflow": workflow_graph,
        "input_bindings": [],
        "effective_parameters": parameters,
    },
    ensure_ascii=False,
    separators=(",", ":"),
).encode("utf-8")

encrypted_payload = encrypt_payload(task_key, plaintext, aad=content_aad)
worker_envelope = wrap_task_key(
    b64url_decode(prepared["worker"]["encryption_public_key"], expected_length=32),
    task_key,
    aad=worker_wrap_aad,
)
reader_envelope = wrap_task_key(
    credentials.keys.encryption_public_bytes(),
    task_key,
    aad=content_aad,
)

commit_body = {
    "encrypted_payload": json.dumps(encrypted_payload.to_dict(), separators=(",", ":")),
    "worker_tdk_envelope": json.dumps(worker_envelope.to_dict(), separators=(",", ":")),
    "reader_envelope": json.dumps(reader_envelope.to_dict(), separators=(",", ":")),
    "key_algorithm": HPKE_ALGORITHM,
    "artifacts": [],
    "artifact_receipts": [],
}
```

When reading the result, rebuild the same content AAD from the reader response and open the opaque
reader envelope locally:

```python
reader_task_key = unwrap_task_key(
    credentials.keys.encryption_private_key,
    json.loads(reader_response["reader_envelope"]),
    aad=content_aad,
)
```

The SDK verifies signatures and bindings. Deciding which Owner and Workspace root keys are trusted
remains the application's responsibility.

## Development

Run the isolated SDK tests from this directory:

```bash
python -m pytest
python -m ruff check .
```

The tests read `tests/sdk_compat/vectors.json` from the repository root. Fixture private keys are
public test data and must never be used outside tests.
