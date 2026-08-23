# SDK compatibility contract

[中文](zh-CN/sdk-compatibility.md)

This document defines the byte-level contract shared by the VGen Python and Java SDKs. It is intentionally extracted from the production CLI, Gateway, and Worker protocol without changing those runtimes. SDK work must remain additive: an SDK may call the existing API, but it must not change an existing request, ciphertext, credential, or runtime behavior to make its own implementation easier.

The source of truth for executable examples is [`tests/sdk_compat/vectors.json`](../tests/sdk_compat/vectors.json). Every private key and secret in that file is public test material and must never be used outside tests.

## Delivery scope

This SDK release provides low-level, cross-language protocol primitives. It does not add or change Gateway endpoints, build workflows, transfer media, manage trust pins, or provide a complete task HTTP client. The primitives are sufficient for an application to construct the cryptographic parts of the existing Service task flow. The current Gateway does not admit a new API Service as a Workspace Data Key recipient, so the public Service flow uses the direct HPKE reader envelope defined below. The Workspace-key-specific sections remain compatibility primitives for already authorized protocol artifacts. Worker certificate and allocation-proof verification remain mandatory before disclosing a Task Data Key to a prepared Worker.

## API Service identity

An API Service has its own `service_id`, signing key, encryption key, scopes, and Workspace membership. It does not reuse a User Device identity, CLI Profile, User recovery key, Worker credential, or their keyring entries.

The stable credential file remains `vgen-service-credentials` version 1:

```json
{
  "format": "vgen-service-credentials",
  "version": 1,
  "service_id": "svc_...",
  "workspace_id": "wsp_...",
  "name": "render-service",
  "scopes": ["task:read", "task:submit"],
  "enrollment_id": "enr_...",
  "device_keys": {
    "format": "vgen-device-keys",
    "version": 1,
    "key_id": "devkey_...",
    "signing_private_key": "...",
    "encryption_private_key": "..."
  }
}
```

`device_keys` is the existing wire-format field name for the Service key pair. It does not turn the Service into a User Device. Renaming the field would break already issued credentials, so SDKs must preserve it.

Private credential files must be readable only by their owner on platforms with POSIX permissions (mode `0600`), must not follow symbolic links, and must never be logged. Writers use compact JSON with keys sorted lexicographically, ASCII escaping enabled, and one final LF byte. Readers should accept insignificant JSON whitespace and object field order, then validate the format, version, key lengths, and derived `key_id`.

## Common encoding rules

- Text is UTF-8.
- Binary JSON fields use RFC 4648 URL-safe Base64 without `=` padding.
- RFC 9421 `Content-Digest` and `Signature` values use standard Base64 with padding.
- Ed25519 and X25519 private and public keys are raw 32-byte values.
- XChaCha20-Poly1305 keys are 32 bytes and nonces are 24 bytes.
- Integer fields used in signed objects must be integers, not floating-point values.

Signed JSON uses the existing VGen canonical JSON profile:

1. Sort object keys lexicographically at every level.
2. Emit no whitespace outside JSON strings.
3. Encode non-ASCII text directly as UTF-8.
4. Reject NaN and infinities.

This profile is not advertised as full RFC 8785. SDKs must reproduce the fixed canonical JSON vector before signing protocol objects.

## Key identifiers and challenge signatures

For raw Ed25519 public key `pk`:

```text
device key id = "devkey_" + base64url_no_pad(
  SHA-256("vgen-device-key-id-v1" || 0x00 || pk)[0:20]
)

root key id = "root_" + base64url_no_pad(
  SHA-256("vgen-root-key-id-v1" || 0x00 || pk)[0:20]
)
```

An API Service signs a Gateway challenge with Ed25519 over these exact bytes:

```text
UTF8("vgen-message-signature-v1") || 0x00 || UTF8(challenge)
```

The response signature is unpadded Base64url. A challenge is short-lived and single-use; an SDK must request a new challenge instead of retrying a consumed or expired one.

## Root trust, Worker certificates, and allocation proofs

The User/Admin root signing key is a separate trust anchor from the API Service keys. An SDK must receive the trusted root public key through an authenticated or locally pinned authority; it must not trust a root key merely because the same Gateway response contains it.

A generic signed key manifest has this shape:

```json
{
  "manifest": { "...": "..." },
  "signer_key_id": "root_...",
  "signature": "..."
}
```

The signature is Ed25519 over:

```text
UTF8("vgen-key-manifest-v1") || 0x00 || canonical_json(manifest)
```

Verification derives `signer_key_id` from the trusted root public key and rejects any mismatch before accepting the signature.

A Worker owner certificate is a specialized key manifest whose manifest contains exactly these bindings:

```json
{
  "version": 1,
  "kind": "vgen-worker-owner-certificate",
  "owner_root_key_id": "root_...",
  "worker_key_id": "devkey_...",
  "worker_signing_public_key": "...",
  "worker_encryption_public_key": "...",
  "issued_at": 1787490000
}
```

The verifier must check the root signature, `owner_root_key_id`, the `worker_key_id` derived from the presented Worker signing key, and exact equality of both presented Worker public keys. A valid signature alone is insufficient: substituting either Worker key must fail.

The certificate digest used by an allocation proof includes the complete signed certificate, not only its manifest:

```text
"sha256:" + lowercase_hex(SHA-256(canonical_json(certificate)))
```

A Workspace allocation proof signs a payload with `vgen-workspace-allocation-proof-v1` as its signature context. Its payload binds all of the following fields:

```text
version, kind, allocation_id, workspace_id, pool_id, worker_id,
worker_signing_public_key, worker_encryption_public_key,
worker_certificate_digest, owner_consent_at_ms,
approver_root_key_id, issued_at
```

`kind` is `vgen-workspace-worker-allocation`; `owner_consent_at_ms` is an integer. The verifier must rebuild the expected payload from the selected Workspace, Pool, Worker, certificate, and consent record, require exact field equality, verify the pinned approver root key ID, and then verify the context-bound Ed25519 signature. Changing any bound value, including only the Pool ID or Worker key, must fail before a Task Data Key is wrapped for that Worker.

## HTTP request-signature profile

Authenticated writes use the existing constrained RFC 9421 profile. The covered components and their order are fixed:

```text
("@method" "@path" "content-digest")
```

The signature parameters are also ordered exactly:

```text
created;nonce;keyid;alg="ed25519"
```

`@method` is uppercase. `@path` is the exact ASCII request target beginning with `/`, including the raw query string when present. `Content-Digest` is SHA-256 of the exact HTTP body bytes. The body must not be serialized again after the digest and signature are calculated.

Every signed request uses a fresh, cryptographically random Base64url nonce and a current Unix timestamp. The fixed time and nonce in the compatibility vector exist only to make tests deterministic.

## Task AAD and payload encryption

Task payloads and artifacts bind encryption to canonical AAD with these exact fields:

```json
{
  "protocol_version": "v1",
  "workspace_id": "wsp_...",
  "task_id": "tsk_...",
  "attempt_id": "atm_...",
  "artifact_id": "payload",
  "key_version": 1
}
```

The AAD bytes are the canonical JSON encoding of that object. Payload encryption is libsodium-compatible XChaCha20-Poly1305-IETF. The serialized ciphertext object is:

```json
{
  "algorithm": "XChaCha20-Poly1305-IETF",
  "nonce": "<24-byte base64url nonce>",
  "ciphertext": "<ciphertext followed by the 16-byte tag>"
}
```

Production code must generate a new random 32-byte Task Data Key and a new random nonce. A `(key, nonce)` pair must never be reused.

## HPKE envelopes

VGen uses RFC 9180 HPKE Base mode with this exact suite:

```text
KEM  = DHKEM(X25519, HKDF-SHA256)  0x0020
KDF  = HKDF-SHA256                  0x0001
AEAD = ChaCha20-Poly1305            0x0003
```

The algorithm identifier is `HPKE-Base-X25519-HKDF-SHA256-ChaCha20Poly1305`. An envelope contains the 32-byte encapsulated public key and the AEAD ciphertext, both unpadded Base64url.

Wrapping a Task Data Key uses:

```text
info = UTF8("vgen-task-key-wrap-v1") || 0x00 || SHA-256(task_aad)
aad  = task_aad
```

At the protocol-primitive level, wrapping a Workspace Data Key for a bound recipient uses:

```text
info = UTF8("vgen-workspace-key-wrap-v1") || 0x00 || SHA-256(workspace_key_aad)
aad  = workspace_key_aad
```

The current recipient-bound Workspace AAD is canonical JSON containing `protocol_version: "v2"`, `workspace_id`, `recipient_type`, `recipient_id`, `key_version`, and the lowercase 64-character `recipient_binding_digest`. SDKs may read legacy v1 envelopes that omit the binding digest. Creating and distributing a new Service-bound envelope requires a future Service recipient-admission flow and is not part of this SDK delivery.

HPKE sealing is randomized. The vector includes a sender ephemeral private key solely so each SDK can run a deterministic internal conformance test. Public production APIs must not accept a caller-selected ephemeral key.

## Direct API Service reader envelope

An API Service that generates a Task Data Key locally can preserve its own read access without a Workspace Data Key. It wraps that Task Data Key directly to the X25519 public key in its independent `vgen-service-credentials` file, using the same Task-key HPKE `info` and Task AAD defined above. The result is an ordinary HPKE envelope; the Service later opens it with its credential encryption private key.

This direct reader primitive does not grant access to another principal and does not replace Workspace recipient admission. It also does not add an HTTP task client in this SDK release. The fixed `service_reader` vector proves that Python, Java, and the production primitives interpret the direct envelope identically.

## Workspace reader envelope

A Workspace reader envelope protects the Task Data Key with the versioned Workspace Data Key using XChaCha20-Poly1305. Its effective AAD is:

```text
UTF8("vgen-workspace-reader-envelope-v1") || 0x00 || task_aad
```

It uses the same serialized shape as a payload ciphertext. Once a principal has been admitted and provisioned with a Workspace Data Key by a supported flow, this envelope lets it recover the Task Data Key while the Gateway continues to route ciphertext only. New Service admission is outside the current SDK scope.

## Conformance policy

Both SDKs must load the same root vector file and verify, at minimum:

- canonical JSON and Base64url handling;
- Service credential parsing and byte-for-byte serialization;
- public-key derivation, key IDs, and challenge signatures;
- root key IDs, generic key manifests, and signature contexts;
- Worker owner certificate bindings and full-certificate digest;
- every Workspace allocation proof binding;
- RFC 9421 request signature headers;
- Task and Workspace AAD;
- XChaCha payload encryption and decryption;
- HPKE open plus deterministic test-only seal;
- a direct HPKE reader envelope for the API Service that owns the credential;
- Task-key, Workspace-key, and Workspace-reader envelopes.

Existing vector fields and expected values are immutable. New cases may be added without changing old ones. A semantic break requires a new vector version and an explicit protocol migration; it must never be silently introduced by one SDK.

The checked-in values are reproducible from the production Python primitives:

```bash
PYTHONPATH=src .venv/bin/python tests/sdk_compat/generate_vectors.py
```

Run the production implementation check with:

```bash
pytest -q tests/sdk_compat
```
