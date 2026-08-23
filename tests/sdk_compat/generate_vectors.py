"""Regenerate the public, deterministic VGen SDK compatibility vectors.

Every private key in this generator and its output is an intentionally public
test fixture. Never reuse any of this key material in a deployed environment.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import vgen.crypto.envelope as crypto_envelope
from vgen.cli.service_credentials import ServiceCredentials
from vgen.crypto import (
    ALLOCATION_PROOF_CONTEXT,
    HPKE_ALGORITHM,
    MANIFEST_CONTEXT,
    DeviceKeys,
    IdentityKeys,
    b64url_encode,
    build_allocation_proof_payload,
    canonical_json,
    device_key_id,
    encrypt_payload,
    hpke_seal,
    root_signing_key_id,
    sign_allocation_proof,
    sign_http_request,
    sign_key_manifest,
    sign_message,
    task_aad,
    worker_certificate_digest,
    workspace_key_aad,
    wrap_task_key,
    wrap_task_key_for_workspace,
    wrap_workspace_key,
)

OUTPUT = Path(__file__).with_name("vectors.json")


def _b64(value: bytes) -> str:
    return b64url_encode(value)


def _raw_x25519_public(private_key: X25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


@contextmanager
def _fixed_hpke_ephemeral(private_key: bytes) -> Iterator[None]:
    actual_class = crypto_envelope.X25519PrivateKey

    class FixedEphemeralFactory:
        @staticmethod
        def generate() -> X25519PrivateKey:
            return actual_class.from_private_bytes(private_key)

    crypto_envelope.X25519PrivateKey = FixedEphemeralFactory  # type: ignore[assignment]
    try:
        yield
    finally:
        crypto_envelope.X25519PrivateKey = actual_class


@contextmanager
def _fixed_nonce(nonce: bytes) -> Iterator[None]:
    actual_token_bytes = crypto_envelope.secrets.token_bytes
    crypto_envelope.secrets.token_bytes = lambda size: nonce
    try:
        yield
    finally:
        crypto_envelope.secrets.token_bytes = actual_token_bytes


def _seal_with_ephemeral(private_key: bytes, operation: Callable[[], Any]) -> Any:
    with _fixed_hpke_ephemeral(private_key):
        return operation()


def _encrypt_with_nonce(nonce: bytes, operation: Callable[[], Any]) -> Any:
    with _fixed_nonce(nonce):
        return operation()


def build_vectors() -> dict[str, Any]:
    service_id = "svc_" + "a" * 26
    workspace_id = "wsp_" + "b" * 26
    enrollment_id = "enr_" + "c" * 26
    task_id = "tsk_" + "d" * 26
    attempt_id = "atm_" + "e" * 26
    worker_id = "wrk_" + "f" * 26
    allocation_id = "wal_" + "g" * 26
    pool_id = "pol_" + "h" * 26
    manifest_id = "kmf_" + "i" * 26

    root_signing_private_key = hashlib.sha256(b"vgen-sdk-compat-root-signing-private-key").digest()
    root_encryption_private_key = hashlib.sha256(
        b"vgen-sdk-compat-root-encryption-private-key"
    ).digest()
    root_identity = IdentityKeys(
        Ed25519PrivateKey.from_private_bytes(root_signing_private_key),
        X25519PrivateKey.from_private_bytes(root_encryption_private_key),
    )

    worker_signing_private_key = hashlib.sha256(
        b"vgen-sdk-compat-worker-signing-private-key"
    ).digest()
    worker_encryption_private_key = bytes.fromhex(
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
    )
    worker_keys = DeviceKeys(
        Ed25519PrivateKey.from_private_bytes(worker_signing_private_key),
        X25519PrivateKey.from_private_bytes(worker_encryption_private_key),
    )

    signing_private_key = bytes(range(32))
    encryption_private_key = bytes(range(32, 64))
    service_keys = DeviceKeys(
        Ed25519PrivateKey.from_private_bytes(signing_private_key),
        X25519PrivateKey.from_private_bytes(encryption_private_key),
    )
    credentials = ServiceCredentials.generate(
        service_id=service_id,
        workspace_id=workspace_id,
        name="SDK Compatibility Fixture",
        scopes=["task:submit", "task:read", "task:cancel"],
        enrollment_id=enrollment_id,
        device_keys=service_keys,
    )
    credential_bytes = credentials.to_bytes()

    generic_manifest = {
        "version": 1,
        "kind": "vgen-sdk-compat-key-manifest",
        "manifest_id": manifest_id,
        "workspace_id": workspace_id,
        "recipient_type": "service",
        "recipient_id": service_id,
        "recipient_key_id": service_keys.key_id,
        "signing_public_key": _b64(service_keys.signing_public_bytes()),
        "encryption_public_key": _b64(service_keys.encryption_public_bytes()),
        "key_version": 3,
        "algorithm": HPKE_ALGORITHM,
        "issued_at": 1787490000,
    }
    generic_manifest_bytes = canonical_json(generic_manifest)
    signed_generic_manifest = sign_key_manifest(root_identity, generic_manifest)

    worker_certificate_manifest = {
        "version": 1,
        "kind": "vgen-worker-owner-certificate",
        "owner_root_key_id": root_identity.root_key_id,
        "worker_key_id": worker_keys.key_id,
        "worker_signing_public_key": _b64(worker_keys.signing_public_bytes()),
        "worker_encryption_public_key": _b64(worker_keys.encryption_public_bytes()),
        "issued_at": 1787490000,
    }
    worker_certificate_manifest_bytes = canonical_json(worker_certificate_manifest)
    worker_certificate = sign_key_manifest(root_identity, worker_certificate_manifest)
    worker_certificate_bytes = canonical_json(worker_certificate)
    certificate_digest = worker_certificate_digest(worker_certificate)

    owner_consent_at = 1787489999.125
    allocation_payload = build_allocation_proof_payload(
        allocation_id=allocation_id,
        workspace_id=workspace_id,
        pool_id=pool_id,
        worker_id=worker_id,
        worker_signing_public_key=_b64(worker_keys.signing_public_bytes()),
        worker_encryption_public_key=_b64(worker_keys.encryption_public_bytes()),
        worker_certificate=worker_certificate,
        owner_consent_at=owner_consent_at,
        approver_root_key_id=root_identity.root_key_id,
        issued_at=1787490001,
    )
    allocation_payload_bytes = canonical_json(allocation_payload)
    allocation_proof = sign_allocation_proof(root_identity, allocation_payload)

    canonical_input = {
        "z": "最后",
        "a": [True, None, {"n": 42, "s": "café"}],
        "escaped": 'line\n"quote"',
    }
    canonical = canonical_json(canonical_input)

    challenge = "sdk-compat-challenge-LOtHj2mfLSs6BsxE5p8sSMwbPUr8aF8o"
    challenge_signing_input = b"vgen-message-signature-v1\x00" + challenge.encode("utf-8")
    challenge_signature = sign_message(
        service_keys.signing_private_key,
        challenge.encode("utf-8"),
    )

    http_body = canonical_json(
        {
            "parameters": {"frames": 39, "seed": -1},
            "prompt": "A café at sunrise",
            "workflow": "vgen/minimax-h3-8step@1.0.0",
        }
    )
    http_path = f"/api/v1/tasks/{task_id}/commit?dry_run=true"
    http_signature = sign_http_request(
        signing_private_key,
        method="POST",
        path=http_path,
        body=http_body,
        key_id=service_keys.key_id,
        created=1787490000,
        nonce="sdk_compat_nonce_000001",
    )
    signature_parameters = http_signature.signature_input.split("=", 1)[1]
    signature_base = (
        '"@method": POST\n'
        f'"@path": {http_path}\n'
        f'"content-digest": {http_signature.content_digest}\n'
        f'"@signature-params": {signature_parameters}'
    ).encode()

    task_fields = {
        "workspace_id": workspace_id,
        "task_id": task_id,
        "attempt_id": attempt_id,
        "artifact_id": "payload",
        "key_version": 3,
    }
    task_binding = task_aad(**task_fields)
    recipient_binding_digest = hashlib.sha256(canonical_json(credentials.public_info())).hexdigest()
    workspace_fields = {
        "workspace_id": workspace_id,
        "recipient_type": "service",
        "recipient_id": service_id,
        "key_version": 3,
        "recipient_binding_digest": recipient_binding_digest,
    }
    workspace_binding = workspace_key_aad(**workspace_fields)

    task_key = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
    workspace_key = bytes.fromhex("ffeeddccbbaa99887766554433221100" * 2)
    plaintext = canonical_json(
        {
            "effective_parameters": {"fps": 24, "frames": 39},
            "input_bindings": [],
            "workflow": {
                "1": {
                    "class_type": "VGenSdkFixture",
                    "inputs": {"prompt": "hello"},
                }
            },
        }
    )
    payload_nonce = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
    payload = _encrypt_with_nonce(
        payload_nonce,
        lambda: encrypt_payload(task_key, plaintext, aad=task_binding),
    )

    hpke_recipient_private_bytes = bytes.fromhex(
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    )
    hpke_recipient = X25519PrivateKey.from_private_bytes(hpke_recipient_private_bytes)
    hpke_ephemeral = bytes.fromhex(
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
    )
    hpke_info = b"vgen-sdk-compat-hpke-v1"
    hpke_aad = canonical_json({"kind": "hpke-direct", "version": 1})
    hpke_plaintext = b"VGen HPKE compatibility fixture"
    hpke = _seal_with_ephemeral(
        hpke_ephemeral,
        lambda: hpke_seal(
            hpke_recipient.public_key(),
            hpke_plaintext,
            info=hpke_info,
            aad=hpke_aad,
        ),
    )

    task_ephemeral = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    )
    task_wrap = _seal_with_ephemeral(
        task_ephemeral,
        lambda: wrap_task_key(
            worker_keys.encryption_public_key,
            task_key,
            aad=task_binding,
        ),
    )
    task_wrap_info = b"vgen-task-key-wrap-v1\x00" + hashlib.sha256(task_binding).digest()

    service_reader_ephemeral = hashlib.sha256(
        b"vgen-sdk-compat-service-reader-ephemeral-private-key"
    ).digest()
    service_reader = _seal_with_ephemeral(
        service_reader_ephemeral,
        lambda: wrap_task_key(
            service_keys.encryption_public_key,
            task_key,
            aad=task_binding,
        ),
    )

    workspace_ephemeral = bytes.fromhex(
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    )
    workspace_wrap = _seal_with_ephemeral(
        workspace_ephemeral,
        lambda: wrap_workspace_key(
            service_keys.encryption_public_key,
            workspace_key,
            aad=workspace_binding,
        ),
    )
    workspace_wrap_info = (
        b"vgen-workspace-key-wrap-v1\x00" + hashlib.sha256(workspace_binding).digest()
    )

    reader_nonce = bytes.fromhex("18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
    reader = _encrypt_with_nonce(
        reader_nonce,
        lambda: wrap_task_key_for_workspace(workspace_key, task_key, aad=task_binding),
    )
    reader_aad = b"vgen-workspace-reader-envelope-v1\x00" + task_binding

    return {
        "format": "vgen-sdk-compatibility-vectors",
        "version": 1,
        "warning": (
            "TEST FIXTURES ONLY. Every private key and secret in this file is public and unsafe."
        ),
        "encoding": {
            "canonical_json": {
                "input": canonical_input,
                "output_utf8": canonical.decode("utf-8"),
                "output_hex": canonical.hex(),
                "sha256": hashlib.sha256(canonical).hexdigest(),
            }
        },
        "identity": {
            "signing_private_key": _b64(signing_private_key),
            "signing_public_key": _b64(service_keys.signing_public_bytes()),
            "encryption_private_key": _b64(encryption_private_key),
            "encryption_public_key": _b64(service_keys.encryption_public_bytes()),
            "device_key_id": device_key_id(service_keys.signing_public_bytes()),
            "root_key_id_for_same_signing_key": root_signing_key_id(
                service_keys.signing_public_bytes()
            ),
            "challenge": challenge,
            "challenge_signature_context_utf8": "vgen-message-signature-v1",
            "challenge_signing_input_base64url": _b64(challenge_signing_input),
            "challenge_signature": _b64(challenge_signature),
        },
        "root_identity": {
            "signing_private_key": _b64(root_signing_private_key),
            "signing_public_key": _b64(root_identity.signing_public_bytes()),
            "encryption_private_key": _b64(root_encryption_private_key),
            "encryption_public_key": _b64(root_identity.encryption_public_bytes()),
            "root_key_id": root_identity.root_key_id,
        },
        "key_manifest": {
            "signing_context_utf8": MANIFEST_CONTEXT.decode("ascii"),
            "canonical_manifest_utf8": generic_manifest_bytes.decode("utf-8"),
            "canonical_manifest_base64url": _b64(generic_manifest_bytes),
            "signing_input_base64url": _b64(MANIFEST_CONTEXT + b"\x00" + generic_manifest_bytes),
            "signed": signed_generic_manifest,
        },
        "worker_owner_certificate": {
            "worker": {
                "id": worker_id,
                "signing_private_key": _b64(worker_signing_private_key),
                "signing_public_key": _b64(worker_keys.signing_public_bytes()),
                "encryption_private_key": _b64(worker_encryption_private_key),
                "encryption_public_key": _b64(worker_keys.encryption_public_bytes()),
                "key_id": worker_keys.key_id,
            },
            "signing_context_utf8": MANIFEST_CONTEXT.decode("ascii"),
            "canonical_manifest_utf8": worker_certificate_manifest_bytes.decode("utf-8"),
            "signing_input_base64url": _b64(
                MANIFEST_CONTEXT + b"\x00" + worker_certificate_manifest_bytes
            ),
            "certificate": worker_certificate,
            "canonical_certificate_utf8": worker_certificate_bytes.decode("utf-8"),
            "certificate_digest": certificate_digest,
        },
        "workspace_allocation_proof": {
            "inputs": {
                "allocation_id": allocation_id,
                "workspace_id": workspace_id,
                "pool_id": pool_id,
                "worker_id": worker_id,
                "worker_signing_public_key": _b64(worker_keys.signing_public_bytes()),
                "worker_encryption_public_key": _b64(worker_keys.encryption_public_bytes()),
                "owner_consent_at": owner_consent_at,
                "approver_root_key_id": root_identity.root_key_id,
                "issued_at": 1787490001,
            },
            "worker_certificate_digest": certificate_digest,
            "signing_context_utf8": ALLOCATION_PROOF_CONTEXT.decode("ascii"),
            "canonical_payload_utf8": allocation_payload_bytes.decode("utf-8"),
            "signing_input_base64url": _b64(
                ALLOCATION_PROOF_CONTEXT + b"\x00" + allocation_payload_bytes
            ),
            "proof": allocation_proof,
            "expected_bindings": allocation_payload,
        },
        "service_credentials": {
            "value": json.loads(credential_bytes),
            "serialized_utf8": credential_bytes.decode("utf-8"),
            "serialized_base64url": _b64(credential_bytes),
            "sha256": hashlib.sha256(credential_bytes).hexdigest(),
        },
        "http_signature": {
            "method": "POST",
            "path": http_path,
            "body": http_body.decode("utf-8"),
            "body_base64url": _b64(http_body),
            "created": 1787490000,
            "nonce": "sdk_compat_nonce_000001",
            "key_id": service_keys.key_id,
            "signature_base_utf8": signature_base.decode("utf-8"),
            "headers": http_signature.to_headers(),
        },
        "task_aad": {
            "fields": task_fields,
            "value_utf8": task_binding.decode("utf-8"),
            "value_base64url": _b64(task_binding),
            "sha256": hashlib.sha256(task_binding).hexdigest(),
        },
        "workspace_key_aad": {
            "fields": workspace_fields,
            "value_utf8": workspace_binding.decode("utf-8"),
            "value_base64url": _b64(workspace_binding),
            "sha256": hashlib.sha256(workspace_binding).hexdigest(),
        },
        "payload_xchacha20poly1305": {
            "algorithm": payload.algorithm,
            "key": _b64(task_key),
            "nonce": _b64(payload_nonce),
            "aad": _b64(task_binding),
            "plaintext": _b64(plaintext),
            "plaintext_utf8": plaintext.decode("utf-8"),
            "ciphertext": _b64(payload.ciphertext),
            "serialized": payload.to_dict(),
        },
        "hpke_direct": {
            "algorithm": hpke.algorithm,
            "recipient_private_key": _b64(hpke_recipient_private_bytes),
            "recipient_public_key": _b64(_raw_x25519_public(hpke_recipient)),
            "sender_ephemeral_private_key": _b64(hpke_ephemeral),
            "info": _b64(hpke_info),
            "aad": _b64(hpke_aad),
            "plaintext": _b64(hpke_plaintext),
            "sealed": hpke.to_dict(),
        },
        "task_key_wrap": {
            "algorithm": task_wrap.algorithm,
            "recipient_private_key": _b64(worker_encryption_private_key),
            "recipient_public_key": _b64(worker_keys.encryption_public_bytes()),
            "sender_ephemeral_private_key": _b64(task_ephemeral),
            "task_data_key": _b64(task_key),
            "aad": _b64(task_binding),
            "effective_info": _b64(task_wrap_info),
            "sealed": task_wrap.to_dict(),
        },
        "service_reader": {
            "algorithm": service_reader.algorithm,
            "service_id": service_id,
            "recipient_private_key": _b64(encryption_private_key),
            "recipient_public_key": _b64(service_keys.encryption_public_bytes()),
            "sender_ephemeral_private_key": _b64(service_reader_ephemeral),
            "task_data_key": _b64(task_key),
            "aad": _b64(task_binding),
            "effective_info": _b64(task_wrap_info),
            "sealed": service_reader.to_dict(),
        },
        "workspace_key_wrap": {
            "algorithm": workspace_wrap.algorithm,
            "recipient_private_key": _b64(encryption_private_key),
            "recipient_public_key": _b64(service_keys.encryption_public_bytes()),
            "sender_ephemeral_private_key": _b64(workspace_ephemeral),
            "workspace_data_key": _b64(workspace_key),
            "aad": _b64(workspace_binding),
            "effective_info": _b64(workspace_wrap_info),
            "sealed": workspace_wrap.to_dict(),
        },
        "workspace_reader": {
            "algorithm": reader.algorithm,
            "workspace_data_key": _b64(workspace_key),
            "task_data_key": _b64(task_key),
            "nonce": _b64(reader_nonce),
            "task_aad": _b64(task_binding),
            "effective_aad": _b64(reader_aad),
            "ciphertext": _b64(reader.ciphertext),
            "serialized": reader.to_dict(),
        },
    }


def main() -> None:
    serialized = json.dumps(build_vectors(), ensure_ascii=False, indent=2) + "\n"
    temporary = OUTPUT.with_name(f".{OUTPUT.name}.tmp")
    try:
        temporary.write_text(serialized, encoding="utf-8")
        temporary.replace(OUTPUT)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
