from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import vgen.crypto.envelope as crypto_envelope
from vgen.cli.main import _verify_prepared_worker_certificate
from vgen.cli.service_credentials import ServiceCredentials
from vgen.crypto import (
    IdentityKeys,
    b64url_decode,
    b64url_encode,
    build_allocation_proof_payload,
    canonical_json,
    decrypt_payload,
    device_key_id,
    encrypt_payload,
    hpke_open,
    hpke_seal,
    root_signing_key_id,
    sign_allocation_proof,
    sign_http_request,
    sign_key_manifest,
    sign_message,
    task_aad,
    unwrap_task_key,
    unwrap_task_key_for_workspace,
    unwrap_workspace_key,
    verify_allocation_proof,
    verify_http_request,
    verify_key_manifest,
    verify_message,
    worker_certificate_digest,
    workspace_key_aad,
    wrap_task_key,
    wrap_task_key_for_workspace,
    wrap_workspace_key,
)

VECTOR_PATH = Path(__file__).with_name("vectors.json")


@pytest.fixture(scope="module")
def vectors() -> dict[str, Any]:
    value = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    assert value["format"] == "vgen-sdk-compatibility-vectors"
    assert value["version"] == 1
    return value


def _raw_x25519_public(private_key: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(private_key)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _fixed_hpke_seal(
    monkeypatch: pytest.MonkeyPatch,
    ephemeral_private_key: bytes,
    operation: Callable[[], Any],
) -> Any:
    actual_class = X25519PrivateKey

    class FixedEphemeralFactory:
        @staticmethod
        def generate() -> X25519PrivateKey:
            return actual_class.from_private_bytes(ephemeral_private_key)

    with monkeypatch.context() as scoped:
        scoped.setattr(crypto_envelope, "X25519PrivateKey", FixedEphemeralFactory)
        return operation()


def _fixed_nonce(
    monkeypatch: pytest.MonkeyPatch,
    nonce: bytes,
    operation: Callable[[], Any],
) -> Any:
    with monkeypatch.context() as scoped:
        scoped.setattr(crypto_envelope.secrets, "token_bytes", lambda size: nonce)
        return operation()


def test_canonical_json_vector(vectors: dict[str, Any]) -> None:
    expected = vectors["encoding"]["canonical_json"]
    encoded = canonical_json(expected["input"])
    assert encoded.decode("utf-8") == expected["output_utf8"]
    assert encoded.hex() == expected["output_hex"]
    assert hashlib.sha256(encoded).hexdigest() == expected["sha256"]


def test_fixture_protocol_ids_are_canonical(vectors: dict[str, Any]) -> None:
    credentials = vectors["service_credentials"]["value"]
    task_fields = vectors["task_aad"]["fields"]
    values = {
        "svc": credentials["service_id"],
        "wsp": credentials["workspace_id"],
        "enr": credentials["enrollment_id"],
        "tsk": task_fields["task_id"],
        "atm": task_fields["attempt_id"],
        "wrk": vectors["worker_owner_certificate"]["worker"]["id"],
        "wal": vectors["workspace_allocation_proof"]["inputs"]["allocation_id"],
        "pol": vectors["workspace_allocation_proof"]["inputs"]["pool_id"],
        "kmf": vectors["key_manifest"]["signed"]["manifest"]["manifest_id"],
    }
    for prefix, value in values.items():
        assert re.fullmatch(rf"{prefix}_[a-z2-7]{{26}}", value)


def _root_signing_material(vectors: dict[str, Any]) -> tuple[bytes, bytes]:
    root = vectors["root_identity"]
    return (
        b64url_decode(root["signing_private_key"], expected_length=32),
        b64url_decode(root["signing_public_key"], expected_length=32),
    )


def test_root_identity_and_generic_key_manifest(vectors: dict[str, Any]) -> None:
    root_private, root_public = _root_signing_material(vectors)
    root = vectors["root_identity"]
    derived_public = (
        Ed25519PrivateKey.from_private_bytes(root_private)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    assert derived_public == root_public
    assert root_signing_key_id(root_public) == root["root_key_id"]

    manifest = vectors["key_manifest"]
    signed = manifest["signed"]
    canonical = canonical_json(signed["manifest"])
    assert canonical.decode("utf-8") == manifest["canonical_manifest_utf8"]
    assert b64url_encode(canonical) == manifest["canonical_manifest_base64url"]
    assert (
        b64url_encode(b"vgen-key-manifest-v1\x00" + canonical)
        == manifest["signing_input_base64url"]
    )

    root_encryption_private = b64url_decode(root["encryption_private_key"], expected_length=32)
    assert _raw_x25519_public(root_encryption_private) == b64url_decode(
        root["encryption_public_key"], expected_length=32
    )

    root_keys = IdentityKeys(
        Ed25519PrivateKey.from_private_bytes(root_private),
        X25519PrivateKey.from_private_bytes(root_encryption_private),
    )
    assert sign_key_manifest(root_keys, signed["manifest"]) == signed
    assert verify_key_manifest(signed, root_public)
    tampered = {**signed, "manifest": {**signed["manifest"], "key_version": 4}}
    assert not verify_key_manifest(tampered, root_public)


def test_worker_owner_certificate_vector(vectors: dict[str, Any]) -> None:
    _, root_public = _root_signing_material(vectors)
    expected = vectors["worker_owner_certificate"]
    worker = expected["worker"]
    certificate = expected["certificate"]
    signing_private = b64url_decode(worker["signing_private_key"], expected_length=32)
    encryption_private = b64url_decode(worker["encryption_private_key"], expected_length=32)
    signing_public = (
        Ed25519PrivateKey.from_private_bytes(signing_private)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    assert b64url_encode(signing_public) == worker["signing_public_key"]
    assert b64url_encode(_raw_x25519_public(encryption_private)) == worker["encryption_public_key"]
    assert device_key_id(signing_public) == worker["key_id"]
    assert verify_key_manifest(certificate, root_public)
    assert canonical_json(certificate).decode("utf-8") == expected["canonical_certificate_utf8"]
    assert worker_certificate_digest(certificate) == expected["certificate_digest"]

    manifest = certificate["manifest"]
    assert set(manifest) == {
        "version",
        "kind",
        "owner_root_key_id",
        "worker_key_id",
        "worker_signing_public_key",
        "worker_encryption_public_key",
        "issued_at",
    }
    assert manifest["version"] == 1
    assert manifest["kind"] == "vgen-worker-owner-certificate"
    assert manifest["owner_root_key_id"] == certificate["signer_key_id"]
    assert manifest["worker_key_id"] == worker["key_id"]
    assert manifest["worker_signing_public_key"] == worker["signing_public_key"]
    assert manifest["worker_encryption_public_key"] == worker["encryption_public_key"]

    prepared_worker = {
        "id": worker["id"],
        "signing_public_key": worker["signing_public_key"],
        "encryption_public_key": worker["encryption_public_key"],
        "certificate": certificate,
        "owner_root_signing_public_key": b64url_encode(root_public),
    }
    _verify_prepared_worker_certificate(prepared_worker)
    tampered_worker = {**prepared_worker, "encryption_public_key": b64url_encode(b"\xff" * 32)}
    with pytest.raises(ValueError, match="does not bind"):
        _verify_prepared_worker_certificate(tampered_worker)


def test_workspace_allocation_proof_vector(vectors: dict[str, Any]) -> None:
    root_private, root_public = _root_signing_material(vectors)
    root = vectors["root_identity"]
    allocation = vectors["workspace_allocation_proof"]
    inputs = allocation["inputs"]
    certificate = vectors["worker_owner_certificate"]["certificate"]
    rebuilt = build_allocation_proof_payload(
        allocation_id=inputs["allocation_id"],
        workspace_id=inputs["workspace_id"],
        pool_id=inputs["pool_id"],
        worker_id=inputs["worker_id"],
        worker_signing_public_key=inputs["worker_signing_public_key"],
        worker_encryption_public_key=inputs["worker_encryption_public_key"],
        worker_certificate=certificate,
        owner_consent_at=inputs["owner_consent_at"],
        approver_root_key_id=inputs["approver_root_key_id"],
        issued_at=inputs["issued_at"],
    )
    assert rebuilt == allocation["expected_bindings"]
    assert rebuilt == allocation["proof"]["payload"]
    assert rebuilt["worker_certificate_digest"] == allocation["worker_certificate_digest"]
    canonical = canonical_json(rebuilt)
    assert canonical.decode("utf-8") == allocation["canonical_payload_utf8"]
    assert (
        b64url_encode(b"vgen-workspace-allocation-proof-v1\x00" + canonical)
        == allocation["signing_input_base64url"]
    )

    root_keys = IdentityKeys(
        Ed25519PrivateKey.from_private_bytes(root_private),
        X25519PrivateKey.from_private_bytes(
            b64url_decode(root["encryption_private_key"], expected_length=32)
        ),
    )
    assert sign_allocation_proof(root_keys, rebuilt) == allocation["proof"]
    assert verify_allocation_proof(
        allocation["proof"],
        root_public,
        expected=rebuilt,
        now=inputs["issued_at"],
    )
    tampered_expected = {**rebuilt, "pool_id": "pol_" + "j" * 26}
    assert not verify_allocation_proof(
        allocation["proof"],
        root_public,
        expected=tampered_expected,
        now=inputs["issued_at"],
    )


def test_identity_key_ids_and_challenge_signature(vectors: dict[str, Any]) -> None:
    identity = vectors["identity"]
    signing_private = b64url_decode(identity["signing_private_key"], expected_length=32)
    signing_public = b64url_decode(identity["signing_public_key"], expected_length=32)
    encryption_private = b64url_decode(identity["encryption_private_key"], expected_length=32)
    assert (
        Ed25519PrivateKey.from_private_bytes(signing_private)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        == signing_public
    )
    assert _raw_x25519_public(encryption_private) == b64url_decode(
        identity["encryption_public_key"], expected_length=32
    )
    assert device_key_id(signing_public) == identity["device_key_id"]
    assert root_signing_key_id(signing_public) == identity["root_key_id_for_same_signing_key"]

    challenge = identity["challenge"].encode("utf-8")
    signature = sign_message(signing_private, challenge)
    signing_input = b"vgen-message-signature-v1\x00" + challenge
    assert b64url_encode(signing_input) == identity["challenge_signing_input_base64url"]
    assert b64url_encode(signature) == identity["challenge_signature"]
    assert verify_message(signing_public, challenge, signature)


def test_service_credential_round_trip_vector(vectors: dict[str, Any]) -> None:
    expected = vectors["service_credentials"]
    serialized = expected["serialized_utf8"].encode("utf-8")
    assert b64url_encode(serialized) == expected["serialized_base64url"]
    assert hashlib.sha256(serialized).hexdigest() == expected["sha256"]

    credentials = ServiceCredentials.from_bytes(serialized)
    assert credentials.to_bytes() == serialized
    assert credentials.service_id == expected["value"]["service_id"]
    assert credentials.workspace_id == expected["value"]["workspace_id"]
    assert credentials.scopes == tuple(expected["value"]["scopes"])
    assert credentials.device_keys.key_id == expected["value"]["device_keys"]["key_id"]
    assert (
        hashlib.sha256(canonical_json(credentials.public_info())).hexdigest()
        == vectors["workspace_key_aad"]["fields"]["recipient_binding_digest"]
    )


def test_http_signature_vector(vectors: dict[str, Any]) -> None:
    identity = vectors["identity"]
    expected = vectors["http_signature"]
    private_key = b64url_decode(identity["signing_private_key"], expected_length=32)
    public_key = b64url_decode(identity["signing_public_key"], expected_length=32)
    body = expected["body"].encode("utf-8")
    assert b64url_encode(body) == expected["body_base64url"]

    signed = sign_http_request(
        private_key,
        method=expected["method"],
        path=expected["path"],
        body=body,
        key_id=expected["key_id"],
        created=expected["created"],
        nonce=expected["nonce"],
    )
    assert signed.to_headers() == expected["headers"]
    verified = verify_http_request(
        public_key,
        method=expected["method"],
        path=expected["path"],
        body=body,
        headers=expected["headers"],
        expected_key_id=expected["key_id"],
        now=expected["created"],
    )
    assert verified.created == expected["created"]
    assert verified.nonce == expected["nonce"]


def test_task_and_workspace_aad_vectors(vectors: dict[str, Any]) -> None:
    for name, builder in (
        ("task_aad", task_aad),
        ("workspace_key_aad", workspace_key_aad),
    ):
        expected = vectors[name]
        value = builder(**expected["fields"])
        assert value.decode("utf-8") == expected["value_utf8"]
        assert b64url_encode(value) == expected["value_base64url"]
        assert hashlib.sha256(value).hexdigest() == expected["sha256"]


def test_xchacha_payload_vector(vectors: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    expected = vectors["payload_xchacha20poly1305"]
    key = b64url_decode(expected["key"], expected_length=32)
    nonce = b64url_decode(expected["nonce"], expected_length=24)
    aad = b64url_decode(expected["aad"])
    plaintext = b64url_decode(expected["plaintext"])

    sealed = _fixed_nonce(
        monkeypatch,
        nonce,
        lambda: encrypt_payload(key, plaintext, aad=aad),
    )
    assert sealed.to_dict() == expected["serialized"]
    assert decrypt_payload(key, expected["serialized"], aad=aad) == plaintext


def test_direct_hpke_vector(vectors: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    expected = vectors["hpke_direct"]
    recipient_private = b64url_decode(expected["recipient_private_key"], expected_length=32)
    recipient_public = b64url_decode(expected["recipient_public_key"], expected_length=32)
    ephemeral_private = b64url_decode(expected["sender_ephemeral_private_key"], expected_length=32)
    info = b64url_decode(expected["info"])
    aad = b64url_decode(expected["aad"])
    plaintext = b64url_decode(expected["plaintext"])

    sealed = _fixed_hpke_seal(
        monkeypatch,
        ephemeral_private,
        lambda: hpke_seal(recipient_public, plaintext, info=info, aad=aad),
    )
    assert sealed.to_dict() == expected["sealed"]
    assert hpke_open(recipient_private, expected["sealed"], info=info, aad=aad) == plaintext


def test_task_key_wrap_vector(vectors: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    expected = vectors["task_key_wrap"]
    recipient_private = b64url_decode(expected["recipient_private_key"], expected_length=32)
    recipient_public = b64url_decode(expected["recipient_public_key"], expected_length=32)
    ephemeral_private = b64url_decode(expected["sender_ephemeral_private_key"], expected_length=32)
    task_key = b64url_decode(expected["task_data_key"], expected_length=32)
    aad = b64url_decode(expected["aad"])

    sealed = _fixed_hpke_seal(
        monkeypatch,
        ephemeral_private,
        lambda: wrap_task_key(recipient_public, task_key, aad=aad),
    )
    assert sealed.to_dict() == expected["sealed"]
    assert unwrap_task_key(recipient_private, expected["sealed"], aad=aad) == task_key


def test_service_reader_vector(vectors: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    expected = vectors["service_reader"]
    recipient_private = b64url_decode(expected["recipient_private_key"], expected_length=32)
    recipient_public = b64url_decode(expected["recipient_public_key"], expected_length=32)
    ephemeral_private = b64url_decode(expected["sender_ephemeral_private_key"], expected_length=32)
    task_key = b64url_decode(expected["task_data_key"], expected_length=32)
    aad = b64url_decode(expected["aad"])

    sealed = _fixed_hpke_seal(
        monkeypatch,
        ephemeral_private,
        lambda: wrap_task_key(recipient_public, task_key, aad=aad),
    )
    assert sealed.to_dict() == expected["sealed"]
    assert unwrap_task_key(recipient_private, expected["sealed"], aad=aad) == task_key


def test_workspace_key_wrap_vector(
    vectors: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = vectors["workspace_key_wrap"]
    recipient_private = b64url_decode(expected["recipient_private_key"], expected_length=32)
    recipient_public = b64url_decode(expected["recipient_public_key"], expected_length=32)
    ephemeral_private = b64url_decode(expected["sender_ephemeral_private_key"], expected_length=32)
    workspace_key = b64url_decode(expected["workspace_data_key"], expected_length=32)
    aad = b64url_decode(expected["aad"])

    sealed = _fixed_hpke_seal(
        monkeypatch,
        ephemeral_private,
        lambda: wrap_workspace_key(recipient_public, workspace_key, aad=aad),
    )
    assert sealed.to_dict() == expected["sealed"]
    assert unwrap_workspace_key(recipient_private, expected["sealed"], aad=aad) == workspace_key


def test_workspace_reader_vector(vectors: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    expected = vectors["workspace_reader"]
    workspace_key = b64url_decode(expected["workspace_data_key"], expected_length=32)
    task_key = b64url_decode(expected["task_data_key"], expected_length=32)
    nonce = b64url_decode(expected["nonce"], expected_length=24)
    aad = b64url_decode(expected["task_aad"])

    sealed = _fixed_nonce(
        monkeypatch,
        nonce,
        lambda: wrap_task_key_for_workspace(workspace_key, task_key, aad=aad),
    )
    assert sealed.to_dict() == expected["serialized"]
    assert unwrap_task_key_for_workspace(workspace_key, expected["serialized"], aad=aad) == task_key
