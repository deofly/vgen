from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import vgen_sdk.envelope as envelope_module
from vgen_sdk import (
    ALLOCATION_PROOF_CONTEXT,
    MANIFEST_CONTEXT,
    DecryptionError,
    DeviceKeys,
    HpkeCiphertext,
    PayloadCiphertext,
    ServiceCredentials,
    b64url_decode,
    b64url_encode,
    build_allocation_proof_payload,
    build_service_challenge_request,
    build_service_session_request,
    canonical_json,
    decrypt_payload,
    encrypt_payload,
    hpke_open,
    hpke_seal,
    root_signing_key_id,
    sign_http_request,
    sign_message,
    sign_service_challenge,
    task_aad,
    unwrap_task_key,
    unwrap_task_key_for_workspace,
    unwrap_workspace_key,
    verify_allocation_proof,
    verify_http_request,
    verify_key_manifest,
    verify_worker_owner_certificate,
    worker_certificate_digest,
    workspace_key_aad,
    wrap_task_key,
    wrap_task_key_for_workspace,
    wrap_workspace_key,
)

VECTORS_PATH = Path(__file__).resolve().parents[3] / "tests" / "sdk_compat" / "vectors.json"


@pytest.fixture(scope="module")
def vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _keys(vectors: dict) -> DeviceKeys:
    identity = vectors["identity"]
    return DeviceKeys.from_private_bytes(
        signing_private_key=b64url_decode(identity["signing_private_key"], expected_length=32),
        encryption_private_key=b64url_decode(
            identity["encryption_private_key"], expected_length=32
        ),
    )


class _FixedX25519PrivateKeyFactory:
    private_key: bytes

    @classmethod
    def generate(cls) -> X25519PrivateKey:
        return X25519PrivateKey.from_private_bytes(cls.private_key)


def _with_fixed_hpke_sender(monkeypatch: pytest.MonkeyPatch, private_key: bytes) -> None:
    _FixedX25519PrivateKeyFactory.private_key = private_key
    monkeypatch.setattr(
        envelope_module,
        "X25519PrivateKey",
        _FixedX25519PrivateKeyFactory,
    )


def test_canonical_json_vector(vectors: dict) -> None:
    vector = vectors["encoding"]["canonical_json"]
    encoded = canonical_json(vector["input"])
    assert encoded.decode("utf-8") == vector["output_utf8"]
    assert encoded.hex() == vector["output_hex"]


def test_device_keys_and_service_challenge_vector(vectors: dict) -> None:
    vector = vectors["identity"]
    keys = _keys(vectors)

    assert keys.signing_public_bytes() == b64url_decode(vector["signing_public_key"])
    assert keys.encryption_public_bytes() == b64url_decode(vector["encryption_public_key"])
    assert keys.key_id == vector["device_key_id"]
    assert (
        root_signing_key_id(keys.signing_public_bytes())
        == vector["root_key_id_for_same_signing_key"]
    )
    assert sign_service_challenge(keys, vector["challenge"]) == vector["challenge_signature"]


def test_root_key_manifest_vector_and_tampering(vectors: dict) -> None:
    root = vectors["root_identity"]
    signed = vectors["key_manifest"]["signed"]
    root_public_key = b64url_decode(root["signing_public_key"])

    assert root_signing_key_id(root_public_key) == root["root_key_id"]
    assert verify_key_manifest(signed, root_public_key)

    tampered = deepcopy(signed)
    tampered["manifest"]["key_version"] += 1
    assert not verify_key_manifest(tampered, root_public_key)
    assert not verify_key_manifest(signed, _keys(vectors).signing_public_bytes())


def test_worker_owner_certificate_vector_and_strict_bindings(vectors: dict) -> None:
    root = vectors["root_identity"]
    vector = vectors["worker_owner_certificate"]
    certificate = vector["certificate"]
    root_public_key = b64url_decode(root["signing_public_key"])
    issued_at = int(certificate["manifest"]["issued_at"])
    worker = {
        "id": vector["worker"]["id"],
        "signing_public_key": vector["worker"]["signing_public_key"],
        "encryption_public_key": vector["worker"]["encryption_public_key"],
        "owner_root_signing_public_key": root["signing_public_key"],
        "certificate": certificate,
    }

    assert worker_certificate_digest(certificate) == vector["certificate_digest"]
    assert (
        worker_certificate_digest(vector["canonical_certificate_utf8"])
        == vector["certificate_digest"]
    )
    assert verify_worker_owner_certificate(worker, root_public_key, now=issued_at)

    changed_worker = dict(worker)
    changed_worker["encryption_public_key"] = vectors["identity"]["encryption_public_key"]
    assert not verify_worker_owner_certificate(changed_worker, root_public_key, now=issued_at)

    changed_root = dict(worker)
    changed_root["owner_root_signing_public_key"] = vectors["identity"]["signing_public_key"]
    assert not verify_worker_owner_certificate(changed_root, root_public_key, now=issued_at)

    future_certificate = deepcopy(certificate)
    future_certificate["manifest"]["issued_at"] = issued_at + 301
    future_certificate["signature"] = b64url_encode(
        sign_message(
            b64url_decode(root["signing_private_key"]),
            canonical_json(future_certificate["manifest"]),
            context=MANIFEST_CONTEXT,
        )
    )
    future_worker = {**worker, "certificate": future_certificate}
    assert not verify_worker_owner_certificate(future_worker, root_public_key, now=issued_at)

    boolean_time_certificate = deepcopy(certificate)
    boolean_time_certificate["manifest"]["issued_at"] = True
    boolean_time_certificate["signature"] = b64url_encode(
        sign_message(
            b64url_decode(root["signing_private_key"]),
            canonical_json(boolean_time_certificate["manifest"]),
            context=MANIFEST_CONTEXT,
        )
    )
    boolean_time_worker = {**worker, "certificate": boolean_time_certificate}
    assert not verify_worker_owner_certificate(boolean_time_worker, root_public_key, now=issued_at)

    wrong_version_certificate = deepcopy(certificate)
    wrong_version_certificate["manifest"]["version"] = 2
    wrong_version_certificate["signature"] = b64url_encode(
        sign_message(
            b64url_decode(root["signing_private_key"]),
            canonical_json(wrong_version_certificate["manifest"]),
            context=MANIFEST_CONTEXT,
        )
    )
    wrong_version_worker = {**worker, "certificate": wrong_version_certificate}
    assert not verify_worker_owner_certificate(wrong_version_worker, root_public_key, now=issued_at)

    with pytest.raises(ValueError, match="max_future_seconds"):
        verify_worker_owner_certificate(
            worker,
            root_public_key,
            now=issued_at,
            max_future_seconds=-1,
        )


def test_workspace_allocation_proof_vector_and_bindings(vectors: dict) -> None:
    root = vectors["root_identity"]
    worker_certificate = vectors["worker_owner_certificate"]["certificate"]
    vector = vectors["workspace_allocation_proof"]
    root_public_key = b64url_decode(root["signing_public_key"])

    payload = build_allocation_proof_payload(
        **vector["inputs"],
        worker_certificate=worker_certificate,
    )
    assert payload == vector["expected_bindings"]
    assert worker_certificate_digest(worker_certificate) == vector["worker_certificate_digest"]
    assert verify_allocation_proof(
        vector["proof"],
        root_public_key,
        expected=vector["expected_bindings"],
        now=vector["inputs"]["issued_at"],
    )

    wrong_binding = dict(vector["expected_bindings"])
    wrong_binding["pool_id"] = "pol_zzzzzzzzzzzzzzzzzzzzzzzzzz"
    assert not verify_allocation_proof(
        vector["proof"],
        root_public_key,
        expected=wrong_binding,
        now=vector["inputs"]["issued_at"],
    )

    future_proof = deepcopy(vector["proof"])
    future_proof["payload"]["issued_at"] = vector["inputs"]["issued_at"] + 301
    future_proof["signature"] = b64url_encode(
        sign_message(
            b64url_decode(root["signing_private_key"]),
            canonical_json(future_proof["payload"]),
            context=ALLOCATION_PROOF_CONTEXT,
        )
    )
    assert not verify_allocation_proof(
        future_proof,
        root_public_key,
        now=vector["inputs"]["issued_at"],
    )

    root_private_key = b64url_decode(root["signing_private_key"])
    for field, invalid_value in (
        ("version", True),
        ("issued_at", True),
        ("owner_consent_at_ms", "1787489999125"),
        ("worker_certificate_digest", "sha256:short"),
    ):
        malformed = deepcopy(vector["proof"])
        malformed["payload"][field] = invalid_value
        malformed["signature"] = b64url_encode(
            sign_message(
                root_private_key,
                canonical_json(malformed["payload"]),
                context=ALLOCATION_PROOF_CONTEXT,
            )
        )
        assert not verify_allocation_proof(
            malformed,
            root_public_key,
            now=vector["inputs"]["issued_at"],
        )

    with pytest.raises(ValueError, match="max_future_seconds"):
        verify_allocation_proof(
            vector["proof"],
            root_public_key,
            now=vector["inputs"]["issued_at"],
            max_future_seconds=-1,
        )


def test_service_credentials_exact_round_trip_and_auth_payloads(vectors: dict) -> None:
    vector = vectors["service_credentials"]
    serialized = vector["serialized_utf8"].encode("utf-8")
    credentials = ServiceCredentials.from_bytes(serialized)

    assert credentials.to_bytes() == serialized
    assert credentials.device_keys.key_id == vectors["identity"]["device_key_id"]
    assert credentials.keys is credentials.device_keys
    assert build_service_challenge_request(credentials) == {
        "principal_type": "service",
        "service_id": vector["value"]["service_id"],
    }
    challenge = {
        "challenge_id": "ses_aaaaaaaaaaaaaaaaaaaaaaaaaa",
        "challenge": vectors["identity"]["challenge"],
        "principal_type": "service",
        "service_id": credentials.service_id,
    }
    assert build_service_session_request(credentials, challenge) == {
        "principal_type": "service",
        "service_id": credentials.service_id,
        "challenge_id": challenge["challenge_id"],
        "signature": vectors["identity"]["challenge_signature"],
    }


def test_http_signature_vector(vectors: dict) -> None:
    vector = vectors["http_signature"]
    keys = _keys(vectors)
    body = vector["body"].encode("utf-8")

    headers = sign_http_request(
        keys,
        method=vector["method"],
        path=vector["path"],
        body=body,
        created=vector["created"],
        nonce=vector["nonce"],
    ).to_headers()

    assert headers == vector["headers"]
    verified = verify_http_request(
        keys.signing_public_key,
        method=vector["method"],
        path=vector["path"],
        body=body,
        headers=headers,
        expected_key_id=keys.key_id,
        now=vector["created"],
    )
    assert verified.key_id == vector["key_id"]
    assert verified.nonce == vector["nonce"]


def test_task_and_workspace_aad_vectors(vectors: dict) -> None:
    task_vector = vectors["task_aad"]
    workspace_vector = vectors["workspace_key_aad"]

    assert task_aad(**task_vector["fields"]).decode("utf-8") == task_vector["value_utf8"]
    assert (
        workspace_key_aad(**workspace_vector["fields"]).decode("utf-8")
        == workspace_vector["value_utf8"]
    )


def test_xchacha_payload_vector(vectors: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    vector = vectors["payload_xchacha20poly1305"]
    key = b64url_decode(vector["key"])
    nonce = b64url_decode(vector["nonce"])
    aad = b64url_decode(vector["aad"])
    plaintext = b64url_decode(vector["plaintext"])

    monkeypatch.setattr(envelope_module.secrets, "token_bytes", lambda length: nonce)
    encrypted = encrypt_payload(key, plaintext, aad=aad)

    assert encrypted.to_dict() == vector["serialized"]
    assert decrypt_payload(key, vector["serialized"], aad=aad) == plaintext
    tampered = PayloadCiphertext(
        nonce=encrypted.nonce,
        ciphertext=encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1]),
    )
    with pytest.raises(DecryptionError):
        decrypt_payload(key, tampered, aad=aad)


def test_direct_hpke_vector(vectors: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    vector = vectors["hpke_direct"]
    private_key = b64url_decode(vector["recipient_private_key"])
    public_key = b64url_decode(vector["recipient_public_key"])
    info = b64url_decode(vector["info"])
    aad = b64url_decode(vector["aad"])
    plaintext = b64url_decode(vector["plaintext"])

    with monkeypatch.context() as patch:
        _with_fixed_hpke_sender(patch, b64url_decode(vector["sender_ephemeral_private_key"]))
        sealed = hpke_seal(public_key, plaintext, info=info, aad=aad)
    assert sealed.to_dict() == vector["sealed"]
    assert hpke_open(private_key, vector["sealed"], info=info, aad=aad) == plaintext
    with pytest.raises(DecryptionError):
        hpke_open(private_key, vector["sealed"], info=info, aad=aad + b"changed")


def test_task_key_wrap_vector(vectors: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    vector = vectors["task_key_wrap"]
    private_key = b64url_decode(vector["recipient_private_key"])
    public_key = b64url_decode(vector["recipient_public_key"])
    task_key = b64url_decode(vector["task_data_key"])
    aad = b64url_decode(vector["aad"])

    with monkeypatch.context() as patch:
        _with_fixed_hpke_sender(patch, b64url_decode(vector["sender_ephemeral_private_key"]))
        wrapped = wrap_task_key(public_key, task_key, aad=aad)
    assert wrapped.to_dict() == vector["sealed"]
    assert unwrap_task_key(private_key, vector["sealed"], aad=aad) == task_key


def test_service_reader_wraps_to_service_credential_key(
    vectors: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    vector = vectors["service_reader"]
    credentials = ServiceCredentials.from_bytes(
        vectors["service_credentials"]["serialized_utf8"].encode("utf-8")
    )
    task_key = b64url_decode(vector["task_data_key"])
    aad = b64url_decode(vector["aad"])

    assert credentials.service_id == vector["service_id"]
    assert credentials.keys.encryption_public_bytes() == b64url_decode(
        vector["recipient_public_key"]
    )
    with monkeypatch.context() as patch:
        _with_fixed_hpke_sender(patch, b64url_decode(vector["sender_ephemeral_private_key"]))
        wrapped = wrap_task_key(
            credentials.keys.encryption_public_bytes(),
            task_key,
            aad=aad,
        )

    assert wrapped.to_dict() == vector["sealed"]
    assert (
        unwrap_task_key(
            credentials.keys.encryption_private_key,
            vector["sealed"],
            aad=aad,
        )
        == task_key
    )


def test_workspace_key_wrap_vector(vectors: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    vector = vectors["workspace_key_wrap"]
    private_key = b64url_decode(vector["recipient_private_key"])
    public_key = b64url_decode(vector["recipient_public_key"])
    workspace_key = b64url_decode(vector["workspace_data_key"])
    aad = b64url_decode(vector["aad"])

    with monkeypatch.context() as patch:
        _with_fixed_hpke_sender(patch, b64url_decode(vector["sender_ephemeral_private_key"]))
        wrapped = wrap_workspace_key(public_key, workspace_key, aad=aad)
    assert wrapped.to_dict() == vector["sealed"]
    assert unwrap_workspace_key(private_key, vector["sealed"], aad=aad) == workspace_key


def test_workspace_reader_vector(vectors: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    vector = vectors["workspace_reader"]
    workspace_key = b64url_decode(vector["workspace_data_key"])
    task_key = b64url_decode(vector["task_data_key"])
    nonce = b64url_decode(vector["nonce"])
    aad = b64url_decode(vector["task_aad"])

    monkeypatch.setattr(envelope_module.secrets, "token_bytes", lambda length: nonce)
    wrapped = wrap_task_key_for_workspace(workspace_key, task_key, aad=aad)

    assert wrapped.to_dict() == vector["serialized"]
    assert unwrap_task_key_for_workspace(workspace_key, vector["serialized"], aad=aad) == task_key


def test_wire_parsers_reject_unknown_algorithms(vectors: dict) -> None:
    hpke = dict(vectors["hpke_direct"]["sealed"])
    hpke["algorithm"] = "not-hpke"
    with pytest.raises(ValueError, match="unsupported"):
        HpkeCiphertext.from_dict(hpke)

    payload = dict(vectors["payload_xchacha20poly1305"]["serialized"])
    payload["algorithm"] = "not-xchacha"
    with pytest.raises(ValueError, match="unsupported"):
        PayloadCiphertext.from_dict(payload)
