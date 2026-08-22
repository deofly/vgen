from __future__ import annotations

import io
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from vgen.crypto import (
    DeviceCertificate,
    DeviceKeys,
    TaskEnvelope,
    build_allocation_proof_payload,
    create_task_envelope,
    decrypt_stream,
    derive_identity_keys,
    deserialize_device_keys,
    encrypt_stream,
    encrypted_stream_size,
    export_recovery_file,
    hpke_open,
    hpke_seal,
    identity_init,
    identity_recover,
    identity_recover_file,
    issue_device_certificate,
    open_task_envelope,
    open_task_envelope_with_workspace_key,
    serialize_device_keys,
    sign_allocation_proof,
    sign_http_request,
    sign_key_manifest,
    task_aad,
    unwrap_task_key,
    unwrap_workspace_key,
    verify_allocation_proof,
    verify_device_certificate,
    verify_http_request,
    verify_key_manifest,
    verify_message,
    workspace_key_aad,
    wrap_task_key,
    wrap_workspace_key,
)
from vgen.protocol import (
    ERROR_REGISTRY,
    ArtifactRef,
    AttemptState,
    ErrorCode,
    ExecutionRequest,
    ExecutorDescriptor,
    TaskState,
    VGenError,
    can_transition_attempt,
    can_transition_task,
    error_envelope,
    new_id,
    require_task_transition,
    validate_id,
)

try:
    import mnemonic as _mnemonic  # noqa: F401

    HAS_MNEMONIC = True
except ImportError:
    HAS_MNEMONIC = False

try:
    import nacl as _nacl  # noqa: F401

    HAS_NACL = True
except ImportError:
    HAS_NACL = False


class ErrorRegistryTest(unittest.TestCase):
    def test_codes_are_complete_unique_six_digit_contracts(self) -> None:
        self.assertEqual(set(ERROR_REGISTRY), set(ErrorCode))
        values = [int(code) for code in ErrorCode]
        self.assertEqual(len(values), len(set(values)))
        self.assertTrue(all(100_000 <= code <= 999_999 for code in values))
        self.assertEqual(ErrorCode.NO_ELIGIBLE_WORKER, 220001)
        self.assertEqual(ErrorCode.EXECUTION_CANCELLED, 320008)

    def test_error_envelope_has_retry_policy_and_redacts_details(self) -> None:
        body = error_envelope(
            ErrorCode.NO_ELIGIBLE_WORKER,
            request_id="req_example",
            details={
                "pool_id": "pol_example",
                "prompt": "private prompt",
                "nested": {"access_token": "private token", "count": 2},
                "download": "https://storage.example/a?signature=secret",
            },
        )["error"]
        self.assertEqual(body["code"], 220001)
        self.assertEqual(body["name"], "NO_ELIGIBLE_WORKER")
        self.assertEqual(body["retry"]["action"], "later")
        self.assertEqual(body["retry"]["after_ms"], 5000)
        self.assertEqual(body["details"]["prompt"], "<redacted>")
        self.assertEqual(body["details"]["nested"]["access_token"], "<redacted>")
        self.assertEqual(body["details"]["download"], "<redacted-url>")

    def test_vgen_error_exposes_registered_http_status(self) -> None:
        error = VGenError(ErrorCode.VALIDATION_FAILED, details={"field": "name"})
        self.assertEqual(error.http_status, 422)
        self.assertEqual(error.to_envelope()["error"]["details"], {"field": "name"})


class ProtocolModelTest(unittest.TestCase):
    def test_resource_ids_are_typed_and_random(self) -> None:
        first = new_id("task")
        second = new_id("task")
        self.assertNotEqual(first, second)
        self.assertTrue(validate_id(first))
        self.assertTrue(validate_id(first, "task"))
        self.assertFalse(validate_id(first, "worker"))
        self.assertFalse(validate_id("tsk_not-base32"))

    def test_state_machines_reject_terminal_or_skipped_transitions(self) -> None:
        self.assertTrue(can_transition_task(TaskState.PREPARED, TaskState.COMMITTED))
        self.assertFalse(can_transition_task(TaskState.PREPARED, TaskState.RUNNING))
        self.assertTrue(can_transition_attempt(AttemptState.LEASED, AttemptState.RUNNING))
        with self.assertRaises(VGenError) as caught:
            require_task_transition(TaskState.SUCCEEDED, TaskState.RUNNING)
        self.assertEqual(caught.exception.code, ErrorCode.TASK_STATE_CONFLICT)

    def test_executor_descriptor_and_request_round_trip(self) -> None:
        descriptor = ExecutorDescriptor(
            executor_type="comfyui",
            version="1.0.0",
            payload_formats=("comfyui-api-graph/v1",),
            operations=("text-to-video", "image-to-video"),
            capabilities={"gpu": "cuda"},
        )
        self.assertEqual(ExecutorDescriptor.from_dict(descriptor.to_dict()), descriptor)

        artifact = ArtifactRef(
            artifact_id="art_example",
            role="first_frame",
            media_type="image/png",
            size_bytes=3,
            sha256="00" * 32,
            ticket={"method": "GET", "path": "/api/v1/artifacts/art_example"},
        )
        request = ExecutionRequest(
            task_id="tsk_example",
            attempt_id="atm_example",
            fencing_token=7,
            workflow_digest="sha256:" + "ab" * 32,
            executor_type="comfyui",
            payload_format="comfyui-api-graph/v1",
            opaque_payload=b'{"graph":{}}',
            inputs=(artifact,),
            deadline_unix_ms=1000,
        )
        self.assertEqual(ExecutionRequest.from_dict(request.to_dict()), request)


class IdentityTest(unittest.TestCase):
    def test_root_derivation_is_deterministic_and_domain_separated(self) -> None:
        first = derive_identity_keys(b"a" * 64)
        second = derive_identity_keys(b"a" * 64)
        other = derive_identity_keys(b"b" * 64)
        self.assertEqual(first.signing_private_bytes(), second.signing_private_bytes())
        self.assertEqual(first.encryption_private_bytes(), second.encryption_private_bytes())
        self.assertNotEqual(first.signing_private_bytes(), first.encryption_private_bytes())
        self.assertNotEqual(first.root_key_id, other.root_key_id)

    def test_context_bound_signatures_and_device_certificates(self) -> None:
        identity = derive_identity_keys(b"identity" * 8)
        signature = identity.sign(b"payload", context=b"test-v1")
        self.assertTrue(
            verify_message(
                identity.signing_public_key,
                b"payload",
                signature,
                context=b"test-v1",
            )
        )
        self.assertFalse(
            verify_message(
                identity.signing_public_key,
                b"payload",
                signature,
                context=b"other-v1",
            )
        )

        device = DeviceKeys.generate()
        restored_device = deserialize_device_keys(serialize_device_keys(device))
        self.assertEqual(restored_device.key_id, device.key_id)
        self.assertEqual(restored_device.signing_private_bytes(), device.signing_private_bytes())
        cert = issue_device_certificate(
            identity,
            device,
            device_id="dev_example",
            issued_at=100,
            expires_at=200,
            serial="serial-example",
        )
        self.assertTrue(verify_device_certificate(cert, identity.signing_public_key, now=150))
        self.assertFalse(verify_device_certificate(cert, identity.signing_public_key, now=250))
        tampered = cert.to_dict()
        tampered["payload"]["device_id"] = "dev_attacker"
        self.assertFalse(
            verify_device_certificate(
                DeviceCertificate.from_dict(tampered), identity.signing_public_key, now=150
            )
        )

    def test_signed_key_manifest_detects_substitution(self) -> None:
        identity = derive_identity_keys(b"manifest" * 8)
        signed = sign_key_manifest(
            identity,
            {"version": 3, "encryption_public_key": "example"},
        )
        self.assertTrue(verify_key_manifest(signed, identity.signing_public_key))
        signed["manifest"]["version"] = 4
        self.assertFalse(verify_key_manifest(signed, identity.signing_public_key))

    def test_allocation_proof_binds_workspace_pool_worker_and_offer_revision(self) -> None:
        admin = derive_identity_keys(b"workspace-admin" * 4)
        payload = build_allocation_proof_payload(
            allocation_id="alc_example",
            workspace_id="wsp_example",
            pool_id="pol_example",
            worker_id="wrk_example",
            worker_signing_public_key="worker-signing-key",
            worker_encryption_public_key="worker-encryption-key",
            worker_certificate={"manifest": {"worker": "example"}, "signature": "x"},
            owner_consent_at=1_700_000_000.125,
            approver_root_key_id=admin.root_key_id,
            issued_at=1_700_000_001,
        )
        proof = sign_allocation_proof(admin, payload)
        self.assertTrue(
            verify_allocation_proof(
                proof,
                admin.signing_public_key,
                expected=payload,
                now=1_700_000_002,
            )
        )
        changed_pool = dict(payload)
        changed_pool["pool_id"] = "pol_other"
        self.assertFalse(
            verify_allocation_proof(
                proof,
                admin.signing_public_key,
                expected=changed_pool,
                now=1_700_000_002,
            )
        )
        changed_consent = dict(payload)
        changed_consent["owner_consent_at_ms"] += 1
        self.assertFalse(
            verify_allocation_proof(
                proof,
                admin.signing_public_key,
                expected=changed_consent,
                now=1_700_000_002,
            )
        )

    def test_http_request_signature_binds_body_path_time_and_nonce(self) -> None:
        device = DeviceKeys.generate()
        signed = sign_http_request(
            device,
            method="post",
            path="/api/v1/tasks?dry_run=false",
            body=b'{"ciphertext":"example"}',
            created=1_000,
            nonce="a" * 32,
        )
        seen: set[str] = set()

        def claim_nonce(nonce: str, created: int) -> bool:
            self.assertEqual(created, 1_000)
            if nonce in seen:
                return False
            seen.add(nonce)
            return True

        verified = verify_http_request(
            device.signing_public_key,
            method="POST",
            path="/api/v1/tasks?dry_run=false",
            body=b'{"ciphertext":"example"}',
            headers=signed.to_headers(),
            expected_key_id=device.key_id,
            now=1_001,
            nonce_is_fresh=claim_nonce,
        )
        self.assertEqual(verified.key_id, device.key_id)
        with self.assertRaises(VGenError) as replay:
            verify_http_request(
                device.signing_public_key,
                method="POST",
                path="/api/v1/tasks?dry_run=false",
                body=b'{"ciphertext":"example"}',
                headers=signed.to_headers(),
                now=1_001,
                nonce_is_fresh=claim_nonce,
            )
        self.assertEqual(replay.exception.code, ErrorCode.REPLAY_DETECTED)
        with self.assertRaises(VGenError) as tampered:
            verify_http_request(
                device.signing_public_key,
                method="POST",
                path="/api/v1/tasks?dry_run=true",
                body=b'{"ciphertext":"example"}',
                headers=signed.to_headers(),
                now=1_001,
            )
        self.assertEqual(tampered.exception.code, ErrorCode.SIGNATURE_INVALID)

    @unittest.skipUnless(HAS_MNEMONIC, "mnemonic package is not installed")
    def test_24_word_identity_and_recovery_file_round_trip(self) -> None:
        bundle = identity_init()
        self.assertEqual(len(bundle.recovery_words), 24)
        recovered = identity_recover(bundle.mnemonic)
        recovered_file = identity_recover_file(export_recovery_file(bundle.mnemonic))
        self.assertEqual(bundle.keys.root_key_id, recovered.root_key_id)
        self.assertEqual(bundle.keys.root_key_id, recovered_file.root_key_id)


class EnvelopeTest(unittest.TestCase):
    def test_workspace_key_envelope_is_recipient_and_version_bound(self) -> None:
        recipient = X25519PrivateKey.generate()
        aad = workspace_key_aad(
            workspace_id="wsp_example",
            recipient_type="user_recovery",
            recipient_id="usr_example",
            key_version=3,
        )
        workspace_key = b"w" * 32
        wrapped = wrap_workspace_key(recipient.public_key(), workspace_key, aad=aad)
        self.assertEqual(unwrap_workspace_key(recipient, wrapped, aad=aad), workspace_key)
        wrong_version = workspace_key_aad(
            workspace_id="wsp_example",
            recipient_type="user_recovery",
            recipient_id="usr_example",
            key_version=4,
        )
        with self.assertRaises(VGenError) as caught:
            unwrap_workspace_key(recipient, wrapped, aad=wrong_version)
        self.assertEqual(caught.exception.code, ErrorCode.DECRYPTION_FAILED)

    def test_hpke_key_wrap_round_trip_and_context_binding(self) -> None:
        recipient = X25519PrivateKey.generate()
        aad = task_aad(
            workspace_id="wsp_example",
            task_id="tsk_example",
            attempt_id="atm_example",
        )
        task_key = b"k" * 32
        wrapped = wrap_task_key(recipient.public_key(), task_key, aad=aad)
        self.assertEqual(unwrap_task_key(recipient, wrapped, aad=aad), task_key)
        with self.assertRaises(VGenError) as caught:
            unwrap_task_key(recipient, wrapped, aad=aad + b"changed")
        self.assertEqual(caught.exception.code, ErrorCode.DECRYPTION_FAILED)

    def test_raw_hpke_rejects_tampering_and_wrong_recipient(self) -> None:
        recipient = X25519PrivateKey.generate()
        sealed = hpke_seal(recipient.public_key(), b"payload", info=b"test", aad=b"a")
        self.assertEqual(hpke_open(recipient, sealed, info=b"test", aad=b"a"), b"payload")
        wrong_recipient = X25519PrivateKey.generate()
        with self.assertRaises(VGenError):
            hpke_open(wrong_recipient, sealed, info=b"test", aad=b"a")

    @unittest.skipUnless(HAS_NACL, "PyNaCl package is not installed")
    def test_task_envelope_has_independent_worker_and_reader_wraps(self) -> None:
        worker = X25519PrivateKey.generate()
        reader = X25519PrivateKey.generate()
        aad = task_aad(
            workspace_id="wsp_example",
            task_id="tsk_example",
            attempt_id="atm_example",
            artifact_id="private-payload",
        )
        envelope = create_task_envelope(
            b"private prompt and workflow",
            {"wrk_example": worker.public_key(), "usr_example": reader.public_key()},
            aad=aad,
            workspace_data_key=b"w" * 32,
        )
        wire = envelope.to_dict()
        restored = TaskEnvelope.from_dict(wire)
        self.assertEqual(
            open_task_envelope(
                restored,
                recipient_id="wrk_example",
                recipient_private_key=worker,
                aad=aad,
            ),
            b"private prompt and workflow",
        )
        self.assertEqual(
            open_task_envelope_with_workspace_key(
                restored,
                workspace_data_key=b"w" * 32,
                aad=aad,
            ),
            b"private prompt and workflow",
        )
        self.assertEqual(
            open_task_envelope(
                restored,
                recipient_id="usr_example",
                recipient_private_key=reader,
                aad=aad,
            ),
            b"private prompt and workflow",
        )
        with self.assertRaises(VGenError) as caught:
            open_task_envelope(
                restored,
                recipient_id="unknown",
                recipient_private_key=reader,
                aad=aad,
            )
        self.assertEqual(caught.exception.code, ErrorCode.RECIPIENT_KEY_UNAVAILABLE)

    @unittest.skipUnless(HAS_NACL, "PyNaCl package is not installed")
    def test_secretstream_round_trip_and_truncation_detection(self) -> None:
        import nacl.bindings

        key = nacl.bindings.crypto_secretstream_xchacha20poly1305_keygen()
        source = b"video-frame" * 1000
        encrypted = io.BytesIO()
        encrypt_stats = encrypt_stream(
            io.BytesIO(source), encrypted, key, aad=b"artifact-aad", chunk_size=127
        )
        decrypted = io.BytesIO()
        decrypt_stats = decrypt_stream(
            io.BytesIO(encrypted.getvalue()), decrypted, key, aad=b"artifact-aad"
        )
        self.assertEqual(decrypted.getvalue(), source)
        self.assertEqual(encrypt_stats.plaintext_bytes, len(source))
        self.assertEqual(decrypt_stats.plaintext_bytes, len(source))
        self.assertEqual(
            encrypt_stats.ciphertext_bytes, encrypted_stream_size(len(source), chunk_size=127)
        )

        with self.assertRaises(VGenError):
            decrypt_stream(
                io.BytesIO(encrypted.getvalue()[:-1]),
                io.BytesIO(),
                key,
                aad=b"artifact-aad",
            )


if __name__ == "__main__":
    unittest.main()
