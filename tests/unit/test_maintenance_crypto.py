from __future__ import annotations

import base64

from vgen.crypto import (
    DeviceKeys,
    build_maintenance_intent_payload,
    derive_identity_keys,
    issue_device_certificate,
    maintenance_spec_digest,
    sign_maintenance_intent,
    verify_maintenance_intent,
)


def _signed_intent() -> tuple[dict[str, object], object, dict[str, object]]:
    owner = derive_identity_keys(b"maintenance-owner" * 4)
    device = DeviceKeys.generate()
    certificate = issue_device_certificate(
        owner,
        device,
        device_id="dev_owner",
        issued_at=100,
        expires_at=1_000,
        serial="maintenance-device",
    )
    spec: dict[str, object] = {
        "version": 1,
        "target_version": "0.2.1",
        "artifact": {"sha256": "sha256:" + "a" * 64, "size_bytes": 123},
    }
    payload = build_maintenance_intent_payload(
        worker_id="wrk_target",
        broker_id="brk_home",
        kind="worker_update",
        spec=spec,
        device_id="dev_owner",
        issued_at=200,
        expires_at=800,
        nonce="nonce_0123456789abcdef",
    )
    return sign_maintenance_intent(device, certificate, payload), owner, spec


def test_maintenance_spec_digest_is_canonical() -> None:
    first = {"b": [2, 3], "a": 1}
    second = {"a": 1, "b": [2, 3]}

    assert maintenance_spec_digest(first) == maintenance_spec_digest(second)
    assert maintenance_spec_digest(first).startswith("sha256:")


def test_maintenance_intent_binds_owner_device_target_kind_and_spec() -> None:
    intent, owner, spec = _signed_intent()

    assert verify_maintenance_intent(
        intent,
        owner.signing_public_key,
        expected_worker_id="wrk_target",
        expected_broker_id="brk_home",
        expected_kind="worker_update",
        expected_spec=spec,
        now=300,
    )
    assert not verify_maintenance_intent(
        intent,
        owner.signing_public_key,
        expected_worker_id="wrk_other",
        expected_broker_id="brk_home",
        expected_kind="worker_update",
        expected_spec=spec,
        now=300,
    )
    assert not verify_maintenance_intent(
        intent,
        owner.signing_public_key,
        expected_worker_id="wrk_target",
        expected_broker_id="brk_home",
        expected_kind="model_install",
        expected_spec=spec,
        now=300,
    )
    changed_spec = dict(spec)
    changed_spec["target_version"] = "0.2.2"
    assert not verify_maintenance_intent(
        intent,
        owner.signing_public_key,
        expected_worker_id="wrk_target",
        expected_broker_id="brk_home",
        expected_kind="worker_update",
        expected_spec=changed_spec,
        now=300,
    )


def test_capability_install_is_an_explicit_signed_maintenance_action() -> None:
    owner = derive_identity_keys(b"capability-owner" * 4)
    device = DeviceKeys.generate()
    certificate = issue_device_certificate(
        owner,
        device,
        device_id="dev_capability_owner",
        issued_at=100,
        expires_at=1_000,
    )
    spec = {
        "kind": "capability_install",
        "workflow_ref": "vgen/ltx-2.5@1.0.0",
        "workflow_digest": "sha256:" + "b" * 64,
        "artifact_sha256": "c" * 64,
        "artifact_size": 123,
        "node_classes_digest": "d" * 64,
        "publisher_key": base64.b64encode(b"p" * 32).decode("ascii"),
        "allow_unsigned_workflow": False,
        "apply": "on_idle",
    }
    payload = build_maintenance_intent_payload(
        worker_id="wrk_target",
        broker_id="brk_home",
        kind="capability_install",
        spec=spec,
        device_id="dev_capability_owner",
        issued_at=200,
        expires_at=800,
        nonce="nonce_0123456789abcdef",
    )
    intent = sign_maintenance_intent(device, certificate, payload)

    assert verify_maintenance_intent(
        intent,
        owner.signing_public_key,
        expected_worker_id="wrk_target",
        expected_broker_id="brk_home",
        expected_kind="capability_install",
        expected_spec=spec,
        now=300,
    )


def test_maintenance_intent_rejects_expiry_extra_fields_and_tampering() -> None:
    intent, owner, spec = _signed_intent()

    assert not verify_maintenance_intent(
        intent,
        owner.signing_public_key,
        expected_worker_id="wrk_target",
        expected_broker_id="brk_home",
        expected_kind="worker_update",
        expected_spec=spec,
        now=800,
    )

    extra = {**intent, "command": "powershell.exe"}
    assert not verify_maintenance_intent(
        extra,
        owner.signing_public_key,
        expected_worker_id="wrk_target",
        expected_broker_id="brk_home",
        expected_kind="worker_update",
        expected_spec=spec,
        now=300,
    )

    tampered = {**intent, "payload": {**intent["payload"], "broker_id": "brk_other"}}
    assert not verify_maintenance_intent(
        tampered,
        owner.signing_public_key,
        expected_worker_id="wrk_target",
        expected_broker_id="brk_other",
        expected_kind="worker_update",
        expected_spec=spec,
        now=300,
    )

    boolean_version = {**intent, "payload": {**intent["payload"], "version": True}}
    assert not verify_maintenance_intent(
        boolean_version,
        owner.signing_public_key,
        expected_worker_id="wrk_target",
        expected_broker_id="brk_home",
        expected_kind="worker_update",
        expected_spec=spec,
        now=300,
    )


def test_sign_maintenance_intent_requires_matching_device_certificate() -> None:
    owner = derive_identity_keys(b"maintenance-owner" * 4)
    certified = DeviceKeys.generate()
    attacker = DeviceKeys.generate()
    certificate = issue_device_certificate(
        owner,
        certified,
        device_id="dev_owner",
        issued_at=100,
        expires_at=1_000,
    )
    payload = build_maintenance_intent_payload(
        worker_id="wrk_target",
        broker_id="brk_home",
        kind="model_install",
        spec={"version": 1, "model_digests": ["sha256:" + "a" * 64]},
        device_id="dev_owner",
        issued_at=200,
        expires_at=800,
        nonce="nonce_0123456789abcdef",
    )

    try:
        sign_maintenance_intent(attacker, certificate, payload)
    except ValueError as exc:
        assert "does not match" in str(exc)
    else:  # pragma: no cover - assertion clarity
        raise AssertionError("an uncertified Device key signed a maintenance intent")


def test_maintenance_verifier_never_raises_for_an_invalid_root_key_object() -> None:
    intent, _, spec = _signed_intent()

    assert not verify_maintenance_intent(
        intent,
        object(),  # type: ignore[arg-type]
        expected_worker_id="wrk_target",
        expected_broker_id="brk_home",
        expected_kind="worker_update",
        expected_spec=spec,
        now=300,
    )
