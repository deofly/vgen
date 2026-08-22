from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from vgen.crypto import DeviceKeys, b64url_encode
from vgen.worker import (
    WorkerCredentialError,
    WorkerCredentials,
    WorkerIdentity,
    WorkerIdentityStore,
)
from vgen.worker import credentials as credential_module


def test_worker_identity_file_is_0600_and_registration_is_public(tmp_path: Path) -> None:
    path = tmp_path / "worker-identity.json"
    store = WorkerIdentityStore()
    identity = store.generate("ignored", file_path=path)
    assert path.stat().st_mode & 0o777 == 0o600
    restored = store.load("ignored", file_path=path)
    assert restored.key_id == identity.key_id
    registration = restored.public_registration(
        name="GPU 1",
        executor_type="comfyui",
        executor_version="1.0",
        capabilities={"gpu_count": 1},
    )
    assert registration["signing_public_key"]
    assert registration["encryption_public_key"]
    assert "private" not in repr(registration).lower()
    assert "private" not in repr(identity).lower()


def test_insecure_worker_identity_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "worker-identity.json"
    path.write_bytes(WorkerIdentity.generate().to_bytes())
    path.chmod(0o644)
    with pytest.raises(WorkerCredentialError, match="0600"):
        WorkerIdentityStore().load("ignored", file_path=path)


def test_worker_credentials_round_trip_optional_owner_maintenance_trust_anchor() -> None:
    root_public = b64url_encode(DeviceKeys.generate().signing_public_bytes())
    value = WorkerCredentials(
        "wrk_test",
        DeviceKeys.generate(),
        "session",
        owner_root_signing_public_key=root_public,
    )
    restored = WorkerCredentials.from_bytes(value.to_bytes())
    assert restored.owner_root_signing_public_key == root_public

    legacy = WorkerCredentials("wrk_legacy", DeviceKeys.generate(), "session")
    assert WorkerCredentials.from_bytes(legacy.to_bytes()).owner_root_signing_public_key is None


def test_windows_private_acl_uses_sid_and_fails_closed_on_icacls_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def succeeded(command: list[str], **kwargs: object) -> SimpleNamespace:
        del kwargs
        calls.append(command)
        if command[0] == "whoami.exe":
            return SimpleNamespace(returncode=0, stdout='"DESKTOP\\user","S-1-5-21-123"\r\n')
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(credential_module.subprocess, "run", succeeded)
    credential_module._protect_windows_private_file(tmp_path / "credential.json")
    assert calls[1][0] == "icacls.exe"
    assert "*S-1-5-21-123:(F)" in calls[1]
    assert "*S-1-5-18:(F)" in calls[1]

    def failed(command: list[str], **kwargs: object) -> SimpleNamespace:
        del kwargs
        if command[0] == "whoami.exe":
            return SimpleNamespace(returncode=0, stdout='"DESKTOP\\user","S-1-5-21-123"\r\n')
        return SimpleNamespace(returncode=5, stdout="access denied")

    monkeypatch.setattr(credential_module.subprocess, "run", failed)
    with pytest.raises(WorkerCredentialError, match="access rules"):
        credential_module._protect_windows_private_file(tmp_path / "credential.json")
