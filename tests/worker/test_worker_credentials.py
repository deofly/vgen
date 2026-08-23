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
from vgen.worker.credentials import (
    load_worker_credentials_file,
    replace_worker_credentials_file_with_backup,
    save_worker_credentials_file,
)


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


def test_worker_credentials_round_trip_canonical_gateway_origin() -> None:
    value = WorkerCredentials(
        "wrk_test",
        DeviceKeys.generate(),
        "session",
        gateway_url="https://GATEWAY.example:443/",
    )
    restored = WorkerCredentials.from_bytes(value.to_bytes())
    assert restored.gateway_url == "https://gateway.example"

    with pytest.raises(WorkerCredentialError, match="must use HTTPS"):
        WorkerCredentials(
            "wrk_test",
            DeviceKeys.generate(),
            "session",
            gateway_url="http://gateway.example",
        )


def test_new_worker_credentials_replace_canonical_atomically_and_keep_backup(
    tmp_path: Path,
) -> None:
    path = tmp_path / "worker-credentials.json"
    old = WorkerCredentials(
        "wrk_old",
        DeviceKeys.generate(),
        "old-session",
        gateway_url="https://gateway.example",
    )
    new = WorkerCredentials(
        "wrk_new",
        DeviceKeys.generate(),
        "new-session",
        gateway_url="https://gateway.example",
    )
    save_worker_credentials_file(path, old)
    old_bytes = path.read_bytes()

    backup = replace_worker_credentials_file_with_backup(path, new)

    assert load_worker_credentials_file(path).worker_id == "wrk_new"
    assert backup.read_bytes() == old_bytes
    assert path.stat().st_mode & 0o777 == 0o600
    assert backup.stat().st_mode & 0o777 == 0o600


def test_failed_atomic_worker_credential_promotion_keeps_canonical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "worker-credentials.json"
    old = WorkerCredentials("wrk_old", DeviceKeys.generate(), "old-session")
    new = WorkerCredentials("wrk_new", DeviceKeys.generate(), "new-session")
    save_worker_credentials_file(path, old)
    old_bytes = path.read_bytes()

    monkeypatch.setattr(
        credential_module.os,
        "replace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("replace failed")),
    )
    with pytest.raises(WorkerCredentialError, match="could not be activated"):
        replace_worker_credentials_file_with_backup(path, new)
    assert path.read_bytes() == old_bytes


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
    assert "/setowner" in calls[1]
    assert "*S-1-5-21-123" in calls[1]
    assert "*S-1-5-21-123:(F)" in calls[2]
    assert "*S-1-5-18:(F)" in calls[2]
    assert "*S-1-5-32-544:(F)" in calls[2]

    def failed(command: list[str], **kwargs: object) -> SimpleNamespace:
        del kwargs
        if command[0] == "whoami.exe":
            return SimpleNamespace(returncode=0, stdout='"DESKTOP\\user","S-1-5-21-123"\r\n')
        return SimpleNamespace(returncode=5, stdout="access denied")

    monkeypatch.setattr(credential_module.subprocess, "run", failed)
    with pytest.raises(WorkerCredentialError, match="access rules"):
        credential_module._protect_windows_private_file(tmp_path / "credential.json")


def test_windows_credential_promotion_hardens_canonical_and_staged_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "worker-credentials.json"
    old = WorkerCredentials("wrk_old", DeviceKeys.generate(), "old-session")
    new = WorkerCredentials("wrk_new", DeviceKeys.generate(), "new-session")
    save_worker_credentials_file(path, old)
    old_bytes = path.read_bytes()
    protected: list[str] = []

    monkeypatch.setattr(credential_module.os, "name", "nt")
    monkeypatch.setattr(
        credential_module,
        "_protect_windows_private_file",
        lambda candidate: protected.append(str(candidate)),
    )

    backup = replace_worker_credentials_file_with_backup(path, new)

    assert protected[0] == str(path.resolve())
    assert ".worker-credentials.json.staged-" in protected[1]
    assert backup.read_bytes() == old_bytes
    assert load_worker_credentials_file(path).worker_id == "wrk_new"
