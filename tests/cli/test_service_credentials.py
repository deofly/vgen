from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from vgen.cli.service_credentials import (
    ServiceCredentialError,
    ServiceCredentials,
    ServiceCredentialStore,
    ServiceSessionStore,
    StoredServiceSession,
)
from vgen.crypto import DeviceKeys


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


def _credentials() -> ServiceCredentials:
    return ServiceCredentials.generate(
        service_id="svc_test",
        workspace_id="wsp_test",
        name="automation",
        scopes=["task:read", "task:submit"],
        enrollment_id="enr_test",
        device_keys=DeviceKeys.generate(),
    )


def test_service_credentials_roundtrip_in_separate_keyring_namespace() -> None:
    backend = MemorySecrets()
    store = ServiceCredentialStore(backend)
    credentials = _credentials()
    store.save("api-prod", credentials)

    loaded = store.load("api-prod")
    assert loaded.public_info() == credentials.public_info()
    assert (
        loaded.device_keys.signing_private_bytes()
        == credentials.device_keys.signing_private_bytes()
    )
    assert (ServiceCredentialStore.SERVICE, "api-prod") in backend.values
    assert all(service != "vgen.identity.v1" for service, _ in backend.values)


def test_service_credential_file_requires_mode_0600_and_is_not_followed(
    tmp_path: Path,
) -> None:
    store = ServiceCredentialStore(MemorySecrets())
    credentials = _credentials()
    target = tmp_path / "service.json"
    store.save("ignored", credentials, file_path=target)
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o600
    assert store.load("ignored", file_path=target).service_id == "svc_test"

    if os.name != "nt":
        target.chmod(0o644)
        with pytest.raises(ServiceCredentialError, match="0600"):
            store.load("ignored", file_path=target)
        target.chmod(0o600)

    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ServiceCredentialError, match="symbolic"):
        store.load("ignored", file_path=link)


def test_service_session_is_typed_and_expires_independently() -> None:
    backend = MemorySecrets()
    store = ServiceSessionStore(backend)
    store.save(
        "team",
        StoredServiceSession(
            token="short-token", expires_at=time.time() + 300, service_id="svc_test"
        ),
    )
    assert store.load("team", "svc_test") is not None
    assert store.load("team", "svc_other") is None
    assert (ServiceSessionStore.SERVICE, "team:svc_test") in backend.values

    store.save(
        "team",
        StoredServiceSession(token="expired", expires_at=time.time() - 1, service_id="svc_expired"),
    )
    assert store.load("team", "svc_expired") is None
    assert (ServiceSessionStore.SERVICE, "team:svc_expired") not in backend.values
