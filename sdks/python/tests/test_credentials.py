from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from vgen_sdk import (
    CredentialError,
    DeviceKeys,
    ServiceCredentials,
    b64url_decode,
)


def _credentials() -> ServiceCredentials:
    return ServiceCredentials.generate(
        service_id="svc_aaaaaaaaaaaaaaaaaaaaaaaaaa",
        workspace_id="wsp_bbbbbbbbbbbbbbbbbbbbbbbbbb",
        name="automation",
        scopes=["task:submit", "task:read", "task:submit"],
        enrollment_id="enr_cccccccccccccccccccccccccc",
        device_keys=DeviceKeys.generate(),
    )


def test_private_file_round_trip(tmp_path: Path) -> None:
    credentials = _credentials()
    path = tmp_path / "service-credentials.json"

    credentials.save(path)

    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    loaded = ServiceCredentials.load(path)
    assert loaded.public_info() == credentials.public_info()
    assert loaded.to_bytes() == credentials.to_bytes()


def test_private_file_rejects_overwrite_loose_mode_and_symlink(tmp_path: Path) -> None:
    credentials = _credentials()
    path = tmp_path / "service-credentials.json"
    credentials.save(path)

    with pytest.raises(CredentialError, match="already exists"):
        credentials.save(path)

    if os.name != "nt":
        path.chmod(0o644)
        with pytest.raises(CredentialError, match="0600"):
            ServiceCredentials.load(path)
        path.chmod(0o700)
        with pytest.raises(CredentialError, match="0600"):
            ServiceCredentials.load(path)
        path.chmod(0o600)

    link = tmp_path / "credentials-link.json"
    link.symlink_to(path)
    with pytest.raises(CredentialError, match="symbolic"):
        ServiceCredentials.load(link)


def test_private_keys_are_not_exposed_by_repr() -> None:
    credentials = _credentials()
    assert "private" not in repr(credentials)
    assert "private" not in repr(credentials.device_keys)


@pytest.mark.parametrize("version", [True, 1.0, "1"])
def test_credential_versions_must_be_json_integers(version: object) -> None:
    raw = json.loads(_credentials().to_bytes())
    raw["version"] = version
    with pytest.raises(CredentialError, match="Unsupported"):
        ServiceCredentials.from_bytes(json.dumps(raw).encode())

    raw = json.loads(_credentials().to_bytes())
    raw["device_keys"]["version"] = version
    with pytest.raises(CredentialError, match="Invalid"):
        ServiceCredentials.from_bytes(json.dumps(raw).encode())


@pytest.mark.parametrize("value", ["YQ==", "YQ+", "YQ/"])
def test_base64url_decoder_rejects_padding_and_standard_alphabet(value: str) -> None:
    with pytest.raises(ValueError, match="unpadded"):
        b64url_decode(value)


def test_sdk_source_does_not_import_runtime_vgen_package() -> None:
    source_root = Path(__file__).resolve().parents[1] / "src" / "vgen_sdk"
    for source in source_root.glob("*.py"):
        text = source.read_text(encoding="utf-8")
        assert "from vgen " not in text
        assert "from vgen." not in text
        assert "import vgen" not in text
