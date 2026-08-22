from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from vgen.worker.model_installer import ModelInstaller, ModelInstallError


class FakeResponse:
    def __init__(self, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def iter_content(self, chunk_size: int) -> Any:
        for offset in range(0, len(self._body), max(1, chunk_size)):
            yield self._body[offset : offset + chunk_size]

    def close(self) -> None:
        return None


class FakeSession:
    def __init__(self, *responses: FakeResponse) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.requests.append({"method": method, "url": url, **kwargs})
        return self.responses.pop(0)


def pin(content: bytes, **overrides: Any) -> Any:
    value = {
        "path": "vae/model.safetensors",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "source": "https://models.example.test/revision/model.safetensors",
        "revision": "revision",
        "license": "Apache-2.0",
        "license_url": "https://licenses.example.test/apache-2.0",
        "gated": False,
        "manual_download": False,
    }
    value.update(overrides)
    return SimpleNamespace(**value)


def public_resolver(_host: str, _port: int) -> tuple[str, ...]:
    return ("8.8.8.8",)


def test_installs_verified_model_without_overwriting(tmp_path: Path) -> None:
    content = b"reviewed model content"
    session = FakeSession(FakeResponse(200, content))
    installer = ModelInstaller(tmp_path, session=session, resolver=public_resolver)  # type: ignore[arg-type]

    result = installer.install(pin(content))

    assert result.status == "installed"
    assert (tmp_path / "vae/model.safetensors").read_bytes() == content
    assert session.requests[0]["headers"] == {}
    second = installer.install(pin(content))
    assert second.status == "already_installed"
    assert len(session.requests) == 1


def test_resumes_its_digest_scoped_partial_with_range(tmp_path: Path) -> None:
    content = b"abcdefghij"
    digest = hashlib.sha256(content).hexdigest()
    directory = tmp_path / "vae"
    directory.mkdir()
    partial = directory / f".model.safetensors.{digest[:16]}.vgen.partial"
    partial.write_bytes(content[:4])
    session = FakeSession(
        FakeResponse(
            206,
            content[4:],
            {"Content-Range": f"bytes 4-{len(content) - 1}/{len(content)}"},
        )
    )

    ModelInstaller(tmp_path, session=session, resolver=public_resolver).install(pin(content))  # type: ignore[arg-type]

    assert session.requests[0]["headers"] == {"Range": "bytes=4-"}
    assert (directory / "model.safetensors").read_bytes() == content
    assert not partial.exists()


def test_digest_failure_keeps_partial_and_never_publishes_target(tmp_path: Path) -> None:
    expected = b"expected content"
    session = FakeSession(FakeResponse(200, b"tampered content"))

    with pytest.raises(ModelInstallError, match="MODEL_(SIZE_MISMATCH|INTEGRITY_FAILED)"):
        ModelInstaller(tmp_path, session=session, resolver=public_resolver).install(pin(expected))  # type: ignore[arg-type]

    assert not (tmp_path / "vae/model.safetensors").exists()


def test_complete_sized_corrupt_partial_is_removed_for_clean_retry(tmp_path: Path) -> None:
    expected = b"expected-model"
    corrupt = b"x" * len(expected)
    model_pin = pin(expected)
    digest = model_pin.sha256
    partial = tmp_path / "vae" / f".model.safetensors.{digest[:16]}.vgen.partial"
    session = FakeSession(FakeResponse(200, corrupt))

    with pytest.raises(ModelInstallError, match="MODEL_INTEGRITY_FAILED"):
        ModelInstaller(tmp_path, session=session, resolver=public_resolver).install(model_pin)  # type: ignore[arg-type]

    assert not partial.exists()
    assert not (tmp_path / "vae/model.safetensors").exists()


def test_rejects_private_source_path_escape_and_manual_pin(tmp_path: Path) -> None:
    content = b"model"
    private_session = FakeSession(FakeResponse(200, content))
    with pytest.raises(ModelInstallError, match="MODEL_SOURCE_NOT_PUBLIC"):
        ModelInstaller(
            tmp_path,
            session=private_session,  # type: ignore[arg-type]
            resolver=lambda _host, _port: ("127.0.0.1",),
        ).install(pin(content))
    assert private_session.requests == []

    with pytest.raises(ModelInstallError, match="MODEL_PATH_INVALID"):
        ModelInstaller(tmp_path, resolver=public_resolver).install(  # type: ignore[arg-type]
            pin(content, path="../outside.safetensors")
        )
    with pytest.raises(ModelInstallError, match="MODEL_MANUAL_ACTION_REQUIRED"):
        ModelInstaller(tmp_path, resolver=public_resolver).install(  # type: ignore[arg-type]
            pin(content, manual_download=True)
        )


def test_existing_mismatched_target_is_never_replaced(tmp_path: Path) -> None:
    target = tmp_path / "vae/model.safetensors"
    target.parent.mkdir()
    target.write_bytes(b"user file")
    with pytest.raises(ModelInstallError, match="MODEL_TARGET_CONFLICT"):
        ModelInstaller(tmp_path, resolver=public_resolver).install(pin(b"reviewed model"))  # type: ignore[arg-type]
    assert target.read_bytes() == b"user file"
