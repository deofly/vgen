from __future__ import annotations

import hashlib
import stat
import subprocess
import sys
import time
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


def _wait_for_file(path: Path, *, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {path.name}")
        time.sleep(0.01)


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
    assert session.requests[0]["headers"] == {}


def test_complete_verified_partial_is_published_without_another_request(tmp_path: Path) -> None:
    content = b"complete verified partial"
    model_pin = pin(content)
    partial = tmp_path / "vae" / f".model.safetensors.{model_pin.sha256[:16]}.vgen.partial"
    partial.parent.mkdir()
    partial.write_bytes(content)
    session = FakeSession()

    result = ModelInstaller(
        tmp_path,
        session=session,  # type: ignore[arg-type]
        resolver=public_resolver,
        huggingface_token=None,
    ).install(
        pin(
            content,
            source=None,
            gated=True,
            manual_download=True,
        )
    )

    assert result.status == "installed"
    assert session.requests == []
    assert (tmp_path / "vae/model.safetensors").read_bytes() == content
    assert not partial.exists()


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
    with pytest.raises(ModelInstallError, match="MODEL_SOURCE_UNAVAILABLE"):
        ModelInstaller(tmp_path, resolver=public_resolver).install(  # type: ignore[arg-type]
            pin(content, source=None)
        )


def test_existing_mismatched_target_is_never_replaced(tmp_path: Path) -> None:
    target = tmp_path / "vae/model.safetensors"
    target.parent.mkdir()
    target.write_bytes(b"user file")
    with pytest.raises(ModelInstallError, match="MODEL_TARGET_CONFLICT"):
        ModelInstaller(tmp_path, resolver=public_resolver).install(pin(b"reviewed model"))  # type: ignore[arg-type]
    assert target.read_bytes() == b"user file"


def test_same_digest_is_downloaded_once_and_hardlinked_to_multiple_placements(
    tmp_path: Path,
) -> None:
    content = b"shared text encoder"
    session = FakeSession(FakeResponse(200, content))
    installer = ModelInstaller(tmp_path, session=session, resolver=public_resolver)  # type: ignore[arg-type]

    first = installer.install(pin(content, path="text_encoders/shared-t5.safetensors"))
    second = installer.install(pin(content, path="clip/shared-t5-copy.safetensors"))

    first_path = tmp_path / "text_encoders/shared-t5.safetensors"
    second_path = tmp_path / "clip/shared-t5-copy.safetensors"
    blob = (
        tmp_path
        / ".vgen/artifacts/sha256"
        / hashlib.sha256(content).hexdigest()[:2]
        / hashlib.sha256(content).hexdigest()
    )
    assert first.status == "installed"
    assert second.status == "already_installed"
    assert len(session.requests) == 1
    assert first_path.read_bytes() == second_path.read_bytes() == blob.read_bytes() == content
    assert first_path.stat().st_ino == second_path.stat().st_ino == blob.stat().st_ino
    assert not first_path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    assert not second_path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    assert not blob.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)


def test_digest_lock_serializes_independent_installers(tmp_path: Path) -> None:
    content = b"one reviewed digest shared across independent worker processes"
    digest = hashlib.sha256(content).hexdigest()
    partial = (
        tmp_path
        / ".vgen/artifacts/sha256"
        / digest[:2]
        / f".{digest}.vgen.partial"
    )
    partial.parent.mkdir(parents=True)
    partial.write_bytes(content)
    held = tmp_path / "held"
    release = tmp_path / "release"
    first_result = tmp_path / "first.result"
    second_result = tmp_path / "second.result"
    helper = """
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from vgen.worker.model_installer import ModelInstaller

root, digest, size, target, mode, marker, release, result = sys.argv[1:9]
root = Path(root)
marker = Path(marker)
release = Path(release)
result = Path(result)
installer = ModelInstaller(root)
pin = SimpleNamespace(
    path=target,
    sha256=digest,
    size=int(size),
    source=None,
    revision=None,
    license=None,
    license_url=None,
    gated=True,
    manual_download=True,
)
if mode == "hold":
    with installer._digest_lock(digest):
        marker.write_text("locked", encoding="utf-8")
        deadline = time.monotonic() + 10
        while not release.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not release.exists():
            raise SystemExit(3)
installed = installer.install(pin)
result.write_text(installed.status, encoding="utf-8")
"""
    first = subprocess.Popen(
        [
            sys.executable,
            "-c",
            helper,
            str(tmp_path),
            digest,
            str(len(content)),
            "text_encoders/shared.safetensors",
            "hold",
            str(held),
            str(release),
            str(first_result),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    second: subprocess.Popen[str] | None = None
    try:
        _wait_for_file(held)
        second = subprocess.Popen(
            [
                sys.executable,
                "-c",
                helper,
                str(tmp_path),
                digest,
                str(len(content)),
                "clip/shared.safetensors",
                "install",
                str(tmp_path / "unused"),
                str(release),
                str(second_result),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.2)
        assert second.poll() is None
        assert not second_result.exists()
        release.write_text("release", encoding="utf-8")
        first_output = first.communicate(timeout=10)
        second_output = second.communicate(timeout=10)
        assert first.returncode == 0, first_output
        assert second.returncode == 0, second_output
        assert {first_result.read_text(), second_result.read_text()} == {
            "installed",
            "already_installed",
        }
        assert (tmp_path / "text_encoders/shared.safetensors").read_bytes() == content
        assert (tmp_path / "clip/shared.safetensors").read_bytes() == content
        assert not partial.exists()
    finally:
        release.touch(exist_ok=True)
        for process in (first, second):
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()


def test_alternative_placement_resumes_the_digest_partial_instead_of_redownloading(
    tmp_path: Path,
) -> None:
    content = b"one digest shared by two reviewed mirrors"
    first_body = content[:-1]
    session = FakeSession(
        FakeResponse(200, first_body),
        FakeResponse(
            206,
            content[-1:],
            {"Content-Range": (f"bytes {len(first_body)}-{len(content) - 1}/{len(content)}")},
        ),
    )
    installer = ModelInstaller(
        tmp_path,
        session=session,  # type: ignore[arg-type]
        resolver=public_resolver,
    )

    with pytest.raises(ModelInstallError, match="MODEL_SIZE_MISMATCH"):
        installer.install(
            pin(
                content,
                path="text_encoders/shared.safetensors",
                source="https://first.example.test/shared.safetensors",
            )
        )

    result = installer.install(
        pin(
            content,
            path="clip/shared.safetensors",
            source="https://second.example.test/shared.safetensors",
        )
    )
    digest = hashlib.sha256(content).hexdigest()
    partial = tmp_path / ".vgen/artifacts/sha256" / digest[:2] / f".{digest}.vgen.partial"

    assert result.status == "installed"
    assert session.requests[1]["headers"] == {"Range": f"bytes={len(first_body)}-"}
    assert sum(len(response) for response in (first_body, content[-1:])) == len(content)
    assert (tmp_path / "clip/shared.safetensors").read_bytes() == content
    assert not partial.exists()


@pytest.mark.parametrize(
    "restricted_pin",
    [
        {"manual_download": True},
        {"source": None},
        {
            "gated": True,
            "source": "https://huggingface.co/example/model/resolve/revision/model.safetensors",
        },
    ],
    ids=["manual", "no-source", "gated-without-token"],
)
def test_existing_cas_blob_is_reused_before_download_requirements(
    tmp_path: Path, restricted_pin: dict[str, Any]
) -> None:
    content = b"shared gated or manual model"
    session = FakeSession(FakeResponse(200, content))
    installer = ModelInstaller(
        tmp_path,
        session=session,  # type: ignore[arg-type]
        resolver=public_resolver,
        huggingface_token=None,
    )
    installer.install(pin(content, path="text_encoders/original.safetensors"))

    result = installer.install(pin(content, path="clip/reused.safetensors", **restricted_pin))

    assert result.status == "already_installed"
    assert len(session.requests) == 1
    assert (tmp_path / "clip/reused.safetensors").read_bytes() == content


def test_existing_target_is_reused_before_download_requirements(tmp_path: Path) -> None:
    content = b"manually placed gated model"
    target = tmp_path / "vae/manually-placed.safetensors"
    target.parent.mkdir()
    target.write_bytes(content)
    session = FakeSession()
    installer = ModelInstaller(
        tmp_path,
        session=session,  # type: ignore[arg-type]
        resolver=public_resolver,
        huggingface_token=None,
    )

    result = installer.install(
        pin(
            content,
            path="vae/manually-placed.safetensors",
            source=None,
            gated=True,
            manual_download=True,
        )
    )

    assert result.status == "already_installed"
    assert session.requests == []
    assert not target.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)


def test_cas_digest_is_rechecked_after_write_permission_is_restored(
    tmp_path: Path,
) -> None:
    content = b"shared artifact"
    installer = ModelInstaller(
        tmp_path,
        session=FakeSession(FakeResponse(200, content)),  # type: ignore[arg-type]
        resolver=public_resolver,
    )
    installer.install(pin(content, path="text_encoders/original.safetensors"))
    digest = hashlib.sha256(content).hexdigest()
    blob = tmp_path / ".vgen/artifacts/sha256" / digest[:2] / digest
    blob.chmod(0o644)
    blob.write_bytes(b"x" * len(content))

    with pytest.raises(ModelInstallError, match="MODEL_CACHE_CONFLICT"):
        installer.install(pin(content, path="clip/reused.safetensors", source=None))

    assert not (tmp_path / "clip/reused.safetensors").exists()


def test_gated_huggingface_token_is_worker_local_and_not_forwarded_to_redirect(
    tmp_path: Path,
) -> None:
    content = b"gated model"
    redirect = FakeResponse(
        302,
        b"",
        {"Location": "https://cdn.example.test/signed/model.safetensors?token=opaque"},
    )
    session = FakeSession(redirect, FakeResponse(200, content))
    installer = ModelInstaller(
        tmp_path,
        session=session,  # type: ignore[arg-type]
        resolver=public_resolver,
        huggingface_token="hf_worker_secret",
    )

    installer.install(
        pin(
            content,
            gated=True,
            source="https://huggingface.co/example/model/resolve/revision/model.safetensors",
        )
    )

    assert session.requests[0]["headers"] == {"Authorization": "Bearer hf_worker_secret"}
    assert session.requests[1]["headers"] == {}


def test_gated_model_requires_worker_local_huggingface_token(tmp_path: Path) -> None:
    with pytest.raises(ModelInstallError, match="MODEL_GATED_CREDENTIAL_UNAVAILABLE"):
        ModelInstaller(
            tmp_path,
            resolver=public_resolver,
            huggingface_token=None,
        ).install(
            pin(
                b"gated",
                gated=True,
                source="https://huggingface.co/example/model/resolve/revision/model.safetensors",
            )
        )


def test_invalid_optional_huggingface_token_does_not_block_public_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"public model"
    monkeypatch.setenv("HF_TOKEN", "invalid token with spaces")
    session = FakeSession(FakeResponse(200, content))

    result = ModelInstaller(
        tmp_path,
        session=session,  # type: ignore[arg-type]
        resolver=public_resolver,
    ).install(pin(content))

    assert result.status == "installed"
