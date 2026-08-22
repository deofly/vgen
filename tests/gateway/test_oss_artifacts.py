from __future__ import annotations

from types import SimpleNamespace

import pytest

from vgen.gateway.app import create_app
from vgen.gateway.artifacts import OssArtifactStore
from vgen.protocol import ErrorCode, VGenError, new_id


class FakeBucket:
    def __init__(self, *, size: int = 1234) -> None:
        self.size = size
        self.signed: list[tuple[str, str, int, dict[str, str] | None]] = []
        self.head_keys: list[str] = []

    def sign_url(
        self,
        method: str,
        key: str,
        expires: int,
        *,
        headers: dict[str, str] | None = None,
    ) -> str:
        self.signed.append((method, key, expires, headers))
        return f"https://bucket.oss.example/{key}?signature=capability-secret"

    def head_object(self, key: str) -> SimpleNamespace:
        self.head_keys.append(key)
        return SimpleNamespace(content_length=self.size)


def test_oss_store_issues_provider_neutral_single_object_tickets() -> None:
    bucket = FakeBucket()
    store = OssArtifactStore(bucket, key_prefix="tenant/vgen")
    artifact_id = new_id("artifact")

    upload = store.issue_ticket(
        artifact_id,
        method="PUT",
        ttl_seconds=60,
        max_bytes=2048,
    )
    download = store.issue_ticket(
        artifact_id,
        method="GET",
        ttl_seconds=60,
        max_bytes=2048,
    )

    assert upload.method == "PUT"
    assert upload.headers == {
        "Content-Type": "application/octet-stream",
        "x-oss-forbid-overwrite": "true",
    }
    assert bucket.signed[0][3] == upload.headers
    assert download.headers == {}
    assert upload.url.startswith("https://")
    assert bucket.signed[0][1].startswith("tenant/vgen/")
    assert bucket.signed[0][1].endswith(f"/{artifact_id}.ciphertext")
    # The capability URL is returned, not retained in store state or an object reference.
    assert "capability-secret" not in repr(store.__dict__)


def test_oss_store_observes_upload_size_without_mislabeling_etag_as_sha256() -> None:
    bucket = FakeBucket(size=1024)
    store = OssArtifactStore(bucket)
    artifact_id = new_id("artifact")

    assert store.observe_upload(artifact_id, max_bytes=1024) == (1024, None)
    with pytest.raises(VGenError) as error:
        store.observe_upload(artifact_id, max_bytes=1023)
    assert error.value.code is ErrorCode.ARTIFACT_INTEGRITY_FAILED


def test_oss_store_rejects_non_artifact_ids_and_insecure_signed_urls() -> None:
    store = OssArtifactStore(FakeBucket())
    with pytest.raises(VGenError) as invalid:
        store.issue_ticket("../../secret", method="GET", ttl_seconds=60, max_bytes=1)
    assert invalid.value.code is ErrorCode.ARTIFACT_NOT_FOUND

    class InsecureBucket(FakeBucket):
        def sign_url(self, *args, **kwargs) -> str:  # type: ignore[no-untyped-def]
            return "http://oss.example/object?signature=secret"

    insecure = OssArtifactStore(InsecureBucket())
    with pytest.raises(VGenError) as error:
        insecure.issue_ticket(new_id("artifact"), method="GET", ttl_seconds=60, max_bytes=1)
    assert error.value.code is ErrorCode.STORAGE_UNAVAILABLE


def test_oss_environment_requires_https_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VGEN_OSS_ENDPOINT", "http://oss-cn-example.aliyuncs.com")
    monkeypatch.setenv("VGEN_OSS_BUCKET", "ciphertext")
    with pytest.raises(RuntimeError, match="HTTPS"):
        OssArtifactStore.from_environment()


def test_gateway_accepts_an_injected_provider_store_without_local_credentials(tmp_path) -> None:
    store = OssArtifactStore(FakeBucket())
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        artifact_store_override=store,
    )
    try:
        assert app.state.artifact_store is store
        assert app.state.artifact_store.store_type == "oss"
    finally:
        app.state.db.close()
