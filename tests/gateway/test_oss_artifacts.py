from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

from vgen.gateway.app import create_app
from vgen.gateway.artifacts import OssArtifactStore, StsCredentials
from vgen.protocol import ErrorCode, VGenError, new_id


class FakeIssuer:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def assume_role(self, **values: object) -> StsCredentials:
        self.calls.append(values)
        return StsCredentials("sts-id", "sts-secret", "sts-token", time.time() + 900)


def make_store(issuer: FakeIssuer | None = None) -> OssArtifactStore:
    return OssArtifactStore(
        issuer or FakeIssuer(),
        endpoint="https://oss-cn-example.aliyuncs.com",
        bucket_name="vgen-private",
        transfer_role_arn="acs:ram::1234567890123456:role/vgen-transfer",
        key_prefix="tenant/vgen",
    )


def test_oss_store_issues_object_scoped_sts_tickets() -> None:
    issuer = FakeIssuer()
    store = make_store(issuer)
    artifact_id = new_id("artifact")
    upload = store.issue_ticket(artifact_id, method="PUT", ttl_seconds=60, max_bytes=2048)
    download = store.issue_ticket(artifact_id, method="GET", ttl_seconds=60, max_bytes=2048)

    assert upload.url.startswith("oss://vgen-private/tenant/vgen/")
    assert upload.provider == "oss_sts"
    assert upload.endpoint == "https://oss-cn-example.aliyuncs.com"
    assert upload.credentials == {
        "access_key_id": "sts-id",
        "access_key_secret": "sts-secret",
        "security_token": "sts-token",
    }
    upload_policy = json.loads(str(issuer.calls[0]["policy"]))
    assert upload_policy["Statement"][0]["Action"] == [
        "oss:PutObject",
        "oss:AbortMultipartUpload",
        "oss:ListParts",
    ]
    assert upload_policy["Statement"][0]["Resource"].endswith(
        f"/{artifact_id}.ciphertext"
    )
    download_policy = json.loads(str(issuer.calls[1]["policy"]))
    assert download_policy["Statement"][0]["Action"] == ["oss:GetObject"]
    assert download.method == "GET"
    assert "sts-secret" not in repr(upload)


def test_oss_store_head_checks_size_without_downloading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []

    class FakeBucket:
        def __init__(self, auth: object, endpoint: str, bucket: str) -> None:
            del auth
            assert endpoint.startswith("https://")
            assert bucket == "vgen-private"

        def head_object(self, key: str) -> SimpleNamespace:
            observed.append(key)
            return SimpleNamespace(content_length=1024)

    import oss2

    monkeypatch.setattr(oss2, "Bucket", FakeBucket)
    monkeypatch.setattr(oss2, "StsAuth", lambda *args: object())
    store = make_store()
    artifact_id = new_id("artifact")
    assert store.observe_upload(artifact_id, max_bytes=1024) == (1024, None)
    assert observed and observed[0].endswith(f"/{artifact_id}.ciphertext")
    with pytest.raises(VGenError) as error:
        store.observe_upload(artifact_id, max_bytes=1023)
    assert error.value.code is ErrorCode.ARTIFACT_INTEGRITY_FAILED


def test_oss_store_access_validation_only_assumes_role() -> None:
    issuer = FakeIssuer()
    make_store(issuer).verify_access()
    assert len(issuer.calls) == 1
    assert issuer.calls[0]["session_name"] == "vgen-config-check"


def test_oss_store_rejects_non_artifact_ids() -> None:
    with pytest.raises(VGenError) as invalid:
        make_store().issue_ticket("../../secret", method="GET", ttl_seconds=60, max_bytes=1)
    assert invalid.value.code is ErrorCode.ARTIFACT_NOT_FOUND


def test_oss_environment_requires_https_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VGEN_OSS_ENDPOINT", "http://oss-cn-example.aliyuncs.com")
    monkeypatch.setenv("VGEN_OSS_BUCKET", "ciphertext")
    with pytest.raises(RuntimeError, match="HTTPS"):
        OssArtifactStore.from_environment()


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://user:secret@oss-cn-example.aliyuncs.com",
        "https://oss-cn-example.aliyuncs.com/private/path",
        "https://oss-cn-example.aliyuncs.com?credential=secret",
    ],
)
def test_oss_environment_rejects_endpoint_credentials_and_paths(
    monkeypatch: pytest.MonkeyPatch, endpoint: str
) -> None:
    monkeypatch.setenv("VGEN_OSS_ENDPOINT", endpoint)
    monkeypatch.setenv("VGEN_OSS_BUCKET", "vgen-private")
    with pytest.raises(RuntimeError, match="credential-free HTTPS origin"):
        OssArtifactStore.from_environment()


def test_oss_environment_rejects_invalid_bucket_before_loading_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VGEN_OSS_ENDPOINT", "https://oss-cn-example.aliyuncs.com")
    monkeypatch.setenv("VGEN_OSS_BUCKET", "UPPERCASE_OR_SECRET")
    with pytest.raises(RuntimeError, match="VGEN_OSS_BUCKET is invalid"):
        OssArtifactStore.from_environment()


def test_gateway_accepts_an_injected_provider_store_without_local_credentials(tmp_path) -> None:
    store = make_store()
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


def test_gateway_prohibits_local_artifact_storage_without_explicit_development_opt_in(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("VGEN_ARTIFACT_STORE", raising=False)
    monkeypatch.delenv("VGEN_ALLOW_LOCAL_ARTIFACT_STORE", raising=False)
    with pytest.raises(RuntimeError, match="explicit development-only"):
        create_app(database_path=str(tmp_path / "missing-store.db"), bootstrap_code="test")
    monkeypatch.setenv("VGEN_ARTIFACT_STORE", "local")
    with pytest.raises(RuntimeError, match="explicit development-only"):
        create_app(database_path=str(tmp_path / "local-store.db"), bootstrap_code="test")
    monkeypatch.setenv("VGEN_ALLOW_LOCAL_ARTIFACT_STORE", "1")
    app = create_app(database_path=str(tmp_path / "dev-local.db"), bootstrap_code="test")
    try:
        assert app.state.artifact_store.store_type == "local"
    finally:
        app.state.db.close()
