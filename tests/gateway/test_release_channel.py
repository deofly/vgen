from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vgen.gateway.app import create_app
from vgen.gateway.main import _parser
from vgen.gateway.releases import ReleaseCatalog, ReleaseManifestInvalid, ReleaseNotFound
from vgen.protocol.errors import ErrorCode

ROOT = Path(__file__).resolve().parents[2]


def _write_release(root: Path, *, artifact_bytes: bytes = b"public-installer") -> dict:
    version = "0.3.0"
    filename = "VGen-macOS-0.3.0.pkg"
    version_root = root / version
    version_root.mkdir(parents=True)
    (version_root / filename).write_bytes(artifact_bytes)
    manifest = {
        "schema_version": 1,
        "audience": "public",
        "version": version,
        "published_at": "2026-08-22T12:34:56Z",
        "artifacts": [
            {
                "name": "macos-cli",
                "kind": "cli-installer",
                "platform": "macos",
                "filename": filename,
                "size": len(artifact_bytes),
                "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                "content_type": "application/octet-stream",
            }
        ],
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True) + "\n").encode()
    (version_root / "manifest.json").write_bytes(manifest_bytes)
    channels = root / "channels"
    channels.mkdir()
    pointer = {
        "schema_version": 1,
        "channel": "stable",
        "version": version,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }
    (channels / "stable.json").write_text(json.dumps(pointer), encoding="utf-8")
    return {"version": version, "filename": filename, "bytes": artifact_bytes}


def _app(tmp_path: Path, release_root: Path | None, *, serve_files: bool = False):
    return create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
        release_root=str(release_root) if release_root is not None else None,
        serve_release_files=serve_files,
        sweep_interval_seconds=3600,
    )


def test_stable_and_version_metadata_have_distinct_cache_policies(tmp_path) -> None:
    release_root = tmp_path / "releases"
    release = _write_release(release_root)
    app = _app(tmp_path, release_root)

    with TestClient(app) as client:
        stable = client.get("/api/v1/releases/channels/stable")
        assert stable.status_code == 200, stable.text
        assert stable.headers["cache-control"] == "public, max-age=0, must-revalidate"
        assert stable.headers["etag"].startswith('"sha256-')
        payload = stable.json()
        assert payload["channel"] == "stable"
        assert payload["version"] == release["version"]
        assert payload["audience"] == "public"
        assert payload["artifacts"] == [
            {
                "name": "macos-cli",
                "kind": "cli-installer",
                "platform": "macos",
                "filename": release["filename"],
                "size": len(release["bytes"]),
                "sha256": hashlib.sha256(release["bytes"]).hexdigest(),
                "content_type": "application/octet-stream",
                "url": f"/releases/{release['version']}/{release['filename']}",
            }
        ]

        immutable = client.get(f"/api/v1/releases/versions/{release['version']}")
        assert immutable.status_code == 200
        assert immutable.headers["cache-control"] == "public, max-age=31536000, immutable"
        assert "channel" not in immutable.json()


def test_release_metadata_does_not_require_session_or_protocol_header(tmp_path) -> None:
    release_root = tmp_path / "releases"
    _write_release(release_root)
    app = _app(tmp_path, release_root)
    with TestClient(app) as client:
        response = client.get("/api/v1/releases/channels/stable")
        assert response.status_code == 200

    operation = app.openapi()["paths"]["/api/v1/releases/channels/{channel}"]["get"]
    assert "security" not in operation
    assert all(
        parameter.get("$ref") != "#/components/parameters/VgenProtocolVersion"
        for parameter in operation.get("parameters", [])
    )


def test_empty_or_unconfigured_release_root_is_a_safe_404(tmp_path) -> None:
    for index, release_root in enumerate((None, tmp_path / "empty")):
        app = create_app(
            database_path=str(tmp_path / f"gateway-{index}.db"),
            bootstrap_code="test-bootstrap",
            artifact_root=str(tmp_path / f"artifacts-{index}"),
            release_root=str(release_root) if release_root is not None else None,
            serve_release_files=True,
            sweep_interval_seconds=3600,
        )
        with TestClient(app) as client:
            metadata = client.get("/api/v1/releases/channels/stable")
            assert metadata.status_code == 404
            assert metadata.json()["error"]["code"] == int(ErrorCode.ARTIFACT_NOT_FOUND)
            download = client.get("/releases/0.3.0/VGen-macOS-0.3.0.pkg")
            assert download.status_code == 404
            assert "test-bootstrap" not in download.text


def test_local_fallback_only_serves_declared_digest_verified_files(tmp_path) -> None:
    release_root = tmp_path / "releases"
    release = _write_release(release_root)
    app = _app(tmp_path, release_root, serve_files=True)
    with TestClient(app) as client:
        response = client.get(f"/releases/{release['version']}/{release['filename']}")
        assert response.status_code == 200
        assert response.content == release["bytes"]
        assert response.headers["cache-control"] == "public, max-age=31536000, immutable"
        assert response.headers["etag"] == (
            f'"sha256-{hashlib.sha256(release["bytes"]).hexdigest()}"'
        )
        assert response.headers["content-disposition"].startswith("attachment;")

        undeclared = client.get(f"/releases/{release['version']}/other.pkg")
        assert undeclared.status_code == 404

    (release_root / release["version"] / release["filename"]).write_bytes(b"tampered")
    second_app = create_app(
        database_path=str(tmp_path / "gateway-tampered.db"),
        bootstrap_code="test-bootstrap",
        artifact_root=str(tmp_path / "artifacts-tampered"),
        release_root=str(release_root),
        serve_release_files=True,
        sweep_interval_seconds=3600,
    )
    with TestClient(second_app) as client:
        tampered = client.get(f"/releases/{release['version']}/{release['filename']}")
        assert tampered.status_code == 422
        assert tampered.json()["error"]["code"] == int(ErrorCode.ARTIFACT_INTEGRITY_FAILED)


def test_local_fallback_is_opt_in(tmp_path) -> None:
    release_root = tmp_path / "releases"
    release = _write_release(release_root)
    app = _app(tmp_path, release_root)
    with TestClient(app) as client:
        response = client.get(f"/releases/{release['version']}/{release['filename']}")
        assert response.status_code == 404


def test_catalog_rejects_traversal_and_symlinks(tmp_path) -> None:
    release_root = tmp_path / "releases"
    release = _write_release(release_root)
    catalog = ReleaseCatalog(release_root, serve_files=True)

    with pytest.raises(ReleaseNotFound):
        catalog.version("../0.3.0")
    with pytest.raises(ReleaseNotFound):
        catalog.file(release["version"], "../private-key")

    artifact = release_root / release["version"] / release["filename"]
    target = tmp_path / "outside.pkg"
    target.write_bytes(release["bytes"])
    artifact.unlink()
    artifact.symlink_to(target)
    with pytest.raises(ReleaseManifestInvalid, match="escapes the configured root"):
        catalog.file(release["version"], release["filename"])


def test_stable_pointer_is_bound_to_immutable_manifest_digest(tmp_path) -> None:
    release_root = tmp_path / "releases"
    _write_release(release_root)
    manifest = release_root / "0.3.0" / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b" ")
    catalog = ReleaseCatalog(release_root)
    with pytest.raises(ReleaseManifestInvalid, match="digest does not match"):
        catalog.channel("stable")


def test_manifest_duplicate_fields_are_rejected(tmp_path) -> None:
    release_root = tmp_path / "releases"
    _write_release(release_root)
    pointer = release_root / "channels" / "stable.json"
    pointer.write_text(
        '{"schema_version":1,"channel":"stable","channel":"stable",'
        '"version":"0.3.0","manifest_sha256":"' + "0" * 64 + '"}',
        encoding="utf-8",
    )
    with pytest.raises(ReleaseManifestInvalid, match="duplicate field"):
        ReleaseCatalog(release_root).channel("stable")


def test_release_public_base_url_is_validated_and_can_target_same_domain_oss_proxy(
    tmp_path,
) -> None:
    release_root = tmp_path / "releases"
    release = _write_release(release_root)
    catalog = ReleaseCatalog(
        release_root,
        public_base_url="https://vgen.example.com/releases",
    )
    assert catalog.version(release["version"])["artifacts"][0]["url"].startswith(
        "https://vgen.example.com/releases/0.3.0/"
    )
    for invalid in ("", "//evil.example/releases", "/../releases", "https://user:pw@host/r"):
        with pytest.raises(ValueError):
            ReleaseCatalog(release_root, public_base_url=invalid)


def test_gateway_cli_exposes_release_configuration_without_enabling_fallback_by_default() -> None:
    arguments = _parser().parse_args(
        [
            "serve",
            "--release-root",
            "/srv/vgen-releases",
            "--release-public-base-url",
            "/releases",
        ]
    )
    assert arguments.release_root == "/srv/vgen-releases"
    assert arguments.release_public_base_url == "/releases"
    assert arguments.serve_release_files is None


def test_ecs_nginx_serves_only_constrained_release_paths_with_correct_caches() -> None:
    gateway_source = (ROOT / "examples" / "ecs" / "nginx-vgen.conf.example").read_text(
        encoding="utf-8"
    )
    source = (
        ROOT / "examples" / "ecs" / "nginx-vgen-releases.conf.example"
    ).read_text(encoding="utf-8")
    unit = (ROOT / "examples" / "ecs" / "vgen-gateway.service").read_text(encoding="utf-8")
    installer = (ROOT / "examples" / "ecs" / "setup-gateway.sh").read_text(encoding="utf-8")
    assert "location = /releases/channels/stable.json" in source
    assert "/releases/" not in gateway_source
    assert "location = /releases/install-macos.sh" in source
    assert "alias /var/www/vgen-releases/install-macos.sh;" in source
    assert "location = /releases/install-macos.sh" in installer
    for config in (source, installer):
        release_location = next(
            line.strip()
            for line in config.splitlines()
            if line.strip().startswith("location ~") and "/releases/" in line
        )
        assert release_location.startswith('location ~ "^/releases/')
        assert release_location.endswith('$" {')
        bootstrap_block = config.split("location = /releases/install-macos.sh {", 1)[1].split(
            "}", 1
        )[0]
        assert 'Cache-Control "public, max-age=0, must-revalidate"' in bootstrap_block
        assert "immutable" not in bootstrap_block
    assert 'Cache-Control "public, max-age=0, must-revalidate"' in source
    assert 'Cache-Control "public, max-age=31536000, immutable"' in source
    assert "location /releases/ {\n    return 404;" in source
    assert "autoindex" not in source
    assert "--release-root /var/www/vgen-releases" in unit
    assert 'readonly RELEASE_ROOT="/var/www/vgen-releases"' in installer
