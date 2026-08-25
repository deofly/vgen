from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shlex
import stat
import subprocess
import sys
import tempfile
import threading
import zipfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from vgen.gateway.releases import ReleaseCatalog

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "build_public_release", ROOT / "tools" / "build_public_release.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

VERSION = "0.3.0"
PUBLISHED_AT = "2026-08-22T12:34:56Z"


def _zip_entry(name: str, value: bytes, *, mode: int = 0o644) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name, (2020, 2, 2, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = mode << 16
    return info, value


def _checksums(files: dict[str, bytes]) -> bytes:
    return b"".join(
        f"{hashlib.sha256(value).hexdigest()}  {name}\n".encode()
        for name, value in files.items()
    )


def _wheel_bytes(
    *,
    distribution: str = "vgen",
    version: str = VERSION,
    tag: str = "py3-none-any",
    marker: bytes = b"same reviewed source",
) -> bytes:
    buffer = io.BytesIO()
    dist_info = f"vgen-{version}.dist-info"
    files = {
        "vgen/__init__.py": marker,
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.4\nName: {distribution}\nVersion: {version}\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            f"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: {tag}\n"
        ).encode(),
    }
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, value in files.items():
            info, content = _zip_entry(name, value)
            archive.writestr(info, content)
    return buffer.getvalue()


def _mac_bundle(
    path: Path,
    *,
    marker: Path | None = None,
    wheel: bytes | None = None,
    gateway_default: str | None = None,
    extra_files: dict[str, bytes] | None = None,
) -> None:
    wheel = _wheel_bytes() if wheel is None else wheel
    prefix = f"VGen-macOS-{VERSION}/"
    install = b"#!/bin/sh\nset -eu\n"
    if marker is not None:
        install += (
            f"printf '%s' \"$1\" > {shlex.quote(str(marker))}\n"
            'mkdir -p "$HOME/.local/bin"\n'
            'cat > "$HOME/.local/bin/vgen" <<\'SH\'\n'
            "#!/bin/sh\n"
            f"if [ \"$1\" = \"--version\" ]; then echo 'vgen {VERSION}'; exit 0; fi\n"
            "if [ \"$1 $2\" = \"profile show\" ]; then exit 1; fi\n"
            "exit 0\n"
            "SH\n"
            'chmod 755 "$HOME/.local/bin/vgen"\n'
        ).encode()
    files = {
        "README.md": b"offline user guide\n",
        "install.command": install,
        f"vgen-{VERSION}-py3-none-any.whl": wheel,
    }
    if gateway_default is not None:
        files["gateway-default.txt"] = gateway_default.encode() + b"\n"
    files.update(extra_files or {})
    with zipfile.ZipFile(path, "w") as archive:
        for name, value in files.items():
            info, content = _zip_entry(
                f"{prefix}{name}", value, mode=0o755 if name == "install.command" else 0o644
            )
            archive.writestr(info, content)
        info, content = _zip_entry(f"{prefix}SHA256SUMS", _checksums(files))
        archive.writestr(info, content)


def _windows_bundle(
    path: Path,
    *,
    include_credentials: bool = False,
    gateway_url: str = "https://gateway.example",
    wheel_value: bytes | None = None,
    extra_files: dict[str, bytes] | None = None,
) -> None:
    wheel_value = _wheel_bytes() if wheel_value is None else wheel_value
    wheel = f"vgen-{VERSION}-py3-none-any.whl"
    config = {
        "format": "vgen-windows-worker-bundle",
        "version": 1,
        "gateway_url": gateway_url,
        "worker_credentials": "worker-credentials.json",
        "wheel": {
            "name": wheel,
            "version": VERSION,
            "sha256": hashlib.sha256(wheel_value).hexdigest(),
        },
        "enrollment": {
            "kind": "worker",
            "identity": "generated_on_worker",
            "secret_input": "hidden_prompt_or_stdin",
        },
    }
    files = {
        "INSTALL.txt": b"credential-free worker\n",
        "enroll-worker.ps1": b"# enrollment\n",
        "start-worker.cmd": b"@echo off\r\n",
        "setup-worker.ps1": b"# setup\n",
        "supervise-worker.ps1": b"# supervisor\n",
        "comfyui-minimax-h3-policy.yaml": b"version: 1\n",
        "vgen-worker-bundle.json": json.dumps(config, sort_keys=True).encode() + b"\n",
        wheel: wheel_value,
    }
    if include_credentials:
        files["worker-credentials.json"] = b'{"private_key":"must-not-ship"}\n'
    files.update(extra_files or {})
    with zipfile.ZipFile(path, "w") as archive:
        for name, value in files.items():
            info, content = _zip_entry(name, value)
            archive.writestr(info, content)
        info, content = _zip_entry("SHA256SUMS", _checksums(files))
        archive.writestr(info, content)


def _inputs(
    tmp_path: Path,
    *,
    marker: Path | None = None,
    gateway_url: str = "https://gateway.example",
    mac_wheel: bytes | None = None,
    windows_wheel: bytes | None = None,
) -> tuple[Path, Path]:
    mac = tmp_path / f"VGen-macOS-{VERSION}.zip"
    windows = tmp_path / f"vgen-windows-worker-installer-{VERSION}.zip"
    _mac_bundle(mac, marker=marker, wheel=mac_wheel)
    _windows_bundle(windows, gateway_url=gateway_url, wheel_value=windows_wheel)
    return mac, windows


def _release_server(
    serve_root: Path,
    *,
    artifact_redirect: str | None = None,
    artifact_failures: int = 0,
) -> ThreadingHTTPServer:
    state = {"artifact_failures": artifact_failures}

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            super().__init__(*args, directory=str(serve_root), **kwargs)

        def log_message(self, _format, *_args):  # type: ignore[no-untyped-def]
            return

        def do_GET(self):  # type: ignore[no-untyped-def]
            if self.path == "/api/v1/releases/channels/stable":
                manifest = json.loads((serve_root / VERSION / "manifest.json").read_bytes())
                pointer = json.loads((serve_root / "channels" / "stable.json").read_bytes())
                body = MODULE._json_bytes(
                    {
                        **manifest,
                        "manifest_sha256": pointer["manifest_sha256"],
                        "channel": "stable",
                        "artifacts": [
                            {
                                **item,
                                "url": f"/releases/{VERSION}/{item['filename']}",
                            }
                            for item in manifest["artifacts"]
                        ],
                    }
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            mac_path = f"/releases/{VERSION}/VGen-macOS-{VERSION}.zip"
            if self.path == mac_path and state["artifact_failures"] > 0:
                state["artifact_failures"] -= 1
                self.send_response(503)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if artifact_redirect and self.path == mac_path:
                self.send_response(302)
                self.send_header("Location", artifact_redirect)
                self.end_headers()
                return
            if self.path.startswith("/releases/"):
                self.path = self.path.removeprefix("/releases")
            return super().do_GET()

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


def _run_bootstrap(
    script: Path,
    *,
    home: Path,
    answer: str = "n\n",
    piped: bool = False,
) -> subprocess.CompletedProcess:
    home.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "HOME": str(home)}
    if piped:
        env["VGEN_INSTALL_YES"] = "1"
    return subprocess.run(
        ["/bin/sh"] if piped else ["/bin/sh", str(script)],
        input=script.read_text(encoding="utf-8") if piped else answer,
        text=True,
        capture_output=True,
        check=False,
        env=env,
        cwd=home,
        timeout=30,
    )


def _build(
    tmp_path: Path,
    *,
    origin: str = "https://gateway.example",
    release_origin: str | None = None,
    marker: Path | None = None,
):
    mac, windows = _inputs(tmp_path, marker=marker, gateway_url=origin)
    return MODULE.build_public_release(
        version=VERSION,
        published_at=PUBLISHED_AT,
        gateway_origin=origin,
        release_origin=release_origin or origin,
        macos_bundle=mac,
        windows_worker_bundle=windows,
        output_root=tmp_path / "public-releases",
    )


def test_builds_gateway_catalog_tree_and_idempotent_stable_bootstrap(tmp_path: Path) -> None:
    result = _build(tmp_path)
    manifest_bytes = result.manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    assert [item["name"] for item in manifest["artifacts"]] == [
        "macos-cli",
        "windows-worker-installer",
    ]
    assert all(item["size"] > 0 for item in manifest["artifacts"])
    assert result.manifest_sha256 == hashlib.sha256(manifest_bytes).hexdigest()
    pointer = json.loads(result.stable_pointer.read_bytes())
    assert pointer == {
        "schema_version": 1,
        "channel": "stable",
        "version": VERSION,
        "manifest_sha256": result.manifest_sha256,
    }
    catalog = ReleaseCatalog(result.root, serve_files=True)
    stable = catalog.channel("stable")
    assert stable["version"] == VERSION
    for item in stable["artifacts"]:
        assert catalog.file(VERSION, item["filename"]).sha256 == item["sha256"]

    before = {
        path.relative_to(result.root).as_posix(): path.read_bytes()
        for path in result.root.rglob("*")
        if path.is_file()
    }
    second = _build(tmp_path)
    after = {
        path.relative_to(second.root).as_posix(): path.read_bytes()
        for path in second.root.rglob("*")
        if path.is_file()
    }
    assert before == after


def test_bootstrap_is_pinned_secret_free_and_requires_reviewed_execution(tmp_path: Path) -> None:
    result = _build(tmp_path)
    script = result.macos_bootstrap.read_text(encoding="utf-8")
    assert stat.S_IMODE(result.macos_bootstrap.stat().st_mode) == 0o755
    assert "https://gateway.example" in script
    assert result.manifest_sha256 in script
    assert "/releases/channels/stable.json" in script
    assert "version manifest SHA-256 mismatch" in script
    assert "macOS artifact size or SHA-256 mismatch" in script
    assert "cross-origin release redirect refused" in script
    assert '"$candidate" -I -B -c' in script
    assert '"$PYTHON_BIN" -I -B <<\'PY\'' in script
    assert "Install the CLI for the current user now? [y/N]" in script
    assert 'status("Checking the latest VGen release...")' in script
    assert "Download interrupted; retrying" in script
    assert 'status("Download complete; verifying the package...")' in script
    assert "read -r answer 2>/dev/null </dev/tty" in script
    assert "install.command\" --install-only" in script
    assert '"$VGEN_BIN" broker service-refresh' in script
    assert "jq" not in script
    assert "curl" not in script
    for secret_word in ("invite_uri", "private_key", "session_token", "recovery_words"):
        assert secret_word not in script

    windows = result.windows_worker_bootstrap.read_text(encoding="utf-8")
    assert stat.S_IMODE(result.windows_worker_bootstrap.stat().st_mode) == 0o644
    assert '$ExpectedVersion = "' + VERSION + '"' in windows
    assert result.manifest_sha256 in windows
    assert "/releases/channels/stable.json" in windows
    assert "windows-worker-installer" in windows
    assert "Get-Sha256 $archiveBytes" in windows
    assert "Installer ZIP contains an unexpected or unsafe path" in windows
    assert '"start-worker.cmd"' in windows
    assert 'Join-Path $vgenRoot "start-worker.cmd"' in windows
    assert 'Join-Path $desktop "VGen Worker.lnk"' in windows
    assert "pause" not in windows.lower()
    for secret_word in ("invite_uri", "private_key", "session_token", "recovery_words"):
        assert secret_word not in windows


def test_windows_bootstrap_installs_a_stable_launcher_and_desktop_shortcut() -> None:
    first_digest = "1" * 64
    second_digest = "2" * 64
    first = MODULE._windows_worker_bootstrap(
        release_origin="https://downloads.example",
        version="0.9.1",
        manifest_sha256=first_digest,
    ).decode("utf-8")
    second = MODULE._windows_worker_bootstrap(
        release_origin="https://downloads.example",
        version="0.9.2",
        manifest_sha256=second_digest,
    ).decode("utf-8")

    stable_path = '$stableLauncher = Join-Path $vgenRoot "start-worker.cmd"'
    shortcut_path = '$shortcutPath = Join-Path $desktop "VGen Worker.lnk"'
    delegate = (
        'set "VGEN_WORKER_VERSION_LAUNCHER='
        '%~dp0installer\\$installLeaf\\start-worker.cmd"'
    )
    for script in (first, second):
        assert stable_path in script
        assert shortcut_path in script
        assert delegate in script
        assert '"%VGEN_WORKER_VERSION_LAUNCHER%"\n' in script
        assert '"%VGEN_WORKER_VERSION_LAUNCHER%" %VGEN_WORKER_SETUP_ARG%' in script
        assert 'set "VGEN_WORKER_SETUP_ARG=-Reenroll"' in script
        assert 'set "VGEN_WORKER_SETUP_ARG=-Repair"' in script
        assert "pause" not in script.lower()
        assert 'call "%VGEN_WORKER_VERSION_LAUNCHER%"' not in script
        assert "Run the public Windows Worker installer again to repair it." in script
        assert "Get-ChildItem" not in script
        assert "Sort-Object CreationTime" not in script
        assert 'Resolve-SafeVGenDirectory $parent "The VGen installer directory"' in script
        assert (
            'Resolve-SafeVGenDirectory $InstallRoot "The verified Worker installer directory"'
            in script
        )
        assert '[IO.File]::Replace($launcherStaging, $stableLauncher, $null)' in script
        assert '[Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)' in script
        assert "$shell.CreateShortcut($shortcutStaging)" in script
        assert "$shortcut.TargetPath = $LauncherPath" in script
        assert "$shortcut.WorkingDirectory = Split-Path -Parent $LauncherPath" in script
        assert "The VGen Worker desktop shortcut could not be installed" in script
        assert script.index("Move-Item -LiteralPath $staging -Destination $installRoot") < script.index(
            "$stableLauncher = Install-VGenWorkerLauncher $installRoot"
        )
        assert script.index("$stableLauncher = Install-VGenWorkerLauncher $installRoot") < script.index(
            "& $stableLauncher"
        )

    assert '& $stableLauncher -Repair' in first
    assert '& $stableLauncher -Repair' in second

    install_root = (
        '$installRoot = Join-Path $parent '
        '"$ExpectedVersion-$($ExpectedManifestSha256.Substring(0, 12))"'
    )
    assert install_root in first
    assert install_root in second
    assert '$ExpectedVersion = "0.9.1"' in first
    assert '$ExpectedVersion = "0.9.2"' in second
    assert first_digest in first
    assert second_digest in second


def test_gateway_and_release_origins_are_independent(tmp_path: Path) -> None:
    result = _build(
        tmp_path,
        origin="https://gateway.example",
        release_origin="https://downloads.example",
    )
    script = result.macos_bootstrap.read_text(encoding="utf-8")
    assert "GATEWAY_ORIGIN=https://gateway.example" in script
    assert "RELEASE_ORIGIN=https://downloads.example" in script
    assert 'stable_url = origin + "/releases/channels/stable.json"' in script
    assert 'configured_gateway != gateway_origin' in script


def test_bootstrap_is_replaced_before_stable_pointer_and_mismatch_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mac, windows = _inputs(tmp_path)
    root = tmp_path / "public-releases"
    channels = root / "channels"
    channels.mkdir(parents=True)
    old_pointer = MODULE._json_bytes(
        {
            "schema_version": 1,
            "channel": "stable",
            "version": "0.2.9",
            "manifest_sha256": "0" * 64,
        }
    )
    (channels / "stable.json").write_bytes(old_pointer)
    (root / "install-macos.sh").write_text("old bootstrap\n", encoding="utf-8")
    original = MODULE._atomic_public_file
    events: list[str] = []

    def observed(path: Path, content: bytes, *, mode: int) -> None:
        if path.name == "install-macos.sh":
            assert (channels / "stable.json").read_bytes() == old_pointer
            original(path, content, mode=mode)
            assert (channels / "stable.json").read_bytes() == old_pointer
            events.append("bootstrap-new-pointer-old-fails-closed")
            return
        if path.name == "stable.json":
            pointer = json.loads(content)
            assert pointer["manifest_sha256"].encode() in (root / "install-macos.sh").read_bytes()
            events.append("pointer-last")
        original(path, content, mode=mode)

    monkeypatch.setattr(MODULE, "_atomic_public_file", observed)
    MODULE.build_public_release(
        version=VERSION,
        published_at=PUBLISHED_AT,
        gateway_origin="https://gateway.example",
        release_origin="https://gateway.example",
        macos_bundle=mac,
        windows_worker_bundle=windows,
        output_root=root,
    )
    assert events == ["bootstrap-new-pointer-old-fails-closed", "pointer-last"]


def test_bootstrap_downloads_same_origin_validates_and_runs_install_command(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "installed.txt"
    serve_root = tmp_path / "serve"
    serve_root.mkdir()

    server = _release_server(serve_root)
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    mac, windows = _inputs(tmp_path, marker=marker, gateway_url=origin)
    temporary_before = set(Path(tempfile.gettempdir()).glob("vgen-macos-install.*"))
    result = MODULE.build_public_release(
        version=VERSION,
        published_at=PUBLISHED_AT,
        gateway_origin=origin,
        release_origin=origin,
        macos_bundle=mac,
        windows_worker_bundle=windows,
        output_root=serve_root,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    attack_marker = tmp_path / "bootstrap-sitecustomize-loaded"
    bootstrap_home = tmp_path / "home"
    bootstrap_home.mkdir()
    (bootstrap_home / "sitecustomize.py").write_text(
        f"open({str(attack_marker)!r}, 'w').write('loaded')\n",
        encoding="utf-8",
    )
    try:
        completed = _run_bootstrap(
            result.macos_bootstrap,
            home=bootstrap_home,
            piped=True,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    assert completed.returncode == 0, completed.stderr
    assert marker.read_text(encoding="utf-8") == "--install-only"
    assert not attack_marker.exists()
    assert "Next:" in completed.stdout
    assert "[vgen] Checking the latest VGen release..." in completed.stderr
    assert "[vgen] Downloading VGen macOS" in completed.stderr
    assert "[vgen] Download complete; verifying the package..." in completed.stderr
    assert set(Path(tempfile.gettempdir()).glob("vgen-macos-install.*")) == temporary_before


def test_bootstrap_retries_a_transient_artifact_download(tmp_path: Path) -> None:
    marker = tmp_path / "installed.txt"
    serve_root = tmp_path / "serve"
    serve_root.mkdir()
    server = _release_server(serve_root, artifact_failures=1)
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    mac, windows = _inputs(tmp_path, marker=marker, gateway_url=origin)
    result = MODULE.build_public_release(
        version=VERSION,
        published_at=PUBLISHED_AT,
        gateway_origin=origin,
        release_origin=origin,
        macos_bundle=mac,
        windows_worker_bundle=windows,
        output_root=serve_root,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        completed = _run_bootstrap(
            result.macos_bootstrap,
            home=tmp_path / "home",
            piped=True,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    assert completed.returncode == 0, completed.stderr
    assert marker.read_text(encoding="utf-8") == "--install-only"
    assert "[vgen] Download interrupted; retrying (1/3)..." in completed.stderr


def test_bootstrap_reports_the_final_artifact_download_reason(tmp_path: Path) -> None:
    serve_root = tmp_path / "serve"
    serve_root.mkdir()
    server = _release_server(serve_root, artifact_failures=3)
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    mac, windows = _inputs(tmp_path, gateway_url=origin)
    result = MODULE.build_public_release(
        version=VERSION,
        published_at=PUBLISHED_AT,
        gateway_origin=origin,
        release_origin=origin,
        macos_bundle=mac,
        windows_worker_bundle=windows,
        output_root=serve_root,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        completed = _run_bootstrap(
            result.macos_bootstrap,
            home=tmp_path / "home",
            piped=True,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    assert completed.returncode != 0
    assert "after 3 attempt(s): HTTP 503" in completed.stderr


@pytest.mark.parametrize("tamper", ("manifest", "artifact"))
def test_bootstrap_rejects_manifest_digest_or_artifact_hash_mismatch(
    tmp_path: Path, tamper: str
) -> None:
    case = tmp_path / tamper
    case.mkdir()
    serve_root = case / "serve"
    serve_root.mkdir()
    server = _release_server(serve_root)
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    mac, windows = _inputs(case, gateway_url=origin)
    result = MODULE.build_public_release(
        version=VERSION,
        published_at=PUBLISHED_AT,
        gateway_origin=origin,
        release_origin=origin,
        macos_bundle=mac,
        windows_worker_bundle=windows,
        output_root=serve_root,
    )
    if tamper == "manifest":
        result.manifest.write_bytes(result.manifest.read_bytes() + b" ")
    else:
        public_mac = result.version_root / mac.name
        value = bytearray(public_mac.read_bytes())
        value[-1] ^= 1
        public_mac.write_bytes(value)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        completed = _run_bootstrap(result.macos_bootstrap, home=case / "home")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    assert completed.returncode != 0
    if tamper == "manifest":
        assert "version manifest SHA-256 mismatch" in completed.stderr
    else:
        assert "macOS artifact size or SHA-256 mismatch" in completed.stderr


def test_bootstrap_rejects_cross_origin_artifact_redirect(tmp_path: Path) -> None:
    serve_root = tmp_path / "serve"
    serve_root.mkdir()
    server = _release_server(
        serve_root,
        artifact_redirect="https://downloads.evil.example/VGen-macOS.zip",
    )
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    mac, windows = _inputs(tmp_path, gateway_url=origin)
    result = MODULE.build_public_release(
        version=VERSION,
        published_at=PUBLISHED_AT,
        gateway_origin=origin,
        release_origin=origin,
        macos_bundle=mac,
        windows_worker_bundle=windows,
        output_root=serve_root,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        completed = _run_bootstrap(result.macos_bootstrap, home=tmp_path / "home")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    assert completed.returncode != 0
    assert "could not download the macOS CLI bundle" in completed.stderr


def test_refuses_symlinks_credentials_duplicates_and_nonidentical_version(tmp_path: Path) -> None:
    mac, windows = _inputs(tmp_path)
    linked = tmp_path / f"VGen-macOS-{VERSION}.zip.link"
    linked.symlink_to(mac)
    with pytest.raises(MODULE.PublicReleaseBuildError, match="regular file"):
        MODULE.build_public_release(
            version=VERSION,
            published_at=PUBLISHED_AT,
            gateway_origin="https://gateway.example",
            release_origin="https://gateway.example",
            macos_bundle=linked,
            windows_worker_bundle=windows,
            output_root=tmp_path / "symlink-output",
        )

    private_root = tmp_path / "private"
    private_root.mkdir()
    private_windows = private_root / f"vgen-windows-worker-installer-{VERSION}.zip"
    _windows_bundle(private_windows, include_credentials=True)
    with pytest.raises(MODULE.PublicReleaseBuildError, match="contains credentials"):
        MODULE._validate_windows_bundle(
            private_windows,
            version=VERSION,
            gateway_origin="https://gateway.example",
        )

    duplicate = tmp_path / f"vgen-windows-worker-installer-{VERSION}.zip.duplicate"
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(duplicate, "w") as archive:
            archive.writestr("same", b"one")
            archive.writestr("same", b"two")
    with zipfile.ZipFile(duplicate) as archive:
        with pytest.raises(MODULE.PublicReleaseBuildError, match="duplicate"):
            MODULE._safe_zip_entries(archive, label="test archive")

    result = MODULE.build_public_release(
        version=VERSION,
        published_at=PUBLISHED_AT,
        gateway_origin="https://gateway.example",
        release_origin="https://gateway.example",
        macos_bundle=mac,
        windows_worker_bundle=windows,
        output_root=tmp_path / "immutable-output",
    )
    (result.version_root / "manifest.json").write_bytes(b"tampered")
    with pytest.raises(MODULE.PublicReleaseBuildError, match="refusing to overwrite"):
        MODULE.build_public_release(
            version=VERSION,
            published_at=PUBLISHED_AT,
            gateway_origin="https://gateway.example",
            release_origin="https://gateway.example",
            macos_bundle=mac,
            windows_worker_bundle=windows,
            output_root=result.root,
        )


@pytest.mark.parametrize("extra_name", ("backup-private-key.txt", "sitecustomize.py"))
def test_windows_public_bundle_rejects_every_extra_file_even_when_checksummed(
    tmp_path: Path, extra_name: str
) -> None:
    bundle_root = tmp_path / extra_name.replace(".", "-")
    bundle_root.mkdir()
    bundle = bundle_root / f"vgen-windows-worker-installer-{VERSION}.zip"
    _windows_bundle(bundle, extra_files={extra_name: b"unexpected executable or secret data"})
    with pytest.raises(MODULE.PublicReleaseBuildError, match="closed public allowlist"):
        MODULE._validate_windows_bundle(
            bundle,
            version=VERSION,
            gateway_origin="https://gateway.example",
        )


@pytest.mark.parametrize("extra_name", ("backup-private-key.txt", "sitecustomize.py"))
def test_macos_public_bundle_rejects_every_extra_file_even_when_checksummed(
    tmp_path: Path, extra_name: str
) -> None:
    bundle_root = tmp_path / extra_name.replace(".", "-")
    bundle_root.mkdir()
    bundle = bundle_root / f"VGen-macOS-{VERSION}.zip"
    _mac_bundle(bundle, extra_files={extra_name: b"unexpected executable or secret data"})
    with pytest.raises(MODULE.PublicReleaseBuildError, match="closed public allowlist"):
        MODULE._validate_macos_bundle(
            bundle,
            version=VERSION,
            gateway_origin="https://gateway.example",
        )


def test_public_installers_must_contain_the_exact_same_reviewed_wheel(tmp_path: Path) -> None:
    mac, windows = _inputs(
        tmp_path,
        mac_wheel=_wheel_bytes(marker=b"mac wheel from source A"),
        windows_wheel=_wheel_bytes(marker=b"Windows wheel from source B"),
    )
    with pytest.raises(MODULE.PublicReleaseBuildError, match="same reviewed VGen wheel"):
        MODULE.build_public_release(
            version=VERSION,
            published_at=PUBLISHED_AT,
            gateway_origin="https://gateway.example",
            release_origin="https://gateway.example",
            macos_bundle=mac,
            windows_worker_bundle=windows,
            output_root=tmp_path / "public-releases",
        )


@pytest.mark.parametrize(
    ("wheel", "message"),
    (
        (b"not a zip wheel", "unreadable VGen wheel"),
        (_wheel_bytes(distribution="other"), "distribution name"),
        (_wheel_bytes(version="0.3.1"), "dist-info is invalid"),
        (_wheel_bytes(tag="cp311-cp311-macosx_11_0_arm64"), "py3-none-any tag"),
    ),
)
def test_rejects_invalid_embedded_wheel_contract(
    tmp_path: Path, wheel: bytes, message: str
) -> None:
    bundle_root = tmp_path / hashlib.sha256(wheel).hexdigest()[:8]
    bundle_root.mkdir()
    bundle = bundle_root / f"VGen-macOS-{VERSION}.zip"
    _mac_bundle(bundle, wheel=wheel)
    with pytest.raises(MODULE.PublicReleaseBuildError, match=message):
        MODULE._validate_macos_bundle(
            bundle,
            version=VERSION,
            gateway_origin="https://gateway.example",
        )


def test_optional_macos_gateway_default_must_match_public_origin(tmp_path: Path) -> None:
    bundle = tmp_path / f"VGen-macOS-{VERSION}.zip"
    _mac_bundle(bundle, gateway_default="https://other-gateway.example")
    with pytest.raises(MODULE.PublicReleaseBuildError, match="does not match"):
        MODULE._validate_macos_bundle(
            bundle,
            version=VERSION,
            gateway_origin="https://gateway.example",
        )


def test_refuses_artifact_that_changes_while_being_staged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mac, windows = _inputs(tmp_path)
    original = MODULE._copy_regular

    def changed_after_copy(source: Path, destination: Path) -> None:
        original(source, destination)
        if destination.name == mac.name:
            destination.write_bytes(destination.read_bytes() + b"changed during publication")

    monkeypatch.setattr(MODULE, "_copy_regular", changed_after_copy)
    with pytest.raises(MODULE.PublicReleaseBuildError, match="changed while"):
        MODULE.build_public_release(
            version=VERSION,
            published_at=PUBLISHED_AT,
            gateway_origin="https://gateway.example",
            release_origin="https://gateway.example",
            macos_bundle=mac,
            windows_worker_bundle=windows,
            output_root=tmp_path / "public-releases",
        )


@pytest.mark.parametrize(
    "origin",
    (
        "http://gateway.example",
        "https://user:password@gateway.example",
        "https://gateway.example/releases",
        "https://gateway.example?invite=secret",
    ),
)
def test_rejects_insecure_or_non_origin_gateway(origin: str) -> None:
    with pytest.raises(MODULE.PublicReleaseBuildError, match="origin"):
        MODULE._validated_gateway_origin(origin)
